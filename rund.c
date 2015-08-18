/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "lib/libt.h"

#define NAME "rund"

static const char *const rcinitcmd[] = { "/etc/rc.init", NULL };
static const char *const rcrebootcmd[] = { "/etc/rc.shutdown", "reboot", NULL };
static const char *const rcpoweroffcmd[] = { "/etc/rc.shutdown", "poweroff", NULL };
static const char *const emergencycmd[] = { "/sbin/sulogin", NULL, };

#ifdef ANYPID
static const char *rundsock = "@rund";
#else
#define rundsock "@rund"
#endif

/* logging */
static int syslog_open;
static int loglevel = LOG_WARNING;

__attribute__((format(printf,2,3)))
static void mylog(int level, const char *fmt, ...)
{
	static char buf[1024];
	va_list va;
	int ret;

	va_start(va, fmt);
	ret = vsnprintf(buf, sizeof(buf)-1, fmt, va);
	va_end(va);
	if (ret < 0)
		; /* nothing to print */
	else if (syslog_open)
		syslog(level, "%s", buf);
	else if (level <= loglevel)
		dprintf(STDERR_FILENO, "%s: %s\n", NAME, buf);
	if (level < LOG_ERR)
		exit(EXIT_FAILURE);
}

#define ESTR(x) strerror(x)

/* globals */
static int sock;
static struct sockaddr_un peername;
static int peernamelen;
static int peeruid;
static int myuid;
static sigset_t savedset;
#ifdef ANYPID
static int mypid;
#endif

/* launch a process for init service */
static int spawn(const char *const argv[])
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		mylog(0, "fork: %s", ESTR(errno));
		return -errno;
	} else if (pid == 0) {
		setenv("RUNDSOCK", rundsock, 1);
		sigprocmask(SIG_SETMASK, &savedset, NULL);
		setsid();
		execvp(*argv, (char **)argv);
		mylog(LOG_CRIT, "execvp: %s", ESTR(errno));
	}
	return pid;
}

static int parse_nullbuff(char *buf, int len, char **pargv[])
{
	static char **argv;
	static int alloced;

	char *str;
	int j;

	for (j = 0, str = buf; (str - buf) < len; ++j) {
		if (!*str)
			/* double null */
			break;
		if ((j+1) >= alloced) {
			/* make some room */
			alloced += 16;
			argv = realloc(argv, sizeof(*argv)*alloced);
			if (!argv)
				return -ENOMEM;
		}
		argv[j] = str;
		str += strlen(str) + 1;
	}
	if (argv)
		argv[j] = NULL;
	*pargv = argv;
	return j;
}

/* watchdog control */
struct wdt {
	struct wdt *next;
	int fd;
	int timeout;
	int owner;
	char file[2];
};
static struct wdt *wdts;

static void do_watchdog(void *dat)
{
	struct wdt *wdt = dat;

	write(wdt->fd, "w", 1);
	libt_add_timeout(wdt->timeout/2.0, do_watchdog, wdt);
}

static int cmd_watchdog(int argc, char *argv[])
{
	struct wdt *wdt;

	if (argc < 2) {
		mylog(LOG_WARNING, "no watchdog device given");
		return -EINVAL;
	}
	wdt = malloc(sizeof(*wdt)+strlen(argv[1]));
	if (!wdt) {
		mylog(LOG_ERR, "malloc failed: %s", ESTR(errno));
		return -errno;
	}
	wdt->fd = open(argv[1], O_RDONLY);
	if (wdt->fd < 0) {
		free(wdt);
		mylog(LOG_ERR, "open %s: %s", argv[1], ESTR(errno));
		return -errno;
	}
	wdt->timeout = (argc > 2) ? (strtoul(argv[2], 0, 0) ?: 1) : 1;
	/* save owner, for later removal authorization */
	wdt->owner = peeruid;
	/* add in linked list */
	wdt->next = wdts;
	wdts = wdt;
	/* first trigger + schedule next */
	do_watchdog(wdt);
	return 0;
}

static int cmd_unwatchdog(int argc, char *argv[])
{
	struct wdt **pwdt, *wdt;

	if (argc < 2) {
		mylog(LOG_WARNING, "no watchdog device given");
		return -EINVAL;
	}
	for (pwdt = &wdts; *pwdt; pwdt = &(*pwdt)->next) {
		if (!strcmp((*pwdt)->file, argv[1])) {
			wdt = *pwdt;
			if (peeruid && (wdt->owner != peeruid)) {
				mylog(LOG_ERR, "remove %s: %s", argv[1], ESTR(EPERM));
				return -EPERM;
			}
			/* remove from linked list */
			*pwdt = (*pwdt)->next;
			libt_remove_timeout(do_watchdog, wdt);
			close(wdt->fd);
			free(wdt);
			return 0;
		}
	}
	return -ENOENT;
}

/* exec control */
struct service {
	struct service *next;
	pid_t pid;
	int flags;
		#define FL_REMOVE	0x01
	double starttime;
	int delay[2]; /* create fibonacci on the fly */
	char **args;
	char **argv;
	int uid;
};

/* global list */
static struct service *svcs;

static void exec_svc(void *dat)
{
	struct service *svc = dat;
	int ret, j;

	if (svc->delay[1])
		/* this service has been throttled */
		mylog(LOG_INFO, "resume %s", *svc->argv);

	ret = fork();
	if (ret < 0) {
		mylog(LOG_ERR, "fork: %s", ESTR(errno));
		/* postpone for 1 second always, no incremental delay */
		libt_add_timeout(1, exec_svc, svc);
	} else if (ret > 0) {
		svc->starttime = libt_now();
		svc->pid = ret;
	} else {
		/* child */
		/* redirect stdout & stderr to /dev/null
		 * We know stdin is /dev/null.
		 * stdout & stderr still default to /dev/console
		 * and may have been redirected,
		 */
		dup2(STDIN_FILENO, STDOUT_FILENO);
		dup2(STDIN_FILENO, STDERR_FILENO);

		sigprocmask(SIG_SETMASK, &savedset, NULL);
		setsid();
		for (j = 0; j < svc->argv-svc->args; ++j)
			putenv(svc->args[j]);
		/* only try to set user when I'm root */
		if (!myuid && svc->uid) {
			/* change user */
			struct passwd *pw;

			pw = getpwuid(svc->uid);
			if (!pw)
				mylog(LOG_CRIT, "unknown uid %i", svc->uid);
			if (initgroups(pw->pw_name, pw->pw_gid) < 0)
				mylog(LOG_CRIT, "initgroups for %s: %s", pw->pw_name, ESTR(errno));
			if (setgid(pw->pw_gid) < 0)
				mylog(LOG_CRIT, "setgid %i: %s", pw->pw_gid, ESTR(errno));
			if (setuid(pw->pw_uid) < 0)
				mylog(LOG_CRIT, "setuid %i: %s", svc->uid, ESTR(errno));
			if (chdir(pw->pw_dir) < 0)
				mylog(LOG_ERR, "chdir %s: %s", pw->pw_dir, ESTR(errno));
			setenv("HOME", pw->pw_dir, 1);
			setenv("USER", pw->pw_name, 1);
		}
		execvp(*svc->argv, svc->argv);
		mylog(LOG_CRIT, "execvp %s: %s", *svc->argv, ESTR(errno));
		_exit(EXIT_FAILURE);
	}
}

static int cmd_add(int argc, char *argv[])
{
	struct service *svc;
	int j, f, result = 0;

	if (myuid && peeruid && (myuid != peeruid))
		/* block on regular user mismatch */
		return -EPERM;
	svc = malloc(sizeof(*svc));
	if (!svc)
		return -ENOMEM;
	memset(svc, 0, sizeof(*svc));
	svc->uid = peeruid;
	/* copy args */
	--argc; ++argv;
	svc->args = malloc(sizeof(char *)*(argc+1));
	if (!svc->args) {
		result = -ENOMEM;
		goto failed;
	}
	for (f = j = 0; j < argc; ++j) {
		if (!svc->argv && !strncmp("USER=", argv[j], 5)) {
			/* still in environment, and user provided */
			struct passwd *pw;

			pw = getpwnam(argv[j]+5);
			if (!pw) {
				result = -EINVAL;
				mylog(LOG_WARNING, "user '%s' unknown", argv[j]+5);
				goto failed;
			}
			if (peeruid && (pw->pw_uid != peeruid)) {
				result = -EPERM;
				mylog(LOG_WARNING, "only root may change user");
				goto failed;
			}
			svc->uid = pw->pw_uid;
			continue;
		}
		svc->args[f] = strdup(argv[j]);
		if (!svc->argv && !strchr(svc->args[f], '='))
			svc->argv = svc->args+f;
		++f;
	}
	svc->args[f] = NULL;
	if (!svc->argv)
		svc->argv = svc->args;

	/* add in linked list */
	svc->next = svcs;
	svcs = svc;
	mylog(LOG_INFO, "start '%s'", *svc->argv);
	/* exec now */
	exec_svc(svc);
	return svc->pid;
failed:
	if (svc->args) {
		for (j = 0; svc->args[j]; ++j)
			free(svc->args[j]);
		free(svc->args);
	}
	free(svc);
	return result;
}

static void cleanup_svc(struct service *svc)
{
	struct service **psvc;
	int j;

	mylog(LOG_INFO, "remove '%s'", *svc->argv);
	/* remove from linked list */
	for (psvc = &svcs; *psvc; psvc = &(*psvc)->next) {
		if (*psvc == svc) {
			*psvc = svc->next;
			break;
		}
	}
	/* free memory */
	for (j = 0; svc->args[j]; ++j)
		free(svc->args[j]);
	free(svc->args);
	free(svc);
}

static struct service *find_svc(struct service *svcs, char *args[])
{
	struct service *svc;
	int j, k;

	if (!*args)
		return NULL;
	if (args[1] && !strcmp(args[1], "*"))
		/* wildcard matches all */
		return svcs;

	for (svc = svcs; svc; svc = svc->next) {
		for (j = 1; args[j]; ++j) {
			for (k = 0; svc->args[k]; ++k)
				if (!strcmp(args[j], svc->args[k]))
					break;
			if (!svc->args[k])
				goto nomatch;
		}
		/* all 'needle's matched */
		return svc;
nomatch:
		/* args[j] was not matched */
		continue;
	}
	return NULL;
}

static int cmd_remove(int argc, char *argv[])
{
	struct service *svc, *nsvc;
	int ndone = 0;
	int err = -ENOENT;

	if (!argv[1])
		/* do not 'implicitely' remove all svcs */
		return -EINVAL;
	for (svc = find_svc(svcs, argv); svc; svc = find_svc(nsvc, argv)) {
		nsvc = svc->next;
		if (peeruid && (svc->uid != peeruid)) {
			/* change returned error into 'permission ...' */
			err = EPERM;
			continue;
		}
		if (svc->pid) {
			mylog(LOG_INFO, "stop '%s'", *svc->argv);
			kill(svc->pid, SIGTERM);
			svc->flags |= FL_REMOVE;
		} else {
			libt_remove_timeout(exec_svc, svc);
			cleanup_svc(svc);
		}
		++ndone;
	}
	return ndone ?: err;
}

static int cmd_removing(int argc, char *argv[])
{
	struct service *svc;
	int ndone = 0;

	for (svc = find_svc(svcs, argv); svc; svc = find_svc(svc->next, argv)) {
		if (peeruid && (svc->uid != peeruid))
			continue;
		if (svc->flags & FL_REMOVE)
			++ndone;
	}
	return ndone;
}

static int cmd_syslog(int argc, char *argv[])
{
	if (myuid != (peeruid ?: myuid))
		return -EPERM;
	if ((argc > 1) && !strcmp(argv[1], "close")) {
		if (!syslog_open)
			return -EEXIST;
		closelog();
		syslog_open = 0;
	} else {
		if (syslog_open)
			return -EEXIST;
		openlog("rund", LOG_PERROR, LOG_DAEMON);
		syslog_open = 1;
	}
	return 0;
}

static int cmd_loglevel(int argc, char *argv[])
{
	if (myuid != (peeruid ?: myuid))
		return -EPERM;
	if (argc > 1) {
		loglevel = strtoul(argv[1], NULL, 0);
		setlogmask(LOG_UPTO(loglevel));
	}
	return loglevel;
}

static int cmd_redir(int argc, char *argv[])
{
	int ret, fd;

	if (myuid != (peeruid ?: myuid))
		return -EPERM;

	if (argc < 2)
		return -EINVAL;
	fd = open(argv[1], O_WRONLY | O_NOCTTY | O_APPEND | O_CREAT, 0666);
	if (fd < 0) {
		ret = errno;
		mylog(LOG_WARNING, "open %s: %s", argv[1], ESTR(errno));
		return -ret;
	}
	ret = 0;
	if (dup2(fd, STDOUT_FILENO) < 0) {
		ret = errno; /* save errno for later return */
		mylog(LOG_WARNING, "dup2 %s stdout: %s", argv[1], ESTR(errno));
	}
	if (dup2(fd, STDERR_FILENO) < 0) {
		ret = errno; /* save errno for later return */
		mylog(LOG_WARNING, "dup2 %s stdout: %s", argv[1], ESTR(errno));
	}
	close(fd);
	return ret;
}

static int cmd_env(int argc, char *argv[])
{
	if (myuid != (peeruid ?: myuid))
		return -EPERM;

	if (argc < 3)
		return -EINVAL;
	setenv(argv[1], argv[2], 1);
	return 0;
}

static char sbuf[16*1024];
static int cmd_status(int argc, char *argv[])
{
	struct service *svc;
	int ndone = 0, err = 0, j, ret;
	char *bufp;

	for (svc = find_svc(svcs, argv); svc; svc = find_svc(svc->next, argv)) {
		if (peeruid && (svc->uid != peeruid)) {
			/* change returned error into 'permission ...' */
			err = EPERM;
			continue;
		}
		bufp = sbuf;
		*bufp++ = '>';
		if (svc->pid)
			bufp += sprintf(bufp, ".pid=%u", svc->pid) +1;
		if (svc->uid)
			bufp += sprintf(bufp, ".uid=%u", svc->uid) +1;
		for (j = 0; svc->args[j]; ++j) {
			strcpy(bufp, svc->args[j]);
			bufp += strlen(bufp)+1;
		}
		ret = sendto(sock, sbuf, bufp-sbuf, 0, (void *)&peername, peernamelen);
		if (ret < 0)
			return -errno;
		++ndone;
	}
	return ndone ?: -err;
}

/* remote commands */
struct cmd {
	const char *name;
	int (*fn)(int argc, char *argv[]);
} static const cmds[] = {
	{ "watchdog", cmd_watchdog, },
	{ "unwatchdog", cmd_unwatchdog, },
	{ "add", cmd_add, },
	{ "remove", cmd_remove, },
	{ "removing", cmd_removing, },
	/* management commands */
	{ "syslog", cmd_syslog, },
	{ "loglevel", cmd_loglevel, },
	{ "redir", cmd_redir, },
	{ "env", cmd_env, },
	{ "status", cmd_status, },
	{ },
};

/* main process */
int main(int argc, char *argv[])
{
	int ret, fd;
	struct service *svc;
	pid_t rcinitpid, pid;
	struct pollfd fset[] = {
		{ .events = POLLIN, },
		{ .events = POLLIN, },
	};
	sigset_t set;
	struct sockaddr_un name = {
		.sun_family = AF_UNIX,
		.sun_path = "\0rund",
	};
	/* for signalfd */
	struct signalfd_siginfo info;
	/* for recvmsg */
	static char buf[16*1024];
	static char resp[128];
	static char cmsgdat[CMSG_SPACE(sizeof(struct ucred))];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsgdat,
		.msg_controllen = sizeof(cmsgdat),
		.msg_name = &peername,
		.msg_namelen = sizeof(peername),
	};
	struct cmsghdr *cmsg;
	/* process recvd cmd */
	char **args;
	int nargs;
	const struct cmd *cmd;

#if ANYPID
	mypid = getpid();
	rundsock = getenv("RUNDSOCK") ?: rundsock;
	strcpy(name.sun_path+1, rundsock+1);
#else
	if ((getpid() != 1) && (getppid() != 1)) {
		printf("%s %s\n", NAME, VERSION);
		return 0;
	}
#endif
	myuid = getuid();
	chdir("/");
	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		mylog(LOG_WARNING, "open %s: %s", "/dev/null", ESTR(errno));
	else {
		dup2(fd, STDIN_FILENO);
		close(fd);
	}
	/* setup signals */
	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, &savedset);
	ret = fset[0].fd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
	if (ret < 0) {
		mylog(LOG_ERR, "signalfd failed: %s", ESTR(errno));
		goto emergency;
	}

	/* open server socket */
	fset[1].fd = sock = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		mylog(LOG_ERR, "socket(unix, ...) failed: %s", ESTR(errno));
		goto emergency;
	}

	ret = bind(sock, (void *)&name, sizeof(name));
	if (ret < 0) {
		mylog(LOG_ERR, "bind(@%s) failed: %s", name.sun_path+1, ESTR(errno));
		goto emergency;
	}

	ret = 1;
	ret = setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &ret, sizeof(ret));
	if (ret < 0) {
		mylog(LOG_ERR, "setsockopt SO_PASSCRED failed: %s", ESTR(errno));
		goto emergency;
	}

	/* launch system start */
#ifdef ANYPID
	if (mypid != 1)
		rcinitpid = 0;
	else
#endif
	rcinitpid = spawn(rcinitcmd);
	while (1) {
		libt_flush();

		ret = poll(fset, 2, libt_get_waittime());
		if (ret < 0)
			mylog(LOG_CRIT, "poll: %s", ESTR(errno));

		if (fset[0].revents) {
			/* signals */

			ret = read(fset[0].fd, &info, sizeof(info));
			if (ret < 0)
				/* TODO: test for EAGAIN */
				mylog(LOG_CRIT, "read signalfd: %s", ESTR(errno));
			switch (info.ssi_signo) {
			case SIGCHLD:
				/* reap lost children */
				while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
					if (rcinitpid == pid)
						rcinitpid = 0;
					/* find service */
					for (svc = svcs; svc; svc = svc->next) {
						if (pid != svc->pid)
							continue;
						svc->pid = 0;
						if (svc->flags & FL_REMOVE) {
							cleanup_svc(svc);
							break;
						}
						if ((svc->starttime + 2) < libt_now()) {
							/* reset delays */
							svc->delay[0] =
							svc->delay[1] = 0;
							libt_add_timeout(0, exec_svc, svc);
							mylog(LOG_WARNING, "restart '%s", *svc->argv);
						} else {
							int delay = (svc->delay[0] + svc->delay[1]) ?: 1;
							svc->delay[0] = svc->delay[1];
							svc->delay[1] = delay;
							libt_add_timeout(delay, exec_svc, svc);
							mylog(LOG_WARNING, "throttle '%s", *svc->argv);
						}
						break;
					}
				}
				break;
			case SIGINT:
				/* reboot */
				if (rcinitpid)
					kill(-rcinitpid, SIGTERM);
#ifdef ANYPID
				if (mypid != 1)
					exit(0);
#endif
				mylog(LOG_INFO, "reboot ...");
				spawn(rcrebootcmd);
				break;
			case SIGTERM:
				/* poweroff */
				if (rcinitpid)
					kill(-rcinitpid, SIGTERM);
#ifdef ANYPID
				if (mypid != 1)
					exit(0);
#endif
				mylog(LOG_INFO, "poweroff ...");
				spawn(rcpoweroffcmd);
				break;
			case SIGHUP:
				/* retry throttled services */
				mylog(LOG_INFO, "reload ...");
				for (svc = svcs; svc; svc = svc->next) {
					if (!svc->pid && svc->delay[1]) {
						/* re-schedule immediate */
						libt_remove_timeout(exec_svc, svc);
						libt_add_timeout(0, exec_svc, svc);
					}
				}
				break;
			}
		}
		if (fset[1].revents) {
			/* socket recvd */
			/* (p)reset sizes */
			msg.msg_namelen = sizeof(peername);
			msg.msg_controllen = sizeof(cmsgdat);
			iov.iov_len = sizeof(buf);

			/* recv */
			ret = recvmsg(sock, &msg, 0);
			if (ret < 0) {
				if (errno != EAGAIN)
					mylog(LOG_WARNING, "recv ctrldat: %s", ESTR(errno));
				goto sock_done;
			}
			cmsg = CMSG_FIRSTHDR(&msg);
			if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
					cmsg->cmsg_type == SCM_CREDENTIALS)
				peeruid = ((struct ucred *)CMSG_DATA(cmsg))->uid;
			else {
				/* no permissions received */
				ret = -EINVAL;
				goto sock_reply;
			}

			/* process data */
			nargs = parse_nullbuff(buf, ret, &args);
			if (nargs < 1) {
				mylog(LOG_WARNING, "no command supplied!");
				ret = -EINVAL;
				goto sock_reply;
			}

			/* lookup command */
			for (cmd = cmds; cmd->name; ++cmd)
				if (!strcmp(cmd->name, *args))
					break;
			if (!cmd->name) {
				mylog(LOG_WARNING, "command '%s' unknown", *args);
				ret = -ENOENT;
				goto sock_reply;
			}
			/* run command */
			peernamelen = msg.msg_namelen;
			ret = cmd->fn(nargs, args);
sock_reply:
			if (!msg.msg_namelen)
				/* anonymous socket, skip reply */
				goto sock_done;
			ret = snprintf(resp, sizeof(resp), "%i", ret);
			ret = sendto(sock, resp, ret, 0, (void *)&peername, msg.msg_namelen);
			if (ret < 0)
				mylog(LOG_ERR, "sendto %c%s: %s", peername.sun_path[0] ?: '@',
						peername.sun_path+1, ESTR(errno));
sock_done:
			; /* empty statement */
		}
	}
	/* not reachable */
	return EXIT_SUCCESS;
emergency:
	execvp(*emergencycmd, (char **)emergencycmd);
	mylog(LOG_ERR, "execvp %s", *emergencycmd);
	execlp("/bin/sh", "sh", NULL);
	mylog(LOG_ERR, "execvp /bin/sh");
	return EXIT_FAILURE;

}
