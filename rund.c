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
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/watchdog.h>

#include "lib/libt.h"

#define NAME "rund"

#define INIT "/etc/rc.init"
#define STOP "/etc/rc.shutdown"
#define HELP "/sbin/sulogin"

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

/* stdin initially is /dev/console
 * I want to redirect it to /dev/null,
 * when I start spawning services.
 * The redirect is seperated from main
 * so I can postpone this until the first
 * service spawns. This relieves the rootfs
 * to have /dev/null at boot time.
 * You can mount /dev and create it later,
 * just before the first service starts.
 */
static int nullin; /* stdin is already /dev/null */
static void set_nullin(void)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		mylog(LOG_WARNING, "open %s: %s", "/dev/null", ESTR(errno));
	else {
		dup2(fd, STDIN_FILENO);
		close(fd);
		nullin = 1;
	}
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
	char file[2];
};
static struct wdt *wdts;

static void do_watchdog(void *dat)
{
	struct wdt *wdt = dat;

	write(wdt->fd, "keepalive", 9);
	libt_add_timeout(wdt->timeout/2.0, do_watchdog, wdt);
}

static int cmd_watchdog(int argc, char *argv[])
{
	struct wdt *wdt, **pwdt;
	int ret;
	const char *device;

	if (peeruid)
		return -EPERM;
	if (argc < 3) {
		mylog(LOG_WARNING, "no watchdog device given");
		return -EINVAL;
	}
	device = argv[2];

	if (!strcmp(argv[1], "remove")) {
		for (pwdt = &wdts; *pwdt; pwdt = &(*pwdt)->next) {
			if (!strcmp((*pwdt)->file, device)) {
				wdt = *pwdt;
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
	/* add a watchdog */
	wdt = malloc(sizeof(*wdt)+strlen(device));
	if (!wdt) {
		mylog(LOG_ERR, "malloc failed: %s", ESTR(errno));
		return -errno;
	}
	strcpy(wdt->file, device);
	wdt->timeout = strtoul(argv[3] ?: "5", NULL, 0);
	if (!wdt->timeout) {
		mylog(LOG_ERR, "illegal watchdog timeout %i: %s",
				wdt->timeout, ESTR(errno));
		free(wdt);
		return -EINVAL;
	}
	wdt->fd = open(device, O_RDWR | O_CLOEXEC);
	if (wdt->fd < 0) {
		free(wdt);
		mylog(LOG_ERR, "open %s: %s", device, ESTR(errno));
		return -errno;
	}
	/* set timeout */
	ret = ioctl(wdt->fd, WDIOC_SETTIMEOUT, &wdt->timeout);
	if (ret < 0 && errno != ENOTSUP) {
		mylog(LOG_ERR, "ioctl %s settimeout %i: %s", device,
				wdt->timeout, ESTR(errno));
		close(wdt->fd);
		free(wdt);
		return -errno;
	}
	/* add in linked list */
	wdt->next = wdts;
	wdts = wdt;
	/* first trigger + schedule next */
	do_watchdog(wdt);
	return 0;
}

/* exec control */
struct service {
	struct service *next;
	pid_t pid;
	int flags;
		#define FL_REMOVE	0x01
		#define FL_INTERVAL	0x02
	double starttime;
	int delay[2]; /* create fibonacci on the fly */
	char **args;
	char **argv;
	int uid;
	double interval;
};

/* global list */
static struct service *svcs;

static void exec_svc(void *dat)
{
	struct service *svc = dat;
	int ret, j;

	if (!nullin)
		set_nullin();
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
		sigprocmask(SIG_SETMASK, &savedset, NULL);
		setsid();
		for (j = 0; j < svc->argv-svc->args; ++j)
			putenv(svc->args[j]);

		/* child */
		/* redirect stdout & stderr to /dev/null
		 * We know stdin is /dev/null.
		 * stdout & stderr still default to /dev/console
		 * and may have been redirected,
		 * Prevent redirect with environment DETACH=0
		 */
		if (strcmp(getenv("DETACH") ?: "1", "0")) {
			dup2(STDIN_FILENO, STDOUT_FILENO);
			dup2(STDIN_FILENO, STDERR_FILENO);
		}

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

static int svc_exist(struct service *dut)
{
	struct service *svc;
	int j;

	for (svc = svcs; svc; svc = svc->next) {
		if (svc->uid != dut->uid)
			continue;

		for (j = 0; svc->args[j] && dut->args[j]; ++j) {
			if (strcmp(svc->args[j], dut->args[j]))
				break;
		}
		if (!svc->args[j] && !dut->args[j])
			return 1;
	}
	return 0;
}

static int cmd_add(int argc, char *argv[])
{
	struct service *svc, *svc2;
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
			if (argv[j][5] == '#') {
				svc->uid = strtoul(argv[j]+6, NULL, 0);
			} else {
				/* do not perform user name lookups
				 * in pid 1. It may involve LDAP queries etc.
				 * Leave this 'runtime dependency' to runc
				 * or any other client
				 */
				result = -EINVAL;
				mylog(LOG_WARNING, "only USER=#xx format accepted");
				goto failed;
			}
			if (peeruid && (svc->uid != peeruid)) {
				result = -EPERM;
				mylog(LOG_WARNING, "only root may change user");
				goto failed;
			}
			continue;
		} else if (!svc->argv && !strncmp("INTERVAL=", argv[j], 9)) {
			svc->interval = strtod(argv[j]+9, NULL);
			svc->flags |= FL_INTERVAL;
			continue;
		} else if (!strncmp("PID=", argv[j], 4)) {
			/* it is way more complicated to allow this for non-root
			 * without leaving security holes (i.e. user A adds svc
			 * with pid P, which is currently owned by user B, and
			 * allows A to kill P).
			 * I also see no real usecase for regular users.
			 */
			if (peeruid != 0) {
				result = -EPERM;
				mylog(LOG_WARNING, "only root may assign PIDs");
				goto failed;
			}
			/* preset pid */
			svc->pid = strtoul(argv[j]+4, NULL, 0);
			for (svc2 = svcs; svc2; svc2 = svc2->next) {
				if (svc2->pid == svc->pid) {
					result = -EEXIST;
					mylog(LOG_WARNING, "I already manage PID %u", svc->pid);
					goto failed;
				}
			}
			/* test process exists */
			if (kill(svc->pid, 0) < 0)
				svc->pid =0 ;
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
	if (svc_exist(svc)) {
		result = -EEXIST;
		goto failed;
	}

	/* add in linked list */
	svc->next = svcs;
	svcs = svc;
	mylog(LOG_INFO, "%s '%s'", svc->pid ? "import" : "add", *svc->argv);
	/* exec now */
	if (!svc->pid)
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
	char *valstr;

	if (myuid != (peeruid ?: myuid))
		return -EPERM;

	if (argc < 2)
		return -EINVAL;

	valstr = strchr(argv[1], '=');
	if (valstr) {
		*valstr++ = 0;
		if (!*valstr)
			return unsetenv(argv[1]);
	} else
		valstr = "";
	return setenv(argv[1], valstr, 1);
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
			bufp += sprintf(bufp, "PID=%u", svc->pid) +1;
		if (svc->uid)
			bufp += sprintf(bufp, "USER=#%u", svc->uid) +1;
		if (svc->flags & FL_INTERVAL)
			bufp += sprintf(bufp, "INTERVAL=%lf", svc->interval) +1;
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

static int cmd_exec(int argc, char *argv[])
{
	if (myuid != (peeruid ?: myuid))
		return -EPERM;
	if (argc < 2)
		return -EINVAL;
	mylog(LOG_ERR, "request to exec %s ...", argv[1]);

	/* send ack now that it is still possible */
	if (sendto(sock, "0", 1, 0, (void *)&peername, peernamelen) < 0)
		return -errno;

	execvp(argv[1], argv+1);
	mylog(LOG_ERR, "execvp() failed: %s", ESTR(errno));
	return -errno;
}

/* remote commands */
struct cmd {
	const char *name;
	int (*fn)(int argc, char *argv[]);
} static const cmds[] = {
	{ "watchdog", cmd_watchdog, },
	{ "add", cmd_add, },
	{ "remove", cmd_remove, },
	{ "removing", cmd_removing, },
	/* management commands */
	{ "syslog", cmd_syslog, },
	{ "loglevel", cmd_loglevel, },
	{ "redir", cmd_redir, },
	{ "env", cmd_env, },
	{ "status", cmd_status, },
	{ "exec", cmd_exec, },
	{ },
};

/* main process */
int main(int argc, char *argv[])
{
	int ret;
	struct service *svc;
	pid_t rcpid, pid;
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
	char *todo;

	if (getpid() == 1) {
	} else if ((argc > 1) && (*argv[1] == '@'))
		strcpy(name.sun_path+1, &argv[1][1]);
	else {
		printf("%s %s\n", NAME, VERSION);
		return 0;
	}
	myuid = getuid();
	chdir("/");
	/* setup signals */
	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, &savedset);
	ret = fset[0].fd = signalfd(-1, &set, 0);
	if (ret < 0) {
		mylog(LOG_ERR, "signalfd failed: %s", ESTR(errno));
		goto emergency;
	}
	fcntl(ret, F_SETFD, fcntl(ret, F_GETFD) | FD_CLOEXEC);

	/* open server socket */
	fset[1].fd = sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		mylog(LOG_ERR, "socket(unix, ...) failed: %s", ESTR(errno));
		goto emergency;
	}
	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

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
	if (getpid() != 1)
		rcpid = 0;
	else if ((rcpid = fork()) == 0) {
		sigprocmask(SIG_SETMASK, &savedset, NULL);
		execvp(INIT, argv);
		mylog(LOG_CRIT, "execvp %s: %s", ESTR(errno), INIT);
	} else if (rcpid < 0)
		mylog(LOG_CRIT, "fork: %s", ESTR(errno));

	while (1) {
		libt_flush();

		ret = poll(fset, 2, libt_get_waittime());
		if (ret < 0)
			mylog(LOG_CRIT, "poll: %s", ESTR(errno));

		if (fset[0].revents) {
			/* signals */
			todo = NULL;

			ret = read(fset[0].fd, &info, sizeof(info));
			if (ret < 0)
				/* TODO: test for EAGAIN */
				mylog(LOG_CRIT, "read signalfd: %s", ESTR(errno));
			switch (info.ssi_signo) {
			case SIGCHLD:
				/* reap lost children */
				while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
					if (rcpid == pid)
						rcpid = 0;
					/* find service */
					for (svc = svcs; svc; svc = svc->next) {
						if (pid != svc->pid)
							continue;
						svc->pid = 0;
						if (svc->flags & FL_REMOVE) {
							cleanup_svc(svc);
							break;
						}
						if (svc->flags & FL_INTERVAL) {
							libt_add_timeout(svc->interval, exec_svc, svc);
						} else if ((svc->starttime + 2) < libt_now()) {
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
			case SIGUSR1:
				todo = todo ?: "halt";
			case SIGINT:
				todo = todo ?: "reboot";
			case SIGTERM:
				todo = todo ?: "poweroff";

				if (rcpid > 0)
					/* kill pending rc.init/rc.shutdown */
					kill(-rcpid, SIGTERM);
				if (getpid() != 1)
					exit(0);
				mylog(LOG_INFO, "%s ...", todo);
				rcpid = fork();
				if (rcpid < 0)
					mylog(LOG_CRIT, "fork: %s", ESTR(errno));
				else if (!rcpid) {
					sigprocmask(SIG_SETMASK, &savedset, NULL);
					execl(STOP, STOP, todo, NULL);
					mylog(LOG_CRIT, "execl %s %s: %s", ESTR(errno), STOP, todo);
				}
				break;
			case SIGHUP:
				/* retry throttled services */
				mylog(LOG_INFO, "reload ...");
				for (svc = svcs; svc; svc = svc->next) {
					if (!svc->pid && (svc->delay[1] ||
						(svc->flags & FL_INTERVAL))) {
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
					cmsg->cmsg_type == SCM_CREDENTIALS) {
				/* instead of accessing the data directly, and
				 * issuing a 'breaking strict aliasing' compiler
				 * warning, I decided to do this the proper way
				 */
				struct ucred uc = { .uid = ~0, .gid = ~0, .pid = ~0, };

				memcpy(&uc, CMSG_DATA(cmsg), sizeof(uc));
				peeruid = uc.uid;
			} else {
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
	execl(HELP, HELP, NULL);
	mylog(LOG_ERR, "execl %s", HELP);
	execlp("/bin/sh", "sh", NULL);
	mylog(LOG_ERR, "execvp /bin/sh");
	return EXIT_FAILURE;

}
