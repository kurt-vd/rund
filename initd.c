/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <signal.h>
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

#define NAME "initd"

static const char *const rcinitcmd[] = { "/etc/rc.init", NULL };
static const char *const rcrebootcmd[] = { "/etc/rc.shutdown", "reboot", NULL };
static const char *const rcpoweroffcmd[] = { "/etc/rc.shutdown", "poweroff", NULL };

#define elog(level, fmt, ...) \
	({\
		/*syslog(level, fmt "\n", ##__VA_ARGS__);*/\
		fprintf(stderr, "%s: " fmt "\n", NAME, ##__VA_ARGS__);\
		if (level < LOG_ERR)\
			exit(1);\
	})

#define ESTR(x) strerror(x)

/* globals */
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
		elog(0, "fork: %s", ESTR(errno));
		return -errno;
	} else if (pid == 0) {
		sigprocmask(SIG_SETMASK, &savedset, NULL);
		setsid();
		execvp(*argv, (char **)argv);
		elog(LOG_CRIT, "execvp: %s", ESTR(errno));
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
		elog(LOG_WARNING, "no watchdog device given");
		return -EINVAL;
	}
	wdt = malloc(sizeof(*wdt)+strlen(argv[1]));
	if (!wdt) {
		elog(LOG_ERR, "malloc failed: %s", ESTR(errno));
		return -errno;
	}
	wdt->fd = open(argv[1], O_RDONLY);
	if (wdt->fd < 0) {
		free(wdt);
		elog(LOG_ERR, "open %s: %s", argv[1], ESTR(errno));
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
		elog(LOG_WARNING, "no watchdog device given");
		return -EINVAL;
	}
	for (pwdt = &wdts; *pwdt; pwdt = &(*pwdt)->next) {
		if (!strcmp((*pwdt)->file, argv[1])) {
			wdt = *pwdt;
			if (peeruid && (wdt->owner != peeruid)) {
				elog(LOG_ERR, "remove %s: %s", argv[1], ESTR(EPERM));
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
		elog(LOG_INFO, "resume %s", *svc->argv);

	ret = fork();
	if (ret < 0) {
		elog(LOG_ERR, "fork: %s", ESTR(errno));
		/* postpone for 1 second always, no incremental delay */
		libt_add_timeout(1, exec_svc, svc);
	} else if (ret > 0) {
		svc->starttime = libt_now();
		svc->pid = ret;
	} else {
		/* child */
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
				elog(LOG_CRIT, "unknown uid %i", svc->uid);
			if (initgroups(pw->pw_name, pw->pw_gid) < 0)
				elog(LOG_CRIT, "initgroups for %s: %s", pw->pw_name, ESTR(errno));
			if (setgid(pw->pw_gid) < 0)
				elog(LOG_CRIT, "setgid %i: %s", pw->pw_gid, ESTR(errno));
			if (setuid(pw->pw_gid) < 0)
				elog(LOG_CRIT, "setuid %i: %s", svc->uid, ESTR(errno));
			setenv("HOME", pw->pw_dir, 1);
			setenv("USER", pw->pw_name, 1);
		}
		execvp(*svc->argv, svc->argv);
		elog(LOG_CRIT, "execvp: %s", ESTR(errno));
		_exit(EXIT_FAILURE);
	}
}

static int cmd_add(int argc, char *argv[])
{
	struct service *svc;
	int j;

	if (myuid && peeruid && (myuid != peeruid))
		/* block on regular user mismatch */
		return -EPERM;
	svc = malloc(sizeof(*svc));
	if (!svc)
		return -ENOMEM;
	memset(svc, 0, sizeof(*svc));
	svc->uid = peeruid;
	/* copy args */
	svc->args = malloc(sizeof(char *)*(argc-1+1));
	for (j = 1; j < argc; ++j) {
		svc->args[j-1] = strdup(argv[j]);
		if (!svc->argv && !strchr(argv[j-1], '='))
			svc->argv = &svc->args[j-1];
	}
	svc->args[j-1] = NULL;
	if (!svc->argv)
		svc->argv = svc->args;

	/* add in linked list */
	svc->next = svcs;
	svcs = svc;
	elog(LOG_INFO, "start '%s'", *svc->argv);
	/* exec now */
	exec_svc(svc);
	return svc->pid;
}

static void cleanup_svc(struct service *svc)
{
	struct service **psvc;
	int j;

	elog(LOG_INFO, "remove '%s'", *svc->argv);
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

	if (!argv[1])
		/* do not 'implicitely' remove all svcs */
		return -EINVAL;
	for (svc = find_svc(svcs, argv); svc; svc = find_svc(nsvc, argv)) {
		nsvc = svc->next;
		if (peeruid && (svc->uid != peeruid))
			continue;
		if (svc->pid) {
			elog(LOG_INFO, "stop '%s'", *svc->argv);
			kill(svc->pid, SIGTERM);
			svc->flags |= FL_REMOVE;
		} else {
			libt_remove_timeout(exec_svc, svc);
			cleanup_svc(svc);
		}
		++ndone;
	}
	return ndone ?: -ENOENT;
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
	{ },
};

/* main process */
int main(int argc, char *argv[])
{
	int ret, sock;
	struct service *svc;
	pid_t rcinitpid, pid;
	struct pollfd fset[] = {
		{ .events = POLLIN, },
		{ .events = POLLIN, },
	};
	sigset_t set;
	struct sockaddr_un name = {
		.sun_family = AF_UNIX,
		.sun_path = "\0initd",
	};
	/* for signalfd */
	struct signalfd_siginfo info;
	/* for recvmsg */
	static char buf[16*1024];
	static char resp[128];
	struct sockaddr_un peername;
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
#endif
	myuid = getuid();
	chdir("/");
	/* setup signals */
	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, &savedset);
	ret = fset[0].fd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
	if (ret < 0)
		/* TODO: start emergency shell */
		elog(LOG_ERR, "signalfd failed: %s", ESTR(errno));

	/* open server socket */
	fset[1].fd = sock = socket(PF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sock < 0)
		/* TODO: start emergency shell */
		elog(LOG_ERR, "socket(unix, ...) failed: %s", ESTR(errno));

	ret = bind(sock, (void *)&name, sizeof(name));
	if (ret < 0)
		/* TODO: start emergency shell */
		elog(LOG_ERR, "bind(@%s) failed: %s", name.sun_path+1, ESTR(errno));

	ret = 1;
	ret = setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &ret, sizeof(ret));
	if (ret < 0)
		/* TODO: start emergency shell */
		elog(LOG_ERR, "setsockopt SO_PASSCRED failed: %s", ESTR(errno));

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
			elog(LOG_CRIT, "poll: %s", ESTR(errno));

		if (fset[0].revents) {
			/* signals */

			ret = read(fset[0].fd, &info, sizeof(info));
			if (ret < 0)
				/* TODO: test for EAGAIN */
				elog(LOG_CRIT, "read signalfd: %s", ESTR(errno));
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
							elog(LOG_WARNING, "restart '%s", *svc->argv);
						} else {
							int delay = (svc->delay[0] + svc->delay[1]) ?: 1;
							svc->delay[0] = svc->delay[1];
							svc->delay[1] = delay;
							libt_add_timeout(delay, exec_svc, svc);
							elog(LOG_WARNING, "throttle '%s", *svc->argv);
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
				elog(LOG_INFO, "reboot ...");
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
				elog(LOG_INFO, "poweroff ...");
				spawn(rcpoweroffcmd);
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
					elog(LOG_WARNING, "recv ctrldat: %s", ESTR(errno));
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
				elog(LOG_WARNING, "no command supplied!");
				ret = -EINVAL;
				goto sock_reply;
			}

			/* lookup command */
			for (cmd = cmds; cmd->name; ++cmd)
				if (!strcmp(cmd->name, *args))
					break;
			if (!cmd->name) {
				elog(LOG_WARNING, "command '%s' unknown", *args);
				ret = -ENOENT;
				goto sock_reply;
			}
			/* run command */
			ret = cmd->fn(nargs, args);
sock_reply:
			if (!msg.msg_namelen)
				/* anonymous socket, skip reply */
				goto sock_done;
			ret = snprintf(resp, sizeof(resp), "%i", ret);
			ret = sendto(fset[1].fd, resp, ret, 0, (void *)&peername, msg.msg_namelen);
			if (ret < 0)
				elog(LOG_ERR, "sendto %c%s: %s", peername.sun_path[0] ?: '@',
						peername.sun_path+1, ESTR(errno));
sock_done:
			; /* empty statement */
		}
	}
	/* not reachable */
	return EXIT_SUCCESS;
}
