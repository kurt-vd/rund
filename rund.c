/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <math.h>
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
#include "lib/libtimechange.h"

#define NAME "rund"

#define INIT "/etc/rc.init"
#define STOP "/etc/rc.shutdown"
#define HELP "/sbin/sulogin"

static int consolevalid;
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
	else if (consolevalid && level <= loglevel)
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
static int nullfd = -1;
static void set_nullfd(void)
{
	if (nullfd >= 0)
		return;
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd < 0)
		mylog(LOG_WARNING, "open %s: %s", "/dev/null", ESTR(errno));
	else if (consolevalid) {
		dup2(nullfd, STDIN_FILENO);
		close(nullfd);
		nullfd = STDIN_FILENO;
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

static int cmd_watchdog(int argc, char *argv[], int cookie)
{
	struct wdt *wdt, **pwdt;
	int ret, result;
	const char *device;

	if (peeruid)
		return -EPERM;
	if (argc < 3) {
		mylog(LOG_WARNING, "no watchdog device given");
		return -EINVAL;
	}
	device = argv[2];

	if (!strcmp(argv[1], "remove")) {
		for (result = 0, pwdt = &wdts; *pwdt;) {
			if (!strcmp((*pwdt)->file, device) || !strcmp(device, "all")) {
				wdt = *pwdt;
				/* remove from linked list */
				*pwdt = (*pwdt)->next;
				libt_remove_timeout(do_watchdog, wdt);
				/* clean exit */
				write(wdt->fd, "V", 1);
				close(wdt->fd);
				free(wdt);
				++result;
			} else {
				pwdt = &(*pwdt)->next;
			}
		}
		return result ?: -ENOENT;

	} else if (!strcmp(argv[1], "pause") || !strcmp(argv[1], "stop")) {
		for (result = 0, wdt = wdts; wdt; wdt = wdt->next) {
			if (!strcmp(wdt->file, device) || !strcmp(device, "all")) {
				libt_remove_timeout(do_watchdog, wdt);
				++result;
			}
		}
		return result ?: -ENOENT;

	} else if (!strcmp(argv[1], "resume") || !strcmp(argv[1], "start")) {
		for (result = 0, wdt = wdts; wdt; wdt = wdt->next) {
			if (!strcmp(wdt->file, device) || !strcmp(device, "all")) {
				do_watchdog(wdt);
				++result;
			}
		}
		return result ?: -ENOENT;

	} else if (!strcmp(argv[1], "change")) {
		for (result = 0, wdt = wdts; wdt; wdt = wdt->next) {
			if (!strcmp(wdt->file, device))
				break;
		}
		if (!wdt)
			return -ENOENT;
		if (argc < 4)
			return 0;
		result = 0;

		int timeout = strtoul(argv[3], 0, 0);
		if (timeout != wdt->timeout) {
			ret = ioctl(wdt->fd, WDIOC_SETTIMEOUT, &timeout);
			if (ret < 0) {
				mylog(LOG_ERR, "ioctl %s settimeout %i: %s", device,
						timeout, ESTR(errno));
				return -errno;
			}
			wdt->timeout = timeout;
			do_watchdog(wdt);
			++result;
		}
		return result;

	} else if (strcmp(argv[1], "add")) {
		mylog(LOG_WARNING, "unknown watchdog command '%s'", argv[1]);
		return -EINVAL;
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
		#define FL_REMOVE	(1 << 0)
		#define FL_INTERVAL	(1 << 1)
		#define FL_PAUSED	(1 << 2)
		#define FL_KILLSPEC	(1 << 3)
		#define FL_ONESHOT	(1 << 4)
		#define FL_LAZY_INTERVAL	(1 << 5)
		#define FL_MANUAL_REQ	(1 << 30)
	double starttime;
	/* memory to decide throttling delay
	 * based on fibonacci numbers
	 */
	unsigned long delay[2];
	/* memory to decide for throttling */
	#define MAXTIMES 3
	double times[MAXTIMES];
	int ntimes, ptimes;

	char **args;
	char **argv;
	char *name;
	int uid;
	double interval, toffset;
	/* end-of-life state */
	int killhup;
	int killgrpdelay, killharddelay;

	/* message to log on next start */
	const char *startmsg;
};

/* fibonacci numbers utilities */
static unsigned long fibonacci_next(unsigned long fib[2])
{
	unsigned long sum;

	sum = fib[0] + fib[1];
	fib[0] = fib[1];
	fib[1] = sum;
	return sum;
}
static void fibonacci_reset(unsigned long fib[2])
{
	fib[0] = 0;
	fib[1] = 1;
}

static inline int svc_throttled(const struct service *svc)
{
	return svc->delay[0] != 0;
}

/* global list */
static struct service *svcs;
static int gkillgrpdelay, gkillharddelay;

/* utils */
static inline int svckillgrpdelay(const struct service *svc)
{
	return (svc->flags & FL_KILLSPEC) ? svc->killgrpdelay : gkillgrpdelay;
}
static inline int svckillharddelay(const struct service *svc)
{
	return (svc->flags & FL_KILLSPEC) ? svc->killharddelay : gkillharddelay;
}

static void exec_svc(void *dat)
{
	struct service *svc = dat;
	int ret, j;

	if (nullfd < 0)
		set_nullfd();
	if (svc->startmsg)
		mylog(LOG_INFO, "%s '%s'", svc->startmsg, svc->name);

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

		/* insert our start reason to the service */
		setenv("RUND_INFO", svc->startmsg ?: "", 1);

		/* child */
		/* redirect stdout & stderr to /dev/null
		 * We know stdin is /dev/null.
		 * stdout & stderr still default to /dev/console
		 * and may have been redirected,
		 * Prevent redirect with environment DETACH=0
		 */
		if (strcmp(getenv("DETACH") ?: "1", "0")) {
			dup2(nullfd, STDOUT_FILENO);
			dup2(nullfd, STDERR_FILENO);
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
		mylog(LOG_CRIT, "execvp %s: %s", svc->name, ESTR(errno));
		_exit(EXIT_FAILURE);
	}
	svc->startmsg = NULL;
}

static struct service *svc_exists(struct service *dut)
{
	struct service *svc;
	int j;

	for (svc = svcs; svc; svc = svc->next) {
		if (svc->uid != dut->uid)
			continue;
		if ((svc->flags & FL_REMOVE) ||
				((svc->flags & FL_ONESHOT) && svc->pid))
			/* ignore services about to be removed */
			continue;

		for (j = 0; svc->args[j] && dut->args[j]; ++j) {
			if (strcmp(svc->args[j], dut->args[j]))
				break;
		}
		if (!svc->args[j] && !dut->args[j])
			return svc;
	}
	return NULL;
}

static int cmd_add(int argc, char *argv[], int cookie)
{
	struct service *svc, *svc2;
	int j, f, result = 0;
	char *endp;
	char *tok;
	double delay = 0;

	if (myuid && peeruid && (myuid != peeruid))
		/* block on regular user mismatch */
		return -EPERM;
	svc = malloc(sizeof(*svc));
	if (!svc)
		return -ENOMEM;
	memset(svc, 0, sizeof(*svc));
	fibonacci_reset(svc->delay);
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
			svc->interval = strtod(strtok(argv[j]+9, ",;") ?: "0", NULL);
			svc->toffset = strtod(strtok(NULL, ",;") ?: "nan", NULL);
			for (tok = strtok(NULL, ",;"); tok; tok = strtok(NULL, ",;")) {
				if (!strcmp(tok, "lazy"))
					svc->flags |= FL_LAZY_INTERVAL;
			}
			svc->flags |= FL_INTERVAL;
			continue;
		} else if (!svc->argv && !strncmp("DELAY=", argv[j], 6)) {
			delay = strtod(argv[j]+6, NULL);
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
				svc->pid = 0;
			continue;
		} else if (!strcmp("PAUSED=1", argv[j])) {
			svc->flags |= FL_PAUSED;
			continue;
		} else if (!strncmp("KILL=", argv[j], 5)) {
			int consumed = 5;
			if (!strcasecmp(&argv[j][consumed], "HUP")) {
				svc->killhup = 1;
				consumed += 3;
				if (argv[j][consumed] == ',')
					++consumed;
			}
			svc->killgrpdelay = strtoul(argv[j]+consumed, &endp, 0);
			if (*endp == ',')
				svc->killharddelay = strtoul(endp+1, NULL, 0);
			svc->flags |= FL_KILLSPEC;
			continue;
		} else if (!strcmp("ONESHOT=1", argv[j])) {
			svc->flags |= FL_ONESHOT;
			continue;
		}
		svc->args[f] = strdup(argv[j]);
		/* some additional processing */
		if (!svc->argv && !strncmp("NAME=", svc->args[f], 5))
			svc->name = svc->args[f]+5;
		if (!svc->argv && !strchr(svc->args[f], '=')) {
			svc->argv = svc->args+f;
			if (!svc->name)
				svc->name = *svc->argv;
		}
		++f;
	}
	svc->args[f] = NULL;
	if (!svc->argv)
		svc->argv = svc->args;
	if (svc_exists(svc)) {
		result = -EEXIST;
		goto failed;
	}

	/* add in linked list */
	svc->next = svcs;
	svcs = svc;
	/* decide to start */
	if (svc->pid)
		mylog(LOG_INFO, "import '%s'", svc->name);
	else if (delay > 0) {
		/* schedule initial delay */
		mylog(LOG_INFO, "scheduled '%s'", svc->name);
		svc->startmsg = "start";
		libt_add_timeout(delay, exec_svc, svc);
	} else if (svc->flags & FL_PAUSED) {
		mylog(LOG_INFO, "declared '%s'", svc->name);
	} else {
		mylog(LOG_INFO, "add '%s'", svc->name);
		/* exec now */
		svc->startmsg = "start";
		exec_svc(svc);
	}
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

static struct service *find_svc3(struct service *svcs, char *args[], int accept_removing)
{
	struct service *svc;
	int j, k;

	if (!args)
		return NULL;

	for (svc = svcs; svc; svc = svc->next) {
		if (!accept_removing && (svc->flags & FL_REMOVE))
			/* do not return a removing service */
			continue;
		if (!strcmp(args[0] ?: "", "*"))
			/* wildcard matches all */
			return svc;
		for (j = 0; args[j]; ++j) {
			if (!strcmp(args[j], svc->name))
				/* argument may be name */
				continue;
			if (!strncmp(args[j], "PID=", 4)) {
				if (strtoul(args[j]+4, NULL, 0) != svc->pid)
					goto nomatch;
				continue;
			}
			if (!strcmp(args[j], "REMOVING=1")) {
				if (!(svc->flags & FL_REMOVE))
					goto nomatch;
				continue;
			}
			if (!strcmp(args[j], "PAUSING=1")) {
				if (!(svc->flags & FL_PAUSED) || !svc->pid)
					goto nomatch;
				continue;
			}
			if (!strcmp(args[j], "ONESHOT=1")) {
				if (!(svc->flags & FL_ONESHOT))
					goto nomatch;
				continue;
			}
			if (!strncmp(args[j], "DELAY=", 6)) {
				/* DELAY=XYZ is not saved, no test possible */
				continue;
			}
			for (k = 0; svc->args[k]; ++k) {
				if (!strcmp(args[j], svc->args[k]))
					break;
				if (svc->args+k < svc->argv && !strncmp(svc->args[k], "NAME=", 5) &&
						!strcmp(svc->args[k]+5, args[j]))
						/* match any NAME=xxx environment variable*/
						break;
			}
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
static inline struct service *find_svc(struct service *svcs, char *args[])
{
	return find_svc3(svcs, args, 0);
}

static void killhard(void *dat)
{
	struct service *svc = dat;

	mylog(LOG_INFO, "kill-hard '%s'", svc->name);
	kill(-svc->pid, SIGKILL);
}

static void killgrp(void *dat)
{
	struct service *svc = dat;

	mylog(LOG_INFO, "kill-grp '%s'", svc->name);
	kill(-svc->pid, SIGTERM);
	if (svckillharddelay(svc))
		libt_add_timeout(svckillharddelay(svc), killhard, svc);
}

static int cmd_remove(int argc, char *argv[], int cookie)
{
	struct service *svc, *nsvc;
	int ndone = 0;
	int err = ENOENT;

	if (!argv[1])
		/* do not 'implicitely' remove all svcs */
		return -EINVAL;
	for (svc = find_svc(svcs, argv+1); svc; svc = find_svc(nsvc, argv+1)) {
		nsvc = svc->next;
		if (peeruid && (svc->uid != peeruid)) {
			/* change returned error into 'permission ...' */
			err = EPERM;
			continue;
		}
		if (svc->pid) {
			mylog(LOG_INFO, "kill '%s'", svc->name);
			kill(svc->pid, SIGTERM);
			svc->flags |= FL_REMOVE;
			if (svckillgrpdelay(svc))
				libt_add_timeout(svckillgrpdelay(svc), killgrp, svc);
			else if (svckillharddelay(svc))
				libt_add_timeout(svckillharddelay(svc), killhard, svc);
		} else {
			mylog(LOG_INFO, "remove '%s'", svc->name);
			libt_remove_timeout(exec_svc, svc);
			cleanup_svc(svc);
		}
		++ndone;
	}
	return ndone ?: -err;
}

static int cmd_reload(int argc, char *argv[], int cookie)
{
	struct service *svc;
	int ndone = 0, err = 0;

	for (svc = find_svc(svcs, argv+1); svc; svc = find_svc(svc->next, argv+1)) {
		if (peeruid && (svc->uid != peeruid)) {
			/* change returned error into 'permission ...' */
			err = EPERM;
			continue;
		}
		if (svc->flags & FL_PAUSED)
			/* ignore paused svc */
			continue;

		if (!svc->pid) {
			/* re-schedule immediate */
			libt_remove_timeout(exec_svc, svc);
			svc->startmsg = "manual";
			libt_add_timeout(0, exec_svc, svc);
			++ndone;

		} else if (svc->flags & FL_INTERVAL) {
			svc->flags |= FL_MANUAL_REQ;
			++ndone;
		}
	}
	return ndone ?: -err;
}

#define COOKIE_PAUSE	1
#define COOKIE_RESUME	2
static int cmd_pause(int argc, char *argv[], int cookie)
{
	struct service *svc;
	int ndone = 0, err = 0;

	if (!argv[1])
		/* do not 'implicitely' pause all svcs */
		return -EINVAL;
	for (svc = find_svc(svcs, argv+1); svc; svc = find_svc(svc->next, argv+1)) {
		if (peeruid && (svc->uid != peeruid)) {
			/* change returned error into 'permission ...' */
			err = EPERM;
			continue;
		}
		if ((cookie & COOKIE_PAUSE) && !(svc->flags & FL_PAUSED)) {
			mylog(LOG_INFO, "stop '%s'", svc->name);
			svc->flags |= FL_PAUSED;
			libt_remove_timeout(exec_svc, svc);
			if (svc->pid) {
				mylog(LOG_INFO, "kill '%s'", svc->name);
				kill(svc->pid, SIGTERM);
				if (svckillgrpdelay(svc))
					libt_add_timeout(svckillgrpdelay(svc), killgrp, svc);
				else if (svckillharddelay(svc))
					libt_add_timeout(svckillharddelay(svc), killhard, svc);
			}
			++ndone;
		}
		if ((cookie & COOKIE_RESUME) && ((svc->flags & FL_PAUSED) || !svc->pid)) {
			svc->flags &= ~FL_PAUSED;
			fibonacci_reset(svc->delay);
			if (!svc->pid)
				libt_add_timeout(0, exec_svc, svc);
			svc->startmsg = "start";
			++ndone;
		}
	}
	return ndone ?: -err;
}

static int cmd_syslog(int argc, char *argv[], int cookie)
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
		openlog("rund", 0, LOG_DAEMON);
		syslog_open = 1;
	}
	return 0;
}

static int cmd_loglevel(int argc, char *argv[], int cookie)
{
	if (myuid != (peeruid ?: myuid))
		return -EPERM;
	if (argc > 1) {
		loglevel = strtoul(argv[1], NULL, 0);
		setlogmask(LOG_UPTO(loglevel));
	}
	return loglevel;
}

static int cmd_redir(int argc, char *argv[], int cookie)
{
	int ret, fd;

	if (myuid != (peeruid ?: myuid))
		return -EPERM;

	if (argc < 2)
		return -EINVAL;
	if (!consolevalid)
		return -ENOTTY;
	fd = open(argv[1], O_WRONLY | O_NOCTTY | O_APPEND | O_CREAT, 0666);
	if (fd < 0) {
		ret = errno;
		mylog(LOG_WARNING, "open %s: %s", argv[1], ESTR(errno));
		return -ret;
	}
	ret = 0;
	if (dup2(fd, STDOUT_FILENO) < 0) {
		ret = -errno; /* save errno for later return */
		mylog(LOG_WARNING, "dup2 %s stdout: %s", argv[1], ESTR(errno));
	}
	if (dup2(fd, STDERR_FILENO) < 0) {
		ret = -errno; /* save errno for later return */
		mylog(LOG_WARNING, "dup2 %s stdout: %s", argv[1], ESTR(errno));
	}
	close(fd);
	return ret;
}

static int cmd_env(int argc, char *argv[], int cookie)
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
static int cmd_status(int argc, char *argv[], int cookie)
{
	struct service *svc;
	struct wdt *wdt;
	int ndone = 0, err = 0, j, ret;
	char *bufp;
	char *options = "s";

	if (argv[1] && *argv[1] == '-') {
		options = argv[1];
		++argv;
	}
	if (strpbrk(options ?: "", "aw"))
	/* add watchdogs */
	for (wdt = wdts; wdt; wdt = wdt->next) {
		bufp = sbuf;
		if (strchr(options, 'q')) {
			/* quiet operation */
			++ndone;
			continue;
		}
		*bufp++ = '>';
		if (strchr(options, 'd')) {
			bufp += sprintf(bufp, "watchdog") +1;
			bufp += sprintf(bufp, "add") +1;
		}
		strcpy(bufp, wdt->file);
		bufp += strlen(bufp)+1;
		bufp += sprintf(bufp, "%i", wdt->timeout) +1;
		ret = sendto(sock, sbuf, bufp-sbuf, 0, (void *)&peername, peernamelen);
		if (ret < 0)
			return -errno;
		++ndone;
	}

	if (strpbrk(options, "as"))
	/* add services */
	for (svc = find_svc3(svcs, argv+1, 1); svc; svc = find_svc3(svc->next, argv+1, 1)) {
		if ((svc->flags & FL_REMOVE) && !strchr(options, 'x'))
			continue;
		if (peeruid && (svc->uid != peeruid)) {
			/* change returned error into 'permission ...' */
			err = EPERM;
			continue;
		}
		if (strchr(options, 'q')) {
			/* quiet operation */
			++ndone;
			continue;
		}
		bufp = sbuf;
		*bufp++ = '>';
		if (strchr(options, 'd'))
			bufp += sprintf(bufp, "add") +1;
		if (svc->pid)
			bufp += sprintf(bufp, "PID=%u", svc->pid) +1;
		if (svc->uid)
			bufp += sprintf(bufp, "USER=#%u", svc->uid) +1;
		if (svc->flags & FL_INTERVAL) {
			bufp += sprintf(bufp, "INTERVAL=%lf", svc->interval);
			if (!isnan(svc->toffset))
				bufp += sprintf(bufp, ",%lf", svc->toffset);
			if (svc->flags & FL_LAZY_INTERVAL)
				bufp += sprintf(bufp, ",lazy");
			bufp += 1;
		}
		if (svc->flags & FL_REMOVE)
			bufp += sprintf(bufp, "REMOVING=1") +1;
		if (svc->flags & FL_PAUSED)
			bufp += sprintf(bufp, "PAUSED=1") +1;
		if (svc->flags & FL_KILLSPEC) {
			bufp += sprintf(bufp, "KILL=");
			if (svc->killhup)
				bufp += sprintf(bufp, "HUP");
			if (svc->killhup && (svc->killgrpdelay || svc->killharddelay))
				*bufp++ = ',';
			if (svc->killgrpdelay)
				bufp += sprintf(bufp, "%i", svc->killgrpdelay);
			if (svc->killharddelay)
				bufp += sprintf(bufp, ",%i", svc->killharddelay);
			/* add null terminator */
			bufp += 1;
		}
		if (svc->flags & FL_ONESHOT)
			bufp += sprintf(bufp, "ONESHOT=1") +1;
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

static int cmd_exec(int argc, char *argv[], int cookie)
{
	if (myuid != (peeruid ?: myuid))
		return -EPERM;
	if (argc < 2)
		return -EINVAL;
	mylog(LOG_ERR, "request to exec %s ...", argv[1]);

	/* send ack now that it is still possible */
	if (sendto(sock, "0", 1, 0, (void *)&peername, peernamelen) < 0)
		return -errno;

	sigprocmask(SIG_SETMASK, &savedset, NULL);
	execvp(argv[1], argv+1);
	mylog(LOG_ERR, "execvp() failed: %s", ESTR(errno));
	return -errno;
}

static double maxthrottle = INFINITY;
static int cmd_maxthrottle(int argc, char *argv[], int cookie)
{
	double value;

	if (myuid != (peeruid ?: myuid))
		return -EPERM;
	if (argc <= 1)
		return -EINVAL;
	value = strtod(argv[1], NULL);
	if (value < 60)
		return -EINVAL;
	maxthrottle = value;
	mylog(LOG_NOTICE, "maxthrottle changed to %.0lf", maxthrottle);
	return 0;
}

static int cmd_setkill(int argc, char *argv[], int cookie)
{
	if (argc <= 1)
		return -EINVAL;

	gkillgrpdelay = strtoul(argv[1], NULL, 0);
	if (argc > 2)
		gkillharddelay = strtoul(argv[2], NULL, 0);
	else
		gkillharddelay = 0;
	mylog(LOG_NOTICE, "global kill spec set to %u,%u", gkillgrpdelay, gkillharddelay);
	return 0;
}

/* remote commands */
struct cmd {
	const char *name;
	int (*fn)(int argc, char *argv[], int cookie);
	int cookie;
} static const cmds[] = {
	{ "watchdog", cmd_watchdog, },
	{ "add", cmd_add, },
	{ "remove", cmd_remove, },
	{ "reload", cmd_reload, },
	{ "manual", cmd_reload, },
	{ "pause", cmd_pause, COOKIE_PAUSE, },
	{ "suspend", cmd_pause, COOKIE_PAUSE, },
	{ "resume", cmd_pause, COOKIE_RESUME, },
	{ "stop", cmd_pause, COOKIE_PAUSE, },
	{ "start", cmd_pause, COOKIE_RESUME, },
	{ "restart", cmd_pause, COOKIE_PAUSE | COOKIE_RESUME, },
	/* management commands */
	{ "maxthrottle", cmd_maxthrottle, },
	{ "setkill", cmd_setkill, },
	{ "syslog", cmd_syslog, },
	{ "loglevel", cmd_loglevel, },
	{ "redir", cmd_redir, },
	{ "env", cmd_env, },
	{ "status", cmd_status, },
	{ "exec", cmd_exec, },
	{ },
};

/* statistics */
static double svc_throttle_time(struct service *svc, double texec)
{
	/* maintain stats */
	if (svc->ntimes < MAXTIMES)
		svc->times[svc->ntimes++] = texec;
	else {
		svc->times[svc->ptimes++] = texec;
		svc->ptimes %= MAXTIMES;
	}

	if (texec < 1)
		/* too short, throttle */
		return fmin(fibonacci_next(svc->delay), maxthrottle);

	if (svc->ntimes <= 1)
		return 0;

	/* take average */
	double sum, ssum, mean, dev;
	int n;
	for (n = 0, sum = ssum = 0; n < svc->ntimes; ++n) {
		sum += svc->times[n];
		ssum += svc->times[n]*svc->times[n];
	}
	mean = sum/n;
	dev = sqrt((ssum/n)-mean*mean);

	if (svc->ntimes > 1 && fabs(dev/mean) < 0.1)
		/* systematic failure suspected, throttle */
		return fmin(fibonacci_next(svc->delay)*mean, maxthrottle);

	/* reset throttling */
	fibonacci_reset(svc->delay);
	return 0;
}

/* main process */
int main(int argc, char *argv[])
{
	int ret;
	struct service *svc;
	pid_t rcpid, pid;
	struct pollfd fset[] = {
		{ .events = POLLIN, },
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

	/* test if console if valid
	 * avoid using stdio if not
	 */
	consolevalid = fset[0].fd > STDERR_FILENO;

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

	/* monitor clock changes */
	fset[2].fd = ret = libtimechange_makefd();
	if (ret < 0) {
		mylog(LOG_ERR, "timerfd for walltime failed: %s", ESTR(errno));
		goto emergency;
	}
	ret = libtimechange_arm(fset[2].fd);
	if (ret < 0) {
		mylog(LOG_ERR, "arm walltime timer failed: %s", ESTR(errno));
		goto emergency;
	}

	/* launch system start */
	int mypid = getpid();
	if ((mypid != 1) && (argc <= 2)) {
		rcpid = 0;
	} else if ((rcpid = fork()) == 0) {
		sigprocmask(SIG_SETMASK, &savedset, NULL);
		if (mypid == 1)
			argv[0] = INIT;
		else {
			name.sun_path[0] = '@';
			setenv("RUND_SOCK", name.sun_path, 1);
			argv += 2;
		}
		execvp(*argv, argv);
		mylog(LOG_CRIT, "execvp %s: %s", ESTR(errno), *argv);
	} else if (rcpid < 0)
		mylog(LOG_CRIT, "fork: %s", ESTR(errno));

	/* Clear the environment.
	 * boot parameters & environment values have been passed to INIT already.
	 * INIT should provide back relevant environment variables.
	 */
	clearenv();

	while (1) {
		libt_flush();

		ret = poll(fset, 3, libt_get_waittime());
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
						if (pid == svc->pid)
							break;
					}
					if (!svc)
						continue;
					/* remove scheduled kill's */
					libt_remove_timeout(killgrp, svc);
					libt_remove_timeout(killhard, svc);
					/* found svc */
					svc->pid = 0;

					if (svc->flags & (FL_REMOVE | FL_ONESHOT)) {
						if (!(svc->flags & FL_REMOVE))
							/* notify 'unexpected' end */
							mylog(LOG_WARNING, "'%s' ended", svc->name);
						else
							mylog(LOG_INFO, "removed '%s'", svc->name);
						cleanup_svc(svc);

					} else if (svc->flags & FL_PAUSED) {
						; /* do nothing */

					} else if (svc->flags & FL_INTERVAL) {
						double delay;

						delay = svc->interval;
						svc->startmsg = "wakeup";
						if (!isnan(svc->toffset)) {
							double strict_offset;
							double wall = libt_walltime();

							if (svc->flags & FL_LAZY_INTERVAL)
								strict_offset = 0;
							else
								strict_offset = libt_now() - svc->starttime;

							/* use localtime-synchronised delay
							 * schedule next since previous start
							 */
							delay = libt_timetointerval4(wall - strict_offset, svc->interval, svc->toffset, 1);
							delay -= strict_offset;
						}
						if ((delay > 1) && (svc->flags & FL_MANUAL_REQ)) {
							svc->startmsg = "manual";
							delay = 0;
						}
						svc->flags &= ~FL_MANUAL_REQ;
						libt_add_timeout(delay, exec_svc, svc);
					} else {
						double delay = svc_throttle_time(svc, libt_now() - svc->starttime);

						if (svc_throttled(svc)) {
							mylog(LOG_WARNING, "throttle '%s'", svc->name);
							svc->startmsg = "iterate";
						} else
							svc->startmsg = "restart";
						libt_add_timeout(delay, exec_svc, svc);
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
				cmd_reload(2, (char *[]){ "reload", "*", NULL, }, 0);
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
			ret = cmd->fn(nargs, args, cmd->cookie);
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
		if (fset[2].revents) {
			int n = 0;

			for (svc = svcs; svc; svc = svc->next) {
				if (!svc->pid && (svc->flags & FL_INTERVAL) &&
					!isnan(svc->toffset)) {
					double delay;

					delay = libt_timetointerval4(libt_walltime(), svc->interval, svc->toffset, 1);
					/* reschedule */
					libt_add_timeout(delay, exec_svc, svc);
					++n;
				}
			}
			mylog(LOG_NOTICE, "walltime changed, %i rescheduled", n);
			ret = libtimechange_arm(fset[2].fd);
			if (ret < 0)
				mylog(LOG_ERR, "arm walltime timer failed: %s", ESTR(errno));
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
