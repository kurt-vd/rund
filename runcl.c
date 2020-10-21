/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define NAME "runcl"

#define LOG_ERR	1
#define LOG_INFO 3
#define mylog(level, fmt, ...) \
	({\
		fprintf(stderr, "%s: " fmt "\n", NAME, ##__VA_ARGS__);\
		if (level <= LOG_ERR)\
			exit(1);\
	})

#define ESTR(x) strerror(x)

/* program options */
static const char help_msg[] =
	NAME ": control utility for rund\n"
	"usage:	" NAME " [OPTIONS ...] CMD [ARGS]\n"
	"\n"
	"Options:\n"
	" -V	Show version\n"
	" -q	Quiet, don't print replies\n"
	" -Q	Quiet bis, don't print failures\n"
	"	To be used to just issue a command without expectations\n"
	" -r[DELAY]	Repeat command each DELAY secs (default 1.0)\n"
	"		until 0 is returned\n"
	" -mDELAY	Repeat Maximum during DELAY secs\n"
	" -sSOCK	Use alternative socket SOCK\n"
	"\n"
	"Commands:\n"
	" watchdog add DEVICE [TIMEOUT]\n"
	"	Add a watchdog trigger with a specific timeout\n"
	" watchdog remove|pause|stop|resume|start DEVICE|all\n"
	"	Remove, start or stop a watchdog\n"
	"	A watchdog is started when added\n"
	" watchdog change DEVICE TIMEOUT\n"
	"	Change the timeout of a watchdog\n"
	" add [KEY=VALUE ...] PROGRAM [ARGUMENT ...]\n"
	"	Add a new service\n"
	"	Special environment variables:\n"
	"	NAME=	Specify label (default is to use PROGRAM)\n"
	"	USER=	to run as different user\n"
	"	KILL=[HUP[,]][GRP][,HARD] Add group-kill and/or hard-kill delays\n"
	"			'HUP' will replace the initial SIGTERM with SIGHUP\n"
	"			usefull for shell-script services\n"
	"	INTERVAL=DELAY	wait DELAY before respawn\n"
	"	INTERVAL=TIME,OFFS	run when localtime passes TIME+OFF\n"
	"			eg. 1d,4h will run each day at 4h\n"
	"			    1h,-5m will run each hour at 55m\n"
	"	DELAY=		to wait a little before running\n"
	"	PAUSED=1	to start suspended\n"
	"	ONESHOT=1	to start a single run\n"
	" remove [KEY=VALUE ...] [PROGRAM] [ARGUMENT ...]\n"
	"	Remove a service\n"
	" remove *\n"
	"	Remove all services\n"
	" reload|manual [KEY=VALUE ...] [PRORAM] [ARGUMENT ...]\n"
	"	Retries a throttled service once\n"
	" stop|pause|suspend [KEY=VALUE ...] [PRORAM] [ARGUMENT ...]\n"
	"	Stops a service, but do not forget about it\n"
	" start|resume [KEY=VALUE ...] [PRORAM] [ARGUMENT ...]\n"
	"	resumes a service\n"
	" restart [KEY=VALUE ...] [PRORAM] [ARGUMENT ...]\n"
	"	Stops and starts a service\n"
	" maxthrottle VALUE\n"
	"	put a ceiling on throttling delays for all services\n"
	" setkill GRPKILLDELAY [HARDKILLDELAY]\n"
	"	change global group-kill delay and hard-kill delay\n"
	" syslog\n"
	" loglevel\n"
	" redir\n"
	" env KEY[=VALUE]\n"
	"	Change environment variable\n"
	" env KEY=\n"
	"	unset environment variable\n"
	" status [-wsadxq] [KEY=VALUE] [PROGRAM] [ARGUMENT ...]\n"
	"	Retrieve status from rund\n"
	"	options:\n"
	"	(w)atchdogs|(s)ervices|(a)ll\n"
	"	(d)ump (q)uiet\n"
	"	(x)include removed-but-not-yet-terminated services\n"
	" exec PROGRAM [ARGUMENT ...]\n"
	"	exec() another program, possible the same\n"
	"	This solves the case where pid 1 has open files\n"
	"	that were removed, which keeps the filesystem busy\n"
	"	for writing\n"
	;
static const char optstring[] = "+?VqQr::m:s:";

/* comm timeout */
static void sigalrm(int sig)
{
	mylog(LOG_ERR, "timeout communicating");
	/* should have exited here */
	exit(1);
}

/* convenience wrapper for send with SCM_CREDENTIALS */
static int sendcred(int sock, const void *dat, unsigned int len, int flags)
{
	struct ucred *pcred;
	union {
		struct cmsghdr hdr;
		char dat[CMSG_SPACE(sizeof(struct ucred))];
	} cmsg = {
		.hdr.cmsg_len = CMSG_LEN(sizeof(struct ucred)),
		.hdr.cmsg_level = SOL_SOCKET,
		.hdr.cmsg_type = SCM_CREDENTIALS,
	};
	struct iovec iov = {
		.iov_base = (void *)dat,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = &cmsg,
		.msg_controllen = cmsg.hdr.cmsg_len,
	};
	pcred = (void *)CMSG_DATA(&cmsg.hdr);
	pcred->pid = getpid();
	pcred->uid = getuid();
	pcred->gid = getgid();
	return sendmsg(sock, &msg, flags);
}

static int ttytest(void)
{
	int fd;

	fd = open("/dev/tty", O_RDWR);
	close(fd);
	/* /dev/tty can only open when a controlling terminal is opened,
	 * /dev/console is not one of them
	 */
	return fd >= 0;
}

/* main process */
int main(int argc, char *argv[])
{
	int ret, opt, sock, j, pos;
	struct sockaddr_un name = {
		.sun_family = AF_UNIX,
		.sun_path = "\0rund",
	};
	double repeat = NAN;
	int maxdelay = 0;
	time_t t0;
	int quiet, quietbis;

	/* prepare cmd */
	static char sbuf[16*1024], rbuf[16*1024];
	char *bufp, *str;

	/* assume quiet operation on non-terminal invocation */
	quiet = !ttytest();
	quietbis = 0;
	/* parse program options */
	while ((opt = getopt(argc, argv, optstring)) != -1)
	switch (opt) {
	case 'V':
		fprintf(stderr, "%s: %s\n", NAME, VERSION);
		return 0;
	case 'q':
		quiet = 1;
		break;
	case 'Q':
		quietbis = 1;
		break;
	case 'r':
		repeat = optarg ? strtod(optarg, NULL) : 1;
		if (!(repeat > 0))
			mylog(LOG_ERR, "bad rate '%s'", optarg);
		break;
	case 's':
		if (*optarg != '@')
			mylog(LOG_ERR, "bad socket name '%s'", optarg);
		strcpy(name.sun_path+1, optarg+1);
		break;
	case 'm':
		maxdelay = ceil(strtod(optarg, NULL));
		break;
	default:
		fprintf(stderr, "%s: option '%c' unrecognised\n", NAME, opt);
	case '?':
		fputs(help_msg, stderr);
		exit(1);
	}

	for (j = optind, bufp = sbuf; j < argc; ++j) {
		if (!strncmp("USER=", argv[j], 5) && argv[j][5] != '#') {
			/* translate users to ID, and relieve pid 1 from
			 * doing (possible time consuming over LDAP)
			 * user name lookups
			 */
			struct passwd *pw;

			pw = getpwnam(argv[j]+5);
			if (!pw)
				mylog(LOG_ERR, "user '%s' unknown", argv[j]+5);
			/* add the argument manually
			 * don't forget to add null terminator
			 */
			bufp += sprintf(bufp, "USER=#%u", pw->pw_uid)+1;
			continue;
		}
		strcpy(bufp, argv[j]);
		bufp += strlen(bufp)+1;
	}
	if (bufp <= sbuf)
		mylog(LOG_ERR, "no command specified");

	/* install timeout handler using sigalrm */
	signal(SIGALRM, sigalrm);

	/* open client socket */
	ret = sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ret < 0)
		mylog(LOG_ERR, "socket(unix, ...) failed: %s", ESTR(errno));
	/* connect to server */
	ret = connect(sock, (void *)&name, sizeof(name));
	if (ret < 0)
		mylog(LOG_ERR, "connect(@%s) failed: %s", name.sun_path+1, ESTR(errno));

	str = name.sun_path+1;
	str += strlen(str);
	sprintf(str, "-%i", getpid());
	ret = bind(sock, (void *)&name, sizeof(name));
	if (ret < 0)
		mylog(LOG_ERR, "bind(@%s) failed: %s", name.sun_path+1, ESTR(errno));

	t0 = time(NULL);
	do {
		/* schedule timeout */
		alarm(1);
		/* send command */
		ret = sendcred(sock, sbuf, bufp - sbuf, 0);
		if (ret < 0)
			mylog(LOG_ERR, "send ...: %s", ESTR(errno));

		do {
			ret = recv(sock, rbuf, sizeof(rbuf)-1, 0);
			if (ret < 0)
				mylog(LOG_ERR, "recv ...: %s", ESTR(errno));
			if (!ret)
				mylog(LOG_ERR, "empty response");
			rbuf[ret] = 0;
			if (*rbuf != '>')
				break;
			for (pos = 1; pos < ret; ) {
				if (pos > 1)
					fputc(' ', stdout);
				fputs(rbuf+pos, stdout);
				pos += strlen(rbuf+pos)+1;
			}
			printf("\n");
			alarm(1);
		} while (1);
		ret = strtol(rbuf, NULL, 0);
		if (ret < 0) {
			if (!quietbis)
				mylog(LOG_ERR, "command failed: %s", ESTR(-ret));
			exit(1);
		}
		if (isnan(repeat)) {
			if (!quiet)
				printf("%i\n", ret);
			break;
		}
		if (maxdelay && (!ret || (time(NULL) > (t0+maxdelay)))) {
			if (!quiet && !quietbis)
				mylog(LOG_INFO, "%s %s after %lu seconds", sbuf,
					ret ? "aborted" : "finished",
					time(NULL)-t0);
			return !!ret;
		}
		/* remove timeout */
		alarm(0);
		if (ret)
			poll(NULL, 0, repeat*1000);
	} while (ret);
	return EXIT_SUCCESS;
}
