/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <getopt.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define NAME "runc"

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
	" -r[DELAY]	Repeat command each DELAY secs (default 1.0)\n"
	"		until 0 is returned\n"
	" -mDELAY	Repeat Maxixum during DELAY secs\n"
	"\n"
	"Commands:\n"
	" add [KEY=VALUE ...] PROGRAM [ARGUMENT ...]\n"
	"	Add a new service\n"
	" remove [KEY=VALUE ...] [PROGRAM] [ARGUMENT ...]\n"
	"	Remove a service\n"
	" remove *\n"
	"	Remove all services\n"
	" removing [KEY=VALUE ...] [PROGRAM] [ARGUMENT ...]\n"
	"	Count the number of removed services that are yet exiting\n"
	" syslog\n"
	" loglevel\n"
	" redir\n"
	;
static const char optstring[] = "+?Vqr::m:";

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

/* main process */
int main(int argc, char *argv[])
{
	int ret, opt, sock, j;
	struct sockaddr_un name = {
		.sun_family = AF_UNIX,
		.sun_path = "\0rund",
	};
	double repeat = NAN;
	int maxdelay = 0;
	time_t t0;
	int quiet = 0;

	/* prepare cmd */
	static char sbuf[16*1024], rbuf[1024];
	char *bufp, *str;

	/* parse program options */
	while ((opt = getopt(argc, argv, optstring)) != -1)
	switch (opt) {
	case 'V':
		fprintf(stderr, "%s: %s\n", NAME, VERSION);
		return 0;
	case 'q':
		quiet = 1;
		break;
	case 'r':
		repeat = optarg ? strtod(optarg, NULL) : 1;
		if (!(repeat > 0))
			mylog(LOG_ERR, "bad rate '%s'", optarg);
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
		mylog(LOG_ERR, "connect(@%s) failed: %s", name.sun_path+1, ESTR(errno));

	t0 = time(NULL);
	do {
		/* schedule timeout */
		alarm(1);
		/* send command */
		ret = sendcred(sock, sbuf, bufp - sbuf, 0);
		if (ret < 0)
			mylog(LOG_ERR, "send ...: %s", ESTR(errno));

		ret = recv(sock, rbuf, sizeof(rbuf)-1, 0);
		if (ret < 0)
			mylog(LOG_ERR, "recv ...: %s", ESTR(errno));
		if (!ret)
			mylog(LOG_ERR, "empty response");
		rbuf[ret] = 0;
		ret = strtol(rbuf, NULL, 0);
		if (ret < 0)
			mylog(LOG_ERR, "command failed: %s", ESTR(-ret));
		if (isnan(repeat)) {
			if (!quiet)
				printf("%i\n", ret);
			break;
		}
		if (maxdelay && (!ret || (time(NULL) > (t0+maxdelay)))) {
			if (!quiet)
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
