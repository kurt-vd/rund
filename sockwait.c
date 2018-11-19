/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define NAME "sockwait"

#define LOG_ERR	1
#define mylog(level, fmt, ...) \
	({\
		fprintf(stderr, "%s: " fmt "\n", NAME, ##__VA_ARGS__);\
		if (level <= LOG_ERR)\
			exit(1);\
	})

#define ESTR(x) strerror(x)

/* program options */
static const char help_msg[] =
	NAME ": wait for a socket\n"
	"usage:	" NAME " [OPTIONS ...] SOCKET\n"
	"\n"
	"Options:\n"
	" -V	Show version\n"
	" -rDELAY	Repeat command each DELAY secs (default 1.0)\n"
	"		until 0 is returned\n"
	" -d	DGRAM socket\n"
	" -f	Wait on regular file (or directory or symlink ...)\n"
	" -n	Return when socket is remotely closed\n"
	"	Consumes all received data\n"
	" -F	Use non-full length for abstract sockets\n"
	;
static const char optstring[] = "?Vr:dfnF";

/* main process */
int main(int argc, char *argv[])
{
	int ret, opt, sock;
	union {
		struct sockaddr sa;
		struct sockaddr_un un;
	} name = {
		.sa.sa_family = PF_UNIX,
	};
	int socklen;
	static char rbuf[16*1024];
	double repeat = 1;
	const char *peerstr;

		#define FL_WAITCLOSE	0x01
		#define FL_FULLNAME	0x02
	int flags = FL_FULLNAME;
	int socktype = SOCK_STREAM;

	/* parse program options */
	while ((opt = getopt(argc, argv, optstring)) != -1)
	switch (opt) {
	case 'V':
		fprintf(stderr, "%s: %s\n", NAME, VERSION);
		return 0;
	case 'r':
		repeat = strtod(optarg, NULL);
		if (!(repeat > 0))
			mylog(LOG_ERR, "bad rate '%s'", optarg);
		break;
	case 'd':
		socktype = SOCK_DGRAM;
		break;
	case 'f':
		name.sa.sa_family = -1;
		break;
	case 'n':
		flags |= FL_WAITCLOSE;
		break;
	case 'F':
		flags &= ~FL_FULLNAME;
		break;

	default:
		fprintf(stderr, "%s: option '%c' unrecognised\n", NAME, opt);
	case '?':
		fputs(help_msg, stderr);
		exit(1);
	}

	if (!argv[optind]) {
		fprintf(stderr, "%s: no socket given\n", NAME);
		fputs(help_msg, stderr);
		exit(1);
	}
	peerstr = argv[optind++];
	if ((socktype != SOCK_STREAM) && (flags & FL_WAITCLOSE))
		mylog(LOG_ERR, "-n is only possible for STREAM sockets");

	while (socktype == -1) {
	}

	switch (name.sa.sa_family) {
	case -1:
		/* wait on file */
		for (;;) {
			struct stat st;

			if (0 == stat(peerstr, &st)) {
				if (!(flags & FL_WAITCLOSE))
					return 0;
			} else if (errno == ENOENT) {
				if (flags & FL_WAITCLOSE)
					return 0;
			}
			poll(NULL, 0, repeat*1000);
		}
		break;
	case PF_UNIX:
		strncpy(name.un.sun_path, peerstr, sizeof(name.un.sun_path));
		socklen = sizeof(name.un.sun_family) + strlen(name.un.sun_path);
		if (name.un.sun_path[0] == '@') {
			/* abstrace namespace */
			name.un.sun_path[0] = 0;
			if (flags & FL_FULLNAME)
				socklen = sizeof(name.un);
		}
		break;
	default:
		mylog(LOG_ERR, "Protocol family %u not supported", name.sa.sa_family);
		break;
	}

	/* open client socket */
	ret = sock = socket(name.sa.sa_family, socktype, 0);
	if (ret < 0)
		mylog(LOG_ERR, "socket '%s' failed: %s", peerstr, ESTR(errno));

	/* connect to server */
	while (!(flags & FL_WAITCLOSE)) {
		ret = connect(sock, (void *)&name, socklen);
		if (ret >= 0)
			/* done */
			return 0;
		if (errno != ECONNREFUSED && errno != ENOENT)
			mylog(LOG_ERR, "connect '%s' failed: %s", peerstr, ESTR(errno));
		poll(NULL, 0, repeat*1000);
	}

	/* waitclose */
	ret = connect(sock, (void *)&name, socklen);
	if (ret < 0)
		mylog(LOG_ERR, "connect '%s' failed: %s", peerstr, ESTR(errno));

	while (1) {
		ret = recv(sock, rbuf, sizeof(rbuf), 0);
		if (!ret)
			/* EOF, socket down */
			return 0;
		if (ret < 0)
			mylog(LOG_ERR, "recv failed: %s", ESTR(errno));
	}
	return EXIT_FAILURE;
}
