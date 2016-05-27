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
	struct sockaddr_un name = {
		.sun_family = AF_UNIX,
	};
	int socklen;
	static char rbuf[16*1024];
	double repeat = 1;

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
		socktype = -1;
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
	if ((socktype != SOCK_STREAM) && (flags & FL_WAITCLOSE))
		mylog(LOG_ERR, "-n is only possible for STREAM sockets");

	while (socktype == -1) {
		/* wait on file */
		struct stat st;

		if (0 == stat(argv[optind], &st)) {
			if (!(flags & FL_WAITCLOSE))
				return 0;
		} else if (errno == ENOENT) {
			if (flags & FL_WAITCLOSE)
				return 0;
		}
		usleep(repeat*1000000);
	}

	strncpy(name.sun_path, argv[optind], sizeof(name.sun_path));
	socklen = sizeof(name.sun_family) + strlen(name.sun_path);
	if (name.sun_path[0] == '@') {
		/* abstrace namespace */
		name.sun_path[0] = 0;
		if (flags & FL_FULLNAME)
			socklen = sizeof(name);
	}

	/* open client socket */
	ret = sock = socket(PF_UNIX, socktype, 0);
	if (ret < 0)
		mylog(LOG_ERR, "socket(unix, ...) failed: %s", ESTR(errno));

	/* connect to server */
	while (!(flags & FL_WAITCLOSE)) {
		ret = connect(sock, (void *)&name, socklen);
		if (ret >= 0)
			/* done */
			return 0;
		if (errno != ECONNREFUSED)
			mylog(LOG_ERR, "connect(%c%s) failed: %s", name.sun_path[0] ?: '@', &name.sun_path[1], ESTR(errno));
		poll(NULL, 0, repeat*1000);
	}

	/* waitclose */
	ret = connect(sock, (void *)&name, socklen);
	if (ret < 0)
		mylog(LOG_ERR, "connect(%c%s) failed: %s", name.sun_path[0] ?: '@', &name.sun_path[1], ESTR(errno));

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
