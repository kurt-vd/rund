/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define NAME "initc"

#define LOG_ERR	1
#define mylog(level, fmt, ...) \
	({\
		fprintf(stderr, "%s: " fmt "\n", NAME, ##__VA_ARGS__);\
		if (level <= LOG_ERR)\
			exit(1);\
	})

#define ESTR(x) strerror(x)

static void sigalrm(int sig)
{
	mylog(LOG_ERR, "timeout communicating");
}

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
	int ret, sock, j;
	struct sockaddr_un name = {
		.sun_family = AF_UNIX,
		.sun_path = "\0initd",
	};

	/* prepare cmd */
	static char buf[16*1024];
	char *bufp = buf, *str;

	for (j = 1; j < argc; ++j) {
		strcpy(bufp, argv[j]);
		bufp += strlen(bufp)+1;
	}
	if (bufp <= buf)
		mylog(LOG_ERR, "no command specified");

	/* schedule timeout */
	signal(SIGALRM, sigalrm);
	alarm(1);

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

	/* send command */
	ret = sendcred(sock, buf, bufp - buf, 0);
	if (ret < 0)
		mylog(LOG_ERR, "send ...: %s", ESTR(errno));

	ret = recv(sock, buf, sizeof(buf), 0);
	if (ret < 0)
		mylog(LOG_ERR, "recv ...: %s", ESTR(errno));
	if (!ret)
		mylog(LOG_ERR, "empty response");
	buf[ret] = 0;
	ret = strtol(buf, NULL, 0);
	if (ret < 0)
		mylog(LOG_ERR, "command failed: %s", ESTR(-ret));
	printf("%i\n", ret);
	return EXIT_SUCCESS;
}
