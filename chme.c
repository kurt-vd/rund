/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/resource.h>

#define NAME "chme"

#define LOG_ERR	1
#define mylog(level, fmt, ...) \
	({\
		fprintf(stderr, "%s: " fmt "\n", NAME, ##__VA_ARGS__);\
		if (level <= LOG_ERR)\
			exit(1);\
		fflush(stderr); \
	})

#define ESTR(x) strerror(x)

#define ARRAY_SIZE(x)	(sizeof(x)/sizeof(*(x)))

/* program options */
static const char help_msg[] =
	NAME ": change process properties\n"
	"usage:	" NAME " [OPTIONS ...] [SETTINGS ...] [--] COMMAND [ARGS ...]\n"
	"\n"
	"Options:\n"
	" -V	Show version\n"
	"Settings:\n"
	" lim:TYPE:VALUE	wrap setrlimit,\n"
	"			TYPE is one of as, core, cpu, data, fsize, memlock, msgqueue,\n"
	"			nice, nofile, nproc, rss, rtprio, rttime, sigpending, stack\n"
	" KEY=VALUE		Set environment variables\n"
	;

/* information */
static const char *const resnames[] = {
	[RLIMIT_AS] = "as",
	[RLIMIT_CORE] = "core",
	[RLIMIT_CPU] = "cpu",
	[RLIMIT_DATA] = "data",
	[RLIMIT_FSIZE] = "fsize",
	[RLIMIT_MEMLOCK] = "memlock",
	[RLIMIT_MSGQUEUE] = "msgqueue",
	[RLIMIT_NICE] = "nice",
	[RLIMIT_NOFILE] = "nofile",
	[RLIMIT_NPROC] = "nproc",
	[RLIMIT_RSS] = "rss",
	[RLIMIT_RTPRIO] = "rtprio",
	[RLIMIT_RTTIME] = "rttime",
	[RLIMIT_SIGPENDING] = "sigpending",
	[RLIMIT_STACK] = "stack",
};

/* main process */
int main(int argc, char *argv[])
{
	int opt;
	char *tok, *str;

	for (++argv; *argv; ++argv) {
		/* test for program options */
		if (**argv == '-') {
			switch ((*argv)[1]) {
			case 'V':
				fprintf(stderr, "%s: %s\n", NAME, VERSION);
				return 0;
			default:
			case '?':
				fputs(help_msg, stderr);
				return (*argv)[1] != '?';
			case '-':
				/* --, ready to run */
				++argv;
				goto run;
			}
			continue;
		}

		/* test for environment variables */
		str = strchr(*argv, '=');
		if (str) {
			*str++ = 0;
			setenv(*argv, str, 1);
			continue;
		}

		/* test for OPT:... */
		if (!strchr(*argv, ':'))
			goto run;

		tok = strtok(*argv, ":");
		if (!tok)
			mylog(LOG_ERR, "bad token '%s'", *argv);

		if (!strcmp(tok, "-")) {
			/* done, exec program */
			++argv;
			break;
		}
		else if (!strcmp(tok, "lim")) {
			tok = strtok(NULL, ":") ?: "";

			for (opt = 0; opt < ARRAY_SIZE(resnames); ++opt) {
				if (!strcmp(resnames[opt] ?: "", tok))
					break;
			}
			if (opt >= ARRAY_SIZE(resnames))
				mylog(LOG_ERR, "resource limit '%s' unknown", tok);

			struct rlimit limit;

			getrlimit(opt, &limit);
			limit.rlim_cur = strtoul(strtok(NULL, ":") ?: "0", NULL, 0);
			if (limit.rlim_cur > limit.rlim_max)
				/* increase max too */
				limit.rlim_max = limit.rlim_cur;

			if (setrlimit(opt, &limit) < 0)
				mylog(LOG_ERR, "rlimit %s %lu %lu: %s", resnames[opt],
						(long)limit.rlim_cur, (long)limit.rlim_max, ESTR(errno));
		}
		else
			mylog(LOG_ERR, "uknown token %s, maybe forgot a '--'", tok);
	}
run:
	if (!*argv)
		return 0;
	execvp(*argv, argv);
	mylog(LOG_ERR, "execvp %s ...: %s", *argv, ESTR(errno));
}
