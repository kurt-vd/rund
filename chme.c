/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>

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
	" cd:DIR		chdir\n"
	" umask:0XX		change umask\n"
	" nice:VAL		set nice\n"
	" lim:TYPE:VALUE	wrap setrlimit,\n"
	"			TYPE is one of as, core, cpu, data, fsize, memlock, msgqueue,\n"
	"			nice, nofile, nproc, rss, rtprio, rttime, sigpending, stack\n"
	" ionice:CLASS,VALUE	set io nice class (none,rt,be,idle) and value\n"
	" sched:P[F][,V1[,V2[,V3]]] Set scheduling.\n"
	"			P is other, fifo, rr, batch, idle, deadline\n"
	"			for fifo and rr, add static priority\n"
	"			for deadline, add runtime[,deadline],period\n"
	" cpu:[~]CPU[-CPU2][,...]	Set cpu affinity mask\n"
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
#ifdef RLIMIT_RTTIME
	[RLIMIT_RTTIME] = "rttime",
#endif
	[RLIMIT_SIGPENDING] = "sigpending",
	[RLIMIT_STACK] = "stack",
};

#ifndef IOPRIO_CLASS_RT
static inline int ioprio_set(int which, int who, int ioprio)
{
	return syscall(__NR_ioprio_set, which, who, ioprio);
}
static inline int ioprio_get(int which, int who)
{
	return syscall(__NR_ioprio_get, which, who);
}
enum {
	IOPRIO_CLASS_NONE,
	IOPRIO_CLASS_RT,
	IOPRIO_CLASS_BE,
	IOPRIO_CLASS_IDLE,
};
enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};

#define IOPRIO_PRIO_VALUE(class, prio)  ((class << 13) | (prio & 0x1fff))
#endif

/* modify scheduler: don't rely on libc implemenation */
#ifndef __NR_sched_setattr
/* XXX use the proper syscall numbers */
#ifdef __x86_64__
#define __NR_sched_setattr		314
#define __NR_sched_getattr		315
#endif

#ifdef __i386__
#define __NR_sched_setattr		351
#define __NR_sched_getattr		352
#endif

#ifdef __arm__
#define __NR_sched_setattr		380
#define __NR_sched_getattr		381
#endif

#endif
#define SCHED_NORMAL	0
#define SCHED_FIFO	1
#define SCHED_RR	2
#define SCHED_BATCH	3
#define SCHED_IDLE	5
#define SCHED_DEADLINE	6
#define SCHED_FLAG_RESET_ON_FORK 1

struct sched_attr {
       uint32_t size;

       uint32_t sched_policy;
       uint64_t sched_flags;

       /* SCHED_NORMAL, SCHED_BATCH */
       int32_t sched_nice;

       /* SCHED_FIFO, SCHED_RR */
       uint32_t sched_priority;

       /* SCHED_DEADLINE (nsec) */
       uint64_t sched_runtime;
       uint64_t sched_deadline;
       uint64_t sched_period;
};

int sched_setattr(pid_t pid,
		const struct sched_attr *attr,
		unsigned int flags)
{
	return syscall(__NR_sched_setattr, pid, attr, flags);
}

/* workaround empty strings in strtok */
char *estrtok(char *haystack, const char *needle)
{
	static char *saved;
	char *result;

	result = saved = haystack ?: saved;
	if (saved) {
		saved = strpbrk(saved, needle);
		if (saved)
			*saved++ = 0;
	}
	return result;
}

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

		tok = estrtok(*argv, ":");
		if (!tok)
			mylog(LOG_ERR, "bad token '%s'", *argv);

		if (!strcmp(tok, "-")) {
			/* done, exec program */
			++argv;
			break;
		}
		else if (!strcmp(tok, "cd")) {
			tok = estrtok(NULL, "") ?: "";

			if (chdir(tok) < 0)
				mylog(LOG_ERR, "chdir %s: %s", tok, ESTR(errno));
		}
		else if (!strcmp(tok, "cpu")) {
			cpu_set_t cs;
			int inv = 0, c1, c2;

			CPU_ZERO(&cs);
			for (tok = estrtok(NULL, ","); tok; tok = estrtok(NULL, ",")) {
				if (*tok == '~' && !CPU_COUNT(&cs)) {
					++tok;
					inv = 1;
					memset(&cs, 0xff, sizeof(cs));
				}

				c1 = c2 = strtoul(tok, &str, 0);
				if (str > tok && *tok == '-')
					c2 = strtol(str+1, NULL, 0);
				for (; c1 <= c2; ++c1)
					if (inv)
						CPU_CLR(c1, &cs);
					else
						CPU_SET(c1, &cs);
			}

			if (sched_setaffinity(0, sizeof(cs), &cs) < 0)
				mylog(LOG_ERR, "sched_setaffinity: %s", ESTR(errno));
		}
		else if (!strcmp(tok, "ionice")) {
			static const char *const ioprios[] = {
				[IOPRIO_CLASS_NONE] = "none",
				[IOPRIO_CLASS_RT] = "rt",
				[IOPRIO_CLASS_BE] = "be",
				[IOPRIO_CLASS_IDLE] = "idle",
			};
			/* find priority class */
			tok = estrtok(NULL, ",") ?: "";
			for (opt = 0; opt < ARRAY_SIZE(ioprios); ++opt) {
				if (!strcmp(ioprios[opt] ?: "", tok))
					break;
			}
			if (opt >= ARRAY_SIZE(ioprios))
				mylog(LOG_ERR, "ioprio class '%s' unknown", tok);
			/* find value */
			int val = strtol(estrtok(NULL, ",") ?: "0", NULL, 0);

			/* commit value */
			if (ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(opt, val)) < 0)
				mylog(LOG_ERR, "ioprio_set %s,%i: %s", ioprios[opt] ?: "", val, ESTR(errno));
		}
		else if (!strcmp(tok, "lim")) {
			tok = estrtok(NULL, ":") ?: "";

			for (opt = 0; opt < ARRAY_SIZE(resnames); ++opt) {
				if (!strcmp(resnames[opt] ?: "", tok))
					break;
			}
			if (opt >= ARRAY_SIZE(resnames))
				mylog(LOG_ERR, "resource limit '%s' unknown", tok);

			struct rlimit limit;

			getrlimit(opt, &limit);
			limit.rlim_cur = strtoul(estrtok(NULL, ":") ?: "0", &str, 0);
			if (*str == 'k' || *str == 'K')
				limit.rlim_cur *= 1024;
			else if (*str == 'M')
				limit.rlim_cur *= 1024 * 1024;

			if (limit.rlim_cur > limit.rlim_max)
				/* increase max too */
				limit.rlim_max = limit.rlim_cur;

			if (setrlimit(opt, &limit) < 0)
				mylog(LOG_ERR, "rlimit %s %lu %lu: %s", resnames[opt],
						(long)limit.rlim_cur, (long)limit.rlim_max, ESTR(errno));
		}
		else if (!strcmp(tok, "nice")) {
			opt = strtol(estrtok(NULL, "") ?: "0", NULL, 0);
			if (setpriority(PRIO_PROCESS, 0, opt) < 0)
				mylog(LOG_ERR, "nice %i: %s", opt, ESTR(errno));
		}
		else if (!strcmp(tok, "sched")) {
			struct sched_attr sa = {};
			static const char policies[] = "ofrb_id";
			/* find policy */
			tok = estrtok(NULL, ",") ?: "";
			str = strchr(policies, *tok);
			if (!str)
				mylog(LOG_ERR, "scheduling policy '%s' unkown", tok);
			sa.sched_policy = str - policies;
			if (strchr(tok, 'R'))
				sa.sched_flags |= SCHED_FLAG_RESET_ON_FORK;

			switch (sa.sched_policy) {
			case SCHED_FIFO:
			case SCHED_RR:
				sa.sched_priority = strtoul(estrtok(NULL, ",") ?: "0", NULL, 0);
				break;
			case SCHED_DEADLINE:
				sa.sched_runtime = strtod(estrtok(NULL, ",") ?: "0", NULL) * 1e9;
				sa.sched_period = strtod(estrtok(NULL, ",") ?: "0", NULL) * 1e9;
				tok = estrtok(NULL, ",");
				if (tok) {
					sa.sched_deadline = sa.sched_period;
					sa.sched_period = strtod(tok, NULL) * 1e9;
				} else
					sa.sched_deadline = (sa.sched_runtime + sa.sched_period)/2;
				break;
			}

			if (sched_setattr(0, &sa, 0) < 0)
				mylog(LOG_ERR, "sched_setattr %i failed: %s", sa.sched_policy, ESTR(errno));
		}
		else if (!strcmp(tok, "umask")) {
			opt = strtoul(estrtok(NULL, "") ?: "0", NULL, 8);
			umask(opt);
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
