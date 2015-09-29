/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>

static const char helpmsg[] =
	"usage: sysreboot ARG [...]\n"
	"\n"
	"sysreboot performs a lowlevel reboot() call.\n"
	"If you are unsure what this is, then this is probably\n"
	"not what you were looking for.\n"
	"\n"
	"ARG is one of:\n"
	" halt		halt the system\n"
	" reboot	reboot the system\n"
	" poweroff	poweroff the system\n"
	" cadhard	reboot on Ctrl+Alt+Del\n"
	" cadsoft	deliver SIGINT on Ctrl+Alt+Del\n"
	;

int main(int argc, char *argv[])
{
	int ret, ctl;

	if (!argv[1])
		ctl = 0;
	else if (!strcmp("halt", argv[1]))
		ctl = RB_HALT_SYSTEM;
	else if (!strcmp("reboot", argv[1]))
		ctl = RB_AUTOBOOT;
	else if (!strcmp("poweroff", argv[1]))
		ctl = RB_POWER_OFF;
	else if (!strcmp("cadhard", argv[1]))
		ctl = RB_ENABLE_CAD;
	else if (!strcmp("cadsoft", argv[1]))
		ctl = RB_DISABLE_CAD;
	else
		ctl = 0;

	if (!ctl) {
		fputs(helpmsg, stderr);
		exit(2);
	}
	ret = reboot(ctl);
	if (ret < 0) {
		fprintf(stderr, "reboot %s: %s\n", argv[1], strerror(errno));
		return 1;
	}
	return 0;
}
