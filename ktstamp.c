/* See LICENSE file for copyright and license details. */
#include <stdio.h>
#include <time.h>
#include <string.h>

int main(int argc, char *argv[])
{
	struct timespec ts;
	int secwidth = !strcmp(argv[1]?: "", "-k") ? 5 : 0;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	printf("%*lu.%06lu\n", secwidth, ts.tv_sec, ts.tv_nsec/1000);
	return 0;
}
