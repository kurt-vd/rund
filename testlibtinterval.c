/*
 * Copyright 2020 Kurt Van Dijck <dev.kurt@vandijck-laurijssen.be>
 *
 * This file is part of libet.
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Public License for more details.
 *
 * You should have received a copy of the GNU Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libt.h"

static double strtodelay(const char *str, char **pendp)
{
	double result;
	char *endp;

	if (!pendp)
		pendp = &endp;
	result = strtod(str, pendp);
	switch (**pendp) {
	case 'w':
		result *= 7;
	case 'd':
		result *= 24;
	case 'h':
		result *= 60;
	case 'm':
		result *= 60;
	case 's':
		++(*pendp);
		break;
	}
	return result;
}

char *timetostr(double dt)
{
	static char buf[128];
	char *str;

	time_t t = (time_t)dt;
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
	str = buf+strlen(buf)-1;
	sprintf(str, "%.6f", fmod(dt, 10));

	return buf;
}

int main(int argc, char *argv[])
{
	const char *sinterval, *soffset;
	double interval, offset;
	double walltime = libt_walltime();;
	double delay;
	int j, max = 10;

	sinterval = (argc >= 2) ? argv[1] : "1d";
	soffset = (argc >= 3) ? argv[2] : "4h";
	if (argc >= 4)
		max = strtoul(argv[3], NULL, 0);

	interval = strtodelay(sinterval, NULL);
	offset = strtodelay(soffset, NULL);

	printf("now %s\n", timetostr(walltime));
	printf("/%s +%s\n", sinterval, soffset);

	for (j = 0; j < max; ++j) {
		delay = libt_timetointerval4(walltime, interval, offset, 10);
		printf("%i %s (+%.0f)\n", j, timetostr(walltime+delay), delay);
		walltime += delay;
	}
	return 0;
}

