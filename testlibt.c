/*
 * Copyright 2015 Kurt Van Dijck <dev.kurt@vandijck-laurijssen.be>
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
#include <stdarg.h>

#include <poll.h>

#include "libt.h"

double tref;
int repeat, add;

static void function(void *dat)
{
	printf("%.3lf: timeout %lu called\n", libt_now() - tref, (long)dat);
	if (repeat == (long)dat) {
		libt_repeat_timeout(1, function, dat);
		printf("%.3lf: repeat %lu %.3lf\n", libt_now() - tref, (long)dat, 1.0);
		repeat = 0;
	} else if (add == (long)dat) {
		libt_add_timeout(1, function, dat);
		printf("%.3lf: add %lu %.3lf\n", libt_now() - tref, (long)dat, 1.0);
		add = 0;
	}
}

static void test(int index, ...)
{
	va_list va;
	double t;
	int queued = 0;

	tref = libt_now();

	printf("## TEST %i\n", index);
	va_start(va, index);
	for (;;) {
		t = va_arg(va, double);
		if (isnan(t))
			break;
		libt_add_timeout(t, function, (void *)(long)++queued);
		printf("%.3lf: queue %.3lf: %i\n", libt_now() - tref, t, queued);
	}
	va_end(va);
	for (;;) {
		if (libt_get_waittime() < 0)
			break;
		poll(NULL, 0, libt_get_waittime());
		printf("%.3lf: wakeup\n", libt_now() - tref);
		libt_handle_expired_timers();
	}
	printf("%.3lf: test done\n", libt_now() - tref);
}

int main(int argc, char *argv[])
{
	repeat = 3;
	test(1, 1.00, 0.75, 0.50, NAN);

	repeat = 1;
	test(2, 0.75, 0.50, 1.00, NAN);

	add = 3;
	test(3, 0.50, 1.00, 0.75, NAN);
	return 0;
}

