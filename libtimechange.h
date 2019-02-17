/*
 * Copyright 2019 Kurt Van Dijck <dev.kurt@vandijck-laurijssen.be>
 *
 * This file is part of libet.
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser Public License for more details.
 *
 * You should have received a copy of the GNU Lesser Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdint.h>
#include <sys/timerfd.h>

/* TFD_TIMER_CANCEL_ON_SET is relatively new ... */
#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

static inline
int libtimechange_makefd(void)
{
	return timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
}

static inline
int libtimechange_arm(int fd)
{
	/* schedule timerfd */
	struct itimerspec spec = {};
	return timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &spec, NULL);
}

static inline
int libtimechange_iterate(int fd)
{
	uint64_t tfdval;
	int ret;

	ret = read(fd, &tfdval, sizeof(tfdval));
	if (ret < 0)
		return ret;
	return tfdval;
}
