/*
 * Copyright 2015 Kurt Van Dijck <dev.kurt@vandijck-laurijssen.be>
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "libt.h"

struct timer {
	struct timer *next, *prev;
	void (*fn)(void *dat);
	void *dat;
	double wakeup;
};

static struct {
	struct timer *timers;
	struct timer *tmptimers;
} s;

/* double-linked-list black magic:
 * The @prev member of the first element points to a 'fake' element
 * which is well-crafted so that assigning prev->next just happens
 * to set the root pointer
 * This function return the required 'fake' pointers
 */
static inline struct timer *t_fakeelement(struct timer **root)
{
	return (struct timer *)(((char *)root) - offsetof(struct timer, next));

}

/* double linked list */
static void t_del(struct timer *t)
{
	if (t->next)
		t->next->prev = t->prev;
	if (t->prev)
		t->prev->next = t->next;
	t->next = t->prev = NULL;
}

static void t_add(struct timer *t, struct timer **root)
{
	t_del(t);
	t->next = *root;
	if (t->next) {
		t->prev = t->next->prev;
		t->next->prev = t;
	} else
		/* this is dirty: fake a timer struct, which will only be used
		 * for setting the @next member
		 */
		t->prev = t_fakeelement(root);
	t->prev->next = t;
}

static void t_add_sorted(struct timer *t, struct timer **root)
{
	t_del(t);
	/* iterate root until all smaller items have passed */
	for (; *root; root = &(*root)->next) {
		if (t->wakeup < (*root)->wakeup)
			break;
	}
	t_add(t, root);
}

/* local/private tools */
static struct timer *t_find(void (*fn)(void *), const void *dat)
{
	struct timer *t;

	for (t = s.timers; t; t = t->next) {
		if ((t->fn == fn) && (t->dat == dat))
			return t;
	}
	for (t = s.tmptimers; t; t = t->next) {
		if ((t->fn == fn) && (t->dat == dat))
			return t;
	}
	return NULL;
}

/* exported API */
double libt_now(void)
{
#if defined(USE_GETTIMEOFDAY)
	struct timeval t;
	if (0 != gettimeofday(&t, 0))
		exit(1);
	return t.tv_sec + ((t.tv_usec % 1000000) / 1e6);
#else
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t) < 0)
		exit(1);
	return t.tv_sec + (t.tv_nsec / 1e9);
#endif
}

void libt_add_timeout(double timeout, void (*fn)(void *), const void *dat)
{
	if (isnan(timeout))
		return;
	libt_add_timeouta(timeout+libt_now(), fn, dat);
}

void libt_add_timeouta(double wakeuptime, void (*fn)(void *), const void *dat)
{
	struct timer *t;

	if (isnan(wakeuptime))
		return;
	t = t_find(fn, dat);
	if (!t) {
		t = malloc(sizeof(*t));
		/* don't test t since I don't know what to do if it was NULL
		 * So, I just use it, and maybe we segfault, which is the best
		 * I can imagine in that case
		 */
		memset(t, 0, sizeof(*t));
		t->fn = fn;
		t->dat = (void *)dat;
	}
	t->wakeup = wakeuptime;
	t_add_sorted(t, &s.timers);
}

void libt_repeat_timeout(double increment, void (*fn)(void *), const void *dat)
{
	struct timer *t;

	if (isnan(increment))
		return;
	t = t_find(fn, dat);
	if (!t)
		libt_add_timeout(increment, fn, dat);
	else {
		double now = libt_now();

		t->wakeup += increment;
		if (t->wakeup < now)
			/* We're scheduling in the past.
			 * Jump to the future again,
			 * make 'repeat' fail in maintaining strict timing
			 * and mimic 'add' behaviour
			 */
			t->wakeup = now + increment;
		t_add_sorted(t, &s.timers);
	}
}

void libt_remove_timeout(void (*fn)(void *), const void *dat)
{
	struct timer *t;

	t = t_find(fn, dat);
	if (t) {
		t_del(t);
		free(t);
	}
}

int libt_timeout_exist(void (*fn)(void *), const void *dat)
{
	return !!t_find(fn, dat);
}

int libt_flush(void)
{
	struct timer *t;
	double now;
	int cnt;

	now = libt_now() +0.001;
	cnt = 0;
	while (s.timers) {
		t = s.timers;
		if (t->wakeup > now)
			break;
		/*
		 * move tries to garbage, for possible re-arm inside
		 * the timer callback
		 */
		t_add(t, &s.tmptimers);
		t->fn(t->dat);
		++cnt;
	}
	/* clean up cache */
	while (s.tmptimers) {
		t = s.tmptimers;
		t_del(t);
		free(t);
	}
	return cnt;
}

double libt_next_wakeup(void)
{
	return s.timers ? s.timers->wakeup : -1;
}

int libt_get_waittime(void)
{
	double tmp;

	if (!s.timers)
		return -1;
	/* avoid integer overflows and use double
	 * An integer overflow may result into a negative
	 * waittime, while nothing is about to happen.
	 * The net result is that the program using
	 * libt_get_waittime() for poll() runs away with the cpu
	 * because the waittime is wrong.
	 */
	tmp = (s.timers->wakeup - libt_now()) * 1000;
	/* compute the max result value that we want to return.
	 * This is 1/4 of the maximum int value
	 */
#define MAXRESULT	((~0U)/4)
	if (tmp <= 0)
		return 0;
	if (tmp > MAXRESULT)
		return MAXRESULT;
	else
		return tmp;
}

/* cleanup storage */
__attribute__((destructor))
void libt_cleanup(void)
{
	struct timer *t;

	while (s.timers) {
		t = s.timers;
		s.timers = t->next;
		free(t);
	}
	while (s.tmptimers) {
		t = s.tmptimers;
		s.tmptimers = t->next;
		free(t);
	}
}
