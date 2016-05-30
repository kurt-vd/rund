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

#include <unistd.h>
#include <sys/epoll.h>

#include "libe.h"

struct event {
	struct event *next, *prev;
	void (*fn)(int fd, void *dat);
	void *dat;
	int fd;
};

static struct {
	struct event *events;
	int epfd; /* epoll file descriptor */
	int nevs;
	#define NEVS	16
	struct epoll_event evs[NEVS];
} s = {
	.epfd = -1,
};

/* double-linked-list black magic:
 * The @prev member of the first element points to a 'fake' element
 * which is well-crafted so that assigning prev->next just happens
 * to set the root pointer
 * This function return the required 'fake' pointers
 */
static inline struct event *t_fakeelement(struct event **root)
{
	return (struct event *)(((char *)root) - offsetof(struct event, next));

}

/* double linked list */
static void t_del(struct event *t)
{
	if (t->next)
		t->next->prev = t->prev;
	if (t->prev)
		t->prev->next = t->next;
	t->next = t->prev = NULL;
}

static void t_add(struct event *t, struct event **root)
{
	t_del(t);
	t->next = *root;
	if (t->next) {
		t->prev = t->next->prev;
		t->next->prev = t;
	} else
		/* this is dirty: fake a event struct, which will only be used
		 * for setting the @next member
		 */
		t->prev = t_fakeelement(root);
	t->prev->next = t;
}

/* exported API */
int libe_add_fd(int fd, void (*fn)(int fd, void *), const void *dat)
{
	struct event *t;

	t = malloc(sizeof(*t));
	/* don't test t since I don't know what to do if it was NULL
	 * So, I just use it, and maybe we segfault, which is the best
	 * I can imagine in that case
	 */
	memset(t, 0, sizeof(*t));
	t->fd = fd;
	t->fn = fn;
	t->dat = (void *)dat;

	t_add(t, &s.events);
	if (s.epfd >= 0) {
		struct epoll_event evdat = {
			.events = EPOLLIN,
			.data.ptr = t,
		};

		return epoll_ctl(s.epfd, EPOLL_CTL_ADD, fd, &evdat);
	}
	return 0;
}

void libe_remove_fd(int fd)
{
	struct event *t;
	int j;

	for (t = s.events; t; t = t->next) {
		if (t->fd == fd)
			break;
	}
	if (t) {
		/* alert? */
		t_del(t);
		free(t);
		for (j = 0; j < s.nevs; ++j) {
			if (s.evs[j].data.ptr == t)
				/* clear this entry */
				s.evs[j].data.ptr = NULL;
		}
	}
	if (s.epfd >= 0)
		epoll_ctl(s.epfd, EPOLL_CTL_DEL, fd, 0);
}

/* main run */
int libe_wait(int waitmsec)
{
	int ret;
	struct event *t;

	if (s.epfd < 0) {
		/* start EPOLL */
		struct epoll_event evdat = {
			.events = EPOLLIN,
		};

		ret = s.epfd = epoll_create(NEVS);
		if (ret < 0)
			return ret;
		for (t = s.events; t; t = t->next) {
			evdat.data.ptr = t;
			ret = epoll_ctl(s.epfd, EPOLL_CTL_ADD, t->fd, &evdat);
			if (ret < 0) {
				close(s.epfd);
				s.epfd = -1;
				return ret;
			}
		}
	}

	ret = epoll_wait(s.epfd, s.evs, NEVS, waitmsec);
	s.nevs = (ret >= 0) ? ret : 0;
	return ret;
}

void libe_flush(void)
{
	int j;
	struct event *t;

	for (j = 0; j < s.nevs; ++j) {
		if (!s.evs[j].data.ptr)
			// cleared by evt_remove
			continue;
		t = s.evs[j].data.ptr;
		t->fn(t->fd, t->dat);
	}
	s.nevs = 0;
}

/* cleanup storage */
__attribute__((destructor))
void libe_cleanup(void)
{
	struct event *t;

	while (s.events) {
		t = s.events;
		s.events = t->next;
		free(t);
	}
	if (s.epfd >= 0)
		close(s.epfd);
}
