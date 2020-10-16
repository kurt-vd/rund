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
#ifndef _libe_h_
#define libe_h_
#ifdef __cplusplus
extern "C" {
#endif

/* watch for events on <fd> */
extern int libe_add_fd(int fd, void (*fn)(int fd, void *), const void *dat);

/* remove a watched <fd>
 * Nothing happens when no matching timeout is found
 */
extern void libe_remove_fd(int fd);

/* wait for any fd to become active, for up to <waitmsec> milliseconds */
extern int libe_wait(int waitmsec);

/* handle any queued events
 * This will call assigned handlers
 */
extern void libe_flush(void);

/* cleanup, called automatically on exit also
 * May be called twice.
 */
extern void libe_cleanup(void);

/* more precise control: RD & WR */
#define LIBE_RD	1
#define LIBE_WR	2

/* set fd to wait for RD and/or WR */
extern int libe_mod_fd(int fd, int mask);

/* retrieve RD/WR event mask */
extern int libe_fd_evs(int fd);

#ifdef __cplusplus
}
#endif
#endif
