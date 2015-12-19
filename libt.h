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
#ifndef _libt_h_
#define libt_h_
#ifdef __cplusplus
extern "C" {
#endif

/* libt's notion of now() */
extern double libt_now(void);

/* schedule a timeout @timerout seconds in the future */
extern void libt_add_timeout(double timeout, void (*fn)(void *), const void *dat);

/* repeat a previously scheduled timeout, @increment seconds further
 * When no matching scheduled timeout is found, this is identical to
 * libt_add_timeout()
 */
extern void libt_repeat_timeout(double increment, void (*fn)(void *), const void *dat);

/* remove a scheduled timeout.
 * Nothing happens when no matching timeout is found
 */
extern void libt_remove_timeout(void (*fn)(void *), const void *dat);

/* return true if a timeout with given properties is currently scheduled
 * This API is not necessary for strict timeout keeping
 * but may be usefull to re-use the timeout presence as state.
 */
extern int libt_timeout_exist(void (*fn)(void *), const void *dat);

/* run callbacks for all timouts that have passed now */
extern int libt_flush(void);

/* retrieve earliest scheduled timeout, in absolute time like libt_now() */
extern double libt_next_wakeup(void);

/* retrieve earliest scheduled timeout in msecs, in relative time
 * This is practical for using in poll()
 */
extern int libt_get_waittime(void);

/* cleanup, called automatically on exit also
 * May be called twice.
 */
extern void libt_cleanup(void);

#ifdef __cplusplus
}
#endif
#endif
