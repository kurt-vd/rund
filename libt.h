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

/* schedule a timeout @wakeuptime */
extern void libt_add_timeouta(double wakeuptime, void (*fn)(void *), const void *dat);

/* schedule a relative timeout @timeout seconds in the future */
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

/* return walltime */
extern double libt_walltime(void);

/* return the time-to-wait for the next timeslice
 * in walltime, so an interval can be synchronised to walltime
 * i.e. to make an interval of 2m elapse on the first second
 * of each even minute.
 * offset is the offset to the interval,
 * set -5 to wakeup 5sec before interval,
 * or +5 to wakeup 5sec after interval
 *
 * walltime is the reference walltime, normally current time
 * if the result would be less than timespan, then return
 * the time to the subsequent interval, i.e. skip 1
 */
extern double libt_timetointerval4(double walltime, double interval, double offset, double pad);

static inline double libt_timetointerval2(double interval, double offset)
{
	return libt_timetointerval4(libt_walltime(), interval, offset, interval*0.05);
}
static inline double libt_timetointerval(double interval)
{
	return libt_timetointerval2(interval, 0);
}

#ifdef __cplusplus
}
#endif
#endif
