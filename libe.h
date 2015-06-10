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

#ifdef __cplusplus
}
#endif
#endif
