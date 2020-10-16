# event + timeout handling library

The purpose of this (very) small library is to deal with asynchronous
(file descriptor) events & timeouts.

Why yet another library?

I __think__ that the semantics for events & timeouts are so different
that I did not merge it into 1 API. Instead, events & timeouts
each have their own API, which will easily integrate together.  
If you want a timeout on a certain event, you should combine that
in your code, not in the library.

This library should allow you to easily schedule
a callback on event or timeout, without having to adhere much
to a predefined skeleton.
The core loop of my program should be defined by my program,
not by some library.  
As such, libet has no required initializations or cleanup API calls.  
__libe_cleanup__ is provided in case the programs needs forking.

Not all programs need both timeout handling and event handling.
The program stays simplere with timeout & event handling seperated, 

The library is meant to be included as source.
I was not interested in shared objects, although it is possible.

The timeout handling comes with a simple test program.
This may help you to understand it.

I have no clue how to (easily) write such test program
for the event handling.

## event API

Add/remove a file descriptor for event monitoring

	extern int libe_add_fd(int fd, void (*fn)(int fd, void *), const void *dat);
	extern void libe_remove_fd(int fd);

Wait for events, up to _waitmsec_ milliseconds

	extern int libe_wait(int waitmsec);

Handle all queued events from last call to __libe_wait()__

	extern void libe_flush(void);

## timeout API

Times are in seconds, as floating points.
This implies linking with __-lm__!

Schedule a timeout in the future

	extern void libt_add_timeout(double timeout, void (*fn)(void *), const void *dat);

Increment/repeat a previously scheduled timeout.
When no timeout is found, this is equal to __libt_add_timeout__.

Incrementing is valid until a timeout callback handler is left.
This means that you can increment the timeout within its handler, altough
is has technically been passed already.

	extern void libt_repeat_timeout(double increment, void (*fn)(void *), const void *dat);

Remove a timeout

	extern void libt_remove_timeout(void (*fn)(void *), const void *dat);

Run callbacks for all timouts that have passed.

	extern int libt_flush(void);

Retrieve the time (in milliseconds!) from now to the first timeout.

	extern int libt_get_waittime(void);

Some other API calls exist, you can inspect them in the sources.

## netrc API

The netrc API is to find a username and/or password for a given
host or host+username.

	int lib_netrc(const char *host, char **user, char **pwd)

The lookup is done in `~/.netrc`.
Please refer to `curl` man page for more detailed info on `~/.netrc`

Enjoy!
