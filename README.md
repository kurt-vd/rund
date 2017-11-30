# run-daemon

This is (yet another) init daemon, initially based on [sinit][1].

rund merges the best of 2 init approaches.
rund itself is an init daemon that only supervises services.
The boot process is offloaded to an external bootscript.
This bootscript or any other process can ask rund to
__run+supervise__ processes.
The configuration of the boot process is reduced to shell script,
or any other program of your choice.
Yet, complex constructs for service selection
remain possible.

Spawning services in parallel during boot is easily done
with backgrounding parts of the script, a technique that existed
for years.

---

_sinit_[1] restricts itself to reaping children,
and spawning an _init_ & _shutdown_ script.
I liked the idea putting startup & shutdown in a simple shell script
very much. By the way, it may be a binary as well.

The problem that _rund_ tries to solve is that the _init_ script
may spawn services, like sshd, httpd, ..., but noone will restart
the service if it fails.

How?

_rund_ opens an anonymous unix datagram socket.
Adding restartable services is done via the _runcl_ companion tool.

Does restarting services belong to init's job?

System startup becomes simpler if I make it so. That's why.

Hum, why exactly?

The service supervisor is the trivial candidate for servicing
the system watchdogs, if any (rund does support multiple watchdogs).
If _init_ is not the supervisor, then _init_ is not covered by
a watchdog. Is _init_ moinitored then?

On systems without watchdog, the problem also exists, but does not require
a solution...

How would the system react if _init_ stalled, and everything else
runs fine?

There is not universal good answer to the above questions, and that
is the argument against a seperate supervisor.
A system without the supervisor being _init_ is one without a supervisor
at all. Use [sinit][1] in that case.

__Why is this better?__

System startup is, as with [_sinit_][1], offloaded to a script,
and is thus not predefined inside the init program.

_rund_ is not statically configured. The lack of config files
imply that they should never be reloaded. Have you ever tried modifying
the behaviour of init on a readonly rootfs?
With _rund_, the operator is in charge, and may choose to remove a service,
add another service, without the need for configuration written to the rootfs.

Dependancy based services require a big deal of knowledge, both from
the dependancy-based tool and from the administrator.
I found dependencies on service level of little use since
you must propagate dependencies properly to inside the service itself anyway.
Not doing so may cause unexpected results, and having a dependancy based
init system only postpones the discovery of such problem until an inconvenient
point in time.
Most services however will fail anyway when some required service
drops out, and will consequently drop out too.  
In short, dependency based booting is nice as theory.

Special operations like _service pre-exec_, _service post-exec_, ...
can better be accomplished by an _wrapper_ program that deals with those
cases. the pre-exec & post-exec concepts do not belong the init system since
those belong inside the entity that we describe as _service_.
This relieves the init daemon from handling zillion scenarios.

Parallelism, which is minimal during _early_ startup, is achieved by
running commands in the shells background.
The early system startup, which is the most error-prone with almost no parallelism,
becomes as easy as shell script.

__How is the system started then?__

I add a bare version of my scripts in examples/

__Is it fast?__

The systems I migrated to rund did boot equally fast as busybox init
(not using scripts, completely configured in /etc/inittab),
and minimally faster than systemd (systemd fails on loading+reading configuration).

[1]: git.suckless.org/sinit
