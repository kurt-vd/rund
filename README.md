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

--

_sinit_[1] restricts itself to reaping children,
and spawning an _init_ & _shutdown_ script.
I liked the idea putting startup & shutdown in a simple shell script
very much. By the way, it may be a binary as well.

The problem that _rund_ tries to solve is that the _init_ script
may spawn services, like sshd, httpd, ..., but noone will restart
the service if it fails.

Does restarting services belong to init's job?

* System startup becomes simpler if I make it so. That's why.
* A service monitor that is not PID 1, does it monitor PID 1 as well?
* The kernel only verifies that PID 1 does not exit, but does not verify
  if it stalled ...
* Having PID 1 be the supervisor is a trivial solution to most problem.
* Keeping PID 1 minimal is the challenge.
  [_sinit_][1] performs well here. _systemd_ clearly does not.

_rund_ opens an anonymous unix datagram socket.
Adding restartable services is done via the _runcl_ companion tool.

__Why is this better?__

System startup is, as with [_sinit_][1], offloaded to a script,
and is thus not predefined inside the init program.

_rund_ is not statically configured. The lack of config files
imply that they should never be reloaded. Have you ever tried modifying
the behaviour of init on a readonly rootfs?
The operator is in charge, and may choose to remove a service,
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
