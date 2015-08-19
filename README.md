# run-daemon

This is (yet another) init daemon, initially based on sinit[1][1].

_sinit_ restricts itself to reaping children,
and spawning an _init_ & _shutdown_ script.
I liked the idea very much.

The problem that _rund_ tries to solve is that the _init_ script
may spawn services, like sshd, httpd, ..., but noone will restart
the service if it fails.

Does restarting services belong to init's job?
System startup becomes simpler if I make it so. That's why.

_rund_ opens an anonymous unix datagram socket.
Adding restartable services is done via the _runc_ companion tool.

__Why is this better?__

System startup is, as with _sinit_, offloaded to a script,
and is thus not predefined inside the init program.

_rund_ is not statically configured. The lack of config files
imply that they should never be reloaded.
The operator is in charge, and may choose to remove a service,
add another service, without the need for configuration.

Dependancy based services require a big deal of knowledge, both from
the dependancy-based tool and from the administrator.
I found dependencies on service level of little use since
you better tell the tools which order to start things anyway.
Most services however will fail anyway when some required service
drops out, and will consequently drop out too.  
In short, it's nice as theory.

Special operations like _service pre-exec_, _service post-exec_, ...
can better be accomplished by an _wrapper_ program that deals with those
cases. This relieves the init daemon from handling zillion scenarios.

Parallelism, which is minimal during early startup, is achieved by
running commands in the shells background.
The early system startup, which is the most error-prone with almost no parallelism,
becomes as easy as shell script.

__How is the system started then?__

I add a bare version of my scripts in examples/

[1]: git.suckless.org/sinit
