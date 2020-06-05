# pam2control
[![Build Status](https://travis-ci.org/alexander-naumov/pam2control.svg?branch=master)](https://travis-ci.org/alexander-naumov/pam2control)

pam2control, commonly known as p2c, is the easily configurable system to
control access to host by using PAM interfaces.
It makes it possible to manages access for some users (or group of users)
just by adding one single line to the config file.
It can notify you by sending an email if somebody login on server.
It uses syslog and also its own logfile for every login-/logout-events.

It's implemented in C and supports FreeBSD and GNU/Linux systems.

## Installing pam2control
```
> cd src
> make
# make install
```
The p2c.conf man page has details on how to configure pam2control.

## Credits

Copyright (c) 2018-2020 Alexander Naumov (alexander_naumov@opensuse.org).

Licensed under GNU GPLv3 (see [LICENSE](https://github.com/alexander-naumov/pam2control/blob/master/LICENSE) file).
