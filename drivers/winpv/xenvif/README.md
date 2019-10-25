XenVif - The Xen Paravitual Network Class Driver for Windows
============================================================

The XenVif package consists of a single device driver:

*    xenvif.sys is a bus driver which attaches to a virtual device created
     by XenBus and creates a child device for each VIF for XenNet to attach
     to.
     It is also a protocol driver for the netif wire protocol (see
     include\\xen\\io\\netif.h).

Quick Start Guide
=================

Building the driver
-------------------

See BUILD.md

Installing the driver
---------------------

See INSTALL.md

Driver Interfaces
=================

See INTERFACES.md

Miscellaneous
=============

For convenience the source repository includes some other scripts:

kdfiles.py
----------

This generates two files called kdfiles32.txt and kdfiles64.txt which can
be used as map files for the .kdfiles WinDBG command.

sdv.py
------

This runs Static Driver Verifier on the source.

clean.py
--------

This removes any files not checked into the repository and not covered by
the .gitignore file.

get_xen_headers.py
------------------

This will import any necessary headers from a given tag of that Xen
repository at git://xenbits.xen.org/xen.git.
