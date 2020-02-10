XenIface - The Xen Interface Driver for Windows
===============================================

The XenIface package consists of a single device driver:

*    xeniface.sys is a driver which attaches to a virtual device created
     by XenBus and provides a WMI to xenstore (and also an IOCTL interface
     for simple xenstore read/write access).

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
