XenNet - The Xen Paravitual Network Device Driver for Windows
=============================================================

The XenNet package consists of a single device driver:

*    xennet.sys is an NDIS6 miniport driver which attaches to a virtual
     device created by XenVif and uses the *netif* wire protocol
     implementation in XenVif to interface to a paravirtual network
     backend. 

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
