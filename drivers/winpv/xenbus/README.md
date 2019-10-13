XenBus - The Xen Paravitual Bus Device Driver for Windows
=========================================================

The XenBus package consists of three device drivers:

*    xenbus.sys is a bus driver which attaches to a virtual device on the PCI
     bus and provides child devices for the other paravirtual device drivers
     to attach to.

*    xen.sys is a support library which provides interfaces for communicating
     with the Xen hypervisor

*    xenfilt.sys is a filter driver which is used to handle unplugging of
     emulated devices (such as disk and network devices) when paravirtual
     devices are available 

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

clean.py
--------

This removes any files not checked into the repository and not covered by
the .gitignore file.

get_xen_headers.py
------------------

This will import any necessary headers from a given tag of that Xen
repository at git://xenbits.xen.org/xen.git.
