Installing the XenBus Package
=============================

It's important to note that the build scripts generate a driver which is
*test signed*. This means that when the driver is installed on a 64-bit
version of Windows you must enabled testsigning mode otherwise your system
will fail signature verification checked on the next reboot.
If you wish to install the test certificate on the target system then copy
xenbus.pfx (which you'll find in he proj subdirectory) onto your system and
use certmgr to install it. (It is not password protected).

xenbus.sys binds to three PCI devices which may be synthesized by QEMU for
your VM:

1. PCI\\VEN_5853&DEV_0001
2. PCI\\VEN_5853&DEV_0002
3. PCI\\VEN_5853&DEV_C000&SUBSYS_C0005853&REV_01

Device 1 or 2 should always be present: This is the Xen Platform PCI Device.
Some versions of XenServer will synthesize variant 2. All upstream Xen
installations will synthesize variant 1.
Device 3 will be present if you are using QEMU 1.6 or newer and your
toolstack has enabled the XenServer PV Device.
The XenBus co-installer will bind the driver to any of these devices but the
driver will only be *active* (i.e. will only create child devices) for one
of them. If device 3 is present then that will be the active device. If
device 3 is not present then either device 1 or 2 (whichever variant is
present) will be active.

To install the driver on your target system, copy the contents of the xenbus
subdirectory onto the system, then navigate into the copy, to either the x86
or x64 subdirectory (whichever is appropriate), and execute the copy of
dpinst.exe you find there with Administrator privilege.
