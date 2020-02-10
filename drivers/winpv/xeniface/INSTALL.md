Installing XenIface
===================

It's important to note that the build scripts generate a driver which is
*test signed*. This means that when the driver is installed on a 64-bit
version of Windows you must enabled testsigning mode otherwise your system
will fail signature verification checked on the next reboot.
If you wish to install the test certificate on the target system then copy
xeniface.pfx (which you'll find in he proj subdirectory) onto your system and
use certmgr to install it. (It is not password protected).

xeniface.sys binds to one of three devices which may be created by XenBus:

1. XENBUS\\VEN_XSC000&DEV_IFACE&REV_00000001
2. XENBUS\\VEN_XS0001&DEV_IFACE&REV_00000001
3. XENBUS\\VEN_XS0002&DEV_IFACE&REV_00000001

The particular device present in your VM will be determined by the binding
of the XenBus driver. The DeviceID of the PCI device to which it is bound is
echoed in the VEN_ substring of the devices it creates. Hence only one of the
above three variants will be present.

To install the driver on your target system, copy the contents of the xeniface
subdirectory onto the system, then navigate into the copy, to either the x86
or x64 subdirectory (whichever is appropriate), and execute the copy of
dpinst.exe you find there with Administrator privilege.
