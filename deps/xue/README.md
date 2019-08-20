# Xue USB 3 Debugger

Xue is a cross-platform driver for the USB 3 Debug Capability (DbC). It is a
header-only library so that it may be easily included into various
environments. The goal of Xue is to provide a high-bandwidth debugger that can
be used with two standard mobile/laptop devices without the need for legacy
UART hardware.

### Hardware Requirements

To use xue, you need two machines: a target and a host. The target (the one
you're debugging) must have a USB 3 xHCI host controller that
implements the Debug Capability as described in the xHCI
[specification](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf).
So far the following Intel (PCI vendor 0x8086) host controllers have been
tested to work:

  - Z370 (PCI device 0xA2AF)
  - Z390 (PCI device 0xA36D)
  - Wildcat Point-LP (PCI device 0x9CB1)
  - Sunrise Point-LP (PCI device 0x9D2F)

Devices not listed here will likely work after you add the appropriate `#define
XUE_XHC_DEV_*` to `xue.h`. If you have a device not listed above, and/or it
does not work after adding the `#define`, please open a merge request so
support can be added.

The host (the machine you're viewing the target output from) only needs one
Super-Speed port. The debug cable that connects the target to the host is an
A/A crossover cable that can be purchased
[here](https://www.datapro.net/products/usb-3-0-super-speed-a-a-debugging-cable.html).
The final requirement is that the cable must be connected directly to a root
Super-Speed port on the target, i.e., it will not work through a hub.

### Debug Targets

Xue is officially supported to run from the following environments:

  - UEFI [applications](test/test_efi.c) (based on gnuefi)
  - Linux kernel [modules](https://github.com/connojd/hypervisor/blob/xue/bfdriver/src/common.c#L373)
  - Bareflank [hypervisor](https://github.com/connojd/hypervisor/blob/xue/bfvmm/src/debug/unistd.cpp#L53)
  - Xen [hypervisor](https://github.com/connojd/xen/blob/xue/xen/drivers/char/xue.c)

> **NOTE:** To use the Xen example above, pass 'console=dbgp dbgp=xue' on the Xen command line

Xue requires a set of operations to properly communicate with the DbC hardware.
These operations are defined in `struct xue_ops` in `xue.h`. Xue provides default
implementations of these operations for each of the four systems above. However,
you may override each of these defaults in order to adapt xue to your target system.
To use xue in your own project, follow these steps:

  1. Ensure `include/xue.h` is in your include path
  2. Allocate and clear a `struct xue` and `struct xue_ops`
  3. If needed, implement system-specific `xue_ops` and initialize the previously allocated `struct xue_ops` with them
  4. Optionally allocate a structure for storing system-specific state. This may be used in conjunction with the operations defined in 3
  5. Open xue by passing the addresses of the above structures to `xue_open`
  6. Write data to xue with `xue_write`

Any NULL members of the `struct xue_ops` passed to `xue_open` will be set
to the xue_sys_* defaults defined for that system. If a member is not NULL,
then xue assumes it is a user-defined override and will simply call it.

### Debug Hosts

Xue itself runs on the target machine and sends any data provided to
`xue_write` to the debug host, which can be either Linux or Windows.
Each host platform has its own instructions outlined below you should
follow in order to read data from xue.

#### Linux

Xue presents itself as the xhci_dbc device over USB. This means that the Linux
driver on the host will bind the xhci_dbc driver to the device and will create
/dev/ttyUSBx file that can be read. You can read this file like any other
serial device, however the `scripts/read.sh` is provided to handle common
things like disconnects that may occur during development.

#### Windows 10

If your debug host is Windows 10, then you can use the `scripts/read.py` script
to read the target's output, but there are a few steps you need to do before
the script will work:
  - Install [zadig](https://zadig.akeo.ie)
  - Run zadig as admin
  - Click 'Device' -> 'Create New Device'
  - Enter 'Xue DbC Device' in the top text box
  - Enter '1D6B' in the left text box of USB ID
  - Enter '0010' in the middle text box of USB ID
  - Click 'Install Driver'

This will install the WinUSB driver and bind the DbC device to it whenever
the debug cable is connected and the DbC enabled.

> **NOTE:** The DbC is considered 'enabled' after a successful call to `xue_open`.

After WinUSB is installed, setup the python environment:
  - Install the latest python
  - Install pyusb with pip
  - Download 7zip and libusb
  - Unpack libusb with 7zip
  - Copy `<libusb>/MS64/dll/libusb-1.0.dll` to `C:\Windows\System\`

Now you should be able to run `python read.py` from a terminal to read the
output from the debug target.

### Known Limitations

  - Does not run from Windows 10. Based on earlier experiments, Windows
    does not allow multiple drivers to map in a given PCI MMIO region
    simultaneously. This prevents Xue from mapping in the DbC's registers
    because Window's xHCI driver already owns the mapping. If anyone
    knows a workaround for this, please share.

  - The DbC is subject to USB host controller resets. This means if any other
    code resets the host controller, the DbC is reset as well. This means that
    if you `xue_open` from EFI, the DbC will be reset. Xue checks if this
    occured before each write, and will re-initialize the device if it has been
    reset, but this could lead to data loss depending on when the host
    controller was reset.

  - The DbC is subject to DMA remapping. If the USB host controller is being
    remapped by an IOMMU, then the default xue_sys_* functions provided in
    `xue.h` may not work.

### Testing

To run the unit tests, pass -DBUILD_TESTS=ON to `cmake`. Then run `make test`.
This runs the actual test and performs static analysis of the resulting binary
with `clang-tidy`.

### Documentation

The portion of the code intended to be "public" is documented with doxygen.
You can generate the docs with `doxygen .doxygen.txt` from the source root.
That said, most of the "internal" code is documented in `xue.h` as well.
