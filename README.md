## Getting Started

The default `config.cmake` file will build the xen components and will
also install the build dependencies for creating PVH guest images.
The available targets can be listed with `make info`. By default,
the EFI binary of the VMM is not built; set ENABLE_BUILD_EFI to "ON" in
config.cmake to do so. The guest images are built under
${CACHE_DIR}/brbuild/<image name>. The following image names are recognized:

 - xsvm (contains xl toolstack, ndvm and vpnvm images, and pciback)
 - ndvm (contains drivers for supported NICs and netback)
 - vpnvm (contains wireguard VPN software, netback, and netfront)

The following drivers are built into the NDVM:

  - r8169 for Realtek devices
  - iwlwifi for Intel 9560 wireless devices
  - e1000e for Intel ethernet devices

More can be added by modifying the NDVM linux kernel config via
'make ndvm-linux-cfg'.

## Building

The instructions below assume the following directory structure:

```
workspace/
├── build/
├── cache/
└── microv/
```

Where 'microv' is the cloned repo, 'cache' is the bareflank depends
CACHE_DIR, and 'build' is the cmake build directory. With this layout,
microv can be built with the following commands:

```bash
$ cd build
$ cp ../microv/config.cmake ..
$ cmake ../microv/deps/hypervisor -DCACHE_DIR=../cache -DCONFIG=../config.cmake
$ make
```

MicroV comes with two drivers in addition to the upstream Bareflank driver:
builder and visr. These driver build targets are added to the make driver_*
commands whenever BUILD_BUILDER and BUILD_VISR cmake variables are enabled
in your config.cmake. You can also control each build individually using
the releveant commands listed in 'make info'.

The builder driver is responsible for allocating memory from the host OS and
creating state necessary for the guest to be run with uvctl (which is a
userspace component used to manage VMs, formerly known as bfexec).

The visr driver is used to support PCI passthrough. It registers an interrupt
handler with the host OS and forward each interrupt to the VMM so that it can
be delivered to the guest OS to which the interrupt has been assigned. Note
that visr (and PCI passthrough) only work if the VMM has been booted from EFI.

To clean, build, and load all the drivers, run:

```bash
cd build
make driver_quick
```

Once builder has been loaded, you can run virtual machines using uvctl. But
before that the images must be built. This is done using the make commands
listed in 'make info' that contain an image name in them. The supported names
are vpnvm, ndvm, and xsvm. To build the vpnvm, ndvm, and xsvm, run the following:

```bash
cd build
make vpnvm
make ndvm
make xsvm
```

Note that to successfully complete the build, libelf needs to be updated to
at least version 0.176. After those steps complete, you can run the xsvm:

```bash
cd build
cp ../microv/rundom0.sh .
./rundom0.sh
```

This will result in a prompt in the xsvm. You can run any command that is
contained in the image which is basically just busybox and the xl toolstack.
Currently, the following xl commands are supported: create, console, info, list,
destroy, network-attach, pci-assignable-*. To destroy the VM and return to the
host terminal, enter Ctrl-C. To exit a program running in the VM without killing
the VM, enter Ctrl-S if you're using Linux and Ctrl-A if you're using Cygwin.

In order to launch the NDVM from xsvm, you need to copy the NDVM's kernel and
initramfs into the xsvm's overlay directory:

```bash
$ cd workspace
$ cp cache/brbuild/ndvm/images/vmlinux microv/overlays/xsvm/boot/ndvm-vmlinux
$ cp cache/brbuild/ndvm/images/rootfs.cpio.gz microv/overlays/xsvm/boot/ndvm-rootfs.cpio.gz
$ make xsvm
```

Then re-run rundom0.sh and run the following from the xsvm command line:

```bash
$ xl create /etc/xen/ndvm.cfg
```

This will create the NDVM and start it. You can console into the NDVM using

```bash
$ xl console ndvm
```

You return back to the xsvm console with Ctrl-] (just like normal Xen). Note
that the same process can be used for running the VPNVM.

## PCI Passthrough

Currently, PCI passthrough is only available when booting the VMM from EFI.
By default, the VMM will hide each PCI network device from the root OS (i.e.
the OS that is booted after the VMM's EFI binary starts up). The VMM presents
a vendor of 0xBFBF, which is the vendor that the visr driver binds to. This
allows visr to acquire a vector and register an interrupt handler
with the root OS.

To passthrough network devices to the NDVM, you first have to add the appropriate
arguments to pciback in the *xsvm*. For example, to passthrough BDF 02:00.0, you
would pass

    --cmdline "xen-pciback.hide=(02:00.0) xen-pciback.passthrough=1"

to uvctl in the rundom0.sh script. More that one device can be used in the hide
parameter (google pciback for more info). In addition you can either add a pci
entry to the guest config file (see overlays/xsvm/etc/xen/ndvm.cfg for an example)
or you can assign the PCI device after the guest has booted with
xl pci-assignable-add.

## Windows PV drivers

Initial support of the Windows PV xenbus, xenvif, and xennet drivers has been
added. They are located at drivers/winpv. To build the drivers, you first need
to download the latest EWDK and run LaunchBuildEnv.cmd as Administrator. Then
from that environment navigate to drivers/winpv and run "powershell
clean-build.ps1". This will build the xenbus, xenvif, and xennet drivers.
Before running them, you need to add the *.pfx files located under
drivers/winpv to the trustedpublisher and root certificate stores with certmgr
(see deploy/windows/app.iss for examples on how to do this). Then you can
install the driver packages with deploy/windows/redist/x64/dpinst and reboot.
Note that you must run the VMM from EFI with the --enable-winpv option enabled
in order for the xenbus driver to be loaded by Windows.


