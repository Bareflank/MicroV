## Getting Started

The default `scripts/cmake/config/config.cmake` file will build the xen
components of the vmm. This can be controlled with the BUILD_XEN cmake
variable. Also by default, the EFI binary of the VMM is not built; set
ENABLE_BUILD_EFI to "ON" in your config.cmake to do so.

## Building the VMM

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
$ cp ../microv/scripts/cmake/config/config.cmake ..
$ cmake ../microv/deps/hypervisor -DCONFIG=../config.cmake
$ make
```

Note that, if desired, ninja may be used instead of make by passing '-G Ninja'
to the cmake invocation above. Parallel builds are fully supported as well.
The output of this step is a built vmm ready to run from late-launch.
To be able run from early-launch (i.e. EFI), re-build with ENABLE_BUILD_EFI set
to ON.

## Building the drivers

Microv comes with two drivers in addition to the upstream Bareflank driver:
builder and visr. These drivers' build targets are added to the make driver_*
commands whenever the BUILD_BUILDER and BUILD_VISR cmake variables are enabled
in your config.cmake. You can also control each driver build individually using
the relevant commands listed in 'make info'.

The builder driver is responsible for allocating memory from the host OS and
creating state necessary for the guest to be run with uvctl (which is a
userspace component used to manage VMs, formerly known as bfexec).

The visr driver is used to support PCI passthrough. It registers an interrupt
handler with the host OS that forwards each interrupt to the VMM so that it can
be delivered to the guest OS to which the interrupt has been assigned. Note
that visr (and PCI passthrough) only work if the VMM has been booted from EFI.

To clean, build, and load all the drivers that are currently enabled in
the cmake config, run:

```bash
cd build
make driver_quick
```

## Running the VMM

To start the vmm from late-launch do the following:

```bash
$ make quick
```

To start the vmm from EFI, copy bareflank.efi to your EFI partition and arrange
for it to be run prior to your OS. I typically install a pre-compiled UEFI
shell from the tianocore EDK2 github repo, then run bareflank.efi from there.
This approach has the added advantage of being able to pass command line argumnets
to bareflank.efi. The arguments it understands are contained in
`deps\hypervisor\bfdriver\src\platform\efi\entry.c`. Also note that load_start_vm defined
in that same file chooses the thing that bareflank.efi boots next (the default is
EFI\boot\bootx64.efi. You will need to change this to point to, e.g. the shell or grub,
if you don't want to boot into Windows.

## Building Guest Images

Once the vmm has been started and builder has been loaded, you can run virtual
machines using uvctl. But before that the images must be built. This is done using
the br2-microv repo located at https://gitlab.ainfosec.com/bareflank/br2-microv.
To build the images described there:

```bash
$ cd workspace
$ git clone -b venom git@gitlab.ainfosec.com:bareflank/br2-microv.git
```

Then follow the steps in br2-microv/README.md. After you perform those steps,
return to the section below for information on how to run them.

## Running Guest Images

uvctl is the userspace application used to launch guest vms. Before a VM is run,
uvctl IOCTLs to the builder driver with the VM's parameters, such as RAM and the path
to vmlinux and rootfs.cpio.gz, as produced by the build step above. Builder
then allocates memory and performs hypercalls prior to the VMM starting the vcpu. Each
vcpu is then associated with a uvctl thread. This thread is then scheduled by the host OS
just like any other thread on the system. In addition, whenever --hvc is passed to uvctl,
it forks a read thread and write thread for communicating with the VM's hvc console.

By default uvctl is located at `build/prefixes/x86_64-userspace-elf/bin`. You can see the
available options by passing -h to uvctl. In addition, you can use the helper script
located at `scripts/util/rundom0.sh` to use common values for the typical options.
You may need to adjust the paths for your system; please read the script before running
it so you understand what it does.

Assuming you launched the xsvm with rundom0.sh, you can use xl to create domains
you compiled in to xsvm (such as the ndvm) using the hvc console.
