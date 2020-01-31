## Getting Started

The default `scripts/cmake/config/config.cmake` file will build the xen
components of the vmm. This can be controlled with the BUILD_XEN cmake
variable. Also by default, the EFI binary of the VMM is not built; set
ENABLE_BUILD_EFI to "ON" in your config.cmake to do so.

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
$ cp ../microv/scripts/cmake/config/config.cmake ..
$ cmake ../microv/deps/hypervisor -DCONFIG=../config.cmake
$ make
```

Note that, if desired, ninja may be used instead of make by passing '-G Ninja'
to the cmake invocation above. Parallel builds are fully supported as well.

MicroV comes with two drivers in addition to the upstream Bareflank driver:
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

Once builder has been loaded, you can run virtual machines using uvctl. But
before that the images must be built. This is done using the brext-microv
repo located at https://gitlab.ainfosec.com/bareflank/brext-microv. This
repo is structured as a br2-external tree (see the upstream buildroot docs if
you don't know what that is). Please see the README in that repo for more
information on how to build and run VMs compatiable with microv.
