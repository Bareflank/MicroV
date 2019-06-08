<img src="https://github.com/Bareflank/boxy/raw/master/docs/boxy_logo.png" alt="boxy-logo" align="right" height="300" />

<br>
<br>

[![GitHub version](https://badge.fury.io/gh/bareflank%2Fboxy.svg)](https://badge.fury.io/gh/bareflank%2Fboxy)
[![Build Status](https://travis-ci.org/Bareflank/boxy.svg?branch=master)](https://travis-ci.org/Bareflank/boxy)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/d7cbb095527c43e09e775f58912cd5fd)](https://www.codacy.com/app/rianquinn/boxy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Bareflank/boxy&amp;utm_campaign=Badge_Grade)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325/badge)](https://bestpractices.coreinfrastructure.org/projects/325)
[![Join the chat at https://gitter.im/Bareflank-hypervisor/Lobby](https://badges.gitter.im/Bareflank-hypervisor/Lobby.svg)](https://gitter.im/Bareflank-hypervisor/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Description

The Boxy Hypervisor is an open source hypervisor led by Assured Information Security, Inc. (AIS),
that provides support for custom, lightweight Linux and Unikernel virtual machines on any platform
including Windows, Linux and UEFI.

<br>

## Project Goals:

- **Intuitive, User-Friendly Interfaces:** Most of the open source hypervisors
  available today are difficult to set up, configure and use. The #1 goal of
  this project is create an open source hypervisor that is capable of supporting
  many different use cases with beautiful, easy to use interfaces. The
  "barrier to entry" should be as low as possible for researchers and admins
  alike.
- **Cross-Platform Support:** In open source, hypervisors that are capable of
  supporting guest virtual machines are mostly limited to Xen, KVM and
  VirtualBox. The first two only support Linux and BSD hosts and while VirtualBox
  expands this support to Windows and macOS, it sacrifices security.
  Boxy aims to support as many hosts as possible including Windows, Linux,
  BSD, macOS and any others without sacrificing performance and security.
- **Disaggregation and Deprivilege:** None of the above mentioned hypervisors
  have a true focus on a reduced Trusted Computing Base (TCB). Xen comes the closest
  and has made amazing progress in this direction, but a fully disaggregated and
  deprivileged host has yet to be fully realized or supported.
- **Performance:** Another important focus of the project is on performance.
  Existing hypervisors make heavy use of emulation where
  virtualization could be used instead, Furthermore, Xen and KVM only support
  Linux and BSD hosts and therefore are not capable of leveraging some of the
  performance benefits of macOS and Windows such as power management
  (i.e. battery life on mobile devices).
- **Scheduling:** Although closely related to performance, Boxy leverages a hybrid
  design, incorporating the design goals of Xen to provide disaggregation
  and deprivilege while leveraging the scheduling benefits of hypervisor designs
  like KVM and VirtualBox. Specifically Boxy doesn't include its own scheduler,
  relying on the host to schedule each VM along with the rest of the critical
  tasks it must perform. Not only does this reduce the over complexity and size
  of Boxy, but it allows Boxy to leverage the advanced schedulers already
  present in the host while simultaneously removing the contention between the
  host scheduler and the hypervisor scheduler, often seen in Xen.
- **Early Boot and Late Launch Support:** Xen, KVM and VirtualBox support early boot
  (i.e. the hypervisor starts first during boot) or late launch (meaning the host
  starts first, and then the hypervisor starts). None of these hypervisors support
  both. Early boot is critical
  in supporting a fully deprivileged host while late launch is easier to set
  up, configure and use. Late launch is also a lot easier on developers,
  preventing the need to reboot each time a line of code changes in the
  hypervisor itself. Boxy aims to support both early boot and late launch from
  inception, giving both users and developers as many options as possible.
- **Robust Testing, CI and CD:** Although Xen, KVM and VirtualBox provide various
  levels of testing, continuous integration and continuous deployment, Boxy
  aims to take this a step further, providing the highest levels of testing
  possible. This will not only improve reliability and security, but also enable
  the use of Boxy in environments were high levels of testing are required such
  as critical infrastructure, medical, automotive and government.
- **Licensing:** Most of the hypervisors available today in open source leverage
  the GPL license making it difficult to incorporate their technologies in
  closed source commercial products. Boxy is licensed under MIT. Feel free to use
  it however you wish. All we ask is that if you find and fix something
  wrong with the open source code, that you work with us to upstream the fix.

### Version 1 Targeted Use-Cases

Boxy is in its early stages of development and as such, it is not, and will not
be capable of supporting all of the use cases that existing, more mature
hypervisors are capable of supporting. Version 1 of Boxy aims to start
somewhere by supporting the following use cases on Windows and Linux hosts:

- **Services VMs:** The most highly requested feature is the ability to execute
  specialized applications in the background using what is called a "Service VM".
  Service VMs are (ideally small) virtual machines that execute a specialized
  workload alongside the host. The difference with Boxy compared
  to other hypervisors is that Boxy can be used to execute a Service VM alongside
  the host while being capable of protecting the Service VM from the host
  (and vice versa). This means that Boxy can be used to do things like execute
  your system's anti-virus in a Service VM instead of directly on the host
  where malware could potentially turn it off. Another example would be to
  leverage Boxy to execute critical software in an isolated environment including
  things like automotive, healthcare and critical infrastructure software.
  To support this goal, Boxy leverages as much automated testing as possible.

- **Introspection/Reverse Engineering:** One specific use case for a Service VM
  is introspection and reverse engineering. Specifically, we aim to provide a
  simple environment for executing LibVMI in a Service VM with the ability to
  safely introspect and reverse engineer the host OS (both Windows and Linux).

- **Web Services:** Another specific use case for a Service VM that we aim to
  support in version 1 are web services. Specifically providing the ability to
  execute several, headless web services simultaniously on a single machine.

There are several other use cases that we would like to support with Boxy in
future versions like full Windows guest support, Containerization, and
of course Cloud Computing, but for now the above use cases are our primary focus
until version 1 is complete.

## Virtualization vs Emulation

One question that comes up a lot is the difference between virtualization and
emulation. In general, there are three ways in which you can talk to a
physical piece of hardware.

- Directly: This is the best way to talk to hardware. In hypervisor environments,
  this is usually done using an IOMMU (also called PCI Passthrough). The issue
  with this approach is that a single VM owns a physical piece of hardware (i.e.
  the hardware is not shared).
- Emulation: One way to share a physical device is to provide each virtual
  machine with an emulated device. Emulation mimics a real, physical device in
  software. Access to the emulated device can then be multiplexed onto a
  single physical device by the hardware. QEMU is often used to provide this
  emulation in existing open source hypervisors. The problem with emulation is
  that the hardware devices being emulated often contain interfaces that are
  not easy or performant to emulate in software. For example, these interface
  might make heavy use of Port IO and Memory Mapped IO, both of which are
  slow and prone to error when emulating in software. This type of hardware
  also often contains timing constraints in the interface designs that are
  even more difficult to ensure in software, especially when interactions
  with the emulated software can be preempted by another virtual machine.
- Virtualization: Aother way to share a physical device is to create virtual
  devices. Virtual devices do not mimic real hardware and instead create a
  brand new, software defined virtual device with an interface that is designed
  specifically to be performance and reliable in virtual environments.
  Virtualization should always be used in place of emulation when possible. The
  biggest issue with virtualization is most operating systems do not come
  pre-packaged with support for virtual devices. Although emaultion is slow and
  unreliable, most operating systems come pre-packaged with the device drivers
  needed to communicate with the device being emulated meaning unmodified versions
  of the OS can be used.

Our goal with this project is to limit our use of emulation as much as possible.
For Linux, this is simple as Linux can be modified to support our virtual devices,
similar to how Xen and KVM work today. Unlike Xen and more like KVM, we aim to keep
our modifications to Linux as self contained as possible while requiring Hardware
Virtualization support (i.e. Xen's PVH model). Unlike KVM we wish to ensure things like
PCI interfaces and QEMU in general are not required. We also aim to ensure our
virtual interfaces support any host operating system including Windows, Linux and
UEFI. To accomplish this, our virtual interfaces will only leverage hypercall
(e.g. vmcalls on Intel) based APIs with the only exception being some CPUID based
enumeraton logic needed when detecting the present of Boxy.

## Compilation Instructions

To compile with default settings for your host environment, run the following commands:

```
git clone --recursive https://github.com/Bareflank/boxy.git
mkdir boxy/build; cd boxy/build
cmake ../hypervisor
make -j<# cores + 1>
```

## Usage Instructions

To use the hypervisor, run the following commands:

```
make driver_quick
make quick
```

to get status information, use the following:

```
make status
make dump
```

to reverse this:

```
make unload
make driver_unload
```
to clean up:

```
make distclean
```

to execute a vm:

```
./prefixes/x86_64-userspace-elf/bin/bfexec --bzimage --path prefixes/vms/bzImage --initrd prefixes/initrd.cpio.gz --uart=0x3F8 --verbose
```
