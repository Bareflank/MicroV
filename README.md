<img src="https://github.com/Bareflank/MicroV/raw/master/.github/images/microv_logo.png" alt="microv-logo"/>

## Description

**warning**: MicroV is currently a work in progress. If you need support now,
please see the [Mono](https://github.com/Bareflank/MicroV/tree/mono) branch until MicroV is more complete which is expected to be some time Q1 of 2022.

The MicroV Hypervisor is an open source, micro-hypervisor led by [Assured
Information Security, Inc.](https://www.ainfosec.com/), designed specifically
to run micro VMs (i.e., tiny virtual machines that require little or no
emulation).

<img src="https://github.com/Bareflank/MicroV/raw/master/.github/images/high_level.png" alt="highlevel"/>

## Advantages:
Unlike existing hypervisors, MicroV's design has some unique advantages including:
<img src="https://github.com/Bareflank/MicroV/raw/master/.github/images/cross_platform.png" alt="cross-platform" align="right" height="300" />
- **Cross-Platform Support:** In open source, examples of hypervisors that are
  capable of supporting guest virtual machines include Xen, KVM, and
  VirtualBox. The first two only support Linux and BSD and VirtualBox
  expands this support to Windows and macOS, while sacrificing security. MicroV
  aims to support as many operating systems as possible including Windows,
  Linux, UEFI and others while maintaining performance and security. This is
  accomplished by compiling the hypervisor as a self-contained binary,
  independent of the root operating system. All of the applications provided
  by MicroV are written in raw C++ to maximize cross-platform
  support, and any code that is platform specific, including drivers, is
  broken into the platform specific logic (which is minimal) and common logic
  that can be used across all platforms.

- **Disaggregation and Deprivilege:** None of the above mentioned hypervisors
  have a true focus on a reduced Trusted Computing Base (TCB). Xen comes the
  closest and has made amazing progress in this direction, but a fully
  disaggregated and deprivileged hypervisor has yet to be fully realized or
  supported. MicroV's design starts with a microkernel architecture inside
  the hypervisor, running most of it's internal logic at lower privilege
  levels. On Intel, when virtualization is enabled, the CPU is divided into
  the host and the guest. The hypervisor runs in the host, while the operating
  system runs in the guest. *Both* the host and the guest have a Ring 0 and
  Ring 3 privilege level. Monolithic hypervisors like Xen and KVM run most,
  if not all of the hypervisor in Ring 0 of the host. Typically we call this
  Ring -1. This picture is far more complicated when you include System
  Management Mode (SMM) which adds two more Ring 0s, so lets pretend they do
  not exist for now. The thing is, this is not the only way to construct a
  hypervisor. Like the operating system in each guest, the hypervisor can use
  both Ring 0 and Ring 3 in the host, keeping the Ring 0 component as small as
  possible, while running most of the logic in Ring 3. In some ways, this is
  how KVM works. The kernel part of the hypervisor in KVM is the entire Linux
  kernel while VM management and emulation is handled in Ring 3 by QEMU
  (usually). The obvious problem with this design, besides the lack of
  cross-platform support is the size of the TCB is huge. MicroV's design
  leverages the Bareflank microkernel which is a small kernel capable of
  executing hypervisor extensions in Ring 3 of the host. By itself,
  Bareflank's microkernel is not capable of executing virtual machines,
  but instead relies on an extension to provide the meat and potatoes. MicroV,
  at its most basic level is a Bareflank extension that runs in Ring 3, that
  provides guest virtual machine support.

- **Performance:** Another important focus of the project is on performance.
  Existing hypervisors make heavy use of emulation where virtualization could
  be used instead, Furthermore, Xen and KVM only support Linux and BSD and
  therefore are not capable of leveraging some of the performance benefits of
  macOS, Android and even Windows such as scheduling and power management,
  which becomes evident when attempting to use these hypervisors on laptops and
  mobile devices. Other approaches to microkernel hypervisors attempt to
  provide their own device drivers, schedulers and power management algorithms.
  This limits their ability to widely support hardware, and guarantees a
  compromised user experience. The operating system that was built for a
  device should be the operating system that manages the device.

- **Virtual Device Support:** Hypervisors like KVM manage all physical devices
  in Ring 0 of the host (the most privileged code on the system) using the
  Linux kernel. This is one way in which Xen is more deprivileged than KVM.
  Unlike KVM which runs device drivers in Ring 0 of the host, Xen runs device
  drivers in Ring 0 of the guest (specifically in Dom 0). MicroV aims to
  take a similar approach to Xen, keeping the code in the host as small as
  possible, and instead, delegating the guest operating system to manage the
  physical devices it is given. All virtual device backend drivers run in Ring
  0 or Ring 3 of the root VM, which is the main virtual machine on the
  system.

  <img src="https://github.com/Bareflank/MicroV/raw/master/.github/images/scheduler.png" alt="cross-platform" align="right" height="300" />
- **Scheduling:** Although closely related to performance, MicroV leverages a
  hybrid design, incorporating the design goals of Xen to provide disaggregation
  and deprivilege while leveraging the scheduling benefits of hypervisor designs
  like KVM and VirtualBox. Specifically MicroV doesn't include its own scheduler
  , relying on the root VM's operating system to schedule each VM along with the
  rest of the critical tasks it must perform. Not only does this reduce the
  overall complexity and size of MicroV, but it allows MicroV to leverage the
  advanced schedulers already present in modern operating systems. Since MicroV
  is designed with cross-platform in mind, this also means that support for
  custom schedulers is possible, including RTOS schedulers.

- **AUTOSAR Compliance:** Although Xen, KVM and VirtualBox provide various
  levels of testing, continuous integration and continuous deployment, MicroV
  aims to take this a step further, providing the highest levels of testing
  possible to support standards such as ISO 26262. In addition, MicroV was
  re-engineered from the ground up using the AUTOSAR coding guidelines (MicroV
  is our third iteration of this hypervisor project). This will not only
  improve reliability and security, but also enable the use of MicroV in
  critical system environments were high levels of testing are required such
  as automotive, medical, space and government.

- **Early Boot and Late Launch Support:** Xen, KVM and VirtualBox support
  early boot (i.e., the hypervisor starts first during boot) or late launch
  (i.e., the operating system starts first, and then the hypervisor starts).
  None of these hypervisors support both.

  <p align="center">
  <img src="https://github.com/Bareflank/MicroV/raw/master/.github/images/boot_order.png" alt="highlevel" height="300"/>
  </p>

  Early boot is critical in supporting a fully deprivileged host while late
  launch is easier to set up, configure and use. Late launch is also a lot
  easier on developers, preventing the need to reboot each time a line of code
  changes in the hypervisor itself. MicroV aims to support both early boot and
  late launch from inception, giving both users and developers as many options
  as possible.

- **Licensing:** Most of the hypervisors available today in open source
  leverage the GPL license making it difficult to incorporate their
  technologies in closed source commercial products. MicroV is licensed
  under MIT. Feel free to use it however you wish. All we ask is that if you
  find and fix something wrong with the open source code, that you work with
  us to upstream the fix. We also love pull requests, RFCs, bug reports and
  feature requests.

## Disadvantages:
No design is without its disadvantages:
- **VM DoS Attacks**:
  Since the main operating system is responsible for scheduling micro VMs for
  execution, it is possible that an attack in this operating system could
  prevent the micro VMs from executing (i.e., DoS attack). For most
  applications, this type of attack is a non-issue as isolation is more
  important than resilience against DoS attacks. With that said, there is no
  reason why a micro VM could not be in charge of scheduling VMs with its own
  scheduling and power management software (just like it would be possible to
  run all of the tool stack software in a dedicated micro VM as well). Like
  Xen, MicroV is designed to ensure these facilities are not dependent on the
  main operating system. The upstream project simply defaults to this type of
  configuration as its the larger, more prevalent use case. And keep in mind
  that there is always a tradeoff. Although the upstream approach is vulnerable
  to DoS attacks, implementing your own scheduler and power management software
  is no easy task, and should be limited to specific use cases (unless
  performance and battery life is not important).

## **Quick start**
TBD

## Interested In Working For AIS?
Check out our [Can You Hack It?®](https://www.canyouhackit.com) challenge and test your skills! Submit your score to show us what you’ve got. We have offices across the country and offer competitive pay and outstanding benefits. Join a team that is not only committed to the future of cyberspace, but to our employee’s success as well.

<p align="center">
  <a href="https://www.ainfosec.com/">
    <img src="https://github.com/Bareflank/MicroV/raw/master/.github/images/ais.png" alt="cross-platform" height="100" />
  </a>
</p>

## Demo
TBD

## **Build Requirements**
Currently, MicroV only supports the Clang/LLVM 10+ compiler. This, however, ensures that MicroV can be natively compiled on Windows including support for cross-compiling. Support for other C++20 compilers can be added if needed, just let us know if that is something you need.

### **Windows**
To compile the BSL on Windows, you must first disable UEFI SecureBoot and enable test signing mode. Note that this might require you to reinstall Windows (**you have been warned**). This can be done from a command prompt with admin privileges:
```
bcdedit.exe /set testsigning ON
<reboot>
```

Next, install the following:
- [Visual Studio](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16) (Enable "Desktop development with C++")
- [WDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- [LLVM 10+](https://github.com/llvm/llvm-project/releases)
- [CMake 3.13+](https://cmake.org/download/)
- [Ninja](https://github.com/ninja-build/ninja/releases)
- [Git](https://git-scm.com/downloads)

Visual Studio is needed as it contains Windows specific libraries that are needed during compilation. Instead of using the Clang/LLVM project that natively ships with Visual Studio, we use the standard Clang/LLVM binaries provided by the LLVM project which ensures we get all of the tools including LLD, Clang Tidy and Clang Format. Also note that you must put Ninja somewhere
in your path (we usually drop into CMake's bin folder). Finally, **make sure you follow all of the instructions when installing the WDK**. These instructions change frequently, and each step must be installed correctly and in the order provided by the instructions. Skipping a step, or installing a package in the wrong order will result in a WDK installation that doesn't work.

To compile the BSL, we are going to use Bash. There are many ways to start Bash including opening a CMD prompt and typing "bash". Once running bash, make sure you add the following to your PATH:
- MSBuild
- devcon
- certmgr

For example, in your .bashrc, you might add the following (depending on where Visual Studio put these files):
```bash
export PATH="/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin:/c/Program Files (x86)/Windows Kits/10/Tools/x64:/c/Program Files (x86)/Windows Kits/10/bin/10.0.19041.0/x64:$PATH"
```

Finally, run the following from Bash:
```bash
git clone https://github.com/bareflank/microv
mkdir microv/build && cd microv/build
cmake ..
ninja info
ninja
```

### **Ubuntu Linux**
To compile the BSL on Ubuntu (20.04 or higher) you must first install the following dependencies:
```bash
sudo apt-get install -y clang cmake lld
```

To compile the BSL, use the following:
```bash
git clone https://github.com/bareflank/microv
mkdir microv/build && cd microv/build
cmake ..
make info
make
```

### **UEFI**
TBD

## Usage Instructions
MicroV is designed to use existing KVM userspace software to execute guest virtual machines from the root VM. To execute our integration tests that leverage the KVM API, do the following:

First, you need to place your current OS into a VM called the root VM. This is done by hoisting your current OS into a VM (often times called a VMX rootkit, but in our case, this is defensive, not offensive). To do this run the following:
```
make loader_quick
make -j<num cores>
make start
```

You can run the following to verify that your OS is not in the root VM:
```
make dump
```

And you should see something like:
```
 ___                __ _           _
| _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__
| _ \/ _` | '_/ -_)  _| / _` | ' \| / /
|___/\__,_|_| \___|_| |_\__,_|_||_|_\_\

Please give us a star on: https://github.com/Bareflank/hypervisor
==================================================================

DEBUG [0000:0000:0000:0000:0000:US]: root OS had been demoted to vm 0x0000 on pp 0x0000
DEBUG [0000:0000:0001:0001:0001:US]: root OS had been demoted to vm 0x0000 on pp 0x0001
DEBUG [0000:0000:0002:0002:0002:US]: root OS had been demoted to vm 0x0000 on pp 0x0002
DEBUG [0000:0000:0003:0003:0003:US]: root OS had been demoted to vm 0x0000 on pp 0x0003
DEBUG [0000:0000:0004:0004:0004:US]: root OS had been demoted to vm 0x0000 on pp 0x0004
```

To be able to run KVM APIs, you must load the shim driver, which acts like KVM. To do this, run:
```
make shim_quick
```

You can only run the shim driver AFTER MicroV has started. Otherwise you will get a failure. If you look at `dmesg`, you will see that the shim driver will have complained that MicroV's is not running, which likely means that you need to rerun `make start`.

If `make start` fails, it means that Bareflank's loader is not running, which is why we can `make loader_quick`.

From here, you can run whatever integration test you want. For example:
```
make kvm_create_vm
make kvm_create_vcpu
```

You can see the results of the integration test by either looking at the resulting console output, or looking at what MicroV's debug buffer contains by using `make dump`.

You can also run MicroV's integration tests as well. These are tests designed to talk directly to MicroV instead of using the KVM APIs. For example:
```
make mv_handle_op_open_handle
make mv_handle_op_close_handle
```

You do not need the shim driver to run these integration tests, and yes, you can use the MicroV ABIs to write your own VMM without the need for the KVM shim, or any of the KVM APIs if you would like. This removes the need for the additional kernel calls and overhead of the shim driver, but requires that you write your own VMM software as things like QEMU and rust-vmm will not work without modifications to talk directly to MicroV instead of to MicroV via the KVM APIs.

## **Resources**
[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://bareflank.herokuapp.com/)

MicroV provides a ton of useful resources to learn how to use the library including:
-   **Documentation**: <https://bareflank.github.io/microv/>
-   **Unit Tests**: <https://github.com/Bareflank/microv/tree/master/test>

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:
-   **Slack**: <https://bareflank.herokuapp.com/>
-   **Issue Tracker**: <https://github.com/Bareflank/microv/issues>

If you would like to help:
-   **Pull Requests**: <https://github.com/Bareflank/microv/pulls>
-   **Contributing Guidelines**: <https://github.com/Bareflank/microv/blob/master/contributing.md>

## **Testing**
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fbareflank%2Fmicrov%2Fbadge&style=flat)](https://actions-badge.atrox.dev/bareflank/microv/goto)
[![codecov](https://codecov.io/gh/Bareflank/microv/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/microv)

MicroV leverages the following tools to ensure the highest possible code quality. Each pull request undergoes the following rigorous testing and review:
-   **Static Analysis:** [Clang Tidy](https://github.com/Bareflank/llvm-project)
-   **Dynamic Analysis:** Google's ASAN and UBSAN
-   **Code Coverage:** Code Coverage with CodeCov
-   **Coding Standards**: [AUTOSAR C++14](https://www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf) and [C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)
-   **Style**: Clang Format
-   **Documentation**: Doxygen

## Serial Instructions
On Windows, serial output might not work, and on some systems (e.g. Intel NUC),
the default Windows serial device may prevent Bareflank from starting at all.
If this is the case, disable the default serial device using the following:
```
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Serial" /f /v "start" /t REG_DWORD /d "4"
```

## License

The Bareflank Hypervisor is licensed under the MIT License.
