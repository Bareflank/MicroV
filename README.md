<img src="https://github.com/Bareflank/MicroV/raw/master/docs/microv.png" alt="microv-logo"/>

## Description

The MicroV Hypervisor is an open source, micro-hypervisor led by [Assured 
Information Security, Inc.](https://www.ainfosec.com/), designed specifically to run micro VMs
(i.e., tiny virtual machines that require little or no emulation). 

## Advantages of MicroV:
Unlike existing hypervisors, MicroV's design has some unique advantages including:
- **Cross-Platform Support:** In open source, hypervisors that are capable of
  supporting guest virtual machines are mostly limited to Xen, KVM and
  VirtualBox. The first two only support Linux and BSD hosts and while VirtualBox
  expands this support to Windows and macOS, it sacrifices security.
  MicroV aims to support as many hosts as possible including Windows, Linux,
  BSD, macOS and any others without sacrificing performance and security. 
  Today, MicroV already has support for Windows and Linux. 

- **Disaggregation and Deprivilege:** None of the above mentioned hypervisors
  have a true focus on a reduced Trusted Computing Base (TCB). Xen comes the closest
  and has made amazing progress in this direction, but a fully disaggregated and
  deprivileged host has yet to be fully realized or supported. MicroV's design 
  starts with a micro-kernel architecture inside the hypervisor, running most 
  of it's internal logic at lower privilege levels. On Intel, when virtualization 
  is enabled, the CPU is divided into the host and the guest. The hypervisor 
  runs in the host, while the operating system runs in the guest. *Both* the host
  and the guest have a Ring 0 and Ring 3 privilege level. Monolithic hypervisors 
  like Xen and KVM run the entire hypervisor in Ring 0 of the host (and in Xen's
  case some of the hypervisor runs in Ring 0 of the guest as well). Typically we 
  call this Ring -1. This picture is far more complicated when you include 
  System Management Mode (SMM) which adds two more Ring 0s, so lets pretend 
  they do not exist for now. The thing is, this is not the only way to construct 
  a hypervisor. Like the operating system in the guest, the hypervisor can use 
  both Ring 0 and Ring 3 in the host, keeping the Ring 0 component as small as 
  possible, while running most of the logic in Ring 3. In some
  ways, this is how KVM works. The kernel part of the hypervisor in KVM is 
  the entire Linux kernel while VM management and emulation is handled in Ring 3
  by QEMU (usually). The obvious problem with this design, besides the lack of 
  cross-platform support is the size of the TCB is huge. 

  In addition, with KVM, the physical devices are all managed from the host 
  using the Linux kernel's device drivers. This is one way in which Xen is 
  more deprivileged than KVM. Unlike KVM which runs device drivers in Ring 0 
  of the host, Xen runs device drivers in Ring 0 of the guest (specifically 
  in Dom 0). MicroV aims to take a similar approach to Xen, keeping all of 
  the code in the host as small as possible, let the guest operating system 
  manage the physical devices it is given. Unlike Xen however, MicroV runs all 
  of the privileged components in the host, and MicroV supports more than just
  Linux. 

- **Performance:** Another important focus of the project is on performance.
  Existing hypervisors make heavy use of emulation where
  virtualization could be used instead, Furthermore, Xen and KVM only support
  Linux and BSD hosts and therefore are not capable of leveraging some of the
  performance benefits of macOS and Windows such as power management. Other 
  approaches to micro-kernel hypervisors attempt to provide their own 
  device drivers, schedulers and power management algorithms. This limits 
  their ability to widely support hardware, and guarantees a compromised user
  experience. The operating system that was built for a device should be the 
  operating system that manages that device when possible. 

- **Scheduling:** Although closely related to performance, MicroV leverages a hybrid
  design, incorporating the design goals of Xen to provide disaggregation
  and deprivilege while leveraging the scheduling benefits of hypervisor designs
  like KVM and VirtualBox. Specifically MicroV doesn't include its own scheduler,
  relying on the host to schedule each VM along with the rest of the critical
  tasks it must perform. Not only does this reduce the over complexity and size
  of MicroV, but it allows MicroV to leverage the advanced schedulers already
  present in the host while simultaneously removing the contention between the
  host scheduler and the hypervisor scheduler, often seen in Xen.

- **Early Boot and Late Launch Support:** Xen, KVM and VirtualBox support early boot
  (i.e. the hypervisor starts first during boot) or late launch (meaning the 
  operating system starts first, and then the hypervisor starts). None of these 
  hypervisors support both. Early boot is critical
  in supporting a fully deprivileged host while late launch is easier to set
  up, configure and use. Late launch is also a lot easier on developers,
  preventing the need to reboot each time a line of code changes in the
  hypervisor itself. MicroV aims to support both early boot and late launch from
  inception, giving both users and developers as many options as possible.

- **AUTOSAR Compliant** Although Xen, KVM and VirtualBox provide various
  levels of testing, continuous integration and continuous deployment, MicroV
  aims to take this a step further, providing the highest levels of testing
  possible. In addition, MicroV was re-engineered from the ground up using 
  the AUTOSAR coding guidelines (MicroV is our third iteration of this 
  hypervisor project). This will not only improve reliability and security, 
  but also enable the use of MicroV in critical system environments were high 
  levels of testing are required such as medical, automotive and government.

- **Licensing:** Most of the hypervisors available today in open source leverage
  the GPL license making it difficult to incorporate their technologies in
  closed source commercial products. MicroV is licensed under MIT. Feel free to use
  it however you wish. All we ask is that if you find and fix something
  wrong with the open source code, that you work with us to upstream the fix.

## Interested In Working For AIS?
Check out our Can You Hack It?® challenge and test your skills! Submit your 
score to show us what you’ve got. We have offices across the country and offer 
competitive pay and outstanding benefits. Join a team that is not only 
committed to the future of cyberspace, but to our employee’s success as well.

www.canyouhackit.com

## Compilation Instructions
TBD

## Usage Instructions
TBD
