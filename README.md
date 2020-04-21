<img src="https://github.com/Bareflank/MicroV/raw/master/docs/microv.png" alt="microv-logo"/>

## Description

[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://bareflank.herokuapp.com/)

The MicroV Hypervisor is an open source, micro-hypervisor led by [Assured 
Information Security, Inc.](https://www.ainfosec.com/), designed specifically 
to run micro VMs (i.e., tiny virtual machines that require little or no 
emulation). 

<img src="https://github.com/Bareflank/MicroV/raw/master/docs/high_level.png" alt="highlevel"/>

## Advantages:
Unlike existing hypervisors, MicroV's design has some unique advantages including:
<img src="https://github.com/Bareflank/MicroV/raw/master/docs/cross_platform.png" alt="cross-platform" align="right" height="300" />
- **Cross-Platform Support:** In open source, examples of hypervisors that are 
  capable of supporting guest virtual machines include Xen, KVM, and 
  VirtualBox. The first two only support Linux and BSD and while VirtualBox 
  expands this support to Windows and macOS, it sacrifices security. MicroV 
  aims to support as many operating systems as possible including Windows, 
  Linux, UEFI and others without sacrificing performance and security. This is 
  accomplished by ensuring the hypervisor is a self-contained binary, 
  independent of the operating system running in the root VM. All of the 
  supporting applications are written in raw C++ to maximize cross-platform 
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
  which becomes evident when attempting to use these hypervisors on IoT and 
  mobile devices. Other approaches to microkernel hypervisors attempt to 
  provide their own device drivers, schedulers and power management algorithms. 
  This limits their ability to widely support hardware, and guarantees a 
  compromised user experience. The operating system that was built for a 
  device should be the  operating system that manages that device. 

- **Virtual Device Support:** Hypervisors like KVM manage all physical devices 
  in Ring 0 of the host (the most privileged code on the system) using the 
  Linux kernel. This is one way in which Xen is more deprivileged than KVM. 
  Unlike KVM which runs device drivers in Ring 0 of the host, Xen runs device 
  drivers in Ring 0 of the guest (specifically in Dom 0). MicroV aims to 
  take a similar approach to Xen, keeping the code in the host as small as 
  possible, and instead, delegating the guest operating system to manage the 
  physical devices it is given. All virtual device backend drivers run in Ring 
  0 or Ring 3 of the guest root VM, which is the main virtual machine on the 
  system. 

  <img src="https://github.com/Bareflank/MicroV/raw/master/docs/scheduler.png" alt="cross-platform" align="right" height="300" />
- **Scheduling:** Although closely related to performance, MicroV leverages a 
  hybrid design, incorporating the design goals of Xen to provide disaggregation 
  and deprivilege while leveraging the scheduling benefits of hypervisor designs 
  like KVM and VirtualBox. Specifically MicroV doesn't include its own scheduler
  , relying on the root VM's operating system to schedule each VM along with the 
  rest of the critical tasks it must perform. Not only does this reduce the over 
  complexity and size of MicroV, but it allows MicroV to leverage the advanced 
  schedulers already present in modern operating systems. Since MicroV is 
  designed with cross-platform in mind, this also means that support for custom 
  schedulers is possible, including RTOS schedulers. 

- **AUTOSAR Compliance:** Although Xen, KVM and VirtualBox provide various 
  levels of testing, continuous integration and continuous deployment, MicroV 
  aims to take this a step further, providing the highest levels of testing 
  possible to support standards such as ISO 26262. In addition, MicroV was 
  re-engineered from the ground up using the AUTOSAR coding guidelines (MicroV 
  is our third iteration of this hypervisor project). This will not only 
  improve reliability and security, but also enable the use of MicroV in 
  critical system environments were high levels of testing are required such 
  as medical, automotive and government.

- **Early Boot and Late Launch Support:** Xen, KVM and VirtualBox support 
  early boot(i.e. the hypervisor starts first during boot) or late launch 
  (meaning the operating system starts first, and then the hypervisor starts). 
  None of these hypervisors support both. 
  
  <p align="center">
  <img src="https://github.com/Bareflank/MicroV/raw/master/docs/boot_order.png" alt="highlevel" height="300"/>
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
- **Limited Guest VM Support**: As stated above, on Intel, the CPU is divided 
  into the host and the guest. The hypervisor runs in the host, and the 
  operating system runs in the guest. The main operating system, which Xen 
  would call Dom 0 can be any operating system. Today, we currently support 
  Windows and Linux, and we even have limited support for UEFI. From there, 
  MicroV lets you create additional, very small guest virtual machines. 
  Currently, MicroV only has support for enlightened operating systems running 
  in these guest VMs. Because they are enlightened, we can keep their size 
  really small, and in some cases, remove the need for emulation entirely, 
  which is where the term MicroVM comes from (i.e., a really small VM that 
  requires little to no emulation). This ultimately means MicroV supports Linux, 
  unikernels and enlightened applications, with no support for more complicated
  operating systems like Windows and macOS. Support for these types of 
  operating systems is possible, but thats a bridge we will cross in the 
  future. 
  
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

## Interested In Working For AIS?
  Check out our [Can You Hack It?®](https://www.canyouhackit.com) challenge 
  and test your skills! Submit your score to show us what you’ve got. We have 
  offices across the country and offer  competitive pay and outstanding 
  benefits. Join a team that is not only committed to the future of cyberspace, 
  but to our employee’s success as well.

<p align="center">
  <a href="https://www.ainfosec.com/">
    <img src="https://github.com/Bareflank/MicroV/raw/master/docs/ais.png" alt="cross-platform" height="100" />
  </a>
</p>

## Compilation Instructions
TBD

## Usage Instructions
TBD
