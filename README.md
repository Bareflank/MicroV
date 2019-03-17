# Boxy Hypervisor

### Project Goals:

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
  where malware could potentially turn it off.
  
- **Introspection/Reverse Engineering:** One specific use case for a Service VM
  is introspection and reverse engineering. Specifically, we aim to provide a 
  simple environment for executing LibVMI in a Service VM with the ability to 
  safely introspect and reverse engineer the host OS (both Windows and Linux). 

- **Web Servers:** Another specific use case for a Service VM that we aim to 
  support in version 1 are web servers. Specifically providing the ability to 
  execute several, headless webservers simultaniously on a single machine. 
  
There are several other use cases that we would like to support with Boxy in 
future versions like full Windows guest support, Containerization, and 
of course Cloud Computing, but for now the above use cases are our primary focus
until version 1 is complete. 

### Tasking

- Bareflank
    - [X] (N) MIT license change
    - [ ] (C++) Removal of shared library support (Rian Quinn)
    - [X] (C++) Merge EAPIs with Base hypervisor (Jared Wright)
    - [X] (N) Re-brand (Rian Quinn)

- Extended APIs
    - [ ] (C++) Complete microcode update logic
    - [ ] (C) Windows sleep support
    - [ ] (C) Linux sleep support
    - [ ] (C) EFI sleep support

- Linux Guest Support
    - [X] (C) bootparam mods
    - [X] (C++) emulated x2APIC

- PV Interface
    - [ ] (C) PV console front
    - [ ] (C++) PV console back
    - [ ] (C) PV block front (Rian Quinn)
    - [ ] (C++) PV block back (Rian Quinn)
    - [ ] (C) PV network front
    - [ ] (C++) PV network back

- GUI / Cmdline
    - [ ] (N) Map out all supported configuration options
    - [ ] (N) Create, configure, delete VMs
    - [ ] (N) Start, stop VMs
    - [ ] (N) Terminal interface for each VM
    - [ ] (N) Windowed view vs Tabbed view
    - [ ] (N) Construct VM filesystem

- Signing
    - [ ] (N) Sign Windows drivers
    - [ ] (N) Sign Linux drivers
    - [ ] (N) Sign EFI applications
    - [ ] (N) Get Shim approved by Microsoft

- Branding
    - [ ] (N) Logo
    - [ ] (N) Website
    - [ ] (N) YouTube Tutorials (Rian Quinn)
