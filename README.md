<img src="https://github.com/Bareflank/MicroV/raw/master/docs/microv.png" alt="microv-logo"/>

# <span style="display:none">MicroV</span> now with Xen support

## Getting Started

Microv is an extension of the Bareflank hypervisor [SDK](deps/hypervisor)
designed to run guest virtual machines. Because it is based on Bareflank, Microv can
be loaded and started from three different execution contexts:

  1. Linux [driver](deps/hypervisor/bfdriver/src/platform/linux/entry.c)
  2. Windows [driver](deps/hypervisor/bfdriver/src/platform/windows/driver.c)
  3. EFI [application](deps/hypervisor/bfdriver/src/platform/efi/entry.c)

The particular option selected above for any given scenario will be referred to as
the "loader" in this document. The first two provide a late-launch capability
(a la KVM), which is useful for rapid development. The last is for early-launch
(a la Xen) and enables better security at the expense of longer edit-build-test
cycles. Both launch types support running guest VMs, but only early-launch
supports PCI passthrough.

Microv implements guest support with the help of two other components in addition
to the VMM. These are the [builder](drivers/builder) driver and [uvctl](uvctl)
application. Once the loader has started the VMM, builder must be
loaded using standard OS facilities (which the driver make targets described
below call into). After that, the guest's kernel and initrd are passed
to uvctl, along with the amount of RAM and any other desired [options](uvctl/args.h).

As mentioned above, PCI passthrough is only supported when the VMM is started
from EFI. The [visr](drivers/visr) driver must also be loaded in addition to builder.
Once the drivers are loaded, you need to pass a `--cmdline` argument to uvctl
that specifies the bus/device/function to hide using pciback. Please see the
comments in [rundom0.sh](scripts/util/rundom0.sh) for more details.

On Windows, Microv supports PV networking via the winpv [drivers](drivers/winpv)
and PCI passthrough. It also uses Inno Setup to package everything into a
single installer binary.

## Building

Microv plugs into the extension mechanism of Bareflank, so it is built using
cmake. The default cmake [config](scripts/cmake/config/config.cmake) file will
build the base VMM along with the [library](vmm/src/xen) that implements the
Xen hypercall interface. Note that if you want to build the EFI loader, you
will need to set `ENABLE_BUILD_EFI` to `ON` in your cmake config file. The
following table depicts the tested build environments for various Microv
components:

| Component | Build Environment |
| ------ | ------ |
| linux loader | linux |
| windows loader | cygwin+wdk 1903|
| efi loader | linux |
| vmm | linux, cygwin |
| uvctl | linux, cygwin, visual studio 2019 |
| builder | linux, cygwin+wdk 1903|
| visr | linux, cygwin+wdk 1903|
| winpv drivers | ewdk 1903 |

### Install Dependencies

Install dependencies based on the components you want to build and where you
want to run them. Other linux distributions will likely work but have not been tested:

##### Arch Linux
```bash
$ sudo pacman -S base-devel bc linux-headers nasm clang cmake
```

##### Ubuntu 17.10 (and above)
```bash
$ sudo apt-get install git build-essential linux-headers-$(uname -r) nasm clang cmake libelf-dev
```

##### Visual Studio 2019
- Install [CMake](https://github.com/Kitware/CMake/releases/download/v3.16.4/cmake-3.16.4-win64-x64.msi)
- Install [NASM](https://www.nasm.us/pub/nasm/releasebuilds/2.14.03rc2/win64/nasm-2.14.03rc2-installer-x64.exe)
- Install [Git](https://git-scm.com/download/win)
- Install [Visual Studio 2019](https://visualstudio.microsoft.com/vs/)
  - Check "Desktop development with C++"
  - Check "C++ CLI / Support"
  - Check "VC++ 2019 version xxx Libs for Spectre (x86 and x64)" where xxx is the latest version available

##### Cygwin
- Install [cygwin](https://www.cygwin.com/setup-x86_64.exe)
  - Accept all the defaults
  - Copy `setup-x86_64.exe` to `C:\cygwin64\bin`.
  - Open a Cygwin terminal as Admin and run the following:

```bash
$ setup-x86_64.exe -q -P git,make,ninja,vim,gcc-core,gcc-g++,nasm,clang,clang++,cmake,python,gettext,bash-completion
```

##### Windows Driver Kit (WDK), version 1903
- Follow the instructions for Visual Studio 2019 above
- Install the [WDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk#download-icon-step-2-install-wdk-for-windows-10-version-1903)
  - Accept all the defaults

##### Enterprise Windows Driver Kit (EWDK), version 1903
- Make sure you have room for a 12.4 GB file on your Windows drive
- Accept the license [terms](https://docs.microsoft.com/en-us/legal/windows/hardware/enterprise-wdk-license-2019)
- Download the .iso

### Build Desired Components
The following instructions assume the following directory structure:

```
workspace/
├── build/
├── cache/
└── microv/
```

Where 'microv' is the cloned repo, 'cache' is the bareflank depends
CACHE_DIR, and 'build' is the cmake build directory. Note this layout will work
on both linux and cygwin. Now you can configure cmake and prepare to build:

```bash
$ cd build
$ cp ../microv/scripts/cmake/config/config.cmake ..
$ cmake ../microv/deps/hypervisor -DCONFIG=../config.cmake
$ cmake ../microv/deps/hypervisor -DCONFIG=../config.cmake -G Ninja # use ninja instead of make
```
If you are building uvctl from Visual Studio, then open the "x64 Native Tools Command Prompt"
program and run

```bash
$ cmake ../microv/deps/hypervisor -DCONFIG=../config.cmake -G "Visual Studio 16 2019" -A x64
```
instead. After that you can open the `hypervisor.sln` file in Visual Studio
and configure/build from the GUI.

> Visual Studio should only be used to build uvctl, so ensure that your config.cmake
> has ENABLE_BUILD_VMM set to OFF and ENABLE_BUILD_USERSPACE set to ON.

If you have used cmake before, then you know that you can set variables by
passing `-Dvar=value` to cmake on the command line. However, one quirk of
Bareflank's build system is that if a variable is set in the config file, that
value will override any set on the command line, so if you need to change a
variable, edit the config file to be safe. The following are some examples of how
to use the various make targets to build and manipulate various components:

> The `echo` commands are not required. They are purely illustrative to
highlight what the options in the config file control.

##### List info about high-level targets
```bash
$ make info
```

##### Build, load, and unload the late-launch loader only
```bash
$ echo 'set(BUILD_BUILDER OFF)' >> ../config.cmake
$ echo 'set(BUILD_VISR OFF)' >> ../config.cmake
$ make driver_build
$ make driver_load
$ make driver_unload
```

##### Clean and build the late-launch loader, builder, and visr
```bash
$ echo 'set(BUILD_BUILDER ON)' >> ../config.cmake
$ echo 'set(BUILD_VISR ON)' >> ../config.cmake
$ make driver_clean
$ make driver_build
```

##### Build userspace components (uvctl) only
```bash
$ echo 'set(ENABLE_BUILD_USERSPACE ON)' >> ../config.cmake
$ echo 'set(ENABLE_BUILD_VMM OFF)' >> ../config.cmake
$ make
```

##### Build the VMM and EFI loader only
```bash
$ echo 'set(ENABLE_BUILD_USERSPACE OFF)' >> ../config.cmake
$ echo 'set(ENABLE_BUILD_VMM ON)' >> ../config.cmake
$ echo 'set(ENABLE_BUILD_EFI ON)' >> ../config.cmake
$ make
```

##### Build the Windows PV drivers
- Ensure that powershell execution policy is unrestricted:

  ```powershell
  PS> Set-ExecutionPolicy Unrestricted
  ```

- Click on the downloaded EWDK iso
- Run `LaunchBuildEnv.cmd` as Administrator
- In the resulting cmd prompt, navigate to the winpv drivers' [source](drivers/winpv)
- Run `powershell .\clean-build.ps1`

##### Build the Windows installer
- Install the [Inno Setup QuickStart Pack](https://www.jrsoftware.org/download.php/ispack.exe?site=1)
  - Accept the defaults
- Build bareflank.efi
- Build uvctl.exe (a Release/x64 version using Visual Studio)
- Build the xsvm and any desired child vms (ndvm, etc.) as discussed below
- Build the visr, builder, and winpv drivers
- Copy bareflank.efi and uvctl.exe to [deploy/windows](deploy/windows)
- Copy the xsvm's vmlinux and rootfs.cpio.gz to [deploy/windows](deploy/windows) and prefix each with 'xsvm-'
- Run [make-installer.ps1](scripts/deploy/make-installer.ps1)
  - Supply the "product name" you want to use with `-ProductName <name>`
  - This will create an installer binary `install-<name>.exe` in `deploy/windows/output`

## Running the VMM

To start the VMM from late-launch:

```bash
$ make quick
$ make stop && make unload && make load && make start  # equivalent to make quick
```

To start the VMM from EFI, copy bareflank.efi to your EFI partition and arrange
for it to be run prior to your OS. I typically install the pre-compiled UEFI
[shell](deploy/windows/shell.efi),
add it as a boot option with `efibootmgr`, then run bareflank.efi from the shell.
This approach has the added advantage of being able to pass command line arguments
to bareflank.efi. The arguments it understands are defined
[here](deps/hypervisor/bfdriver/src/platform/efi/entry.c#L54).

Also note that bareflank.efi loads the next EFI binary based on the cmake
`EFI_BOOT_NEXT` config option. Set that value in your config.cmake to point to
the EFI binary you want bareflank.efi to run after it has started the VMM. The
path is relative to the mountpoint of your EFI system partition (ESP). For example,
if your ESP is mounted at `/boot/efi` and you want bareflank.efi to run
`/boot/efi/EFI/grubx64.efi`, then you would use the following in your config.cmake:

```cmake
set(EFI_BOOT_NEXT "/EFI/grubx64.efi")
```

The default value points to Windows Boot Manager and is found
[here](scripts/cmake/config/default.cmake#L64). You can change that to point
to whatever EFI binary you want to run after the VMM has started (e.g. back to
the shell or grub).

Note that if you use the Windows installer, you dont need install
the shell by hand as described above. Instead pass `-useshell` to
[make-installer.ps1](scripts/deploy/make-installer.ps1). Then after running the
installer itself and rebooting, you will automatically boot into the shell. From there
you can run `bareflank.efi --enable-winpv` to start the VMM. Microv will boot
the EFI entry given by `EFI_BOOT_NEXT` from your config.cmake like normal.

## Building Guest Images

Once the VMM has been started and builder has been loaded, you can run virtual
machines using uvctl. But before that the images must be built. This is done using
the [br2-microv](https://gitlab.ainfosec.com/bareflank/br2-microv) repo.
To build the images described there:

```bash
$ cd workspace
$ git clone -b venom git@gitlab.ainfosec.com:bareflank/br2-microv.git
```

Then follow the steps in the [README](https://gitlab.ainfosec.com/bareflank/br2-microv/blob/venom/README.md).
After you perform those steps, return to the section below for information on
how to run the images.

## Running Guest Images

uvctl is the userspace application used to launch guest vms. Before a VM is run,
uvctl IOCTLs to the builder driver with the VM's parameters, such as RAM and the path
to vmlinux and rootfs.cpio.gz, as produced by the build step above. Builder
then allocates memory and performs hypercalls prior to the VMM starting the vcpu. Each
vcpu is then associated with a uvctl thread. This thread is then scheduled by the host OS
just like any other thread on the system. In addition, whenever --hvc is passed to uvctl,
it forks a read thread and write thread for communicating with the VM's hvc console.

By default uvctl is located at `build/prefixes/x86_64-userspace-elf/bin` on linux
and `build/prefixes/x86_64-userspace-pe/bin` on cygwin. You can
see the available options by passing -h to uvctl. In addition, you can use the
helper script [rundom0.sh](scripts/util/rundom0.sh) for linux and
[rundom0-cygwin.sh](scripts/util/rundom0-cygwin.sh) for cygwin which supply
common values for the typical options. You may need to adjust the paths for your
system; please read the script before running it so you understand what it does.

Assuming you launched the xsvm with one of the helper scripts, you can use `xl`
to create domains you compiled in to xsvm (such as the ndvm) using the hvc console.
