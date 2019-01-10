To build the installer:

1. Open the command prompt as an administrator, run 'bcdedit /set testsigning on', and reboot.
2. Obtain the vmlinux, vmlinux-hello, and vmlinux-ndvm images.
3. Obtain Inno Setup (http://www.jrsoftware.org/download.php/is.exe?site=1), and follow the wizard. Allow the installation of unsigned drivers (there will be three).
4. Once Inno Setup is installed, open Bareflank.iss, and run 'Compile' to get an installer package.
5. The package will open as a normal installer. Follow the prompts and the system will reboot.
6. To uninstall, enter the 'Add or remove programs' menu, find 'Bareflank version 1.0', select 'Uninstall', then select 'Yes' when asked to reboot.
