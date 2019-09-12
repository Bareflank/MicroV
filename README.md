## Getting Started

The default `config.cmake` file will build the xen components and will
also install the build dependencies for creating PVH guest images.
The available targets can be listed with `make info`. Currently, the
xsvm is configured to build the xen toolstack so it is treated as dom0.

To run the xenstore VM (i.e. xsvm), copy the `rundom0.sh` script into
the root of the cmake build directory then run the following:

```bash
$ cmake ... # configure cmake with CONFIG=path/to/microv/config.cmake
$ make driver_quick
$ make
$ make quick
$ make xsvm
$ ./rundom0.sh
```

If those steps succeed, you will see the guest booting and presenting you with
a login prompt. The user name is 'root' and there is no password. From there
you can run any command that is available in the guest image. There aren't
many except for the busybox commands and xl. Note that not all xl commands are
supported. You can try them out if youd like, but most will result in an
unhandled hypercall. If it does, appropriate error messages will be printed
over serial by the VMM.

The primary command being worked now is `xl create`. This is responsible for
creating a new domain and running. You can try starting the ndvm with this
command:

```bash
$ xl create -c /etc/xen/ndvm.cfg
```

There isn't a console for the ndvm yet, so you will only see some debugging
messages from xl and from the VMM as it boots. To exit the xsvm, type Ctrl-C.
This will kill the guest and bring you back to your original console used to
rundom0.sh.
