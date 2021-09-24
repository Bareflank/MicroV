#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    void *mem;

    if (argc != 2) {
        fprintf(stderr, "USAGE: %s <guest-image>\n", argv[0]);
        return 1;
    }

    if ((kvm_fd = open("/dev/microv_shim", O_RDWR)) < 0) {
        fprintf(stderr, "failed to open /dev/microv_shim: %d\n", errno);
        return 1;
    }

    if ((vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0)) < 0) {
        fprintf(stderr, "failed to create vm: %d\n", errno);
        return 1;
    }

    if ((mem = mmap(
             NULL,
             1 << 30,
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
             -1,
             0)) == NULL) {
        fprintf(stderr, "mmap failed: %d\n", errno);
        return 1;
    }

    struct kvm_userspace_memory_region region;
    memset(&region, 0, sizeof(region));
    region.slot = 0;
    region.guest_phys_addr = 0;
    region.memory_size = 1 << 30;
    region.userspace_addr = (uintptr_t)mem;
    if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        fprintf(stderr, "ioctl KVM_SET_USER_MEMORY_REGION failed: %d\n", errno);
        return 1;
    }

    int img_fd = open(argv[1], O_RDONLY);
    if (img_fd < 0) {
        fprintf(stderr, "can not open binary file: %d\n", errno);
        return 1;
    }
    char *p = (char *)mem;
    for (;;) {
        int r = read(img_fd, p, 4096);
        if (r <= 0) {
            break;
        }
        p += r;
    }
    close(img_fd);

    if ((vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0)) < 0) {
        fprintf(stderr, "can not create vcpu: %d\n", errno);
        return 1;
    }
    int kvm_run_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (kvm_run_mmap_size < 0) {
        fprintf(stderr, "ioctl KVM_GET_VCPU_MMAP_SIZE: %d\n", errno);
        return 1;
    }
    struct kvm_run *run = (struct kvm_run *)mmap(
        NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
    if (run == NULL) {
        fprintf(stderr, "mmap kvm_run: %d\n", errno);
        return 1;
    }

    struct kvm_regs regs;
    struct kvm_sregs sregs;
    if (ioctl(vcpu_fd, KVM_GET_SREGS, &(sregs)) < 0) {
        perror("can not get sregs\n");
        exit(1);
    }

#define CODE_START 0x0000

    sregs.cs.selector = CODE_START;
    sregs.cs.base = CODE_START * 16;
    sregs.ss.selector = CODE_START;
    sregs.ss.base = CODE_START * 16;
    sregs.ds.selector = CODE_START;
    sregs.ds.base = CODE_START * 16;
    sregs.es.selector = CODE_START;
    sregs.es.base = CODE_START * 16;
    sregs.fs.selector = CODE_START;
    sregs.fs.base = CODE_START * 16;
    sregs.gs.selector = CODE_START;

    if (ioctl(vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("can not set sregs");
        return 1;
    }

    regs.rflags = 2;
    regs.rip = 0;

    if (ioctl(vcpu_fd, KVM_SET_REGS, &(regs)) < 0) {
        perror("KVM SET REGS\n");
        return 1;
    }

    for (;;) {
        int ret = ioctl(vcpu_fd, KVM_RUN, 0);
        if (ret < 0) {
            fprintf(stderr, "KVM_RUN failed\n");
            return 1;
        }

        switch (run->exit_reason) {
            case KVM_EXIT_IO:
                printf(
                    "IO port: %x, data: %x\n",
                    run->io.port,
                    *(int *)((char *)(run) + run->io.data_offset));
                sleep(1);
                break;
            case KVM_EXIT_SHUTDOWN:
                goto exit;
        }
    }
exit:
    close(kvm_fd);
    return 0;
}
