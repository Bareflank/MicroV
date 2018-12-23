/*
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

#include <common.h>
#include <bfbuilderinterface.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>
#include <bfplatform.h>

#define MAX_VMS 0x1000
struct vm_t g_vms[MAX_VMS] = {0};

/* -------------------------------------------------------------------------- */
/* VM Helpers                                                                 */
/* -------------------------------------------------------------------------- */

DEFINE_MUTEX(g_vm_mutex);

static struct vm_t *
acquire_vm(void)
{
    int64_t i;
    struct vm_t *vm = 0;

    mutex_lock(&g_vm_mutex);

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 0) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. No more VMs can be created\n");
        goto done;
    }

    platform_memset(vm, 0, sizeof(struct vm_t));
    vm->used = 1;

done:

    mutex_unlock(&g_vm_mutex);
    return vm;
}

static struct vm_t *
get_vm(domainid_t domainid)
{
    int64_t i;
    struct vm_t *vm = 0;

    mutex_lock(&g_vm_mutex);

    for (i = 0; i < MAX_VMS; i++) {
        vm = &g_vms[i];
        if (vm->used == 1 && vm->domainid == domainid) {
            break;
        }
    }

    if (i == MAX_VMS) {
        BFALERT("MAX_VMS reached. Could not locate VM\n");
        goto done;
    }

done:

    mutex_unlock(&g_vm_mutex);
    return vm;
}

/* -------------------------------------------------------------------------- */
/* Misc Device                                                                */
/* -------------------------------------------------------------------------- */

static int
dev_open(struct inode *inode, struct file *file)
{
    BFDEBUG("dev_open succeeded\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    BFDEBUG("dev_release succeeded\n");
    return 0;
}

static long
ioctl_create_from_elf(struct create_from_elf_args *args)
{
    int64_t ret;
    struct create_from_elf_args kern_args;

    void *file = 0;
    void *cmdl = 0;

    ret = copy_from_user(
        &kern_args, args, sizeof(struct create_from_elf_args));
    if (ret != 0) {
        BFALERT("IOCTL_CREATE_FROM_ELF: failed to copy args from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    if (kern_args.file_size != 0) {
        file = platform_alloc_rw(kern_args.file_size);
        if (file == NULL) {
            BFALERT("IOCTL_CREATE_FROM_ELF: failed to allocate memory for file\n");
            goto failed;
        }

        ret = copy_from_user(
            file, kern_args.file, kern_args.file_size);
        if (ret != 0) {
            BFALERT("IOCTL_CREATE_FROM_ELF: failed to copy file from userspace\n");
            goto failed;
        }

        kern_args.file = file;
    }

    if (kern_args.cmdl_size != 0) {
        cmdl = platform_alloc_rw(kern_args.cmdl_size);
        if (cmdl == NULL) {
            BFALERT("IOCTL_CREATE_FROM_ELF: failed to allocate memory for file\n");
            goto failed;
        }

        ret = copy_from_user(
            cmdl, kern_args.cmdl, kern_args.cmdl_size);
        if (ret != 0) {
            BFALERT("IOCTL_CREATE_FROM_ELF: failed to copy cmdl from userspace\n");
            goto failed;
        }

        kern_args.cmdl = cmdl;
    }

    ret = common_create_from_elf(acquire_vm(), &kern_args);
    if (ret != BF_SUCCESS) {
        BFDEBUG("common_create_from_elf failed: %llx\n", ret);
        goto failed;
    }

    kern_args.file = 0;
    kern_args.cmdl = 0;

    ret = copy_to_user(
        args, &kern_args, sizeof(struct create_from_elf_args));
    if (ret != 0) {
        BFALERT("IOCTL_CREATE_FROM_ELF: failed to copy args to userspace\n");
        common_destroy(get_vm(kern_args.domainid));
        goto failed;
    }

    platform_free_rw(file, kern_args.file_size);
    platform_free_rw(cmdl, kern_args.cmdl_size);

    BFDEBUG("IOCTL_CREATE_FROM_ELF: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    kern_args.file = 0;
    kern_args.cmdl = 0;

    platform_free_rw(file, kern_args.file_size);
    platform_free_rw(cmdl, kern_args.cmdl_size);

    BFALERT("IOCTL_CREATE_FROM_ELF: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_destroy(domainid_t *args)
{
    int64_t ret;
    domainid_t domainid;

    ret = copy_from_user(&domainid, args, sizeof(domainid_t));
    if (ret != 0) {
        BFALERT("IOCTL_DESTROY: failed to copy args from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    ret = common_destroy(get_vm(domainid));
    if (ret != BF_SUCCESS) {
        BFDEBUG("common_destroy failed: %llx\n", ret);
        return BF_IOCTL_FAILURE;
    }

    BFDEBUG("IOCTL_DESTROY: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
dev_unlocked_ioctl(
    struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case IOCTL_CREATE_FROM_ELF_CMD:
            return ioctl_create_from_elf((struct create_from_elf_args *)arg);

        case IOCTL_DESTROY_CMD:
            return ioctl_destroy((domainid_t *)arg);

        default:
            return -EINVAL;
    }
}

static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl
};

static struct miscdevice builder_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = BUILDER_NAME,
    .fops = &fops,
    .mode = 0666
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_init(void)
{
    mutex_init(&g_vm_mutex);

    if (misc_register(&builder_dev) != 0) {
        BFALERT("misc_register failed\n");
        return -EPERM;
    }

    BFDEBUG("dev_init succeeded\n");
    return 0;
}

void
dev_exit(void)
{
    misc_deregister(&builder_dev);

    BFDEBUG("dev_exit succeeded\n");
    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
