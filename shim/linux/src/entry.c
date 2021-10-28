/* SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT */

/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <debug.h>
#include <handle_system_kvm_check_extension.h>
#include <handle_system_kvm_create_vm.h>
#include <handle_system_kvm_destroy_vm.h>
#include <handle_system_kvm_get_api_version.h>
#include <handle_system_kvm_get_msr_index_list.h>
#include <handle_system_kvm_get_msrs.h>
#include <handle_system_kvm_get_supported_cpuid.h>
#include <handle_system_kvm_get_vcpu_mmap_size.h>
#include <handle_vcpu_kvm_get_fpu.h>
#include <handle_vcpu_kvm_get_mp_state.h>
#include <handle_vcpu_kvm_get_msrs.h>
#include <handle_vcpu_kvm_get_regs.h>
#include <handle_vcpu_kvm_get_sregs.h>
#include <handle_vcpu_kvm_get_tsc_khz.h>
#include <handle_vcpu_kvm_run.h>
#include <handle_vcpu_kvm_set_fpu.h>
#include <handle_vcpu_kvm_set_mp_state.h>
#include <handle_vcpu_kvm_set_msrs.h>
#include <handle_vcpu_kvm_set_regs.h>
#include <handle_vcpu_kvm_set_sregs.h>
#include <handle_vm_kvm_check_extension.h>
#include <handle_vm_kvm_create_vcpu.h>
#include <handle_vm_kvm_destroy_vcpu.h>
#include <handle_vm_kvm_set_user_memory_region.h>
#include <linux/anon_inodes.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#include <mv_constants.h>
#include <mv_types.h>
#include <platform.h>
#include <serial_init.h>
#include <shim_fini.h>
#include <shim_init.h>
#include <shim_platform_interface.h>
#include <shim_vm_t.h>

static int
dev_open(struct inode *const inode, struct file *const file)
{
    (void)inode;
    (void)file;

    return 0;
}

static int
dev_release(struct inode *const inode, struct file *const file)
{
    (void)inode;
    (void)file;

    return 0;
}

static int
vm_release_impl(struct shim_vm_t *const pmut_vm)
{
    uint64_t mut_i;

    platform_expects(NULL != pmut_vm);
    pmut_vm->fd = 0;

    for (mut_i = ((uint64_t)0); mut_i < MICROV_MAX_VCPUS; ++mut_i) {
        if (0 != (int32_t)pmut_vm->vcpus[mut_i].fd) {
            return 0;
        }
    }

    handle_system_kvm_destroy_vm(pmut_vm);

    platform_mutex_destroy(&pmut_vm->mutex);
    vfree(pmut_vm);

    return 0;
}

static int
vm_release(struct inode *const inode, struct file *const file)
{
    (void)inode;

    platform_expects(NULL != file);
    return vm_release_impl((struct shim_vm_t *)file->private_data);
}

static int
vcpu_release_impl(struct shim_vcpu_t *const pmut_vcpu)
{
    platform_expects(NULL != pmut_vcpu);
    pmut_vcpu->fd = 0;

    handle_vm_kvm_destroy_vcpu(pmut_vcpu);

    platform_expects(NULL != pmut_vcpu->vm);
    if (0 == (int32_t)pmut_vcpu->vm->fd) {
        vm_release_impl(pmut_vcpu->vm);
    }

    return 0;
}

static int
vcpu_release(struct inode *const inode, struct file *const file)
{
    (void)inode;

    platform_expects(NULL != file);
    return vcpu_release_impl((struct shim_vcpu_t *)file->private_data);
}

static int
device_release(struct inode *const inode, struct file *const file)
{
    (void)inode;
    (void)file;

    return -EINVAL;
}

static struct file_operations fops_vm;
static struct file_operations fops_vcpu;
static struct file_operations fops_device;

/* -------------------------------------------------------------------------- */
/* System IOCTLs                                                              */
/* -------------------------------------------------------------------------- */

static long
dispatch_system_kvm_check_extension(unsigned long const user_args)
{
    uint32_t ret;

    if (handle_system_kvm_check_extension(user_args, &ret)) {
        bferror("system kvm check_extension failed");
        return -EINVAL;
    }

    return (long)ret;
}

static long
dispatch_system_kvm_create_vm(void)
{
    char name[22];

    struct shim_vm_t *const pmut_vm = vmalloc(sizeof(struct shim_vm_t));
    if (NULL == pmut_vm) {
        bferror("vmalloc failed");
        return -ENOMEM;
    }

    platform_memset(pmut_vm, ((uint8_t)0), sizeof(struct shim_vm_t));
    platform_mutex_init(&pmut_vm->mutex);

    if (handle_system_kvm_create_vm(pmut_vm)) {
        bferror("handle_system_kvm_create_vm failed");
        goto vmalloc_failed;
    }

    snprintf(name, sizeof(name), "kvm-vm:%d", pmut_vm->id);

    pmut_vm->fd = anon_inode_getfd(name, &fops_vm, pmut_vm, O_RDWR | O_CLOEXEC);
    if ((int32_t)pmut_vm->fd < 0) {
        bferror("anon_inode_getfd failed");
        goto handle_system_kvm_create_vm_failed;
    }

    return (long)pmut_vm->fd;

handle_system_kvm_create_vm_failed:
    handle_system_kvm_destroy_vm(pmut_vm);

vmalloc_failed:
    vfree(pmut_vm);

    return -EINVAL;
}

static long
dispatch_system_kvm_get_api_version(void)
{
    uint32_t api_version;
    handle_system_kvm_get_api_version(&api_version);
    return (long)api_version;
}

static long
dispatch_system_kvm_get_emulated_cpuid(struct kvm_cpuid2 *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_system_kvm_get_msr_feature_index_list(
    struct kvm_msr_list *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_system_kvm_get_msr_index_list(
    struct kvm_msr_list __user *const user_args)
{
    struct kvm_msr_list mut_args;
    int64_t mut_ret;

    if (platform_copy_from_user(
            &mut_args,
            user_args,
            sizeof(mut_args) - sizeof(mut_args.indices))) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    if (mut_args.nmsrs > MSR_LIST_MAX_INDICES) {
        bferror("caller nmsrs exceeds MSR_LIST_MAX_INDICES");
        return -ENOMEM;
    }

    mut_ret = handle_system_kvm_get_msr_index_list(&mut_args);
    if (SHIM_2BIG == mut_ret) {
        if (platform_copy_to_user(
                user_args, &mut_args, sizeof(mut_args.nmsrs))) {
            bferror("platform_copy_to_user nmsrs failed");
            return -EINVAL;
        }

        return -E2BIG;
    }
    else if (mut_ret) {
        bferror("handle_system_kvm_get_msr_index_list failed");
        return -EINVAL;
    }

    if (platform_copy_to_user(
            user_args,
            &mut_args,
            sizeof(mut_args.nmsrs) +
                mut_args.nmsrs * sizeof(*mut_args.indices))) {
        bferror("platform_copy_to_user indices failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_system_kvm_get_msrs(struct kvm_msrs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_system_kvm_get_supported_cpuid(
    struct kvm_cpuid2 __user *const pmut_user_args)
{
    struct kvm_cpuid2 *pmut_mut_args;
    int64_t mut_ret;

    pmut_mut_args = vzalloc(sizeof(*pmut_mut_args));
    if (NULL == pmut_mut_args) {
        bferror("vzalloc failed");
        return -ENOMEM;
    }

    mut_ret = -EINVAL;
    if (platform_copy_from_user(
            pmut_mut_args,
            pmut_user_args,
            sizeof(*pmut_mut_args) - sizeof(pmut_mut_args->entries))) {
        bferror("platform_copy_from_user failed");
        goto out_free;
    }

    mut_ret = -ENOMEM;
    if (pmut_mut_args->nent > CPUID2_MAX_ENTRIES) {
        bferror("caller nent exceeds CPUID2_MAX_ENTRIES");
        goto out_free;
    }

    mut_ret = handle_system_kvm_get_supported_cpuid(pmut_mut_args);
    if (SHIM_2BIG == mut_ret) {
        if (platform_copy_to_user(
                pmut_user_args, pmut_mut_args, sizeof(pmut_mut_args->nent))) {
            bferror("platform_copy_to_user nent failed");
            mut_ret = -EINVAL;
        }
        else {
            mut_ret = -E2BIG;
        }

        goto out_free;
    }
    else if (mut_ret) {
        bferror("handle_system_kvm_get_msr_index_list failed");
        goto out_free;
    }

    mut_ret = -EINVAL;
    if (platform_copy_to_user(
            pmut_user_args,
            pmut_mut_args,
            sizeof(pmut_mut_args->nent) +
                pmut_mut_args->nent * sizeof(*pmut_mut_args->entries))) {
        bferror("platform_copy_to_user failed");
        goto out_free;
    }

    mut_ret = 0;

out_free:
    if (pmut_mut_args) {
        vfree(pmut_mut_args);
    }

    return mut_ret;
}

static long
dispatch_system_kvm_get_vcpu_mmap_size(void)
{
    uint32_t size;
    handle_system_kvm_get_vcpu_mmap_size(&size);
    return (long)size;
}

static long
dispatch_system_kvm_memory_encrypt_op(unsigned long *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_system_kvm_memory_encrypt_reg_region(
    struct kvm_enc_region *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_system_kvm_memory_encrypt_unreg_region(
    struct kvm_enc_region *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_system_kvm_x86_get_mce_cap_supported(uint64_t *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dev_unlocked_ioctl_system(
    struct file *const file,
    unsigned int const cmd,
    unsigned long const ioctl_args)
{
    switch (cmd) {
        case KVM_CHECK_EXTENSION: {
            return dispatch_system_kvm_check_extension(ioctl_args);
        }

        case KVM_CREATE_VM: {
            return dispatch_system_kvm_create_vm();
        }

        case KVM_GET_API_VERSION: {
            if (ioctl_args) {
                bferror("KVM_GET_API_VERSION: ioctl_args are present");
                return -EINVAL;
            }

            return dispatch_system_kvm_get_api_version();
        }

        case KVM_GET_EMULATED_CPUID: {
            return dispatch_system_kvm_get_emulated_cpuid(
                (struct kvm_cpuid2 *)ioctl_args);
        }

        case KVM_GET_MSR_FEATURE_INDEX_LIST: {
            return dispatch_system_kvm_get_msr_feature_index_list(
                (struct kvm_msr_list *)ioctl_args);
        }

        case KVM_GET_MSR_INDEX_LIST: {
            return dispatch_system_kvm_get_msr_index_list(
                (struct kvm_msr_list __user *)ioctl_args);
        }

        case KVM_GET_MSRS: {
            return dispatch_system_kvm_get_msrs((struct kvm_msrs *)ioctl_args);
        }

        case KVM_GET_SUPPORTED_CPUID: {
            return dispatch_system_kvm_get_supported_cpuid(
                (struct kvm_cpuid2 *)ioctl_args);
        }

        case KVM_GET_VCPU_MMAP_SIZE: {
            return dispatch_system_kvm_get_vcpu_mmap_size();
        }

        case KVM_MEMORY_ENCRYPT_OP: {
            return dispatch_system_kvm_memory_encrypt_op(
                (unsigned long *)ioctl_args);
        }

        case KVM_MEMORY_ENCRYPT_REG_REGION: {
            return dispatch_system_kvm_memory_encrypt_reg_region(
                (struct kvm_enc_region *)ioctl_args);
        }

        case KVM_MEMORY_ENCRYPT_UNREG_REGION: {
            return dispatch_system_kvm_memory_encrypt_unreg_region(
                (struct kvm_enc_region *)ioctl_args);
        }

        case KVM_X86_GET_MCE_CAP_SUPPORTED: {
            return dispatch_system_kvm_x86_get_mce_cap_supported(
                (uint64_t *)ioctl_args);
        }

        default: {
            bferror_x64("invalid system ioctl cmd", cmd);
            return -EINVAL;
        }
    };

    return 0;
}

/* -------------------------------------------------------------------------- */
/* VM IOCTLs                                                                  */
/* -------------------------------------------------------------------------- */

static long
dispatch_vm_kvm_check_extension(
    struct shim_vm_t *pmut_mut_vm, unsigned long const user_args)
{
    uint32_t ret;

    if (handle_vm_kvm_check_extension(user_args, &ret)) {
        bferror("vm kvm check_extension failed");
        return -EINVAL;
    }

    return (long)ret;
}

static long
dispatch_vm_kvm_clear_dirty_log(struct kvm_clear_dirty_log *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_create_device(struct kvm_create_device *const ioctl_args)
{
    (void)ioctl_args;

    (void)fops_device;
    return -EINVAL;
}

static long
dispatch_kvm_create_irqchip(void)
{
    return -EINVAL;
}

static long
dispatch_vm_kvm_create_pit2(struct kvm_pit_config *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_create_vcpu(struct shim_vm_t *const pmut_vm)
{
    char name[24];
    struct shim_vcpu_t *pmut_mut_vcpu;

    if (handle_vm_kvm_create_vcpu(pmut_vm, &pmut_mut_vcpu)) {
        bferror("handle_vm_kvm_create_vcpu failed");
        return -EINVAL;
    }

    pmut_mut_vcpu->run = vmalloc_user(sizeof(struct kvm_run));
    platform_expects(NULL != pmut_mut_vcpu->run);

    platform_expects(NULL != pmut_mut_vcpu);
    snprintf(name, sizeof(name), "kvm-vcpu:%d", pmut_mut_vcpu->id);

    pmut_mut_vcpu->fd = (uint64_t)anon_inode_getfd(
        name, &fops_vcpu, pmut_mut_vcpu, O_RDWR | O_CLOEXEC);
    if ((int32_t)pmut_mut_vcpu->fd < 0) {
        bferror("anon_inode_getfd failed");
        goto handle_vm_kvm_create_vcpu_failed;
    }

    pmut_mut_vcpu->run->exit_reason = 42;
    pmut_mut_vcpu->vm = pmut_vm;
    return (long)pmut_mut_vcpu->fd;

handle_vm_kvm_create_vcpu_failed:
    handle_vm_kvm_destroy_vcpu(pmut_mut_vcpu);

    return -EINVAL;
}

static long
dispatch_vm_kvm_get_clock(struct kvm_clock_data *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_get_debugregs(struct kvm_debugregs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_get_device_attr(struct kvm_device_attr *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_get_dirty_log(struct kvm_dirty_log *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_get_irqchip(struct kvm_irqchip *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_get_pit2(struct kvm_pit_state2 *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_has_device_attr(struct kvm_device_attr *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_hyperv_eventfd(struct kvm_hyperv_eventfd *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_ioeventfd(struct kvm_ioeventfd *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_irq_line(struct kvm_irq_level *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_irqfd(struct kvm_irqfd *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_register_coalesced_mmio(
    struct kvm_coalesced_mmio_zone *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_reinject_control(void)
{
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_boot_cpu_id(void)
{
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_clock(struct kvm_clock_data *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_debugregs(struct kvm_debugregs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_device_attr(struct kvm_device_attr *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_gsi_routing(struct kvm_irq_routing *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_identity_map_addr(uint64_t *const ioctl_args)
{
    (void)ioctl_args;
    /*we just return zero as we dont implement this IOCTL as of now
    and to integrate with QEMU we need this IOCTL to return zero */
    return 0;
}

static long
dispatch_vm_kvm_set_irqchip(struct kvm_irqchip *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_pit2(struct kvm_pit_state2 *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_pmu_event_filter(
    struct kvm_pmu_event_filter *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_tss_addr(void)
{
    /*we just return zero as we dont implement this IOCTL as of now
    and to integrate with QEMU we need this IOCTL to return zero */
    return 0;
}

static long
dispatch_vm_kvm_set_user_memory_region(
    struct kvm_userspace_memory_region const *const user_args,
    struct shim_vm_t *const pmut_vm)
{
    struct kvm_userspace_memory_region mut_args;
    uint64_t const size = sizeof(mut_args);

    if (platform_copy_from_user(&mut_args, user_args, size)) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    if (handle_vm_kvm_set_user_memory_region(&mut_args, pmut_vm)) {
        bferror("handle_vm_kvm_set_user_memory_region failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vm_kvm_signal_msi(struct kvm_msi *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_unregister_coalesced_mmio(
    struct kvm_coalesced_mmio_zone *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vm_kvm_xen_hvm_config(struct kvm_xen_hvm_config *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dev_unlocked_ioctl_vm(
    struct file *const file,
    unsigned int const cmd,
    unsigned long const ioctl_args)
{
    struct shim_vm_t *pmut_mut_vm;
    platform_expects(NULL != file);

    pmut_mut_vm = (struct shim_vm_t *)file->private_data;

    switch (cmd) {
        case KVM_CHECK_EXTENSION: {
            return dispatch_vm_kvm_check_extension(pmut_mut_vm, ioctl_args);
        }

        case KVM_CLEAR_DIRTY_LOG: {
            return dispatch_vm_kvm_clear_dirty_log(
                (struct kvm_clear_dirty_log *)ioctl_args);
        }

        case KVM_CREATE_DEVICE: {
            return dispatch_vm_kvm_create_device(
                (struct kvm_create_device *)ioctl_args);
        }

        case KVM_CREATE_IRQCHIP: {
            return dispatch_kvm_create_irqchip();
        }

        case KVM_CREATE_PIT2: {
            return dispatch_vm_kvm_create_pit2(
                (struct kvm_pit_config *)ioctl_args);
        }

        case KVM_CREATE_VCPU: {
            return dispatch_vm_kvm_create_vcpu(pmut_mut_vm);
        }

        case KVM_GET_CLOCK: {
            return dispatch_vm_kvm_get_clock(
                (struct kvm_clock_data *)ioctl_args);
        }

        case KVM_GET_DEBUGREGS: {
            return dispatch_vm_kvm_get_debugregs(
                (struct kvm_debugregs *)ioctl_args);
        }

        case KVM_GET_DEVICE_ATTR: {
            return dispatch_vm_kvm_get_device_attr(
                (struct kvm_device_attr *)ioctl_args);
        }

        case KVM_GET_DIRTY_LOG: {
            return dispatch_vm_kvm_get_dirty_log(
                (struct kvm_dirty_log *)ioctl_args);
        }

        case KVM_GET_IRQCHIP: {
            return dispatch_vm_kvm_get_irqchip(
                (struct kvm_irqchip *)ioctl_args);
        }

        case KVM_GET_PIT2: {
            return dispatch_vm_kvm_get_pit2(
                (struct kvm_pit_state2 *)ioctl_args);
        }

        case KVM_HAS_DEVICE_ATTR: {
            return dispatch_vm_kvm_has_device_attr(
                (struct kvm_device_attr *)ioctl_args);
        }

        case KVM_HYPERV_EVENTFD: {
            return dispatch_vm_kvm_hyperv_eventfd(
                (struct kvm_hyperv_eventfd *)ioctl_args);
        }

        case KVM_IOEVENTFD: {
            return dispatch_vm_kvm_ioeventfd(
                (struct kvm_ioeventfd *)ioctl_args);
        }

        case KVM_IRQ_LINE: {
            return dispatch_vm_kvm_irq_line((struct kvm_irq_level *)ioctl_args);
        }

        case KVM_IRQFD: {
            return dispatch_vm_kvm_irqfd((struct kvm_irqfd *)ioctl_args);
        }

        case KVM_REGISTER_COALESCED_MMIO: {
            return dispatch_vm_kvm_register_coalesced_mmio(
                (struct kvm_coalesced_mmio_zone *)ioctl_args);
        }

        case KVM_REINJECT_CONTROL: {
            return dispatch_vm_kvm_reinject_control();
        }

        case KVM_SET_BOOT_CPU_ID: {
            return dispatch_vm_kvm_set_boot_cpu_id();
        }

        case KVM_SET_CLOCK: {
            return dispatch_vm_kvm_set_clock(
                (struct kvm_clock_data *)ioctl_args);
        }

        case KVM_SET_DEBUGREGS: {
            return dispatch_vm_kvm_set_debugregs(
                (struct kvm_debugregs *)ioctl_args);
        }

        case KVM_SET_DEVICE_ATTR: {
            return dispatch_vm_kvm_set_device_attr(
                (struct kvm_device_attr *)ioctl_args);
        }

        case KVM_SET_GSI_ROUTING: {
            return dispatch_vm_kvm_set_gsi_routing(
                (struct kvm_irq_routing *)ioctl_args);
        }

        case KVM_SET_IDENTITY_MAP_ADDR: {
            return dispatch_vm_kvm_set_identity_map_addr(
                (uint64_t *)ioctl_args);
        }

        case KVM_SET_IRQCHIP: {
            return dispatch_vm_kvm_set_irqchip(
                (struct kvm_irqchip *)ioctl_args);
        }

        case KVM_SET_PIT2: {
            return dispatch_vm_kvm_set_pit2(
                (struct kvm_pit_state2 *)ioctl_args);
        }

        case KVM_SET_PMU_EVENT_FILTER: {
            return dispatch_vm_kvm_set_pmu_event_filter(
                (struct kvm_pmu_event_filter *)ioctl_args);
        }

        case KVM_SET_TSS_ADDR: {
            return dispatch_vm_kvm_set_tss_addr();
        }

        case KVM_SET_USER_MEMORY_REGION: {
            return dispatch_vm_kvm_set_user_memory_region(
                (struct kvm_userspace_memory_region const *)ioctl_args,
                pmut_mut_vm);
        }

        case KVM_SIGNAL_MSI: {
            return dispatch_vm_kvm_signal_msi((struct kvm_msi *)ioctl_args);
        }

        case KVM_UNREGISTER_COALESCED_MMIO: {
            return dispatch_vm_kvm_unregister_coalesced_mmio(
                (struct kvm_coalesced_mmio_zone *)ioctl_args);
        }

        case KVM_XEN_HVM_CONFIG: {
            return dispatch_vm_kvm_xen_hvm_config(
                (struct kvm_xen_hvm_config *)ioctl_args);
        }

        default: {
            bferror_x64("invalid vm ioctl cmd", cmd);
            return -EINVAL;
        }
    };

    return 0;
}

/* -------------------------------------------------------------------------- */
/* VCPU IOCTLs                                                                */
/* -------------------------------------------------------------------------- */

static long
dispatch_vcpu_kvm_enable_cap(struct kvm_enable_cap *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_cpuid2(struct kvm_cpuid2 *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_fpu(
    struct shim_vcpu_t const *const vcpu, struct kvm_fpu *const ioctl_args)
{
    struct kvm_fpu mut_args;
    uint64_t const size = sizeof(mut_args);

    if (handle_vcpu_kvm_get_fpu(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_get_fpu failed");
        return -EINVAL;
    }

    if (platform_copy_to_user(ioctl_args, &mut_args, size)) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vcpu_kvm_get_lapic(struct kvm_lapic_state *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_mp_state(
    struct shim_vcpu_t const *const vcpu, struct kvm_mp_state *const user_args)
{
    struct kvm_mp_state mut_args;

    if (NULL == user_args) {
        bferror("user_args are null");
        return -EINVAL;
    }

    if (handle_vcpu_kvm_get_mp_state(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_get_mp_state failed");
        return -EINVAL;
    }

    if (platform_copy_to_user(user_args, &mut_args, sizeof(mut_args))) {
        bferror("platform_copy_to_user failed");
        return -EINVAL;
    }
    return 0;
}

static long
dispatch_vcpu_kvm_get_msrs(
    struct shim_vcpu_t const *const vcpu, struct kvm_msrs *const user_args)
{
    struct kvm_msrs mut_args;
    uint64_t const size = sizeof(mut_args);

    if (handle_vcpu_kvm_get_msrs(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_get_msrs failed");
        return -EINVAL;
    }

    if (platform_copy_to_user(user_args, &mut_args, size)) {
        bferror("platform_copy_to_user failed");
        return -EINVAL;
    }

    return (long)mut_args.nmsrs;
}

static long
dispatch_vcpu_kvm_get_nested_state(struct kvm_nested_state *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_one_reg(struct kvm_one_reg *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_regs(
    struct shim_vcpu_t const *const vcpu, struct kvm_regs *const user_args)
{
    struct kvm_regs mut_args;
    uint64_t const size = sizeof(mut_args);

    if (handle_vcpu_kvm_get_regs(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_get_regs failed");
        return -EINVAL;
    }

    if (platform_copy_to_user(user_args, &mut_args, size)) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vcpu_kvm_get_sregs(
    struct shim_vcpu_t const *const vcpu, struct kvm_sregs *const user_args)
{
    struct kvm_sregs mut_args;
    uint64_t const size = sizeof(mut_args);

    if (handle_vcpu_kvm_get_sregs(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_get_sregs failed");
        return -EINVAL;
    }

    if (platform_copy_to_user(user_args, &mut_args, size)) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vcpu_kvm_get_supported_hv_cpuid(struct kvm_cpuid2 *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_tsc_khz(void)
{
    uint64_t tsc_khz;

    if (handle_vcpu_kvm_get_tsc_khz(&tsc_khz)) {
        bferror("handle_vcpu_kvm_get_tsc_khz failed");
        return -EINVAL;
    }

    return (long)tsc_khz;
}

static long
dispatch_vcpu_kvm_get_vcpu_events(struct kvm_vcpu_events *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_xcrs(struct kvm_xcrs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_xsave(struct kvm_xsave *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_interrupt(struct kvm_interrupt *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_kvmclock_ctrl(void)
{
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_nmi(void)
{
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_run(struct shim_vcpu_t *const vcpu)
{
    if (handle_vcpu_kvm_run(vcpu)) {
        bferror("handle_vcpu_kvm_run failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vcpu_kvm_set_cpuid(struct kvm_cpuid *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_cpuid2(struct kvm_cpuid2 *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_fpu(
    struct shim_vcpu_t *const vcpu, struct kvm_fpu *const ioctl_args)
{
    struct kvm_fpu mut_args;
    uint64_t const size = sizeof(mut_args);

    if (platform_copy_from_user(&mut_args, ioctl_args, size)) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    if (handle_vcpu_kvm_set_fpu(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_set_fpu failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vcpu_kvm_set_guest_debug(struct kvm_guest_debug *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_lapic(struct kvm_lapic_state *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_mp_state(
    struct shim_vcpu_t const *const vcpu, struct kvm_mp_state *const user_args)
{
    struct kvm_mp_state mut_args;

    if (NULL == user_args) {
        bferror("user_args are null");
        return -EINVAL;
    }

    if (platform_copy_from_user(&mut_args, user_args, sizeof(mut_args))) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    if (handle_vcpu_kvm_set_mp_state(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_set_mp_state failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vcpu_kvm_set_msrs(
    struct shim_vcpu_t const *const vcpu, struct kvm_msrs *const user_args)
{

    struct kvm_msrs mut_args;
    uint64_t const size = sizeof(mut_args);

    if (NULL == user_args) {
        bferror("user_args are null");
        return -EINVAL;
    }

    if (platform_copy_from_user(&mut_args, user_args, size)) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    if (0 == mut_args.nmsrs) {
        /* Nothing to do */
        return 0;
    }

    if (handle_vcpu_kvm_set_msrs(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_set_msrs failed");
        return -EINVAL;
    }

    return mut_args.nmsrs;
}

static long
dispatch_vcpu_kvm_set_nested_state(struct kvm_nested_state *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_one_reg(struct kvm_one_reg *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_regs(
    struct shim_vcpu_t const *const vcpu, struct kvm_regs *const user_args)
{
    struct kvm_regs mut_args;
    uint64_t const size = sizeof(mut_args);

    if (platform_copy_from_user(&mut_args, user_args, size)) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    if (handle_vcpu_kvm_set_regs(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_set_regs failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vcpu_kvm_set_signal_mask(struct kvm_signal_mask *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_sregs(
    struct shim_vcpu_t const *const vcpu, struct kvm_sregs *const user_args)
{
    struct kvm_sregs mut_args;
    uint64_t const size = sizeof(mut_args);

    if (platform_copy_from_user(&mut_args, user_args, size)) {
        bferror("platform_copy_from_user failed");
        return -EINVAL;
    }

    if (handle_vcpu_kvm_set_sregs(vcpu, &mut_args)) {
        bferror("handle_vcpu_kvm_set_sregs failed");
        return -EINVAL;
    }

    return 0;
}

static long
dispatch_vcpu_kvm_set_tsc_khz(void)
{
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_vcpu_events(struct kvm_vcpu_events *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_xcrs(struct kvm_xcrs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_xsave(struct kvm_xsave *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_smi(void)
{
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_translate(struct kvm_translation *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_x86_set_mce(struct kvm_x86_mce *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_x86_setup_mce(uint64_t *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dev_unlocked_ioctl_vcpu(
    struct file *const file,
    unsigned int const cmd,
    unsigned long const ioctl_args)
{
    struct shim_vcpu_t *pmut_mut_vcpu;
    platform_expects(NULL != file);

    pmut_mut_vcpu = (struct shim_vcpu_t *)file->private_data;

    switch (cmd) {
        case KVM_ENABLE_CAP: {
            return dispatch_vcpu_kvm_enable_cap(
                (struct kvm_enable_cap *)ioctl_args);
        }

        case KVM_GET_CPUID2: {
            return dispatch_vcpu_kvm_get_cpuid2(
                (struct kvm_cpuid2 *)ioctl_args);
        }

        case KVM_GET_FPU: {
            return dispatch_vcpu_kvm_get_fpu(
                pmut_mut_vcpu, (struct kvm_fpu *)ioctl_args);
        }

        case KVM_GET_LAPIC: {
            return dispatch_vcpu_kvm_get_lapic(
                (struct kvm_lapic_state *)ioctl_args);
        }

        case KVM_GET_MP_STATE: {
            return dispatch_vcpu_kvm_get_mp_state(
                pmut_mut_vcpu, (struct kvm_mp_state *)ioctl_args);
        }

        case KVM_GET_MSRS: {
            return dispatch_vcpu_kvm_get_msrs(
                pmut_mut_vcpu, (struct kvm_msrs *)ioctl_args);
        }

        case KVM_GET_NESTED_STATE: {
            return dispatch_vcpu_kvm_get_nested_state(
                (struct kvm_nested_state *)ioctl_args);
        }

        case KVM_GET_ONE_REG: {
            return dispatch_vcpu_kvm_get_one_reg(
                (struct kvm_one_reg *)ioctl_args);
        }

        case KVM_GET_REGS: {
            return dispatch_vcpu_kvm_get_regs(
                pmut_mut_vcpu, (struct kvm_regs *)ioctl_args);
        }

        case KVM_GET_SREGS: {
            return dispatch_vcpu_kvm_get_sregs(
                pmut_mut_vcpu, (struct kvm_sregs *)ioctl_args);
        }

        case KVM_GET_SUPPORTED_HV_CPUID: {
            return dispatch_vcpu_kvm_get_supported_hv_cpuid(
                (struct kvm_cpuid2 *)ioctl_args);
        }

        case KVM_GET_TSC_KHZ: {
            if (ioctl_args) {
                bferror("KVM_GET_TSC_KHZ: ioctl_args are present");
                return -EINVAL;
            }
            return dispatch_vcpu_kvm_get_tsc_khz();
        }

        case KVM_GET_VCPU_EVENTS: {
            return dispatch_vcpu_kvm_get_vcpu_events(
                (struct kvm_vcpu_events *)ioctl_args);
        }

        case KVM_GET_XCRS: {
            return dispatch_vcpu_kvm_get_xcrs((struct kvm_xcrs *)ioctl_args);
        }

        case KVM_GET_XSAVE: {
            return dispatch_vcpu_kvm_get_xsave((struct kvm_xsave *)ioctl_args);
        }

        case KVM_INTERRUPT: {
            return dispatch_vcpu_kvm_interrupt(
                (struct kvm_interrupt *)ioctl_args);
        }

        case KVM_KVMCLOCK_CTRL: {
            return dispatch_vcpu_kvm_kvmclock_ctrl();
        }

        case KVM_NMI: {
            return dispatch_vcpu_kvm_nmi();
        }

        case KVM_RUN: {
            return dispatch_vcpu_kvm_run(pmut_mut_vcpu);
        }

        case KVM_SET_CPUID: {
            return dispatch_vcpu_kvm_set_cpuid((struct kvm_cpuid *)ioctl_args);
        }

        case KVM_SET_CPUID2: {
            return dispatch_vcpu_kvm_set_cpuid2(
                (struct kvm_cpuid2 *)ioctl_args);
        }

        case KVM_SET_FPU: {
            return dispatch_vcpu_kvm_set_fpu(
                pmut_mut_vcpu, (struct kvm_fpu *)ioctl_args);
        }

        case KVM_SET_GUEST_DEBUG: {
            return dispatch_vcpu_kvm_set_guest_debug(
                (struct kvm_guest_debug *)ioctl_args);
        }

        case KVM_SET_LAPIC: {
            return dispatch_vcpu_kvm_set_lapic(
                (struct kvm_lapic_state *)ioctl_args);
        }

        case KVM_SET_MP_STATE: {
            return dispatch_vcpu_kvm_set_mp_state(
                pmut_mut_vcpu, (struct kvm_mp_state *)ioctl_args);
        }

        case KVM_SET_MSRS: {
            return dispatch_vcpu_kvm_set_msrs(
                pmut_mut_vcpu, (struct kvm_msrs *)ioctl_args);
        }

        case KVM_SET_NESTED_STATE: {
            return dispatch_vcpu_kvm_set_nested_state(
                (struct kvm_nested_state *)ioctl_args);
        }

        case KVM_SET_ONE_REG: {
            return dispatch_vcpu_kvm_set_one_reg(
                (struct kvm_one_reg *)ioctl_args);
        }

        case KVM_SET_REGS: {
            return dispatch_vcpu_kvm_set_regs(
                pmut_mut_vcpu, (struct kvm_regs *)ioctl_args);
        }

        case KVM_SET_SIGNAL_MASK: {
            return dispatch_vcpu_kvm_set_signal_mask(
                (struct kvm_signal_mask *)ioctl_args);
        }

        case KVM_SET_SREGS: {
            return dispatch_vcpu_kvm_set_sregs(
                pmut_mut_vcpu, (struct kvm_sregs *)ioctl_args);
        }

        case KVM_SET_TSC_KHZ: {
            return dispatch_vcpu_kvm_set_tsc_khz();
        }

        case KVM_SET_VCPU_EVENTS: {
            return dispatch_vcpu_kvm_set_vcpu_events(
                (struct kvm_vcpu_events *)ioctl_args);
        }

        case KVM_SET_XCRS: {
            return dispatch_vcpu_kvm_set_xcrs((struct kvm_xcrs *)ioctl_args);
        }

        case KVM_SET_XSAVE: {
            return dispatch_vcpu_kvm_set_xsave((struct kvm_xsave *)ioctl_args);
        }

        case KVM_SMI: {
            return dispatch_vcpu_kvm_smi();
        }

        case KVM_TRANSLATE: {
            return dispatch_vcpu_kvm_translate(
                (struct kvm_translation *)ioctl_args);
        }

        case KVM_X86_SET_MCE: {
            return dispatch_vcpu_kvm_x86_set_mce(
                (struct kvm_x86_mce *)ioctl_args);
        }

        case KVM_X86_SETUP_MCE: {
            return dispatch_vcpu_kvm_x86_setup_mce((uint64_t *)ioctl_args);
        }

        default: {
            bferror_x64("invalid ioctl cmd", cmd);
            return -EINVAL;
        }
    };

    return 0;
}

/* -------------------------------------------------------------------------- */
/* Device IOCTLs                                                              */
/* -------------------------------------------------------------------------- */

static long
dispatch_device_kvm_get_device_attr(struct kvm_device_attr *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_device_kvm_has_device_attr(struct kvm_device_attr *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_device_kvm_set_device_attr(struct kvm_device_attr *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dev_unlocked_ioctl_device(
    struct file *const file,
    unsigned int const cmd,
    unsigned long const ioctl_args)
{
    switch (cmd) {
        case KVM_GET_DEVICE_ATTR: {
            return dispatch_device_kvm_get_device_attr(
                (struct kvm_device_attr *)ioctl_args);
        }

        case KVM_HAS_DEVICE_ATTR: {
            return dispatch_device_kvm_has_device_attr(
                (struct kvm_device_attr *)ioctl_args);
        }

        case KVM_SET_DEVICE_ATTR: {
            return dispatch_device_kvm_set_device_attr(
                (struct kvm_device_attr *)ioctl_args);
        }

        default: {
            bferror_x64("invalid ioctl cmd", cmd);
            return -EINVAL;
        }
    };

    return 0;
}

static vm_fault_t
dispatch_vcpu_mmap_fault(struct vm_fault *vmf)
{
    struct shim_vcpu_t *pmut_mut_vcpu;

    platform_expects(NULL != vmf);

    if (vmf->pgoff != 0) {
        bferror("a page offset of 0 is currently not supported");
        return -EINVAL;
    }

    pmut_mut_vcpu = (struct shim_vcpu_t *)vmf->vma->vm_file->private_data;
    platform_expects(NULL != pmut_mut_vcpu);

    vmf->page = vmalloc_to_page(pmut_mut_vcpu->run);
    get_page(vmf->page);

    return 0;
}

static const struct vm_operations_struct vops_vcpu = {
    .fault = dispatch_vcpu_mmap_fault,
};

static int
dispatch_vcpu_mmap(struct file *const file, struct vm_area_struct *vma)
{
    vma->vm_ops = &vops_vcpu;

    /// TODO:
    /// - We need to validate the mmap arguments here, which are not
    ///   being done.
    ///

    return 0;
}

static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl_system};

static struct miscdevice shim_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = SHIM_NAME,
    .fops = &fops,
    .mode = 0666};

static struct file_operations fops_vm = {
    .release = vm_release,                     // --
    .unlocked_ioctl = dev_unlocked_ioctl_vm    // --
};

static struct file_operations fops_vcpu = {
    .release = vcpu_release,                      // --
    .unlocked_ioctl = dev_unlocked_ioctl_vcpu,    // --
    .mmap = dispatch_vcpu_mmap                    // --
};

static struct file_operations fops_device = {
    .release = device_release,                     // --
    .unlocked_ioctl = dev_unlocked_ioctl_device    // --
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_reboot(struct notifier_block *nb, unsigned long code, void *unused)
{
    return NOTIFY_DONE;
}

static int
resume(void)
{
    return NOTIFY_BAD;
}

static int
suspend(void)
{
    return NOTIFY_BAD;
}

int
dev_pm(struct notifier_block *nb, unsigned long code, void *unused)
{
    int ret;

    switch (code) {
        case PM_SUSPEND_PREPARE:
        case PM_HIBERNATION_PREPARE:
        case PM_RESTORE_PREPARE: {
            ret = suspend();
            break;
        }

        case PM_POST_SUSPEND:
        case PM_POST_HIBERNATION:
        case PM_POST_RESTORE: {
            ret = resume();
            break;
        }

        default: {
            ret = NOTIFY_DONE;
            break;
        }
    }

    return ret;
}

static struct notifier_block reboot_notifier_block = {
    .notifier_call = dev_reboot};

static struct notifier_block pm_notifier_block = {.notifier_call = dev_pm};

int
dev_init(void)
{
    register_reboot_notifier(&reboot_notifier_block);
    register_pm_notifier(&pm_notifier_block);

    serial_init();

    if (shim_init()) {
        bferror("shim_init failed");
        goto shim_init_failed;
    }

    if (misc_register(&shim_dev)) {
        bferror("misc_register failed");
        goto misc_register_failed;
    }

    return 0;

    misc_deregister(&shim_dev);
misc_register_failed:

    shim_fini();
shim_init_failed:

    unregister_pm_notifier(&pm_notifier_block);
    unregister_reboot_notifier(&reboot_notifier_block);

    return -EPERM;
}

void
dev_exit(void)
{
    misc_deregister(&shim_dev);
    shim_fini();
    unregister_pm_notifier(&pm_notifier_block);
    unregister_reboot_notifier(&reboot_notifier_block);
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("Dual MIT/GPL");
