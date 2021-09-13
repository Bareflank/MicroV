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
#include <handle_system_kvm_create_vm.h>
#include <handle_system_kvm_destroy_vm.h>
#include <handle_system_kvm_get_vcpu_mmap_size.h>
#include <handle_vm_kvm_create_vcpu.h>
#include <handle_vm_kvm_destroy_vcpu.h>
#include <linux/anon_inodes.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#include <mv_constants.h>
#include <platform.h>
#include <serial_init.h>
#include <shim_fini.h>
#include <shim_init.h>
#include <shim_platform_interface.h>
#include <shim_vm_t.h>
#include <types.h>

static int
dev_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
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
    vfree(pmut_vm);

    return 0;
}

static int
vm_release(struct inode *inode, struct file *file)
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
vcpu_release(struct inode *inode, struct file *file)
{
    (void)inode;

    platform_expects(NULL != file);
    return vcpu_release_impl((struct shim_vcpu_t *)file->private_data);
}

static int
device_release(struct inode *inode, struct file *file)
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
dispatch_system_kvm_check_extension(void)
{
    return -EINVAL;
}

static long
dispatch_system_kvm_create_vm(void)
{
    char name[22];

    struct shim_vm_t *const pmut_vm =
        (struct shim_vm_t *)vmalloc(sizeof(struct shim_vm_t));

    if (NULL == pmut_vm) {
        bferror("vmalloc failed");
        return -EINVAL;
    }

    platform_mutex_init(&pmut_vm->mutex);

    if (handle_system_kvm_create_vm(pmut_vm)) {
        bferror("handle_system_kvm_create_vm failed");
        goto vmalloc_failed;
    }

    snprintf(name, sizeof(name), "kvm-vm:%d", pmut_vm->id);

    pmut_vm->fd =
        (uint64_t)anon_inode_getfd(name, &fops_vm, pmut_vm, O_RDWR | O_CLOEXEC);
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
    return -EINVAL;
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
dispatch_system_kvm_get_msr_index_list(struct kvm_msr_list *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_system_kvm_get_msrs(struct kvm_msrs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_system_kvm_get_supported_cpuid(struct kvm_cpuid2 *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
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
    struct file *file, unsigned int cmd, unsigned long ioctl_args)
{
    switch (cmd) {
        case KVM_CHECK_EXTENSION: {
            return dispatch_system_kvm_check_extension();
        }

        case KVM_CREATE_VM: {
            return dispatch_system_kvm_create_vm();
        }

        case KVM_GET_API_VERSION: {
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
                (struct kvm_msr_list *)ioctl_args);
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
dispatch_vm_kvm_check_extension(void)
{
    return -EINVAL;
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

    platform_expects(NULL != pmut_mut_vcpu);
    snprintf(name, sizeof(name), "kvm-vcpu:%d", pmut_mut_vcpu->id);

    pmut_mut_vcpu->fd = (uint64_t)anon_inode_getfd(
        name, &fops_vcpu, pmut_mut_vcpu, O_RDWR | O_CLOEXEC);
    if ((int32_t)pmut_mut_vcpu->fd < 0) {
        bferror("anon_inode_getfd failed");
        goto handle_vm_kvm_create_vcpu_failed;
    }

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
    return -EINVAL;
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
    return -EINVAL;
}

static long
dispatch_vm_kvm_set_user_memory_region(
    struct kvm_userspace_memory_region *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
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
    struct file *file, unsigned int cmd, unsigned long ioctl_args)
{
    struct shim_vm_t *pmut_mut_vm;
    platform_expects(NULL != file);

    pmut_mut_vm = (struct shim_vm_t *)file->private_data;

    switch (cmd) {
        case KVM_CHECK_EXTENSION: {
            return dispatch_vm_kvm_check_extension();
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
                (struct kvm_userspace_memory_region *)ioctl_args);
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
dispatch_vcpu_kvm_get_fpu(struct kvm_fpu *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_lapic(struct kvm_lapic_state *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_mp_state(struct kvm_mp_state *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_msrs(struct kvm_msrs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
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
dispatch_vcpu_kvm_get_regs(struct kvm_regs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_get_sregs(struct kvm_sregs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
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
    return -EINVAL;
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
dispatch_vcpu_kvm_run(void)
{
    return -EINVAL;
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
dispatch_vcpu_kvm_set_fpu(struct kvm_fpu *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
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
dispatch_vcpu_kvm_set_mp_state(struct kvm_mp_state *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_msrs(struct kvm_msrs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
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
dispatch_vcpu_kvm_set_regs(struct kvm_regs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_signal_mask(struct kvm_signal_mask *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dispatch_vcpu_kvm_set_sregs(struct kvm_sregs *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
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
    struct file *file, unsigned int cmd, unsigned long ioctl_args)
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
            return dispatch_vcpu_kvm_get_fpu((struct kvm_fpu *)ioctl_args);
        }

        case KVM_GET_LAPIC: {
            return dispatch_vcpu_kvm_get_lapic(
                (struct kvm_lapic_state *)ioctl_args);
        }

        case KVM_GET_MP_STATE: {
            return dispatch_vcpu_kvm_get_mp_state(
                (struct kvm_mp_state *)ioctl_args);
        }

        case KVM_GET_MSRS: {
            return dispatch_vcpu_kvm_get_msrs((struct kvm_msrs *)ioctl_args);
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
            return dispatch_vcpu_kvm_get_regs((struct kvm_regs *)ioctl_args);
        }

        case KVM_GET_SREGS: {
            return dispatch_vcpu_kvm_get_sregs((struct kvm_sregs *)ioctl_args);
        }

        case KVM_GET_SUPPORTED_HV_CPUID: {
            return dispatch_vcpu_kvm_get_supported_hv_cpuid(
                (struct kvm_cpuid2 *)ioctl_args);
        }

        case KVM_GET_TSC_KHZ: {
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
            return dispatch_vcpu_kvm_run();
        }

        case KVM_SET_CPUID: {
            return dispatch_vcpu_kvm_set_cpuid((struct kvm_cpuid *)ioctl_args);
        }

        case KVM_SET_CPUID2: {
            return dispatch_vcpu_kvm_set_cpuid2(
                (struct kvm_cpuid2 *)ioctl_args);
        }

        case KVM_SET_FPU: {
            return dispatch_vcpu_kvm_set_fpu((struct kvm_fpu *)ioctl_args);
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
                (struct kvm_mp_state *)ioctl_args);
        }

        case KVM_SET_MSRS: {
            return dispatch_vcpu_kvm_set_msrs((struct kvm_msrs *)ioctl_args);
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
            return dispatch_vcpu_kvm_set_regs((struct kvm_regs *)ioctl_args);
        }

        case KVM_SET_SIGNAL_MASK: {
            return dispatch_vcpu_kvm_set_signal_mask(
                (struct kvm_signal_mask *)ioctl_args);
        }

        case KVM_SET_SREGS: {
            return dispatch_vcpu_kvm_set_sregs((struct kvm_sregs *)ioctl_args);
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
    struct file *file, unsigned int cmd, unsigned long ioctl_args)
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
    .release = vm_release, .unlocked_ioctl = dev_unlocked_ioctl_vm};

static struct file_operations fops_vcpu = {
    .release = vcpu_release, .unlocked_ioctl = dev_unlocked_ioctl_vcpu};

static struct file_operations fops_device = {
    .release = device_release, .unlocked_ioctl = dev_unlocked_ioctl_device};

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
