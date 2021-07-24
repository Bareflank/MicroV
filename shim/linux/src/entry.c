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
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#include <platform.h>
#include <serial_init.h>
#include <shim_fini.h>
#include <shim_init.h>
#include <shim_platform_interface.h>
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

static long
handle_kvm_get_api_version(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_create_vm(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_msr_index_list(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_msr_feature_index_list(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_check_extension(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_vcpu_mmap_size(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_create_vcpu(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_dirty_log(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_run(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_regs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_regs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_sregs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_sregs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_translate(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_interrupt(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_msrs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_msrs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_cpuid(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_cpuid2(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_signal_mask(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_fpu(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_fpu(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_create_irqchip(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_irq_line(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_irqchip(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_irqchip(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_xen_hvm_config(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_clock(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_clock(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_vcpu_events(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_vcpu_events(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_debugregs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_debugregs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_user_memory_region(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_tss_addr(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_enable_cap(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_mp_state(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_mp_state(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_identity_map_addr(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_boot_cpu_id(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_xsave(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_xsave(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_xcrs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_xcrs(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_supported_cpuid(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_gsi_routing(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_tsc_khz(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_tsc_khz(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_lapic(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_lapic(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_ioeventfd(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_nmi(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_one_reg(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_one_reg(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_kvmclock_ctrl(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_signal_msi(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_create_pit2(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_pit2(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_pit2(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_irqfd(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_create_device(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_device_attr(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_device_attr(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_has_device_attr(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_guest_debug(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_emulated_cpuid(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_smi(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_reinject_control(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_x86_get_mce_cap_supported(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_x86_setup_mce(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_x86_set_mce(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_memory_encrypt_op(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_memory_encrypt_reg_region(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_memory_encrypt_unreg_region(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_hyperv_eventfd(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_nested_state(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_nested_state(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_register_coalesced_mmio(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_unregister_coalesced_mmio(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_clear_dirty_log(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_get_supported_hv_cpuid(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
handle_kvm_set_pmu_event_filter(void *const ioctl_args)
{
    (void)ioctl_args;
    return -EINVAL;
}

static long
dev_unlocked_ioctl(
    struct file *file, unsigned int cmd, unsigned long ioctl_args)
{
    switch (cmd) {
        case KVM_GET_API_VERSION: {
            return handle_kvm_get_api_version();
        }

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM();
        }

        case KVM_GET_MSR_INDEX_LIST: {
            return handle_KVM_GET_MSR_INDEX_LIST((struct kvm_msr_list *)ioctl_args);
        }

        case KVM_GET_MSR_FEATURE_INDEX_LIST: {
            return handle_KVM_GET_MSR_FEATURE_INDEX_LIST((struct kvm_msr_list *)ioctl_args);
        }

        case KVM_CHECK_EXTENSION: {
            return handle_KVM_CHECK_EXTENSION();
        }

        case KVM_GET_VCPU_MMAP_SIZE: {
            return handle_KVM_GET_VCPU_MMAP_SIZE();
        }

        case KVM_CREATE_VCPU: {
            return handle_KVM_CREATE_VCPU();
        }

        case KVM_GET_DIRTY_LOG: {
            return handle_KVM_GET_DIRTY_LOG((struct kvm_dirty_log *)ioctl_args);
        }

        case KVM_RUN: {
            return handle_KVM_RUN();
        }

        case KVM_GET_REGS: {
            return handle_KVM_GET_REGS((struct kvm_regs *)ioctl_args);
        }

        case KVM_SET_REGS: {
            return handle_KVM_SET_REGS((struct kvm_regs *)ioctl_args);
        }

        case KVM_GET_SREGS: {
            return handle_KVM_GET_SREGS((struct kvm_sregs *)ioctl_args);
        }

        case KVM_SET_SREGS: {
            return handle_KVM_SET_SREGS((struct kvm_sregs *)ioctl_args);
        }

        case KVM_TRANSLATE: {
            return handle_KVM_TRANSLATE((struct kvm_translation *)ioctl_args);
        }

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_INTERRUPT _IOW(SHIMIO, 0x86, struct kvm_interrupt)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_MSRS _IOWR(SHIMIO, 0x88, struct kvm_msrs)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_MSRS _IOW(SHIMIO, 0x89, struct kvm_msrs)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_CPUID _IOW(SHIMIO, 0x8a, struct kvm_cpuid)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_CPUID2 _IOWR(SHIMIO, 0x91, struct kvm_cpuid2)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_CPUID2 _IOW(SHIMIO, 0x90, struct kvm_cpuid2)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_SIGNAL_MASK _IOW(SHIMIO, 0x8b, struct kvm_signal_mask)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_FPU _IOR(SHIMIO, 0x8c, struct kvm_fpu)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_FPU _IOW(SHIMIO, 0x8d, struct kvm_fpu)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_CREATE_IRQCHIP _IO(SHIMIO, 0x60)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_IRQ_LINE _IOW(SHIMIO, 0x61, struct kvm_irq_level)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_IRQCHIP _IOWR(SHIMIO, 0x62, struct kvm_irqchip)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_IRQCHIP _IOR(SHIMIO, 0x63, struct kvm_irqchip)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_XEN_HVM_CONFIG _IOW(SHIMIO, 0x7a, struct kvm_xen_hvm_config)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_CLOCK _IOR(SHIMIO, 0x7c, struct kvm_clock_data)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_CLOCK _IOW(SHIMIO, 0x7b, struct kvm_clock_data)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_VCPU_EVENTS _IOR(SHIMIO, 0x9f, struct kvm_vcpu_events)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_VCPU_EVENTS _IOW(SHIMIO, 0xa0, struct kvm_vcpu_events)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_DEBUGREGS _IOR(SHIMIO, 0xa1, struct kvm_debugregs)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_DEBUGREGS _IOW(SHIMIO, 0xa2, struct kvm_debugregs)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_USER_MEMORY_REGION _IOW(SHIMIO, 0x46, struct kvm_userspace_memory_region)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_TSS_ADDR _IO(SHIMIO, 0x47)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_ENABLE_CAP _IOW(SHIMIO, 0xa3, struct kvm_enable_cap)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_MP_STATE _IOR(SHIMIO, 0x98, struct kvm_mp_state)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_MP_STATE _IOW(SHIMIO, 0x99, struct kvm_mp_state)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_IDENTITY_MAP_ADDR _IOW(SHIMIO, 0x48, __u64)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_BOOT_CPU_ID _IO(SHIMIO, 0x78)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_XSAVE _IOR(SHIMIO, 0xa4, struct kvm_xsave)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_XSAVE _IOW(SHIMIO, 0xa5, struct kvm_xsave)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_XCRS _IOR(SHIMIO, 0xa6, struct kvm_xcrs)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_XCRS _IOW(SHIMIO, 0xa7, struct kvm_xcrs)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_SUPPORTED_CPUID _IOWR(SHIMIO, 0x05, struct kvm_cpuid2)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_GSI_ROUTING _IOW(SHIMIO, 0x6a, struct kvm_irq_routing)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_TSC_KHZ _IO(SHIMIO, 0xa3)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_TSC_KHZ _IO(SHIMIO, 0xa2)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_LAPIC _IOR(SHIMIO, 0x8e, struct kvm_lapic_state)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_LAPIC _IOW(SHIMIO, 0x8f, struct kvm_lapic_state)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_IOEVENTFD _IOW(SHIMIO, 0x79, struct kvm_ioeventfd)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_NMI _IO(SHIMIO, 0x9a)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_ONE_REG _IOW(SHIMIO, 0xab, struct kvm_one_reg)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_ONE_REG _IOW(SHIMIO, 0xac, struct kvm_one_reg)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_KVMCLOCK_CTRL _IO(SHIMIO, 0xad)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SIGNAL_MSI _IOW(SHIMIO, 0xa5, struct kvm_msi)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_CREATE_PIT2 _IOW(SHIMIO, 0x77, struct kvm_pit_config)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_PIT2 _IOR(SHIMIO, 0x9f, struct kvm_pit_state2)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_PIT2 _IOW(SHIMIO, 0xa0, struct kvm_pit_state2)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_IRQFD _IOW(SHIMIO, 0x76, struct kvm_irqfd)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_CREATE_DEVICE _IOWR(SHIMIO, 0xe0, struct kvm_create_device)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_DEVICE_ATTR _IOW(SHIMIO, 0xe2, struct kvm_device_attr)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_DEVICE_ATTR _IOW(SHIMIO, 0xe1, struct kvm_device_attr)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_HAS_DEVICE_ATTR _IOW(SHIMIO, 0xe3, struct kvm_device_attr)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_GUEST_DEBUG _IOW(SHIMIO, 0x9b, struct kvm_guest_debug)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_EMULATED_CPUID _IOWR(SHIMIO, 0x09, struct kvm_cpuid2)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SMI _IO(SHIMIO, 0xb7)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_REINJECT_CONTROL _IO(SHIMIO, 0x71)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_X86_GET_MCE_CAP_SUPPORTED _IOR(SHIMIO, 0x9d, __u64)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_X86_SETUP_MCE _IOW(SHIMIO, 0x9c, __u64)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_X86_SET_MCE _IOW(SHIMIO, 0x9e, struct kvm_x86_mce)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_MEMORY_ENCRYPT_OP _IOWR(SHIMIO, 0xba, unsigned long)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_MEMORY_ENCRYPT_REG_REGION _IOR(SHIMIO, 0xbb, struct kvm_enc_region)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_MEMORY_ENCRYPT_UNREG_REGION _IOR(SHIMIO, 0xbc, struct kvm_enc_region)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_HYPERV_EVENTFD _IOW(SHIMIO, 0xbd, struct kvm_hyperv_eventfd)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_NESTED_STATE _IOWR(SHIMIO, 0xbe, struct kvm_nested_state)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_NESTED_STATE _IOW(SHIMIO, 0xbf, struct kvm_nested_state)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_REGISTER_COALESCED_MMIO _IOW(SHIMIO, 0x67, struct kvm_coalesced_mmio_zone)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_UNREGISTER_COALESCED_MMIO _IOW(SHIMIO, 0x68, struct kvm_coalesced_mmio_zone)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_CLEAR_DIRTY_LOG _IOWR(SHIMIO, 0xc0, struct kvm_clear_dirty_log)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_GET_SUPPORTED_HV_CPUID _IOWR(SHIMIO, 0xc1, struct kvm_cpuid2)

        case KVM_CREATE_VM: {
            return handle_KVM_CREATE_VM((struct xxx *)ioctl_args);
        }
#define KVM_SET_PMU_EVENT_FILTER _IOW(SHIMIO, 0xb2, struct kvm_pmu_event_filter)












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
    .unlocked_ioctl = dev_unlocked_ioctl};

static struct miscdevice shim_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = SHIM_NAME,
    .fops = &fops,
    .mode = 0666};

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
