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

#ifndef SHIM_PLATFORM_INTERFACE_H
#define SHIM_PLATFORM_INTERFACE_H

#include <kvm_clear_dirty_log.h>
#include <kvm_clock_data.h>
#include <kvm_coalesced_mmio_zone.h>
#include <kvm_cpuid.h>
#include <kvm_cpuid2.h>
#include <kvm_create_device.h>
#include <kvm_debugregs.h>
#include <kvm_device_attr.h>
#include <kvm_dirty_log.h>
#include <kvm_enable_cap.h>
#include <kvm_enc_region.h>
#include <kvm_fpu.h>
#include <kvm_guest_debug.h>
#include <kvm_hyperv_eventfd.h>
#include <kvm_interrupt.h>
#include <kvm_ioeventfd.h>
#include <kvm_irq_level.h>
#include <kvm_irq_routing.h>
#include <kvm_irqchip.h>
#include <kvm_irqfd.h>
#include <kvm_lapic_state.h>
#include <kvm_mp_state.h>
#include <kvm_msi.h>
#include <kvm_msr_list.h>
#include <kvm_msrs.h>
#include <kvm_nested_state.h>
#include <kvm_one_reg.h>
#include <kvm_pit_config.h>
#include <kvm_pit_state2.h>
#include <kvm_pmu_event_filter.h>
#include <kvm_regs.h>
#include <kvm_signal_mask.h>
#include <kvm_sregs.h>
#include <kvm_translation.h>
#include <kvm_userspace_memory_region.h>
#include <kvm_vcpu_events.h>
#include <kvm_x86_mce.h>
#include <kvm_xcrs.h>
#include <kvm_xen_hvm_config.h>
#include <kvm_xsave.h>
#include <linux/ioctl.h>

#define SHIMIO 0xAE

/** @brief defines the name of the shim */
#define SHIM_NAME "microv_shim"
/** @brief defines the /dev name of the shim */
#define SHIM_DEVICE_NAME "/dev/microv_shim"

/**
 * @brief Hack for defining ioctl commands that require structs
 * with zero-length arrays. This is usually for ioctls that return
 * a list. We will use arrays with defined length instead.
 *
 * It is just like _IOWR, except it takes a second type argument and
 * subtracts its size from the size of the first type.
 */
#define _IOWR_LIST(type, nr, size, size_arr)                                                       \
    _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), sizeof(size) - sizeof(size_arr))

#define _IOW_LIST(type, nr, size, sub_size)                                                        \
    _IOC(_IOC_WRITE, (type), (nr), sizeof(size) - sizeof(sub_size))

/** @brief defines KVM's KVM_GET_API_VERSION IOCTL */
#define KVM_GET_API_VERSION _IO(SHIMIO, 0x00)
/** @brief defines KVM's KVM_CREATE_VM IOCTL */
#define KVM_CREATE_VM _IO(SHIMIO, 0x01)
/** @brief defines KVM's KVM_GET_MSR_INDEX_LIST IOCTL */
#define KVM_GET_MSR_INDEX_LIST                                                                     \
    _IOWR_LIST(SHIMIO, 0x02, struct kvm_msr_list, uint32_t[MSR_LIST_MAX_INDICES])
/** @brief defines KVM's KVM_GET_MSR_FEATURE_INDEX_LIST IOCTL */
#define KVM_GET_MSR_FEATURE_INDEX_LIST _IOWR(SHIMIO, 0x0a, struct kvm_msr_list)
/** @brief defines KVM's KVM_CHECK_EXTENSION IOCTL */
#define KVM_CHECK_EXTENSION _IO(SHIMIO, 0x03)
/** @brief defines KVM's KVM_GET_VCPU_MMAP_SIZE IOCTL */
#define KVM_GET_VCPU_MMAP_SIZE _IO(SHIMIO, 0x04)
/** @brief defines KVM's KVM_CREATE_VCPU IOCTL */
#define KVM_CREATE_VCPU _IO(SHIMIO, 0x41)
/** @brief defines KVM's KVM_GET_DIRTY_LOG IOCTL */
#define KVM_GET_DIRTY_LOG _IOW(SHIMIO, 0x42, struct kvm_dirty_log)
/** @brief defines KVM's KVM_RUN IOCTL */
#define KVM_RUN _IO(SHIMIO, 0x80)
/** @brief defines KVM's KVM_GET_REGS IOCTL */
#define KVM_GET_REGS _IOR(SHIMIO, 0x81, struct kvm_regs)
/** @brief defines KVM's KVM_SET_REGS IOCTL */
#define KVM_SET_REGS _IOW(SHIMIO, 0x82, struct kvm_regs)
/** @brief defines KVM's KVM_GET_SREGS IOCTL */
#define KVM_GET_SREGS _IOR(SHIMIO, 0x83, struct kvm_sregs)
/** @brief defines KVM's KVM_SET_SREGS IOCTL */
#define KVM_SET_SREGS _IOW(SHIMIO, 0x84, struct kvm_sregs)
/** @brief defines KVM's KVM_TRANSLATE IOCTL */
#define KVM_TRANSLATE _IOWR(SHIMIO, 0x85, struct kvm_translation)
/** @brief defines KVM's KVM_INTERRUPT IOCTL */
#define KVM_INTERRUPT _IOW(SHIMIO, 0x86, struct kvm_interrupt)
/** @brief defines KVM's KVM_GET_MSRS IOCTL */
#define KVM_GET_MSRS                                                                               \
    _IOWR_LIST(SHIMIO, 0x88, struct kvm_msrs, struct kvm_msr_entry[MV_RDL_MAX_ENTRIES])
//#define KVM_GET_MSRS _IOWR(SHIMIO, 0x88, struct kvm_msrs)
/** @brief defines KVM's KVM_SET_MSRS IOCTL */
#define KVM_SET_MSRS                                                                               \
    _IOW_LIST(SHIMIO, 0x89, struct kvm_msrs, struct kvm_msr_entry[MV_RDL_MAX_ENTRIES])
/** @brief defines KVM's KVM_SET_CPUID IOCTL */
#define KVM_SET_CPUID _IOW(SHIMIO, 0x8a, struct kvm_cpuid)
/** @brief defines KVM's KVM_GET_CPUID2 IOCTL */
#define KVM_GET_CPUID2 _IOWR(SHIMIO, 0x91, struct kvm_cpuid2)
/** @brief defines KVM's KVM_SET_CPUID2 IOCTL */
#define KVM_SET_CPUID2 _IOW(SHIMIO, 0x90, struct kvm_cpuid2)
/** @brief defines KVM's KVM_SET_SIGNAL_MASK IOCTL */
#define KVM_SET_SIGNAL_MASK _IOW(SHIMIO, 0x8b, struct kvm_signal_mask)
/** @brief defines KVM's KVM_GET_FPU IOCTL */
#define KVM_GET_FPU _IOR(SHIMIO, 0x8c, struct kvm_fpu)
/** @brief defines KVM's KVM_SET_FPU IOCTL */
#define KVM_SET_FPU _IOW(SHIMIO, 0x8d, struct kvm_fpu)
/** @brief defines KVM's KVM_CREATE_IRQCHIP IOCTL */
#define KVM_CREATE_IRQCHIP _IO(SHIMIO, 0x60)
/** @brief defines KVM's KVM_IRQ_LINE IOCTL */
#define KVM_IRQ_LINE _IOW(SHIMIO, 0x61, struct kvm_irq_level)
/** @brief defines KVM's KVM_GET_IRQCHIP IOCTL */
#define KVM_GET_IRQCHIP _IOWR(SHIMIO, 0x62, struct kvm_irqchip)
/** @brief defines KVM's KVM_SET_IRQCHIP IOCTL */
#define KVM_SET_IRQCHIP _IOR(SHIMIO, 0x63, struct kvm_irqchip)
/** @brief defines KVM's KVM_XEN_HVM_CONFIG IOCTL */
#define KVM_XEN_HVM_CONFIG _IOW(SHIMIO, 0x7a, struct kvm_xen_hvm_config)
/** @brief defines KVM's KVM_GET_CLOCK IOCTL */
#define KVM_GET_CLOCK _IOR(SHIMIO, 0x7c, struct kvm_clock_data)
/** @brief defines KVM's KVM_SET_CLOCK IOCTL */
#define KVM_SET_CLOCK _IOW(SHIMIO, 0x7b, struct kvm_clock_data)
/** @brief defines KVM's KVM_GET_VCPU_EVENTS IOCTL */
#define KVM_GET_VCPU_EVENTS _IOR(SHIMIO, 0x9f, struct kvm_vcpu_events)
/** @brief defines KVM's KVM_SET_VCPU_EVENTS IOCTL */
#define KVM_SET_VCPU_EVENTS _IOW(SHIMIO, 0xa0, struct kvm_vcpu_events)
/** @brief defines KVM's KVM_GET_DEBUGREGS IOCTL */
#define KVM_GET_DEBUGREGS _IOR(SHIMIO, 0xa1, struct kvm_debugregs)
/** @brief defines KVM's KVM_SET_DEBUGREGS IOCTL */
#define KVM_SET_DEBUGREGS _IOW(SHIMIO, 0xa2, struct kvm_debugregs)
/** @brief defines KVM's KVM_SET_USER_MEMORY_REGION IOCTL */
#define KVM_SET_USER_MEMORY_REGION _IOW(SHIMIO, 0x46, struct kvm_userspace_memory_region)
/** @brief defines KVM's KVM_SET_TSS_ADDR IOCTL */
#define KVM_SET_TSS_ADDR _IO(SHIMIO, 0x47)
/** @brief defines KVM's KVM_ENABLE_CAP IOCTL */
#define KVM_ENABLE_CAP _IOW(SHIMIO, 0xa3, struct kvm_enable_cap)
/** @brief defines KVM's KVM_GET_MP_STATE IOCTL */
#define KVM_GET_MP_STATE _IOR(SHIMIO, 0x98, struct kvm_mp_state)
/** @brief defines KVM's KVM_SET_MP_STATE IOCTL */
#define KVM_SET_MP_STATE _IOW(SHIMIO, 0x99, struct kvm_mp_state)
/** @brief defines KVM's KVM_SET_IDENTITY_MAP_ADDR IOCTL */
#define KVM_SET_IDENTITY_MAP_ADDR _IOW(SHIMIO, 0x48, __u64)
/** @brief defines KVM's KVM_SET_BOOT_CPU_ID IOCTL */
#define KVM_SET_BOOT_CPU_ID _IO(SHIMIO, 0x78)
/** @brief defines KVM's KVM_GET_XSAVE IOCTL */
#define KVM_GET_XSAVE _IOR(SHIMIO, 0xa4, struct kvm_xsave)
/** @brief defines KVM's KVM_SET_XSAVE IOCTL */
#define KVM_SET_XSAVE _IOW(SHIMIO, 0xa5, struct kvm_xsave)
/** @brief defines KVM's KVM_GET_XCRS IOCTL */
#define KVM_GET_XCRS _IOR(SHIMIO, 0xa6, struct kvm_xcrs)
/** @brief defines KVM's KVM_SET_XCRS IOCTL */
#define KVM_SET_XCRS _IOW(SHIMIO, 0xa7, struct kvm_xcrs)
/** @brief defines KVM's KVM_GET_SUPPORTED_CPUID IOCTL */
#define KVM_GET_SUPPORTED_CPUID                                                                    \
    _IOWR_LIST(SHIMIO, 0x05, struct kvm_cpuid2, struct kvm_cpuid_entry2[CPUID2_MAX_ENTRIES])
/** @brief defines KVM's KVM_SET_GSI_ROUTING IOCTL */
#define KVM_SET_GSI_ROUTING _IOW(SHIMIO, 0x6a, struct kvm_irq_routing)
/** @brief defines KVM's KVM_GET_TSC_KHZ IOCTL */
#define KVM_GET_TSC_KHZ _IO(SHIMIO, 0xa3)
/** @brief defines KVM's KVM_SET_TSC_KHZ IOCTL */
#define KVM_SET_TSC_KHZ _IO(SHIMIO, 0xa2)
/** @brief defines KVM's KVM_GET_LAPIC IOCTL */
#define KVM_GET_LAPIC _IOR(SHIMIO, 0x8e, struct kvm_lapic_state)
/** @brief defines KVM's KVM_SET_LAPIC IOCTL */
#define KVM_SET_LAPIC _IOW(SHIMIO, 0x8f, struct kvm_lapic_state)
/** @brief defines KVM's KVM_IOEVENTFD IOCTL */
#define KVM_IOEVENTFD _IOW(SHIMIO, 0x79, struct kvm_ioeventfd)
/** @brief defines KVM's KVM_NMI IOCTL */
#define KVM_NMI _IO(SHIMIO, 0x9a)
/** @brief defines KVM's KVM_GET_ONE_REG IOCTL */
#define KVM_GET_ONE_REG _IOW(SHIMIO, 0xab, struct kvm_one_reg)
/** @brief defines KVM's KVM_SET_ONE_REG IOCTL */
#define KVM_SET_ONE_REG _IOW(SHIMIO, 0xac, struct kvm_one_reg)
/** @brief defines KVM's KVM_KVMCLOCK_CTRL IOCTL */
#define KVM_KVMCLOCK_CTRL _IO(SHIMIO, 0xad)
/** @brief defines KVM's KVM_SIGNAL_MSI IOCTL */
#define KVM_SIGNAL_MSI _IOW(SHIMIO, 0xa5, struct kvm_msi)
/** @brief defines KVM's KVM_CREATE_PIT2 IOCTL */
#define KVM_CREATE_PIT2 _IOW(SHIMIO, 0x77, struct kvm_pit_config)
/** @brief defines KVM's KVM_GET_PIT2 IOCTL */
#define KVM_GET_PIT2 _IOR(SHIMIO, 0x9f, struct kvm_pit_state2)
/** @brief defines KVM's KVM_SET_PIT2 IOCTL */
#define KVM_SET_PIT2 _IOW(SHIMIO, 0xa0, struct kvm_pit_state2)
/** @brief defines KVM's KVM_IRQFD IOCTL */
#define KVM_IRQFD _IOW(SHIMIO, 0x76, struct kvm_irqfd)
/** @brief defines KVM's KVM_CREATE_DEVICE IOCTL */
#define KVM_CREATE_DEVICE _IOWR(SHIMIO, 0xe0, struct kvm_create_device)
/** @brief defines KVM's KVM_GET_DEVICE_ATTR IOCTL */
#define KVM_GET_DEVICE_ATTR _IOW(SHIMIO, 0xe2, struct kvm_device_attr)
/** @brief defines KVM's KVM_SET_DEVICE_ATTR IOCTL */
#define KVM_SET_DEVICE_ATTR _IOW(SHIMIO, 0xe1, struct kvm_device_attr)
/** @brief defines KVM's KVM_HAS_DEVICE_ATTR IOCTL */
#define KVM_HAS_DEVICE_ATTR _IOW(SHIMIO, 0xe3, struct kvm_device_attr)
/** @brief defines KVM's KVM_SET_GUEST_DEBUG IOCTL */
#define KVM_SET_GUEST_DEBUG _IOW(SHIMIO, 0x9b, struct kvm_guest_debug)
/** @brief defines KVM's KVM_GET_EMULATED_CPUID IOCTL */
#define KVM_GET_EMULATED_CPUID _IOWR(SHIMIO, 0x09, struct kvm_cpuid2)
/** @brief defines KVM's KVM_SMI IOCTL */
#define KVM_SMI _IO(SHIMIO, 0xb7)
/** @brief defines KVM's KVM_REINJECT_CONTROL IOCTL */
#define KVM_REINJECT_CONTROL _IO(SHIMIO, 0x71)
/** @brief defines KVM's KVM_X86_GET_MCE_CAP_SUPPORTED IOCTL */
#define KVM_X86_GET_MCE_CAP_SUPPORTED _IOR(SHIMIO, 0x9d, __u64)
/** @brief defines KVM's KVM_X86_SETUP_MCE IOCTL */
#define KVM_X86_SETUP_MCE _IOW(SHIMIO, 0x9c, __u64)
/** @brief defines KVM's KVM_X86_SET_MCE IOCTL */
#define KVM_X86_SET_MCE _IOW(SHIMIO, 0x9e, struct kvm_x86_mce)
/** @brief defines KVM's KVM_MEMORY_ENCRYPT_OP IOCTL */
#define KVM_MEMORY_ENCRYPT_OP _IOWR(SHIMIO, 0xba, unsigned long)
/** @brief defines KVM's KVM_MEMORY_ENCRYPT_REG_REGION IOCTL */
#define KVM_MEMORY_ENCRYPT_REG_REGION _IOR(SHIMIO, 0xbb, struct kvm_enc_region)
/** @brief defines KVM's KVM_MEMORY_ENCRYPT_UNREG_REGION IOCTL */
#define KVM_MEMORY_ENCRYPT_UNREG_REGION _IOR(SHIMIO, 0xbc, struct kvm_enc_region)
/** @brief defines KVM's KVM_HYPERV_EVENTFD IOCTL */
#define KVM_HYPERV_EVENTFD _IOW(SHIMIO, 0xbd, struct kvm_hyperv_eventfd)
/** @brief defines KVM's KVM_GET_NESTED_STATE IOCTL */
#define KVM_GET_NESTED_STATE _IOWR(SHIMIO, 0xbe, struct kvm_nested_state)
/** @brief defines KVM's KVM_SET_NESTED_STATE IOCTL */
#define KVM_SET_NESTED_STATE _IOW(SHIMIO, 0xbf, struct kvm_nested_state)
/** @brief defines KVM's KVM_REGISTER_COALESCED_MMIO IOCTL */
#define KVM_REGISTER_COALESCED_MMIO _IOW(SHIMIO, 0x67, struct kvm_coalesced_mmio_zone)
/** @brief defines KVM's KVM_UNREGISTER_COALESCED_MMIO IOCTL */
#define KVM_UNREGISTER_COALESCED_MMIO _IOW(SHIMIO, 0x68, struct kvm_coalesced_mmio_zone)
/** @brief defines KVM's KVM_CLEAR_DIRTY_LOG IOCTL */
#define KVM_CLEAR_DIRTY_LOG _IOWR(SHIMIO, 0xc0, struct kvm_clear_dirty_log)
/** @brief defines KVM's KVM_GET_SUPPORTED_HV_CPUID IOCTL */
#define KVM_GET_SUPPORTED_HV_CPUID _IOWR(SHIMIO, 0xc1, struct kvm_cpuid2)
/** @brief defines KVM's KVM_SET_PMU_EVENT_FILTER IOCTL */
#define KVM_SET_PMU_EVENT_FILTER _IOW(SHIMIO, 0xb2, struct kvm_pmu_event_filter)

#endif
