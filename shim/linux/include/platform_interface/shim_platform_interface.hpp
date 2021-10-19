/// SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT
///
/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef SHIM_PLATFORM_INTERFACE_HPP
#define SHIM_PLATFORM_INTERFACE_HPP

#include <asm/ioctl.h>
#include <kvm_fpu.hpp>
#include <kvm_mp_state.hpp>
#include <kvm_regs.hpp>
#include <kvm_sregs.hpp>
#include <kvm_userspace_memory_region.hpp>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>

// #include <kvm_clear_dirty_log.hpp>
// #include <kvm_clock_data.hpp>
// #include <kvm_coalesced_mmio_zone.hpp>
// #include <kvm_cpuid.hpp>
// #include <kvm_cpuid2.hpp>
// #include <kvm_create_device.hpp>
// #include <kvm_debugregs.hpp>
// #include <kvm_device_attr.hpp>
// #include <kvm_dirty_log.hpp>
// #include <kvm_enable_cap.hpp>
// #include <kvm_enc_region.hpp>
// #include <kvm_fpu.hpp>
// #include <kvm_guest_debug.hpp>
// #include <kvm_hyperv_eventfd.hpp>
// #include <kvm_interrupt.hpp>
// #include <kvm_ioeventfd.hpp>
// #include <kvm_irq_level.hpp>
// #include <kvm_irq_routing.hpp>
// #include <kvm_irqchip.hpp>
// #include <kvm_irqfd.hpp>
// #include <kvm_lapic_state.hpp>
// #include <kvm_mp_state.hpp>
// #include <kvm_msi.hpp>
// #include <kvm_msr_list.hpp>
// #include <kvm_msrs.hpp>
// #include <kvm_nested_state.hpp>
// #include <kvm_one_reg.hpp>
// #include <kvm_pit_config.hpp>
// #include <kvm_pit_state2.hpp>
// #include <kvm_pmu_event_filter.hpp>
// #include <kvm_regs.hpp>
// #include <kvm_signal_mask.hpp>
// #include <kvm_sregs.hpp>
// #include <kvm_translation.hpp>
// #include <kvm_userspace_memory_region.hpp>
// #include <kvm_vcpu_events.hpp>
// #include <kvm_x86_mce.hpp>
// #include <kvm_xcrs.hpp>
// #include <kvm_xen_hvm_config.hpp>
// #include <kvm_xsave.hpp>

namespace shim
{
    /// @brief magic number for KVM IOCTLs
    constexpr bsl::safe_umx SHIMIO{0xAE_umx};

    /// @brief defines the name of the shim
    constexpr bsl::string_view NAME{"microv_shim"};
    /// @brief defines the /dev name of the shim
    constexpr bsl::string_view DEVICE_NAME{"/dev/microv_shim"};

    /// @brief defines KVM's KVM_GET_API_VERSION IOCTL
    constexpr bsl::safe_umx KVM_GET_API_VERSION{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x00))};
    /// @brief defines KVM's KVM_CREATE_VM IOCTL
    constexpr bsl::safe_umx KVM_CREATE_VM{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x01))};
    // /// @brief defines KVM's KVM_GET_MSR_INDEX_LIST IOCTL
    // constexpr bsl::safe_umx KVM_GET_MSR_INDEX_LIST{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0x02, struct kvm_msr_list))};
    // /// @brief defines KVM's KVM_GET_MSR_FEATURE_INDEX_LIST IOCTL
    // constexpr bsl::safe_umx KVM_GET_MSR_FEATURE_INDEX_LIST{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0x0a, struct kvm_msr_list))};
    /// @brief defines KVM's KVM_CHECK_EXTENSION IOCTL
    constexpr bsl::safe_umx KVM_CHECK_EXTENSION{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x03))};
    /// @brief defines KVM's KVM_GET_VCPU_MMAP_SIZE IOCTL
    constexpr bsl::safe_umx KVM_GET_VCPU_MMAP_SIZE{
        static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x04))};
    /// @brief defines KVM's KVM_CREATE_VCPU IOCTL
    constexpr bsl::safe_umx KVM_CREATE_VCPU{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x41))};
    // /// @brief defines KVM's KVM_GET_DIRTY_LOG IOCTL
    // constexpr bsl::safe_umx KVM_GET_DIRTY_LOG{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x42, struct kvm_dirty_log))};
    /// @brief defines KVM's KVM_RUN IOCTL
    constexpr bsl::safe_umx KVM_RUN{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x80))};
    /// @brief defines KVM's KVM_GET_REGS IOCTL
    constexpr bsl::safe_umx KVM_GET_REGS{
        static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x81, struct kvm_regs))};
    /// @brief defines KVM's KVM_SET_REGS IOCTL
    constexpr bsl::safe_umx KVM_SET_REGS{
        static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x82, struct kvm_regs))};
    /// @brief defines KVM's KVM_GET_SREGS IOCTL
    constexpr bsl::safe_umx KVM_GET_SREGS{
        static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x83, struct kvm_sregs))};
    /// @brief defines KVM's KVM_SET_SREGS IOCTL
    constexpr bsl::safe_umx KVM_SET_SREGS{
        static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x84, struct kvm_sregs))};
    // /// @brief defines KVM's KVM_TRANSLATE IOCTL
    // constexpr bsl::safe_umx KVM_TRANSLATE{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0x85, struct kvm_translation))};
    // /// @brief defines KVM's KVM_INTERRUPT IOCTL
    // constexpr bsl::safe_umx KVM_INTERRUPT{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x86, struct kvm_interrupt))};
    // /// @brief defines KVM's KVM_GET_MSRS IOCTL
    // constexpr bsl::safe_umx KVM_GET_MSRS{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0x88, struct kvm_msrs))};
    // /// @brief defines KVM's KVM_SET_MSRS IOCTL
    // constexpr bsl::safe_umx KVM_SET_MSRS{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x89, struct kvm_msrs))};
    // /// @brief defines KVM's KVM_SET_CPUID IOCTL
    // constexpr bsl::safe_umx KVM_SET_CPUID{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x8a, struct kvm_cpuid))};
    // /// @brief defines KVM's KVM_GET_CPUID2 IOCTL
    // constexpr bsl::safe_umx KVM_GET_CPUID2{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0x91, struct kvm_cpuid2))};
    // /// @brief defines KVM's KVM_SET_CPUID2 IOCTL
    // constexpr bsl::safe_umx KVM_SET_CPUID2{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x90, struct kvm_cpuid2))};
    // /// @brief defines KVM's KVM_SET_SIGNAL_MASK IOCTL
    // constexpr bsl::safe_umx KVM_SET_SIGNAL_MASK{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x8b, struct kvm_signal_mask))};
    /// @brief defines KVM's KVM_GET_FPU IOCTL
    constexpr bsl::safe_umx KVM_GET_FPU{
        static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x8c, struct kvm_fpu))};
    /// @brief defines KVM's KVM_SET_FPU IOCTL
    constexpr bsl::safe_umx KVM_SET_FPU{
        static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x8d, struct kvm_fpu))};
    /// @brief defines KVM's KVM_CREATE_IRQCHIP IOCTL
    constexpr bsl::safe_umx KVM_CREATE_IRQCHIP{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x60))};
    // /// @brief defines KVM's KVM_IRQ_LINE IOCTL
    // constexpr bsl::safe_umx KVM_IRQ_LINE{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x61, struct kvm_irq_level))};
    // /// @brief defines KVM's KVM_GET_IRQCHIP IOCTL
    // constexpr bsl::safe_umx KVM_GET_IRQCHIP{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0x62, struct kvm_irqchip))};
    // /// @brief defines KVM's KVM_SET_IRQCHIP IOCTL
    // constexpr bsl::safe_umx KVM_SET_IRQCHIP{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x63, struct kvm_irqchip))};
    // /// @brief defines KVM's KVM_XEN_HVM_CONFIG IOCTL
    // constexpr bsl::safe_umx KVM_XEN_HVM_CONFIG{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x7a, struct kvm_xen_hvm_config))};
    // /// @brief defines KVM's KVM_GET_CLOCK IOCTL
    // constexpr bsl::safe_umx KVM_GET_CLOCK{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x7c, struct kvm_clock_data))};
    // /// @brief defines KVM's KVM_SET_CLOCK IOCTL
    // constexpr bsl::safe_umx KVM_SET_CLOCK{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x7b, struct kvm_clock_data))};
    // /// @brief defines KVM's KVM_GET_VCPU_EVENTS IOCTL
    // constexpr bsl::safe_umx KVM_GET_VCPU_EVENTS{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x9f, struct kvm_vcpu_events))};
    // /// @brief defines KVM's KVM_SET_VCPU_EVENTS IOCTL
    // constexpr bsl::safe_umx KVM_SET_VCPU_EVENTS{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xa0, struct kvm_vcpu_events))};
    // /// @brief defines KVM's KVM_GET_DEBUGREGS IOCTL
    // constexpr bsl::safe_umx KVM_GET_DEBUGREGS{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0xa1, struct kvm_debugregs))};
    // /// @brief defines KVM's KVM_SET_DEBUGREGS IOCTL
    // constexpr bsl::safe_umx KVM_SET_DEBUGREGS{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xa2, struct kvm_debugregs))};
    /// @brief defines KVM's KVM_SET_USER_MEMORY_REGION IOCTL
    constexpr bsl::safe_umx KVM_SET_USER_MEMORY_REGION{
        static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x46, struct kvm_userspace_memory_region))};
    /// @brief defines KVM's KVM_SET_TSS_ADDR IOCTL
    constexpr bsl::safe_umx KVM_SET_TSS_ADDR{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x47))};
    /// @brief defines KVM's KVM_ENABLE_CAP IOCTL
    // constexpr bsl::safe_umx KVM_ENABLE_CAP{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xa3, struct kvm_enable_cap))};
    /// @brief defines KVM's KVM_GET_MP_STATE IOCTL
    constexpr bsl::safe_umx KVM_GET_MP_STATE{
        static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x98, struct kvm_mp_state))};
    /// @brief defines KVM's KVM_SET_MP_STATE IOCTL
    constexpr bsl::safe_umx KVM_SET_MP_STATE{
        static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x99, struct kvm_mp_state))};
    /// @brief defines KVM's KVM_SET_IDENTITY_MAP_ADDR IOCTL
    constexpr bsl::safe_umx KVM_SET_IDENTITY_MAP_ADDR{
        static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x48, bsl::uint64))};
    /// @brief defines KVM's KVM_SET_BOOT_CPU_ID IOCTL
    constexpr bsl::safe_umx KVM_SET_BOOT_CPU_ID{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x78))};
    // /// @brief defines KVM's KVM_GET_XSAVE IOCTL
    // constexpr bsl::safe_umx KVM_GET_XSAVE{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0xa4, struct kvm_xsave))};
    // /// @brief defines KVM's KVM_SET_XSAVE IOCTL
    // constexpr bsl::safe_umx KVM_SET_XSAVE{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xa5, struct kvm_xsave))};
    // /// @brief defines KVM's KVM_GET_XCRS IOCTL
    // constexpr bsl::safe_umx KVM_GET_XCRS{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0xa6, struct kvm_xcrs))};
    // /// @brief defines KVM's KVM_SET_XCRS IOCTL
    // constexpr bsl::safe_umx KVM_SET_XCRS{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xa7, struct kvm_xcrs))};
    // /// @brief defines KVM's KVM_GET_SUPPORTED_CPUID IOCTL
    // constexpr bsl::safe_umx KVM_GET_SUPPORTED_CPUID{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0x05, struct kvm_cpuid2))};
    // /// @brief defines KVM's KVM_SET_GSI_ROUTING IOCTL
    // constexpr bsl::safe_umx KVM_SET_GSI_ROUTING{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x6a, struct kvm_irq_routing))};
    /// @brief defines KVM's KVM_GET_TSC_KHZ IOCTL
    constexpr bsl::safe_umx KVM_GET_TSC_KHZ{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0xa3))};
    /// @brief defines KVM's KVM_SET_TSC_KHZ IOCTL
    constexpr bsl::safe_umx KVM_SET_TSC_KHZ{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0xa2))};
    // /// @brief defines KVM's KVM_GET_LAPIC IOCTL
    // constexpr bsl::safe_umx KVM_GET_LAPIC{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x8e, struct kvm_lapic_state))};
    // /// @brief defines KVM's KVM_SET_LAPIC IOCTL
    // constexpr bsl::safe_umx KVM_SET_LAPIC{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x8f, struct kvm_lapic_state))};
    // /// @brief defines KVM's KVM_IOEVENTFD IOCTL
    // constexpr bsl::safe_umx KVM_IOEVENTFD{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x79, struct kvm_ioeventfd))};
    /// @brief defines KVM's KVM_NMI IOCTL
    constexpr bsl::safe_umx KVM_NMI{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x9a))};
    // /// @brief defines KVM's KVM_GET_ONE_REG IOCTL
    // constexpr bsl::safe_umx KVM_GET_ONE_REG{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xab, struct kvm_one_reg))};
    // /// @brief defines KVM's KVM_SET_ONE_REG IOCTL
    // constexpr bsl::safe_umx KVM_SET_ONE_REG{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xac, struct kvm_one_reg))};
    /// @brief defines KVM's KVM_KVMCLOCK_CTRL IOCTL
    constexpr bsl::safe_umx KVM_KVMCLOCK_CTRL{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0xad))};
    // /// @brief defines KVM's KVM_SIGNAL_MSI IOCTL
    // constexpr bsl::safe_umx KVM_SIGNAL_MSI{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xa5, struct kvm_msi))};
    // /// @brief defines KVM's KVM_CREATE_PIT2 IOCTL
    // constexpr bsl::safe_umx KVM_CREATE_PIT2{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x77, struct kvm_pit_config))};
    // /// @brief defines KVM's KVM_GET_PIT2 IOCTL
    // constexpr bsl::safe_umx KVM_GET_PIT2{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x9f, struct kvm_pit_state2))};
    // /// @brief defines KVM's KVM_SET_PIT2 IOCTL
    // constexpr bsl::safe_umx KVM_SET_PIT2{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xa0, struct kvm_pit_state2))};
    // /// @brief defines KVM's KVM_IRQFD IOCTL
    // constexpr bsl::safe_umx KVM_IRQFD{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x76, struct kvm_irqfd))};
    // /// @brief defines KVM's KVM_CREATE_DEVICE IOCTL
    // constexpr bsl::safe_umx KVM_CREATE_DEVICE{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0xe0, struct kvm_create_device))};
    // /// @brief defines KVM's KVM_GET_DEVICE_ATTR IOCTL
    // constexpr bsl::safe_umx KVM_GET_DEVICE_ATTR{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xe2, struct kvm_device_attr))};
    // /// @brief defines KVM's KVM_SET_DEVICE_ATTR IOCTL
    // constexpr bsl::safe_umx KVM_SET_DEVICE_ATTR{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xe1, struct kvm_device_attr))};
    // /// @brief defines KVM's KVM_HAS_DEVICE_ATTR IOCTL
    // constexpr bsl::safe_umx KVM_HAS_DEVICE_ATTR{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xe3, struct kvm_device_attr))};
    // /// @brief defines KVM's KVM_SET_GUEST_DEBUG IOCTL
    // constexpr bsl::safe_umx KVM_SET_GUEST_DEBUG{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x9b, struct kvm_guest_debug))};
    // /// @brief defines KVM's KVM_GET_EMULATED_CPUID IOCTL
    // constexpr bsl::safe_umx KVM_GET_EMULATED_CPUID{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0x09, struct kvm_cpuid2))};
    /// @brief defines KVM's KVM_SMI IOCTL
    constexpr bsl::safe_umx KVM_SMI{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0xb7))};
    /// @brief defines KVM's KVM_REINJECT_CONTROL IOCTL
    constexpr bsl::safe_umx KVM_REINJECT_CONTROL{static_cast<bsl::uintmx>(_IO(SHIMIO.get(), 0x71))};
    /// @brief defines KVM's KVM_X86_GET_MCE_CAP_SUPPORTED IOCTL
    constexpr bsl::safe_umx KVM_X86_GET_MCE_CAP_SUPPORTED{
        static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0x9d, bsl::uint64))};
    /// @brief defines KVM's KVM_X86_SETUP_MCE IOCTL
    constexpr bsl::safe_umx KVM_X86_SETUP_MCE{
        static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x9c, bsl::uint64))};
    // /// @brief defines KVM's KVM_X86_SET_MCE IOCTL
    // constexpr bsl::safe_umx KVM_X86_SET_MCE{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x9e, struct kvm_x86_mce))};
    /// @brief defines KVM's KVM_MEMORY_ENCRYPT_OP IOCTL
    constexpr bsl::safe_umx KVM_MEMORY_ENCRYPT_OP{
        static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0xba, unsigned long))};
    // /// @brief defines KVM's KVM_MEMORY_ENCRYPT_REG_REGION IOCTL
    // constexpr bsl::safe_umx KVM_MEMORY_ENCRYPT_REG_REGION{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0xbb, struct kvm_enc_region))};
    // /// @brief defines KVM's KVM_MEMORY_ENCRYPT_UNREG_REGION IOCTL
    // constexpr bsl::safe_umx KVM_MEMORY_ENCRYPT_UNREG_REGION{static_cast<bsl::uintmx>(_IOR(SHIMIO.get(), 0xbc, struct kvm_enc_region))};
    // /// @brief defines KVM's KVM_HYPERV_EVENTFD IOCTL
    // constexpr bsl::safe_umx KVM_HYPERV_EVENTFD{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xbd, struct kvm_hyperv_eventfd))};
    // /// @brief defines KVM's KVM_GET_NESTED_STATE IOCTL
    // constexpr bsl::safe_umx KVM_GET_NESTED_STATE{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0xbe, struct kvm_nested_state))};
    // /// @brief defines KVM's KVM_SET_NESTED_STATE IOCTL
    // constexpr bsl::safe_umx KVM_SET_NESTED_STATE{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xbf, struct kvm_nested_state))};
    // /// @brief defines KVM's KVM_REGISTER_COALESCED_MMIO IOCTL
    // constexpr bsl::safe_umx KVM_REGISTER_COALESCED_MMIO{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x67, struct kvm_coalesced_mmio_zone))};
    // /// @brief defines KVM's KVM_UNREGISTER_COALESCED_MMIO IOCTL
    // constexpr bsl::safe_umx KVM_UNREGISTER_COALESCED_MMIO{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0x68, struct kvm_coalesced_mmio_zone))};
    // /// @brief defines KVM's KVM_CLEAR_DIRTY_LOG IOCTL
    // constexpr bsl::safe_umx KVM_CLEAR_DIRTY_LOG{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0xc0, struct kvm_clear_dirty_log))};
    // /// @brief defines KVM's KVM_GET_SUPPORTED_HV_CPUID IOCTL
    // constexpr bsl::safe_umx KVM_GET_SUPPORTED_HV_CPUID{static_cast<bsl::uintmx>(_IOWR(SHIMIO.get(), 0xc1, struct kvm_cpuid2))};
    // /// @brief defines KVM's KVM_SET_PMU_EVENT_FILTER IOCTL
    // constexpr bsl::safe_umx KVM_SET_PMU_EVENT_FILTER{static_cast<bsl::uintmx>(_IOW(SHIMIO.get(), 0xb2, struct kvm_pmu_event_filter))};
}

#endif
