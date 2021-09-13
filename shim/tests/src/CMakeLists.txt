#
# Copyright (C) 2020 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set(CURRENT_FUNCTION_LIST_DIR ${CMAKE_CURRENT_LIST_DIR})

# ------------------------------------------------------------------------------
# Sources Needed By All Tests
# ------------------------------------------------------------------------------

add_library(shim_tests_common)

target_include_directories(shim_tests_common PRIVATE
    ${COMMON_INCLUDES}
)

target_include_directories(shim_tests_common PRIVATE SYSTEM
    ${COMMON_SYSTEM_INCLUDES}
)

target_sources(shim_tests_common PRIVATE
    ${CURRENT_FUNCTION_LIST_DIR}/platform.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_hndl.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/g_mut_shared_pages.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/shared_page_for_current_pp.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/shim_fini.c
    ${CURRENT_FUNCTION_LIST_DIR}/../../src/shim_init.c
)

target_compile_definitions(shim_tests_common PRIVATE
    ${COMMON_DEFINES}
)

# ------------------------------------------------------------------------------
# Macros For This Directory
# ------------------------------------------------------------------------------

macro(mv_add_test NAME SOURCES)
    bf_add_test(
        test_${NAME}
        SOURCES ${SOURCES}
        INCLUDES ${COMMON_INCLUDES}
        SYSTEM_INCLUDES ${COMMON_SYSTEM_INCLUDES}
        DEFINES ${COMMON_DEFINES}
        LIBRARIES shim_tests_common
    )
endmacro(mv_add_test)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

mv_add_test(handle_device_kvm_get_device_attr ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_device_kvm_get_device_attr.c)
mv_add_test(handle_device_kvm_has_device_attr ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_device_kvm_has_device_attr.c)
mv_add_test(handle_device_kvm_set_device_attr ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_device_kvm_set_device_attr.c)
mv_add_test(handle_system_kvm_check_extension ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_check_extension.c)
mv_add_test(handle_system_kvm_create_vm ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_create_vm.c)
mv_add_test(handle_system_kvm_destroy_vm ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_destroy_vm.c)
mv_add_test(handle_system_kvm_get_api_version ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_get_api_version.c)
mv_add_test(handle_system_kvm_get_emulated_cpuid ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_get_emulated_cpuid.c)
mv_add_test(handle_system_kvm_get_msr_feature_index_list ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_get_msr_feature_index_list.c)
mv_add_test(handle_system_kvm_get_msr_index_list ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_get_msr_index_list.c)
mv_add_test(handle_system_kvm_get_msrs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_get_msrs.c)
mv_add_test(handle_system_kvm_get_supported_cpuid ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_get_supported_cpuid.c)
mv_add_test(handle_system_kvm_get_vcpu_mmap_size ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_get_vcpu_mmap_size.c)
mv_add_test(handle_system_kvm_memory_encrypt_op ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_memory_encrypt_op.c)
mv_add_test(handle_system_kvm_memory_encrypt_reg_region ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_memory_encrypt_reg_region.c)
mv_add_test(handle_system_kvm_memory_encrypt_unreg_region ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_memory_encrypt_unreg_region.c)
mv_add_test(handle_system_kvm_x86_get_mce_cap_supported ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_system_kvm_x86_get_mce_cap_supported.c)
mv_add_test(handle_vcpu_kvm_enable_cap ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_enable_cap.c)
mv_add_test(handle_vcpu_kvm_get_cpuid2 ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_cpuid2.c)
mv_add_test(handle_vcpu_kvm_get_fpu ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_fpu.c)
mv_add_test(handle_vcpu_kvm_get_lapic ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_lapic.c)
mv_add_test(handle_vcpu_kvm_get_mp_state ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_mp_state.c)
mv_add_test(handle_vcpu_kvm_get_msrs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_msrs.c)
mv_add_test(handle_vcpu_kvm_get_nested_state ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_nested_state.c)
mv_add_test(handle_vcpu_kvm_get_one_reg ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_one_reg.c)
mv_add_test(handle_vcpu_kvm_get_regs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_regs.c)
mv_add_test(handle_vcpu_kvm_get_sregs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_sregs.c)
mv_add_test(handle_vcpu_kvm_get_supported_hv_cpuid ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_supported_hv_cpuid.c)
mv_add_test(handle_vcpu_kvm_get_tsc_khz ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_tsc_khz.c)
mv_add_test(handle_vcpu_kvm_get_vcpu_events ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_vcpu_events.c)
mv_add_test(handle_vcpu_kvm_get_xcrs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_xcrs.c)
mv_add_test(handle_vcpu_kvm_get_xsave ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_get_xsave.c)
mv_add_test(handle_vcpu_kvm_interrupt ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_interrupt.c)
mv_add_test(handle_vcpu_kvm_kvmclock_ctrl ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_kvmclock_ctrl.c)
mv_add_test(handle_vcpu_kvm_nmi ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_nmi.c)
mv_add_test(handle_vcpu_kvm_run ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_run.c)
mv_add_test(handle_vcpu_kvm_set_cpuid2 ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_cpuid2.c)
mv_add_test(handle_vcpu_kvm_set_cpuid ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_cpuid.c)
mv_add_test(handle_vcpu_kvm_set_fpu ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_fpu.c)
mv_add_test(handle_vcpu_kvm_set_guest_debug ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_guest_debug.c)
mv_add_test(handle_vcpu_kvm_set_lapic ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_lapic.c)
mv_add_test(handle_vcpu_kvm_set_mp_state ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_mp_state.c)
mv_add_test(handle_vcpu_kvm_set_msrs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_msrs.c)
mv_add_test(handle_vcpu_kvm_set_nested_state ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_nested_state.c)
mv_add_test(handle_vcpu_kvm_set_one_reg ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_one_reg.c)
mv_add_test(handle_vcpu_kvm_set_regs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_regs.c)
mv_add_test(handle_vcpu_kvm_set_signal_mask ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_signal_mask.c)
mv_add_test(handle_vcpu_kvm_set_sregs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_sregs.c)
mv_add_test(handle_vcpu_kvm_set_tsc_khz ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_tsc_khz.c)
mv_add_test(handle_vcpu_kvm_set_vcpu_events ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_vcpu_events.c)
mv_add_test(handle_vcpu_kvm_set_xcrs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_xcrs.c)
mv_add_test(handle_vcpu_kvm_set_xsave ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_set_xsave.c)
mv_add_test(handle_vcpu_kvm_smi ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_smi.c)
mv_add_test(handle_vcpu_kvm_translate ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_translate.c)
mv_add_test(handle_vcpu_kvm_x86_set_mce ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_x86_set_mce.c)
mv_add_test(handle_vcpu_kvm_x86_setup_mce ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vcpu_kvm_x86_setup_mce.c)
mv_add_test(handle_vm_kvm_check_extension ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_check_extension.c)
mv_add_test(handle_vm_kvm_clear_dirty_log ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_clear_dirty_log.c)
mv_add_test(handle_vm_kvm_create_device ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_create_device.c)
mv_add_test(handle_vm_kvm_create_irqchip ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_create_irqchip.c)
mv_add_test(handle_vm_kvm_create_pit2 ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_create_pit2.c)
mv_add_test(handle_vm_kvm_create_vcpu ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_create_vcpu.c)
mv_add_test(handle_vm_kvm_destroy_vcpu ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_destroy_vcpu.c)
mv_add_test(handle_vm_kvm_get_clock ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_get_clock.c)
mv_add_test(handle_vm_kvm_get_debugregs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_get_debugregs.c)
mv_add_test(handle_vm_kvm_get_device_attr ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_get_device_attr.c)
mv_add_test(handle_vm_kvm_get_dirty_log ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_get_dirty_log.c)
mv_add_test(handle_vm_kvm_get_irqchip ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_get_irqchip.c)
mv_add_test(handle_vm_kvm_get_pit2 ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_get_pit2.c)
mv_add_test(handle_vm_kvm_has_device_attr ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_has_device_attr.c)
mv_add_test(handle_vm_kvm_hyperv_eventfd ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_hyperv_eventfd.c)
mv_add_test(handle_vm_kvm_ioeventfd ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_ioeventfd.c)
mv_add_test(handle_vm_kvm_irqfd ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_irqfd.c)
mv_add_test(handle_vm_kvm_irq_line ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_irq_line.c)
mv_add_test(handle_vm_kvm_register_coalesced_mmio ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_register_coalesced_mmio.c)
mv_add_test(handle_vm_kvm_reinject_control ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_reinject_control.c)
mv_add_test(handle_vm_kvm_set_boot_cpu_id ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_boot_cpu_id.c)
mv_add_test(handle_vm_kvm_set_clock ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_clock.c)
mv_add_test(handle_vm_kvm_set_debugregs ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_debugregs.c)
mv_add_test(handle_vm_kvm_set_device_attr ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_device_attr.c)
mv_add_test(handle_vm_kvm_set_gsi_routing ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_gsi_routing.c)
mv_add_test(handle_vm_kvm_set_identity_map_addr ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_identity_map_addr.c)
mv_add_test(handle_vm_kvm_set_irqchip ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_irqchip.c)
mv_add_test(handle_vm_kvm_set_pit2 ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_pit2.c)
mv_add_test(handle_vm_kvm_set_pmu_event_filter ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_pmu_event_filter.c)
mv_add_test(handle_vm_kvm_set_tss_addr ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_tss_addr.c)
mv_add_test(handle_vm_kvm_set_user_memory_region ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_set_user_memory_region.c)
mv_add_test(handle_vm_kvm_signal_msi ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_signal_msi.c)
mv_add_test(handle_vm_kvm_unregister_coalesced_mmio ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_unregister_coalesced_mmio.c)
mv_add_test(handle_vm_kvm_xen_hvm_config ${CMAKE_CURRENT_LIST_DIR}/../../src/handle_vm_kvm_xen_hvm_config.c)
mv_add_test(platform ${CMAKE_CURRENT_LIST_DIR}/platform.c)
mv_add_test(serial_write ${CMAKE_CURRENT_LIST_DIR}/../../src/serial_write.c)
mv_add_test(shared_page_for_current_pp ${CMAKE_CURRENT_LIST_DIR}/../../src/shared_page_for_current_pp.c)
mv_add_test(shim_fini ${CMAKE_CURRENT_LIST_DIR}/../../src/shim_fini.c)
mv_add_test(shim_init ${CMAKE_CURRENT_LIST_DIR}/../../src/shim_init.c)

add_subdirectory(x64)
