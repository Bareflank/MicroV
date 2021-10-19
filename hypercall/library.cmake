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

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/function/microv_target_source.cmake)

add_library(hypercall)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(hypercall PUBLIC
            include/x64/amd
            src/x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(hypercall PUBLIC
            include/x64/intel
            src/x64/intel
        )
    endif()

    target_include_directories(hypercall PUBLIC
        include/x64
        src/x64
    )
endif()

target_include_directories(hypercall PUBLIC
    include
    src
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/mv_reg_t.h
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/mv_reg_t.hpp
    )
endif()

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_bit_size_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_bit_size_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_cdl_entry_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_cdl_entry_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_cdl_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_cdl_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_constants.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_constants.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_cpuid_flag_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_cpuid_flag_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_exit_io_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_exit_io_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_exit_mmio_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_exit_mmio_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_exit_msr_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_exit_msr_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_exit_reason_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_exit_reason_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_mdl_entry_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_mdl_entry_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_mdl_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_mdl_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_mp_state_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_mp_state_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_rdl_entry_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_rdl_entry_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_rdl_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_rdl_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_run_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_run_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_translation_t.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_translation_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_types.h
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_types.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_debug_ops.h
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_debug_ops.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_hypercall.h
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_hypercall_impl.h
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_hypercall_impl.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_hypercall_t.hpp
)

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        if(WIN32)
            microv_target_source(hypercall src/windows/x64/amd/mv_debug_op_out_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_handle_op_close_handle_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_handle_op_open_handle_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_id_op_version_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_pp_op_cpuid_get_supported_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_pp_op_ppid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_pp_op_set_shared_page_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_pp_op_msr_get_supported_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_pp_op_tsc_get_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_pp_op_tsc_set_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vm_op_create_vm_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vm_op_destroy_vm_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vm_op_mmio_map_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vm_op_mmio_unmap_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vm_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vp_op_create_vp_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vp_op_destroy_vp_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vp_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vp_op_vpid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_create_vs_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_destroy_vs_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_fpu_get_all_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_fpu_set_all_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_gla_to_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_mp_state_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_mp_state_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_msr_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_msr_get_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_msr_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_msr_set_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_reg_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_reg_get_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_reg_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_reg_set_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_run_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_tsc_get_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_tsc_set_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_vpid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_vs_op_vsid_impl.S ${HEADERS})
        else()
            microv_target_source(hypercall src/linux/x64/amd/mv_debug_op_out_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_handle_op_close_handle_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_handle_op_open_handle_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_id_op_version_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_pp_op_cpuid_get_supported_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_pp_op_ppid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_pp_op_set_shared_page_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_pp_op_msr_get_supported_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_pp_op_tsc_get_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_pp_op_tsc_set_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vm_op_create_vm_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vm_op_destroy_vm_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vm_op_mmio_map_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vm_op_mmio_unmap_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vm_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vp_op_create_vp_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vp_op_destroy_vp_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vp_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vp_op_vpid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_create_vs_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_destroy_vs_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_fpu_get_all_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_fpu_set_all_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_gla_to_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_mp_state_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_mp_state_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_msr_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_msr_get_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_msr_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_msr_set_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_reg_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_reg_get_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_reg_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_reg_set_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_run_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_tsc_get_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_tsc_set_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_vpid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_vsid_impl.S ${HEADERS})
        endif()
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        if(WIN32)
            microv_target_source(hypercall src/windows/x64/intel/mv_debug_op_out_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_handle_op_close_handle_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_handle_op_open_handle_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_id_op_version_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_pp_op_clr_shared_page_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/amd/mv_pp_op_cpuid_get_supported_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_pp_op_ppid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_pp_op_set_shared_page_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_pp_op_msr_get_supported_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_pp_op_tsc_get_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_pp_op_tsc_set_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vm_op_create_vm_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vm_op_destroy_vm_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vm_op_mmio_map_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vm_op_mmio_unmap_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vm_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vp_op_create_vp_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vp_op_destroy_vp_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vp_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vp_op_vpid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_create_vs_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_destroy_vs_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_fpu_get_all_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_fpu_set_all_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_gla_to_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_mp_state_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_mp_state_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_msr_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_msr_get_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_msr_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_msr_set_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_reg_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_reg_get_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_reg_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_reg_set_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_run_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_tsc_get_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_tsc_set_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_vpid_impl.S ${HEADERS})
            microv_target_source(hypercall src/windows/x64/intel/mv_vs_op_vsid_impl.S ${HEADERS})
        else()
            microv_target_source(hypercall src/linux/x64/intel/mv_debug_op_out_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_handle_op_close_handle_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_handle_op_open_handle_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_id_op_version_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_pp_op_clr_shared_page_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_pp_op_cpuid_get_supported_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_pp_op_ppid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_pp_op_set_shared_page_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_pp_op_msr_get_supported_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_pp_op_tsc_get_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_pp_op_tsc_set_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vm_op_create_vm_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vm_op_destroy_vm_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vm_op_mmio_map_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vm_op_mmio_unmap_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vm_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vp_op_create_vp_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vp_op_destroy_vp_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vp_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vp_op_vpid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_create_vs_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_destroy_vs_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_fpu_get_all_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_fpu_set_all_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_gla_to_gpa_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_mp_state_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_mp_state_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_msr_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_msr_get_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_msr_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_msr_set_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_reg_get_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_reg_get_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_reg_set_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_reg_set_list_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_run_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_tsc_get_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_tsc_set_khz_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_vmid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_vpid_impl.S ${HEADERS})
            microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_vsid_impl.S ${HEADERS})
        endif()
    endif()
endif()

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(hypercall PUBLIC
    bsl
    hypervisor
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS hypercall DESTINATION lib)
