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

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/config/default.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/function/microv_target_source.cmake)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/write_constants.cmake)

# ------------------------------------------------------------------------------
# Executable
# ------------------------------------------------------------------------------

add_executable(extension_bin)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(extension_bin PRIVATE
            include/x64/amd
            src/x64/amd
            ../hypercall/include/x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(extension_bin PRIVATE
            include/x64/intel
            src/x64/intel
            ../hypercall/include/x64/intel
        )
    endif()

    target_include_directories(extension_bin PRIVATE
        include/x64
        src/x64
        ../hypercall/include/x64
    )
endif()

target_include_directories(extension_bin PRIVATE
    include
    src
    ../hypercall/include
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/gs_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/l0e_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/l1e_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/l2e_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/l3e_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/dispatch_vmexit_cr.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/dispatch_vmexit.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/dispatch_vmexit_io.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/dispatch_vmexit_mmio.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/gs_initialize.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/pp_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/second_level_page_table_helpers.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/amd/vs_t.hpp
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/gs_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/l0e_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/l1e_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/l2e_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/l3e_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/arch_helpers.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/dispatch_vmexit_cr.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/dispatch_vmexit.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/dispatch_vmexit_io.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/dispatch_vmexit_mmio.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/dispatch_vmexit_nmi_window.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/gs_initialize.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/pp_t.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/second_level_page_table_helpers.hpp
            ${CMAKE_CURRENT_LIST_DIR}/src/x64/intel/vs_t.hpp
        )
    endif()

    list(APPEND HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/cr_access_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/pdpte_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/pdte_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/pml4te_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/include/x64/pte_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_abi_helpers.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_cpuid.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_dr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_hlt.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_init.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_intr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_intr_window.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_mmio.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_nmi.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_rdmsr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_sipi.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_triple_fault.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/dispatch_vmexit_wrmsr.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_cpuid_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_decoder_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_dr_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_ioapic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_io_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_lapic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_mmio_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_msr_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_pic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_pit_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/emulated_tlb_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/get_tsc_freq.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_cpuid_impl.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_cpuid_impl.S
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_xrstr_impl.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_xrstr_impl.S
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_xsave_impl.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/intrinsic_xsave_impl.S
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pause.S
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pp_cpuid_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pp_lapic_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pp_mmio_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pp_msr_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pp_mtrrs_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/pp_reg_t.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/x64/vm_t.hpp
    )
endif()

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include/allocated_status_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/errc_types.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/map_page_flags.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/page_1g_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/page_2m_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/page_4k_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/pause.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/queue.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/running_status_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/tls_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/alloc_bitmap.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_bootstrap.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_fail.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmcall_helpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmcall_mv_debug_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmcall_mv_handle_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmcall_mv_id_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmcall_mv_pp_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmcall_mv_vm_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmcall_mv_vp_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmcall_mv_vs_op.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmexit_unknown.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dispatch_vmexit_vmcall.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/lock_guard_helpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/lock_guard_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/page_pool_helpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/page_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/pp_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/pp_unique_map_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/pp_unique_shared_page_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/second_level_page_table_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/spinlock_helpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/spinlock_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/tls_initialize.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vm_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_pool_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vp_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/vs_pool_t.hpp
)

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    microv_target_source(extension_bin src/x64/intrinsic_cpuid_impl.S ${HEADERS})
    microv_target_source(extension_bin src/x64/intrinsic_xrstr_impl.S ${HEADERS})
    microv_target_source(extension_bin src/x64/intrinsic_xsave_impl.S ${HEADERS})
    microv_target_source(extension_bin src/x64/pause.S ${HEADERS})
endif()

microv_target_source(extension_bin src/main.cpp ${HEADERS})

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

target_compile_definitions(hypervisor INTERFACE
    MICROV_MAX_PP_MAPS=${MICROV_MAX_PP_MAPS}_umx
    MICROV_MAX_VMS=${MICROV_MAX_VMS}_umx
    MICROV_MAX_VCPUS=${MICROV_MAX_VCPUS}_umx
    MICROV_MAX_GPA_SIZE=${MICROV_MAX_GPA_SIZE}_umx
    MICROV_MAX_SLOTS=${MICROV_MAX_SLOTS}_umx
    MICROV_INTERRUPT_QUEUE_SIZE=${MICROV_INTERRUPT_QUEUE_SIZE}_umx
)

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(extension_bin PRIVATE
    runtime
    bsl
    loader
    syscall
    lib
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
    add_custom_command(TARGET extension_bin POST_BUILD COMMAND ${CMAKE_STRIP} extension_bin)
endif()

install(TARGETS extension_bin DESTINATION bin)
