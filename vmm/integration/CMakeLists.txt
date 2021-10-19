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

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/function/microv_add_integration.cmake)

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/support/integration_utils.hpp
)

microv_add_vmm_integration(mv_debug_op_out HEADERS)
microv_add_vmm_integration(mv_emulate_interrupts HEADERS)
microv_add_vmm_integration(mv_emulate_io HEADERS)
#microv_add_vmm_integration(mv_emulate_nmi HEADERS)
microv_add_vmm_integration(mv_handle_op_close_handle HEADERS)
microv_add_vmm_integration(mv_handle_op_open_handle HEADERS)
microv_add_vmm_integration(mv_hypercall_t HEADERS)
microv_add_vmm_integration(mv_pp_op_clr_shared_page_gpa HEADERS)
microv_add_vmm_integration(mv_pp_op_ppid HEADERS)
microv_add_vmm_integration(mv_pp_op_set_shared_page_gpa HEADERS)
microv_add_vmm_integration(mv_pp_op_cpuid_get_supported_list HEADERS)
microv_add_vmm_integration(mv_pp_op_msr_get_supported_list HEADERS)
microv_add_vmm_integration(mv_pp_op_tsc_get_khz HEADERS)
microv_add_vmm_integration(mv_pp_op_tsc_set_khz HEADERS)
microv_add_vmm_integration(mv_vm_op_create_vm HEADERS)
microv_add_vmm_integration(mv_vm_op_destroy_vm HEADERS)
microv_add_vmm_integration(mv_vm_op_mmio_map HEADERS)
microv_add_vmm_integration(mv_vm_op_mmio_unmap HEADERS)
microv_add_vmm_integration(mv_vm_op_vmid HEADERS)
microv_add_vmm_integration(mv_vp_op_create_vp HEADERS)
microv_add_vmm_integration(mv_vp_op_destroy_vp HEADERS)
microv_add_vmm_integration(mv_vp_op_vmid HEADERS)
microv_add_vmm_integration(mv_vp_op_vpid HEADERS)
microv_add_vmm_integration(mv_vs_op_create_vs HEADERS)
microv_add_vmm_integration(mv_vs_op_destroy_vs HEADERS)
microv_add_vmm_integration(mv_vs_op_fpu_get_all HEADERS)
microv_add_vmm_integration(mv_vs_op_fpu_set_all HEADERS)
microv_add_vmm_integration(mv_vs_op_gla_to_gpa HEADERS)
microv_add_vmm_integration(mv_vs_op_mp_state_get HEADERS)
microv_add_vmm_integration(mv_vs_op_mp_state_set HEADERS)
microv_add_vmm_integration(mv_vs_op_msr_get_list HEADERS)
microv_add_vmm_integration(mv_vs_op_msr_get HEADERS)
microv_add_vmm_integration(mv_vs_op_msr_set_list HEADERS)
microv_add_vmm_integration(mv_vs_op_msr_set HEADERS)
microv_add_vmm_integration(mv_vs_op_reg_get_list HEADERS)
microv_add_vmm_integration(mv_vs_op_reg_get HEADERS)
microv_add_vmm_integration(mv_vs_op_reg_set_list HEADERS)
microv_add_vmm_integration(mv_vs_op_reg_set HEADERS)
microv_add_vmm_integration(mv_vs_op_run_32bit_io_test HEADERS)
microv_add_vmm_integration(mv_vs_op_run HEADERS)
microv_add_vmm_integration(mv_vs_op_tsc_get_khz HEADERS)
microv_add_vmm_integration(mv_vs_op_vmid HEADERS)
microv_add_vmm_integration(mv_vs_op_vpid HEADERS)
microv_add_vmm_integration(mv_vs_op_vsid HEADERS)
