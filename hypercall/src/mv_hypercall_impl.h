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

#ifndef MV_HYPERCALL_IMPL_H
#define MV_HYPERCALL_IMPL_H

#include <mv_exit_reason_t.h>
#include <mv_reg_t.h>
#include <mv_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ---------------------------------------------------------------------- */
    /* mv_id_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_id_op_version.
     *
     * <!-- inputs/outputs -->
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_id_op_version_impl(uint32_t *const pmut_reg0_out) NOEXCEPT;

    /* ---------------------------------------------------------------------- */
    /* mv_handle_ops                                                          */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_handle_op_open_handle.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_handle_op_open_handle_impl(uint32_t const reg0_in, uint64_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_handle_op_close_handle.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_handle_op_close_handle_impl(uint64_t const reg0_in) NOEXCEPT;

    /* ---------------------------------------------------------------------- */
    /* mv_debug_ops                                                           */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_debug_op_out.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     */
    void mv_debug_op_out_impl(uint64_t const reg0_in, uint64_t const reg1_in) NOEXCEPT;

    /* ---------------------------------------------------------------------- */
    /* mv_pp_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_pp_op_ppid.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_pp_op_ppid_impl(uint64_t const reg0_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_pp_op_clr_shared_page_gpa.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_pp_op_clr_shared_page_gpa_impl(uint64_t const reg0_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_pp_op_set_shared_page_gpa.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_pp_op_set_shared_page_gpa_impl(uint64_t const reg0_in, uint64_t const reg1_in) NOEXCEPT;

    /* ---------------------------------------------------------------------- */
    /* mv_vm_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vm_op_create_vm.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vm_op_create_vm_impl(uint64_t const reg0_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vm_op_destroy_vm.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vm_op_destroy_vm_impl(uint64_t const reg0_in, uint16_t const reg1_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vm_op_vmid.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vm_op_vmid_impl(uint64_t const reg0_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vm_op_mmio_map.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param reg2_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vm_op_mmio_map_impl(
        uint64_t const reg0_in, uint16_t const reg1_in, uint16_t const reg2_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vm_op_mmio_unmap.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vm_op_mmio_unmap_impl(uint64_t const reg0_in, uint16_t const reg1_in) NOEXCEPT;

    /* ---------------------------------------------------------------------- */
    /* mv_vp_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vp_op_create_vp.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vp_op_create_vp_impl(
        uint64_t const reg0_in, uint16_t const reg1_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vp_op_destroy_vp.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vp_op_destroy_vp_impl(uint64_t const reg0_in, uint16_t const reg1_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vp_op_vmid.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vp_op_vmid_impl(
        uint64_t const reg0_in, uint16_t const reg1_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vp_op_vpid.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vp_op_vpid_impl(uint64_t const reg0_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /* ---------------------------------------------------------------------- */
    /* mv_vs_ops                                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_create_vs.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_create_vs_impl(
        uint64_t const reg0_in, uint16_t const reg1_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_destroy_vs.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vs_op_destroy_vs_impl(uint64_t const reg0_in, uint16_t const reg1_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_vmid.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_vmid_impl(
        uint64_t const reg0_in, uint16_t const reg1_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_vpid.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_vpid_impl(
        uint64_t const reg0_in, uint16_t const reg1_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_vsid.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vs_op_vsid_impl(uint64_t const reg0_in, uint16_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_gla_to_gpa.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param reg2_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_gla_to_gpa_impl(
        uint64_t const reg0_in,
        uint16_t const reg1_in,
        uint64_t const reg2_in,
        uint64_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_run.
     *
     * <!-- inputs/outputs -->s
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_run_impl(
        uint64_t const reg0_in,
        uint16_t const reg1_in,
        enum mv_exit_reason_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_reg_get.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param reg2_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_reg_get_impl(
        uint64_t const reg0_in,
        uint16_t const reg1_in,
        enum mv_reg_t const reg2_in,
        uint64_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_reg_set.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param reg2_in n/a
     *   @param reg3_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_reg_set_impl(
        uint64_t const reg0_in,
        uint16_t const reg1_in,
        enum mv_reg_t const reg2_in,
        uint64_t const reg3_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_reg_get_list.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vs_op_reg_get_list_impl(uint64_t const reg0_in, uint16_t const reg1_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_reg_set_list.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vs_op_reg_set_list_impl(uint64_t const reg0_in, uint16_t const reg1_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_msr_get.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param reg2_in n/a
     *   @param pmut_reg0_out n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_msr_get_impl(
        uint64_t const reg0_in,
        uint16_t const reg1_in,
        uint32_t const reg2_in,
        uint64_t *const pmut_reg0_out) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_msr_set.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @param reg2_in n/a
     *   @param reg3_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t mv_vs_op_msr_set_impl(
        uint64_t const reg0_in,
        uint16_t const reg1_in,
        uint32_t const reg2_in,
        uint64_t const reg3_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_msr_get_list.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vs_op_msr_get_list_impl(uint64_t const reg0_in, uint16_t const reg1_in) NOEXCEPT;

    /**
     * <!-- description -->
     *   @brief Implements the ABI for mv_vs_op_msr_set_list.
     *
     * <!-- inputs/outputs -->
     *   @param reg0_in n/a
     *   @param reg1_in n/a
     *   @return n/a
     */
    NODISCARD mv_status_t
    mv_vs_op_msr_set_list_impl(uint64_t const reg0_in, uint16_t const reg1_in) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif
