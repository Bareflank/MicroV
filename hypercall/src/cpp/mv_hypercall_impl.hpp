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

#ifndef MV_HYPERCALL_IMPL_HPP
#define MV_HYPERCALL_IMPL_HPP

#include <mv_reg_t.hpp>
#include <mv_types.hpp>

#include <bsl/char_type.hpp>
#include <bsl/cstr_type.hpp>

namespace hypercall
{
    // -------------------------------------------------------------------------
    // mv_id_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for mv_id_op_version.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    mv_id_op_version_impl(bsl::safe_uint32::value_type *const pmut_reg0_out) noexcept
        -> mv_status_t::value_type;

    // -------------------------------------------------------------------------
    // mv_handle_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for mv_handle_op_open_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto mv_handle_op_open_handle_impl(
        bsl::safe_uint32::value_type const reg0_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> mv_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for mv_handle_op_close_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    mv_handle_op_close_handle_impl(bsl::safe_uint64::value_type const reg0_in) noexcept
        -> mv_status_t::value_type;

    // -------------------------------------------------------------------------
    // mv_debug_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for mv_debug_op_out.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    extern "C" void mv_debug_op_out_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in) noexcept;

    // -------------------------------------------------------------------------
    // mv_vps_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for mv_vps_op_gva_to_gla.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param pmut_reg0_out n/a
    ///
    extern "C" [[nodiscard]] auto mv_vps_op_gva_to_gla_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint32::value_type const reg1_in,
        bsl::safe_uint64::value_type const reg2_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> mv_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for mv_vps_op_gla_to_gpa.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param pmut_reg0_out n/a
    ///
    extern "C" [[nodiscard]] auto mv_vps_op_gla_to_gpa_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint64::value_type const reg2_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> mv_status_t::value_type;
}

#endif
