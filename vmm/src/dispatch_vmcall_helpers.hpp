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

#ifndef DISPATCH_VMCALL_HELPERS_HPP
#define DISPATCH_VMCALL_HELPERS_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_vmcall_abi_helpers.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// ------------------------------------------------------------------------
    /// Validation Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns true if the provided version is supported.
    ///     Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register containing the version to verify
    ///   @return Returns true if the provided version is supported.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    is_version_supported(bsl::safe_u64 const &reg) noexcept -> bool
    {
        auto const version{bsl::to_u32(reg)};
        if (bsl::unlikely(version != hypercall::MV_SPEC_ID1_VAL)) {
            bsl::error() << "unsupported hypercall ABI "    //--
                         << bsl::hex(version)               //--
                         << bsl::endl                       //--
                         << bsl::here();                    //--

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the handle provided in tls.reg0 is valid.
    ///     Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @return Returns true if the handle provided in tls.reg0 is valid.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    verify_handle(syscall::bf_syscall_t const &sys) noexcept -> bool
    {
        if (bsl::unlikely(get_reg0(sys) != hypercall::MV_HANDLE_VAL)) {
            bsl::error() << "invalid handle "          // --
                         << bsl::hex(get_reg0(sys))    // --
                         << bsl::endl                  // --
                         << bsl::here();               // --

            return false;
        }

        return true;
    }

    /// ------------------------------------------------------------------------
    /// Report Unsupported Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Tells the user that the hypercall is unknown or is not
    ///     supported by MicroV.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @return Always returns vmexit_failure_advance_ip_and_run.
    ///
    [[nodiscard]] constexpr auto
    report_hypercall_unknown_unsupported(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
    {
        bsl::error() << "unknown hypercall "                    //--
                     << bsl::hex(get_reg_hypercall(mut_sys))    //--
                     << bsl::endl                               //--
                     << bsl::here();                            //--

        set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
        return vmexit_failure_advance_ip_and_run;
    }
}

#endif
