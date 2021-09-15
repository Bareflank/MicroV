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

#include <integration_utils.hpp>
#include <mv_constants.hpp>
#include <mv_hypercall_impl.hpp>
#include <mv_hypercall_t.hpp>
#include <mv_types.hpp>

#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        mv_status_t mut_ret{};

        integration::initialize_globals();
        auto const gpa0{hypercall::to_gpa(&hypercall::g_shared_page0, core0)};

        // GPA that is not paged aligned
        constexpr auto ugla{42_u64};
        mut_ret = mv_pp_op_set_shared_page_gpa_impl(hndl.get(), ugla.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // NULL GPA
        constexpr auto ngla{0_u64};
        mut_ret = mv_pp_op_set_shared_page_gpa_impl(hndl.get(), ngla.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // GPA out of range
        constexpr auto ogla{0xFFFFFFFFFFFFFFFF_u64};
        mut_ret = mv_pp_op_set_shared_page_gpa_impl(hndl.get(), ogla.get());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // Setting after a clear succeeds
        {
            integration::verify(mut_hvc.mv_pp_op_set_shared_page_gpa(gpa0));
            integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());
            integration::verify(mut_hvc.mv_pp_op_set_shared_page_gpa(gpa0));
        }

        // Clearing more than once is fine
        {
            integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());
            integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());
        }

        // Clear many times
        constexpr auto num_loops{0x100_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            integration::verify(mut_hvc.mv_pp_op_set_shared_page_gpa(gpa0));
            integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());
        }

        return bsl::exit_success;
    }
}

/// <!-- description -->
///   @brief Provides the main entry point for this application.
///
/// <!-- inputs/outputs -->
///   @return bsl::exit_success on success, bsl::exit_failure otherwise.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();
    return hypercall::tests();
}
