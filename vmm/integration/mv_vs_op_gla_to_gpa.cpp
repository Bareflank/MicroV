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
#include <mv_translation_t.hpp>
#include <mv_types.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// @brief provides a variable to get the GPA of
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    alignas(HYPERVISOR_PAGE_SIZE.get()) bool g_mut_test{};

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
        mv_translation_t mut_trn{};
        mv_hypercall_t mut_hvc{};

        bsl::safe_umx const gla{to_umx(&g_mut_test)};
        bsl::safe_umx mut_gpa{};

        /// NOTE:
        /// - Touch g_mut_test. This ensures that g_mut_test is paged in. On Linux,
        ///   if g_mut_test has not yet been used, it would not be paged in.
        ///

        g_mut_test = true;

        /// NOTE:
        /// - Since we only support 64bit, a global variable's GVA will always
        ///   be a GLA on at least Intel, AMD and ARM so long as we do not
        ///   use a variable from thread local storage.
        ///

        integration::verify(mut_hvc.initialize());
        auto const hndl{mut_hvc.handle()};

        // invalid VSID
        mut_ret =
            mv_vs_op_gla_to_gpa_impl(hndl.get(), MV_INVALID_ID.get(), gla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VMS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_gla_to_gpa_impl(hndl.get(), oor.get(), gla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VMS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_gla_to_gpa_impl(hndl.get(), nyc.get(), gla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // GLA that is not paged aligned
        constexpr auto ugla{42_u64};
        mut_ret =
            mv_vs_op_gla_to_gpa_impl(hndl.get(), MV_SELF_ID.get(), ugla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // NULL GLA
        constexpr auto ngla{0_u64};
        mut_ret =
            mv_vs_op_gla_to_gpa_impl(hndl.get(), MV_SELF_ID.get(), ngla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // GLA that is not present (i.e. not paged in)
        constexpr auto npgla{0x1000_u64};
        mut_ret =
            mv_vs_op_gla_to_gpa_impl(hndl.get(), MV_SELF_ID.get(), npgla.get(), mut_gpa.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VSID that has been created, but has not been initialized
        {
            auto const vsid{mut_hvc.mv_vs_op_create_vs(MV_SELF_ID)};
            integration::verify(vsid.is_valid_and_checked());

            mut_trn = mut_hvc.mv_vs_op_gla_to_gpa(vsid, to_umx(&g_mut_test));
            integration::verify(!mut_trn.is_valid);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
        }

        // // Get a valid GPA a lot to make sure mapping/unmapping works
        // {
        //     constexpr auto num_loops{0x1000_umx};
        //     for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
        //         mut_trn = mut_hvc.mv_vs_op_gla_to_gpa(MV_SELF_ID, to_umx(&g_mut_test));
        //         integration::verify(mut_trn.is_valid);
        //     }
        // }

        // Get the gpa and print the results for manual inspection
        {
            mut_trn = mut_hvc.mv_vs_op_gla_to_gpa(MV_SELF_ID, to_umx(&g_mut_test));
            integration::verify(mut_trn.is_valid);

            bsl::debug() << "the result is:\n"
                         << "  - vaddr: " << bsl::hex(mut_trn.vaddr) << bsl::endl
                         << "  - laddr: " << bsl::hex(mut_trn.laddr) << bsl::endl
                         << "  - paddr: " << bsl::hex(mut_trn.paddr) << bsl::endl
                         << "  - flags: " << bsl::hex(mut_trn.flags) << bsl::endl
                         << "  - is_valid: " << mut_trn.is_valid << bsl::endl
                         << bsl::endl;
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
