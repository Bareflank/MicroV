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

#include "../../include/handle_vcpu_kvm_get_regs.h"

#include <helpers.hpp>
#include <kvm_regs.h>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace shim
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        init_tests();
        bsl::ut_scenario{"success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                kvm_regs mut_args{};
                constexpr auto entryval{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_val = entryval.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle_vcpu_kvm_get_regs(&mut_vcpu, &mut_args));
                        bsl::ut_check(entryval == mut_args.rax);
                        bsl::ut_check(entryval == mut_args.rbx);
                        bsl::ut_check(entryval == mut_args.rcx);
                        bsl::ut_check(entryval == mut_args.rdx);
                        bsl::ut_check(entryval == mut_args.rsi);
                        bsl::ut_check(entryval == mut_args.rdi);
                        bsl::ut_check(entryval == mut_args.rsp);
                        bsl::ut_check(entryval == mut_args.rbp);
                        bsl::ut_check(entryval == mut_args.r8);
                        bsl::ut_check(entryval == mut_args.r9);
                        bsl::ut_check(entryval == mut_args.r10);
                        bsl::ut_check(entryval == mut_args.r11);
                        bsl::ut_check(entryval == mut_args.r12);
                        bsl::ut_check(entryval == mut_args.r13);
                        bsl::ut_check(entryval == mut_args.r14);
                        bsl::ut_check(entryval == mut_args.r15);
                        bsl::ut_check(entryval == mut_args.rip);
                        bsl::ut_check(entryval == mut_args.rflags);
                    };
                };
            };
        };
        bsl::ut_scenario{"mv_vs_op_reg_get_list fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                kvm_regs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_reg_get_list = MV_INVALID_ID;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_FAILURE == handle_vcpu_kvm_get_regs(&mut_vcpu, &mut_args));
                    };
                };
            };
        };

        return fini_tests();
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();
    return shim::tests();
}
