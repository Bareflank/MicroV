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

#include "../../include/handle_system_kvm_get_msr_index_list.h"

#include <helpers.hpp>
#include <kvm_msr_list.h>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace shim
{
    constexpr auto VAL64{42_u64};
    constexpr auto INIT_NMSRS{0x10_u32};

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
        constexpr auto handle{&handle_system_kvm_get_msr_index_list};
        init_tests();

        bsl::ut_scenario{"success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_msr_list mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.nmsrs = INIT_NMSRS.get();
                    g_mut_val = bsl::safe_u64::magic_2().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_args));
                    };
                };
            };
        };

        bsl::ut_scenario{"success multiple pages"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_msr_list mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.nmsrs = INIT_NMSRS.get();
                    g_mut_val = bsl::safe_u64::magic_2().get();
                    g_mut_mv_pp_op_msr_get_supported_list = MV_STATUS_FAILURE_SET_RDL_REG1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_pp_op_msr_get_supported_list = {};
                        g_mut_val = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"hypervisor not detected"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_msr_list mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_hypervisor_detected = false;
                    mut_args.nmsrs = INIT_NMSRS.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_hypervisor_detected = true;
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_pp_op_msr_get_supported_list corrupts num_entries"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_msr_list mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_pp_op_msr_get_supported_list = MV_STATUS_FAILURE_CORRUPT_NUM_ENTRIES;
                    mut_args.nmsrs = INIT_NMSRS.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_pp_op_msr_get_supported_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_pp_op_msr_get_supported_list fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_msr_list mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_pp_op_msr_get_supported_list = VAL64.get();
                    mut_args.nmsrs = INIT_NMSRS.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_pp_op_msr_get_supported_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"number of MSRs is larger than kvm_msr_list indices"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_msr_list mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.nmsrs = INIT_NMSRS.get();
                    g_mut_val = VAL64.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_2BIG == handle(&mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_val = {};
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
