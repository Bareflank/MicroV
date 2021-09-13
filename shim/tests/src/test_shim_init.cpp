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

#include "../../include/shim_init.h"
#include "shim_fini.h"

#include <helpers.hpp>

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
        bsl::ut_scenario{"success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_id_op_version = MV_ALL_SPECS_SUPPORTED_VAL;
                    g_mut_mv_handle_op_open_handle = MV_HANDLE_VAL;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == shim_init());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        bsl::ut_required_step(SHIM_SUCCESS == shim_fini());
                    };
                };
            };
        };

        bsl::ut_scenario{"too many cpus"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_platform_num_online_cpus = 0xFFFFFFFFU;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == shim_init());
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_platform_num_online_cpus = 1U;
                    };
                };
            };
        };

        bsl::ut_scenario{"unsupported version"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_id_op_version = 0U;
                    g_mut_mv_handle_op_open_handle = MV_HANDLE_VAL;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == shim_init());
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_handle_op_open_handle fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_id_op_version = MV_ALL_SPECS_SUPPORTED_VAL;
                    g_mut_mv_handle_op_open_handle = MV_INVALID_HANDLE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == shim_init());
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_alloc fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_id_op_version = MV_ALL_SPECS_SUPPORTED_VAL;
                    g_mut_mv_handle_op_open_handle = MV_HANDLE_VAL;
                    g_mut_platform_alloc_fails = 1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == shim_init());
                    };
                };
            };
        };

        return bsl::ut_success();
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
