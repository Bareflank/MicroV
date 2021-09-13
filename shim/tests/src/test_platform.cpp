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

#include <debug.h>
#include <helpers.hpp>

#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace shim
{
    extern "C" [[nodiscard]] constexpr auto
    foo_success(uint32_t const cpu) noexcept -> int64_t
    {
        bsl::discard(cpu);
        return SHIM_SUCCESS;
    }

    extern "C" [[nodiscard]] constexpr auto
    foo_failure(uint32_t const cpu) noexcept -> int64_t
    {
        bsl::discard(cpu);
        return SHIM_FAILURE;
    }

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
        bsl::ut_scenario{"silence debug.h"} = []() noexcept {
            bfdebug("");
            bfdebug_x8("", {});
            bfdebug_x16("", {});
            bfdebug_x32("", {});
            bfdebug_x64("", {});
            bfdebug_d8("", {});
            bfdebug_d16("", {});
            bfdebug_d32("", {});
            bfdebug_d64("", {});
            bfdebug_ptr("", {});

            bferror("");
            bferror_x8("", {});
            bferror_x16("", {});
            bferror_x32("", {});
            bferror_x64("", {});
            bferror_d8("", {});
            bferror_d16("", {});
            bferror_d32("", {});
            bferror_d64("", {});
            bferror_ptr("", {});
        };

        bsl::ut_scenario{"platform_expects"} = []() noexcept {
            platform_expects(1);
        };

        bsl::ut_scenario{"platform_ensures"} = []() noexcept {
            platform_ensures(1);
        };

        bsl::ut_scenario{"platform_alloc success"} = []() noexcept {
            bsl::ut_when{} = [&]() noexcept {
                auto *const pmut_ptr{platform_alloc(HYPERVISOR_PAGE_SIZE)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr != pmut_ptr);
                };
                bsl::ut_cleanup{} = [&]() noexcept {
                    platform_free(pmut_ptr, HYPERVISOR_PAGE_SIZE);
                };
            };
        };

        bsl::ut_scenario{"platform_alloc fails"} = []() noexcept {
            bsl::ut_when{} = [&]() noexcept {
                g_mut_platform_alloc_fails = 2;
                auto *const pmut_ptr1{platform_alloc(HYPERVISOR_PAGE_SIZE)};
                auto *const pmut_ptr2{platform_alloc(HYPERVISOR_PAGE_SIZE)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr != pmut_ptr1);
                    bsl::ut_check(nullptr == pmut_ptr2);
                };
                bsl::ut_cleanup{} = [&]() noexcept {
                    platform_free(pmut_ptr1, HYPERVISOR_PAGE_SIZE);
                    platform_free(pmut_ptr2, HYPERVISOR_PAGE_SIZE);
                };
            };
        };

        bsl::ut_scenario{"platform_free success"} = []() noexcept {
            bsl::ut_when{} = [&]() noexcept {
                auto *const pmut_ptr{platform_alloc(HYPERVISOR_PAGE_SIZE)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr != pmut_ptr);
                };
                bsl::ut_cleanup{} = [&]() noexcept {
                    platform_free(pmut_ptr, HYPERVISOR_PAGE_SIZE);
                };
            };
        };

        bsl::ut_scenario{"platform_free nullptr"} = []() noexcept {
            platform_free({}, {});
        };

        bsl::ut_scenario{"platform_virt_to_phys"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool const val{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(platform_virt_to_phys(&val) == (uintptr_t)&val);
                };
            };
        };

        bsl::ut_scenario{"platform_memset"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{true};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_when{} = [&]() noexcept {
                    platform_memset(&mut_dst, {}, size.get());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_dst);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_memcpy"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{true};
                bool const src{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_when{} = [&]() noexcept {
                    platform_memcpy(&mut_dst, &src, size.get());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_dst);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_copy_from_user"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{true};
                bool const src{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_when{} = [&]() noexcept {
                    platform_copy_from_user(&mut_dst, &src, size.get());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_dst);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_copy_to_user"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_dst{true};
                bool const src{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_when{} = [&]() noexcept {
                    platform_copy_to_user(&mut_dst, &src, size.get());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_dst);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_num_online_cpus"} = []() noexcept {
            bsl::ut_check(1U == platform_num_online_cpus());
        };

        bsl::ut_scenario{"platform_on_each_cpu success"} = []() noexcept {
            bsl::ut_check(SHIM_SUCCESS == platform_on_each_cpu(&foo_success, {}));
        };

        bsl::ut_scenario{"platform_on_each_cpu failure"} = []() noexcept {
            bsl::ut_check(SHIM_FAILURE == platform_on_each_cpu(&foo_failure, {}));
        };

        bsl::ut_scenario{"platform_mutex does nothing under test"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                platform_mutex mut_mutex{};    // NOLINT
                bsl::ut_when{} = [&]() noexcept {
                    platform_mutex_init(&mut_mutex);      // NOLINT
                    platform_mutex_lock(&mut_mutex);      // NOLINT
                    platform_mutex_unlock(&mut_mutex);    // NOLINT
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
