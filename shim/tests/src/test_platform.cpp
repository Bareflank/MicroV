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

#include <constants.h>
#include <platform.h>
#include <types.h>

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
        bsl::ut_scenario{"platform_alloc success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
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
        };

        bsl::ut_scenario{"platform_alloc size 0"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    auto *const pmut_ptr{platform_alloc({})};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(nullptr == pmut_ptr);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_free success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
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
        };

        bsl::ut_scenario{"platform_free nullptr"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        platform_free({}, {});
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_virt_to_phys"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool const val{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(platform_virt_to_phys(&val) == (uintptr_t)&val);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_memset"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_d{true};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_SUCCESS == platform_memset(&mut_d, {}, size.get()));
                    bsl::ut_check(!mut_d);
                };
            };
        };

        bsl::ut_scenario{"platform_memset invalid dst"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_FAILURE == platform_memset({}, {}, size.get()));
                };
            };
        };

        bsl::ut_scenario{"platform_memcpy"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_d{true};
                bool const s{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_SUCCESS == platform_memcpy(&mut_d, &s, size.get()));
                    bsl::ut_check(!mut_d);
                };
            };
        };

        bsl::ut_scenario{"platform_memcpy invalid dst"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool const s{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_FAILURE == platform_memcpy({}, &s, size.get()));
                };
            };
        };

        bsl::ut_scenario{"platform_memcpy invalid src"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_d{true};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_FAILURE == platform_memcpy(&mut_d, {}, size.get()));
                };
            };
        };

        bsl::ut_scenario{"platform_copy_from_user"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_d{true};
                bool const s{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_SUCCESS == platform_copy_from_user(&mut_d, &s, size.get()));
                    bsl::ut_check(!mut_d);
                };
            };
        };

        bsl::ut_scenario{"platform_copy_from_user invalid dst"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool const s{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_FAILURE == platform_copy_from_user({}, &s, size.get()));
                };
            };
        };

        bsl::ut_scenario{"platform_copy_from_user invalid src"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_d{true};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_FAILURE == platform_copy_from_user(&mut_d, {}, size.get()));
                };
            };
        };

        bsl::ut_scenario{"platform_copy_to_user"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_d{true};
                bool const s{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_SUCCESS == platform_copy_to_user(&mut_d, &s, size.get()));
                    bsl::ut_check(!mut_d);
                };
            };
        };

        bsl::ut_scenario{"platform_copy_to_user invalid dst"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool const s{};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_FAILURE == platform_copy_to_user({}, &s, size.get()));
                };
            };
        };

        bsl::ut_scenario{"platform_copy_to_user invalid src"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bool mut_d{true};
                constexpr bsl::safe_umx size{sizeof(bool)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(SHIM_FAILURE == platform_copy_to_user(&mut_d, {}, size.get()));
                };
            };
        };

        bsl::ut_scenario{"platform_num_online_cpus"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(1U == platform_num_online_cpus());
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_on_each_cpu success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == platform_on_each_cpu(&foo_success, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_on_each_cpu failure"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == platform_on_each_cpu(&foo_failure, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_expects"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        platform_expects(1);
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_ensures"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        platform_ensures(1);
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
