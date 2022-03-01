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

#include "../../include/handle_system_kvm_check_extension.h"

#include <helpers.hpp>

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
        constexpr auto handle{&handle_system_kvm_check_extension};

        bsl::ut_scenario{"capext_cpuid success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_cpuid{1_u16};
                constexpr auto capext_cpuid{7_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capext_cpuid.get(), mut_checkext.data()));
                        bsl::ut_check(ret_cpuid == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capimmexit success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capimexit{1_u16};
                constexpr auto capimmexit{136_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capimmexit.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capimexit == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capuser_memory success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capuser{1_u16};
                constexpr auto capuser_memory{3_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capuser_memory.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capuser == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capset_tss_addr success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_captss{1_u16};
                constexpr auto captss_addr{4_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(captss_addr.get(), mut_checkext.data()));
                        bsl::ut_check(ret_captss == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capnr_vcpus success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capvcpus{1_u16};
                constexpr auto capnr_vcpus{9_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capnr_vcpus.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capvcpus == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capnr_memslots success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capmemslots{64_u16};
                constexpr auto capnr_memslots{10_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capnr_memslots.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capmemslots == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capmp_state success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capmpstate{1_u16};
                constexpr auto capmp_state{14_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capmp_state.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capmpstate == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capdestory_regionworks success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capdesrworks{1_u16};
                constexpr auto capdes_regionworks{21_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capdes_regionworks.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capdesrworks == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capjoin_regionworks success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capjoinrworks{1_u16};
                constexpr auto capjoin_regionworks{30_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capjoin_regionworks.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capjoinrworks == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capmce success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capmce{32_u16};
                constexpr auto capmce{31_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(capmce.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capmce == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capgettsckhz success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_captsckhz{1_u16};
                constexpr auto captsckhz{61_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(captsckhz.get(), mut_checkext.data()));
                        bsl::ut_check(ret_captsckhz == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capmaxvcpus success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capmaxvcpus{2_u16};
                constexpr auto capmaxvcpus{66_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capmaxvcpus.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capmaxvcpus == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capirqchip success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capmaxirqchip{1_u16};
                constexpr auto capmaxirqchip{0_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capmaxirqchip.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capmaxirqchip == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capioeventfd success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capioeventfd{1_u16};
                constexpr auto capioeventfd{36_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capioeventfd.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capioeventfd == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"capirqfd success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capirqfd{1_u16};
                constexpr auto capirqfd{32_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(capirqfd.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capirqfd == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };

        bsl::ut_scenario{"tscdeadlinetimer success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_captscdtimer{1_u16};
                constexpr auto captscdtimer{72_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(captscdtimer.get(), mut_checkext.data()));
                        bsl::ut_check(ret_captscdtimer == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"maxvcpuid success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capmaxvcpuid{32767_u16};
                constexpr auto capmaxvcpuid{128_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(capmaxvcpuid.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capmaxvcpuid == bsl::to_u16(mut_checkext));
                    };
                };
            };
        };
        bsl::ut_scenario{"unsupported extension"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::safe_u32 mut_checkext{};
                constexpr auto ret_capmaxvcpuid{0_u16};
                constexpr auto unsupportedext{129_u64};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            SHIM_SUCCESS == handle(unsupportedext.get(), mut_checkext.data()));
                        bsl::ut_check(ret_capmaxvcpuid == bsl::to_u16(mut_checkext));
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
