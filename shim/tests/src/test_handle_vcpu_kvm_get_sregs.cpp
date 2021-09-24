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

#include "../../include/handle_vcpu_kvm_get_sregs.h"

#include <helpers.hpp>
#include <kvm_dtable.h>
#include <kvm_segment.h>
#include <kvm_sregs.h>
#include <shim_vcpu_t.h>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace shim
{
    constexpr auto VAL16{42_u16};
    constexpr auto VAL32{42_u32};
    constexpr auto VAL64{42_u64};

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
        constexpr auto handle{&handle_vcpu_kvm_get_sregs};

        bsl::ut_scenario{"success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_val = VAL64.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&vcpu, &mut_args));
                        bsl::ut_check(VAL64 == mut_args.cs.base);
                        bsl::ut_check(VAL32 == mut_args.cs.limit);
                        bsl::ut_check(VAL16 == mut_args.cs.selector);
                        bsl::ut_check(VAL64 == mut_args.ds.base);
                        bsl::ut_check(VAL32 == mut_args.ds.limit);
                        bsl::ut_check(VAL16 == mut_args.ds.selector);
                        bsl::ut_check(VAL64 == mut_args.es.base);
                        bsl::ut_check(VAL32 == mut_args.es.limit);
                        bsl::ut_check(VAL16 == mut_args.es.selector);
                        bsl::ut_check(VAL64 == mut_args.fs.base);
                        bsl::ut_check(VAL32 == mut_args.fs.limit);
                        bsl::ut_check(VAL16 == mut_args.fs.selector);
                        bsl::ut_check(VAL64 == mut_args.gs.base);
                        bsl::ut_check(VAL32 == mut_args.gs.limit);
                        bsl::ut_check(VAL16 == mut_args.gs.selector);
                        bsl::ut_check(VAL64 == mut_args.ss.base);
                        bsl::ut_check(VAL32 == mut_args.ss.limit);
                        bsl::ut_check(VAL16 == mut_args.ss.selector);
                        bsl::ut_check(VAL64 == mut_args.tr.base);
                        bsl::ut_check(VAL32 == mut_args.tr.limit);
                        bsl::ut_check(VAL16 == mut_args.tr.selector);
                        bsl::ut_check(VAL64 == mut_args.ldt.base);
                        bsl::ut_check(VAL32 == mut_args.ldt.limit);
                        bsl::ut_check(VAL16 == mut_args.ldt.selector);
                        bsl::ut_check(VAL64 == mut_args.gdt.base);
                        bsl::ut_check(VAL16 == mut_args.gdt.limit);
                        bsl::ut_check(VAL64 == mut_args.idt.base);
                        bsl::ut_check(VAL16 == mut_args.idt.limit);
                        bsl::ut_check(VAL64 == mut_args.cr0);
                        bsl::ut_check(VAL64 == mut_args.cr2);
                        bsl::ut_check(VAL64 == mut_args.cr3);
                        bsl::ut_check(VAL64 == mut_args.cr4);
                        bsl::ut_check(VAL64 == mut_args.cr8);
                        bsl::ut_check(VAL64 == mut_args.efer);
                        bsl::ut_check(VAL64 == mut_args.apic_base);
                    };
                };
            };
        };

        bsl::ut_scenario{"hypervisor not detected"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_hypervisor_detected = false;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_hypervisor_detected = true;
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_reg_get_list fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_reg_get_list = VAL64.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_vs_op_reg_get_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_reg_get_list adds 0 register"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_reg_get_list = MV_STATUS_FAILURE_INC_NUM_ENTRIES;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_vs_op_reg_get_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_reg_get_list adds unknown"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_reg_get_list = MV_STATUS_FAILURE_ADD_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_vs_op_reg_get_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_reg_get_list corrupts num_entries"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_reg_get_list = MV_STATUS_FAILURE_CORRUPT_NUM_ENTRIES;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_vs_op_reg_get_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_msr_get_list fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_msr_get_list = VAL64.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_vs_op_msr_get_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_msr_get_list adds 0 register"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_msr_get_list = MV_STATUS_FAILURE_INC_NUM_ENTRIES;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_vs_op_msr_get_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_msr_get_list adds unknown"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_msr_get_list = MV_STATUS_FAILURE_ADD_UNKNOWN;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_vs_op_msr_get_list = {};
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_msr_get_list corrupts num_entries"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t const vcpu{};
                kvm_sregs mut_args{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_msr_get_list = MV_STATUS_FAILURE_CORRUPT_NUM_ENTRIES;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&vcpu, &mut_args));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_mv_vs_op_msr_get_list = {};
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
