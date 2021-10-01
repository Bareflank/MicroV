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

#include "../../include/handle_vcpu_kvm_run.h"

#include <helpers.hpp>
#include <kvm_run.h>
#include <mv_bit_size_t.h>
#include <mv_exit_reason_t.h>
#include <shim_vcpu_t.h>

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
        constexpr auto handle{&handle_vcpu_kvm_run};

        bsl::ut_scenario{"hypervisor not detected"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_hypervisor_detected = false;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_hypervisor_detected = true;
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"platform_interrupted returns interrupted"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_platform_interrupted = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_INTERRUPTED == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_platform_interrupted = false;
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"exit immediately"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    mut_vcpu.run->immediate_exit = bsl::safe_u8::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_INTERRUPTED == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        mut_vcpu.run->immediate_exit = {};
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns failure"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_failure;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                        bsl::ut_check(KVM_EXIT_FAIL_ENTRY == mut_vcpu.run->exit_reason);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns unknown"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_unknown;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                        bsl::ut_check(KVM_EXIT_UNKNOWN == mut_vcpu.run->exit_reason);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns hlt"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_hlt;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io in"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_IN};
                constexpr auto size{mv_bit_size_t_8};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_vcpu));
                        bsl::ut_check(KVM_EXIT_IO == mut_vcpu.run->exit_reason);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io out"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_OUT};
                constexpr auto size{mv_bit_size_t_8};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_vcpu));
                        bsl::ut_check(KVM_EXIT_IO == mut_vcpu.run->exit_reason);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io unknown type"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr auto type{42_u64};
                constexpr auto size{mv_bit_size_t_8};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io 8 bit"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_IN};
                constexpr auto size{mv_bit_size_t_8};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_vcpu));
                        bsl::ut_check(KVM_EXIT_IO == mut_vcpu.run->exit_reason);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io 16 bit"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_IN};
                constexpr auto size{mv_bit_size_t_16};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_vcpu));
                        bsl::ut_check(KVM_EXIT_IO == mut_vcpu.run->exit_reason);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io 32 bit"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_IN};
                constexpr auto size{mv_bit_size_t_32};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_vcpu));
                        bsl::ut_check(KVM_EXIT_IO == mut_vcpu.run->exit_reason);
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io 64 bit"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_IN};
                constexpr auto size{mv_bit_size_t_64};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io random size"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_IN};
                constexpr auto size{static_cast<mv_bit_size_t>(42)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io addr out of range"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0xFFFFFFFFFFFFFFFF_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_IN};
                constexpr auto size{mv_bit_size_t_8};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns io reps out of range"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                constexpr auto addr{0x10_u64};
                constexpr auto data{42_u64};
                constexpr auto reps{0xFFFFFFFFFFFFFFFF_u64};
                constexpr bsl::safe_u64 type{MV_EXIT_IO_IN};
                constexpr auto size{mv_bit_size_t_8};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_io;
                    g_mut_mv_vs_op_run_io.addr = addr.get();
                    g_mut_mv_vs_op_run_io.data = data.get();
                    g_mut_mv_vs_op_run_io.reps = reps.get();
                    g_mut_mv_vs_op_run_io.type = type.get();
                    g_mut_mv_vs_op_run_io.size = size;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns mmio"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_mmio;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns msr"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_msr;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns interrupt"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_interrupt;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns nmi"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = mv_exit_reason_t_nmi;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_mv_vs_op_run returns random"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                shim_vcpu_t mut_vcpu{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_vcpu.run = new kvm_run();    // NOLINT
                    g_mut_mv_vs_op_run = static_cast<mv_exit_reason_t>(-42);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_vcpu));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        delete mut_vcpu.run;    // NOLINT // GRCOV_EXCLUDE_BR
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
