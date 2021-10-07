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

#include "../../mocks/mv_hypercall.h"

#include <mv_constants.h>
#include <mv_exit_io_t.h>
#include <mv_exit_reason_t.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <mv_translation_t.h>
#include <mv_types.h>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace shim
{
    extern "C"
    {
        constinit void *g_mut_shared_pages[HYPERVISOR_MAX_PPS];    // NOLINT
        constinit bsl::uint64 g_mut_val{};

        constinit bsl::uint32 g_mut_mv_id_op_version{};

        constinit bsl::uint64 g_mut_mv_handle_op_open_handle{};
        constinit mv_status_t g_mut_mv_handle_op_close_handle{};

        constinit bsl::uint16 g_mut_mv_pp_op_ppid{};
        constinit mv_status_t g_mut_mv_pp_op_clr_shared_page_gpa{};
        constinit mv_status_t g_mut_mv_pp_op_set_shared_page_gpa{};
        constinit mv_status_t g_mut_mv_pp_op_cpuid_get_supported_list{};
        constinit mv_status_t g_mut_mv_pp_op_msr_get_supported_list{};
        constinit mv_status_t g_mut_mv_pp_op_tsc_get_khz{};
        constinit mv_status_t g_mut_mv_pp_op_tsc_set_khz{};

        constinit bsl::uint16 g_mut_mv_vm_op_create_vm{};
        constinit mv_status_t g_mut_mv_vm_op_destroy_vm{};
        constinit bsl::uint16 g_mut_mv_vm_op_vmid{};
        constinit mv_status_t g_mut_mv_vm_op_mmio_map{};
        constinit mv_status_t g_mut_mv_vm_op_mmio_unmap{};

        constinit bsl::uint16 g_mut_mv_vp_op_create_vp{};
        constinit mv_status_t g_mut_mv_vp_op_destroy_vp{};
        constinit bsl::uint16 g_mut_mv_vp_op_vmid{};
        constinit bsl::uint16 g_mut_mv_vp_op_vpid{};

        constinit bsl::uint16 g_mut_mv_vs_op_create_vs{};
        constinit mv_status_t g_mut_mv_vs_op_destroy_vs{};
        constinit bsl::uint16 g_mut_mv_vs_op_vmid{};
        constinit bsl::uint16 g_mut_mv_vs_op_vpid{};
        constinit bsl::uint16 g_mut_mv_vs_op_vsid{};
        constinit mv_translation_t g_mut_mv_vs_op_gla_to_gpa{};
        constinit mv_exit_reason_t g_mut_mv_vs_op_run{};
        constinit mv_exit_io_t g_mut_mv_vs_op_run_io{};
        constinit mv_status_t g_mut_mv_vs_op_reg_get{};
        constinit mv_status_t g_mut_mv_vs_op_reg_set{};
        constinit mv_status_t g_mut_mv_vs_op_reg_get_list{};
        constinit mv_status_t g_mut_mv_vs_op_reg_set_list{};
        constinit mv_status_t g_mut_mv_vs_op_msr_get{};
        constinit mv_status_t g_mut_mv_vs_op_msr_set{};
        constinit mv_status_t g_mut_mv_vs_op_msr_get_list{};
        constinit mv_status_t g_mut_mv_vs_op_msr_set_list{};
        constinit mv_status_t g_mut_mv_vs_op_fpu_get_all{};
        constinit mv_status_t g_mut_mv_vs_op_fpu_set_all{};
        constinit mv_status_t g_mut_mv_vs_op_mp_state_get{};
        constinit mv_status_t g_mut_mv_vs_op_mp_state_set{};
        constinit mv_status_t g_mut_mv_vs_op_tsc_get_khz{};

        extern bool g_mut_hypervisor_detected;
        extern bool g_mut_platform_alloc_fails;
        extern bsl::safe_u32 g_mut_platform_num_online_cpus;
        extern int64_t g_mut_platform_mlock;
        extern int64_t g_mut_platform_munlock;
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
        bsl::uint64 const hndl{42};                     // NOLINT
        bsl::uint64 const gla{HYPERVISOR_PAGE_SIZE};    // NOLINT
        bsl::uint64 const gpa{HYPERVISOR_PAGE_SIZE};    // NOLINT

        bsl::ut_scenario{"mv_id_op_version"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_id_op_version};
                constexpr auto expected{42_u32};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_id_op_version = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall());
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_handle_op_open_handle"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_handle_op_open_handle};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_handle_op_open_handle = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall({}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_handle_op_close_handle"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_handle_op_close_handle};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_handle_op_close_handle = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_pp_op_ppid"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_pp_op_ppid};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_pp_op_ppid = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_pp_op_clr_shared_page_gpa"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_pp_op_clr_shared_page_gpa};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_pp_op_clr_shared_page_gpa = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_pp_op_set_shared_page_gpa"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_pp_op_set_shared_page_gpa};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_pp_op_set_shared_page_gpa = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, gpa));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_pp_op_cpuid_get_supported_list"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_pp_op_cpuid_get_supported_list};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_pp_op_cpuid_get_supported_list = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_pp_op_msr_get_supported_list"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_pp_op_msr_get_supported_list};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_pp_op_msr_get_supported_list = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_create_vm"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vm_op_create_vm};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vm_op_create_vm = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_destroy_vm"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vm_op_destroy_vm};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vm_op_destroy_vm = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_vmid"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vm_op_vmid};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vm_op_vmid = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_mmio_map"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vm_op_mmio_map};
                constexpr auto success_attempts{2_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vm_op_mmio_map = success_attempts.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::safe_u64::magic_0() == hypercall(hndl, {}, {}));
                        bsl::ut_check(bsl::safe_u64::magic_0() != hypercall(hndl, {}, {}));
                        bsl::ut_check(bsl::safe_u64::magic_0() == hypercall(hndl, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_mmio_unmap"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vm_op_mmio_unmap};
                constexpr auto success_attempts{2_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vm_op_mmio_unmap = success_attempts.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::safe_u64::magic_0() == hypercall(hndl, {}));
                        bsl::ut_check(bsl::safe_u64::magic_0() != hypercall(hndl, {}));
                        bsl::ut_check(bsl::safe_u64::magic_0() == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vp_op_create_vp"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vp_op_create_vp};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vp_op_create_vp = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vp_op_destroy_vp"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vp_op_destroy_vp};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vp_op_destroy_vp = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vp_op_vmid"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vp_op_vmid};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vp_op_vmid = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vp_op_vpid"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vp_op_vpid};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vp_op_vpid = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_create_vs"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_create_vs};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_create_vs = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_destroy_vs"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_destroy_vs};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_destroy_vs = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_vmid"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_vmid};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_vmid = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_vpid"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_vpid};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_vpid = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_vsid"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_vsid};
                constexpr auto expected{42_u16};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_vsid = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_gla_to_gpa"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_gla_to_gpa};
                constexpr auto val{42_u64};
                constexpr mv_translation_t expected{
                    val.get(), val.get(), val.get(), val.get(), bsl::safe_u8::magic_1().get()};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_gla_to_gpa = expected;
                    auto const ret{hypercall(hndl, {}, gla)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(ret.vaddr == val);
                        bsl::ut_check(ret.laddr == val);
                        bsl::ut_check(ret.paddr == val);
                        bsl::ut_check(ret.flags == val);
                        bsl::ut_check(ret.is_valid == bsl::safe_u8::magic_1());
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_run"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_run};
                constexpr mv_exit_reason_t expected{mv_exit_reason_t_failure};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_run = expected;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_run"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_run};
                constexpr mv_exit_reason_t expected{mv_exit_reason_t_unknown};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_run = expected;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_run"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_run};
                constexpr mv_exit_reason_t expected{mv_exit_reason_t_hlt};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_run = expected;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_run"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_run};
                constexpr mv_exit_reason_t expected{mv_exit_reason_t_io};
                mv_exit_io_t mut_exit_io{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_shared_pages[0] = &mut_exit_io;
                    g_mut_mv_vs_op_run = expected;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_run"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_run};
                constexpr mv_exit_reason_t expected{mv_exit_reason_t_mmio};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_run = expected;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_reg_get"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_reg_get};
                constexpr auto expected{42_u64};
                constexpr mv_reg_t reg{mv_reg_t_dummy};
                bsl::safe_u64 mut_val{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_val = expected.get();
                    g_mut_mv_vs_op_reg_get = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}, reg, mut_val.data()));
                        bsl::ut_check(expected == mut_val);
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_reg_set"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_reg_set};
                constexpr auto expected{42_u64};
                constexpr mv_reg_t reg{mv_reg_t_dummy};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_reg_set = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}, reg, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_reg_get_list"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_reg_get_list};
                constexpr auto expected{42_u64};
                mv_rdl_t mut_rdl{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_rdl.num_entries = bsl::safe_u64::magic_2().get();
                    g_mut_shared_pages[0] = &mut_rdl;
                    g_mut_val = expected.get();
                    g_mut_mv_vs_op_reg_get_list = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                        bsl::ut_check(expected == mut_rdl.entries[0].val);
                        bsl::ut_check(expected == mut_rdl.entries[1].val);
                        bsl::ut_check(expected != mut_rdl.entries[2].val);
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_reg_set_list"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_reg_set_list};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_reg_set_list = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_msr_get"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_msr_get};
                constexpr auto expected{42_u64};
                bsl::safe_u64 mut_val{};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_val = expected.get();
                    g_mut_mv_vs_op_msr_get = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}, {}, mut_val.data()));
                        bsl::ut_check(expected == mut_val);
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_msr_set"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_msr_set};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_msr_set = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}, {}, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_msr_get_list"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_msr_get_list};
                constexpr auto expected{42_u64};
                mv_rdl_t mut_rdl{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_rdl.num_entries = bsl::safe_u64::magic_2().get();
                    g_mut_shared_pages[0] = &mut_rdl;
                    g_mut_val = expected.get();
                    g_mut_mv_vs_op_msr_get_list = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                        bsl::ut_check(expected == mut_rdl.entries[0].val);
                        bsl::ut_check(expected == mut_rdl.entries[1].val);
                        bsl::ut_check(expected != mut_rdl.entries[2].val);
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_msr_set_list"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_msr_set_list};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_msr_set_list = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_fpu_get_all"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_fpu_get_all};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_fpu_get_all = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vs_op_fpu_set_all"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                constexpr auto hypercall{&mv_vs_op_fpu_set_all};
                constexpr auto expected{42_u64};
                bsl::ut_when{} = [&]() noexcept {
                    g_mut_mv_vs_op_fpu_set_all = expected.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(expected == hypercall(hndl, {}));
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
