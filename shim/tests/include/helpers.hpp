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

#include "g_mut_hndl.h"      // IWYU pragma: export
#include "mv_constants.h"    // IWYU pragma: export
#include "mv_exit_io_t.h"    // IWYU pragma: export
#include "mv_exit_reason_t.h"
#include "mv_hypercall.h"    // IWYU pragma: export
#include "mv_translation_t.h"
#include "mv_types.h"    // IWYU pragma: export

#include <shim_fini.h>
#include <shim_init.h>

#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace shim
{
    extern "C"
    {
        /// BUG:
        /// - For some reason we cannot use "inline" here as it generate
        ///   linker errors. There should be no difference between adding
        ///   inline vs. not adding it other than removing ODR issues,
        ///   but that does not seem to be the case. For now, the ODR issues
        ///   can be ignored since we will only include this file once for
        ///   each unit test, and we mark everything as NOLINT. We either
        ///   need to track down what we are doing wrong, or report a bug
        ///   to LLVM.
        ///

        constinit void *g_mut_shared_pages[HYPERVISOR_MAX_PPS];    // NOLINT
        constinit bsl::uint64 g_mut_val{};                         // NOLINT

        constinit bsl::uint32 g_mut_mv_id_op_version{};    // NOLINT

        constinit bsl::uint64 g_mut_mv_handle_op_open_handle{};     // NOLINT
        constinit mv_status_t g_mut_mv_handle_op_close_handle{};    // NOLINT

        constinit bsl::uint16 g_mut_mv_pp_op_ppid{};                        // NOLINT
        constinit mv_status_t g_mut_mv_pp_op_clr_shared_page_gpa{};         // NOLINT
        constinit mv_status_t g_mut_mv_pp_op_cpuid_get_supported_list{};    // NOLINT
        constinit mv_status_t g_mut_mv_pp_op_msr_get_supported_list{};      // NOLINT
        constinit mv_status_t g_mut_mv_pp_op_set_shared_page_gpa{};         // NOLINT
        constinit mv_status_t g_mut_mv_pp_op_tsc_get_khz{};                 // NOLINT
        constinit mv_status_t g_mut_mv_pp_op_tsc_set_khz{};                 // NOLINT

        constinit bsl::uint16 g_mut_mv_vm_op_create_vm{};     // NOLINT
        constinit mv_status_t g_mut_mv_vm_op_destroy_vm{};    // NOLINT
        constinit bsl::uint16 g_mut_mv_vm_op_vmid{};          // NOLINT
        constinit mv_status_t g_mut_mv_vm_op_mmio_map{};      // NOLINT
        constinit mv_status_t g_mut_mv_vm_op_mmio_unmap{};    // NOLINT

        constinit bsl::uint16 g_mut_mv_vp_op_create_vp{};     // NOLINT
        constinit mv_status_t g_mut_mv_vp_op_destroy_vp{};    // NOLINT
        constinit bsl::uint16 g_mut_mv_vp_op_vmid{};          // NOLINT
        constinit bsl::uint16 g_mut_mv_vp_op_vpid{};          // NOLINT

        constinit bsl::uint16 g_mut_mv_vs_op_create_vs{};          // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_destroy_vs{};         // NOLINT
        constinit bsl::uint16 g_mut_mv_vs_op_vmid{};               // NOLINT
        constinit bsl::uint16 g_mut_mv_vs_op_vpid{};               // NOLINT
        constinit bsl::uint16 g_mut_mv_vs_op_vsid{};               // NOLINT
        constinit mv_translation_t g_mut_mv_vs_op_gla_to_gpa{};    // NOLINT
        constinit mv_exit_reason_t g_mut_mv_vs_op_run{};           // NOLINT
        constinit mv_exit_io_t g_mut_mv_vs_op_run_io{};            // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_reg_get{};            // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_reg_set{};            // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_reg_get_list{};       // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_reg_set_list{};       // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_msr_get{};            // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_msr_set{};            // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_msr_get_list{};       // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_msr_set_list{};       // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_fpu_get_all{};        // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_fpu_set_all{};        // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_mp_state_get{};       // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_mp_state_set{};       // NOLINT
        constinit mv_status_t g_mut_mv_vs_op_tsc_get_khz{};        // NOLINT

        extern bool g_mut_hypervisor_detected;
        extern bool g_mut_platform_alloc_fails;
        extern bool g_mut_platform_virt_to_phys_user_fails;
        extern bsl::safe_u32 g_mut_platform_num_online_cpus;
        extern int64_t g_mut_platform_mlock;
        extern int64_t g_mut_platform_munlock;
        extern bool g_mut_platform_interrupted;
    }

    /// <!-- description -->
    ///   @brief Ensures the basics are set up for a test so that we do
    ///     not need to copy/paste this setup logic in every test.
    ///
    constexpr void
    init_tests() noexcept
    {
        g_mut_hypervisor_detected = true;
        g_mut_platform_num_online_cpus = 1U;
        g_mut_mv_id_op_version = MV_ALL_SPECS_SUPPORTED_VAL;
        g_mut_mv_handle_op_open_handle = MV_HANDLE_VAL;

        bsl::expects(SHIM_SUCCESS == shim_init());
    }

    /// <!-- description -->
    ///   @brief Cleanups resources that are needed.
    ///
    [[nodiscard]] constexpr auto
    fini_tests() noexcept -> bsl::exit_code
    {
        shim_fini();
        return bsl::ut_success();
    }

    /// <!-- description -->
    ///   @brief Returns a pointer of type T to the shared page
    ///     so that you can set return values
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    shared_page_as() noexcept -> T *
    {
        T *const pmut_ptr = static_cast<T *>(g_mut_shared_pages[0]);    // NOLINT

        bsl::expects(nullptr != pmut_ptr);
        return pmut_ptr;
    }
}
