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

#ifndef INTEGRATION_UTILS_HPP
#define INTEGRATION_UTILS_HPP

#ifdef _WIN32
// clang-format off

/// NOTE:
/// - The windows includes that we use here need to remain in this order.
///   Otherwise the code will not compile. Also, when using CPP, we need
///   to remove the max/min macros as they are used by the C++ standard.
///

#include <Windows.h>
#undef max
#undef min

// clang-format on
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>       // IWYU pragma: keep
#include <sys/mman.h>    // IWYU pragma: keep
#endif

#include <mv_cpuid_flag_t.hpp>    // IWYU pragma: keep
#include <basic_page_4k_t.hpp>
#include <cstdlib>
#include <ifmap_t.hpp>
#include <mv_constants.hpp>
#include <mv_exit_reason_t.hpp>
#include <mv_hypercall_t.hpp>
#include <mv_mdl_t.hpp>
#include <mv_rdl_t.hpp>
#include <mv_reg_t.hpp>
#include <mv_translation_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

constexpr auto self{hypercall::MV_SELF_ID};        // NOLINT
constexpr auto core0{bsl::safe_u64::magic_0()};    // NOLINT
constexpr auto core1{bsl::safe_u64::magic_1()};    // NOLINT
constexpr auto vsid0{bsl::safe_u16::magic_0()};    // NOLINT
constexpr auto vsid1{bsl::safe_u16::magic_1()};    // NOLINT

hypercall::mv_hypercall_t mut_hvc{};    // NOLINT
bsl::safe_u64 hndl{};                   // NOLINT

namespace integration
{
#ifdef _WIN32
    /// <!-- description -->
    ///   @brief Sets the core affinity of the integration test
    ///
    /// <!-- inputs/outputs -->
    ///   @param core the core to run the integration test on.
    ///
    inline void
    set_affinity(bsl::safe_u64 const &core) noexcept
    {
        bsl::expects(SetProcessAffinityMask(GetCurrentProcess(), 1ULL << core.get()));
    }

    /// <!-- description -->
    ///   @brief lock the virtual address space into RAM, preventing that memory
    ///    from being paged to the swap area.
    ///
    /// <!-- inputs/outputs -->
    ///   @param addr the address to lock in memory
    ///   @param len the length in bytes
    ///
    inline void
    platform_mlock(void const *const addr, bsl::safe_u64 const &len) noexcept
    {
        bsl::expects(nullptr != addr);
        bsl::expects(0_u64 != len);

        bsl::print() << bsl::red << "platform_mlock not yet implemented";
        bsl::print() << bsl::rst << sloc;
        exit(1);
    }
#else
    /// <!-- description -->
    ///   @brief Sets the core affinity of the integration test
    ///
    /// <!-- inputs/outputs -->
    ///   @param core the core to run the integration test on.
    ///
    inline void
    set_affinity(bsl::safe_u64 const &core) noexcept
    {
        cpu_set_t mut_mask;

        CPU_ZERO(&mut_mask);               // NOLINT
        CPU_SET(core.get(), &mut_mask);    // NOLINT

        bsl::expects(0 == sched_setaffinity(0, sizeof(mut_mask), &mut_mask));
    }

    /// <!-- description -->
    ///   @brief lock the virtual address space into RAM, preventing that memory
    ///    from being paged to the swap area.
    ///
    /// <!-- inputs/outputs -->
    ///   @param addr the address to lock in memory
    ///   @param len the length in bytes
    ///
    inline void
    platform_mlock(void const *const addr, bsl::safe_u64 const &len) noexcept
    {
        bsl::expects(nullptr != addr);
        bsl::expects(0_u64 != len);
        bsl::expects(0 == mlock(addr, static_cast<size_t>(len.get())));
    }
#endif

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    constexpr void
    verify(bool const test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    constexpr void
    verify(bsl::errc_type const test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of bsl::safe_integral to test.
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    template<typename T>
    constexpr void
    verify(
        bsl::safe_integral<T> const &test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }
}

namespace hypercall
{
    /// @brief defines the shared page used for this test for core 0
    alignas(HYPERVISOR_PAGE_SIZE.get()) lib::basic_page_4k_t g_shared_page0{};    // NOLINT
    /// @brief defines the shared page used for this test for core 1
    alignas(HYPERVISOR_PAGE_SIZE.get()) lib::basic_page_4k_t g_shared_page1{};    // NOLINT

    /// <!-- description -->
    ///   @brief Returns bsl::to_u64(reinterpret_cast<bsl::uintmx>(ptr))
    ///
    /// <!-- inputs/outputs -->
    ///   @param ptr the pointer to convert to a bsl::safe_u64
    ///   @return Returns bsl::to_u64(reinterpret_cast<bsl::uintmx>(ptr))
    ///
    [[nodiscard]] constexpr auto
    to_u64(void const *const ptr) noexcept -> bsl::safe_u64
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return bsl::to_u64(reinterpret_cast<bsl::uintmx>(ptr));
    }

    /// <!-- description -->
    ///   @brief Returns reinterpret_cast<T *>(&g_shared_page0);
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to convert the shared page to
    ///   @return Returns reinterpret_cast<T *>(&g_shared_page0);
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_0() noexcept -> T *
    {
        return reinterpret_cast<T *>(&g_shared_page0);    // NOLINT
    }

    /// <!-- description -->
    ///   @brief Returns reinterpret_cast<T *>(&g_shared_page1);
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to convert the shared page to
    ///   @return Returns reinterpret_cast<T *>(&g_shared_page1);
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_1() noexcept -> T *
    {
        return reinterpret_cast<T *>(&g_shared_page1);    // NOLINT
    }

    /// <!-- description -->
    ///   @brief Returns the GPA of a provided pointer.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ptr the pointer to convert to a GPA
    ///   @param core the core # to use to perform the translation
    ///   @return Returns the GPA of a provided pointer.
    ///
    [[nodiscard]] constexpr auto
    to_gpa(void const *const ptr, bsl::safe_u64 const &core) noexcept -> bsl::safe_u64
    {
        integration::set_affinity(core);

        auto const trans{mut_hvc.mv_vs_op_gla_to_gpa(self, to_u64(ptr))};
        integration::verify(trans.is_valid);

        auto const gpa{trans.paddr};
        integration::verify(gpa.is_valid_and_checked());

        return gpa;
    }
}

namespace integration
{
    /// <!-- description -->
    ///   @brief Initializes the integration test's globals
    ///
    constexpr void
    initialize_globals() noexcept
    {
        constexpr auto tsc_khz{0x42_umx};

        hypercall::g_shared_page0 = {};
        hypercall::g_shared_page1 = {};

        integration::verify(mut_hvc.initialize());
        hndl = mut_hvc.handle();

        integration::set_affinity(core0);
        integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());
        integration::set_affinity(core1);
        integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());

        integration::set_affinity(core0);
        integration::verify(mut_hvc.mv_pp_op_tsc_set_khz(tsc_khz));
        integration::set_affinity(core1);
        integration::verify(mut_hvc.mv_pp_op_tsc_set_khz(tsc_khz));

        integration::set_affinity(core0);
    }

    /// <!-- description -->
    ///   @brief Initializes the shared pages.
    ///
    constexpr void
    initialize_shared_pages() noexcept
    {
        auto const gpa0{hypercall::to_gpa(&hypercall::g_shared_page0, core0)};
        auto const gpa1{hypercall::to_gpa(&hypercall::g_shared_page1, core1)};
        platform_mlock(&hypercall::g_shared_page0, HYPERVISOR_PAGE_SIZE);
        platform_mlock(&hypercall::g_shared_page1, HYPERVISOR_PAGE_SIZE);

        integration::set_affinity(core0);
        integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());
        integration::verify(mut_hvc.mv_pp_op_set_shared_page_gpa(gpa0));
        integration::set_affinity(core1);
        integration::verify(mut_hvc.mv_pp_op_clr_shared_page_gpa());
        integration::verify(mut_hvc.mv_pp_op_set_shared_page_gpa(gpa1));
        integration::set_affinity(core0);
    }

    /// <!-- description -->
    ///   @brief Initializes the register state of a VS to support a
    ///     16bit VM that starts at address 0.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VS to initialize
    ///
    constexpr void
    initialize_register_state_for_16bit_vm(bsl::safe_u16 const &vsid) noexcept
    {
        using namespace hypercall;    // NOLINT

        auto *const pmut_rdl{hypercall::to_0<hypercall::mv_rdl_t>()};
        integration::set_affinity(core0);

        constexpr auto total{3_idx};
        constexpr auto cs_sel_idx{0_idx};
        constexpr auto cs_base_idx{1_idx};
        constexpr auto rip_idx{2_idx};

        pmut_rdl->entries.at_if(cs_sel_idx)->reg = to_u64(mv_reg_t::mv_reg_t_cs_selector).get();
        pmut_rdl->entries.at_if(cs_sel_idx)->val = {};
        pmut_rdl->entries.at_if(cs_base_idx)->reg = to_u64(mv_reg_t::mv_reg_t_cs_base).get();
        pmut_rdl->entries.at_if(cs_base_idx)->val = {};
        pmut_rdl->entries.at_if(rip_idx)->reg = to_u64(mv_reg_t::mv_reg_t_rip).get();
        pmut_rdl->entries.at_if(rip_idx)->val = {};

        pmut_rdl->num_entries = total.get();
        integration::verify(mut_hvc.mv_vs_op_reg_set_list(vsid));
    }

    /// <!-- description -->
    ///   @brief Executes mv_vs_op_run until the first non-interrupt based
    ///     exit is seen and then returns this exit.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VS to run
    ///   @return Returns the first non-interrupt exit reason that is seen
    ///
    [[nodiscard]] constexpr auto
    run_until_non_interrupt_exit(bsl::safe_u16 const &vsid) noexcept -> hypercall::mv_exit_reason_t
    {
        while (true) {
            auto const exit_reason{mut_hvc.mv_vs_op_run(vsid)};
            switch (exit_reason) {
                case hypercall::mv_exit_reason_t::mv_exit_reason_t_interrupt: {
                    continue;
                }

                case hypercall::mv_exit_reason_t::mv_exit_reason_t_nmi: {
                    continue;
                }

                default: {
                    break;
                }
            }

            return exit_reason;
        }
    }

    /// <!-- description -->
    ///   @brief Loads a VM image given a file name
    ///
    /// <!-- inputs/outputs -->
    ///   @param filename the name of the VM image's file
    ///   @return the resulting VM image
    ///
    [[nodiscard]] constexpr auto
    load_vm(bsl::string_view const &filename) noexcept -> ifmap_t
    {
        ifmap_t mut_vm_image{filename};
        integration::verify(!mut_vm_image.empty());

        /// NOTE:
        /// - Quickly calculate the checksum of the VM image. This will
        ///   ensure that the image is in memory before we attempt to
        ///   get it's GLA. The right way to do this would be to lock
        ///   the memory in place using mlock or VirtualLock
        ///

        bsl::uint8 sum{};    // NOLINT
        for (bsl::safe_idx mut_i{}; mut_i < mut_vm_image.size(); ++mut_i) {
            sum += static_cast<bsl::uint8 const *>(mut_vm_image.data())[mut_i.get()];    // NOLINT
        }

        bsl::print() << "checksum ["                             // --
                     << bsl::cyn << filename << bsl::rst         // --
                     << "]: "                                    // --
                     << bsl::ylw << bsl::hex(sum) << bsl::rst    // --
                     << bsl::endl;                               // --

        auto const gpa{hypercall::to_gpa(mut_vm_image.data(), core0)};
        mut_vm_image.set_gpa(gpa);

        return mut_vm_image;
    }

    /// <!-- description -->
    ///   @brief Maps a VM image into a VM.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vm_image the VM image to map
    ///   @param phys the stating GPA when mapping the VM image
    ///   @param vmid the ID of the VM to map the image to
    ///
    constexpr void
    map_vm(ifmap_t const &vm_image, bsl::safe_u64 const &phys, bsl::safe_u16 const &vmid) noexcept
    {
        constexpr auto inc{bsl::to_idx(HYPERVISOR_PAGE_SIZE)};

        auto *const pmut_mdl{hypercall::to_0<hypercall::mv_mdl_t>()};
        integration::set_affinity(core0);

        pmut_mdl->num_entries = {};
        for (bsl::safe_idx mut_i{}; mut_i < vm_image.size(); mut_i += inc) {
            auto const dst{(phys + bsl::to_u64(mut_i)).checked()};
            auto const src{(vm_image.gpa() + bsl::to_u64(mut_i)).checked()};

            pmut_mdl->entries.at_if(bsl::to_idx(pmut_mdl->num_entries))->dst = dst.get();
            pmut_mdl->entries.at_if(bsl::to_idx(pmut_mdl->num_entries))->src = src.get();
            pmut_mdl->entries.at_if(bsl::to_idx(pmut_mdl->num_entries))->bytes = inc.get();
            ++pmut_mdl->num_entries;

            if (pmut_mdl->num_entries >= hypercall::MV_MDL_MAX_ENTRIES) {
                integration::verify(mut_hvc.mv_vm_op_mmio_map(vmid, self));
                pmut_mdl->num_entries = {};
            }
            else {
                bsl::touch();
            }
        }

        if (bsl::safe_u64::magic_0() != pmut_mdl->num_entries) {
            integration::verify(mut_hvc.mv_vm_op_mmio_map(vmid, self));
            pmut_mdl->num_entries = {};
        }
        else {
            bsl::touch();
        }
    }
}

#endif
