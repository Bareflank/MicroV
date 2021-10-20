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

#ifndef EMULATED_CPUID_T_HPP
#define EMULATED_CPUID_T_HPP

#include <bf_syscall_t.hpp>
#include <cpuid_commands.hpp>
#include <errc_types.hpp>
#include <gs_t.hpp>
#include <mv_cdl_entry_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::emulated_cpuid_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated CPUID handler.
    ///
    ///   @note IMPORTANT: This class is a per-VS class, and all accesses
    ///     to CPUID from a VM (root or guest) must come from this class.
    ///
    class emulated_cpuid_t final
    {
        /// @brief stores the ID of the VS associated with this emulated_cpuid_t
        bsl::safe_u16 m_assigned_vsid{};

        /// @brief stores the standard CPUID leaves
        bsl::array<
            bsl::array<hypercall::mv_cdl_entry_t, CPUID_NUM_STD_INDEXES.get()>,
            CPUID_NUM_STD_FUNCTIONS.get()>
            m_std_leaves{};
        /// @brief stores the extended CPUID leaves
        bsl::array<
            bsl::array<hypercall::mv_cdl_entry_t, CPUID_NUM_EXT_INDEXES.get()>,
            CPUID_NUM_EXT_FUNCTIONS.get()>
            m_ext_leaves{};

        /// <!-- description -->
        ///   @brief Sets up a leaf
        ///
        /// <!-- inputs/outputs -->
        ///   @param fun the CPUID function to use
        ///   @param idx the CPUID index to use
        ///   @param eax_mask the mask applied to the EAX register
        ///   @param eax_enable_mask the enable mask applied to the EAX register
        ///   @param ebx_mask the mask applied to the EBX register
        ///   @param ebx_enable_mask the enable mask applied to the EBX register
        ///   @param ecx_mask the mask applied to the ECX register
        ///   @param ecx_enable_mask the enable mask applied to the ECX register
        ///   @param edx_mask the mask applied to the EDX register
        ///   @param edx_enable_mask the enable mask applied to the EDX register
        ///
        constexpr void
        setup_leaf(
            bsl::safe_u32 const &fun,
            bsl::safe_u64 const &idx,
            bsl::safe_u64 const &eax_mask,
            bsl::safe_u64 const &eax_enable_mask,
            bsl::safe_u64 const &ebx_mask,
            bsl::safe_u64 const &ebx_enable_mask,
            bsl::safe_u64 const &ecx_mask,
            bsl::safe_u64 const &ecx_enable_mask,
            bsl::safe_u64 const &edx_mask,
            bsl::safe_u64 const &edx_enable_mask) noexcept
        {
            auto const idx_i{bsl::to_idx(idx)};

            hypercall::mv_cdl_entry_t *pmut_mut_entry{};

            if (fun < CPUID_FN8000_0000) {
                auto const fun_i{bsl::to_idx(fun)};
                pmut_mut_entry = m_std_leaves.at_if(fun_i)->at_if(idx_i);
            }
            else {
                auto const fun_i{bsl::to_idx((fun - CPUID_FN8000_0000).checked())};
                pmut_mut_entry = m_ext_leaves.at_if(fun_i)->at_if(idx_i);
            }

            auto mut_eax{bsl::to_u64(fun)};
            bsl::safe_u64 mut_ebx{};
            auto mut_ecx{idx};
            bsl::safe_u64 mut_edx{};

            intrinsic_t::cpuid(mut_eax, mut_ebx, mut_ecx, mut_edx);

            pmut_mut_entry->fun = fun.get();
            pmut_mut_entry->idx = bsl::to_u32_unsafe(idx).get();
            pmut_mut_entry->eax = bsl::to_u32_unsafe(((mut_eax)&eax_mask) | eax_enable_mask).get();
            pmut_mut_entry->ebx = bsl::to_u32_unsafe(((mut_ebx)&ebx_mask) | ebx_enable_mask).get();
            pmut_mut_entry->ecx = bsl::to_u32_unsafe(((mut_ecx)&ecx_mask) | ecx_enable_mask).get();
            pmut_mut_entry->edx = bsl::to_u32_unsafe(((mut_edx)&edx_mask) | edx_enable_mask).get();
        }

        /// <!-- description -->
        ///   @brief Prints a leaf
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T The type to query
        ///   @param output to output to use, e.g. bsl::debug()
        ///   @param entry the mv_cdl_entry_t to read the CPUID from
        ///   @param loc the location of the call site
        ///
        template<typename T>
        static constexpr void
        print_leaf(
            bsl::out<T> const &output,
            hypercall::mv_cdl_entry_t const &entry,
            bsl::source_location const &loc = bsl::here()) noexcept
        {
            constexpr auto upper16{16_u32};
            output << "CPUID leaf Fn"                                                    // --
                   << bsl::fmt("04x", bsl::to_u16_unsafe(entry.fun >> upper16.get()))    // --
                   << "_"                                                                // --
                   << bsl::fmt("04x", bsl::to_u16_unsafe(entry.fun))                     // --
                   << "h ["                                                              // --
                   << bsl::fmt("02x", bsl::to_u16_unsafe(entry.idx))                     // --
                   << "] "                                                               // --
                   << "["                                                                // --
                   << bsl::hex(entry.eax)                                                // --
                   << ":"                                                                // --
                   << bsl::hex(entry.ebx)                                                // --
                   << ":"                                                                // --
                   << bsl::hex(entry.ecx)                                                // --
                   << ":"                                                                // --
                   << bsl::hex(entry.edx)                                                // --
                   << "] was requested\n"                                                // --
                   << loc;                                                               // --
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this emulated_cpuid_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_cpuid_t
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) noexcept
        {
            bsl::expects(this->assigned_vsid() == syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_vsid = ~vsid;
        }

        /// <!-- description -->
        ///   @brief Release the emulated_cpuid_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_vsid = {};
        }

        /// <!-- description -->
        ///   @brief Allocates the emulated_cpuid_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_cpuid_t
        ///
        ///
        constexpr void
        allocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            bsl::expects(vsid != syscall::BF_INVALID_ID);
            bsl::expects(vsid == this->assigned_vsid());

            constexpr auto z{0_u64};
            constexpr auto m{bsl::safe_u64::max_value()};

            // clang-format off
            setup_leaf(CPUID_FN0000_0000, z, m, z, m, z, m, z, m, z);

            setup_leaf(
                CPUID_FN0000_0001, z,
                m, z,
                m, z,
                CPUID_FN0000_0001_ECX, CPUID_FN0000_0001_ECX_HYPERVISOR_BIT,
                CPUID_FN0000_0001_EDX, z);

            setup_leaf(CPUID_FN8000_0000, z, m, z, m, z, m, z, m, z);

            setup_leaf(
                CPUID_FN8000_0001, z,
                m, z,
                z, z,
                CPUID_FN8000_0001_ECX, z,
                CPUID_FN8000_0001_EDX, z);

            setup_leaf(CPUID_FN8000_0002, z, m, z, m, z, m, z, m, z);
            setup_leaf(CPUID_FN8000_0003, z, m, z, m, z, m, z, m, z);
            setup_leaf(CPUID_FN8000_0004, z, m, z, m, z, m, z, m, z);
            // clang-format on
        }

        /// <!-- description -->
        ///   @brief Deallocates the emulated_cpuid_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_cpuid_t
        ///
        ///
        constexpr void
        deallocate(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) const noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            bsl::expects(vsid != syscall::BF_INVALID_ID);
            bsl::expects(vsid == this->assigned_vsid());
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     emulated_cpuid_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     emulated_cpuid_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vsid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vsid.is_valid_and_checked());
            return ~m_assigned_vsid;
        }

        /// <!-- description -->
        ///   @brief Reads CPUID on the physical processor using the values
        ///     stored in the eax, ebx, ecx, and edx registers provided by the
        ///     syscall layer and stores the results in the same registers.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise. If the PP was asked to promote the VS,
        ///     vmexit_success_promote is returned.
        ///
        [[nodiscard]] static constexpr auto
        get_root(syscall::bf_syscall_t &mut_sys, intrinsic_t const &intrinsic) noexcept
            -> bsl::errc_type
        {
            auto mut_rax{mut_sys.bf_tls_rax()};
            auto mut_rcx{mut_sys.bf_tls_rcx()};

            /// TODO:
            /// - If the hypervisor feature bit is read, we need to report
            ///   that a hypervisor is running. This is needed to ensure
            ///   that the vmcall instruction is ok to execute.
            ///

            if (loader::CPUID_COMMAND_EAX == bsl::to_u32_unsafe(mut_rax)) {
                switch (bsl::to_u32_unsafe(mut_rcx).get()) {
                    case loader::CPUID_COMMAND_ECX_STOP.get(): {
                        bsl::debug() << bsl::rst << "about to"                         // --
                                     << bsl::red << " promote "                        // --
                                     << bsl::rst << "root OS on pp "                   // --
                                     << bsl::cyn << bsl::hex(mut_sys.bf_tls_ppid())    // --
                                     << bsl::rst << bsl::endl;                         // --

                        mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                        return vmexit_success_promote;
                    }

                    case loader::CPUID_COMMAND_ECX_REPORT_ON.get(): {
                        bsl::debug() << bsl::rst << "root OS had been"                 // --
                                     << bsl::grn << " demoted "                        // --
                                     << bsl::rst << "to vm "                           // --
                                     << bsl::cyn << bsl::hex(mut_sys.bf_tls_vmid())    // --
                                     << bsl::rst << " on pp "                          // --
                                     << bsl::cyn << bsl::hex(mut_sys.bf_tls_ppid())    // --
                                     << bsl::rst << bsl::endl;                         // --

                        mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                        return bsl::errc_success;
                    }

                    case loader::CPUID_COMMAND_ECX_REPORT_OFF.get(): {
                        mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                        return bsl::errc_success;
                    }

                    default: {
                        break;
                    }
                }

                bsl::error() << "unsupported cpuid command "    // --
                             << bsl::hex(mut_rcx)               // --
                             << bsl::endl                       // --
                             << bsl::here();                    // --

                mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_FAILURE);
                return bsl::errc_failure;
            }

            auto const old_rax{mut_rax};

            auto mut_rbx{mut_sys.bf_tls_rbx()};
            auto mut_rdx{mut_sys.bf_tls_rdx()};
            intrinsic.cpuid(mut_rax, mut_rbx, mut_rcx, mut_rdx);

            constexpr auto fn0000_00001{0x00000001_u32};
            if (fn0000_00001 == bsl::to_u32_unsafe(old_rax)) {
                constexpr auto hypervisor_bit{0x0000000080000000_u64};
                mut_rcx |= hypervisor_bit;
            }
            else {
                bsl::touch();
            }

            mut_sys.bf_tls_set_rax(mut_rax);
            mut_sys.bf_tls_set_rbx(mut_rbx);
            mut_sys.bf_tls_set_rcx(mut_rcx);
            mut_sys.bf_tls_set_rdx(mut_rdx);

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Reads CPUID on the physical processor using the values
        ///     stored in the eax, ebx, ecx, and edx registers provided by the
        ///     syscall layer and stores the results in the same registers.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise. If the PP was asked to promote the VS,
        ///     vmexit_success_promote is returned.
        ///
        [[nodiscard]] static constexpr auto
        get(syscall::bf_syscall_t const &sys, intrinsic_t const &intrinsic) noexcept
            -> bsl::errc_type
        {
            bsl::discard(sys);
            bsl::discard(intrinsic);

            /// NOTE:
            /// - Create an array: mv_cpuid_leaf_t[max_functions][max_indexes].
            ///   The reason that this is 2-d is that some require
            /// - CPUID is actually in the hotpath, so yes, this takes up
            ///   a bunch of memory that will be wasted, but it is really
            ///   fast because you can just use a simple array lookup.
            /// - Initialize this array in the initialize function.
            ///
            /// - For get(), you simply return what is in the array.
            /// - For set(), you change what is in the array, but you are
            ///   only allowed to reduce capabilities, meaning once the
            ///   array is initialized, set can only zero out a feature,
            ///   it cannot add a 1. Set also cannot change certain
            ///   cpuid leaves. For now, we should only support the
            ///   ability to set features. Everything else should throw
            ///   an error. This might be an issue with the APIC topology
            ///   stuff, but address that if it happens. Keep it simple
            ///   unless QEMU requires more.
            ///

            /// NOTE:
            /// - For supported(), permissable() and emulated(), that code
            ///   belongs in the PP, but, it needs to be in sync with this
            ///   code, so any changes that change these functions needs
            ///   to be keep in sync.
            ///

            /// NOTE:
            /// - Don't forget about the hypervisor bit. See root code for
            ///   example. The hypervisor bit should be initialized, meaning
            ///   don't calculate it like we do with the root.
            ///

            bsl::error() << "get not implemented\n" << bsl::here();
            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Returns the requested CPUID leaf (mv_cdl_entry_t.fun and
        ///     mv_cdl_entry_t.idx) into the eax, ebx, ecx, and edx registers of
        ///     the CDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_entry the mv_cdl_entry_t to read the CPUID from
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        get(syscall::bf_syscall_t const &sys, hypercall::mv_cdl_entry_t &mut_entry) const noexcept
            -> bsl::errc_type
        {
            bsl::discard(sys);

            using leaves_type = decltype(m_std_leaves);
            leaves_type const *mut_leaves{};
            if (mut_entry.fun < CPUID_FN8000_0000.get()) {
                mut_leaves = &m_std_leaves;
            }
            else {
                mut_leaves = &m_ext_leaves;
            }

            for (auto const &leaves_idx : *mut_leaves) {
                if (leaves_idx.at_if(bsl::safe_idx::magic_0())->fun != mut_entry.fun) {
                    continue;
                }

                for (auto const &leaf : leaves_idx) {
                    if (leaf.idx != mut_entry.idx) {
                        continue;
                    }

                    mut_entry.eax = leaf.eax;
                    mut_entry.ebx = leaf.ebx;
                    mut_entry.ecx = leaf.ecx;
                    mut_entry.edx = leaf.edx;

                    return bsl::errc_success;
                }
            }

            print_leaf(bsl::error(), mut_entry);

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Sets the requested CPUID leaves with the eax, ebx, ecx, and
        ///     edx registers given by the CDL. It reducing capabilities is
        ///     allowed.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param entry the mv_cdl_entry_t to read the CPUID from
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        set(syscall::bf_syscall_t const &sys, hypercall::mv_cdl_entry_t const &entry) noexcept
            -> bsl::errc_type
        {
            bsl::discard(sys);

            auto mut_i{bsl::to_idx(entry.fun)};
            if (mut_i >= bsl::to_idx(CPUID_FN8000_0000)) {
                mut_i -= bsl::to_idx(CPUID_FN8000_0000);
            }
            else {
                bsl::touch();
            }

            constexpr auto cpuid_index_0{0_u64};
            constexpr auto upper32{32_u64};
            auto const req{(bsl::to_u64(entry.fun) << upper32) | bsl::to_u64(entry.idx)};

            switch (req.get()) {

                case ((bsl::to_u64(CPUID_FN0000_0001) << upper32) | cpuid_index_0).get(): {
                    auto *const pmut_entry{
                        m_std_leaves.at_if(mut_i)->at_if(bsl::to_idx(entry.idx))};
                    if (entry.eax != bsl::safe_u32::magic_0()) {
                        break;
                    }
                    if (entry.ebx != bsl::safe_u32::magic_0()) {
                        break;
                    }

                    pmut_entry->ecx &= entry.ecx;
                    pmut_entry->edx &= entry.edx;

                    return bsl::errc_success;
                }

                case ((bsl::to_u64(CPUID_FN8000_0001) << upper32) | cpuid_index_0).get(): {
                    auto *const pmut_entry{
                        m_ext_leaves.at_if(mut_i)->at_if(bsl::to_idx(entry.idx))};
                    if (entry.eax != bsl::safe_u32::magic_0()) {
                        break;
                    }
                    if (entry.ebx != bsl::safe_u32::magic_0()) {
                        break;
                    }

                    pmut_entry->ecx &= entry.ecx;
                    pmut_entry->edx &= entry.edx;

                    return bsl::errc_success;
                }

                default: {
                    break;
                }
            }

            print_leaf(bsl::error(), entry);

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Reads the requested CPUID function and index given by the
        ///     CDL into the eax, ebx, ecx, and edx registers of the CDL.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param mut_cdl the mv_cdl_t to read the CPUID into
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        get_list(syscall::bf_syscall_t const &sys, hypercall::mv_cdl_t &mut_cdl) const noexcept
            -> bsl::errc_type
        {
            bsl::discard(sys);
            bsl::discard(mut_cdl);

            for (bsl::safe_idx mut_i{}; mut_i < mut_cdl.num_entries; ++mut_i) {
                if (bsl::unlikely(!get(sys, *mut_cdl.entries.at_if(mut_i)))) {
                    bsl::error() << "get_list failed\n" << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the requested CPUID leaves with the eax, ebx, ecx, and
        ///     edx registers given by the CDL. It reducing capabilities is
        ///     allowed.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param cdl the mv_cdl_entry_t to read the CPUID into
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise.
        ///
        [[nodiscard]] constexpr auto
        set_list(syscall::bf_syscall_t const &sys, hypercall::mv_cdl_t const &cdl) noexcept
            -> bsl::errc_type
        {
            for (bsl::safe_idx mut_i{}; mut_i < cdl.num_entries; ++mut_i) {
                auto const &entry{*cdl.entries.at_if(mut_i)};
                if (bsl::unlikely(!set(sys, entry))) {
                    bsl::error() << "Set CPUID failed\n" << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }
    };
}

#endif
