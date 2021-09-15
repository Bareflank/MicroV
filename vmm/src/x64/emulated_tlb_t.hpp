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

#ifndef EMULATED_TLB_T_HPP
#define EMULATED_TLB_T_HPP

#include <basic_page_table_t.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <mv_translation_t.hpp>
#include <pdpte_t.hpp>
#include <pdte_t.hpp>
#include <pml4te_t.hpp>
#include <pp_pool_t.hpp>
#include <pte_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/is_same.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::emulated_tlb_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated TLB handler.
    ///
    ///   @note IMPORTANT: This class is a per-VS class, and all attempts to
    ///     translate a GVA to a GPA for the guest should go through this
    ///     class so that the results can be cached, just like a real TLB
    ///     would do. This prevents the translation from happening over and
    ///     over when it doesn't need to.
    ///
    ///   @note IMPORTANT: Once the actual TLB is implemented here, if the
    ///     guest executes a TLB flush instruction, we need to flush our
    ///     emulated TLB, in addition to executing the instruction so that
    ///     hardware can do the same thing. Note that, if the guest execute
    ///     a invlpg instruction for example, this code would need to flush
    ///     the emulated TLB, and it would also need to run invvpid to ensure
    ///     the TLB is flushed for that virtual address, but only for that
    ///     specific VM (otherwise one VM could DoS another).
    ///
    class emulated_tlb_t final
    {
        /// @brief stores the ID of the VS associated with this emulated_tlb_t
        bsl::safe_u16 m_assigned_vsid{};

        /// <!-- description -->
        ///   @brief Returns the pml4t_t offset given a guest
        ///     linear address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gla the guest linear address to get the offset from.
        ///   @return the resulting offset from the guest linear address
        ///
        [[nodiscard]] static constexpr auto
        gla_to_pml4to(bsl::safe_u64 const &gla) noexcept -> bsl::safe_idx
        {
            constexpr auto mask{0x1FF_u64};
            constexpr auto shft{39_u64};
            return bsl::to_idx((gla >> shft) & mask);
        }

        /// <!-- description -->
        ///   @brief Returns the pdpt_t offset given a guest
        ///     linear address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gla the guest linear address to get the offset from.
        ///   @return the resulting offset from the guest linear address
        ///
        [[nodiscard]] static constexpr auto
        gla_to_pdpto(bsl::safe_u64 const &gla) noexcept -> bsl::safe_idx
        {
            constexpr auto mask{0x1FF_u64};
            constexpr auto shft{30_u64};
            return bsl::to_idx((gla >> shft) & mask);
        }

        /// <!-- description -->
        ///   @brief Returns the pdt_t offset given a guest
        ///     linear address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gla the guest linear address to get the offset from.
        ///   @return the resulting offset from the guest linear address
        ///
        [[nodiscard]] static constexpr auto
        gla_to_pdto(bsl::safe_u64 const &gla) noexcept -> bsl::safe_idx
        {
            constexpr auto mask{0x1FF_u64};
            constexpr auto shft{21_u64};
            return bsl::to_idx((gla >> shft) & mask);
        }

        /// <!-- description -->
        ///   @brief Returns the pt_t offset given a guest
        ///     linear address.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gla the guest linear address to get the offset from.
        ///   @return the resulting offset from the guest linear address
        ///
        [[nodiscard]] static constexpr auto
        gla_to_pto(bsl::safe_u64 const &gla) noexcept -> bsl::safe_idx
        {
            constexpr auto mask{0x1FF_u64};
            constexpr auto shft{12_u64};
            return bsl::to_idx((gla >> shft) & mask);
        }

        /// <!-- description -->
        ///   @brief Returns a copy of the requested pml4t_t entry. We return a
        ///     copy because a pml4t_t entry is only 64bits, and holding
        ///     onto a pointer would require that we hold onto the map. To
        ///     prevent this, we simply return a copy, which releases the map
        ///     on exit. This ensures that we are only holding one map at any
        ///     given time, and a copy of 64bits is fast.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gla the GLA to translate to a GPA
        ///   @param gla_pml4t the GLA of the pml4t_t to get the entry from
        ///   @return Returns a copy of the requested pml4t_t entry
        ///
        [[nodiscard]] static constexpr auto
        get_pml4te(
            syscall::bf_syscall_t &mut_sys,
            pp_pool_t &mut_pp_pool,
            bsl::safe_u64 const &gla,
            bsl::safe_u64 const &gla_pml4t) noexcept -> pml4te_t
        {
            using table_t = lib::basic_page_table_t<pml4te_t const>;

            bsl::expects(gla.is_valid_and_checked());
            bsl::expects(hypercall::mv_is_page_aligned(gla));
            bsl::expects(gla_pml4t.is_valid_and_checked());
            bsl::expects(hypercall::mv_is_page_aligned(gla_pml4t));

            if (bsl::unlikely(gla_pml4t.is_zero())) {
                bsl::error() << "get_pml4te for gla "                               // --
                             << bsl::hex(gla)                                       // --
                             << " failed because the gpa of the pml4t_t is NULL"    // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return {};
            }

            auto const pml4t{mut_pp_pool.map<table_t const>(mut_sys, gla_pml4t)};
            if (bsl::unlikely(pml4t.is_invalid())) {
                bsl::error() << "get_pml4te for gla "                    // --
                             << bsl::hex(gla)                            // --
                             << " failed attempting to map the pml4t"    // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return {};
            }

            return *(pml4t->entries.at_if(gla_to_pml4to(gla)));
        }

        /// <!-- description -->
        ///   @brief Returns a copy of the requested pdpt_t entry. We return a
        ///     copy because a pdpt_t entry is only 64bits, and holding
        ///     onto a pointer would require that we hold onto the map. To
        ///     prevent this, we simply return a copy, which releases the map
        ///     on exit. This ensures that we are only holding one map at any
        ///     given time, and a copy of 64bits is fast.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gla the GLA to translate to a GPA
        ///   @param gla_pdpt the GLA of the pdpt_t to get the entry from
        ///   @return Returns a copy of the requested pdpt_t entry
        ///
        [[nodiscard]] static constexpr auto
        get_pdpte(
            syscall::bf_syscall_t &mut_sys,
            pp_pool_t &mut_pp_pool,
            bsl::safe_u64 const &gla,
            bsl::safe_u64 const &gla_pdpt) noexcept -> pdpte_t
        {
            using table_t = lib::basic_page_table_t<pdpte_t const>;

            bsl::expects(gla.is_valid_and_checked());
            bsl::expects(hypercall::mv_is_page_aligned(gla));
            bsl::expects(gla_pdpt.is_valid_and_checked());
            bsl::expects(hypercall::mv_is_page_aligned(gla_pdpt));

            if (bsl::unlikely(gla_pdpt.is_zero())) {
                bsl::error() << "get_pdpte for gla "                               // --
                             << bsl::hex(gla)                                      // --
                             << " failed because the gpa of the pdpt_t is NULL"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return {};
            }

            auto const pdpt{mut_pp_pool.map<table_t const>(mut_sys, gla_pdpt)};
            if (bsl::unlikely(pdpt.is_invalid())) {
                bsl::error() << "get_pdpte for gla "                    // --
                             << bsl::hex(gla)                           // --
                             << " failed attempting to map the pdpt"    // --
                             << bsl::endl                               // --
                             << bsl::here();                            // --

                return {};
            }

            return *(pdpt->entries.at_if(gla_to_pdpto(gla)));
        }

        /// <!-- description -->
        ///   @brief Returns a copy of the requested pdt_t entry. We return a
        ///     copy because a pdt_t entry is only 64bits, and holding
        ///     onto a pointer would require that we hold onto the map. To
        ///     prevent this, we simply return a copy, which releases the map
        ///     on exit. This ensures that we are only holding one map at any
        ///     given time, and a copy of 64bits is fast.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gla the GLA to translate to a GPA
        ///   @param gla_pdt the GLA of the pdt_t to get the entry from
        ///   @return Returns a copy of the requested pdt_t entry
        ///
        [[nodiscard]] static constexpr auto
        get_pdte(
            syscall::bf_syscall_t &mut_sys,
            pp_pool_t &mut_pp_pool,
            bsl::safe_u64 const &gla,
            bsl::safe_u64 const &gla_pdt) noexcept -> pdte_t
        {
            using table_t = lib::basic_page_table_t<pdte_t const>;

            bsl::expects(gla.is_valid_and_checked());
            bsl::expects(hypercall::mv_is_page_aligned(gla));
            bsl::expects(gla_pdt.is_valid_and_checked());
            bsl::expects(hypercall::mv_is_page_aligned(gla_pdt));

            if (bsl::unlikely(gla_pdt.is_zero())) {
                bsl::error() << "get_pdte for gla "                               // --
                             << bsl::hex(gla)                                     // --
                             << " failed because the gpa of the pdt_t is NULL"    // --
                             << bsl::endl                                         // --
                             << bsl::here();                                      // --

                return {};
            }

            auto const pdt{mut_pp_pool.map<table_t const>(mut_sys, gla_pdt)};
            if (bsl::unlikely(pdt.is_invalid())) {
                bsl::error() << "get_pdte for gla "                    // --
                             << bsl::hex(gla)                          // --
                             << " failed attempting to map the pdt"    // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return {};
            }

            return *(pdt->entries.at_if(gla_to_pdto(gla)));
        }

        /// <!-- description -->
        ///   @brief Returns a copy of the requested pt_t entry. We return a
        ///     copy because a pt_t entry is only 64bits, and holding
        ///     onto a pointer would require that we hold onto the map. To
        ///     prevent this, we simply return a copy, which releases the map
        ///     on exit. This ensures that we are only holding one map at any
        ///     given time, and a copy of 64bits is fast.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gla the GLA to translate to a GPA
        ///   @param gla_pt the GLA of the pt_t to get the entry from
        ///   @return Returns a copy of the requested pt_t entry
        ///
        [[nodiscard]] static constexpr auto
        get_pte(
            syscall::bf_syscall_t &mut_sys,
            pp_pool_t &mut_pp_pool,
            bsl::safe_u64 const &gla,
            bsl::safe_u64 const &gla_pt) noexcept -> pte_t
        {
            using table_t = lib::basic_page_table_t<pte_t const>;

            bsl::expects(gla.is_valid_and_checked());
            bsl::expects(hypercall::mv_is_page_aligned(gla));
            bsl::expects(gla_pt.is_valid_and_checked());
            bsl::expects(hypercall::mv_is_page_aligned(gla_pt));

            if (bsl::unlikely(gla_pt.is_zero())) {
                bsl::error() << "get_pte for gla "                               // --
                             << bsl::hex(gla)                                    // --
                             << " failed because the gpa of the pt_t is NULL"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return {};
            }

            auto const pt{mut_pp_pool.map<table_t const>(mut_sys, gla_pt)};
            if (bsl::unlikely(pt.is_invalid())) {
                bsl::error() << "get_pte for gla "                    // --
                             << bsl::hex(gla)                         // --
                             << " failed attempting to map the pt"    // --
                             << bsl::endl                             // --
                             << bsl::here();                          // --

                return {};
            }

            return *(pt->entries.at_if(gla_to_pto(gla)));
        }

        /// <!-- description -->
        ///   @brief Returns the paddr field of a mv_translation_t
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of entry to get the paddr from
        ///   @param entry the entry to get the paddr from
        ///   @return Returns the paddr field of a mv_translation_t
        ///
        template<typename T>
        [[nodiscard]] static constexpr auto
        get_paddr(T const &entry) noexcept -> bsl::safe_u64
        {
            return entry.phys << HYPERVISOR_PAGE_SHIFT;
        }

        /// <!-- description -->
        ///   @brief Returns the flags field of a mv_translation_t
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of entry to get the flags from
        ///   @param entry the entry to get the flags from
        ///   @return Returns the flags field of a mv_translation_t
        ///
        template<typename T>
        [[nodiscard]] static constexpr auto
        get_flags(T const &entry) noexcept -> bsl::safe_u64
        {
            bsl::safe_u64 mut_flags{hypercall::MV_MAP_FLAG_READ_ACCESS};

            if constexpr (bsl::is_same<T, pdpte_t>::value) {
                mut_flags |= hypercall::MV_MAP_FLAG_1G_PAGE;
            }

            if constexpr (bsl::is_same<T, pdte_t>::value) {
                mut_flags |= hypercall::MV_MAP_FLAG_2M_PAGE;
            }

            if constexpr (bsl::is_same<T, pte_t>::value) {
                mut_flags |= hypercall::MV_MAP_FLAG_4K_PAGE;
            }

            constexpr auto is_writeable{1_u64};
            if (is_writeable == entry.rw) {
                mut_flags |= hypercall::MV_MAP_FLAG_WRITE_ACCESS;
            }
            else {
                bsl::touch();
            }

            constexpr auto is_executable{0_u64};
            if (is_executable == entry.nx) {
                mut_flags |= hypercall::MV_MAP_FLAG_EXECUTE_ACCESS;
            }
            else {
                bsl::touch();
            }

            constexpr auto is_user{1_u64};
            if (is_user == entry.us) {
                mut_flags |= hypercall::MV_MAP_FLAG_USER;
            }
            else {
                bsl::touch();
            }

            return mut_flags;
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this emulated_tlb_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_tlb_t
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
        ///   @brief Release the emulated_tlb_t.
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
        ///   @brief Returns the ID of the PP associated with this
        ///     emulated_tlb_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     emulated_tlb_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vsid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vsid.is_valid_and_checked());
            return ~m_assigned_vsid;
        }

        /// <!-- description -->
        ///   @brief Translates a guest GLA to a guest GPA using the paging
        ///     configuration of the guest stored in CR0, CR3 and CR4.
        ///
        /// <!-- notes -->
        ///   @note This function is slow. It has to map in guest page tables
        ///     so that it can walk these tables and perform the translation.
        ///     Once the translation is done, these translations are unmapped.
        ///     If we didn't do this, the direct map would become polluted with
        ///     maps that are no longer needed, and these maps may eventually
        ///     point to memory used by the guest to store a secret.
        ///
        ///   @note IMPORTANT: One way to improve performance of code that
        ///     uses this function is to cache these translations. This would
        ///     implement a virtual TLB. You might not call it that, but that
        ///     is what it is. If we store ANY translations, we must clear
        ///     them when the guest attempts to perform any TLB invalidations,
        ///     as the translation might not be valid any more. This is made
        ///     even worse with remote TLB invalidations that the guest
        ///     performs because the hypervisor has to mimic the same behaviour
        ///     that any race conditions introduce. For example, if we are in
        ///     the middle of emulating an instruction on one CPU, and another
        ///     performs an invalidation, emulation needs to complete before
        ///     the invalidation takes place. Otherwise, a use-after-free
        ///     bug could occur. This only applies to the decoding portion of
        ///     emulation as the CPU is pipelined. Reads/writes to memory
        ///     during the rest of emulation may still read garbage, and that
        ///     is what the CPU would do. To simplify this, all translations
        ///     should ALWAYS come from this function. Meaning, if a translation
        ///     must be stored, it should be stored here in a virtual TLB. This
        ///     way, any invalidations to a VS can be flushed in the VS. If
        ///     all functions always have to call this function, it will simply
        ///     return a cached translation. If the cache is flushed because
        ///     the guest performed a flush, the required TLB update will
        ///     automatically happen. This way, software always does the GLA
        ///     to GPA conversion when it is needed, and only when it is needed
        ///     the same way the hardware would. DO NOT CACHE THE RESULTS OF
        ///     THIS FUNCTION. YOU MUST ALWAYS CALL THIS FUNCTION EVERYTIME
        ///     A TRANSLATION IS NEEDED.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param mut_pp_pool the pp_pool_t to use
        ///   @param gla the GLA to translate to a GPA
        ///   @param cr0 the CR0 to use for translation
        ///   @param cr3 the CR3 to use for translation
        ///   @param cr4 the CR4 to use for translation
        ///   @return Returns mv_translation_t containing the results of the
        ///     translation.
        ///
        [[nodiscard]] constexpr auto
        gla_to_gpa(
            syscall::bf_syscall_t &mut_sys,
            pp_pool_t &mut_pp_pool,
            bsl::safe_u64 const &gla,
            bsl::safe_u64 const &cr0,
            bsl::safe_u64 const &cr3,
            bsl::safe_u64 const &cr4) const noexcept -> hypercall::mv_translation_t
        {
            bsl::expects(this->assigned_vsid() == mut_sys.bf_tls_vsid());

            bsl::expects(gla.is_valid_and_checked());
            bsl::expects(gla.is_pos());
            bsl::expects(cr0.is_valid_and_checked());
            bsl::expects(cr0.is_pos());
            bsl::expects(cr3.is_valid_and_checked());
            bsl::expects(cr3.is_pos());
            bsl::expects(cr4.is_valid_and_checked());
            bsl::expects(cr4.is_pos());

            /// NOTE:
            /// - This function needs a pretty wide contract as inputs to
            ///   this function will come from any VM (meaning don't use
            ///   bsl::expects unless you are sure the input has been
            ///   scrubbed using a wide contract from some other location)
            ///

            /// TODO:
            /// - Add support for 16bit real mode
            /// - Add support for 32bit protected mode with paging disabled
            /// - Add support for 32bit protected mode with paging, without PAE
            /// - Add support for 32bit protected mode with paging, with PAE
            ///

            auto const pml4t_gpa{hypercall::mv_page_aligned(cr3)};
            auto const pml4te{get_pml4te(mut_sys, mut_pp_pool, gla, pml4t_gpa)};
            if (bsl::unlikely(bsl::safe_umx::magic_0() == pml4te.phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return {};
            }

            if (bsl::unlikely(bsl::safe_umx::magic_0() == pml4te.p)) {
                bsl::error() << "gla_to_gpa failed because the pml4te for gla "    // --
                             << bsl::hex(gla)                                      // --
                             << " is not marked present"                           // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return {};
            }

            auto const pdpt_gpa{pml4te.phys << HYPERVISOR_PAGE_SHIFT};
            auto const pdpte{get_pdpte(mut_sys, mut_pp_pool, gla, pdpt_gpa)};
            if (bsl::unlikely(bsl::safe_umx::magic_0() == pdpte.phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return {};
            }

            if (bsl::unlikely(bsl::safe_umx::magic_0() == pdpte.p)) {
                bsl::error() << "gla_to_gpa failed because the pdpte for gla "    // --
                             << bsl::hex(gla)                                     // --
                             << " is not marked present"                          // --
                             << bsl::endl                                         // --
                             << bsl::here();                                      // --

                return {};
            }

            if (bsl::safe_umx::magic_1() == pdpte.ps) {
                return {{}, gla, get_paddr(pdpte), get_flags(pdpte), true};
            }

            auto const pdt_gpa{pdpte.phys << HYPERVISOR_PAGE_SHIFT};
            auto const pdte{get_pdte(mut_sys, mut_pp_pool, gla, pdt_gpa)};
            if (bsl::unlikely(bsl::safe_umx::magic_0() == pdte.phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return {};
            }

            if (bsl::unlikely(bsl::safe_umx::magic_0() == pdte.p)) {
                bsl::error() << "gla_to_gpa failed because the pdte for gla "    // --
                             << bsl::hex(gla)                                    // --
                             << " is not marked present"                         // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return {};
            }

            if (bsl::safe_umx::magic_1() == pdte.ps) {
                return {{}, gla, get_paddr(pdte), get_flags(pdte), true};
            }

            auto const pt_gpa{pdte.phys << HYPERVISOR_PAGE_SHIFT};
            auto const pte{get_pte(mut_sys, mut_pp_pool, gla, pt_gpa)};
            if (bsl::unlikely(bsl::safe_umx::magic_0() == pte.phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return {};
            }

            if (bsl::unlikely(bsl::safe_umx::magic_0() == pte.p)) {
                bsl::error() << "gla_to_gpa failed because the pte for gla "    // --
                             << bsl::hex(gla)                                   // --
                             << " is not marked present"                        // --
                             << bsl::endl                                       // --
                             << bsl::here();                                    // --

                return {};
            }

            return {{}, gla, get_paddr(pte), get_flags(pte), true};
        }
    };
}

#endif
