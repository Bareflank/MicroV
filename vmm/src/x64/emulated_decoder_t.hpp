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

#ifndef EMULATED_DECODER_T_HPP
#define EMULATED_DECODER_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// @class microv::emulated_decoder_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated decoder handler.
    ///
    ///   @note IMPORTANT: This class is a per-VS class, and attempts to
    ///     decode an instruction must come from this class. The most likely
    ///     source of instruction decodes will come from the LAPIC. This is
    ///     because a MMIO trap will occur for the LAPIC, and MicroV will
    ///     need to determine if the access is a read/write, and what LAPIC
    ///     register as well as which general purpose register is involved.
    ///
    ///   @note IMPORTANT: Take a look at the HyperV Top-Level Specification
    ///     and how it handles the LAPIC. Specifically, it states that any
    ///     access to the APIC must come from one of just a couple of supported
    ///     register combinations. Instead of taking this approach, this
    ///     code should handle any combination and return an instruction_t
    ///     that contains enums for the instruction opcode, src and dst
    ///     operands, etc. So for example, you would return:
    ///     - {mov, mem, rax, ptr} meaning mov [ptr], rax
    ///     - {mov, rax, mem, ptr} meaning mov rax, [ptr]
    ///     - {mov, rax, rbx} meaning mov rax, rbx
    ///
    ///     The instruction_t for this might look like:
    ///     @code
    ///     struct instruction_t final
    ///     {
    ///         instruction_opcode_t opcode;
    ///         instruction_operand_t dst;
    ///         instruction_operand_t src;
    ///         bsl::safe_umx gva;
    ///     };
    ///     @endcode
    ///
    ///     Only decode the things that MicroV actually needs to be able to
    ///     handle, and return an error otherwise. Once that is done, the LAPIC
    ///     code should map in the LAPIC associated with the guest VS and then
    ///     when a trap occurres, look at the address. If a decode has already
    ///     happened, just use the decode that has already been cached. If the
    ///     decode has not happened, use the emulated TLB to map the access
    ///     and the use this class to perform the decode and cache the results.
    ///     This prevents future LAPIC accesses from having to perform the
    ///     map and decode on every access. Simply look up the address and
    ///     then perform the access.
    ///
    ///   @note IMPORTANT: If a decode is cached, as it should be, any time
    ///     the guest executes a TLB flush instruction, this decode cache
    ///     must also be flushed. This is because the virtual address may
    ///     now point to a different physical address, in which case the
    ///     instruction that was decoded might be different. For an LAPIC
    ///     access, this is HIGHLY unlikely, but it is possible and would lead
    ///     to some pretty weird bugs.
    ///
    class emulated_decoder_t final
    {
        /// @brief stores the ID of the VS associated with this emulated_cpuid_t
        bsl::safe_u16 m_assigned_vsid{};

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
    };
}

#endif
