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

#ifndef DISPATCH_VMCALL_ABI_HELPERS
#define DISPATCH_VMCALL_ABI_HELPERS

#include <bf_syscall_t.hpp>

#include <bsl/safe_integral.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, returns reg_hypercall for the MicroV ABI.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg_hypercall from
    ///   @return Given a bf_syscall_t, returns reg_hypercall for the MicroV ABI.
    ///
    [[nodiscard]] constexpr auto
    get_reg_hypercall(syscall::bf_syscall_t const &sys) noexcept -> bsl::safe_u64
    {
        return sys.bf_tls_rax();
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, sets reg_return for the MicroV ABI to val.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg_return from
    ///   @param val the value to set reg_return to
    ///
    constexpr void
    set_reg_return(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &val) noexcept
    {
        sys.bf_tls_set_rax(val);
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, returns reg0 for the MicroV ABI.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg0 from
    ///   @return Given a bf_syscall_t, returns reg0 for the MicroV ABI.
    ///
    [[nodiscard]] constexpr auto
    get_reg0(syscall::bf_syscall_t const &sys) noexcept -> bsl::safe_u64
    {
        return sys.bf_tls_r10();
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, sets reg0 for the MicroV ABI to val.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg0 from
    ///   @param val the value to set reg0 to
    ///
    constexpr void
    set_reg0(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &val) noexcept
    {
        sys.bf_tls_set_r10(val);
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, returns reg1 for the MicroV ABI.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg1 from
    ///   @return Given a bf_syscall_t, returns reg1 for the MicroV ABI.
    ///
    [[nodiscard]] constexpr auto
    get_reg1(syscall::bf_syscall_t const &sys) noexcept -> bsl::safe_u64
    {
        return sys.bf_tls_r11();
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, sets reg1 for the MicroV ABI to val.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg1 from
    ///   @param val the value to set reg1 to
    ///
    constexpr void
    set_reg1(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &val) noexcept
    {
        sys.bf_tls_set_r11(val);
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, returns reg2 for the MicroV ABI.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg2 from
    ///   @return Given a bf_syscall_t, returns reg2 for the MicroV ABI.
    ///
    [[nodiscard]] constexpr auto
    get_reg2(syscall::bf_syscall_t const &sys) noexcept -> bsl::safe_u64
    {
        return sys.bf_tls_r12();
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, sets reg2 for the MicroV ABI to val.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg2 from
    ///   @param val the value to set reg2 to
    ///
    constexpr void
    set_reg2(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &val) noexcept
    {
        sys.bf_tls_set_r12(val);
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, returns reg3 for the MicroV ABI.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg3 from
    ///   @return Given a bf_syscall_t, returns reg3 for the MicroV ABI.
    ///
    [[nodiscard]] constexpr auto
    get_reg3(syscall::bf_syscall_t const &sys) noexcept -> bsl::safe_u64
    {
        return sys.bf_tls_r13();
    }

    /// <!-- description -->
    ///   @brief Given a bf_syscall_t, sets reg3 for the MicroV ABI to val.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to get reg3 from
    ///   @param val the value to set reg3 to
    ///
    constexpr void
    set_reg3(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &val) noexcept
    {
        sys.bf_tls_set_r13(val);
    }
}

#endif
