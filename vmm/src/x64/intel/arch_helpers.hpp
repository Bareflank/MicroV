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

#ifndef ARCH_HELPERS_HPP
#define ARCH_HELPERS_HPP

#include <bsl/safe_integral.hpp>

namespace microv
{
    /// @brief defines the GPR index for RAX
    constexpr auto GPR_RAX{0_u64};
    /// @brief defines the GPR index for RCX
    constexpr auto GPR_RCX{1_u64};
    /// @brief defines the GPR index for RDX
    constexpr auto GPR_RDX{2_u64};
    /// @brief defines the GPR index for RBX
    constexpr auto GPR_RBX{3_u64};
    /// @brief defines the GPR index for RSP
    constexpr auto GPR_RSP{4_u64};
    /// @brief defines the GPR index for RBP
    constexpr auto GPR_RBP{5_u64};
    /// @brief defines the GPR index for RSI
    constexpr auto GPR_RSI{6_u64};
    /// @brief defines the GPR index for RDI
    constexpr auto GPR_RDI{7_u64};
    /// @brief defines the GPR index for R8
    constexpr auto GPR_R8{8_u64};
    /// @brief defines the GPR index for R9
    constexpr auto GPR_R9{9_u64};
    /// @brief defines the GPR index for R10
    constexpr auto GPR_R10{10_u64};
    /// @brief defines the GPR index for R11
    constexpr auto GPR_R11{11_u64};
    /// @brief defines the GPR index for R12
    constexpr auto GPR_R12{12_u64};
    /// @brief defines the GPR index for R13
    constexpr auto GPR_R13{13_u64};
    /// @brief defines the GPR index for R14
    constexpr auto GPR_R14{14_u64};
    /// @brief defines the GPR index for R15
    constexpr auto GPR_R15{15_u64};

    /// <!-- description -->
    ///   @brief Given a GPR index, returns the value of the GPR. Note that
    ///     the GPRs will most come from the TLS, so the VS that you wish to
    ///     get the GPR value from must be active before you call this.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param vsid the ID of the VS to get the GPR from (RSP only)
    ///   @param gpr the GPR to get the value from
    ///   @return Returns the value of the GPR on success. Returns
    ///     bsl::safe_u64::failure() on failure.
    ///
    [[nodiscard]] constexpr auto
    get_gpr(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &gpr) noexcept -> bsl::safe_u64
    {
        switch (gpr.get()) {
            case GPR_RAX.get(): {
                return sys.bf_tls_rax();
            }

            case GPR_RCX.get(): {
                return sys.bf_tls_rcx();
            }

            case GPR_RDX.get(): {
                return sys.bf_tls_rdx();
            }

            case GPR_RBX.get(): {
                return sys.bf_tls_rbx();
            }

            case GPR_RSP.get(): {
                constexpr auto rsp_idx{syscall::bf_reg_t::bf_reg_t_rsp};
                return sys.bf_vs_op_read(vsid, rsp_idx);
            }

            case GPR_RBP.get(): {
                return sys.bf_tls_rbp();
            }

            case GPR_RSI.get(): {
                return sys.bf_tls_rsi();
            }

            case GPR_RDI.get(): {
                return sys.bf_tls_rdi();
            }

            case GPR_R8.get(): {
                return sys.bf_tls_r8();
            }

            case GPR_R9.get(): {
                return sys.bf_tls_r9();
            }

            case GPR_R10.get(): {
                return sys.bf_tls_r10();
            }

            case GPR_R11.get(): {
                return sys.bf_tls_r11();
            }

            case GPR_R12.get(): {
                return sys.bf_tls_r12();
            }

            case GPR_R13.get(): {
                return sys.bf_tls_r13();
            }

            case GPR_R14.get(): {
                return sys.bf_tls_r14();
            }

            case GPR_R15.get(): {
                return sys.bf_tls_r15();
            }

            default: {
                break;
            }
        }

        bsl::error() << "unknown GPR value "    // --
                     << gpr                     // --
                     << bsl::endl               // --
                     << bsl::here();            // --

        return bsl::safe_u64::failure();
    }

    /// <!-- description -->
    ///   @brief Given a GPR index, sets the value of the GPR. Note that
    ///     the GPRs will most come from the TLS, so the VS that you wish to
    ///     set the GPR value for must be active before you call this.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param vsid the ID of the VS to set the GPR for (RSP only)
    ///   @param gpr the GPR to set
    ///   @param val the value to set the GPR to
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    set_gpr(
        syscall::bf_syscall_t &mut_sys,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &gpr,
        bsl::safe_u64 const &val) noexcept -> bsl::errc_type
    {
        switch (gpr.get()) {
            case GPR_RAX.get(): {
                mut_sys.bf_tls_set_rax(val);
                return bsl::errc_success;
            }

            case GPR_RCX.get(): {
                mut_sys.bf_tls_set_rcx(val);
                return bsl::errc_success;
            }

            case GPR_RDX.get(): {
                mut_sys.bf_tls_set_rdx(val);
                return bsl::errc_success;
            }

            case GPR_RBX.get(): {
                mut_sys.bf_tls_set_rbx(val);
                return bsl::errc_success;
            }

            case GPR_RSP.get(): {
                constexpr auto rsp_idx{syscall::bf_reg_t::bf_reg_t_rsp};
                return mut_sys.bf_vs_op_write(vsid, rsp_idx, val);
            }

            case GPR_RBP.get(): {
                mut_sys.bf_tls_set_rbp(val);
                return bsl::errc_success;
            }

            case GPR_RSI.get(): {
                mut_sys.bf_tls_set_rsi(val);
                return bsl::errc_success;
            }

            case GPR_RDI.get(): {
                mut_sys.bf_tls_set_rdi(val);
                return bsl::errc_success;
            }

            case GPR_R8.get(): {
                mut_sys.bf_tls_set_r8(val);
                return bsl::errc_success;
            }

            case GPR_R9.get(): {
                mut_sys.bf_tls_set_r9(val);
                return bsl::errc_success;
            }

            case GPR_R10.get(): {
                mut_sys.bf_tls_set_r10(val);
                return bsl::errc_success;
            }

            case GPR_R11.get(): {
                mut_sys.bf_tls_set_r11(val);
                return bsl::errc_success;
            }

            case GPR_R12.get(): {
                mut_sys.bf_tls_set_r12(val);
                return bsl::errc_success;
            }

            case GPR_R13.get(): {
                mut_sys.bf_tls_set_r13(val);
                return bsl::errc_success;
            }

            case GPR_R14.get(): {
                mut_sys.bf_tls_set_r14(val);
                return bsl::errc_success;
            }

            case GPR_R15.get(): {
                mut_sys.bf_tls_set_r15(val);
                return bsl::errc_success;
            }

            default: {
                break;
            }
        }

        bsl::error() << "unknown GPR value "    // --
                     << gpr                     // --
                     << bsl::endl               // --
                     << bsl::here();            // --

        return bsl::errc_failure;
    }
}

#endif
