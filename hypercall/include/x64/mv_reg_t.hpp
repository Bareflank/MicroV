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

#ifndef MV_REG_T_HPP
#define MV_REG_T_HPP

#include <bsl/cstdint.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief Defines which register to use for certain hypercalls
    ///
    enum class mv_reg_t : bsl::int32
    {
        /// @brief defines the rax register
        mv_reg_t_rax = 1,
        /// @brief defines the rbx register
        mv_reg_t_rbx = 2,
        /// @brief defines the rcx register
        mv_reg_t_rcx = 3,
        /// @brief defines the rdx register
        mv_reg_t_rdx = 4,
        /// @brief defines the rbp register
        mv_reg_t_rbp = 5,
        /// @brief defines the rsi register
        mv_reg_t_rsi = 6,
        /// @brief defines the rdi register
        mv_reg_t_rdi = 7,
        /// @brief defines the r8 register
        mv_reg_t_r8 = 8,
        /// @brief defines the r9 register
        mv_reg_t_r9 = 9,
        /// @brief defines the r10 register
        mv_reg_t_r10 = 10,
        /// @brief defines the r11 register
        mv_reg_t_r11 = 11,
        /// @brief defines the r12 register
        mv_reg_t_r12 = 12,
        /// @brief defines the r13 register
        mv_reg_t_r13 = 13,
        /// @brief defines the r14 register
        mv_reg_t_r14 = 14,
        /// @brief defines the r15 register
        mv_reg_t_r15 = 15,
        /// @brief defines the rsp register
        mv_reg_t_rsp = 16,
        /// @brief defines the rip register
        mv_reg_t_rip = 17,
        /// @brief defines the rflags register
        mv_reg_t_rflags = 18,
        /// @brief defines the es_selector register
        mv_reg_t_es_selector = 19,
        /// @brief defines the es_attrib register
        mv_reg_t_es_attrib = 20,
        /// @brief defines the es_limit register
        mv_reg_t_es_limit = 21,
        /// @brief defines the es_base register
        mv_reg_t_es_base = 22,
        /// @brief defines the cs_selector register
        mv_reg_t_cs_selector = 23,
        /// @brief defines the cs_attrib register
        mv_reg_t_cs_attrib = 24,
        /// @brief defines the cs_limit register
        mv_reg_t_cs_limit = 25,
        /// @brief defines the cs_base register
        mv_reg_t_cs_base = 26,
        /// @brief defines the ss_selector register
        mv_reg_t_ss_selector = 27,
        /// @brief defines the ss_attrib register
        mv_reg_t_ss_attrib = 28,
        /// @brief defines the ss_limit register
        mv_reg_t_ss_limit = 29,
        /// @brief defines the ss_base register
        mv_reg_t_ss_base = 30,
        /// @brief defines the ds_selector register
        mv_reg_t_ds_selector = 31,
        /// @brief defines the ds_attrib register
        mv_reg_t_ds_attrib = 32,
        /// @brief defines the ds_limit register
        mv_reg_t_ds_limit = 33,
        /// @brief defines the ds_base register
        mv_reg_t_ds_base = 34,
        /// @brief defines the fs_selector register
        mv_reg_t_fs_selector = 35,
        /// @brief defines the fs_attrib register
        mv_reg_t_fs_attrib = 36,
        /// @brief defines the fs_limit register
        mv_reg_t_fs_limit = 37,
        /// @brief defines the fs_base register
        mv_reg_t_fs_base = 38,
        /// @brief defines the gs_selector register
        mv_reg_t_gs_selector = 39,
        /// @brief defines the gs_attrib register
        mv_reg_t_gs_attrib = 40,
        /// @brief defines the gs_limit register
        mv_reg_t_gs_limit = 41,
        /// @brief defines the gs_base register
        mv_reg_t_gs_base = 42,
        /// @brief defines the ldtr_selector register
        mv_reg_t_ldtr_selector = 43,
        /// @brief defines the ldtr_attrib register
        mv_reg_t_ldtr_attrib = 44,
        /// @brief defines the ldtr_limit register
        mv_reg_t_ldtr_limit = 45,
        /// @brief defines the ldtr_base register
        mv_reg_t_ldtr_base = 46,
        /// @brief defines the tr_selector register
        mv_reg_t_tr_selector = 47,
        /// @brief defines the tr_attrib register
        mv_reg_t_tr_attrib = 48,
        /// @brief defines the tr_limit register
        mv_reg_t_tr_limit = 49,
        /// @brief defines the tr_base register
        mv_reg_t_tr_base = 50,
        /// @brief defines the gdtr_selector register
        mv_reg_t_gdtr_selector = 51,
        /// @brief defines the gdtr_attrib register
        mv_reg_t_gdtr_attrib = 52,
        /// @brief defines the gdtr_limit register
        mv_reg_t_gdtr_limit = 53,
        /// @brief defines the gdtr_base register
        mv_reg_t_gdtr_base = 54,
        /// @brief defines the idtr_selector register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_idtr_selector = 55,
        /// @brief defines the idtr_attrib register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_idtr_attrib = 56,
        /// @brief defines the idtr_limit register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_idtr_limit = 57,
        /// @brief defines the idtr_base register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        mv_reg_t_idtr_base = 58,
        /// @brief defines the dr0 register
        mv_reg_t_dr0 = 59,
        /// @brief defines the dr1 register
        mv_reg_t_dr1 = 60,
        /// @brief defines the dr2 register
        mv_reg_t_dr2 = 61,
        /// @brief defines the dr3 register
        mv_reg_t_dr3 = 62,
        /// @brief defines the dr6 register
        mv_reg_t_dr6 = 63,
        /// @brief defines the dr7 register
        mv_reg_t_dr7 = 64,
        /// @brief defines the cr0 register
        mv_reg_t_cr0 = 65,
        /// @brief defines the cr2 register
        mv_reg_t_cr2 = 66,
        /// @brief defines the cr3 register
        mv_reg_t_cr3 = 67,
        /// @brief defines the cr4 register
        mv_reg_t_cr4 = 68,
        /// @brief defines the cr8 register
        mv_reg_t_cr8 = 69,
        /// @brief defines the xcr0 register (Intel Only)
        mv_reg_t_xcr0 = 70,
        /// @brief defines and invalid mv_reg_t
        mv_reg_t_invalid = 71,
    };
}

#endif
