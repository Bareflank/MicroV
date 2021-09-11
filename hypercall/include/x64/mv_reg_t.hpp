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
    enum class mv_reg_t : bsl::uint64
    {
        /// @brief defines the rax register
        mv_reg_t_rax = static_cast<bsl::uint64>(1),
        /// @brief defines the rbx register
        mv_reg_t_rbx = static_cast<bsl::uint64>(2),
        /// @brief defines the rcx register
        mv_reg_t_rcx = static_cast<bsl::uint64>(3),
        /// @brief defines the rdx register
        mv_reg_t_rdx = static_cast<bsl::uint64>(4),
        /// @brief defines the rbp register
        mv_reg_t_rbp = static_cast<bsl::uint64>(5),
        /// @brief defines the rsi register
        mv_reg_t_rsi = static_cast<bsl::uint64>(6),
        /// @brief defines the rdi register
        mv_reg_t_rdi = static_cast<bsl::uint64>(7),
        /// @brief defines the r8 register
        mv_reg_t_r8 = static_cast<bsl::uint64>(8),
        /// @brief defines the r9 register
        mv_reg_t_r9 = static_cast<bsl::uint64>(9),
        /// @brief defines the r10 register
        mv_reg_t_r10 = static_cast<bsl::uint64>(10),
        /// @brief defines the r11 register
        mv_reg_t_r11 = static_cast<bsl::uint64>(11),
        /// @brief defines the r12 register
        mv_reg_t_r12 = static_cast<bsl::uint64>(12),
        /// @brief defines the r13 register
        mv_reg_t_r13 = static_cast<bsl::uint64>(13),
        /// @brief defines the r14 register
        mv_reg_t_r14 = static_cast<bsl::uint64>(14),
        /// @brief defines the r15 register
        mv_reg_t_r15 = static_cast<bsl::uint64>(15),
        /// @brief defines the rsp register
        mv_reg_t_rsp = static_cast<bsl::uint64>(16),
        /// @brief defines the rip register
        mv_reg_t_rip = static_cast<bsl::uint64>(17),
        /// @brief defines the rflags register
        mv_reg_t_rflags = static_cast<bsl::uint64>(18),
        /// @brief defines the es_selector register
        mv_reg_t_es_selector = static_cast<bsl::uint64>(19),
        /// @brief defines the es_attrib register
        mv_reg_t_es_attrib = static_cast<bsl::uint64>(20),
        /// @brief defines the es_limit register
        mv_reg_t_es_limit = static_cast<bsl::uint64>(21),
        /// @brief defines the es_base register
        mv_reg_t_es_base = static_cast<bsl::uint64>(22),
        /// @brief defines the cs_selector register
        mv_reg_t_cs_selector = static_cast<bsl::uint64>(23),
        /// @brief defines the cs_attrib register
        mv_reg_t_cs_attrib = static_cast<bsl::uint64>(24),
        /// @brief defines the cs_limit register
        mv_reg_t_cs_limit = static_cast<bsl::uint64>(25),
        /// @brief defines the cs_base register
        mv_reg_t_cs_base = static_cast<bsl::uint64>(26),
        /// @brief defines the ss_selector register
        mv_reg_t_ss_selector = static_cast<bsl::uint64>(27),
        /// @brief defines the ss_attrib register
        mv_reg_t_ss_attrib = static_cast<bsl::uint64>(28),
        /// @brief defines the ss_limit register
        mv_reg_t_ss_limit = static_cast<bsl::uint64>(29),
        /// @brief defines the ss_base register
        mv_reg_t_ss_base = static_cast<bsl::uint64>(30),
        /// @brief defines the ds_selector register
        mv_reg_t_ds_selector = static_cast<bsl::uint64>(31),
        /// @brief defines the ds_attrib register
        mv_reg_t_ds_attrib = static_cast<bsl::uint64>(32),
        /// @brief defines the ds_limit register
        mv_reg_t_ds_limit = static_cast<bsl::uint64>(33),
        /// @brief defines the ds_base register
        mv_reg_t_ds_base = static_cast<bsl::uint64>(34),
        /// @brief defines the fs_selector register
        mv_reg_t_fs_selector = static_cast<bsl::uint64>(35),
        /// @brief defines the fs_attrib register
        mv_reg_t_fs_attrib = static_cast<bsl::uint64>(36),
        /// @brief defines the fs_limit register
        mv_reg_t_fs_limit = static_cast<bsl::uint64>(37),
        /// @brief defines the fs_base register
        mv_reg_t_fs_base = static_cast<bsl::uint64>(38),
        /// @brief defines the gs_selector register
        mv_reg_t_gs_selector = static_cast<bsl::uint64>(39),
        /// @brief defines the gs_attrib register
        mv_reg_t_gs_attrib = static_cast<bsl::uint64>(40),
        /// @brief defines the gs_limit register
        mv_reg_t_gs_limit = static_cast<bsl::uint64>(41),
        /// @brief defines the gs_base register
        mv_reg_t_gs_base = static_cast<bsl::uint64>(42),
        /// @brief defines the ldtr_selector register
        mv_reg_t_ldtr_selector = static_cast<bsl::uint64>(43),
        /// @brief defines the ldtr_attrib register
        mv_reg_t_ldtr_attrib = static_cast<bsl::uint64>(44),
        /// @brief defines the ldtr_limit register
        mv_reg_t_ldtr_limit = static_cast<bsl::uint64>(45),
        /// @brief defines the ldtr_base register
        mv_reg_t_ldtr_base = static_cast<bsl::uint64>(46),
        /// @brief defines the tr_selector register
        mv_reg_t_tr_selector = static_cast<bsl::uint64>(47),
        /// @brief defines the tr_attrib register
        mv_reg_t_tr_attrib = static_cast<bsl::uint64>(48),
        /// @brief defines the tr_limit register
        mv_reg_t_tr_limit = static_cast<bsl::uint64>(49),
        /// @brief defines the tr_base register
        mv_reg_t_tr_base = static_cast<bsl::uint64>(50),
        /// @brief defines the gdtr_selector register
        mv_reg_t_gdtr_selector = static_cast<bsl::uint64>(51),
        /// @brief defines the gdtr_attrib register
        mv_reg_t_gdtr_attrib = static_cast<bsl::uint64>(52),
        /// @brief defines the gdtr_limit register
        mv_reg_t_gdtr_limit = static_cast<bsl::uint64>(53),
        /// @brief defines the gdtr_base register
        mv_reg_t_gdtr_base = static_cast<bsl::uint64>(54),
        /// @brief defines the idtr_selector register
        mv_reg_t_idtr_selector = static_cast<bsl::uint64>(55),
        /// @brief defines the idtr_attrib register
        mv_reg_t_idtr_attrib = static_cast<bsl::uint64>(56),
        /// @brief defines the idtr_limit register
        mv_reg_t_idtr_limit = static_cast<bsl::uint64>(57),
        /// @brief defines the idtr_base register
        mv_reg_t_idtr_base = static_cast<bsl::uint64>(58),
        /// @brief defines the dr0 register
        mv_reg_t_dr0 = static_cast<bsl::uint64>(59),
        /// @brief defines the dr1 register
        mv_reg_t_dr1 = static_cast<bsl::uint64>(60),
        /// @brief defines the dr2 register
        mv_reg_t_dr2 = static_cast<bsl::uint64>(61),
        /// @brief defines the dr3 register
        mv_reg_t_dr3 = static_cast<bsl::uint64>(62),
        /// @brief defines the dr6 register
        mv_reg_t_dr6 = static_cast<bsl::uint64>(63),
        /// @brief defines the dr7 register
        mv_reg_t_dr7 = static_cast<bsl::uint64>(64),
        /// @brief defines the cr0 register
        mv_reg_t_cr0 = static_cast<bsl::uint64>(65),
        /// @brief defines the cr2 register
        mv_reg_t_cr2 = static_cast<bsl::uint64>(66),
        /// @brief defines the cr3 register
        mv_reg_t_cr3 = static_cast<bsl::uint64>(67),
        /// @brief defines the cr4 register
        mv_reg_t_cr4 = static_cast<bsl::uint64>(68),
        /// @brief defines the cr8 register
        mv_reg_t_cr8 = static_cast<bsl::uint64>(69),
        /// @brief defines the xcr0 register (Intel Only)
        mv_reg_t_xcr0 = static_cast<bsl::uint64>(70),
    };
}

#endif
