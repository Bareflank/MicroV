/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MV_REG_T_HP
#define MV_REG_T_HP

/**
 * <!-- description -->
 *   @brief Defines which register to use for read/write
 */
enum mv_reg_t
{
    mv_reg_t_dummy = 0,
    mv_reg_t_rax = 1,
    mv_reg_t_rbx = 2,
    mv_reg_t_rcx = 3,
    mv_reg_t_rdx = 4,
    mv_reg_t_rbp = 5,
    mv_reg_t_rsi = 6,
    mv_reg_t_rdi = 7,
    mv_reg_t_r8 = 8,
    mv_reg_t_r9 = 9,
    mv_reg_t_r10 = 10,
    mv_reg_t_r11 = 11,
    mv_reg_t_r12 = 12,
    mv_reg_t_r13 = 13,
    mv_reg_t_r14 = 14,
    mv_reg_t_r15 = 15,
    mv_reg_t_rsp = 16,
    mv_reg_t_rip = 17,
    mv_reg_t_rflags = 18
};

#endif
