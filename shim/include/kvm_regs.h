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

#ifndef KVM_REGS_H
#define KVM_REGS_H

#include <stdint.h>

#pragma pack(push, 1)

/**
 * @struct kvm_regs
 *
 * <!-- description -->
 *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
 *   @var kvm_regs::rax 
 *   Member rax holds register value
 *   @var kvm_regs::rbx
 *   Member rbx holds register value
 *   @var kvm_regs::rcx
 *   Member rcx holds register value
 *   @var kvm_regs::rdx
 *   Member rdx holds register value
 *   @var kvm_regs::rsi
 *   Member rsi holds register value
 *   @var kvm_regs::rdi
 *   Member rdi holds register value
 *   @var kvm_regs::rsp
 *   Member rsp holds register value
 *   @var kvm_regs::rbp
 *   Member rbp holds register value
 *   @var kvm_regs::r8
 *   Member r8 holds register value
 *   @var kvm_regs::r9
 *   Member r9 holds register value
 *   @var kvm_regs::r10
 *   Member r10 holds register value
 *   @var kvm_regs::r11
 *   Member r11 holds register value
 *   @var kvm_regs::r12
 *   Member r12 holds register value
 *   @var kvm_regs::r13
 *   Member r13 holds register value
 *   @var kvm_regs::r14
 *   Member r14 holds register value
 *   @var kvm_regs::r15
 *   Member r15 holds register value
 *   @var kvm_regs::rip
 *   Member rip holds register value
 *   @var kvm_regs::rflags
 *   Member rflags holds register value
 */

struct kvm_regs
{
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
};

#pragma pack(pop)

#endif
