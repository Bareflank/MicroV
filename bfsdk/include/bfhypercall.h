/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef HYPERCALL_H
#define HYPERCALL_H

#include <bftypes.h>
#include <bfmemory.h>
#include <bfconstants.h>
#include <bferrorcodes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4) NOEXCEPT;
uint64_t _vmcall1(void *r1) NOEXCEPT;
uint64_t _vmcall2(void *r1, void *r2) NOEXCEPT;
uint64_t _vmcall3(void *r1, void *r2, void *r3) NOEXCEPT;
uint64_t _vmcall4(void *r1, void *r2, void *r3, void *r4) NOEXCEPT;

#ifdef __cplusplus
}
#endif

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

#define domainid_t uint64_t
#define vcpuid_t uint64_t

#define INVALID_DOMAINID 0xFFFFFFFFFFFFFFFF
#define INVALID_VCPUID 0xFFFFFFFFFFFFFFFF

#define SELF 0xFFFFFFFFFFFFFFFE

// -----------------------------------------------------------------------------
// Opcodes
// -----------------------------------------------------------------------------

#define hypercall_enum_run_op 0x01
#define hypercall_enum_domain_op 0x02
#define hypercall_enum_vcpu_op 0x03
#define hypercall_enum_uart_op 0x04
#define hypercall_enum_virq_op 0x10
#define hypercall_enum_vclock_op 0x11

#define bfopcode(a) ((a & 0x00FF000000000000) >> 48)

// -----------------------------------------------------------------------------
// Run Operations
// -----------------------------------------------------------------------------

#define hypercall_enum_run_op__hlt 1
#define hypercall_enum_run_op__fault 2
#define hypercall_enum_run_op__continue 3
#define hypercall_enum_run_op__yield 4
#define hypercall_enum_run_op__set_wallclock 5

#define run_op_ret_op(a) ((0x000000000000000FULL & a) >> 0)
#define run_op_ret_arg(a) ((0xFFFFFFFFFFFFFFF0ULL & a) >> 4)

static inline vcpuid_t
hypercall_run_op(vcpuid_t vcpuid, uint64_t arg1, uint64_t arg2)
{
    return _vmcall(
        0xBF01000000000000, vcpuid, arg1, arg2
    );
}

// -----------------------------------------------------------------------------
// Uart Operations
// -----------------------------------------------------------------------------

#define hypercall_enum_uart_op__char 1
#define hypercall_enum_uart_op__nhex 2
#define hypercall_enum_uart_op__ndec 3

static inline vcpuid_t
hypercall_uart_char_op(uint16_t port, uint64_t c)
{
    return _vmcall(
        0xBF04000000000000, hypercall_enum_uart_op__char, port, c
    );
}

static inline vcpuid_t
hypercall_uart_nhex_op(uint16_t port, uint64_t val)
{
    return _vmcall(
        0xBF04000000000000, hypercall_enum_uart_op__nhex, port, val
    );
}

static inline vcpuid_t
hypercall_uart_ndec_op(uint16_t port, uint64_t val)
{
    return _vmcall(
        0xBF04000000000000, hypercall_enum_uart_op__ndec, port, val
    );
}

// -----------------------------------------------------------------------------
// Domain Operations
// -----------------------------------------------------------------------------

#define hypercall_enum_domain_op__create_domain 0xBF02000000000100
#define hypercall_enum_domain_op__destroy_domain 0xBF02000000000101

#define hypercall_enum_domain_op__set_uart 0xBF02000000000200
#define hypercall_enum_domain_op__set_pt_uart 0xBF02000000000201
#define hypercall_enum_domain_op__dump_uart 0xBF02000000000202

#define hypercall_enum_domain_op__share_page_r 0xBF02000000000300
#define hypercall_enum_domain_op__share_page_rw 0xBF02000000000301
#define hypercall_enum_domain_op__share_page_rwe 0xBF02000000000303
#define hypercall_enum_domain_op__donate_page_r 0xBF02000000000310
#define hypercall_enum_domain_op__donate_page_rw 0xBF02000000000311
#define hypercall_enum_domain_op__donate_page_rwe 0xBF02000000000313

#define hypercall_enum_domain_op__rax 0xBF02000000010000
#define hypercall_enum_domain_op__set_rax 0xBF02000000010001
#define hypercall_enum_domain_op__rbx 0xBF02000000010010
#define hypercall_enum_domain_op__set_rbx 0xBF02000000010011
#define hypercall_enum_domain_op__rcx 0xBF02000000010020
#define hypercall_enum_domain_op__set_rcx 0xBF02000000010021
#define hypercall_enum_domain_op__rdx 0xBF02000000010030
#define hypercall_enum_domain_op__set_rdx 0xBF02000000010031
#define hypercall_enum_domain_op__rbp 0xBF02000000010040
#define hypercall_enum_domain_op__set_rbp 0xBF02000000010041
#define hypercall_enum_domain_op__rsi 0xBF02000000010050
#define hypercall_enum_domain_op__set_rsi 0xBF02000000010051
#define hypercall_enum_domain_op__rdi 0xBF02000000010060
#define hypercall_enum_domain_op__set_rdi 0xBF02000000010061
#define hypercall_enum_domain_op__r08 0xBF02000000010070
#define hypercall_enum_domain_op__set_r08 0xBF02000000010071
#define hypercall_enum_domain_op__r09 0xBF02000000010080
#define hypercall_enum_domain_op__set_r09 0xBF02000000010081
#define hypercall_enum_domain_op__r10 0xBF02000000010090
#define hypercall_enum_domain_op__set_r10 0xBF02000000010091
#define hypercall_enum_domain_op__r11 0xBF020000000100A0
#define hypercall_enum_domain_op__set_r11 0xBF020000000100A1
#define hypercall_enum_domain_op__r12 0xBF020000000100B0
#define hypercall_enum_domain_op__set_r12 0xBF020000000100B1
#define hypercall_enum_domain_op__r13 0xBF020000000100C0
#define hypercall_enum_domain_op__set_r13 0xBF020000000100C1
#define hypercall_enum_domain_op__r14 0xBF020000000100D0
#define hypercall_enum_domain_op__set_r14 0xBF020000000100D1
#define hypercall_enum_domain_op__r15 0xBF020000000100E0
#define hypercall_enum_domain_op__set_r15 0xBF020000000100E1
#define hypercall_enum_domain_op__rip 0xBF020000000100F0
#define hypercall_enum_domain_op__set_rip 0xBF020000000100F1
#define hypercall_enum_domain_op__rsp 0xBF02000000010100
#define hypercall_enum_domain_op__set_rsp 0xBF02000000010101
#define hypercall_enum_domain_op__gdt_base 0xBF02000000010110
#define hypercall_enum_domain_op__set_gdt_base 0xBF02000000010111
#define hypercall_enum_domain_op__gdt_limit 0xBF02000000010120
#define hypercall_enum_domain_op__set_gdt_limit 0xBF02000000010121
#define hypercall_enum_domain_op__idt_base 0xBF02000000010130
#define hypercall_enum_domain_op__set_idt_base 0xBF02000000010131
#define hypercall_enum_domain_op__idt_limit 0xBF02000000010140
#define hypercall_enum_domain_op__set_idt_limit 0xBF02000000010141
#define hypercall_enum_domain_op__cr0 0xBF02000000010150
#define hypercall_enum_domain_op__set_cr0 0xBF02000000010151
#define hypercall_enum_domain_op__cr3 0xBF02000000010160
#define hypercall_enum_domain_op__set_cr3 0xBF02000000010161
#define hypercall_enum_domain_op__cr4 0xBF02000000010170
#define hypercall_enum_domain_op__set_cr4 0xBF02000000010171
#define hypercall_enum_domain_op__ia32_efer 0xBF02000000010180
#define hypercall_enum_domain_op__set_ia32_efer 0xBF02000000010181
#define hypercall_enum_domain_op__ia32_pat 0xBF02000000010190
#define hypercall_enum_domain_op__set_ia32_pat 0xBF02000000010191

#define hypercall_enum_domain_op__es_selector 0xBF02000000020000
#define hypercall_enum_domain_op__set_es_selector 0xBF02000000020001
#define hypercall_enum_domain_op__es_base 0xBF02000000020010
#define hypercall_enum_domain_op__set_es_base 0xBF02000000020011
#define hypercall_enum_domain_op__es_limit 0xBF02000000020020
#define hypercall_enum_domain_op__set_es_limit 0xBF02000000020021
#define hypercall_enum_domain_op__es_access_rights 0xBF02000000020030
#define hypercall_enum_domain_op__set_es_access_rights 0xBF02000000020031
#define hypercall_enum_domain_op__cs_selector 0xBF02000000020100
#define hypercall_enum_domain_op__set_cs_selector 0xBF02000000020101
#define hypercall_enum_domain_op__cs_base 0xBF02000000020110
#define hypercall_enum_domain_op__set_cs_base 0xBF02000000020111
#define hypercall_enum_domain_op__cs_limit 0xBF02000000020120
#define hypercall_enum_domain_op__set_cs_limit 0xBF02000000020121
#define hypercall_enum_domain_op__cs_access_rights 0xBF02000000020130
#define hypercall_enum_domain_op__set_cs_access_rights 0xBF02000000020131
#define hypercall_enum_domain_op__ss_selector 0xBF02000000020200
#define hypercall_enum_domain_op__set_ss_selector 0xBF02000000020201
#define hypercall_enum_domain_op__ss_base 0xBF02000000020210
#define hypercall_enum_domain_op__set_ss_base 0xBF02000000020211
#define hypercall_enum_domain_op__ss_limit 0xBF02000000020220
#define hypercall_enum_domain_op__set_ss_limit 0xBF02000000020221
#define hypercall_enum_domain_op__ss_access_rights 0xBF02000000020230
#define hypercall_enum_domain_op__set_ss_access_rights 0xBF02000000020231
#define hypercall_enum_domain_op__ds_selector 0xBF02000000020300
#define hypercall_enum_domain_op__set_ds_selector 0xBF02000000020301
#define hypercall_enum_domain_op__ds_base 0xBF02000000020310
#define hypercall_enum_domain_op__set_ds_base 0xBF02000000020311
#define hypercall_enum_domain_op__ds_limit 0xBF02000000020320
#define hypercall_enum_domain_op__set_ds_limit 0xBF02000000020321
#define hypercall_enum_domain_op__ds_access_rights 0xBF02000000020330
#define hypercall_enum_domain_op__set_ds_access_rights 0xBF02000000020331
#define hypercall_enum_domain_op__fs_selector 0xBF02000000020400
#define hypercall_enum_domain_op__set_fs_selector 0xBF02000000020401
#define hypercall_enum_domain_op__fs_base 0xBF02000000020410
#define hypercall_enum_domain_op__set_fs_base 0xBF02000000020411
#define hypercall_enum_domain_op__fs_limit 0xBF02000000020420
#define hypercall_enum_domain_op__set_fs_limit 0xBF02000000020421
#define hypercall_enum_domain_op__fs_access_rights 0xBF02000000020430
#define hypercall_enum_domain_op__set_fs_access_rights 0xBF02000000020431
#define hypercall_enum_domain_op__gs_selector 0xBF02000000020500
#define hypercall_enum_domain_op__set_gs_selector 0xBF02000000020501
#define hypercall_enum_domain_op__gs_base 0xBF02000000020510
#define hypercall_enum_domain_op__set_gs_base 0xBF02000000020511
#define hypercall_enum_domain_op__gs_limit 0xBF02000000020520
#define hypercall_enum_domain_op__set_gs_limit 0xBF02000000020521
#define hypercall_enum_domain_op__gs_access_rights 0xBF02000000020530
#define hypercall_enum_domain_op__set_gs_access_rights 0xBF02000000020531
#define hypercall_enum_domain_op__tr_selector 0xBF02000000020600
#define hypercall_enum_domain_op__set_tr_selector 0xBF02000000020601
#define hypercall_enum_domain_op__tr_base 0xBF02000000020610
#define hypercall_enum_domain_op__set_tr_base 0xBF02000000020611
#define hypercall_enum_domain_op__tr_limit 0xBF02000000020620
#define hypercall_enum_domain_op__set_tr_limit 0xBF02000000020621
#define hypercall_enum_domain_op__tr_access_rights 0xBF02000000020630
#define hypercall_enum_domain_op__set_tr_access_rights 0xBF02000000020631
#define hypercall_enum_domain_op__ldtr_selector 0xBF02000000020700
#define hypercall_enum_domain_op__set_ldtr_selector 0xBF02000000020701
#define hypercall_enum_domain_op__ldtr_base 0xBF02000000020710
#define hypercall_enum_domain_op__set_ldtr_base 0xBF02000000020711
#define hypercall_enum_domain_op__ldtr_limit 0xBF02000000020720
#define hypercall_enum_domain_op__set_ldtr_limit 0xBF02000000020721
#define hypercall_enum_domain_op__ldtr_access_rights 0xBF02000000020730
#define hypercall_enum_domain_op__set_ldtr_access_rights 0xBF02000000020731

#define UART_MAX_BUFFER 0x4000

static inline domainid_t
hypercall_domain_op__create_domain(void)
{
    return _vmcall(
        hypercall_enum_domain_op__create_domain,
        0,
        0,
        0
    );
}

static inline status_t
hypercall_domain_op__destroy_domain(domainid_t foreign_domainid)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__destroy_domain,
        foreign_domainid,
        0,
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__set_uart(domainid_t foreign_domainid, uint64_t uart)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__set_uart,
        foreign_domainid,
        uart,
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__set_pt_uart(domainid_t foreign_domainid, uint64_t uart)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__set_pt_uart,
        foreign_domainid,
        uart,
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline uint64_t
hypercall_domain_op__dump_uart(domainid_t domainid, char *buffer)
{
    return _vmcall(
        hypercall_enum_domain_op__dump_uart,
        domainid,
        bfrcast(uint64_t, buffer),
        0
    );
}

static inline status_t
hypercall_domain_op__share_page_r(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__share_page_r,
        foreign_domainid,
        gpa,
        foreign_gpa
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__share_page_rw(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__share_page_rw,
        foreign_domainid,
        gpa,
        foreign_gpa
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__share_page_rwe(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__share_page_rwe,
        foreign_domainid,
        gpa,
        foreign_gpa
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__donate_page_r(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__donate_page_r,
        foreign_domainid,
        gpa,
        foreign_gpa
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__donate_page_rw(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__donate_page_rw,
        foreign_domainid,
        gpa,
        foreign_gpa
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
hypercall_domain_op__donate_page_rwe(
    domainid_t foreign_domainid, uint64_t gpa, uint64_t foreign_gpa)
{
    status_t ret = _vmcall(
        hypercall_enum_domain_op__donate_page_rwe,
        foreign_domainid,
        gpa,
        foreign_gpa
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

#define hypercall_domain_op__reg(reg)                                           \
    static inline uint64_t                                                      \
    hypercall_domain_op__ ## reg(domainid_t domainid)                           \
    {                                                                           \
        return _vmcall(                                                         \
            hypercall_enum_domain_op__## reg,                                   \
            domainid,                                                           \
            0,                                                                  \
            0                                                                   \
        );                                                                      \
    }

#define hypercall_domain_op__set_reg(reg)                                       \
    static inline status_t                                                      \
    hypercall_domain_op__set_ ## reg(domainid_t domainid, uint64_t val)         \
    {                                                                           \
        status_t ret = _vmcall(                                                 \
            hypercall_enum_domain_op__set_ ## reg,                              \
            domainid,                                                           \
            val,                                                                \
            0                                                                   \
        );                                                                      \
                                                                                \
        return ret == 0 ? SUCCESS : FAILURE;                                    \
    }

hypercall_domain_op__reg(rax)
hypercall_domain_op__set_reg(rax)
hypercall_domain_op__reg(rbx)
hypercall_domain_op__set_reg(rbx)
hypercall_domain_op__reg(rcx)
hypercall_domain_op__set_reg(rcx)
hypercall_domain_op__reg(rdx)
hypercall_domain_op__set_reg(rdx)
hypercall_domain_op__reg(rbp)
hypercall_domain_op__set_reg(rbp)
hypercall_domain_op__reg(rsi)
hypercall_domain_op__set_reg(rsi)
hypercall_domain_op__reg(rdi)
hypercall_domain_op__set_reg(rdi)
hypercall_domain_op__reg(r08)
hypercall_domain_op__set_reg(r08)
hypercall_domain_op__reg(r09)
hypercall_domain_op__set_reg(r09)
hypercall_domain_op__reg(r10)
hypercall_domain_op__set_reg(r10)
hypercall_domain_op__reg(r11)
hypercall_domain_op__set_reg(r11)
hypercall_domain_op__reg(r12)
hypercall_domain_op__set_reg(r12)
hypercall_domain_op__reg(r13)
hypercall_domain_op__set_reg(r13)
hypercall_domain_op__reg(r14)
hypercall_domain_op__set_reg(r14)
hypercall_domain_op__reg(r15)
hypercall_domain_op__set_reg(r15)
hypercall_domain_op__reg(rip)
hypercall_domain_op__set_reg(rip)
hypercall_domain_op__reg(rsp)
hypercall_domain_op__set_reg(rsp)
hypercall_domain_op__reg(gdt_base)
hypercall_domain_op__set_reg(gdt_base)
hypercall_domain_op__reg(gdt_limit)
hypercall_domain_op__set_reg(gdt_limit)
hypercall_domain_op__reg(idt_base)
hypercall_domain_op__set_reg(idt_base)
hypercall_domain_op__reg(idt_limit)
hypercall_domain_op__set_reg(idt_limit)
hypercall_domain_op__reg(cr0)
hypercall_domain_op__set_reg(cr0)
hypercall_domain_op__reg(cr3)
hypercall_domain_op__set_reg(cr3)
hypercall_domain_op__reg(cr4)
hypercall_domain_op__set_reg(cr4)
hypercall_domain_op__reg(ia32_efer)
hypercall_domain_op__set_reg(ia32_efer)
hypercall_domain_op__reg(ia32_pat)
hypercall_domain_op__set_reg(ia32_pat)

hypercall_domain_op__reg(es_selector)
hypercall_domain_op__set_reg(es_selector)
hypercall_domain_op__reg(es_base)
hypercall_domain_op__set_reg(es_base)
hypercall_domain_op__reg(es_limit)
hypercall_domain_op__set_reg(es_limit)
hypercall_domain_op__reg(es_access_rights)
hypercall_domain_op__set_reg(es_access_rights)
hypercall_domain_op__reg(cs_selector)
hypercall_domain_op__set_reg(cs_selector)
hypercall_domain_op__reg(cs_base)
hypercall_domain_op__set_reg(cs_base)
hypercall_domain_op__reg(cs_limit)
hypercall_domain_op__set_reg(cs_limit)
hypercall_domain_op__reg(cs_access_rights)
hypercall_domain_op__set_reg(cs_access_rights)
hypercall_domain_op__reg(ss_selector)
hypercall_domain_op__set_reg(ss_selector)
hypercall_domain_op__reg(ss_base)
hypercall_domain_op__set_reg(ss_base)
hypercall_domain_op__reg(ss_limit)
hypercall_domain_op__set_reg(ss_limit)
hypercall_domain_op__reg(ss_access_rights)
hypercall_domain_op__set_reg(ss_access_rights)
hypercall_domain_op__reg(ds_selector)
hypercall_domain_op__set_reg(ds_selector)
hypercall_domain_op__reg(ds_base)
hypercall_domain_op__set_reg(ds_base)
hypercall_domain_op__reg(ds_limit)
hypercall_domain_op__set_reg(ds_limit)
hypercall_domain_op__reg(ds_access_rights)
hypercall_domain_op__set_reg(ds_access_rights)
hypercall_domain_op__reg(fs_selector)
hypercall_domain_op__set_reg(fs_selector)
hypercall_domain_op__reg(fs_base)
hypercall_domain_op__set_reg(fs_base)
hypercall_domain_op__reg(fs_limit)
hypercall_domain_op__set_reg(fs_limit)
hypercall_domain_op__reg(fs_access_rights)
hypercall_domain_op__set_reg(fs_access_rights)
hypercall_domain_op__reg(gs_selector)
hypercall_domain_op__set_reg(gs_selector)
hypercall_domain_op__reg(gs_base)
hypercall_domain_op__set_reg(gs_base)
hypercall_domain_op__reg(gs_limit)
hypercall_domain_op__set_reg(gs_limit)
hypercall_domain_op__reg(gs_access_rights)
hypercall_domain_op__set_reg(gs_access_rights)
hypercall_domain_op__reg(tr_selector)
hypercall_domain_op__set_reg(tr_selector)
hypercall_domain_op__reg(tr_base)
hypercall_domain_op__set_reg(tr_base)
hypercall_domain_op__reg(tr_limit)
hypercall_domain_op__set_reg(tr_limit)
hypercall_domain_op__reg(tr_access_rights)
hypercall_domain_op__set_reg(tr_access_rights)
hypercall_domain_op__reg(ldtr_selector)
hypercall_domain_op__set_reg(ldtr_selector)
hypercall_domain_op__reg(ldtr_base)
hypercall_domain_op__set_reg(ldtr_base)
hypercall_domain_op__reg(ldtr_limit)
hypercall_domain_op__set_reg(ldtr_limit)
hypercall_domain_op__reg(ldtr_access_rights)
hypercall_domain_op__set_reg(ldtr_access_rights)

// -----------------------------------------------------------------------------
// vCPU Operations
// -----------------------------------------------------------------------------

#define hypercall_enum_vcpu_op__create_vcpu 0xBF03000000000100
#define hypercall_enum_vcpu_op__kill_vcpu 0xBF03000000000101
#define hypercall_enum_vcpu_op__destroy_vcpu 0xBF03000000000102

static inline vcpuid_t
hypercall_vcpu_op__create_vcpu(domainid_t domainid)
{
    return _vmcall(
        hypercall_enum_vcpu_op__create_vcpu,
        domainid,
        0,
        0
    );
}

static inline status_t
hypercall_vcpu_op__kill_vcpu(vcpuid_t vcpuid)
{
    return _vmcall(
        hypercall_enum_vcpu_op__kill_vcpu,
        vcpuid,
        0,
        0
    );
}

static inline status_t
hypercall_vcpu_op__destroy_vcpu(vcpuid_t vcpuid)
{
    return _vmcall(
        hypercall_enum_vcpu_op__destroy_vcpu,
        vcpuid,
        0,
        0
    );
}

/* -------------------------------------------------------------------------- */
/* Virtual IRQs                                                               */
/* -------------------------------------------------------------------------- */

#define boxy_virq__vclock_event_handler 0xBF00000000000201

#define hypercall_enum_virq_op__set_hypervisor_callback_vector 0xBF10000000000100
#define hypercall_enum_virq_op__get_next_virq 0xBF10000000000101

static inline uint64_t
hypercall_virq_op__set_hypervisor_callback_vector(uint64_t vector)
{
    return _vmcall(
        hypercall_enum_virq_op__set_hypervisor_callback_vector, vector, 0, 0);
}

static inline uint64_t
hypercall_virq_op__get_next_virq(void)
{
    return _vmcall(
        hypercall_enum_virq_op__get_next_virq, 0, 0, 0);
}

/* -------------------------------------------------------------------------- */
/* Virtual Clock                                                              */
/* -------------------------------------------------------------------------- */

#define hypercall_enum_vclock_op__get_tsc_freq_khz 0xBF11000000000100
#define hypercall_enum_vclock_op__set_next_event 0xBF11000000000102
#define hypercall_enum_vclock_op__reset_host_wallclock 0xBF11000000000103
#define hypercall_enum_vclock_op__set_host_wallclock_rtc 0xBF11000000000104
#define hypercall_enum_vclock_op__set_host_wallclock_tsc 0xBF11000000000105
#define hypercall_enum_vclock_op__set_guest_wallclock_rtc 0xBF11000000000106
#define hypercall_enum_vclock_op__set_guest_wallclock_tsc 0xBF11000000000107
#define hypercall_enum_vclock_op__get_guest_wallclock 0xBF11000000000108

static inline uint64_t
hypercall_vclock_op__get_tsc_freq_khz(void)
{
    return _vmcall(
        hypercall_enum_vclock_op__get_tsc_freq_khz, 0, 0, 0);
}

static inline uint64_t
hypercall_vclock_op__set_next_event(uint64_t tsc_delta)
{
    return _vmcall(
        hypercall_enum_vclock_op__set_next_event, tsc_delta, 0, 0);
}

static inline status_t
hypercall_vclock_op__reset_host_wallclock(void)
{
    return _vmcall(
        hypercall_enum_vclock_op__reset_host_wallclock, 0, 0, 0
    );
}

static inline status_t
hypercall_vclock_op__set_host_wallclock_rtc(
    vcpuid_t vcpuid, int64_t sec, int64_t nsec)
{
    return _vmcall(
        hypercall_enum_vclock_op__set_host_wallclock_rtc,
        vcpuid,
        bfscast(uint64_t, sec),
        bfscast(uint64_t, nsec)
    );
}

static inline status_t
hypercall_vclock_op__set_host_wallclock_tsc(
    vcpuid_t vcpuid, uint64_t val)
{
    return _vmcall(
        hypercall_enum_vclock_op__set_host_wallclock_tsc,
        vcpuid,
        val,
        0
    );
}

static inline status_t
hypercall_vclock_op__set_guest_wallclock_rtc(void)
{
    return _vmcall(
        hypercall_enum_vclock_op__set_guest_wallclock_rtc, 0, 0, 0
    );
}

static inline status_t
hypercall_vclock_op__set_guest_wallclock_tsc(void)
{
    return _vmcall(
        hypercall_enum_vclock_op__set_guest_wallclock_tsc, 0, 0, 0
    );
}

static inline uint64_t
hypercall_vclock_op__get_guest_wallclock(
    int64_t *sec, long *nsec, uint64_t *tsc)
{
    uint64_t op = hypercall_enum_vclock_op__get_guest_wallclock;

    if (sec == 0 || nsec == 0 || tsc == 0) {
        return FAILURE;
    }

    return _vmcall4(
        &op, sec, nsec, tsc);
}

#pragma pack(pop)

#endif
