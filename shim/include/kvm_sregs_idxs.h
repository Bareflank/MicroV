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

#ifndef KVM_SREGS_IDXS_H
#define KVM_SREGS_IDXS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief index for ES SELECTOR register in kvm segment */
#define ES_SELECTOR_IDX ((uint16_t)0)
/** @brief index for ES BASE register in kvm segment */
#define ES_BASE_IDX ((uint64_t)1)
/** @brief index for ES LIMIT register in kvm segment */
#define ES_LIMIT_IDX ((uint32_t)2)
/** @brief index for ES ATTRIB  register in kvm segment */
#define ES_ATTRIB_IDX ((uint8_t)3)
/** @brief index for CS SELECTOR register in kvm segment */
#define CS_SELECTOR_IDX ((uint16_t)4)
/** @brief index for CS BASE register in kvm segment */
#define CS_BASE_IDX ((uint64_t)5)
/** @brief index for CS LIMIT register in kvm segment */
#define CS_LIMIT_IDX ((uint32_t)6)
/** @brief index for CS ATTRIB register in kvm segment */
#define CS_ATTRIB_IDX ((uint8_t)7)
/** @brief index for DS SELECTOR register in kvm segment */
#define DS_SELECTOR_IDX ((uint16_t)8)
/** @brief index for DS BASE register in kvm segment */
#define DS_BASE_IDX ((uint64_t)9)
/** @brief index for DS LIMIT register in kvm segment */
#define DS_LIMIT_IDX ((uint32_t)10)
/** @brief index for DS ATTRIB  register in kvm segment */
#define DS_ATTRIB_IDX ((uint8_t)11)
/** @brief index for FS SELECTOR register in kvm segment */
#define FS_SELECTOR_IDX ((uint16_t)12)
/** @brief index for FS BASE register in kvm segment */
#define FS_BASE_IDX ((uint64_t)13)
/** @brief index for FS LIMIT register in kvm segment */
#define FS_LIMIT_IDX ((uint32_t)14)
/** @brief index for FS ATTRIB register in kvm segment */
#define FS_ATTRIB_IDX ((uint8_t)15)
/** @brief index for GS SELECTOR register in kvm segment */
#define GS_SELECTOR_IDX ((uint16_t)16)
/** @brief index for GS BASE register in kvm segment */
#define GS_BASE_IDX ((uint64_t)17)
/** @brief index for GS LIMIT register in kvm segment */
#define GS_LIMIT_IDX ((uint32_t)18)
/** @brief index for GS ATTRIB register in kvm segment */
#define GS_ATTRIB_IDX ((uint8_t)19)
/** @brief index for SS SELECTOR register in kvm segment */
#define SS_SELECTOR_IDX ((uint16_t)20)
/** @brief index for SS BASE register in kvm segment */
#define SS_BASE_IDX ((uint64_t)21)
/** @brief index for SS LIMIT register in kvm segment */
#define SS_LIMIT_IDX ((uint32_t)22)
/** @brief index for SS ATTRIB register in kvm segment */
#define SS_ATTRIB_IDX ((uint8_t)23)
/** @brief index for TR SELECTOR register in kvm segment */
#define TR_SELECTOR_IDX ((uint16_t)24)
/** @brief index for TR BASE register in kvm segment */
#define TR_BASE_IDX ((uint64_t)25)
/** @brief index for TR LIMIT register in kvm segment */
#define TR_LIMIT_IDX ((uint32_t)26)
/** @brief index for TR ATTRIB register in kvm segment */
#define TR_ATTRIB_IDX ((uint8_t)27)
/** @brief index for LDT SELECTOR register in kvm segment */
#define LDT_SELECTOR_IDX ((uint16_t)28)
/** @brief index for LDT BASE register in kvm segment */
#define LDT_BASE_IDX ((uint64_t)29)
/** @brief index for LDT LIMIT register in kvm segment */
#define LDT_LIMIT_IDX ((uint32_t)30)
/** @brief index for LDT ATTRIB register in kvm segment */
#define LDT_ATTRIB_IDX ((uint8_t)31)
/** @brief index for GDT LIMIT register in kvm dtable */
#define GDT_LIMIT_IDX ((uint16_t)32)
/** @brief index for GDT BASE register in kvm dtable */
#define GDT_BASE_IDX ((uint64_t)33)
/** @brief index for IDT LIMIT register in kvm dtable */
#define IDT_LIMIT_IDX ((uint16_t)34)
/** @brief index for IDT BASE register in kvm dtable */
#define IDT_BASE_IDX ((uint64_t)35)
/** @brief index for CR0 register in kvm sregs */
#define CR0_IDX ((uint64_t)36)
/** @brief index for CR2 register in kvm sregs */
#define CR2_IDX ((uint64_t)37)
/** @brief index for CR3 register in kvm sregs */
#define CR3_IDX ((uint64_t)38)
/** @brief index for CR4 register in kvm sregs */
#define CR4_IDX ((uint64_t)39)
/** @brief index for CR8 register in kvm sregs */
#define CR8_IDX ((uint64_t)40)
/** @brief index for EFER register in kvm sregs */
#define MSR_EFER_IDX ((uint64_t)41)
/** @brief index for APIC_BASE register in kvm sregs */
#define MSR_APIC_BASE_IDX ((uint64_t)42)
/** @brief stores the regs total number of entries for rdl */
#define TOTAL_SREGS_NUM_REG_ENTRIES ((uint64_t)40)
/** @brief stores the regs total number of set entries reg+val for rdl */
#define TOTAL_SREGS_SET_NUM_REG_ENTRIES ((uint64_t)80)
/** @brief stores the MSR total number of entries for rdl */
#define TOTAL_SREGS_NUM_MSR_ENTRIES ((uint64_t)2)
/** @brief stores the msr total number of set entries reg+val for rdl */
#define TOTAL_SREGS_SET_NUM_MSR_ENTRIES ((uint64_t)4)

#ifdef __cplusplus
}
#endif

#endif
