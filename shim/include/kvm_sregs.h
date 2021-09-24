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

#ifndef KVM_SREGS_H
#define KVM_SREGS_H

#include <kvm_dtable.h>
#include <kvm_segment.h>
#include <stdint.h>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wold-style-cast"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief stores the attrib type mask of segment */
#define ATTRIB_TYPE_MASK ((uint64_t)0x0000000FU)
/** @brief stores the attrib type shift of segment */
#define ATTRIB_TYPE_SHIFT ((uint64_t)0)
/** @brief stores the attrib s mask of segment */
#define ATTRIB_S_MASK ((uint64_t)0x00000001U)
/** @brief stores the attrib s shift of segment */
#define ATTRIB_S_SHIFT ((uint64_t)4)
/** @brief stores the attrib dpl mask of segment */
#define ATTRIB_DPL_MASK ((uint64_t)0x00000003U)
/** @brief stores the attrib dpl shift of segment */
#define ATTRIB_DPL_SHIFT ((uint64_t)5)
/** @brief stores the attrib present mask of segment */
#define ATTRIB_PRESENT_MASK ((uint64_t)0x00000001U)
/** @brief stores the attrib type shift of segment */
#define ATTRIB_PRESENT_SHIFT ((uint64_t)7)
/** @brief stores the attrib avl mask of segment */
#define ATTRIB_AVL_MASK ((uint64_t)0x00000001U)
/** @brief stores the attrib avl shift of segment */
#define ATTRIB_AVL_SHIFT ((uint64_t)12)
/** @brief stores the attrib l mask of segment */
#define ATTRIB_L_MASK ((uint64_t)0x00000001U)
/** @brief stores the attrib l shift of segment */
#define ATTRIB_L_SHIFT ((uint64_t)13)
/** @brief stores the attrib db mask of segment */
#define ATTRIB_DB_MASK ((uint64_t)0x00000001U)
/** @brief stores the attrib db shift of segment */
#define ATTRIB_DB_SHIFT ((uint64_t)14)
/** @brief stores the attrib g mask of segment */
#define ATTRIB_G_MASK ((uint64_t)0x00000001U)
/** @brief stores the attrib g shift of segment */
#define ATTRIB_G_SHIFT ((uint64_t)15)

/** @brief stores the EFER MSR address */
#define EFER_REG ((uint64_t)0xC0000080U)
/** @brief stores the APIC_BASE MSR address */
#define APIC_BASE_REG ((uint64_t)0x0000001BU)

/** @brief stores the size of the interrupt bitmap */
#define INTERRUPT_BITMAP_SIZE ((uint64_t)4)

    /**
     * @struct kvm_sregs
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_sregs
    {
        /** @brief stores that value of the cs segment register */
        struct kvm_segment cs;
        /** @brief stores that value of the ds segment register */
        struct kvm_segment ds;
        /** @brief stores that value of the es segment register */
        struct kvm_segment es;
        /** @brief stores that value of the fs segment register */
        struct kvm_segment fs;
        /** @brief stores that value of the gs segment register */
        struct kvm_segment gs;
        /** @brief stores that value of the ss segment register */
        struct kvm_segment ss;
        /** @brief stores that value of the tr segment register */
        struct kvm_segment tr;
        /** @brief stores that value of the ldt segment register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        struct kvm_segment ldt;
        /** @brief stores that value of the gdt dtable register */
        struct kvm_dtable gdt;
        /** @brief stores that value of the gdt dtable register */
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        struct kvm_dtable idt;
        /** @brief stores that value of the cr0 register */
        uint64_t cr0;
        /** @brief stores that value of the cr2 register */
        uint64_t cr2;
        /** @brief stores that value of the cr3 register */
        uint64_t cr3;
        /** @brief stores that value of the cr4 register */
        uint64_t cr4;
        /** @brief stores that value of the cr8 register */
        uint64_t cr8;
        /** @brief stores that value of the efer register */
        uint64_t efer;
        /** @brief stores that value of the apic_base register */
        uint64_t apic_base;
        /** @brief stores that value of the interrupt bitmap */
        uint64_t interrupt_bitmap[INTERRUPT_BITMAP_SIZE];
    };

#ifdef __cplusplus
}
#endif

#endif
