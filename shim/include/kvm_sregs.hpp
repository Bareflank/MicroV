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

#ifndef KVM_SREGS_HPP
#define KVM_SREGS_HPP

#include <kvm_dtable.hpp>
#include <kvm_segment.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// @brief stores the attrib type mask of segment
    constexpr auto ATTRIB_TYPE_MASK{0x0000000F_u64};
    /// @brief stores the attrib type shift of segment
    constexpr auto ATTRIB_TYPE_SHIFT{0_u64};
    /// @brief stores the attrib s mask of segment
    constexpr auto ATTRIB_S_MASK{0x00000001_u64};
    /// @brief stores the attrib s shift of segment
    constexpr auto ATTRIB_S_SHIFT{4_u64};
    /// @brief stores the attrib dpl mask of segment
    constexpr auto ATTRIB_DPL_MASK{0x00000003_u64};
    /// @brief stores the attrib dpl shift of segment
    constexpr auto ATTRIB_DPL_SHIFT{5_u64};
    /// @brief stores the attrib present mask of segment
    constexpr auto ATTRIB_PRESENT_MASK{0x00000001_u64};
    /// @brief stores the attrib type shift of segment
    constexpr auto ATTRIB_PRESENT_SHIFT{7_u64};
    /// @brief stores the attrib avl mask of segment
    constexpr auto ATTRIB_AVL_MASK{0x00000001_u64};
    /// @brief stores the attrib avl shift of segment
    constexpr auto ATTRIB_AVL_SHIFT{12_u64};
    /// @brief stores the attrib l mask of segment
    constexpr auto ATTRIB_L_MASK{0x00000001_u64};
    /// @brief stores the attrib l shift of segment
    constexpr auto ATTRIB_L_SHIFT{13_u64};
    /// @brief stores the attrib db mask of segment
    constexpr auto ATTRIB_DB_MASK{0x00000001_u64};
    /// @brief stores the attrib db shift of segment
    constexpr auto ATTRIB_DB_SHIFT{14_u64};
    /// @brief stores the attrib g mask of segment
    constexpr auto ATTRIB_G_MASK{0x00000001_u64};
    /// @brief stores the attrib g shift of segment
    constexpr auto ATTRIB_G_SHIFT{15_u64};

    /// @brief stores the EFER MSR address
    constexpr auto EFER{0xC0000080_u64};
    /// @brief stores the APIC_BASE MSR address
    constexpr auto APIC_BASE{0x0000001B_u64};

    /// @brief stores the size of the interrupt bitmap
    constexpr auto INTERRUPT_BITMAP_SIZE{4_u64};

    /// @struct kvm_sregs
    ///
    /// <!-- description -->
    ///   @brief see /include/uapi/linux/kvm.h in Linux for more details.
    ///
    struct kvm_sregs final
    {
        /// @brief stores that value of the cs segment register
        struct kvm_segment cs;
        /// @brief stores that value of the ds segment register
        struct kvm_segment ds;
        /// @brief stores that value of the es segment register
        struct kvm_segment es;
        /// @brief stores that value of the fs segment register
        struct kvm_segment fs;
        /// @brief stores that value of the gs segment register
        struct kvm_segment gs;
        /// @brief stores that value of the ss segment register
        struct kvm_segment ss;
        /// @brief stores that value of the tr segment register
        struct kvm_segment tr;
        /// @brief stores that value of the ldt segment register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        struct kvm_segment ldt;
        /// @brief stores that value of the gdt dtable register
        struct kvm_dtable gdt;
        /// @brief stores that value of the gdt dtable register
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        struct kvm_dtable idt;
        /// @brief stores that value of the cr0 register
        bsl::uint64 cr0;
        /// @brief stores that value of the cr2 register
        bsl::uint64 cr2;
        /// @brief stores that value of the cr3 register
        bsl::uint64 cr3;
        /// @brief stores that value of the cr4 register
        bsl::uint64 cr4;
        /// @brief stores that value of the cr8 register
        bsl::uint64 cr8;
        /// @brief stores that value of the efer register
        bsl::uint64 efer;
        /// @brief stores that value of the apic_base register
        bsl::uint64 apic_base;
        /// @brief stores that value of the interrupt bitmap
        bsl::array<bsl::uint64, INTERRUPT_BITMAP_SIZE.get()> interrupt_bitmap;
    };
}

#pragma pack(pop)

#endif
