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

#ifndef KVM_IRQCHIP_HPP
#define KVM_IRQCHIP_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#pragma pack(push, 1)

namespace shim
{
    /// @brief defines the size of the dummy field
    constexpr auto KVM_IRQCHIP_DUMMY{512_umx};
    /// @brief defines the size of theiopic pins
    constexpr auto KVM_IOAPIC_NUM_PINS{24_umx};
    /// @brief defines the size of the reserved field
    constexpr auto KVM_IOAPIC_RESERVED{4_umx};

    /// @struct kvm_irqchip
    ///
    /// <!-- description -->
    ///   @brief see /include/uapi/linux/kvm.h in Linux for more details.
    ///
    struct kvm_irqchip final
    {

        /// @brief ID of the interrupt cntroller 0 = PIC1, 1 = PIC2, 2 = IOAPIC
        bsl::uint32 chip_id;
        /// @brief number of pad in entries
        bsl::uint32 pad;

        //NOLINTNEXTLINE [bsl-decl-forbidden]
        union
        {
            /// @brief dummy
            bsl::array<bsl::uint8, KVM_IRQCHIP_DUMMY.get()> dummy;
            /// @brief pic state
            struct
            {
                /// @brief edge detection
                bsl::uint8 last_irr;
                /// @brief interrupt request register
                bsl::uint8 irr;
                /// @brief  interrupt mask register
                bsl::uint8 imr;
                /// @brief interrupt service register
                bsl::uint8 isr;
                /// @brief  highest irq priority
                bsl::uint8 priority_add;
                /// @brief TODO
                bsl::uint8 irq_base;
                /// @brief TODO
                bsl::uint8 read_reg_select;
                /// @brief TODO
                bsl::uint8 poll;
                /// @brief TODO
                bsl::uint8 special_mask;
                /// @brief TODO
                bsl::uint8 init_state;
                /// @brief TODO
                bsl::uint8 auto_eoi;
                /// @brief TODO
                bsl::uint8 rotate_on_auto_eoi;
                /// @brief TODO
                bsl::uint8 special_fully_nested_mode;
                /// @brief true if 4 byte init
                bsl::uint8 init4;
                /// @brief  PIIX edge/trigger selection
                bsl::uint8 elcr;
                /// @brief TODO
                bsl::uint8 elcr_mask;
            } /** @brief TODO*/ kvm_pic_state;

            /// @brief iopic state
            struct
            {
                /// @brief TODO
                bsl::uint64 base_address;
                /// @brief TODO
                bsl::uint32 ioregsel;
                /// @brief TODO
                bsl::uint32 id;
                /// @brief TODO
                bsl::uint32 irr;
                /// @brief TODO
                bsl::uint32 pad;
                /// @brief redirtbl structure
                //NOLINTNEXTLINE [bsl-decl-forbidden
                union
                {
                    /// @brief TODO
                    //NOLINTNEXTLINE
                    bsl::uint64 bits;
                    /// @brief TODO
                    struct
                    {
                        /// @brief TODO
                        bsl::uint8 vector;
                        /// @brief TODO
                        bsl::uint8 delivery_mode : 3;
                        /// @brief TODO
                        bsl::uint8 dest_mode : 1;
                        /// @brief TODO
                        bsl::uint8 delivery_status : 1;
                        /// @brief TODO
                        bsl::uint8 polarity : 1;
                        /// @brief TODO
                        bsl::uint8 remote_irr : 1;
                        /// @brief TODO
                        bsl::uint8 trig_mode : 1;
                        /// @brief TODO
                        bsl::uint8 mask : 1;
                        /// @brief TODO
                        bsl::uint8 reserve : 7;
                        /// @brief TODO
                        bsl::array<bsl::uint8, KVM_IOAPIC_RESERVED.get()> reserved;
                        /// @brief TODO
                        bsl::uint8 dest_id;
                    } fields;
                };
                bsl::array<bsl::uint8, KVM_IOAPIC_NUM_PINS.get()> redirtbl;
            } kvm_ioapic_state;
        } /** @brief TODO*/ pic;
    };
}

#pragma pack(pop)

#endif
