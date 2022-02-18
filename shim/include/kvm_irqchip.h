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

#ifndef KVM_IRQCHIP_H
#define KVM_IRQCHIP_H

#include <stdint.h>
#define KVM_IRQCHIP_DUMMY ((uint32_t)512)
#define KVM_IOAPIC_NUM_PINS ((uint32_t)24)
#define KVM_IOAPIC_RESERVED ((uint32_t)4)

#ifdef __clang__
#pragma clang diagnostic ignored "-Wold-style-cast"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
    * @struct kvm_irqchip
    *
    * <!-- description -->
    *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
    */
    struct kvm_irqchip
    {

        /** @brief ID of the interrupt cntroller 0 = PIC1, 1 = PIC2, 2 = IOAPIC */
        int32_t chip_id;
        /** @brief number of pad in entries */
        int32_t pad;

        //NOLINTNEXTLINE [bsl-decl-forbidden]
        union
        {
            /** @brief dummy */
            char dummy[KVM_IRQCHIP_DUMMY];

            /** @brief pic state */
            struct
            {
                /** @brief edge detection*/
                uint8_t last_irr;
                /** @brief interrupt request register*/
                uint8_t irr;
                /** @brief  interrupt mask register*/
                uint8_t imr;
                /** @brief interrupt service register*/
                uint8_t isr;
                /** @brief  highest irq priority*/
                uint8_t priority_add;
                /** @brief TODO*/
                uint8_t irq_base;
                /** @brief TODO*/
                uint8_t read_reg_select;
                /** @brief TODO*/
                uint8_t poll;
                /** @brief TODO*/
                uint8_t special_mask;
                /** @brief TODO*/
                uint8_t init_state;
                /** @brief TODO*/
                uint8_t auto_eoi;
                /** @brief TODO*/
                uint8_t rotate_on_auto_eoi;
                /** @brief TODO*/
                uint8_t special_fully_nested_mode;
                /** @brief true if 4 byte init*/
                uint8_t init4;
                /** @brief  PIIX edge/trigger selection*/
                uint8_t elcr;
                /** @brief TODO*/
                uint8_t elcr_mask;
            } /** @brief TODO*/ kvm_pic_state;

            /** @brief iopic state */
            struct
            {
                /** @brief TODO*/
                uint64_t base_address;
                /** @brief TODO*/
                uint32_t ioregsel;
                /** @brief TODO*/
                uint32_t id;
                /** @brief TODO*/
                uint32_t irr;
                /** @brief TODO*/
                uint32_t pad;
                /** @brief redirtbl structure */
                //NOLINTNEXTLINE [bsl-decl-forbidden
                union
                {
                    /** @brief TODO*/
                    //NOLINTNEXTLINE
                    uint64_t bits;
                    /** @brief TODO*/
                    struct
                    {
                        /** @brief TODO*/
                        uint8_t vector;
                        /** @brief TODO*/
                        uint8_t delivery_mode : 3;
                        /** @brief TODO*/
                        uint8_t dest_mode : 1;
                        /** @brief TODO*/
                        uint8_t delivery_status : 1;
                        /** @brief TODO*/
                        uint8_t polarity : 1;
                        /** @brief TODO*/
                        uint8_t remote_irr : 1;
                        /** @brief TODO*/
                        uint8_t trig_mode : 1;
                        /** @brief TODO*/
                        uint8_t mask : 1;
                        /** @brief TODO*/
                        uint8_t reserve : 7;
                        /** @brief TODO*/
                        uint8_t reserved[KVM_IOAPIC_RESERVED];
                        /** @brief TODO*/
                        uint8_t dest_id;
                    } /** @brief TODO*/ fields;
                } /** @brief TODO*/ redirtbl[KVM_IOAPIC_NUM_PINS];
            } /** @brief TODO*/ kvm_ioapic_state;
        } /** @brief TODO*/ pic;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
