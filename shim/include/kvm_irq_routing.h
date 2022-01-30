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

#ifndef KVM_IRQ_ROUTING_H
#define KVM_IRQ_ROUTING_H

#define KVM_ENTRY ((uint32_t)0)
#define KVM_PAD ((uint32_t)8)

#include <stdint.h>

#define KVM_IRQ_ROUTING_IRQCHIP 1
#define KVM_IRQ_ROUTING_MSI 2
#define KVM_IRQ_ROUTING_S390_ADAPTER 3

#ifdef __clang__
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wzero-length-array"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
     * @struct kvm_irq_routing_irqchip
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    //NOLINTNEXTLINE
    struct kvm_irq_routing_irqchip
    {
        /** @brief TODO */
        uint32_t irqchip;
        /** @brief TODO */
        uint32_t pin;
    };

    /**
     * @struct kvm_irq_routing_msi
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    //NOLINTNEXTLINE
    struct kvm_irq_routing_msi
    {
        /** @brief TODO */
        uint32_t address_lo;
        /** @brief TODO */
        uint32_t address_hi;
        /** @brief TODO */
        uint32_t data;
        /** @brief TODO */
        uint32_t pad;
    };

    /**
     * @struct kvm_irq_routing_s390_adapter
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    //NOLINTNEXTLINE
    struct kvm_irq_routing_s390_adapter
    {
        /** @brief TODO */
        uint64_t ind_addr;
        /** @brief TODO */
        uint64_t summary_addr;
        /** @brief TODO */
        uint64_t ind_offset;
        /** @brief TODO */
        uint32_t summary_offset;
        /** @brief TODO */
        uint32_t adapter_id;
    };

    /**
     * @struct kvm_irq_routing_entry
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_irq_routing_entry    //NOLINT
    {
        /** @brief TODO */
        uint32_t gsi;
        /** @brief TODO */
        uint32_t type;
        /** @brief TODO */
        uint32_t flags;
        /** @brief TODO */
        uint32_t pad;
        /** @brief TODO */
        //NOLINTNEXTLINE
        union
        {
            /** @brief TODO */
            struct kvm_irq_routing_irqchip irqchip;
            /** @brief TODO */
            struct kvm_irq_routing_msi msi;
            /** @brief TODO */
            struct kvm_irq_routing_s390_adapter adapter;
            /** @brief TODO */
            uint32_t pad[KVM_PAD];
        } /** @brief TODO */ u;
    };
    /** TODO: REMOVE ABOVE STRUCTURE: The above structures are part of other branches as of now,
    * they will be available to include here once respective branches are merged with master. */

    /**
     * @struct kvm_irq_routing
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_irq_routing
    {
        /** @brief TODO */
        uint32_t nr;
        /** @brief TODO */
        uint32_t flags;
        /** @brief TODO */
        struct kvm_irq_routing_entry entries[KVM_ENTRY];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
