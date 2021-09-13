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

#ifndef KVM_RUN_H
#define KVM_RUN_H

#include <kvm_run_ex.h>
#include <kvm_run_fail_entry.h>
#include <kvm_run_hw.h>
#include <kvm_run_io.h>
#include <kvm_run_mmio.h>
#include <kvm_run_system_event.h>
#include <kvm_run_tpr_access.h>
#include <stdint.h>
#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief defines the size of the padding1 field */
#define KVM_RUN_PADDING1_SIZE ((uint64_t)6)
/** @brief defines the size of the padding2 field */
#define KVM_RUN_PADDING2_SIZE ((uint64_t)256)
/** @brief defines the size of the padding3 field */
#define KVM_RUN_PADDING3_SIZE ((uint64_t)2048)

    /**
     * @struct kvm_run
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_run
    {
        /** @brief TODO */
        uint8_t request_interrupt_window;
        /** @brief TODO */
        uint8_t immediate_exit;
        /** @brief TODO */
        uint8_t padding1[KVM_RUN_PADDING1_SIZE];

        /** @brief TODO */
        uint32_t exit_reason;
        /** @brief TODO */
        uint8_t ready_for_interrupt_injection;
        /** @brief TODO */
        uint8_t if_flag;
        /** @brief TODO */
        uint16_t flags;

        /** @brief TODO */
        uint64_t cr8;
        /** @brief TODO */
        uint64_t apic_base;

        /**
         * <!-- description -->
         *   @brief TODO
         */
        // NOLINTNEXTLINE(bsl-decl-forbidden)
        union
        {
            /** @brief TODO */
            struct kvm_run_hw hw;
            /** @brief TODO */
            struct kvm_run_fail_entry fail_entry;
            /** @brief TODO */
            struct kvm_run_ex ex;
            /** @brief TODO */
            struct kvm_run_io io;
            /** @brief TODO */
            struct kvm_run_mmio mmio;
            /** @brief TODO */
            struct kvm_run_tpr_access tpr_access;
            /** @brief TODO */
            struct kvm_run_system_event system_event;

            /** @brief TODO */
            char padding2[KVM_RUN_PADDING2_SIZE];
        };

        /** @brief TODO */
        uint64_t kvm_valid_regs;
        /** @brief TODO */
        uint64_t kvm_dirty_regs;

        /** @brief TODO */
        char padding3[KVM_RUN_PADDING3_SIZE];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
