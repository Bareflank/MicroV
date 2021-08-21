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

#include <stdint.h>
#include <types.h>

#pragma pack(push, 1)
/** @brief defines the size of the padding1 field */
#define PADDING1_SIZE ((int)6)
/** @brief defines the size of the padding2 field */
#define PADDING2_SIZE ((int)256)
/** @brief defines the size of the padding3 field */
#define PADDING3_SIZE ((int)2048)

/**
 * @struct kvm_run
 *
 * <!-- description -->
 *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
 *   @var kvm_run::request_interrupt_window
 *   Member request_interrupt_window useful in conjunction with KVM_INTERRUPT
 *   @var kvm_run::immediate_exit
 *   Member immediate_exit is polled once when KVM_RUN starts
 *   @var kvm_run::padding1
 *   Member padding1 is ignored if KVM_CAP_IMMEDIATE_EXIT is not available
 *   @var kvm_run::exit_reason
 *   Member exit_reason informs application code why KVM_RUN has returned
 *   @var kvm_run::ready_for_interrupt_injection 
 *   Member ready_for_interrupt_injection indicates an interrupt can be injected now with KVM_INTERRUPT
 *   @var kvm_run::if_flag
 *   Member if_flag contains value of the current interrupt flag
 *   @var kvm_run::flags
 *   Member flags detailing state of the VCPU that may affect the device's behaviour
 *   @var kvm_run::cr8
 *   Member cr8 contains value of the cr8 Register
 *   @var kvm_run::apic_base
 *   Member apic_base contains value of the APIC BASE msr
 *   @var kvm_run::kvm_valid_regs
 *   Member kvm_valid_regs specifies register classes set by the host
 *   @var kvm_run::kvm_dirty_regs
 *   Member kvm_dirty_regs specifies register classes dirtied by userspace
 *   @var kvm_run::s
 *   Member s union allows userspace to access certain guest registers without having to call GET/SET_REGS
 */
struct kvm_run
{
    uint8_t request_interrupt_window;
    uint8_t immediate_exit;
    uint8_t padding1[PADDING1_SIZE];

    uint32_t exit_reason;
    uint8_t ready_for_interrupt_injection;
    uint8_t if_flag;
    uint16_t flags;

    uint64_t cr8;
    uint64_t apic_base;

    union
    {
        struct
        {
            uint64_t hardware_exit_reason;
        } hw;

        struct
        {
            uint64_t hardware_entry_failure_reason;
            uint32_t cpu;
        } fail_entry;

        struct
        {
            uint32_t exception;
            uint32_t error_code;
        } ex;

        struct
        {
            uint8_t direction;
            uint8_t size;
            uint16_t port;
            uint32_t count;
            uint64_t data_offset;
        } io;

        struct
        {
            uint64_t phys_addr;
            uint8_t data[8];
            uint32_t len;
            uint8_t is_write;
        } mmio;

        struct
        {
            uint64_t rip;
            uint32_t is_write;
            uint32_t pad;
        } tpr_access;

        struct
        {
            uint32_t type;
            uint64_t flags;
        } system_event;

        char padding2[PADDING2_SIZE];
    };

    uint64_t kvm_valid_regs;
    uint64_t kvm_dirty_regs;

    union
    {
        char padding3[PADDING3_SIZE];
    } s;
};

#pragma pack(pop)

#endif
