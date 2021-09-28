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

#ifndef KVM_CONSTANTS_H
#define KVM_CONSTANTS_H

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief defines KVM_GET_API_VERSION API to return */
#define KVM_API_VERSION 12
/** @brief defines KVM_CAP_USER_MEMORY for check extension */
#define KVM_CAP_USER_MEMORY 3
/** @brief defines KVM_CAP_SET_TSS_ADDR for check extension */
#define KVM_CAP_SET_TSS_ADDR 4
/** @brief defines KVM_CAP_EXT_CPUID for check extension */
#define KVM_CAP_EXT_CPUID 7
/** @brief defines KVM_CAP_NR_VCPUS for check extension */
#define KVM_CAP_NR_VCPUS 9
/** @brief defines KVM_CAP_NR_MEMSLOTS for check extension */
#define KVM_CAP_NR_MEMSLOTS 10
/** @brief defines KVM_CAP_MP_STATE for check extension */
#define KVM_CAP_MP_STATE 14
/** @brief defines KVM_CAP_DESTROY_MEMORY_REGION_WORKS for check extension */
#define KVM_CAP_DESTROY_MEMORY_REGION_WORKS 21
/** @brief defines KVM_CAP_JOIN_MEMORY_REGIONS_WORKS for check extension */
#define KVM_CAP_JOIN_MEMORY_REGIONS_WORKS 30
/** @brief defines KVM_CAP_MCE for check extension */
#define KVM_CAP_MCE 31
/** @brief defines KVM_CAP_GET_TSC_KHZ for check extension */
#define KVM_CAP_GET_TSC_KHZ 61
/** @brief defines KVM_CAP_MAX_VCPUS for check extension */
#define KVM_CAP_MAX_VCPUS 66
/** @brief defines KVM_CAP_TSC_DEADLINE_TIMER for check extension */
#define KVM_CAP_TSC_DEADLINE_TIMER 72
/** @brief defines KVM_CAP_MAX_VCPU_ID for check extension */
#define KVM_CAP_MAX_VCPU_ID 128
/** @brief defines KVM_CAP_IMMEDIATE_EXIT for check extension */
#define KVM_CAP_IMMEDIATE_EXIT 136
/** @brief defines MICROV_MAX_MCE_BANKS  */
#define MICROV_MAX_MCE_BANKS 32

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
