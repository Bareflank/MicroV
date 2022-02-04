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
// #define KVM_CAP_USER_MEMORY 3
// /** @brief defines KVM_CAP_SET_TSS_ADDR for check extension */
// #define KVM_CAP_SET_TSS_ADDR 4
// /** @brief defines KVM_CAP_EXT_CPUID for check extension */
// #define KVM_CAP_EXT_CPUID 7
// /** @brief defines KVM_CAP_NR_VCPUS for check extension */
// #define KVM_CAP_NR_VCPUS 9
// /** @brief defines KVM_CAP_NR_MEMSLOTS for check extension */
// #define KVM_CAP_NR_MEMSLOTS 10
// /** @brief defines KVM_CAP_MP_STATE for check extension */
// #define KVM_CAP_MP_STATE 14
// /** @brief defines KVM_CAP_DESTROY_MEMORY_REGION_WORKS for check extension */
// #define KVM_CAP_DESTROY_MEMORY_REGION_WORKS 21
// * @brief defines KVM_CAP_JOIN_MEMORY_REGIONS_WORKS for check extension 
// #define KVM_CAP_JOIN_MEMORY_REGIONS_WORKS 30
// /** @brief defines KVM_CAP_MCE for check extension */
// #define KVM_CAP_MCE 31
// /** @brief defines KVM_CAP_GET_TSC_KHZ for check extension */
// #define KVM_CAP_GET_TSC_KHZ 61
// /** @brief defines KVM_CAP_MAX_VCPUS for check extension */
// #define KVM_CAP_MAX_VCPUS 66
// /** @brief defines KVM_CAP_TSC_DEADLINE_TIMER for check extension */
// #define KVM_CAP_TSC_DEADLINE_TIMER 72
// /** @brief defines KVM_CAP_MAX_VCPU_ID for check extension */
// #define KVM_CAP_MAX_VCPU_ID 128
// /** @brief defines KVM_CAP_IMMEDIATE_EXIT for check extension */
// #define KVM_CAP_IMMEDIATE_EXIT 136
/** @brief defines KVM_MP_STATE_RUNNABLE for mp state */
#define KVM_MP_STATE_RUNNABLE 0
/** @brief defines KVM_MP_STATE_UNINITIALIZED for mp state */
#define KVM_MP_STATE_UNINITIALIZED 1
/** @brief defines KVM_MP_STATE_INIT_RECEIVED for mp state */
#define KVM_MP_STATE_INIT_RECEIVED 2
/** @brief defines KVM_MP_STATE_HALTED for mp state */
#define KVM_MP_STATE_HALTED 3
/** @brief defines KVM_MP_STATE_SIPI_RECEIVED for mp state */
#define KVM_MP_STATE_SIPI_RECEIVED 4


/*
 * Extension capability list.
 */
#define KVM_CAP_IRQCHIP   0
#define KVM_CAP_HLT   1
#define KVM_CAP_MMU_SHADOW_CACHE_CONTROL 2
#define KVM_CAP_USER_MEMORY 3
#define KVM_CAP_SET_TSS_ADDR 4
#define KVM_CAP_VAPIC 6
#define KVM_CAP_EXT_CPUID 7
#define KVM_CAP_CLOCKSOURCE 8
#define KVM_CAP_NR_VCPUS 9       /* returns recommended max vcpus per vm */
#define KVM_CAP_NR_MEMSLOTS 10   /* returns max memory slots per vm */
#define KVM_CAP_PIT 11
#define KVM_CAP_NOP_IO_DELAY 12
#define KVM_CAP_PV_MMU 13
#define KVM_CAP_MP_STATE 14
#define KVM_CAP_COALESCED_MMIO 15
#define KVM_CAP_SYNC_MMU 16  /* Changes to host mmap are reflected in guest */
#define KVM_CAP_IOMMU 18
/* Bug in KVM_SET_USER_MEMORY_REGION fixed: */
#define KVM_CAP_DESTROY_MEMORY_REGION_WORKS 21
#define KVM_CAP_USER_NMI 22
#define KVM_CAP_SET_GUEST_DEBUG 23
#define KVM_CAP_REINJECT_CONTROL 24
#define KVM_CAP_IRQ_ROUTING 25
#define KVM_CAP_IRQ_INJECT_STATUS 26
#define KVM_CAP_ASSIGN_DEV_IRQ 29
/* Another bug in KVM_SET_USER_MEMORY_REGION fixed: */
#define KVM_CAP_JOIN_MEMORY_REGIONS_WORKS 30
#define KVM_CAP_MCE 31
#define KVM_CAP_IRQFD 32
#define KVM_CAP_PIT2 33
#define KVM_CAP_SET_BOOT_CPU_ID 34
#define KVM_CAP_PIT_STATE2 35
#define KVM_CAP_IOEVENTFD 36
#define KVM_CAP_SET_IDENTITY_MAP_ADDR 37
#define KVM_CAP_XEN_HVM 38
#define KVM_CAP_ADJUST_CLOCK 39
#define KVM_CAP_INTERNAL_ERROR_DATA 40
#define KVM_CAP_VCPU_EVENTS 41
#define KVM_CAP_S390_PSW 42
#define KVM_CAP_PPC_SEGSTATE 43
#define KVM_CAP_HYPERV 44
#define KVM_CAP_HYPERV_VAPIC 45
#define KVM_CAP_HYPERV_SPIN 46
#define KVM_CAP_PCI_SEGMENT 47
#define KVM_CAP_PPC_PAIRED_SINGLES 48
#define KVM_CAP_INTR_SHADOW 49
#define KVM_CAP_DEBUGREGS 50
#define KVM_CAP_X86_ROBUST_SINGLESTEP 51
#define KVM_CAP_PPC_OSI 52
#define KVM_CAP_PPC_UNSET_IRQ 53
#define KVM_CAP_ENABLE_CAP 54
#define KVM_CAP_XSAVE 55
#define KVM_CAP_XCRS 56
#define KVM_CAP_PPC_GET_PVINFO 57
#define KVM_CAP_PPC_IRQ_LEVEL 58
#define KVM_CAP_ASYNC_PF 59
#define KVM_CAP_TSC_CONTROL 60
#define KVM_CAP_GET_TSC_KHZ 61
#define KVM_CAP_PPC_BOOKE_SREGS 62
#define KVM_CAP_SPAPR_TCE 63
#define KVM_CAP_PPC_SMT 64
#define KVM_CAP_PPC_RMA 65
#define KVM_CAP_MAX_VCPUS 66       /* returns max vcpus per vm */
#define KVM_CAP_PPC_HIOR 67
#define KVM_CAP_PPC_PAPR 68
#define KVM_CAP_SW_TLB 69
#define KVM_CAP_ONE_REG 70
#define KVM_CAP_S390_GMAP 71
#define KVM_CAP_TSC_DEADLINE_TIMER 72
#define KVM_CAP_S390_UCONTROL 73
#define KVM_CAP_SYNC_REGS 74
#define KVM_CAP_PCI_2_3 75
#define KVM_CAP_KVMCLOCK_CTRL 76
#define KVM_CAP_SIGNAL_MSI 77
#define KVM_CAP_PPC_GET_SMMU_INFO 78
#define KVM_CAP_S390_COW 79
#define KVM_CAP_PPC_ALLOC_HTAB 80
#define KVM_CAP_READONLY_MEM 81
#define KVM_CAP_IRQFD_RESAMPLE 82
#define KVM_CAP_PPC_BOOKE_WATCHDOG 83
#define KVM_CAP_PPC_HTAB_FD 84
#define KVM_CAP_S390_CSS_SUPPORT 85
#define KVM_CAP_PPC_EPR 86
#define KVM_CAP_ARM_PSCI 87
#define KVM_CAP_ARM_SET_DEVICE_ADDR 88
#define KVM_CAP_DEVICE_CTRL 89
#define KVM_CAP_IRQ_MPIC 90
#define KVM_CAP_PPC_RTAS 91
#define KVM_CAP_IRQ_XICS 92
#define KVM_CAP_ARM_EL1_32BIT 93
#define KVM_CAP_SPAPR_MULTITCE 94
#define KVM_CAP_EXT_EMUL_CPUID 95
#define KVM_CAP_HYPERV_TIME 96
#define KVM_CAP_IOAPIC_POLARITY_IGNORED 97
#define KVM_CAP_ENABLE_CAP_VM 98
#define KVM_CAP_S390_IRQCHIP 99
#define KVM_CAP_IOEVENTFD_NO_LENGTH 100
#define KVM_CAP_VM_ATTRIBUTES 101
#define KVM_CAP_ARM_PSCI_0_2 102
#define KVM_CAP_PPC_FIXUP_HCALL 103
#define KVM_CAP_PPC_ENABLE_HCALL 104
#define KVM_CAP_CHECK_EXTENSION_VM 105
#define KVM_CAP_S390_USER_SIGP 106
#define KVM_CAP_S390_VECTOR_REGISTERS 107
#define KVM_CAP_S390_MEM_OP 108
#define KVM_CAP_S390_USER_STSI 109
#define KVM_CAP_S390_SKEYS 110
#define KVM_CAP_MIPS_FPU 111
#define KVM_CAP_MIPS_MSA 112
#define KVM_CAP_S390_INJECT_IRQ 113
#define KVM_CAP_S390_IRQ_STATE 114
#define KVM_CAP_PPC_HWRNG 115
#define KVM_CAP_DISABLE_QUIRKS 116
#define KVM_CAP_X86_SMM 117
#define KVM_CAP_MULTI_ADDRESS_SPACE 118
#define KVM_CAP_GUEST_DEBUG_HW_BPS 119
#define KVM_CAP_GUEST_DEBUG_HW_WPS 120
#define KVM_CAP_SPLIT_IRQCHIP 121
#define KVM_CAP_IOEVENTFD_ANY_LENGTH 122
#define KVM_CAP_HYPERV_SYNIC 123
#define KVM_CAP_S390_RI 124
#define KVM_CAP_SPAPR_TCE_64 125
#define KVM_CAP_ARM_PMU_V3 126
#define KVM_CAP_VCPU_ATTRIBUTES 127
#define KVM_CAP_MAX_VCPU_ID 128
#define KVM_CAP_X2APIC_API 129
#define KVM_CAP_S390_USER_INSTR0 130
#define KVM_CAP_MSI_DEVID 131
#define KVM_CAP_PPC_HTM 132
#define KVM_CAP_SPAPR_RESIZE_HPT 133
#define KVM_CAP_PPC_MMU_RADIX 134
#define KVM_CAP_PPC_MMU_HASH_V3 135
#define KVM_CAP_IMMEDIATE_EXIT 136
#define KVM_CAP_MIPS_VZ 137
#define KVM_CAP_MIPS_TE 138
#define KVM_CAP_MIPS_64BIT 139
#define KVM_CAP_S390_GS 140
#define KVM_CAP_S390_AIS 141
#define KVM_CAP_SPAPR_TCE_VFIO 142
#define KVM_CAP_X86_DISABLE_EXITS 143
#define KVM_CAP_ARM_USER_IRQ 144
#define KVM_CAP_S390_CMMA_MIGRATION 145
#define KVM_CAP_PPC_FWNMI 146
#define KVM_CAP_PPC_SMT_POSSIBLE 147
#define KVM_CAP_HYPERV_SYNIC2 148
#define KVM_CAP_HYPERV_VP_INDEX 149
#define KVM_CAP_S390_AIS_MIGRATION 150
#define KVM_CAP_PPC_GET_CPU_CHAR 151
#define KVM_CAP_S390_BPB 152
#define KVM_CAP_GET_MSR_FEATURES 153
#define KVM_CAP_HYPERV_EVENTFD 154
#define KVM_CAP_HYPERV_TLBFLUSH 155
#define KVM_CAP_S390_HPAGE_1M 156
#define KVM_CAP_NESTED_STATE 157
#define KVM_CAP_ARM_INJECT_SERROR_ESR 158
#define KVM_CAP_MSR_PLATFORM_INFO 159
#define KVM_CAP_PPC_NESTED_HV 160
#define KVM_CAP_HYPERV_SEND_IPI 161
#define KVM_CAP_COALESCED_PIO 162
#define KVM_CAP_HYPERV_ENLIGHTENED_VMCS 163
#define KVM_CAP_EXCEPTION_PAYLOAD 164
#define KVM_CAP_ARM_VM_IPA_SIZE 165
#define KVM_CAP_MANUAL_DIRTY_LOG_PROTECT 166 /* Obsolete */
#define KVM_CAP_HYPERV_CPUID 167
#define KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 168
#define KVM_CAP_PPC_IRQ_XIVE 169
#define KVM_CAP_ARM_SVE 170
#define KVM_CAP_ARM_PTRAUTH_ADDRESS 171
#define KVM_CAP_ARM_PTRAUTH_GENERIC 172
#define KVM_CAP_PMU_EVENT_FILTER 173
#define KVM_CAP_ARM_IRQ_LINE_LAYOUT_2 174
#define KVM_CAP_HYPERV_DIRECT_TLBFLUSH 175


#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
