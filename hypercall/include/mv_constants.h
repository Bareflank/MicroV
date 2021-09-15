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

#ifndef MV_CONSTANTS_H
#define MV_CONSTANTS_H

#include <constants.h>
#include <mv_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // -------------------------------------------------------------------------
    // Page Alignment
    // -------------------------------------------------------------------------

    /**
     * <!-- description -->
     *   @brief Returns true if the provided address is page aligned,
     *     returns false otherwise.
     *
     * <!-- inputs/outputs -->
     *   @param addr the address to query
     *   @return Returns 0 if the provided address is page aligned,
     *     returns a non-zero value otherwise.
     */
    NODISCARD static inline uint64_t
    mv_is_page_aligned(uint64_t const addr) NOEXCEPT
    {
        uint64_t const mask = HYPERVISOR_PAGE_SIZE - ((uint64_t)1);
        return (addr & mask);
    }

    /**
 * <!-- description -->
 *   @brief Returns the page aligned version of the addr
 *
 * <!-- inputs/outputs -->
 *   @param addr the address to query
 *   @return Returns the page aligned version of the addr
 */
    NODISCARD static inline uint64_t
    mv_page_aligned(uint64_t const addr) NOEXCEPT
    {
        uint64_t const one = ((uint64_t)1);
        return (addr & ~(HYPERVISOR_PAGE_SIZE - one));
    }

/* -------------------------------------------------------------------------- */
/* Handle                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * NOTE:
 * - Currently, MicroV does not use the handle. This will be updated in
 *   the future so that opening a handle will return a unique value, and
 *   all resources that are created are owned by that handle, so although
 *   it is hardcoded for now, it will not be in the future.
 */

/** @brief Internal to MicroV */
#define MV_HANDLE_VAL ((uint64_t)0x42)

/* -------------------------------------------------------------------------- */
/* Handle                                                                     */
/* -------------------------------------------------------------------------- */

/** @brief Indicates the map has read access */
#define MV_MAP_FLAG_READ_ACCESS ((uint64_t)0x0000000000000001);
/** @brief Indicates the map has write access */
#define MV_MAP_FLAG_WRITE_ACCESS ((uint64_t)0x0000000000000002);
/** @brief Indicates the map has execute access */
#define MV_MAP_FLAG_EXECUTE_ACCESS ((uint64_t)0x0000000000000004);
/** @brief Indicates the map has user privileges */
#define MV_MAP_FLAG_USER ((uint64_t)0x0000000000000008);
/** @brief Indicates the map is 4k in size */
#define MV_MAP_FLAG_4K_PAGE ((uint64_t)0x0000000000000200);
/** @brief Indicates the map is 2m in size */
#define MV_MAP_FLAG_2M_PAGE ((uint64_t)0x0000000000000400);
/** @brief Indicates the map is 1g in size */
#define MV_MAP_FLAG_1G_PAGE ((uint64_t)0x0000000000000800);
/** @brief Indicates the map is mapped as UC */
#define MV_MAP_FLAG_UNCACHEABLE ((uint64_t)0x0200000000000000);
/** @brief Indicates the map is mapped as UC- */
#define MV_MAP_FLAG_UNCACHEABLE_MINUS ((uint64_t)0x0400000000000000);
/** @brief Indicates the map is mapped as WC */
#define MV_MAP_FLAG_WRITE_COMBINING ((uint64_t)0x0800000000000000);
/** @brief Indicates the map is mapped as WC +*/
#define MV_MAP_FLAG_WRITE_COMBINING_PLUS ((uint64_t)0x1000000000000000);
/** @brief Indicates the map is mapped as WT */
#define MV_MAP_FLAG_WRITE_THROUGH ((uint64_t)0x2000000000000000);
/** @brief Indicates the map is mapped as WB */
#define MV_MAP_FLAG_WRITE_BACK ((uint64_t)0x4000000000000000);
/** @brief Indicates the map is mapped as WP */
#define MV_MAP_FLAG_WRITE_PROTECTED ((uint64_t)0x8000000000000000);

/* -------------------------------------------------------------------------- */
/* Special IDs                                                                */
/* -------------------------------------------------------------------------- */

/** @brief Defines an invalid ID for an extension, VM, VP and VS */
#define MV_INVALID_ID ((uint16_t)0xFFFF)

/** @brief Defines the ID for "self" */
#define MV_SELF_ID ((uint16_t)0xFFFE)

/** @brief Defines the ID for "all" */
#define MV_ALL_ID ((uint16_t)0xFFFD)

/** @brief Defines the bootstrap physical processor ID */
#define MV_BS_PPID ((uint16_t)0x0)

/** @brief Defines the root virtual machine ID */
#define MV_ROOT_VMID ((uint16_t)0x0)

/* -------------------------------------------------------------------------- */
/* Hypercall Status Codes                                                     */
/* -------------------------------------------------------------------------- */

/** @brief Indicates the hypercall returned successfully */
#define MV_STATUS_SUCCESS ((uint64_t)0x0000000000000000)
/** @brief Indicates an unknown error occurred */
#define MV_STATUS_FAILURE_UNKNOWN ((uint64_t)0xDEAD000000010001)
/** @brief Indicates the hypercall is unsupported */
#define MV_STATUS_FAILURE_INVALID_HANDLE ((uint64_t)0xDEAD000000020001)
/** @brief Indicates the provided handle is invalid */
#define MV_STATUS_FAILURE_UNSUPPORTED ((uint64_t)0xDEAD000000040001)
/** @brief Indicates the policy engine denied the hypercall */
#define MV_STATUS_INVALID_PERM_DENIED ((uint64_t)0xDEAD000000010002)
/** @brief Indicates input reg0 is invalid */
#define MV_STATUS_INVALID_INPUT_REG0 ((uint64_t)0xDEAD000000010003)
/** @brief Indicates input reg1 is invalid */
#define MV_STATUS_INVALID_INPUT_REG1 ((uint64_t)0xDEAD000000020003)
/** @brief Indicates input reg2 is invalid */
#define MV_STATUS_INVALID_INPUT_REG2 ((uint64_t)0xDEAD000000040003)
/** @brief Indicates input reg3 is invalid */
#define MV_STATUS_INVALID_INPUT_REG3 ((uint64_t)0xDEAD000000080003)
/** @brief Indicates output reg0 is invalid */
#define MV_STATUS_INVALID_OUTPUT_REG0 ((uint64_t)0xDEAD000000100003)
/** @brief Indicates output reg1 is invalid */
#define MV_STATUS_INVALID_OUTPUT_REG1 ((uint64_t)0xDEAD000000200003)
/** @brief Indicates output reg2 is invalid */
#define MV_STATUS_INVALID_OUTPUT_REG2 ((uint64_t)0xDEAD000000400003)
/** @brief Indicates output reg3 is invalid */
#define MV_STATUS_INVALID_OUTPUT_REG3 ((uint64_t)0xDEAD000000800003)
/** @brief Indicates software should execute the hypercall again */
#define MV_STATUS_RETRY_CONTINUATION ((uint64_t)0xDEAD000000100004)

/* -------------------------------------------------------------------------- */
/* Syscall Inputs                                                             */
/* -------------------------------------------------------------------------- */

/** @brief Defines the MV_HYPERCALL_SIG field for RAX */
#define MV_HYPERCALL_SIG_VAL ((uint64_t)0x764D000000000000)
/** @brief Defines a mask for MV_HYPERCALL_SIG */
#define MV_HYPERCALL_SIG_MASK ((uint64_t)0xFFFF000000000000)
/** @brief Defines a mask for MV_HYPERCALL_FLAGS */
#define MV_HYPERCALL_FLAGS_MASK ((uint64_t)0x0000FFFF00000000)
/** @brief Defines a mask for MV_HYPERCALL_OP */
#define MV_HYPERCALL_OPCODE_MASK ((uint64_t)0xFFFF0000FFFF0000)
/** @brief Defines a mask for MV_HYPERCALL_OP (with no signature added) */
#define MV_HYPERCALL_OPCODE_NOSIG_MASK ((uint64_t)0x00000000FFFF0000)
/** @brief Defines a mask for MV_HYPERCALL_IDX */
#define MV_HYPERCALL_INDEX_MASK ((uint64_t)0x000000000000FFFF)

    /**
 * <!-- description -->
 *   @brief n/a
 *
 * <!-- inputs/outputs -->
 *   @param rax n/a
 *   @return n/a
 */
    NODISCARD static inline uint64_t
    mv_hypercall_sig(uint64_t const rax) NOEXCEPT
    {
        return rax & MV_HYPERCALL_SIG_MASK;
    }

    /**
 * <!-- description -->
 *   @brief n/a
 *
 * <!-- inputs/outputs -->
 *   @param rax n/a
 *   @return n/a
 */
    NODISCARD static inline uint64_t
    mv_hypercall_flags(uint64_t const rax) NOEXCEPT
    {
        return rax & MV_HYPERCALL_FLAGS_MASK;
    }

    /**
 * <!-- description -->
 *   @brief n/a
 *
 * <!-- inputs/outputs -->
 *   @param rax n/a
 *   @return n/a
 */
    NODISCARD static inline uint64_t
    mv_hypercall_opcode(uint64_t const rax) NOEXCEPT
    {
        return rax & MV_HYPERCALL_OPCODE_MASK;
    }

    /**
 * <!-- description -->
 *   @brief n/a
 *
 * <!-- inputs/outputs -->
 *   @param rax n/a
 *   @return n/a
 */
    NODISCARD static inline uint64_t
    mv_hypercall_opcode_nosig(uint64_t const rax) NOEXCEPT
    {
        return rax & MV_HYPERCALL_OPCODE_NOSIG_MASK;
    }

    /**
 * <!-- description -->
 *   @brief n/a
 *
 * <!-- inputs/outputs -->
 *   @param rax n/a
 *   @return n/a
 */
    NODISCARD static inline uint64_t
    mv_hypercall_index(uint64_t const rax) NOEXCEPT
    {
        return rax & MV_HYPERCALL_INDEX_MASK;
    }

/* -------------------------------------------------------------------------- */
/* Specification IDs                                                          */
/* -------------------------------------------------------------------------- */

/** @brief Defines the ID for version #1 of this spec */
#define MV_SPEC_ID1_VAL ((uint32_t)0x3123764D)

/** @brief Defines the mask for checking support for version #1 of this spec */
#define MV_SPEC_ID1_MASK ((uint32_t)0x2)

/** @brief Defines all versions supported */
#define MV_ALL_SPECS_SUPPORTED_VAL ((uint32_t)0x2)

/** @brief Defines an invalid version */
#define MV_INVALID_VERSION ((uint32_t)0x80000000)

    /**
 * <!-- description -->
 *   @brief n/a
 *
 * <!-- inputs/outputs -->
 *   @param version n/a
 *   @return n/a
 */
    NODISCARD static inline int32_t
    mv_is_spec1_supported(uint32_t const version) NOEXCEPT
    {
        if (((uint32_t)0) == (version & MV_SPEC_ID1_MASK)) {
            return 1;
        }

        return 0;
    }

/* -------------------------------------------------------------------------- */
/* Hypercall Opcodes - ID Support                                             */
/* -------------------------------------------------------------------------- */

/** @brief Defines the hypercall opcode for mv_id_op */
#define MV_ID_OP_VAL ((uint64_t)0x764D000000000000)
/** @brief Defines the hypercall opcode for mv_id_op (nosig) */
#define MV_ID_OP_NOSIG_VAL ((uint64_t)0x0000000000000000)

/* -------------------------------------------------------------------------- */
/* Hypercall Opcodes - Handle Support                                         */
/* -------------------------------------------------------------------------- */

/** @brief Defines the hypercall opcode for mv_handle_op */
#define MV_HANDLE_OP_VAL ((uint64_t)0x764D000000010000)
/** @brief Defines the hypercall opcode for mv_handle_op (nosig) */
#define MV_HANDLE_OP_NOSIG_VAL ((uint64_t)0x0000000000010000)

/* -------------------------------------------------------------------------- */
/* Hypercall Opcodes - Debug Support                                          */
/* -------------------------------------------------------------------------- */

/** @brief Defines the hypercall opcode for mv_debug_op */
#define MV_DEBUG_OP_VAL ((uint64_t)0x764D000000020000)
/** @brief Defines the hypercall opcode for mv_debug_op (nosig) */
#define MV_DEBUG_OP_NOSIG_VAL ((uint64_t)0x00000000000020000)

/* -------------------------------------------------------------------------- */
/* Hypercall Opcodes - PP Support                                             */
/* -------------------------------------------------------------------------- */

/** @brief Defines the hypercall opcode for mv_pp_op */
#define MV_PP_OP_VAL ((uint64_t)0x764D000000030000)
/** @brief Defines the hypercall opcode for mv_pp_op (nosig) */
#define MV_PP_OP_NOSIG_VAL ((uint64_t)0x0000000000030000)

/* -------------------------------------------------------------------------- */
/* Hypercall Opcodes - VM Support                                             */
/* -------------------------------------------------------------------------- */

/** @brief Defines the hypercall opcode for mv_vm_op */
#define MV_VM_OP_VAL ((uint64_t)0x764D000000040000)
/** @brief Defines the hypercall opcode for mv_vm_op (nosig) */
#define MV_VM_OP_NOSIG_VAL ((uint64_t)0x0000000000040000)

/* -------------------------------------------------------------------------- */
/* Hypercall Opcodes - VP Support                                             */
/* -------------------------------------------------------------------------- */

/** @brief Defines the hypercall opcode for mv_vp_op */
#define MV_VP_OP_VAL ((uint64_t)0x764D000000050000)
/** @brief Defines the hypercall opcode for mv_vp_op (nosig) */
#define MV_VP_OP_NOSIG_VAL ((uint64_t)0x0000000000050000)

/* -------------------------------------------------------------------------- */
/* Hypercall Opcodes - VS Support                                            */
/* -------------------------------------------------------------------------- */

/** @brief Defines the hypercall opcode for mv_vs_op */
#define MV_VS_OP_VAL ((uint64_t)0x764D000000060000)
/** @brief Defines the hypercall opcode for mv_vs_op (nosig) */
#define MV_VS_OP_NOSIG_VAL ((uint64_t)0x0000000000060000)

/* -------------------------------------------------------------------------- */
/* Hypercall Related Constants                                                */
/* -------------------------------------------------------------------------- */

/** @brief Defines the index for mv_id_op_version */
#define MV_INVALID_HANDLE ((uint64_t)0xFFFFFFFFFFFFFFFF)

/* -------------------------------------------------------------------------- */
/* Hypercall Indexes                                                          */
/* -------------------------------------------------------------------------- */

/** @brief Defines the index for mv_id_op_version */
#define MV_ID_OP_VERSION_IDX_VAL ((uint64_t)0x0000000000000000)
/** @brief Defines the index for mv_id_op_has_capability */
#define MV_ID_OP_HAS_CAPABILITY_IDX_VAL ((uint64_t)0x0000000000000001)
/** @brief Defines the index for mv_id_op_clr_capability */
#define MV_ID_OP_CLR_CAPABILITY_IDX_VAL ((uint64_t)0x0000000000000002)
/** @brief Defines the index for mv_id_op_set_capability */
#define MV_ID_OP_SET_CAPABILITY_IDX_VAL ((uint64_t)0x0000000000000003)

/** @brief Defines the index for mv_handle_op_open_handle */
#define MV_HANDLE_OP_OPEN_HANDLE_IDX_VAL ((uint64_t)0x0000000000000000)
/** @brief Defines the index for mv_handle_op_close_handle */
#define MV_HANDLE_OP_CLOSE_HANDLE_IDX_VAL ((uint64_t)0x0000000000000001)

/** @brief Defines the index for mv_debug_op_out */
#define MV_DEBUG_OP_OUT_IDX_VAL ((uint64_t)0x0000000000000000)

/** @brief Defines the index for mv_pp_op_ppid */
#define MV_PP_OP_PPID_IDX_VAL ((uint64_t)0x0000000000000000)
/** @brief Defines the index for mv_pp_op_clr_shared_page_gpa */
#define MV_PP_OP_CLR_SHARED_PAGE_GPA_IDX_VAL ((uint64_t)0x0000000000000001)
/** @brief Defines the index for mv_pp_op_set_shared_page_gpa */
#define MV_PP_OP_SET_SHARED_PAGE_GPA_IDX_VAL ((uint64_t)0x0000000000000002)
/** @brief Defines the index for mv_pp_op_cpuid_get_supported */
#define MV_PP_OP_CPUID_GET_SUPPORTED_IDX_VAL ((uint64_t)0x0000000000000003)
/** @brief Defines the index for mv_pp_op_cpuid_get_permissable */
#define MV_PP_OP_CPUID_GET_PERMISSABLE_IDX_VAL ((uint64_t)0x0000000000000004)
/** @brief Defines the index for mv_pp_op_cpuid_get_emulated */
#define MV_PP_OP_CPUID_GET_EMULATED_IDX_VAL ((uint64_t)0x0000000000000005)
/** @brief Defines the index for mv_pp_op_reg_get_supported */
#define MV_PP_OP_REG_GET_SUPPORTED_IDX_VAL ((uint64_t)0x0000000000000006)
/** @brief Defines the index for mv_pp_op_reg_get_permissable */
#define MV_PP_OP_REG_GET_PERMISSABLE_IDX_VAL ((uint64_t)0x0000000000000007)
/** @brief Defines the index for mv_pp_op_reg_get_emulated */
#define MV_PP_OP_REG_GET_EMULATED_IDX_VAL ((uint64_t)0x0000000000000008)
/** @brief Defines the index for mv_pp_op_msr_get_supported */
#define MV_PP_OP_MSR_GET_SUPPORTED_IDX_VAL ((uint64_t)0x000000000000009)
/** @brief Defines the index for mv_pp_op_msr_get_permissable */
#define MV_PP_OP_MSR_GET_PERMISSABLE_IDX_VAL ((uint64_t)0x000000000000000A)
/** @brief Defines the index for mv_pp_op_msr_get_emulated */
#define MV_PP_OP_MSR_GET_EMULATED_IDX_VAL ((uint64_t)0x000000000000000B)
/** @brief Defines the index for mv_pp_op_tsc_get_khz */
#define MV_PP_OP_TSC_GET_KHZ_IDX_VAL ((uint64_t)0x000000000000000C)
/** @brief Defines the index for mv_pp_op_tsc_set_khz */
#define MV_PP_OP_TSC_SET_KHZ_IDX_VAL ((uint64_t)0x000000000000000D)

/** @brief Defines the index for mv_vm_op_create_vm */
#define MV_VM_OP_CREATE_VM_IDX_VAL ((uint64_t)0x0000000000000000)
/** @brief Defines the index for mv_vm_op_destroy_vm */
#define MV_VM_OP_DESTROY_VM_IDX_VAL ((uint64_t)0x0000000000000001)
/** @brief Defines the index for mv_vm_op_vmid */
#define MV_VM_OP_VMID_IDX_VAL ((uint64_t)0x0000000000000002)
/** @brief Defines the index for mv_vm_op_io_clr_trap */
#define MV_VM_OP_IO_CLR_TRAP_IDX_VAL ((uint64_t)0x0000000000000003)
/** @brief Defines the index for mv_vm_op_io_set_trap */
#define MV_VM_OP_IO_SET_TRAP_IDX_VAL ((uint64_t)0x0000000000000004)
/** @brief Defines the index for mv_vm_op_io_clr_trap_all */
#define MV_VM_OP_IO_CLR_TRAP_ALL_IDX_VAL ((uint64_t)0x0000000000000005)
/** @brief Defines the index for mv_vm_op_io_set_trap_all */
#define MV_VM_OP_IO_SET_TRAP_ALL_IDX_VAL ((uint64_t)0x0000000000000006)
/** @brief Defines the index for mv_vm_op_mmio_map */
#define MV_VM_OP_MMIO_MAP_IDX_VAL ((uint64_t)0x0000000000000007)
/** @brief Defines the index for mv_vm_op_mmio_unmap */
#define MV_VM_OP_MMIO_UNMAP_IDX_VAL ((uint64_t)0x0000000000000008)
/** @brief Defines the index for mv_vm_op_mmio_clr_trap */
#define MV_VM_OP_MMIO_CLR_TRAP_IDX_VAL ((uint64_t)0x0000000000000009)
/** @brief Defines the index for mv_vm_op_mmio_set_trap */
#define MV_VM_OP_MMIO_SET_TRAP_IDX_VAL ((uint64_t)0x000000000000000A)
/** @brief Defines the index for mv_vm_op_mmio_clr_trap_all */
#define MV_VM_OP_MMIO_CLR_TRAP_ALL_IDX_VAL ((uint64_t)0x000000000000000B)
/** @brief Defines the index for mv_vm_op_mmio_set_trap_all */
#define MV_VM_OP_MMIO_SET_TRAP_ALL_IDX_VAL ((uint64_t)0x000000000000000C)
/** @brief Defines the index for mv_vm_op_msr_clr_trap */
#define MV_VM_OP_MSR_CLR_TRAP_IDX_VAL ((uint64_t)0x000000000000000D)
/** @brief Defines the index for mv_vm_op_msr_set_trap */
#define MV_VM_OP_MSR_SET_TRAP_IDX_VAL ((uint64_t)0x000000000000000E)
/** @brief Defines the index for mv_vm_op_msr_clr_trap_all */
#define MV_VM_OP_MSR_CLR_TRAP_ALL_IDX_VAL ((uint64_t)0x000000000000000F)
/** @brief Defines the index for mv_vm_op_msr_set_trap_all */
#define MV_VM_OP_MSR_SET_TRAP_ALL_IDX_VAL ((uint64_t)0x0000000000000010)

/** @brief Defines the index for mv_vp_op_create_vp */
#define MV_VP_OP_CREATE_VP_IDX_VAL ((uint64_t)0x0000000000000000)
/** @brief Defines the index for mv_vp_op_destroy_vp */
#define MV_VP_OP_DESTROY_VP_IDX_VAL ((uint64_t)0x0000000000000001)
/** @brief Defines the index for mv_vp_op_vmid */
#define mv_vp_op_vmid_IDX_VAL ((uint64_t)0x0000000000000002)
/** @brief Defines the index for mv_vp_op_vpid */
#define mv_vp_op_vpid_IDX_VAL ((uint64_t)0x0000000000000003)

/** @brief Defines the index for mv_vs_op_create_vs */
#define MV_VS_OP_CREATE_VS_IDX_VAL ((uint64_t)0x0000000000000000)
/** @brief Defines the index for mv_vs_op_destroy_vs */
#define MV_VS_OP_DESTROY_VS_IDX_VAL ((uint64_t)0x0000000000000001)
/** @brief Defines the index for mv_vs_op_vmid */
#define MV_VS_OP_VMID_IDX_VAL ((uint64_t)0x0000000000000002)
/** @brief Defines the index for mv_vs_op_vpid */
#define MV_VS_OP_VPID_IDX_VAL ((uint64_t)0x0000000000000003)
/** @brief Defines the index for mv_vs_op_vsid */
#define MV_VS_OP_VSID_IDX_VAL ((uint64_t)0x0000000000000004)
/** @brief Defines the index for mv_vs_op_gva_to_gla */
#define MV_VS_OP_GVA_TO_GLA_IDX_VAL ((uint64_t)0x0000000000000005)
/** @brief Defines the index for mv_vs_op_gla_to_gpa */
#define MV_VS_OP_GLA_TO_GPA_IDX_VAL ((uint64_t)0x0000000000000006)
/** @brief Defines the index for mv_vs_op_gva_to_gpa */
#define MV_VS_OP_GVA_TO_GPA_IDX_VAL ((uint64_t)0x0000000000000007)
/** @brief Defines the index for mv_vs_op_run */
#define MV_VS_OP_RUN_IDX_VAL ((uint64_t)0x0000000000000008)
/** @brief Defines the index for mv_vs_op_cpuid_get */
#define MV_VS_OP_CPUID_GET_IDX_VAL ((uint64_t)0x0000000000000009)
/** @brief Defines the index for mv_vs_op_cpuid_set */
#define MV_VS_OP_CPUID_SET_IDX_VAL ((uint64_t)0x000000000000000A)
/** @brief Defines the index for mv_vs_op_cpuid_get_all */
#define MV_VS_OP_CPUID_GET_ALL_IDX_VAL ((uint64_t)0x000000000000000B)
/** @brief Defines the index for mv_vs_op_cpuid_set_all */
#define MV_VS_OP_CPUID_SET_ALL_IDX_VAL ((uint64_t)0x000000000000000C)
/** @brief Defines the index for mv_vs_op_reg_get */
#define MV_VS_OP_REG_GET_IDX_VAL ((uint64_t)0x000000000000000D)
/** @brief Defines the index for mv_vs_op_reg_set */
#define MV_VS_OP_REG_SET_IDX_VAL ((uint64_t)0x000000000000000E)
/** @brief Defines the index for mv_vs_op_reg_get_list */
#define MV_VS_OP_REG_GET_LIST_IDX_VAL ((uint64_t)0x000000000000000F)
/** @brief Defines the index for mv_vs_op_reg_set_list */
#define MV_VS_OP_REG_SET_LIST_IDX_VAL ((uint64_t)0x0000000000000010)
/** @brief Defines the index for mv_vs_op_msr_get */
#define MV_VS_OP_MSR_GET_IDX_VAL ((uint64_t)0x0000000000000017)
/** @brief Defines the index for mv_vs_op_msr_set */
#define MV_VS_OP_MSR_SET_IDX_VAL ((uint64_t)0x0000000000000018)
/** @brief Defines the index for mv_vs_op_msr_get_list */
#define MV_VS_OP_MSR_GET_LIST_IDX_VAL ((uint64_t)0x0000000000000019)
/** @brief Defines the index for mv_vs_op_msr_set_list */
#define MV_VS_OP_MSR_SET_LIST_IDX_VAL ((uint64_t)0x000000000000001A)
/** @brief Defines the index for mv_vs_op_fpu_get */
#define MV_VS_OP_FPU_GET_IDX_VAL ((uint64_t)0x000000000000001B)
/** @brief Defines the index for mv_vs_op_fpu_set */
#define MV_VS_OP_FPU_SET_IDX_VAL ((uint64_t)0x000000000000001C)
/** @brief Defines the index for mv_vs_op_fpu_get_all */
#define MV_VS_OP_FPU_GET_ALL_IDX_VAL ((uint64_t)0x000000000000001D)
/** @brief Defines the index for mv_vs_op_fpu_set_all */
#define MV_VS_OP_FPU_SET_ALL_IDX_VAL ((uint64_t)0x000000000000001E)
/** @brief Defines the index for mv_vs_op_xsave_get */
#define MV_VS_OP_XSAVE_GET_IDX_VAL ((uint64_t)0x000000000000001F)
/** @brief Defines the index for mv_vs_op_xsave_set */
#define MV_VS_OP_XSAVE_SET_IDX_VAL ((uint64_t)0x0000000000000020)
/** @brief Defines the index for mv_vs_op_xsave_get_all */
#define MV_VS_OP_XSAVE_GET_ALL_IDX_VAL ((uint64_t)0x0000000000000021)
/** @brief Defines the index for mv_vs_op_xsave_set_all */
#define MV_VS_OP_XSAVE_SET_ALL_IDX_VAL ((uint64_t)0x0000000000000022)

#ifdef __cplusplus
}
#endif

#endif
