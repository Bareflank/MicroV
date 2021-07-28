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

#ifndef MV_CONSTANTS_HPP
#define MV_CONSTANTS_HPP

#include <mv_types.hpp>

#include <bsl/convert.hpp>

namespace hypercall
{
    // -------------------------------------------------------------------------
    // Page Alignment
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns true if the provided address is page aligned,
    ///     returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param addr the address to query
    ///   @return Returns true if the provided address is page aligned,
    ///     returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    mv_is_page_aligned(bsl::safe_uint64 const &addr) noexcept -> bool
    {
        constexpr auto mask{0x0000000000000FFF_u64};
        return (addr & mask).is_zero();
    }

    // -------------------------------------------------------------------------
    // Handle
    // -------------------------------------------------------------------------

    /// NOTE:
    /// - Currently, MicroV does not use the handle. This will be updated in
    ///   the future so that opening a handle will return a unique value, and
    ///   all resources that are created are owned by that handle, so although
    ///   it is hardcoded for now, it will not be in the future.
    ///

    /// @brief Internal to MicroV
    constexpr auto MV_HANDLE_VAL{0x42_u64};

    // -------------------------------------------------------------------------
    // Special IDs
    // -------------------------------------------------------------------------

    /// @brief Defines an invalid ID for an extension, VM, VP and VPS
    constexpr auto MV_INVALID_ID{0xFFFF_u16};

    /// @brief Defines the ID for "self"
    constexpr auto MV_SELF_ID{0xFFFE_u16};

    /// @brief Defines the ID for "all"
    constexpr auto MV_ALL_ID{0xFFFD_u16};

    /// @brief Defines the bootstrap physical processor ID
    constexpr auto MV_BS_PPID{0x0_u16};

    /// @brief Defines the root virtual machine ID
    constexpr auto MV_ROOT_VMID{0x0_u16};

    // -------------------------------------------------------------------------
    // Hypercall Status Codes
    // -------------------------------------------------------------------------

    /// @brief Indicates the hypercall returned successfully
    constexpr auto MV_STATUS_SUCCESS{0x0000000000000000_u64};
    /// @brief Indicates an unknown error occurred
    constexpr auto MV_STATUS_FAILURE_UNKNOWN{0xDEAD000000010001_u64};
    /// @brief Indicates the hypercall is unsupported
    constexpr auto MV_STATUS_FAILURE_INVALID_HANDLE{0xDEAD000000020001_u64};
    /// @brief Indicates the provided handle is invalid
    constexpr auto MV_STATUS_FAILURE_UNSUPPORTED{0xDEAD000000040001_u64};
    /// @brief Indicates the policy engine denied the hypercall
    constexpr auto MV_STATUS_INVALID_PERM_DENIED{0xDEAD000000010002_u64};
    /// @brief Indicates input reg0 is invalid
    constexpr auto MV_STATUS_INVALID_INPUT_REG0{0xDEAD000000010003_u64};
    /// @brief Indicates input reg1 is invalid
    constexpr auto MV_STATUS_INVALID_INPUT_REG1{0xDEAD000000020003_u64};
    /// @brief Indicates input reg2 is invalid
    constexpr auto MV_STATUS_INVALID_INPUT_REG2{0xDEAD000000040003_u64};
    /// @brief Indicates input reg3 is invalid
    constexpr auto MV_STATUS_INVALID_INPUT_REG3{0xDEAD000000080003_u64};
    /// @brief Indicates output reg0 is invalid
    constexpr auto MV_STATUS_INVALID_OUTPUT_REG0{0xDEAD000000100003_u64};
    /// @brief Indicates output reg1 is invalid
    constexpr auto MV_STATUS_INVALID_OUTPUT_REG1{0xDEAD000000200003_u64};
    /// @brief Indicates output reg2 is invalid
    constexpr auto MV_STATUS_INVALID_OUTPUT_REG2{0xDEAD000000400003_u64};
    /// @brief Indicates output reg3 is invalid
    constexpr auto MV_STATUS_INVALID_OUTPUT_REG3{0xDEAD000000800003_u64};
    /// @brief Indicates software should execute the hypercall again
    constexpr auto MV_STATUS_RETRY_CONTINUATION{0xDEAD000000100004_u64};

    // -------------------------------------------------------------------------
    // Hypercall Inputs
    // -------------------------------------------------------------------------

    /// @brief Defines the MV_HYPERCALL_SIG field for RAX
    constexpr auto MV_HYPERCALL_SIG_VAL{0x764D000000000000_u64};
    /// @brief Defines a mask for MV_HYPERCALL_SIG
    constexpr auto MV_HYPERCALL_SIG_MASK{0xFFFF000000000000_u64};
    /// @brief Defines a mask for MV_HYPERCALL_FLAGS
    constexpr auto MV_HYPERCALL_FLAGS_MASK{0x0000FFFF00000000_u64};
    /// @brief Defines a mask for MV_HYPERCALL_OP
    constexpr auto MV_HYPERCALL_OPCODE_MASK{0xFFFF0000FFFF0000_u64};
    /// @brief Defines a mask for MV_HYPERCALL_OP (with no signature added)
    constexpr auto MV_HYPERCALL_OPCODE_NOSIG_MASK{0x00000000FFFF0000_u64};
    /// @brief Defines a mask for MV_HYPERCALL_IDX
    constexpr auto MV_HYPERCALL_INDEX_MASK{0x000000000000FFFF_u64};

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    mv_hypercall_sig(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & MV_HYPERCALL_SIG_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    mv_hypercall_flags(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & MV_HYPERCALL_FLAGS_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    mv_hypercall_opcode(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & MV_HYPERCALL_OPCODE_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    mv_hypercall_opcode_nosig(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & MV_HYPERCALL_OPCODE_NOSIG_MASK;
    }

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    mv_hypercall_index(bsl::safe_uint64 const &rax) noexcept -> bsl::safe_uint64
    {
        return rax & MV_HYPERCALL_INDEX_MASK;
    }

    // -------------------------------------------------------------------------
    // Specification IDs
    // -------------------------------------------------------------------------

    /// @brief Defines the ID for version #1 of this spec
    constexpr auto MV_SPEC_ID1_VAL{0x3123764D_u32};

    /// @brief Defines the mask for checking support for version #1 of this spec
    constexpr auto MV_SPEC_ID1_MASK{0x2_u32};

    /// @brief Defines all versions supported
    constexpr auto MV_ALL_SPECS_SUPPORTED_VAL{0x2_u32};

    /// @brief Defines an invalid version
    constexpr auto MV_INVALID_VERSION{0x80000000_u32};

    /// <!-- description -->
    ///   @brief n/a
    ///
    /// <!-- inputs/outputs -->
    ///   @param version n/a
    ///   @return n/a
    ///
    [[nodiscard]] constexpr auto
    mv_is_spec1_supported(bsl::safe_uint32 const &version) noexcept -> bool
    {
        return (!(version & MV_SPEC_ID1_MASK).is_zero());
    }

    // -------------------------------------------------------------------------
    // Hypercall Opcodes - ID Support
    // -------------------------------------------------------------------------

    /// @brief Defines the hypercall opcode for mv_id_op
    constexpr auto MV_ID_OP_VAL{0x764D000000000000_u64};
    /// @brief Defines the hypercall opcode for mv_id_op (nosig)
    constexpr auto MV_ID_OP_NOSIG_VAL{0x0000000000000000_u64};

    // -------------------------------------------------------------------------
    // Hypercall Opcodes - Handle Support
    // -------------------------------------------------------------------------

    /// @brief Defines the hypercall opcode for mv_handle_op
    constexpr auto MV_HANDLE_OP_VAL{0x764D000000010000_u64};
    /// @brief Defines the hypercall opcode for mv_handle_op (nosig)
    constexpr auto MV_HANDLE_OP_NOSIG_VAL{0x0000000000010000_u64};

    // -------------------------------------------------------------------------
    // Hypercall Opcodes - Debug Support
    // -------------------------------------------------------------------------

    /// @brief Defines the hypercall opcode for mv_debug_op
    constexpr auto MV_DEBUG_OP_VAL{0x764D000000020000_u64};
    /// @brief Defines the hypercall opcode for mv_debug_op (nosig)
    constexpr auto MV_DEBUG_OP_NOSIG_VAL{0x00000000000020000_u64};

    // -------------------------------------------------------------------------
    // Hypercall Opcodes - PP Support
    // -------------------------------------------------------------------------

    /// @brief Defines the hypercall opcode for mv_pp_op
    constexpr auto MV_PP_OP_VAL{0x764D000000030000_u64};
    /// @brief Defines the hypercall opcode for mv_pp_op (nosig)
    constexpr auto MV_PP_OP_NOSIG_VAL{0x0000000000030000_u64};

    // -------------------------------------------------------------------------
    // Hypercall Opcodes - VM Support
    // -------------------------------------------------------------------------

    /// @brief Defines the hypercall opcode for mv_vm_op
    constexpr auto MV_VM_OP_VAL{0x764D000000040000_u64};
    /// @brief Defines the hypercall opcode for mv_vm_op (nosig)
    constexpr auto MV_VM_OP_NOSIG_VAL{0x0000000000040000_u64};

    // -------------------------------------------------------------------------
    // Hypercall Opcodes - VP Support
    // -------------------------------------------------------------------------

    /// @brief Defines the hypercall opcode for mv_vp_op
    constexpr auto MV_VP_OP_VAL{0x764D000000050000_u64};
    /// @brief Defines the hypercall opcode for mv_vp_op (nosig)
    constexpr auto MV_VP_OP_NOSIG_VAL{0x0000000000050000_u64};

    // -------------------------------------------------------------------------
    // Hypercall Opcodes - VPS Support
    // -------------------------------------------------------------------------

    /// @brief Defines the hypercall opcode for mv_vps_op
    constexpr auto MV_VPS_OP_VAL{0x764D000000060000_u64};
    /// @brief Defines the hypercall opcode for mv_vps_op (nosig)
    constexpr auto MV_VPS_OP_NOSIG_VAL{0x0000000000060000_u64};

    // -------------------------------------------------------------------------
    // Hypercall Related Constants
    // -------------------------------------------------------------------------

    /// @brief Defines an invalid handle
    constexpr auto MV_INVALID_HANDLE{0xFFFFFFFFFFFFFFFF_u64};

    // -------------------------------------------------------------------------
    // Hypercall Indexes
    // -------------------------------------------------------------------------

    /// @brief Defines the index for mv_id_op_version
    constexpr auto MV_ID_OP_VERSION_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for mv_id_op_has_capability
    constexpr auto MV_ID_OP_HAS_CAPABILITY_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for mv_id_op_clr_capability
    constexpr auto MV_ID_OP_CLR_CAPABILITY_IDX_VAL{0x0000000000000002_u64};
    /// @brief Defines the index for mv_id_op_set_capability
    constexpr auto MV_ID_OP_SET_CAPABILITY_IDX_VAL{0x0000000000000003_u64};

    /// @brief Defines the index for mv_handle_op_open_handle
    constexpr auto MV_HANDLE_OP_OPEN_HANDLE_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for mv_handle_op_close_handle
    constexpr auto MV_HANDLE_OP_CLOSE_HANDLE_IDX_VAL{0x0000000000000001_u64};

    /// @brief Defines the index for mv_debug_op_out
    constexpr auto MV_DEBUG_OP_OUT_IDX_VAL{0x0000000000000000_u64};

    /// @brief Defines the index for mv_pp_op_get_shared_page_gpa
    constexpr auto MV_PP_OP_GET_SHARED_PAGE_GPA_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for mv_pp_op_set_shared_page_gpa
    constexpr auto MV_PP_OP_SET_SHARED_PAGE_GPA_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for mv_pp_op_cpuid_get_supported
    constexpr auto MV_PP_OP_CPUID_GET_SUPPORTED_IDX_VAL{0x0000000000000002_u64};
    /// @brief Defines the index for mv_pp_op_cpuid_get_permissable
    constexpr auto MV_PP_OP_CPUID_GET_PERMISSABLE_IDX_VAL{0x0000000000000003_u64};
    /// @brief Defines the index for mv_pp_op_cpuid_get_emulated
    constexpr auto MV_PP_OP_CPUID_GET_EMULATED_IDX_VAL{0x0000000000000004_u64};
    /// @brief Defines the index for mv_pp_op_reg_get_supported
    constexpr auto MV_PP_OP_REG_GET_SUPPORTED_IDX_VAL{0x0000000000000005_u64};
    /// @brief Defines the index for mv_pp_op_reg_get_permissable
    constexpr auto MV_PP_OP_REG_GET_PERMISSABLE_IDX_VAL{0x0000000000000006_u64};
    /// @brief Defines the index for mv_pp_op_reg_get_emulated
    constexpr auto MV_PP_OP_REG_GET_EMULATED_IDX_VAL{0x0000000000000007_u64};
    /// @brief Defines the index for mv_pp_op_msr_get_supported
    constexpr auto MV_PP_OP_MSR_GET_SUPPORTED_IDX_VAL{0x000000000000008_u64};
    /// @brief Defines the index for mv_pp_op_msr_get_permissable
    constexpr auto MV_PP_OP_MSR_GET_PERMISSABLE_IDX_VAL{0x0000000000000009_u64};
    /// @brief Defines the index for mv_pp_op_msr_get_emulated
    constexpr auto MV_PP_OP_MSR_GET_EMULATED_IDX_VAL{0x000000000000000A_u64};
    /// @brief Defines the index for mv_pp_op_tsc_get_khz
    constexpr auto MV_PP_OP_TSC_GET_KHZ_IDX_VAL{0x000000000000000B_u64};
    /// @brief Defines the index for mv_pp_op_tsc_set_khz
    constexpr auto MV_PP_OP_TSC_SET_KHZ_IDX_VAL{0x000000000000000C_u64};

    /// @brief Defines the index for mv_vm_op_create_vm
    constexpr auto MV_VM_OP_CREATE_VM_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for mv_vm_op_destroy_vm
    constexpr auto MV_VM_OP_DESTROY_VM_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for mv_vm_op_vmid
    constexpr auto MV_VM_OP_VMID_IDX_VAL{0x0000000000000002_u64};
    /// @brief Defines the index for mv_vm_op_io_clr_trap
    constexpr auto MV_VM_OP_IO_CLR_TRAP_IDX_VAL{0x0000000000000003_u64};
    /// @brief Defines the index for mv_vm_op_io_set_trap
    constexpr auto MV_VM_OP_IO_SET_TRAP_IDX_VAL{0x0000000000000004_u64};
    /// @brief Defines the index for mv_vm_op_io_clr_trap_all
    constexpr auto MV_VM_OP_IO_CLR_TRAP_ALL_IDX_VAL{0x0000000000000005_u64};
    /// @brief Defines the index for mv_vm_op_io_set_trap_all
    constexpr auto MV_VM_OP_IO_SET_TRAP_ALL_IDX_VAL{0x0000000000000006_u64};
    /// @brief Defines the index for mv_vm_op_mmio_map
    constexpr auto MV_VM_OP_MMIO_MAP_IDX_VAL{0x0000000000000007_u64};
    /// @brief Defines the index for mv_vm_op_mmio_unmap
    constexpr auto MV_VM_OP_MMIO_UNMAP_IDX_VAL{0x0000000000000008_u64};
    /// @brief Defines the index for mv_vm_op_mmio_clr_trap
    constexpr auto MV_VM_OP_MMIO_CLR_TRAP_IDX_VAL{0x0000000000000009_u64};
    /// @brief Defines the index for mv_vm_op_mmio_set_trap
    constexpr auto MV_VM_OP_MMIO_SET_TRAP_IDX_VAL{0x000000000000000A_u64};
    /// @brief Defines the index for mv_vm_op_mmio_clr_trap_all
    constexpr auto MV_VM_OP_MMIO_CLR_TRAP_ALL_IDX_VAL{0x000000000000000B_u64};
    /// @brief Defines the index for mv_vm_op_mmio_set_trap_all
    constexpr auto MV_VM_OP_MMIO_SET_TRAP_ALL_IDX_VAL{0x000000000000000C_u64};
    /// @brief Defines the index for mv_vm_op_msr_clr_trap
    constexpr auto MV_VM_OP_MSR_CLR_TRAP_IDX_VAL{0x000000000000000D_u64};
    /// @brief Defines the index for mv_vm_op_msr_set_trap
    constexpr auto MV_VM_OP_MSR_SET_TRAP_IDX_VAL{0x000000000000000E_u64};
    /// @brief Defines the index for mv_vm_op_msr_clr_trap_all
    constexpr auto MV_VM_OP_MSR_CLR_TRAP_ALL_IDX_VAL{0x000000000000000F_u64};
    /// @brief Defines the index for mv_vm_op_msr_set_trap_all
    constexpr auto MV_VM_OP_MSR_SET_TRAP_ALL_IDX_VAL{0x0000000000000010_u64};

    /// @brief Defines the index for mv_vp_op_create_vp
    constexpr auto MV_VP_OP_CREATE_VP_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for mv_vp_op_destroy_vp
    constexpr auto MV_VP_OP_DESTROY_VP_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for mv_vp_op_vmid
    constexpr auto mv_vp_op_vmid_IDX_VAL{0x0000000000000002_u64};
    /// @brief Defines the index for mv_vp_op_vpid
    constexpr auto mv_vp_op_vpid_IDX_VAL{0x0000000000000003_u64};

    /// @brief Defines the index for mv_vps_op_create_vps
    constexpr auto MV_VPS_OP_CREATE_VPS_IDX_VAL{0x0000000000000000_u64};
    /// @brief Defines the index for mv_vps_op_destroy_vps
    constexpr auto MV_VPS_OP_DESTROY_VPS_IDX_VAL{0x0000000000000001_u64};
    /// @brief Defines the index for mv_vps_op_vmid
    constexpr auto MV_VPS_OP_VMID_IDX_VAL{0x0000000000000002_u64};
    /// @brief Defines the index for mv_vps_op_vpid
    constexpr auto MV_VPS_OP_VPID_IDX_VAL{0x0000000000000003_u64};
    /// @brief Defines the index for mv_vps_op_vpsid
    constexpr auto MV_VPS_OP_VPSID_IDX_VAL{0x0000000000000004_u64};
    /// @brief Defines the index for mv_vps_op_gva_to_gla
    constexpr auto MV_VPS_OP_GVA_TO_GLA_IDX_VAL{0x0000000000000005_u64};
    /// @brief Defines the index for mv_vps_op_gla_to_gpa
    constexpr auto MV_VPS_OP_GLA_TO_GPA_IDX_VAL{0x0000000000000006_u64};
    /// @brief Defines the index for mv_vps_op_gva_to_gpa
    constexpr auto MV_VPS_OP_GVA_TO_GPA_IDX_VAL{0x0000000000000007_u64};
    /// @brief Defines the index for mv_vps_op_run
    constexpr auto MV_VPS_OP_RUN_IDX_VAL{0x0000000000000008_u64};
    /// @brief Defines the index for mv_vps_op_cpuid_get
    constexpr auto MV_VPS_OP_CPUID_GET_IDX_VAL{0x0000000000000009_u64};
    /// @brief Defines the index for mv_vps_op_cpuid_set
    constexpr auto MV_VPS_OP_CPUID_SET_IDX_VAL{0x000000000000000A_u64};
    /// @brief Defines the index for mv_vps_op_cpuid_get_all
    constexpr auto MV_VPS_OP_CPUID_GET_ALL_IDX_VAL{0x000000000000000B_u64};
    /// @brief Defines the index for mv_vps_op_cpuid_set_all
    constexpr auto MV_VPS_OP_CPUID_SET_ALL_IDX_VAL{0x000000000000000C_u64};
    /// @brief Defines the index for mv_vps_op_reg_get
    constexpr auto MV_VPS_OP_REG_GET_IDX_VAL{0x000000000000000D_u64};
    /// @brief Defines the index for mv_vps_op_reg_set
    constexpr auto MV_VPS_OP_REG_SET_IDX_VAL{0x000000000000000E_u64};
    /// @brief Defines the index for mv_vps_op_reg_get_all
    constexpr auto MV_VPS_OP_REG_GET_ALL_IDX_VAL{0x000000000000000F_u64};
    /// @brief Defines the index for mv_vps_op_reg_set_all
    constexpr auto MV_VPS_OP_REG_SET_ALL_IDX_VAL{0x0000000000000010_u64};
    /// @brief Defines the index for mv_vps_op_reg_get_general
    constexpr auto MV_VPS_OP_REG_GET_GENERAL_IDX_VAL{0x0000000000000011_u64};
    /// @brief Defines the index for mv_vps_op_reg_set_general
    constexpr auto MV_VPS_OP_REG_SET_GENERAL_IDX_VAL{0x0000000000000012_u64};
    /// @brief Defines the index for mv_vps_op_reg_get_system
    constexpr auto MV_VPS_OP_REG_GET_SYSTEM_IDX_VAL{0x0000000000000013_u64};
    /// @brief Defines the index for mv_vps_op_reg_set_system
    constexpr auto MV_VPS_OP_REG_SET_SYSTEM_IDX_VAL{0x0000000000000014_u64};
    /// @brief Defines the index for mv_vps_op_reg_get_debug
    constexpr auto MV_VPS_OP_REG_GET_DEBUG_IDX_VAL{0x0000000000000015_u64};
    /// @brief Defines the index for mv_vps_op_reg_set_debug
    constexpr auto MV_VPS_OP_REG_SET_DEBUG_IDX_VAL{0x0000000000000016_u64};
    /// @brief Defines the index for mv_vps_op_msr_get
    constexpr auto MV_VPS_OP_MSR_GET_IDX_VAL{0x0000000000000017_u64};
    /// @brief Defines the index for mv_vps_op_msr_set
    constexpr auto MV_VPS_OP_MSR_SET_IDX_VAL{0x0000000000000018_u64};
    /// @brief Defines the index for mv_vps_op_msr_get_all
    constexpr auto MV_VPS_OP_MSR_GET_ALL_IDX_VAL{0x0000000000000019_u64};
    /// @brief Defines the index for mv_vps_op_msr_set_all
    constexpr auto MV_VPS_OP_MSR_SET_ALL_IDX_VAL{0x000000000000001A_u64};
    /// @brief Defines the index for mv_vps_op_fpu_get
    constexpr auto MV_VPS_OP_FPU_GET_IDX_VAL{0x000000000000001B_u64};
    /// @brief Defines the index for mv_vps_op_fpu_set
    constexpr auto MV_VPS_OP_FPU_SET_IDX_VAL{0x000000000000001C_u64};
    /// @brief Defines the index for mv_vps_op_fpu_get_all
    constexpr auto MV_VPS_OP_FPU_GET_ALL_IDX_VAL{0x000000000000001D_u64};
    /// @brief Defines the index for mv_vps_op_fpu_set_all
    constexpr auto MV_VPS_OP_FPU_SET_ALL_IDX_VAL{0x000000000000001E_u64};
    /// @brief Defines the index for mv_vps_op_xsave_get
    constexpr auto MV_VPS_OP_XSAVE_GET_IDX_VAL{0x000000000000001F_u64};
    /// @brief Defines the index for mv_vps_op_xsave_set
    constexpr auto MV_VPS_OP_XSAVE_SET_IDX_VAL{0x0000000000000020_u64};
    /// @brief Defines the index for mv_vps_op_xsave_get_all
    constexpr auto MV_VPS_OP_XSAVE_GET_ALL_IDX_VAL{0x0000000000000021_u64};
    /// @brief Defines the index for mv_vps_op_xsave_set_all
    constexpr auto MV_VPS_OP_XSAVE_SET_ALL_IDX_VAL{0x0000000000000022_u64};
}

#endif
