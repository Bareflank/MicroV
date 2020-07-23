## Table of Contents <!-- omit in toc -->

- [1. Introduction](#1-introduction)
  - [1.1. Reserved Values](#11-reserved-values)
  - [1.2. Document Revision](#12-document-revision)
  - [1.3. Glossary](#13-glossary)
  - [1.4. Scalar Types](#14-scalar-types)
  - [1.5. Memory Address Types](#15-memory-address-types)
  - [1.6. Constants, Structures, Enumerations and Bit Fields](#16-constants-structures-enumerations-and-bit-fields)
    - [1.6.1. Null](#161-null)
    - [1.6.2. Specification IDs](#162-specification-ids)
    - [1.6.3. Handle Type](#163-handle-type)
    - [1.6.4. Register Type](#164-register-type)
    - [1.6.5. GPA Flags](#165-gpa-flags)
    - [1.6.6. Memory Descriptor Lists](#166-memory-descriptor-lists)
  - [1.7. Endianness](#17-endianness)
- [2. Feature and Interface Discovery](#2-feature-and-interface-discovery)
  - [2.1. Hypervisor Discovery](#21-hypervisor-discovery)
    - [2.1.1. CPUID_0000_0001_ECX](#211-cpuid_0000_0001_ecx)
  - [2.2. MicroV CPUID Leaves](#22-microv-cpuid-leaves)
    - [2.2.1. CPUID_4000_0000_EAX](#221-cpuid_4000_0000_eax)
    - [2.2.2. CPUID_4000_XX00_EBX](#222-cpuid_4000_xx00_ebx)
    - [2.2.3. CPUID_4000_XX00_ECX](#223-cpuid_4000_xx00_ecx)
    - [2.2.4. CPUID_4000_XX00_EDX](#224-cpuid_4000_xx00_edx)
    - [2.2.5. CPUID_4000_XX01_EAX](#225-cpuid_4000_xx01_eax)
    - [2.2.6. CPUID_4000_XX01_EBX](#226-cpuid_4000_xx01_ebx)
    - [2.2.7. CPUID_4000_XX01_ECX](#227-cpuid_4000_xx01_ecx)
    - [2.2.8. CPUID_4000_XX01_EDX](#228-cpuid_4000_xx01_edx)
    - [2.2.9. CPUID_4000_XX02_EAX](#229-cpuid_4000_xx02_eax)
    - [2.2.10. CPUID_4000_XX02_EBX](#2210-cpuid_4000_xx02_ebx)
    - [2.2.11. CPUID_4000_XX02_ECX](#2211-cpuid_4000_xx02_ecx)
    - [2.2.12. CPUID_4000_XX02_EDX](#2212-cpuid_4000_xx02_edx)
- [3. Hypercall Interface](#3-hypercall-interface)
  - [3.1. Hypercall Continuation](#31-hypercall-continuation)
  - [3.2. Legal Hypercall Environments](#32-legal-hypercall-environments)
  - [3.3. Alignment Requirements](#33-alignment-requirements)
  - [3.4. Hypercall Status Codes](#34-hypercall-status-codes)
    - [3.4.1. MV_STATUS_SUCCESS, VALUE=0](#341-mv_status_success-value0)
    - [3.4.2. MV_STATUS_FAILURE, VALUE=1](#342-mv_status_failure-value1)
    - [3.4.3. MV_STATUS_INVALID_PERM, VALUE=2](#343-mv_status_invalid_perm-value2)
    - [3.4.4. MV_STATUS_INVALID_PARAMS, VALUE=3](#344-mv_status_invalid_params-value3)
    - [3.4.5. MV_STATUS_INVALID_GPA, VALUE=0x4](#345-mv_status_invalid_gpa-value0x4)
    - [3.4.6. MV_STATUS_INVALID_SIZE, VALUE=0x5](#346-mv_status_invalid_size-value0x5)
    - [3.4.7. MV_STATUS_RETRY, VALUE=0x6](#347-mv_status_retry-value0x6)
    - [3.4.8. MV_STATUS_INVALID_VMID, VALUE=0x7](#348-mv_status_invalid_vmid-value0x7)
    - [3.4.9. MV_STATUS_INVALID_UUID, VALUE=0x8](#349-mv_status_invalid_uuid-value0x8)
    - [3.4.10. MV_STATUS_INVALID_VPID, VALUE=0x9](#3410-mv_status_invalid_vpid-value0x9)
  - [3.5. Hypercall Inputs](#35-hypercall-inputs)
  - [3.6. Hypercall Outputs](#36-hypercall-outputs)
  - [3.7. Hypercall Opcodes](#37-hypercall-opcodes)
    - [3.7.1. Debug Support](#371-debug-support)
    - [3.7.2. Handle Support](#372-handle-support)
    - [3.7.3. Virtual Machines](#373-virtual-machines)
    - [3.7.4. Virtual Processors](#374-virtual-processors)
  - [3.8. Debug Hypercalls](#38-debug-hypercalls)
    - [3.8.1. mv_debug_op_out, OP=0x0, IDX=0x0](#381-mv_debug_op_out-op0x0-idx0x0)
    - [3.8.2. mv_debug_op_dump_vms, OP=0x0, IDX=0x1](#382-mv_debug_op_dump_vms-op0x0-idx0x1)
    - [3.8.3. mv_debug_op_dump_vps, OP=0x0, IDX=0x2](#383-mv_debug_op_dump_vps-op0x0-idx0x2)
    - [3.8.4. mv_debug_op_dump_vmexit_log, OP=0x0, IDX=0x3](#384-mv_debug_op_dump_vmexit_log-op0x0-idx0x3)
    - [3.8.5. mv_debug_op_dump_memory_map, OP=0x0, IDX=0x4](#385-mv_debug_op_dump_memory_map-op0x0-idx0x4)
  - [3.9. Handle Hypercalls](#39-handle-hypercalls)
    - [3.9.1. mv_handle_op_open_handle, OP=0x1, IDX=0x0](#391-mv_handle_op_open_handle-op0x1-idx0x0)
    - [3.9.2. mv_handle_op_close_handle, OP=0x1, IDX=0x1](#392-mv_handle_op_close_handle-op0x1-idx0x1)
- [4. Virtual Machines](#4-virtual-machines)
  - [4.1. Virtual Machine Types](#41-virtual-machine-types)
  - [4.2. VMID](#42-vmid)
  - [4.3. UUID](#43-uuid)
  - [4.4. Virtual Machine Properties](#44-virtual-machine-properties)
    - [4.4.1. mv_vm_properties_op_uuid, OP=0x2, IDX=0x0](#441-mv_vm_properties_op_uuid-op0x2-idx0x0)
    - [4.4.2. mv_vm_properties_op_vmid, OP=0x2, IDX=0x1](#442-mv_vm_properties_op_vmid-op0x2-idx0x1)
    - [4.4.3. mv_vm_properties_is_root_vm, OP=0x2, IDX=0x2](#443-mv_vm_properties_is_root_vm-op0x2-idx0x2)
    - [4.4.4. mv_vm_properties_is_guest_vm, OP=0x2, IDX=0x3](#444-mv_vm_properties_is_guest_vm-op0x2-idx0x3)
    - [4.4.5. mv_vm_properties_state, OP=0x2, IDX=0x4](#445-mv_vm_properties_state-op0x2-idx0x4)
    - [4.4.6. mv_vm_properties_op_e820, OP=0x2, IDX=0x5](#446-mv_vm_properties_op_e820-op0x2-idx0x5)
    - [4.4.7. mv_vm_properties_op_set_e820, OP=0x2, IDX=0x6](#447-mv_vm_properties_op_set_e820-op0x2-idx0x6)
    - [4.4.8. mv_vm_properties_op_set_pt_uart, OP=0x2, IDX=0x7](#448-mv_vm_properties_op_set_pt_uart-op0x2-idx0x7)
  - [4.5. Virtual Machine State](#45-virtual-machine-state)
    - [4.5.1. mv_vm_state_op_initial_reg_val, OP=0x3, IDX=0x0](#451-mv_vm_state_op_initial_reg_val-op0x3-idx0x0)
    - [4.5.2. mv_vm_state_op_set_initial_reg_val, OP=0x3, IDX=0x1](#452-mv_vm_state_op_set_initial_reg_val-op0x3-idx0x1)
    - [4.5.3. mv_vm_state_op_list_of_initial_reg_vals, OP=0x3, IDX=0x2](#453-mv_vm_state_op_list_of_initial_reg_vals-op0x3-idx0x2)
    - [4.5.4. mv_vm_state_op_set_list_of_initial_reg_vals, OP=0x3, IDX=0x3](#454-mv_vm_state_op_set_list_of_initial_reg_vals-op0x3-idx0x3)
    - [4.5.5. mv_vm_state_op_initial_msr_val, OP=0x3, IDX=0x4](#455-mv_vm_state_op_initial_msr_val-op0x3-idx0x4)
    - [4.5.6. mv_vm_state_op_set_initial_msr_val, OP=0x3, IDX=0x5](#456-mv_vm_state_op_set_initial_msr_val-op0x3-idx0x5)
    - [4.5.7. mv_vm_state_op_list_of_initial_msr_vals, OP=0x3, IDX=0x6](#457-mv_vm_state_op_list_of_initial_msr_vals-op0x3-idx0x6)
    - [4.5.8. mv_vm_state_op_set_list_of_initial_msr_vals, OP=0x3, IDX=0x7](#458-mv_vm_state_op_set_list_of_initial_msr_vals-op0x3-idx0x7)
    - [4.5.9. mv_vm_state_op_gva_to_gpa, OP=0x3, IDX=0x8](#459-mv_vm_state_op_gva_to_gpa-op0x3-idx0x8)
    - [4.5.10. mv_vm_state_op_map_range, OP=0x3, IDX=0x9](#4510-mv_vm_state_op_map_range-op0x3-idx0x9)
    - [4.5.11. mv_vm_state_op_unmap_range, OP=0x3, IDX=0xA](#4511-mv_vm_state_op_unmap_range-op0x3-idx0xa)
    - [4.5.12. mv_vm_state_op_copy_range, OP=0x3, IDX=0xB](#4512-mv_vm_state_op_copy_range-op0x3-idx0xb)
    - [4.5.13. mv_vm_state_op_map_mdl, OP=0x3, IDX=0xC](#4513-mv_vm_state_op_map_mdl-op0x3-idx0xc)
    - [4.5.14. mv_vm_state_op_unmap_mdl, OP=0x3, IDX=0xD](#4514-mv_vm_state_op_unmap_mdl-op0x3-idx0xd)
    - [4.5.15. mv_vm_state_op_copy_mdl, OP=0x3, IDX=0xE](#4515-mv_vm_state_op_copy_mdl-op0x3-idx0xe)
    - [4.5.16. mv_vm_state_op_gpa_flags, OP=0x3, IDX=0xF](#4516-mv_vm_state_op_gpa_flags-op0x3-idx0xf)
    - [4.5.17. mv_vm_state_op_set_gpa_flags, OP=0x3, IDX=0x10](#4517-mv_vm_state_op_set_gpa_flags-op0x3-idx0x10)
  - [4.6. Virtual Machine Management](#46-virtual-machine-management)
    - [4.6.1. mv_vm_management_op_create_vm, OP=0x4, IDX=0x0](#461-mv_vm_management_op_create_vm-op0x4-idx0x0)
    - [4.6.2. mv_vm_management_op_destroy_vm, OP=0x4, IDX=0x1](#462-mv_vm_management_op_destroy_vm-op0x4-idx0x1)
    - [4.6.3. mv_vm_management_op_pause_vm, OP=0x4, IDX=0x2](#463-mv_vm_management_op_pause_vm-op0x4-idx0x2)
    - [4.6.4. mv_vm_management_op_resume_vm, OP=0x4, IDX=0x3](#464-mv_vm_management_op_resume_vm-op0x4-idx0x3)
  - [4.7. Virtual Machine Key/Value Store](#47-virtual-machine-keyvalue-store)
    - [4.7.1. mv_vm_kv_op_open, OP=0x5, IDX=0x0](#471-mv_vm_kv_op_open-op0x5-idx0x0)
    - [4.7.2. mv_vm_kv_op_close, OP=0x5, IDX=0x1](#472-mv_vm_kv_op_close-op0x5-idx0x1)
    - [4.7.3. mv_vm_kv_op_read_val, OP=0x5, IDX=0x2](#473-mv_vm_kv_op_read_val-op0x5-idx0x2)
    - [4.7.4. mv_vm_kv_op_write_val, OP=05, IDX=0x3](#474-mv_vm_kv_op_write_val-op05-idx0x3)
    - [4.7.5. mv_vm_kv_op_read_range, OP=0x5, IDX=0x4](#475-mv_vm_kv_op_read_range-op0x5-idx0x4)
    - [4.7.6. mv_vm_kv_op_write_range, OP=05, IDX=0x5](#476-mv_vm_kv_op_write_range-op05-idx0x5)
    - [4.7.7. mv_vm_kv_op_read_mdl, OP=0x5, IDX=0x6](#477-mv_vm_kv_op_read_mdl-op0x5-idx0x6)
    - [4.7.8. mv_vm_kv_op_write_mdl, OP=05, IDX=0x7](#478-mv_vm_kv_op_write_mdl-op05-idx0x7)
    - [4.7.9. mv_vm_kv_op_global_store, OP=0x5, IDX=0x8](#479-mv_vm_kv_op_global_store-op0x5-idx0x8)
    - [4.7.10. mv_vm_kv_op_set_global_store, OP=05, IDX=0x9](#4710-mv_vm_kv_op_set_global_store-op05-idx0x9)
- [5. Virtual Processor](#5-virtual-processor)
  - [5.1. Virtual Processor Types](#51-virtual-processor-types)
  - [5.2. VPID](#52-vpid)
  - [5.3. Virtual Processor Properties](#53-virtual-processor-properties)
    - [5.3.1. mv_vp_op_vpid, OP=0x6, IDX=0x0](#531-mv_vp_op_vpid-op0x6-idx0x0)
    - [5.3.2. mv_vp_op_vmid, OP=0x6, IDX=0x2](#532-mv_vp_op_vmid-op0x6-idx0x2)
    - [5.3.3. mv_vp_op_uuid, OP=0x6, IDX=0x3](#533-mv_vp_op_uuid-op0x6-idx0x3)
    - [5.3.4. mv_vp_op_is_root_vp, OP=0x6, IDX=0x4](#534-mv_vp_op_is_root_vp-op0x6-idx0x4)
    - [5.3.5. mv_vp_op_is_guest_vp, OP=0x6, IDX=0x5](#535-mv_vp_op_is_guest_vp-op0x6-idx0x5)
    - [5.3.6. mv_vp_op_state, OP=0x6, IDX=0x6](#536-mv_vp_op_state-op0x6-idx0x6)
  - [5.4. Virtual Processor State](#54-virtual-processor-state)
    - [5.4.1. mv_vp_state_op_reg_val, OP=0x7, IDX=0x0](#541-mv_vp_state_op_reg_val-op0x7-idx0x0)
    - [5.4.2. mv_vp_state_op_set_reg_val, OP=0x7, IDX=0x1](#542-mv_vp_state_op_set_reg_val-op0x7-idx0x1)
    - [5.4.3. mv_vp_state_op_list_of_reg_vals, OP=0x7, IDX=0x2](#543-mv_vp_state_op_list_of_reg_vals-op0x7-idx0x2)
    - [5.4.4. mv_vp_state_op_set_list_of_reg_vals, OP=0x7, IDX=0x3](#544-mv_vp_state_op_set_list_of_reg_vals-op0x7-idx0x3)
    - [5.4.5. mv_vp_state_op_msr_val, OP=0x7, IDX=0x4](#545-mv_vp_state_op_msr_val-op0x7-idx0x4)
    - [5.4.6. mv_vp_state_op_set_msr_val, OP=0x7, IDX=0x5](#546-mv_vp_state_op_set_msr_val-op0x7-idx0x5)
    - [5.4.7. mv_vp_state_op_list_of_msr_vals, OP=0x7, IDX=0x6](#547-mv_vp_state_op_list_of_msr_vals-op0x7-idx0x6)
    - [5.4.8. mv_vp_state_op_set_list_of_msr_vals, OP=0x7, IDX=0x7](#548-mv_vp_state_op_set_list_of_msr_vals-op0x7-idx0x7)
    - [5.4.9. mv_vp_state_op_hve_val, OP=0x7, IDX=0x8](#549-mv_vp_state_op_hve_val-op0x7-idx0x8)
    - [5.4.10. mv_vp_state_op_set_hve_val, OP=0x7, IDX=0x9](#5410-mv_vp_state_op_set_hve_val-op0x7-idx0x9)
    - [5.4.11. mv_vp_state_op_list_of_hve_vals, OP=0x7, IDX=0xA](#5411-mv_vp_state_op_list_of_hve_vals-op0x7-idx0xa)
    - [5.4.12. mv_vp_state_op_set_list_of_hve_vals, OP=0x7, IDX=0xB](#5412-mv_vp_state_op_set_list_of_hve_vals-op0x7-idx0xb)
    - [5.4.13. mv_vp_state_op_xsave_val, OP=0x7, IDX=0xC](#5413-mv_vp_state_op_xsave_val-op0x7-idx0xc)
    - [5.4.14. mv_vp_state_op_set_xsave_val, OP=0x7, IDX=0xD](#5414-mv_vp_state_op_set_xsave_val-op0x7-idx0xd)
  - [5.5. Virtual Processor Management](#55-virtual-processor-management)
    - [5.5.1. mv_vp_management_op_create_vp, OP=0x8, IDX=0x0](#551-mv_vp_management_op_create_vp-op0x8-idx0x0)
    - [5.5.2. mv_vp_management_op_destroy_vp, OP=0x8, IDX=0x1](#552-mv_vp_management_op_destroy_vp-op0x8-idx0x1)
    - [5.5.3. mv_vp_management_op_run_vp, OP=0x8, IDX=0x2](#553-mv_vp_management_op_run_vp-op0x8-idx0x2)
    - [5.5.4. mv_vp_management_op_kill_vp, OP=0x8, IDX=0x3](#554-mv_vp_management_op_kill_vp-op0x8-idx0x3)
    - [5.5.5. mv_vp_management_op_pause_vp, OP=0x4, IDX=0x4](#555-mv_vp_management_op_pause_vp-op0x4-idx0x4)
    - [5.5.6. mv_vp_management_op_resume_vp, OP=0x4, IDX=0x5](#556-mv_vp_management_op_resume_vp-op0x4-idx0x5)
  - [5.6. Virtual Processor Exits](#56-virtual-processor-exits)

# 1. Introduction

This specification defines the ABI between VM software and the MicroV hypervisor (including both root VMs and guest VMs). This includes the use of CPUID and Hypercalls. This specification does not define the ABI between the Bareflank Microkernel and Bareflank Extensions. Please see the Bareflank Microkernel Specification for more information on the ABI supported by the Bareflank Microkernel for writing customer hypervisor extensions. This specification also does not define the ABI for any support drivers like the Bareflank Loader or the MicroV Support drivers. Please see the Bareflank Loader Specification or the MicroV Support Specification for more information. Finally, this ABI does not define the HyperV or Xen ABIs. Please see the [Hypervisor Top Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs) as well as the Xen PVH/HVM Specification for more information. It should be noted that MicroV depends on the Xen PVH/HVM Specification to provide a fully functional hypervisor, and as such, some of the APIs/ABIs in this document depend on facilities provided by the Xen PVH/HVM Specification. The goal of this specification is to define the portion of the ABI that the Xen PVH/HVM Specification does not provide. 

This specification is specific to 64bit Intel and AMD processors conforming to the amd64 specification. Future revisions of this specification may include ARM64 conforming to the aarch64 specification as well.

## 1.1. Reserved Values

| Name | Description |
| :--- | :---------- |
| REVZ | reserved zero, meaning the value must be set to 0 |
| REVI | reserved ignore, meaning the value is ignored |

## 1.2. Document Revision

| Version | Description |
| :------ | :---------- |
| Mv#1 | The initial version of this specification |

## 1.3. Glossary

| Abbreviation | Description |
| :----------- | :---------- |
| VM | Virtual Machine |
| VP | Virtual Processor |
| VMS | Virtual Machine State |
| VPS | Virtual Processor State |
| VMID | Virtual Machine Identifier |
| VPID | Virtual Processor Identifier |
| UUID | Universally Unique Identifier |
| OS | Operating System |
| BIOS | Basic Input/Output System |
| UEFI | Unified Extensible Firmware Interface |
| Host | Refers to the hypervisor (i.e., the code responsible for executing different virtual machines on the same physical hardware). For MicroV, this is the Bareflank Microkernel and its associated extensions. Sometimes referred to as VMX root |
| Guest | Any software executing in a Virtual Machine |
| SPA | System Physical Address. An SPA refers to a physical address as seen by the system without the addition of virtualization |
| GPA | Guest Physical Address. A GPA refers to a physical address as seen by a VM and requires a translation to convert to an SPA |
| GVA | Guest Virtual Address. A GVA refers to a virtual address as seen by a VM and requires a guest controlled translation to convert to a GPA |
| Page Aligned | A region of memory whose address is divisible by 0x1000 |
| Page | A page aligned region of memory that is 0x1000 bytes in size |
| Root VM | The first VM created when MicroV is launched. The OS/BIOS/UEFI that is running when MicroV is launch is placed in the Root VM |
| Guest VM | Any additional VM created by the Root VM |
| Root VP | When first started, MicroV creates one and only one Root VP for every physical core/thread on the system. The Root VPs are owned by the Root VM |
| Guest VP | Any additional VP created by a Root VP. Guest VPs are owned by Guest VMs |
| Parent VP | From a Guest VP point of view, the Parent VP is the Root VP that is currently executing it. A Guest VP's Parent VP can change |
| Child VP | From a Root VP point of view, the Child VP is the Guest VP that the Root VP is currently executing. A Root VP's Child VP can change |
| Donate | Refers to giving a resources from one VM to another. Once donated, the VM donating no longer has access to the resource |
| Share | Refers to sharing a resources from one VM to another. Once shared, both VMs have access to the resource |
| Foreign | A action taking place between two different child VMs |
| VP Migration | The act of transferring ownership of a guest VP from one root VP to another |

## 1.4. Scalar Types

| Name | Type |
| :--- | :--- |
| mv_status_t | uint64_t |
| mv_uint8_t | uint8_t |
| mv_uint16_t | uint16_t |
| mv_uint32_t | uint32_t |
| mv_uint64_t | uint64_t |

## 1.5. Memory Address Types

| Name | Type |
| :--- | :--- |
| System Physical Address (SPA) | mv_uint64_t |
| Guest Physical Address (GPA) | mv_uint64_t |
| Guest Virtual Address (GVA) | mv_uint64_t |

## 1.6. Constants, Structures, Enumerations and Bit Fields

### 1.6.1. Null

**const, void *: MV_NULL**
| Value | Description |
| :---- | :---------- |
| 0 | Defines the value of a null pointer |

### 1.6.2. Specification IDs

The following defines the specification IDs used when opening a handle. These provide software with a means to define which specification it talks.

**const, mv_uint32_t: MV_SPEC_ID1_VAL**
| Value | Description |
| :---- | :---------- |
| 0x3123764D | Defines the ID for version #1 of this spec |

### 1.6.3. Handle Type

The mv_handle_t structure is an opaque structure containing the handle that is used by most of the hypercalls in this specification. The opaque structure is used internally by the C wrapper interface for storing state as needed and should not be accessed directly. The C wrapper is allowed to redefine the internal layout of this structure at any time (e.g., the C wrapper might provide an alternative layout for unit testing).

**struct: mv_handle_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| hndl | mv_uint64_t | 0x0 | 8 bytes | The handle returned by mv_handle_op_open_handle |

### 1.6.4. Register Type

Some of the hypercalls in this specification need the ability to call out a specific register. This enumeration type is used to define which register is being requested by the hypercall.

**enum, mv_uint64_t: mv_reg_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| mv_reg_t_rax | 0 | defines the rax register |
| mv_reg_t_rbx | 1 | defines the rbx register |
| mv_reg_t_rcx | 2 | defines the rcx register |
| mv_reg_t_rdx | 3 | defines the rdx register |
| mv_reg_t_rdi | 4 | defines the rdi register |
| mv_reg_t_rsi | 5 | defines the rsi register |
| mv_reg_t_r8 | 6 | defines the r8 register |
| mv_reg_t_r9 | 7 | defines the r9 register |
| mv_reg_t_r10 | 8 | defines the r10 register |
| mv_reg_t_r11 | 9 | defines the r11 register |
| mv_reg_t_r12 | 10 | defines the r12 register |
| mv_reg_t_r13 | 11 | defines the r13 register |
| mv_reg_t_r14 | 12 | defines the r14 register |
| mv_reg_t_r15 | 13 | defines the r15 register |
| mv_reg_t_rbp | 14 | defines the rbp register |
| mv_reg_t_rsp | 15 | defines the rsp register |
| mv_reg_t_rip | 16 | defines the rip register |
| mv_reg_t_cr0 | 17 | defines the cr0 register |
| mv_reg_t_cr2 | 18 | defines the cr2 register |
| mv_reg_t_cr3 | 19 | defines the cr3 register |
| mv_reg_t_cr4 | 20 | defines the cr4 register |
| mv_reg_t_cr8 | 21 | defines the cr8 register |
| mv_reg_t_dr0 | 22 | defines the dr0 register |
| mv_reg_t_dr1 | 23 | defines the dr1 register |
| mv_reg_t_dr2 | 24 | defines the dr2 register |
| mv_reg_t_dr3 | 25 | defines the dr3 register |
| mv_reg_t_dr4 | 26 | defines the dr4 register |
| mv_reg_t_dr5 | 27 | defines the dr5 register |
| mv_reg_t_dr6 | 28 | defines the dr6 register |
| mv_reg_t_dr7 | 29 | defines the dr7 register |
| mv_reg_t_rflags | 30 | defines the rflags register |
| mv_reg_t_es | 31 | defines the es register |
| mv_reg_t_es_base_addr | 32 | defines the es_base_addr register |
| mv_reg_t_es_limit | 33 | defines the es_limit register |
| mv_reg_t_es_attributes | 34 | defines the es_attributes register |
| mv_reg_t_cs | 35 | defines the cs register |
| mv_reg_t_cs_base_addr | 36 | defines the cs_base_addr register |
| mv_reg_t_cs_limit | 37 | defines the cs_limit register |
| mv_reg_t_cs_attributes | 38 | defines the cs_attributes register |
| mv_reg_t_ss | 39 | defines the ss register |
| mv_reg_t_ss_base_addr | 40 | defines the ss_base_addr register |
| mv_reg_t_ss_limit | 41 | defines the ss_limit register |
| mv_reg_t_ss_attributes | 42 | defines the ss_attributes register |
| mv_reg_t_ds | 43 | defines the ds register |
| mv_reg_t_ds_base_addr | 44 | defines the ds_base_addr register |
| mv_reg_t_ds_limit | 45 | defines the ds_limit register |
| mv_reg_t_ds_attributes | 46 | defines the ds_attributes register |
| mv_reg_t_fs | 47 | defines the fs register |
| mv_reg_t_fs_base_addr | 48 | defines the fs_base_addr register |
| mv_reg_t_fs_limit | 49 | defines the fs_limit register |
| mv_reg_t_fs_attributes | 50 | defines the fs_attributes register |
| mv_reg_t_gs | 51 | defines the gs register |
| mv_reg_t_gs_base_addr | 52 | defines the gs_base_addr register |
| mv_reg_t_gs_limit | 53 | defines the gs_limit register |
| mv_reg_t_gs_attributes | 54 | defines the gs_attributes register |
| mv_reg_t_ldtr | 55 | defines the ldtr register |
| mv_reg_t_ldtr_base_addr | 56 | defines the ldtr_base_addr register |
| mv_reg_t_ldtr_limit | 57 | defines the ldtr_limit register |
| mv_reg_t_ldtr_attributes | 58 | defines the ldtr_attributes register |
| mv_reg_t_tr | 59 | defines the tr register |
| mv_reg_t_tr_base_addr | 60 | defines the tr_base_addr register |
| mv_reg_t_tr_limit | 61 | defines the tr_limit register |
| mv_reg_t_tr_attributes | 62 | defines the tr_attributes register |
| mv_reg_t_gdtr | 63 | defines the gdtr register |
| mv_reg_t_gdtr_base_addr | 64 | defines the gdtr_base_addr register |
| mv_reg_t_gdtr_limit | 65 | defines the gdtr_limit register |
| mv_reg_t_gdtr_attributes | 66 | defines the gdtr_attributes register |
| mv_reg_t_idtr | 67 | defines the idtr register |
| mv_reg_t_idtr_base_addr | 68 | defines the idtr_base_addr register |
| mv_reg_t_idtr_limit | 69 | defines the idtr_limit register |
| mv_reg_t_idtr_attributes | 70 | defines the idtr_attributes register |
| mv_reg_t_max | 71 | defines the max register value |

### 1.6.5. GPA Flags

The GPA flags are used by some of the hypercalls as both inputs to a hypercall as well as outputs from a hypercall to provide information about how a GPA should be or is mapped. These flags can also be used to define UEFI Memory Map and E820 Memory Map types.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 0 | MV_GPA_FLAG_RESERVED_MEM | Indicates the GPA points to memory reserved by BIOS/UEFI |
| 6:1 | revz | REVZ |
| 7 | MV_GPA_FLAG_CONVENTIONAL_MEM | Indicates the GPA points to memory available for general use (i.e., usable RAM) |
| 8 | MV_GPA_FLAG_UNUSABLE_MEM | Indicates the GPA points to unusable memory |
| 9 | MV_GPA_FLAG_ACPI_RECLAIM_MEM | Indicates the GPA points to ACPI reclaimable memory |
| 10 | MV_GPA_FLAG_ACPI_NVS_MEM | Indicates the GPA points to ACPI NVS memory |
| 31:11 | revz | REVZ |
| 32 | MV_GPA_FLAG_READ_ACCESS | Indicates the GPA has read access |
| 33 | MV_GPA_FLAG_WRITE_ACCESS | Indicates the GPA has write access |
| 34 | MV_GPA_FLAG_EXECUTE_ACCESS | Indicates the GPA has execute access |
| 35 | MV_GPA_FLAG_UNCACHEABLE | Indicates the GPA is mapped as UC |
| 36 | MV_GPA_FLAG_UNCACHEABLE_MINUS | Indicates the GPA is mapped as UC- |
| 37 | MV_GPA_FLAG_WRITE_COMBINING | Indicates the GPA is mapped as WC |
| 38 | MV_GPA_FLAG_WRITE_COMBINING_PLUS | Indicates the GPA is mapped as WC+ |
| 39 | MV_GPA_FLAG_WRITE_THROUGH | Indicates the GPA is mapped as WT |
| 40 | MV_GPA_FLAG_WRITE_BACK | Indicates the GPA is mapped as WB |
| 41 | MV_GPA_FLAG_WRITE_PROTECTED | Indicates the GPA is mapped as WP |
| 42 | MV_GPA_FLAG_PAGE_SIZE_4k | Indicates the GPA is a 4k page |
| 43 | MV_GPA_FLAG_PAGE_SIZE_2M | Indicates the GPA is a 2M page |
| 44 | MV_GPA_FLAG_PAGE_SIZE_1G | Indicates the GPA is a 1G page |
| 45 | MV_GPA_FLAG_DONATE | Indicates the GPA should be donated instead of shared |
| 46 | MV_GPA_FLAG_ZOMBIE | Indicates that if a source VM crashes, it becomes a zombie instead of killing the destination VM |
| 63:47 | revz | REVZ |

### 1.6.6. Memory Descriptor Lists

A memory descriptor list describes a discontiguous region of guest physical memory. Memory descriptor lists are used to describe for example an e820 map, or a region of memory that should be mapped, unmapped or copied by the hypercalls described in this specification.

An MDL consists of a 4k page of memory, capable of storing MV_MDL_MAP_MAX_NUM_ENTRIES, with each entry describing one contiguous region of guest physical memory. By combining multiple entries into a list, software is capable of describing a discontiguous region of guest physical memory.

**const, mv_uint64_t: MV_MDL_MAP_MAX_NUM_ENTRIES**
| Value | Description |
| :---- | :---------- |
| 169 | Defines the max number of entries in an MDL |

Each entry in the MDL defines a contiguous region of the guest's physical memory, and each entry in the MDL is defined as follows:

**struct: mv_mdl_entry_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| gpa | mv_uint64_t | 0x0 | 8 bytes | The starting gpa of the memory range |
| size | mv_uint64_t | 0x8 | 8 bytes | The number of bytes in the memory range |
| flags | mv_uint64_t | 0x10 | 8 bytes | Flags used to describe the memory range as well as operations to perform on the memory range depending on the hypercall |

The format of the MDL in the 4k page is as follows:

**struct: mv_mdl_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| num_entries | mv_uint64_t | 0x0 | 8 bytes | The number of entries in the MDL |
| next | mv_uint64_t | 0x8 | 8 bytes | The GPA of the next mv_mdl_t in the list |
| revz | mv_uint64_t | 0x18 | 24 bytes | REVZ |
| entries | mv_mdl_entry_t[MV_MDL_MAP_MAX_NUM_ENTRIES] | 0x28 | 4056 bytes | Each entry in the MDL |

## 1.7. Endianness

This document only applies to 64bit Intel and AMD systems conforming to the amd64 architecture. As such, this document is limited to little endian.

# 2. Feature and Interface Discovery

## 2.1. Hypervisor Discovery

Hypervisor discovery is defined by the [Hypervisor Top Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs). Reading CPUID_0000_0001_ECX bit 31 will indicate if software is executing in a virtualized environment. If bit 31 is set, software can safely read CPUID_4000_0000 to the value returned by CPUID_4000_0000_EAX if the hypervisor conforms to the [Hypervisor Top Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs).

The CPUID leaves in this section describe how to determine if the hypervisor is MicroV as well as which version of MicroV software is running on. The following code demonstrates how to use these CPUID leaves:

```c
#define MV_CPUID_HYPERVISOR_PRESENT (((mv_uint32_t)1) << 31)
#define MV_CPUID_SPEC_ID1 (((mv_uint32_t)1) << 0)

#define MV_CPUID_MIN_LEAF_VAL ((mv_uint32_t)0x40000202)
#define MV_CPUID_MAX_LEAF_VAL ((mv_uint32_t)0x4000FFFF)
#define MV_CPUID_INIT_VAL ((mv_uint32_t)0x40000200)
#define MV_CPUID_INC_VAL ((mv_uint32_t)0x100)
#define MV_CPUID_VENDOR_ID1_VAL ((mv_uint32_t)0x694D6642)
#define MV_CPUID_VENDOR_ID2_VAL ((mv_uint32_t)0x566F7263)

static inline mv_uint32_t
mv_present(mv_uint32_t spec_id)
{
    mv_uint32_t eax;
    mv_uint32_t ebx;
    mv_uint32_t ecx;
    mv_uint32_t edx;
    mv_uint32_t max_leaf;
    mv_uint32_t leaf;

    /**
     * First check to see if software is running on a hypervisor. Although not
     * officially documented by Intel/AMD, bit 31 of the feature identifiers is
     * reserved for hypervisors, and any hypervisor that conforms (at least in
     * part) to the Hypervisor Top Level Functional Specification will set this.
     */

    eax = 0x00000001;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    if ((ecx & MV_CPUID_HYPERVISOR_PRESENT) == 0) {
        return 0;
    }

    /**
     * Now that we know that we are running on a hypervisor, the next step is
     * determine how many hypervisor specific CPUID leaves are supported. This
     * is done as follows. Note that the MicroV spec defines the min/max values
     * for the return of this query, which we can also use to determine if this
     * is MicroV.
     */

    eax = 0x40000000;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    max_leaf = eax;
    if (max_leaf < MV_CPUID_MIN_LEAF_VAL || max_leaf > MV_CPUID_MAX_LEAF_VAL) {
        return 0;
    }

    /**
     * Now that we know how many CPUID leaves to parse, we can scan the CPUID
     * leaves for MicroV. Since MicroV also supports the HyperV and Xen
     * interfaces, we start at 0x40000200, and increment by 0x100 until we
     * find MicroV's signature. Normally, the first leaf should be MicroV, but
     * we need to scan just incase future MicroV specs add additional ABIs.
     */

    for (leaf = MV_CPUID_INIT_VAL; leaf < max_leaf; leaf += MV_CPUID_INC_VAL) {
        eax = leaf;
        _mv_cpuid(&eax, &ebx, &ecx, &edx);

        if (ebx == MV_CPUID_VENDOR_ID1_VAL && ecx == MV_CPUID_VENDOR_ID2_VAL) {
            break;
        }
    }

    if (leaf >= max_leaf) {
        return 0;
    }

    /**
     * Finally, we need to verify which version of the spec software speaks and
     * verifying that MicroV also speaks this same spec.
     */

    eax = leaf + 0x00000001U;
    _mv_cpuid(&eax, &ebx, &ecx, &edx);

    switch (spec_id) {
        case MV_SPEC_ID1_VAL: {
            if ((eax & MV_CPUID_SPEC_ID1) == 0) {
                return 0;
            }

            break;
        }

        default:
            return 0;
    }

    /**
     * If we got this far, it means that software is running on MicroV, and
     * both MicroV and software speak the same specification, which means
     * software may proceed with communicating with MicroV. The next step is
     * to open an handle and use it for additional hypercalls.
     */

    return 1;
}
```

### 2.1.1. CPUID_0000_0001_ECX

This CPUID query returns miscellaneous feature identifiers. If mv_hypervisor_present returns a non-zero value, a hypervisor is running. To identify what hypervisor is running, use CPUID_4000_0000 through CPUID_4000_FFFF as defined below.

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 30:0 | ... | Please see the Intel/AMD manuals |
| 31 | MV_CPUID_HYPERVISOR_PRESENT | Enabled if software is in a virtual machine |

## 2.2. MicroV CPUID Leaves

The following sections define the CPUID leaves MicroV provides.

### 2.2.1. CPUID_4000_0000_EAX

This CPUID query returns the total number of CPUID leaves supported by MicroV. The [Hypervisor Top Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs) states that this value be no larger than 0x400000FF. If the hypervisor executing is MicroV, this value is extended to 0x4000FFFF. If the value returned by this query is not in the range of 0x40000001 to 0x4000FFFF, the hypervisor does not conform to this specification, and therefore is not MicroV. MicroV is capable of supporting the MicroV, Xen and HyperV interfaces. CPUID_4000_0000 to CPUID_4000_00FF provides information related to the HyperV interface, while CPUID_4000_0100 to CPUID_4000_01FF provides information related to the Xen interface, and CPUID_4000_XX00 to CPUID_4000_XXFF provides information related to the MicroV interface.

To locate the MicroV interface, software should scan from CPUID_4000_0200 to the value returned by CPUID_4000_0000_EAX in 0x100 increments. If software is unable to locate MicroV before hitting the end of the above range, the hypervisor is not MicroV.

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | MV_MAX_CPUID_LEAF | The max value for EAX when querying CPUID for MicroV specific information |

**const, mv_uint32_t: MV_CPUID_MIN_LEAF_VAL**
| Value | Description |
| :---- | :---------- |
| 0x40000202 | Defines the minimum expected return value of mv_max_cpuid_leaf |

**const, mv_uint32_t: MV_CPUID_MAX_LEAF_VAL**
| Value | Description |
| :---- | :---------- |
| 0x4000FFFF | Defines the maximum expected return value of mv_max_cpuid_leaf |

**const, mv_uint32_t: MV_CPUID_INIT_VAL**
| Value | Description |
| :---- | :---------- |
| 0x40000200 | Defines the first CPUID to scan from |

**const, mv_uint32_t: MV_CPUID_INC_VAL**
| Value | Description |
| :---- | :---------- |
| 0x100 | Defines increment used when scanning CPUID |

### 2.2.2. CPUID_4000_XX00_EBX

This CPUID query returns "BfMi".

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | MV_VENDOR_ID1 | Returns 0x694D6642 - "BfMi"|

**const, mv_uint32_t: MV_CPUID_VENDOR_ID1_VAL**
| Value | Description |
| :---- | :---------- |
| 0x694D6642 | Defines the expected return value of mv_vendor_id1 |

### 2.2.3. CPUID_4000_XX00_ECX

This CPUID query returns "croV".

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | MV_VENDOR_ID2 | Returns 0x566F7263 - "croV" |

**const, mv_uint32_t: MV_CPUID_VENDOR_ID2_VAL**
| Value | Description |
| :---- | :---------- |
| 0x566F7263 | Defines the expected return value of mv_vendor_id2 |

### 2.2.4. CPUID_4000_XX00_EDX

Reserved

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | REVZ | Returns 0 |

### 2.2.5. CPUID_4000_XX01_EAX

This CPUID query returns which versions of this specification are supported by MicroV. When software is opening a handle using mv_handle_op_open_handle, a version must be provided. This should be done by first determining which versions MicroV supports and then providing mv_handle_op_open_handle with a version that software also supports.

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 0 | MV_CPUID_SPEC_ID1 | Enabled if MicroV supports version MV_SPEC_ID1_VAL |
| 31:1 | REVZ |

### 2.2.6. CPUID_4000_XX01_EBX

Reserved

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | REVZ | Returns 0 |

### 2.2.7. CPUID_4000_XX01_ECX

Reserved

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | REVZ | Returns 0 |

### 2.2.8. CPUID_4000_XX01_EDX

Reserved

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | REVZ | Returns 0 |

### 2.2.9. CPUID_4000_XX02_EAX

Reserved

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | REVZ | Returns 0 |

### 2.2.10. CPUID_4000_XX02_EBX

This CPUID query returns the month and year of the release of this version of the MicroV hypervisor.

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:16 | MV_VER_YEAR | Returns the year MicroV was released |
| 15:0 | MV_VER_MONTH | Returns the month MicroV was released |

### 2.2.11. CPUID_4000_XX02_ECX

Reserved

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | REVZ | Returns 0 |

### 2.2.12. CPUID_4000_XX02_EDX

This CPUID query returns MicroV's incremental build number. Typically, this CPUID query will return 0, but if patches are required for any given release, the incremental build number will be increased to reflect the changes. In other words, the 64 bit value of EBX:EDX will continue to increase with each new release of MicroV and can be used to identify compatibility.

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | MV_BUILD_NUM | Returns the incremental build number for MicroV |

# 3. Hypercall Interface

The following section defines the hypercall interface used by this specification, and therefore MicroV.

## 3.1. Hypercall Continuation

Some hypercalls might take a long time to execute. Since MicroV does not service interrupts, interrupts are disabled while a hypercall is being processed. If a hypercall takes to long, this can have adverse effects on software if interrupts need to perform work while the hypercall is attempting to process.

To prevent this from occurring, long running hypercalls resume software periodically without advancing the instruction pointer. This forces the hypercall to be executed again, allowing the hypervisor to resume its execution. For this reason, some hypercalls might generate more than one VMExit, and more importantly, software should not rely on a hypercall completing before other operations can take place (e.g., servicing interrupts).

In some cases, software might want more control on how a continuation is handled. For example, if software needs to perform additional actions above and beyond servicing interrupts. To support this, the MV_HYPERCALL_FLAGS_SCC flag can be set, telling the hypervisor to advance the instruction pointer and return MV_STATUS_RETRY_CONTINUATION, indicating to software that a continuation is required and software should retry the hypercall when it is ready.

## 3.2. Legal Hypercall Environments

Hypercalls can be executed from both user-space and kernel-space once long-mode has been enabled. The hypercall ABI defined by this document assumes support for 64bit registers and as such, all other modes are not supported with respect to hypercalls (i.e., the other modes of operation are supported by MicroV, its only the use of hypercalls from these other modes that are not supported).

## 3.3. Alignment Requirements

Most guest physical addresses are required to be page aligned. When this occurs, the hypercall documentation will state that bits 11:0 are REVZ. If this is not documented, software can safely assume that the lower 12 bits of the GPA are valid and can be provided.

If a hypercall must provide input/output larger than what is supported from a register only hypercall, a structure will be used instead. When this occurs, software must place the structure in a page (that is page aligned) at offset 0 of the page, providing the GPA of the page as input.

## 3.4. Hypercall Status Codes

Every hypercall returns a mv_status_t to indicate if the hypercall executed successfully or not and why. The mv_status_t value is layed out as follows:

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:48 | MV_STATUS_SIG | Contains 0x0000 on success, 0xDEAD on failure |
| 47:16 | MV_STATUS_FLAGS | Contains the flags associated with the mv_status_t |
| 15:0 | MV_STATUS_VALUE | Contains the value of the mv_status_t |

MV_STATUS_VALUE is used to determine success, or which type of error occurred. MV_STATUS_FLAGS provide additional information about why the error occurred. It should be noted that MV_STATUS_FLAGS is optional and used solely for diagnostics. As such, the hypervisor may or may not provide them.

Finally, every hypercall might return MV_STATUS_SUCCESS, MV_STATUS_FAILURE, MV_STATUS_INVALID_PERM or MV_STATUS_INVALID_PARAMS. For this reason, these status codes are not documented in the hypercall documentation, as software should assume any of these status codes could be returned, in addition to the status codes that are documented.

```c
static inline mv_status_t
mv_status_sig(mv_status_t const status)
{
    return (status & 0xFFFF000000000000);
}
```

```c
static inline mv_status_t
mv_status_flags(mv_status_t const status)
{
    return (status & 0x0000FFFFFFFF0000);
}
```

```c
static inline mv_status_t
mv_status_value(mv_status_t const status)
{
    return (status & 0x000000000000FFFF);
}
```

### 3.4.1. MV_STATUS_SUCCESS, VALUE=0

Used to indicated that the hypercall returned successfully. This mv_status_t does not support flags, and as a result, software may safely check the result of a hypercall with 0 to determine if an error occurred or not without having to parse the individual fields of mv_status_t.

### 3.4.2. MV_STATUS_FAILURE, VALUE=1

Used to indicate a general failure.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_FAILURE_UNKNOWN | Indicates an unknown error occurred |
| 17 | MV_STATUS_FAILURE_UNKNOWN_HYPERCALL | Indicates the hypercall is unknown |
| 18 | MV_STATUS_FAILURE_INVALID_HANDLE | Indicates the provided handle is invalid |
| 19 | MV_STATUS_FAILURE_UNSUPPORTED_HYPERCALL | Indicates the hypercall is unsupported |
| 20 | MV_STATUS_FAILURE_UNSUPPORTED_FLAGS | Indicates one or more provided flags are unsupported |
| 21 | MV_STATUS_FAILURE_UNSUPPORTED_SPED_ID | Indicates the provided specification version is not supported |

### 3.4.3. MV_STATUS_INVALID_PERM, VALUE=2

Used to indicate a permissions failure.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_INVALID_PERM_VMID | Indicates the calling VM is not allowed to execute this hypercall |
| 17 | MV_STATUS_INVALID_PERM_DENIED | Indicates the policy engine denied hypercall |

### 3.4.4. MV_STATUS_INVALID_PARAMS, VALUE=3

Used to indicate that one or more input/output parameters provided to the C wrapper are invalid.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_INVALID_PARAMS0 | Indicates param 0 is invalid |
| 17 | MV_STATUS_INVALID_PARAMS1 | Indicates param 1 is invalid |
| 18 | MV_STATUS_INVALID_PARAMS2 | Indicates param 2 is invalid |
| 19 | MV_STATUS_INVALID_PARAMS3 | Indicates param 3 is invalid |
| 20 | MV_STATUS_INVALID_PARAMS4 | Indicates param 4 is invalid |
| 21 | MV_STATUS_INVALID_PARAMS5 | Indicates param 5 is invalid |

### 3.4.5. MV_STATUS_INVALID_GPA, VALUE=0x4

Used to indicate a provided GPA is invalid.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_INVALID_GPA_NULL | Indicates the provided GPA was 0 |
| 17 | MV_STATUS_INVALID_GPA_OUT_OF_RANGE | Indicates the provided GPA is not mapped in the VM |
| 18 | MV_STATUS_INVALID_GPA_ALIGNMENT | Indicates the provided GPA is not properly aligned |

### 3.4.6. MV_STATUS_INVALID_SIZE, VALUE=0x5

Used to indicate a provided size is invalid.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_INVALID_SIZE_ZERO | Indicates the provided size was 0  |
| 17 | MV_STATUS_INVALID_SIZE_OUT_OF_RANGE | Indicates the provided size is out of range |
| 18 | MV_STATUS_INVALID_SIZE_ALIGNMENT | Indicates the provided size is not properly aligned  |

### 3.4.7. MV_STATUS_RETRY, VALUE=0x6

Used to indicate to software that it should execute the hypercall again. This usually occurs when the hypervisor needs to execute the hypercall using a continuation.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_RETRY_CONTINUATION | Indicates the reason is due to a continuation |

### 3.4.8. MV_STATUS_INVALID_VMID, VALUE=0x7

Used to indicate that that the provided VMID is invalid.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_INVALID_VMID_UNKNOWN | Indicates the provided VMID does not exist |
| 17 | MV_STATUS_INVALID_VMID_UNSUPPORTED_ROOT | Indicates the ROOT VMID is unsupported |
| 18 | MV_STATUS_INVALID_VMID_UNSUPPORTED_SELF | Indicates the SELF VMID is unsupported |
| 19 | MV_STATUS_INVALID_VMID_UNSUPPORTED_GLOBAL_STORE | Indicates the GLOBAL STORE VMID is unsupported |
| 20 | MV_STATUS_INVALID_VMID_UNSUPPORTED_ANY | Indicates the ANY VMID is unsupported |

### 3.4.9. MV_STATUS_INVALID_UUID, VALUE=0x8

Used to indicate that that the provided UUID is invalid.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_INVALID_UUID_UNKNOWN | Indicates the provided UUID does not exist |
| 17 | MV_STATUS_INVALID_UUID_UNSUPPORTED_ROOT | Indicates the ROOT UUID is unsupported |
| 18 | MV_STATUS_INVALID_UUID_UNSUPPORTED_SELF | Indicates the SELF UUID is unsupported |
| 19 | MV_STATUS_INVALID_UUID_UNSUPPORTED_GLOBAL_STORE | Indicates the GLOBAL STORE UUID is unsupported |
| 20 | MV_STATUS_INVALID_UUID_UNSUPPORTED_ANY | Indicates the ANY UUID is unsupported |

### 3.4.10. MV_STATUS_INVALID_VPID, VALUE=0x9

Used to indicate that that the provided VPID is invalid.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 16 | MV_STATUS_INVALID_VPID_UNKNOWN | Indicates the provided VPID does not exist |
| 17 | MV_STATUS_INVALID_VPID_UNSUPPORTED_SELF | Indicates the SELF VPID is unsupported |
| 18 | MV_STATUS_INVALID_VPID_UNSUPPORTED_PARENT | Indicates the PARENT VPID is unsupported |
| 19 | MV_STATUS_INVALID_VPID_UNSUPPORTED_ANY | Indicates the ANY VPID is unsupported |

## 3.5. Hypercall Inputs

Before software can execute a hypercall, it must first open a handle to the hypercall interface. This is done by executing the mv_handle_op_open_handle hypercall. This handle must be provided as the first argument to each hypercall in R10 (i.e., REG0) and can be released using the mv_handle_op_close_handle hypercall.

**R10:**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:0 | MV_HANDLE | The result of mv_handle_op_open_handle |

Every hypercall must provide information about what hypercall is being made. This is done by filling out RAX as follows:

**RAX:**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:48 | MV_HYPERCALL_SIG | 0x764D = "Mv" |
| 47:32 | MV_HYPERCALL_FLAGS | Contains the hypercall's flags |
| 31:16 | MV_HYPERCALL_OP | Contains the hypercall's opcode |
| 15:0 | MV_HYPERCALL_IDX | Contains the hypercall's index |

**const, mv_uint64_t: MV_HYPERCALL_SIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000000000 | Defines the MV_HYPERCALL_SIG field for RAX |

**const, mv_uint64_t: MV_OP_SHIFT**
| Value | Description |
| :---- | :---------- |
| 16 | Defines the shift needed to remove the index to ensure the opcode starts at bit 0 |

MV_HYPERCALL_SIG is used to ensure the hypercall is in fact a MicroV specific hypercall. MV_HYPERCALL_FLAGS is used to provide additional hypercall options.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 32 | MV_HYPERCALL_FLAGS_SCC | Tells MicroV that if a continuation is required, MicroV should return MV_STATUS_RETRY_CONTINUATION instead of automatically retrying the hypercall, allowing software to control when the continuation occurs |

MV_HYPERCALL_OP determines which opcode the hypercall belongs to, logically grouping hypercalls based on their function. This is also used internally within the hypervisor to dispatch the hypercall to the proper handler. MV_HYPERCALL_IDX, when combined with MV_HYPERCALL_OP determines what hypercall is being made. The values assigned to both MV_HYPERCALL_IDX and MV_HYPERCALL_OP are tightly packed to ensure MicroV (and variants) can use jump tables instead of branch logic for dispatching hypercalls as desired (depends on the trade off between retpoline mitigations and branch induced pipeline stalls).

It should be noted that when parsing the opcode of a hypercall, the MV_HYPERCALL_SIG is usually included in the definition of the opcode to ease the process of parsing the above fields to determine if a hypercall is supported. This can also be seen in mv_hypercall_opcode which returns MV_HYPERCALL_SIG and MV_HYPERCALL_OP. mv_hypercall_opcode_nosig can be used instead of mv_hypercall_opcode if the sig is not desired.

```c
static inline mv_uint64_t
mv_hypercall_sig(mv_uint64_t const rax)
{
    return (rax & 0xFFFF000000000000);
}
```

```c
static inline mv_uint64_t
mv_hypercall_flags(mv_uint64_t const rax)
{
    return (rax & 0x0000FFFF00000000);
}
```

```c
static inline mv_uint64_t
mv_hypercall_opcode(mv_uint64_t const rax)
{
    return (rax & 0xFFFF0000FFFF0000);
}
```

```c
static inline mv_uint64_t
mv_hypercall_opcode_nosig(mv_uint64_t const rax)
{
    return (rax & 0x00000000FFFF0000);
}
```

```c
static inline mv_uint64_t
mv_hypercall_index(mv_uint64_t const rax)
{
    return (rax & 0x000000000000FFFF);
}
```

The following defines the input registers for x64 based systems (i.e., x86_64 and amd64):

**Arguments:**
| Register Name | Description |
| :------------ | :---------- |
| R10 | Set to the result of mv_handle_op_open_handle |
| R11 | Stores the value of REG1 (hypercall specific) |
| R12 | Stores the value of REG2 (hypercall specific) |
| R13 | Stores the value of REG3 (hypercall specific) |
| R14 | Stores the value of REG4 (hypercall specific) |
| R15 | Stores the value of REG5 (hypercall specific) |

All unused registers by any hypercall are considered REVI.

## 3.6. Hypercall Outputs

Every hypercall returns a mv_status_t, which is used to indicate if the hypercall succeeded, or failed and why. This mv_status_t is returned in RAX. It should be noted that the C wrapper calls are allowed to return a mv_status_t without actually making the hypercall if they determine the hypercall cannot be safely executed. This is usually due to the caller providing the C wrapper with invalid arguments.

**RAX:**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:0 | MV_STATUS | Contains the value of mv_status_t |

The following defines the output registers for x64 based systems (i.e., x86_64 and amd64):

**Arguments:**
| Register Name | Description |
| :------------ | :---------- |
| R10 | Stores the value of REG0 (hypercall specific) |
| R11 | Stores the value of REG1 (hypercall specific) |
| R12 | Stores the value of REG2 (hypercall specific) |
| R13 | Stores the value of REG3 (hypercall specific) |
| R14 | Stores the value of REG4 (hypercall specific) |
| R15 | Stores the value of REG5 (hypercall specific) |

## 3.7. Hypercall Opcodes

The following sections define the different opcodes that are supported by this specification. Note that each opcode includes the hypercall signature making it easier to validate if the hypercall is supported or not.

### 3.7.1. Debug Support

**const, mv_uint64_t: MV_DEBUG_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000000000 | Defines the hypercall opcode for mv_debug_op hypercalls |

**const, mv_uint64_t: MV_DEBUG_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall opcode for mv_debug_op hypercalls with no signature |

### 3.7.2. Handle Support

**const, mv_uint64_t: MV_HANDLE_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000010000 | Defines the hypercall opcode for mv_handle_op hypercalls |

**const, mv_uint64_t: MV_HANDLE_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000010000 | Defines the hypercall opcode for mv_handle_op hypercalls with no signature |

### 3.7.3. Virtual Machines

**const, mv_uint64_t: MV_VM_PROPERTIES_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000020000 | Defines the hypercall opcode for mv_vm_properties_op hypercalls |

**const, mv_uint64_t: MV_VM_PROPERTIES_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000020000 | Defines the hypercall opcode for mv_vm_properties_op hypercalls with no signature |

**const, mv_uint64_t: MV_VM_STATE_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000030000 | Defines the hypercall opcode for mv_vm_state_op hypercalls |

**const, mv_uint64_t: MV_VM_STATE_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000030000 | Defines the hypercall opcode for mv_vm_state_op hypercalls with no signature |

**const, mv_uint64_t: MV_VM_MANAGEMENT_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000040000 | Defines the hypercall opcode for mv_vm_management_op hypercalls |

**const, mv_uint64_t: MV_VM_MANAGEMENT_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000040000 | Defines the hypercall opcode for mv_vm_management_op hypercalls with no signature |

**const, mv_uint64_t: MV_VM_KV_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000050000 | Defines the hypercall opcode for mv_vm_kv_op hypercalls |

**const, mv_uint64_t: MV_VM_KV_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000050000 | Defines the hypercall opcode for mv_vm_kv_op hypercalls with no signature |

### 3.7.4. Virtual Processors

**const, mv_uint64_t: MV_VP_PROPERTIES_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000060000 | Defines the hypercall opcode for mv_vp_properties_op hypercalls |

**const, mv_uint64_t: MV_VP_PROPERTIES_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000060000 | Defines the hypercall opcode for mv_vp_properties_op hypercalls with no signature |

**const, mv_uint64_t: MV_VP_STATE_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000070000 | Defines the hypercall opcode for mv_vp_state_op hypercalls |

**const, mv_uint64_t: MV_VP_STATE_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000070000 | Defines the hypercall opcode for mv_vp_state_op hypercalls with no signature |

**const, mv_uint64_t: MV_VP_MANAGEMENT_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000080000 | Defines the hypercall opcode for mv_vp_management_op hypercalls |

**const, mv_uint64_t: MV_VP_MANAGEMENT_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000080000 | Defines the hypercall opcode for mv_vp_management_op hypercalls with no signature |

**const, mv_uint64_t: MV_VP_EXIT_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000090000 | Defines the hypercall opcode for mv_vp_exit_op hypercalls |

**const, mv_uint64_t: MV_VP_EXIT_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000090000 | Defines the hypercall opcode for mv_vp_exit_op hypercalls with no signature |

## 3.8. Debug Hypercalls

### 3.8.1. mv_debug_op_out, OP=0x0, IDX=0x0

This hypercall tells the hypervisor to output R10 and R11 to the console device the hypervisor is currently using for debugging. The purpose of this hypercall is to provide a simple means for debugging issues with the guest and can be used by a VM from both user-space and the kernel, even when the operating system is not fully bootstrapped or is in a failure state (so long as long-mode is enabled). Also note that this hypercall is designed to execute as quickly as possible (although it is still constrained by the speed at which it can dump debug text to the console).

**WARNING:**
In production builds of MicroV, this hypercall is not present.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The first value to output to the hypervisor's console |
| REG1 | 63:0 | The second value to output to the hypervisor's console |

**const, mv_uint64_t: MV_DEBUG_OP_OUT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_debug_op_out |

```c
static inline mv_status_t
mv_debug_op_out(
    mv_uint64_t const val1,    /* IN */
    mv_uint64_t const val2)    /* IN */
{
    return _mv_debug_op_out(val1, val2);
}
```

### 3.8.2. mv_debug_op_dump_vms, OP=0x0, IDX=0x1

This hypercall tells the hypervisor to output the state of a VM to the console device the hypervisor is currently using for debugging. The report that is generated is implementation defined, and in some cases could take a while to complete. In other words, this hypercall should only be used when debugging, and only in scenarios where you can afford the time needed to output a lot of VM state to the hypervisor's console.

**WARNING:**
In production builds of MicroV, this hypercall is not present.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The VMID of the VM whose state is to be outputted |

**const, mv_uint64_t: MV_DEBUG_OP_DUMP_VMS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_debug_op_dump_vms |

```c
static inline mv_status_t
mv_debug_op_dump_vms(
    mv_uint64_t const vmid)    /* IN */
{
    return _mv_debug_op_dump_vms(vmid);
}
```

### 3.8.3. mv_debug_op_dump_vps, OP=0x0, IDX=0x2

This hypercall tells the hypervisor to output the state of a VP to the console device the hypervisor is currently using for debugging. The report that is generated is implementation defined, and in some cases could take a while to complete. In other words, this hypercall should only be used when debugging, and only in scenarios where you can afford the time needed to output a lot of VP state to the hypervisor's console.

**WARNING:**
In production builds of MicroV, this hypercall is not present.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The VPID of the VP whose state is to be outputted |

**const, mv_uint64_t: MV_DEBUG_OP_DUMP_VPS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the hypercall index for mv_debug_op_dump_vps |

```c
static inline mv_status_t
mv_debug_op_dump_vps(
    mv_uint64_t const vpid)    /* IN */
{
    return _mv_debug_op_dump_vps(vpid);
}
```

### 3.8.4. mv_debug_op_dump_vmexit_log, OP=0x0, IDX=0x3

This hypercall tells the hypervisor to output the vmexit log. The vmexit log is a chronological log of the "X" number of exits that have occurred from the time the call to mv_debug_op_dump_vmexit_log is made. The total number of "X" logs is implementation defined and not under the control of software (i.e., this value is usually compiled into MicroV cannot be changed at runtime). In addition, the format of this log is also implementation defined. If the hypervisor has to kill a VP for VM for any reason it will output this log by default for debugging purposes, but sometimes, software is aware of odd condition, or is even aware that something bad has happened, and this hypercall provides software with an opportunity to dump this log on demand.

**WARNING:**
In production builds of MicroV, this hypercall is not present.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The VPID of the VP to dump the log from |

**const, mv_uint64_t: MV_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the hypercall index for mv_debug_op_dump_vmexit_log |

```c
static inline mv_status_t
mv_debug_op_dump_vmexit_log(
    mv_uint64_t const vpid)    /* IN */
{
    return _mv_debug_op_dump_vmexit_log(vpid);
}
```

### 3.8.5. mv_debug_op_dump_memory_map, OP=0x0, IDX=0x4

TBD - output system physical mappings for each VM

## 3.9. Handle Hypercalls

### 3.9.1. mv_handle_op_open_handle, OP=0x1, IDX=0x0

This hypercall returns a handle which is required to execute the remaining hypercalls.

Some versions of MicroV might provide a certain degree of backwards compatibility which can be queried using CPUID_4000_XX01_EAX. The version argument of this hypercall provides software with means to tell the hypervisor which version of this spec it is trying to use. If software provides a version that MicroV doesn't support (i.e., a version that is not listed by CPUID_4000_XX01_EAX), this hypercall will fail.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | REVI |
| REG1 | 63:32 | REVI |
| REG1 | 31:0 | The version of this spec that software supports |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value to set REG0 to for all other hypercalls (minus debugging hypercalls) |

**const, mv_uint64_t: MV_HANDLE_OP_OPEN_HANDLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_handle_op_open_handle |

```c
static inline mv_status_t
mv_handle_op_open_handle(
    mv_uint32_t const version,           /* IN */
    struct mv_handle_t *const handle)    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS1;
    }

    return _mv_handle_op_open_handle(version, &handle->hndl);
}
```

### 3.9.2. mv_handle_op_close_handle, OP=0x1, IDX=0x1

This hypercall closes a previously opened handle.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**const, mv_uint64_t: MV_HANDLE_OP_CLOSE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_handle_op_close_handle |

```c
static inline mv_status_t
mv_handle_op_close_handle(
    struct mv_handle_t const *const handle)    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_handle_op_close_handle(handle->hndl);
}
```

# 4. Virtual Machines

A Virtual Machine or VM virtually represents a physical computer and stores the resources that are shared between one or more Virtual Processors called the Virtual Machine State or VMS. MicroV is capable of executing multiple VMs simultaneously on the same physical machine. In some configurations these VMs might share the same physical cores/threads and in other configurations, each VM is given dedicated access to one or more physical cores/threads, and either share the rest of hardware, or the rest of hardware is divided up between VMs using something like an IOMMU (or some combination of the two).

There are different types of VMs. The root VM is the initial VM created by MicroV and executes whatever operating system was executing at the time MicroV was started. In some configurations (early boot), MicroV is started from BIOS/UEFI and demotes BIOS/UEFI into the root VM. From there, BIOS/UEFI might boot an additional operating system such as Windows or Linux inside the root VM. In other configurations (late launch), an operating system such as Windows or Linux has already booted and MicroV is started some time later. In this configuration MicroV demotes the current operating system into the root VM and executes from there.

The early boot configuration of MicroV provides better security as well as early access to memory resources reducing fragmentation and increasing the efficiency of the overall system (reduces shattering of large pages). The late launch configuration of MicroV is easier to develop for as well as deploy (no need to modify the boot process of the system).

All additional VMs that are created from the root VM are called guest VMs. Guest VMs are not capable of creating additional guest VMs (VMs can only be created by the root VM). That is, MicroV uses a breath of many, depth of one approach.

## 4.1. Virtual Machine Types

## 4.2. VMID

The Virtual Machine ID or VMID is a 64bit number that uniquely identifies a VM. The VMID given to a VM is determined by when the VM is created and therefore can change depending on the order of how each VM has been started since the last reboot of the hypervisor. Any VMID greater than or equal to 0xFFFFFFFF00000000 or equal to 0 is reserved.

**const, mv_uint64_t: MV_VMID_ROOT**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the VMID for the Root VM |

**const, mv_uint64_t: MV_VMID_SELF**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFF0 | Defines the VMID for SELF (i.e., the calling VM) |

**const, mv_uint64_t: MV_VMID_GLOBAL_STORE**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFF1 | Defines the VMID for Global Store (i.e., the VM storing the global key/value store) |

**const, mv_uint64_t: MV_VMID_ANY**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFFF | Defines the VMID for ANY (i.e., any VM) |

## 4.3. UUID

The UUID is a 128bit number that uniquely identifies a VM, and never changes. even if the hypervisor is rebooted. The UUID can be used to give each VM a unique "name", and a VM with the same name cannot be running more than once at a time. Any UUID greater than or equal to 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0 or equal to 0 is reserved.

**const, mv_uint64_t: MV_UUID1_ROOT**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the first 64bits of the UUID for the Root VM |

**const, mv_uint64_t: MV_UUID2_ROOT**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the last 64bits of the UUID for the Root VM |

**const, mv_uint64_t: MV_UUID1_SELF**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFF0 | Defines the first 64bits of the UUID for SELF (i.e., the calling VM) |

**const, mv_uint64_t: MV_UUID2_SELF**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFFF | Defines the last 64bits of the UUID for SELF (i.e., the calling VM) |

**const, mv_uint64_t: MV_UUID1_GLOBAL_STORE**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFF1 | Defines the first 64bits of the UUID for the Global Store (i.e., the VM storing the global key/value store) |

**const, mv_uint64_t: MV_UUID2_GLOBAL_STORE**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFFF | Defines the last 64bits of the UUID for the Global Store (i.e., the VM storing the global key/value store) |

**const, mv_uint64_t: MV_UUID1_ANY**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFFF | Defines the first 64bits of the UUID for ANY (i.e., any VM) |

**const, mv_uint64_t: MV_UUID2_ANY**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFFF | Defines the last 64bits of the UUID for ANY (i.e., any VM) |

## 4.4. Virtual Machine Properties

### 4.4.1. mv_vm_properties_op_uuid, OP=0x2, IDX=0x0

This hypercall returns a UUID given a VMID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID to convert to a UUID |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The first 64 bits of the resulting UUID |
| REG1 | 63:0 | The last 64 bits of the resulting UUID |

**const, mv_uint64_t: MV_VM_PROPERTIES_OP_UUID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_vm_properties_op_uuid |

```c
static inline mv_status_t
mv_vm_properties_op_uuid(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t *const uuid1,                  /* OUT */
    mv_uint64_t *const uuid2)                  /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == uuid1) {
        return MV_STATUS_INVALID_PARAMS2;
    }

    if (MV_NULL == uuid2) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_properties_op_uuid(handle->hndl, vmid, uuid1, uuid2);
}
```

### 4.4.2. mv_vm_properties_op_vmid, OP=0x2, IDX=0x1

This hypercall returns a VMID given a UUID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The first 64 bits of the UUID to convert to a VMID |
| REG2 | 63:0 | The last 64 bits of the UUID to convert to a VMID |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting VMID |

**const, mv_uint64_t: MV_VM_PROPERTIES_OP_VMID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_vm_properties_op_vmid |

```c
static inline mv_status_t
mv_vm_properties_op_vmid(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const uuid1,                   /* IN */
    mv_uint64_t const uuid2,                   /* IN */
    mv_uint64_t *const vmid)                   /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == vmid) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_properties_op_vmid(handle->hndl, uuid1, uuid2, vmid);
}
```

### 4.4.3. mv_vm_properties_is_root_vm, OP=0x2, IDX=0x2

TBD

### 4.4.4. mv_vm_properties_is_guest_vm, OP=0x2, IDX=0x3

TBD

### 4.4.5. mv_vm_properties_state, OP=0x2, IDX=0x4

TBD

### 4.4.6. mv_vm_properties_op_e820, OP=0x2, IDX=0x5

This hypercall returns the e820 map associated with a specific VM given it's VMID. It should be noted that mv_vm_properties_op_set_e820 must first be called to set the e820 map (as the hypervisor has no means to determine this information on its own), otherwise this hypercall will return an error. It should be noted that we use the MDL structure to define the e820 map. This API has also reserved an argument for future use if more than MV_MDL_MAP_MAX_NUM_ENTRIES entries is required.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID of the VM to get the e820 for |
| REG2 | 63:0 | REVI |
| REG3 | 63:12 | The GPA of the MDL to return the e820 map to |
| REG3 | 11:0 | REVZ |

**const, mv_uint64_t: MV_VM_PROPERTIES_OP_E820_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the hypercall index for mv_vm_properties_op_e820 |

Upon successful completion of this hypercall, the page provided by the input register REG3 at offset 0 will contain the e820 map defined as an MDL.

```c
static inline mv_status_t
mv_vm_properties_op_e820(
    struct mv_handle_t const *const handle,     /* IN */
    mv_uint64_t const vmid,                     /* IN */
    mv_uint64_t const revz,                     /* IN */
    mv_uint64_t const e820_map_gpa)             /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_properties_op_e820(handle->hndl, vmid, revz, e820_map_gpa);
}
```

### 4.4.7. mv_vm_properties_op_set_e820, OP=0x2, IDX=0x6

This hypercall sets the e820 map associated with a specific VM given it's VMID. It should be noted that mv_vm_properties_op_set_e820 must first be called to set the e820 map (as the hypervisor has no means to determine this information on its own), before mv_vm_properties_op_e820 can be called, otherwise it will return an error. It should also be noted that we use the MDL structure to define the e820 map. This API has also reserved an argument for future use if more than MV_MDL_MAP_MAX_NUM_ENTRIES entries is required.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID of the VM to set the e820 for |
| REG2 | 63:0 | REVI |
| REG3 | 63:12 | The GPA of the MDL to set the e820 map to |
| REG3 | 11:0 | REVZ |

**const, mv_uint64_t: MV_VM_PROPERTIES_OP_SET_E820_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the hypercall index for mv_vm_properties_op_set_e820 |

Upon successful completion of this hypercall, the page provided by the input register REG3 at offset 0 will be used to set the e820 map defined as an MDL.

```c
static inline mv_status_t
mv_vm_properties_op_set_e820(
    struct mv_handle_t const *const handle,     /* IN */
    mv_uint64_t const vmid,                     /* IN */
    mv_uint64_t const revz,                     /* IN */
    mv_uint64_t const e820_map_gpa)             /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_properties_op_set_e820(
               handle->hndl, vmid, revz, e820_map_gpa);
}
```

### 4.4.8. mv_vm_properties_op_set_pt_uart, OP=0x2, IDX=0x7

This hypercall is used to provide a guest VM with a UART from the root VM by passing the hardware from the root VM's UART to the guest VM. This can be used to support debugging.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID of the VM to receive the UART |
| REG2 | 63:16 | REVZ |
| REG2 | 15:0 | The starting port of the UART to pass through |

**const, mv_uint64_t: MV_VM_PROPERTIES_OP_SET_PT_UART_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the hypercall index for mv_vm_properties_op_set_pt_uart |

```c
static inline mv_status_t
mv_vm_properties_op_set_pt_uart(
    struct mv_handle_t const *const handle,     /* IN */
    mv_uint64_t const vmid,                     /* IN */
    mv_uint16_t const port)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_properties_op_set_pt_uart(handle->hndl, vmid, port);
}
```

## 4.5. Virtual Machine State

### 4.5.1. mv_vm_state_op_initial_reg_val, OP=0x3, IDX=0x0

When a VP is started, it gets its initial register value from a cache in the VM. This hypercall provides a means to read from this cache for register types (not including MSRs).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID to read the initial VP value from |
| REG2 | 63:0 | A mv_reg_t describing the register value requested |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value read from the cache |

**const, mv_uint64_t: MV_VM_STATE_OP_INITIAL_REG_VAL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_vm_state_op_initial_reg_val |

```c
static inline mv_status_t
mv_vm_state_op_initial_reg_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const reg,                     /* IN */
    mv_uint64_t *const val)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (reg >= mv_reg_t_max) {
        return MV_STATUS_INVALID_PARAMS2;
    }

    if (MV_NULL == val) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_state_op_initial_reg_val(handle->hndl, vmid, reg, val);
}
```

### 4.5.2. mv_vm_state_op_set_initial_reg_val, OP=0x3, IDX=0x1

When a VP is started, it gets its initial register value from a cache in the VM. This hypercall provides a means to write to this cache for register types (not including MSRs).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID to write the initial VP val to |
| REG2 | 63:0 | A mv_reg_t describing the register val requested |
| REG3 | 63:0 | The value to write to the cache |

**const, mv_uint64_t: MV_VM_STATE_OP_SET_INITIAL_REG_VAL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_vm_state_op_set_initial_reg_val |

```c
static inline mv_status_t
mv_vm_state_op_set_initial_reg_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const reg,                     /* IN */
    mv_uint64_t const val)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (reg >= mv_reg_t_max) {
        return MV_STATUS_INVALID_PARAMS2;
    }

    return _mv_vm_state_op_set_initial_reg_val(handle->hndl, vmid, reg, val);
}
```

### 4.5.3. mv_vm_state_op_list_of_initial_reg_vals, OP=0x3, IDX=0x2

TBD

### 4.5.4. mv_vm_state_op_set_list_of_initial_reg_vals, OP=0x3, IDX=0x3

TBD

### 4.5.5. mv_vm_state_op_initial_msr_val, OP=0x3, IDX=0x4

When a VP is started, it gets its initial register value from a cache in the VM. This hypercall provides a means to read from this cache for MSRs.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID to read the initial VP state from |
| REG2 | 63:32 | REVZ |
| REG2 | 31:0 | The MSR to read from |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value read from the cache |

**const, mv_uint64_t: MV_VM_STATE_OP_INITIAL_MSR_VAL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the hypercall index for mv_vm_state_op_initial_msr_val |

```c
static inline mv_status_t
mv_vm_state_op_initial_msr_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint32_t const msr,                     /* IN */
    mv_uint64_t *const val)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == val) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_state_op_initial_msr_val(handle->hndl, vmid, msr, val);
}
```

### 4.5.6. mv_vm_state_op_set_initial_msr_val, OP=0x3, IDX=0x5

When a VP is started, it gets its initial register value from a cache in the VM. This hypercall provides a means to write to this cache for MSRs.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID to write the initial VP state to |
| REG2 | 63:32 | REVZ |
| REG2 | 31:0 | The MSR to write to |
| REG3 | 63:0 | The value to write to the cache |

**const, mv_uint64_t: MV_VM_STATE_OP_SET_INITIAL_MSR_VAL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the hypercall index for mv_vm_state_op_set_initial_msr_val |

```c
static inline mv_status_t
mv_vm_state_op_set_initial_msr_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint32_t const msr,                     /* IN */
    mv_uint64_t const val)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_set_initial_msr_val(handle->hndl, vmid, msr, val);
}
```

### 4.5.7. mv_vm_state_op_list_of_initial_msr_vals, OP=0x3, IDX=0x6

TBD

### 4.5.8. mv_vm_state_op_set_list_of_initial_msr_vals, OP=0x3, IDX=0x7

TBD

### 4.5.9. mv_vm_state_op_gva_to_gpa, OP=0x3, IDX=0x8

This hypercall is used to translate a GVA to a GPA given the VMID of the VM whose GVA is being translated and the GPA of the highest-level page-translation table used for translation (the value that would be written to bits 63:12 of CR3, usually pointing to a PDT, PDPT or PML4). This hypercall returns an error code if the requested GVA is not mapped into the provided page translation tables.

**Warning:**
This hypercall should be used with caution. Specifically, this hypercall is provided for VM introspection purposes and should not be used to translate a user-space GVA to a GPA which is then used to map/grant memory to another VM without first ensuring the provided GVA will not be swapped to disk by the operating system (i.e., the GVA must be marked as non-paged by the operating system kernel). If the operating system kernel is allowed to swap the GVA to disk, the GPA returned by this hypercall could be used by other user-space processes resulting in corruption. In general, it is a lot faster and more reliable to ask the operating system to perform this conversion for you instead of relying on MicroV to perform this action, with the exception being VM introspection for certain situations when used properly. You have been warned.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vmid whose GVA is being translated |
| REG2 | 63:12 | The GPA of the highest-level page-translation table used for translation |
| REG2 | 11:0 | REVI |
| REG3 | 63:0 | The GVA to translate |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting GPA |
| REG1 | 63:32 | The flags associated with the GPA including the memory type, access rights and page size (see GPA flags for more details) |
| REG1 | 31:0 | REVZ |

**const, mv_uint64_t: MV_VM_STATE_OP_GVA_TO_GPA_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000008 | Defines the hypercall index for mv_vm_state_op_gva_to_gpa |

```c
static inline mv_status_t
mv_vm_state_op_gva_to_gpa(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const ptt_gpa,                 /* IN */
    mv_uint64_t const gva,                     /* IN */
    mv_uint64_t *const gpa,                    /* OUT */
    mv_uint64_t *const flags)                  /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == gpa) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    if (MV_NULL == flags) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vm_state_op_gva_to_gpa(
               handle->hndl, vmid, ptt_gpa, gva, gpa, flags);
}
```

### 4.5.10. mv_vm_state_op_map_range, OP=0x3, IDX=0x9

This hypercall is used to map a range of physically contiguous memory. The caller must provide the source VMID (i.e., the VM to map memory from), and a destination VMID (i.e., the VM to map memory to). In addition, the caller must provide the source GPA (i.e., the GPA of the range of memory to map from), and the destination GPA (i.e., the GPA of the range of memory to map to). Finally, the caller must provide the number of 4k pages in the range to map, as well as flags associated with how memory should be mapped. If the number of 4k pages is set to 0, 1 4k page is assumed.

If MV_GPA_FLAG_DONATE is set in the flags, the memory will be donated from the source VM to the destination VM, meaning the source VM will no longer have access to the donated memory once the hypercall is complete. The only VM that is allowed to make a call to mv_vm_state_op_map_range with MV_GPA_FLAG_DONATE is the root VM and the source VM must be the root VM.

If MV_GPA_FLAG_DONATE is not set (the default), the source memory range is mapped into both the source and destination, meaning both VMs will share the same system physical memory range from the source VM, allowing them to pass data between them. Sharing memory between two different VMs introduces a dependency between these VMs. If the source VM should crash, the memory being shared with the destination VM becomes a problem. MicroV provides two different approaches to handling this situation. By default, if the source VM crashes, MicroV will also kill the destination VM by instructing the root VM to execute mv_vp_op_kill on the destination VM before destroying the source VM. This default behavior prevents memory leaks, and other potential security issues. If the destination VM is the root VM or if mv_vm_state_op_map_range is called with MV_GPA_FLAG_ZOMBIE, the source VM will not be destroyed and instead will remain as a zombie until the destination VM finally unmaps the memory, allowing the source VM to finally be destroyed. Note that if a chain of VMs is created using mv_vm_state_op_map_range, the default behavior could result in the entire chain of VMs being killed.

By default, memory is mapped as read-only for both donations and shared memory, meaning the destination VM is given read-only access to the mapped memory range. If MV_GPA_FLAG_DONATE is set, the source VM's access to the memory is removed. If MV_GPA_FLAG_DONATE is not set, the source VM's access to the memory is left unchanged. For example, if the source VM's memory range is mapped as read/write/execute, after this memory range is mapped into the destination VM, the source VM will still have read/write/execute access to the range while the destination VM will have read-only access to the range. If additional memory access rights are needed for the destination VM, the caller can provide MV_GPA_FLAG_WRITE_ACCESS and MV_GPA_FLAG_EXECUTE_ACCESS to provide whatever access right combination is needed. If the source VM's access rights need to be adjusted, the mv_vm_op_gpa_set_flags call can be used to perform this operation. It should be noted that not all combinations are supported (depends on the hardware).

How the memory type is set for both the source GPA and the destination GPA depends on the type of map that is occurring. It should be noted that the following memory type rules are performed on a page by page basis in the requested range.

If MV_GPA_FLAG_DONATE is set, the destination GPA's memory type is left unchanged. If the destination GPA has never been mapped, the memory type defaults to write-back. Software can also control how the destination GPA's memory type is set by providing one of the cacheability flags (e.g., MV_GPA_FLAG_WRITE_COMBINING). The flags that are supported depends on the system. Use of these flags should be handled with care. If memory was mapped using a strict caching scheme, changing the memory type to a less-strict scheme might lead to undefined behavior.

If MV_GPA_FLAG_DONATE is not set, both the source and destination GPA's memory types are set to the combination of their memory types using the combination rules defined by both Intel and AMD (please see their software development manuals for more information about how memory type combining is performed with Intel's EPT and AMD's NCR3). For example, if the source GPA is set to write-back and the destination GPA is set to write-through, both the source GPA and the destination GPA will be set to write-through. If either the source GPA or the destination GPA are not mapped, their memory type defaults to write-back, and then the combination is calculated from there. Software can also control how the source and destination GPA's memory type is set by providing one of the cacheability flags (e.g., MV_GPA_FLAG_WRITE_COMBINING). As stated previously, the flags that are supported depends on the system and the use of these flags should be handled with care.

**Warning:**
This hypercall should be used with caution. Specifically, the range should be marked by either the source operating system or the destination operating system as non-paged. If this is not done, both operating systems might page-out the guest physical memory to disk, resulting in corruption. For example, if this hypercall is being used to map a VM's memory into another VM's memory for introspection, the source VM's GPA range should be marked as non-paged.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The source VMID |
| REG2 | 63:12 | The source GPA of the range to map from |
| REG2 | 11:0 | REVZ |
| REG3 | 63:0 | The destination VMID |
| REG4 | 63:12 | The destination GPA of the range to map to |
| REG4 | 11:0 | REVZ |
| REG5 | 63:32 | The GPA flags used to determine how to map the range |
| REG5 | 31:0 | The total number of 4k pages to map |

**const, mv_uint64_t: MV_VM_STATE_OP_MAP_RANGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000009 | Defines the hypercall index for mv_vm_state_op_map_range |

```c
static inline mv_status_t
mv_vm_state_op_map_range(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const flags_size)              /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_map_range(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, flags_size);
}
```

### 4.5.11. mv_vm_state_op_unmap_range, OP=0x3, IDX=0xA

This hypercall is used to unmap a previously mapped range of physically contiguous memory. The caller must provide the source VMID (i.e., the VM the memory was mapped from), and a destination VMID (i.e., the VM the memory was mapped to). In addition, the caller must provide the source GPA (i.e., the GPA of the range of memory that was mapped from the source), and the destination GPA (i.e., the GPA of the range of memory to unmap from the destination). Finally, the caller must provide the number of 4k pages in the range to unmap, as well as flags associated with how memory should be unmapped (if applicable). If the number of 4k pages is set to 0, 1 4k page is assumed. If the provided ranges do not match previously mapped ranges, this hypercall will fail.

If MV_GPA_FLAG_DONATE was set in the flags when the memory was originally mapped, this hypercall will fail. Once memory is donated, the only way for this memory to be returned to the root VM is to destroy the destination VM.

If MV_GPA_FLAG_DONATE was not set in the flags (the default), the map in the destination VM is removed. The source VM's map remains unchanged, even if the original call to mv_vm_state_op_map_range modified the source VM's memory type. The  mv_vm_op_gpa_set_flags hypercall can be used to modify the source VM's memory range after a call to mv_vm_state_op_unmap_range is made if needed.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The source VMID |
| REG2 | 63:12 | The source GPA of the range to unmap |
| REG2 | 11:0 | REVZ |
| REG3 | 63:0 | The destination VMID |
| REG4 | 63:12 | The destination GPA of the range to unmap |
| REG4 | 11:0 | REVZ |
| REG5 | 63:32 | The GPA flags used to determine how to unmap the range |
| REG5 | 31:0 | The total number of 4k pages to unmap |

**const, mv_uint64_t: MV_VM_STATE_OP_UNMAP_RANGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000A | Defines the hypercall index for mv_vm_state_op_unmap_range |

```c
static inline mv_status_t
mv_vm_state_op_unmap_range(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const flags_size)              /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_unmap_range(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, flags_size);
}
```

### 4.5.12. mv_vm_state_op_copy_range, OP=0x3, IDX=0xB

This hypercall is used to copy a range of physically contiguous memory from one VM to another. Unless shared memory is required, this hypercall should be used instead of mv_vm_state_op_map_range as it does not change the memory map of either the source or the destination VM. The caller must provide the source VMID (i.e., the VM to copy memory from), and a destination VMID (i.e., the VM to copy memory to). In addition, the caller must provide the source GPA (i.e., the GPA of the range of memory to copy memory from), and the destination GPA (i.e., the GPA of the range of memory to copy memory to). Finally, the caller must provide the number of 4k pages in the range to copy. If the number of 4k pages is set to 0, 1 4k page is assumed.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The source VMID |
| REG2 | 63:12 | The source GPA of the range to copy from |
| REG2 | 11:0 | REVZ |
| REG3 | 63:0 | The destination VMID |
| REG4 | 63:12 | The destination GPA of the range to copy to |
| REG4 | 11:0 | REVZ |
| REG5 | 63:32 | REVZ |
| REG5 | 31:0 | The total number of 4k pages to copy |

**const, mv_uint64_t: MV_VM_STATE_OP_COPY_RANGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000B | Defines the hypercall index for mv_vm_state_op_copy_range |

```c
static inline mv_status_t
mv_vm_state_op_copy_range(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const size)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_copy_range(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, size);
}
```

### 4.5.13. mv_vm_state_op_map_mdl, OP=0x3, IDX=0xC

This hypercall is used to map a range of physically discontiguous memory. The caller must provide the source VMID (i.e., the VM to map memory from), and a destination VMID (i.e., the VM to map memory to). In addition, the caller must provide the source GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory to map from), and the destination GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory to map to). Finally, the caller must provide flags associated with how memory should be mapped. Unlike mv_vm_state_op_map_range, mv_vm_state_op_map_mdl uses an MDL to describe how much memory should be mapped, as well as it's layout. If each physically contiguous range in the MDL is not the same between the source and the destination, this hypercall will fail. However, the starting address of each range does not have to match between the source and destination, just the size. This, for example, allows the caller to map physically discontiguous memory from one VM to a phyiscally contiguous range in the other VM.

If MV_GPA_FLAG_DONATE is set in the flags, the memory will be donated from the source VM to the destination VM, meaning the source VM will no longer have access to the donated memory once the hypercall is complete. The only VM that is allowed to make a call to mv_vm_state_op_map_range with MV_GPA_FLAG_DONATE is the root VM and the source VM must be the root VM.

If MV_GPA_FLAG_DONATE is not set (the default), the source memory range is mapped into both the source and destination, meaning both VMs will share the same system physical memory range from the source VM, allowing them to pass data between them. Sharing memory between two different VMs introduces a dependency between these VMs. If the source VM should crash, the memory being shared with the destination VM becomes a problem. MicroV provides two different approaches to handling this situation. By default, if the source VM crashes, MicroV will also kill the destination VM by instructing the root VM to execute mv_vp_op_kill on the destination VM before destroying the source VM. This default behavior prevents memory leaks, and other potential security issues. If the destination VM is the root VM or if mv_vm_state_op_map_range is called with MV_GPA_FLAG_ZOMBIE, the source VM will not be destroyed and instead will remain as a zombie until the destination VM finally unmaps the memory, allowing the source VM to finally be destroyed. Note that if a chain of VMs is created using mv_vm_state_op_map_range, the default behavior could result in the entire chain of VMs being killed.

By default, memory is mapped as read-only for both donations and shared memory, meaning the destination VM is given read-only access to the mapped memory range. If MV_GPA_FLAG_DONATE is set, the source VM's access to the memory is removed. If MV_GPA_FLAG_DONATE is not set, the source VM's access to the memory is left unchanged. For example, if the source VM's memory range is mapped as read/write/execute, after this memory range is mapped into the destination VM, the source VM will still have read/write/execute access to the range while the destination VM will have read-only access to the range. If additional memory access rights are needed for the destination VM, the caller can provide MV_GPA_FLAG_WRITE_ACCESS and MV_GPA_FLAG_EXECUTE_ACCESS to provide whatever access right combination is needed. If the source VM's access rights need to be adjusted, the mv_vm_op_gpa_set_flags call can be used to perform this operation. It should be noted that not all combinations are supported (depends on the hardware).

How the memory type is set for both the source GPA and the destination GPA depends on the type of map that is occurring. It should be noted that the following memory type rules are performed on a page by page basis in the requested range.

If MV_GPA_FLAG_DONATE is set, the destination GPA's memory type is left unchanged. If the destination GPA has never been mapped, the memory type defaults to write-back. Software can also control how the destination GPA's memory type is set by providing one of the cacheability flags (e.g., MV_GPA_FLAG_WRITE_COMBINING). The flags that are supported depends on the system. Use of these flags should be handled with care. If memory was mapped using a strict caching scheme, changing the memory type to a less-strict scheme might lead to undefined behavior.

If MV_GPA_FLAG_DONATE is not set, both the source and destination GPA's memory types are set to the combination of their memory types using the combination rules defined by both Intel and AMD (please see their software development manuals for more information about how memory type combining is performed with Intel's EPT and AMD's NCR3). For example, if the source GPA is set to write-back and the destination GPA is set to write-through, both the source GPA and the destination GPA will be set to write-through. If either the source GPA or the destination GPA are not mapped, their memory type defaults to write-back, and then the combination is calculated from there. Software can also control how the source and destination GPA's memory type is set by providing one of the cacheability flags (e.g., MV_GPA_FLAG_WRITE_COMBINING). As stated previously, the flags that are supported depends on the system and the use of these flags should be handled with care.

**Warning:**
This hypercall should be used with caution. Specifically, the range should be marked by either the source operating system or the destination operating system as non-paged. If this is not done, both operating systems might page-out the guest physical memory to disk, resulting in corruption. For example, if this hypercall is being used to map a VM's memory into another VM's memory for introspection, the source VM's GPA range should be marked as non-paged.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The source VMID |
| REG2 | 63:12 | The source GPA of the MDL that describes the range to map from |
| REG2 | 11:0 | REVZ |
| REG3 | 63:0 | The destination VMID |
| REG4 | 63:12 | The destination GPA of the MDL that describes the range to map to |
| REG4 | 11:0 | REVZ |
| REG5 | 63:32 | The GPA flags used to determine how to map the range |
| REG5 | 31:0 | REVZ |

**const, mv_uint64_t: MV_VM_STATE_OP_MAP_MDL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000C | Defines the hypercall index for mv_vm_state_op_map_mdl |

```c
static inline mv_status_t
mv_vm_state_op_map_mdl(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const flags)                   /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_map_mdl(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, flags);
}
```

### 4.5.14. mv_vm_state_op_unmap_mdl, OP=0x3, IDX=0xD

This hypercall is used to unmap a previously mapped range of physically discontiguous memory. The caller must provide the source VMID (i.e., the VM the memory was mapped from), and a destination VMID (i.e., the VM the memory was mapped to). In addition, the caller must provide the source GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory that was mapped from the source), and the destination GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory to unmap from the destination). Finally, the caller must provide the flags associated with how memory should be unmapped (if applicable). If the provided ranges do not match previously mapped ranges, this hypercall will fail.

If MV_GPA_FLAG_DONATE was set in the flags when the memory was originally mapped, this hypercall will fail. Once memory is donated, the only way for this memory to be returned to the root VM is to destroy the destination VM.

If MV_GPA_FLAG_DONATE was not set in the flags (the default), the map in the destination VM is removed. The source VM's map remains unchanged, even if the original call to mv_vm_state_op_map_mdl modified the source VM's memory type. The  mv_vm_op_gpa_set_flags hypercall can be used to modify the source VM's memory range after a call to mv_vm_state_op_unmap_mdl is made if needed.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The source VMID |
| REG2 | 63:12 | The source GPA of the MDL that describes the range to unmap |
| REG2 | 11:0 | REVZ |
| REG3 | 63:0 | The destination VMID |
| REG4 | 63:12 | The destination GPA of the MDL that describes the range to unmap |
| REG4 | 11:0 | REVZ |
| REG5 | 63:32 | The GPA flags used to determine how to unmap the range |
| REG5 | 31:0 | REVZ |

**const, mv_uint64_t: MV_VM_STATE_OP_UNMAP_MDL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000D | Defines the hypercall index for mv_vm_state_op_unmap_mdl |

```c
static inline mv_status_t
mv_vm_state_op_unmap_mdl(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa,                 /* IN */
    mv_uint64_t const flags)                   /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_unmap_mdl(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa, flags);
}
```

### 4.5.15. mv_vm_state_op_copy_mdl, OP=0x3, IDX=0xE

This hypercall is used to copy a range of physically discontiguous memory from one VM to another. Unless shared memory is required, this hypercall should be used instead of mv_vm_state_op_map_range as it does not change the memory map of either the source or the destination VM. The caller must provide the source VMID (i.e., the VM to copy memory from), and a destination VMID (i.e., the VM to copy memory to). In addition, the caller must provide the source GPA (i.e., the GPA of the range of memory to copy memory from), and the destination GPA (i.e., the GPA of the range of memory to copy memory to). Finally, the caller must provide the number of 4k pages in the range to copy.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The source VMID |
| REG2 | 63:12 | The source GPA of the range to copy from |
| REG2 | 11:0 | REVZ |
| REG3 | 63:0 | The destination VMID |
| REG4 | 63:12 | The destination GPA of the range to copy to |
| REG4 | 11:0 | REVZ |

**const, mv_uint64_t: MV_VM_STATE_OP_COPY_MDL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000E | Defines the hypercall index for mv_vm_state_op_copy_mdl |

```c
static inline mv_status_t
mv_vm_state_op_copy_mdl(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const src_vmid,                /* IN */
    mv_uint64_t const src_gpa,                 /* IN */
    mv_uint64_t const dst_vmid,                /* IN */
    mv_uint64_t const dst_gpa)                 /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_state_op_copy_mdl(
               handle->hndl, src_vmid, src_gpa, dst_vmid, dst_gpa);
}
```

### 4.5.16. mv_vm_state_op_gpa_flags, OP=0x3, IDX=0xF

This hypercall is used get the GPA flags of a GPA given the VMID associated with this GPA. This can be used to determine how a GPA is mapped including it's access permissions, memory type and page size.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID of the GPA flags to get |
| REG2 | 63:12 | The GPA of the flags to get |
| REG2 | 11:0 | REVZ |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:32 | The resulting GPA flags |

**const, mv_uint64_t: MV_VM_STATE_OP_GPA_FLAGS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000F | Defines the hypercall index for mv_vm_state_op_gpa_flags |

```c
mv_status_t
mv_vm_state_op_gpa_flags(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const gpa,                     /* IN */
    mv_uint64_t *const flags);                 /* OUT */
```

### 4.5.17. mv_vm_state_op_set_gpa_flags, OP=0x3, IDX=0x10

This hypercall is used set the GPA flags of a GPA given the VMID associated with this GPA and the flags to set. The GPA flags that are supported by this hypercall is implementation defined. Also note that the flags being set apply to the entire GPA. For example, if the provided GPA points to a 2M GPA to SPA mapping, the flags being set will apply to the entire 2M.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID of the GPA flags to set |
| REG2 | 63:12 | The GPA of the flags to set |
| REG2 | 11:0 | REVZ |
| REG3 | 63:32 | The flags to set the GPA flags to |

**const, mv_uint64_t: MV_VM_STATE_OP_SET_GPA_FLAGS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000010 | Defines the hypercall index for mv_vm_state_op_set_gpa_flags |

```c
mv_status_t
mv_vm_state_op_set_gpa_flags(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t const gpa,                     /* IN */
    mv_uint64_t const flags);                  /* IN */
```

## 4.6. Virtual Machine Management

### 4.6.1. mv_vm_management_op_create_vm, OP=0x4, IDX=0x0

This hypercall is used to create a new VM. The only VM that is allowed to execute this hypercall is the root VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The vmid of the newly created VM |

**const, mv_uint64_t: MV_VM_MANAGEMENT_OP_CREATE_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_vm_management_op_create_vm |

```c
static inline mv_status_t
mv_vm_management_op_create_vm(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t *const vmid)                   /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == vmid) {
        return MV_STATUS_INVALID_PARAMS1;
    }

    return _mv_vm_management_op_create_vm(handle->hndl, vmid);
}
```

### 4.6.2. mv_vm_management_op_destroy_vm, OP=0x4, IDX=0x1

This hypercall is used to destroy a previously created VM. The only VM that is allowed to execute this hypercall is the root VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vmid of the VM to destroy |

**const, mv_uint64_t: MV_VM_MANAGEMENT_OP_DESTROY_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_vm_management_op_destroy_vm |

```c
static inline mv_status_t
mv_vm_management_op_destroy_vm(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_management_op_destroy_vm(handle->hndl, vmid);
}
```

### 4.6.3. mv_vm_management_op_pause_vm, OP=0x4, IDX=0x2

This hypercall is used to ensure none of the VPs for a given VM are executing. The provided VMID cannot be MV_VMID_SELF.

If the VMID is for a guest VM, the hypervisor will trap to all of the physical cores/threads, and if a VP for the requested gueset VM was in the middle of executing one of the physical cores/threads, the VP will return back to the root VP that donated it's execution time. Once MicroV can ensure that all VPs for the requested VM have paused, this hypercall will return. While a guest VM is paused, calls to mv_vp_management_op_run_vp will result in mv_vp_exit_t_retry until a call to mv_vm_management_op_resume_vm is made.

If the VMID is the root VM (i.e., MV_VMID_ROOT), MicroV will pause all of the physical cores/threads (except for the physical core/thread making this hypercall) by spinning each core until mv_vm_management_op_resume_vm is called. Note that if the guest VM that makes a call to pause a root VM has more than one VP, its other VPs will not be able to execute while the root VM is paused.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vmid of the VM to pause |

**const, mv_uint64_t: MV_VM_MANAGEMENT_OP_PAUSE_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000002 | Defines the hypercall index for mv_vm_management_op_pause_vm |

```c
static inline mv_status_t
mv_vm_management_op_pause_vm(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_management_op_pause_vm(handle->hndl, vmid);
}
```

### 4.6.4. mv_vm_management_op_resume_vm, OP=0x4, IDX=0x3

This hypercall is resume any previously paused VPs given the VMID of the VM that owns the VPs.

If the VMID is for a guest VM, the VM will be premitted to execute again, and calls to mv_vp_management_op_run_vp will no longer result in mv_vp_exit_t_retry.

If the VMID is the root VM (i.e., MV_VMID_ROOT), MicroV will stop spinning the other physical cores/threads and allow the system to execute as normal.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vmid of the VM to pause |

**const, mv_uint64_t: MV_VM_MANAGEMENT_OP_RESUME_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000003 | Defines the hypercall index for mv_vm_management_op_resume_vm |

```c
static inline mv_status_t
mv_vm_management_op_resume_vm(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vm_management_op_resume_vm(handle->hndl, vmid);
}
```

## 4.7. Virtual Machine Key/Value Store

The following hypercalls provide a simple per-VM key/value store. Specifically, a VM creates a structure (defined by this specification) in it's own memory to store data/permissions and uses the open/close hypercalls to inform the hypervisor of where this information is located. Other VMs can then use the read/write functions to read/write from this store based on the provided permissions. All read/write operations are conducted using a memcpy by MicroV, ensuring the hypervisor can enforce permissions and provide sanity checks. All keys would be based on a GUID and VMID, allowing a one-to-many relationship for each GUID, ensuring GUIDs can be used for specific protocols and easily enforced by a policy engine similar to how IP works with the port/address model.

Unlike XenStore, each VM can have it's own store while allowing one VM (usually the root VM) to act as the "global store". Additionally, the interface to this store is through a set of hypercalls and memcpys, ensuring the hypervisor has a means to introspect all communications through its own policy engine. Finally, there is no notion of a "watch" or transaction support. This is a simple lockless DB whose code can be implemented in a header file and used in different systems as needed without the need for a bus, or complicated events.

### 4.7.1. mv_vm_kv_op_open, OP=0x5, IDX=0x0

TBD

### 4.7.2. mv_vm_kv_op_close, OP=0x5, IDX=0x1

TBD

### 4.7.3. mv_vm_kv_op_read_val, OP=0x5, IDX=0x2

TBD

### 4.7.4. mv_vm_kv_op_write_val, OP=05, IDX=0x3

TBD

### 4.7.5. mv_vm_kv_op_read_range, OP=0x5, IDX=0x4

TBD

### 4.7.6. mv_vm_kv_op_write_range, OP=05, IDX=0x5

TBD

### 4.7.7. mv_vm_kv_op_read_mdl, OP=0x5, IDX=0x6

TBD

### 4.7.8. mv_vm_kv_op_write_mdl, OP=05, IDX=0x7

TBD

### 4.7.9. mv_vm_kv_op_global_store, OP=0x5, IDX=0x8

TBD

### 4.7.10. mv_vm_kv_op_set_global_store, OP=05, IDX=0x9

TBD

# 5. Virtual Processor

A Virtual Processor or VP virtually represents a physical core/thread on the system. It is the "thing" that executes code. It contains a copy of the state stored on a physical core/thread called the Virtual Processor State or VPS. Each time a VP is scheduled for execution, it replaces the state on the physical core/thread with one of the VPSs it owns. Once the VP is done executing, the current state of the physical core/thread is saved back to the VPS in use, allowing another VP to execute as needed.

There are different types of VPs. The root VPs are created when MicroV is first started and one and only one root VP is created for every physical core/thread on the system. Root VPs are owned by the Root VM. MicroV does not provide the ability to create additional root VPs.

Any additional VPs that are created are called guest VPs which are owned and executed by the root VPs. Guest VPs cannot create additional guest VPs (meaning guest VPs must be created by a root VP). When a root VP executes a guest VP using the mv_vp_management_op_run_vp hypercall, it is said to be "donating" its execution time to the guest VP. This allows, for example, applications running in the root VM to execute guest VMs, whose time is billed to the application making the call to mv_vp_management_op_run_vp.

Unlike guest VMs who only have a single owning root VM, guest VPs can be owned by a single but different root VP at any given time. When a root VP executes a guest VP, the root VP becomes the parent VP and the guest VP becomes the child VP. During execution of a guest VP the parent/child relationship does not change. Once the guest VP's execution is complete the parent/child relationship is released and the scheduler is free to transfer ownership of a guest VP from one root VP to another. This transfer of ownership usually occurs during VP migration and is due to the fact that a guest VM is not required to have the same number of guest VPs compared to the number of root VPs which reflects the physical number of cores/threads on the system. As a result, the scheduler is free to move guest VPs to different root VPs as needed to optimize performance, resulting in a VP migration.

## 5.1. Virtual Processor Types

## 5.2. VPID

The Virtual Processor ID or VPID is a 64bit number that uniquely identifies a VP. The VPID given to a VP is determined by when the VP is created and therefore can change depending on the order of how each VP has been started since the last reboot of the hypervisor. Any VPID greater than or equal to 0xFFFFFFFF00000000 is reserved.

**const, mv_uint64_t: MV_VPID_SELF**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFF0 | Defines the VPID for SELF (i.e., the calling VP) |

**const, mv_uint64_t: MV_VPID_PARENT**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFF1 | Defines the VPID for PARENT (i.e., the calling VP's parent) |

**const, mv_uint64_t: MV_VPID_ANY**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFFF | Defines the VPID for ANY (i.e., any VP) |

## 5.3. Virtual Processor Properties

### 5.3.1. mv_vp_op_vpid, OP=0x6, IDX=0x0

This hypercall returns a VPID of the currently running VP.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting VPID |

**const, mv_uint64_t: MV_VP_OP_VPID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_vp_op_vpid |

```c
static inline mv_status_t
mv_vp_op_vpid(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t *const vpid)                   /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == vpid) {
        return MV_STATUS_INVALID_PARAMS1;
    }

    return _mv_vp_op_vpid(handle->hndl, vpid);
}
```

### 5.3.2. mv_vp_op_vmid, OP=0x6, IDX=0x2

TBD

### 5.3.3. mv_vp_op_uuid, OP=0x6, IDX=0x3

TBD

### 5.3.4. mv_vp_op_is_root_vp, OP=0x6, IDX=0x4

TBD

### 5.3.5. mv_vp_op_is_guest_vp, OP=0x6, IDX=0x5

TBD

### 5.3.6. mv_vp_op_state, OP=0x6, IDX=0x6

TBD

## 5.4. Virtual Processor State

### 5.4.1. mv_vp_state_op_reg_val, OP=0x7, IDX=0x0

This hypercall provides a means to read a VP's VPS (not including MSRs). Note that if the VP is currently executing, the value returned by this hypercall may not be accurate. Control of how a VP executes can be done by waiting for a VP Event, waiting for the VP to be swapped with another VP, or pausing a VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VPID to read the value from |
| REG2 | 63:0 | A mv_reg_t describing the register value requested |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value read from the VPS |

**const, mv_uint64_t: MV_VP_STATE_OP_REG_VAL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_vp_state_op_reg_val |

```c
static inline mv_status_t
mv_vp_state_op_reg_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint64_t const reg,                     /* IN */
    mv_uint64_t *const val)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == val) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vp_state_op_reg_val(handle->hndl, vpid, reg, val);
}
```

### 5.4.2. mv_vp_state_op_set_reg_val, OP=0x7, IDX=0x1

This hypercall provides a means to write to a VP's VPS (not including MSRs). Note that if the VP is currently executing, this hypercall will fail. Control of how a VP executes can be done by waiting for a VP Event, waiting for the VP to be swapped with another VP, or pausing a VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VPID to write the value to |
| REG2 | 63:0 | A mv_reg_t describing the register val requested |
| REG3 | 63:0 | The value to write to the VPS |

**const, mv_uint64_t: MV_VP_STATE_OP_SET_REG_VAL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_vp_state_op_set_reg_val |

```c
static inline mv_status_t
mv_vp_state_op_set_reg_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint64_t const reg,                     /* IN */
    mv_uint64_t const val)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_state_op_set_reg_val(handle->hndl, vpid, reg, val);
}
```

### 5.4.3. mv_vp_state_op_list_of_reg_vals, OP=0x7, IDX=0x2

TBD

### 5.4.4. mv_vp_state_op_set_list_of_reg_vals, OP=0x7, IDX=0x3

TBD

### 5.4.5. mv_vp_state_op_msr_val, OP=0x7, IDX=0x4

This hypercall provides a means to read a VP's VPS for MSRs. Note that if the VP is currently executing, the value returned by this hypercall may not be accurate. Control of how a VP executes can be done by waiting for a VP Event, waiting for the VP to be swapped with another VP, or pausing a VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VPID to read the VP state from |
| REG2 | 63:32 | REVZ |
| REG2 | 31:0 | The MSR to read from |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value read from the VPS |

**const, mv_uint64_t: MV_VP_STATE_OP_MSR_VAL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the hypercall index for mv_vp_state_op_msr_val |

```c
static inline mv_status_t
mv_vp_state_op_msr_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint32_t const msr,                     /* IN */
    mv_uint64_t *const val)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == val) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vp_state_op_msr_val(handle->hndl, vpid, msr, val);
}
```

### 5.4.6. mv_vp_state_op_set_msr_val, OP=0x7, IDX=0x5

This hypercall provides a means to write to a VP's VPS for MSRs. Note that if the VP is currently executing, this hypercall will fail. Control of how a VP executes can be done by waiting for a VP Event, waiting for the VP to be swapped with another VP, or pausing a VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VPID to write the VP state to |
| REG2 | 63:32 | REVZ |
| REG2 | 31:0 | The MSR to write to |
| REG3 | 63:0 | The value to write to the VPS |

**const, mv_uint64_t: MV_VP_STATE_OP_SET_MSR_VAL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the hypercall index for mv_vp_state_op_set_msr_val |

```c
static inline mv_status_t
mv_vp_state_op_set_msr_val(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint32_t const msr,                     /* IN */
    mv_uint64_t const val)                     /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_state_op_set_msr_val(handle->hndl, vpid, msr, val);
}
```

### 5.4.7. mv_vp_state_op_list_of_msr_vals, OP=0x7, IDX=0x6

TBD

### 5.4.8. mv_vp_state_op_set_list_of_msr_vals, OP=0x7, IDX=0x7

TBD

### 5.4.9. mv_vp_state_op_hve_val, OP=0x7, IDX=0x8

TBD - get VMCS/VMCS guest and read-only val

### 5.4.10. mv_vp_state_op_set_hve_val, OP=0x7, IDX=0x9

TBD - set VMCS/VMCS guest and read-only val

### 5.4.11. mv_vp_state_op_list_of_hve_vals, OP=0x7, IDX=0xA

TBD

### 5.4.12. mv_vp_state_op_set_list_of_hve_vals, OP=0x7, IDX=0xB

TBD

### 5.4.13. mv_vp_state_op_xsave_val, OP=0x7, IDX=0xC

TBD - get xsave

### 5.4.14. mv_vp_state_op_set_xsave_val, OP=0x7, IDX=0xD

TBD - set xsave

## 5.5. Virtual Processor Management

### 5.5.1. mv_vp_management_op_create_vp, OP=0x8, IDX=0x0

This hypercall is used to create a new VP. The only VM that is allowed to execute this hypercall is the root VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The VMID of the VM to receive the new VP |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The vpid of the newly created VP |

**const, mv_uint64_t: MV_VP_MANAGEMENT_OP_CREATE_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_vp_management_op_create_vp |

```c
static inline mv_status_t
mv_vp_management_op_create_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vmid,                    /* IN */
    mv_uint64_t *const vpid)                   /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == vpid) {
        return MV_STATUS_INVALID_PARAMS2;
    }

    return _mv_vp_management_op_create_vp(handle->hndl, vmid, vpid);
}
```

### 5.5.2. mv_vp_management_op_destroy_vp, OP=0x8, IDX=0x1

This hypercall is used to destroy a previously created VP. The only VM that is allowed to execute this hypercall is the root VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vpid of the VP to destroy |

**const, mv_uint64_t: MV_VP_MANAGEMENT_OP_DESTROY_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_vp_management_op_destroy_vp |

```c
static inline mv_status_t
mv_vp_management_op_destroy_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_management_op_destroy_vp(handle->hndl, vpid);
}
```

### 5.5.3. mv_vp_management_op_run_vp, OP=0x8, IDX=0x2

This hypercall is used to run a guest VP. The only VM that is allowed to execute this hypercall is the root VM. When a VP is run (which is always by a root VP), the root VP "donates" it's execution time to the provided guest VP. Execution will be returned to the root VP on any number of events, but usually, this occurs when an interrupt fires that the guest VP is not meant to handle.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vpid of a guest VP to run |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The reason for the return (i.e., mv_vp_exit_t) |
| REG1 | 63:0 | An output argument (depends on the return reason) |

**const, mv_uint64_t: MV_VP_MANAGEMENT_OP_RUN_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the hypercall index for mv_vp_management_op_run_vp |

When mv_vp_management_op_run_vp returns, a return reason is provided which are defiined as follows

**enum, mv_uint32_t: mv_vp_exit_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| mv_vp_exit_t_external_interrupt | 0 | The VP stopped execution due to an external interrupt |
| mv_vp_exit_t_yield | 1 | The VP stopped execution due to a yeild, meaning it has nothing to do and needs to wait.  |
| mv_vp_exit_t_retry | 2 | The VP stopped execution asking to be run again. Its possible that a future attempt to run the VP might return mv_vp_exit_t_retry again |
| mv_vp_exit_t_hlt | 3 | The VP stopped execution due to a hlt, meaning it is done executing and can be destroyed |
| mv_vp_exit_t_fault | 4 | The VP stopped execution due to a fault, meaning an error condition occurred and the VP can no longer execute |
| mv_vp_exit_t_sync_tsc | 5 | The VP stopped execution to ask for the wallclock/tsc to be synchronized |
| mv_vp_exit_t_suspend | 6 | The VP stopped execution to tell software that the system is trying to suspend |
| mv_vp_exit_t_max | 7 | The max value for mv_vp_exit_t |

If mv_vp_exit_t_external_interrupt is returned, software should execute mv_vp_management_op_run_vp again as soon as possible. If mv_vp_exit_t_yield is returned, software should run mv_vp_management_op_run_vp again after sleeping for REG1 number of nanoseconds. If mv_vp_exit_t_retry is returned, software should execute mv_vp_management_op_run_vp again after yielding to the OS. Software could also use a backoff model, adding a sleep whose time increases as mv_vp_management_op_run_vp continues to return mv_vp_exit_t_retry. REG1 can be used to determine the uniqueness of mv_vp_exit_t_retry. mv_vp_exit_t_hlt tells software to destroy the VP and that software finished without any errors while mv_vp_exit_t_fault tells software to destroy the VP and that an error actually occured with the error code being returned in REG1. mv_vp_exit_t_sync_tsc tells software that it needs to synchronize the the wallclock and TSC.

```c
static inline mv_status_t
mv_vp_management_op_run_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid,                    /* IN */
    mv_uint64_t *const reason,                 /* OUT */
    mv_uint64_t *const arg)                    /* OUT */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    if (MV_NULL == reason) {
        return MV_STATUS_INVALID_PARAMS2;
    }

    if (MV_NULL == arg) {
        return MV_STATUS_INVALID_PARAMS3;
    }

    return _mv_vp_management_op_run_vp(handle->hndl, vpid, reason, arg);
}
```

### 5.5.4. mv_vp_management_op_kill_vp, OP=0x8, IDX=0x3

This hypercall is used to destroy a previously created VP. The only VM that is allowed to execute this hypercall is the root VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vpid of the VP to destroy |

**const, mv_uint64_t: MV_VP_MANAGEMENT_OP_KILL_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the hypercall index for mv_vp_management_op_kill_vp |

```c
static inline mv_status_t
mv_vp_management_op_pause_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_management_op_pause_vp(handle->hndl, vpid);
}
```

### 5.5.5. mv_vp_management_op_pause_vp, OP=0x4, IDX=0x4

This hypercall is used to ensure a VP is not executing. The provided VPID cannot be MV_VPID_SELF.

If the VPID is for a guest VP, the hypervisor will trap to all of the physical cores/threads, and if a VP for the requested gueset VP was in the middle of executing one of the physical cores/threads, the VP will return back to the root VP that donated it's execution time. Once MicroV can ensure that the requested VP has been paused, this hypercall will return. While a guest VP is paused, calls to mv_vp_management_op_run_vp will result in mv_vp_exit_t_retry until a call to mv_vp_management_op_resume_vp is made.

If the VPID is the root VP (i.e., MV_VPID_ROOT), MicroV will pause all of the physical cores/threads (except for the physical core/thread making this hypercall) by spinning each core until mv_vp_management_op_resume_vp is called. Note that if the guest VP that makes a call to pause a root VP has more than one VP, its other VPs will not be able to execute while the root VP is paused.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vpid of the VP to pause |

**const, mv_uint64_t: MV_VP_MANAGEMENT_OP_PAUSE_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000004 | Defines the hypercall index for mv_vp_management_op_pause_vp |

```c
static inline mv_status_t
mv_vp_management_op_pause_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_management_op_pause_vp(handle->hndl, vpid);
}
```

### 5.5.6. mv_vp_management_op_resume_vp, OP=0x4, IDX=0x5

This hypercall is resume any previously paused VP given a VPID.

If the VPID is for a guest VP, the VP will be premitted to execute again, and calls to mv_vp_management_op_run_vp will no longer result in mv_vp_exit_t_retry.

If the VPID is the root VP (i.e., MV_VPID_ROOT), MicroV will stop spinning the other physical cores/threads and allow the system to execute as normal.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 63:0 | The vpid of the VP to pause |

**const, mv_uint64_t: MV_VP_MANAGEMENT_OP_RESUME_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000005 | Defines the hypercall index for mv_vp_management_op_resume_vp |

```c
static inline mv_status_t
mv_vp_management_op_resume_vp(
    struct mv_handle_t const *const handle,    /* IN */
    mv_uint64_t const vpid)                    /* IN */
{
    if (MV_NULL == handle) {
        return MV_STATUS_INVALID_PARAMS0;
    }

    return _mv_vp_management_op_resume_vp(handle->hndl, vpid);
}
```

## 5.6. Virtual Processor Exits

TBD - Mimics VMX/SVM exits and will need a set of hypercalls to throw an event when a specific HVE event occurs.
