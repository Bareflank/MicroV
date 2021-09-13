## Table of Contents <!-- omit in toc -->

- [1. Introduction](#1-introduction)
  - [1.1. Reserved Values](#11-reserved-values)
  - [1.2. Document Revision](#12-document-revision)
  - [1.3. Glossary](#13-glossary)
  - [1.4. Constants, Structures, Enumerations and Bit Fields](#14-constants-structures-enumerations-and-bit-fields)
    - [1.4.1. Register Type](#141-register-type)
      - [1.4.1.1. Intel/AMD](#1411-intelamd)
    - [1.4.2. Register Type](#142-register-type)
    - [1.4.3. Register Descriptor Lists](#143-register-descriptor-lists)
    - [1.4.4. Memory Descriptor Lists](#144-memory-descriptor-lists)
    - [1.4.5. Map Flags](#145-map-flags)
  - [1.5. ID Constants](#15-id-constants)
  - [1.6. Endianness](#16-endianness)
  - [1.7. Physical Processor (PP)](#17-physical-processor-pp)
  - [1.8. Virtual Machine (VM)](#18-virtual-machine-vm)
  - [1.9. Virtual Processor (VP)](#19-virtual-processor-vp)
  - [1.10. Virtual Processor State (VS)](#110-virtual-processor-state-vs)
- [2. Hypercall Interface](#2-hypercall-interface)
  - [2.1. Legal Hypercall Environments](#21-legal-hypercall-environments)
  - [2.2. Alignment Requirements](#22-alignment-requirements)
  - [2.3. Hypercall Status Codes](#23-hypercall-status-codes)
    - [2.3.1. MV_STATUS_SUCCESS, VALUE=0](#231-mv_status_success-value0)
    - [2.3.2. MV_STATUS_FAILURE, VALUE=1](#232-mv_status_failure-value1)
    - [2.3.3. MV_STATUS_INVALID_PERM, VALUE=2](#233-mv_status_invalid_perm-value2)
    - [2.3.4. MV_STATUS_INVALID_PARAMS, VALUE=3](#234-mv_status_invalid_params-value3)
    - [2.3.5. MV_STATUS_RETRY, VALUE=0x6](#235-mv_status_retry-value0x6)
    - [2.3.6. MV_STATUS_EXIT, VALUE=0x6](#236-mv_status_exit-value0x6)
  - [2.4. Hypercall Inputs](#24-hypercall-inputs)
  - [2.5. Hypercall Outputs](#25-hypercall-outputs)
  - [2.6. Hypercall Opcodes](#26-hypercall-opcodes)
    - [2.6.1. ID Support](#261-id-support)
    - [2.6.2. Handle Support](#262-handle-support)
    - [2.6.3. Debug Support](#263-debug-support)
    - [2.6.4. Physical Processors](#264-physical-processors)
    - [2.6.5. Virtual Machines](#265-virtual-machines)
    - [2.6.6. Virtual Processors](#266-virtual-processors)
    - [2.6.7. Virtual Processor State](#267-virtual-processor-state)
  - [2.7. Hypercall Specification IDs](#27-hypercall-specification-ids)
  - [2.8. Hypercall Continuation](#28-hypercall-continuation)
  - [2.9. ID Hypercalls](#29-id-hypercalls)
    - [2.9.1. mv_id_op_version, OP=0x0, IDX=0x0](#291-mv_id_op_version-op0x0-idx0x0)
    - [2.9.2. mv_id_op_get_capability, OP=0x0, IDX=0x1](#292-mv_id_op_get_capability-op0x0-idx0x1)
    - [2.9.3. mv_id_op_clr_capability, OP=0x0, IDX=0x2](#293-mv_id_op_clr_capability-op0x0-idx0x2)
    - [2.9.4. mv_id_op_set_capability, OP=0x0, IDX=0x3](#294-mv_id_op_set_capability-op0x0-idx0x3)
    - [2.9.5. mv_id_op_has_capability, OP=0x0, IDX=0x4](#295-mv_id_op_has_capability-op0x0-idx0x4)
  - [2.10. Handle Hypercalls](#210-handle-hypercalls)
    - [2.10.1. mv_handle_op_open_handle, OP=0x1, IDX=0x0](#2101-mv_handle_op_open_handle-op0x1-idx0x0)
    - [2.10.2. mv_handle_op_close_handle, OP=0x1, IDX=0x1](#2102-mv_handle_op_close_handle-op0x1-idx0x1)
  - [2.11. Debug Hypercalls](#211-debug-hypercalls)
    - [2.11.1. mv_debug_op_out, OP=0x2, IDX=0x0](#2111-mv_debug_op_out-op0x2-idx0x0)
  - [2.12. Physical Processor Hypercalls](#212-physical-processor-hypercalls)
    - [2.12.1. mv_pp_op_ppid, OP=0x3, IDX=0x0](#2121-mv_pp_op_ppid-op0x3-idx0x0)
    - [2.12.2. mv_pp_op_clr_shared_page_gpa, OP=0x3, IDX=0x1](#2122-mv_pp_op_clr_shared_page_gpa-op0x3-idx0x1)
    - [2.12.3. mv_pp_op_set_shared_page_gpa, OP=0x3, IDX=0x2](#2123-mv_pp_op_set_shared_page_gpa-op0x3-idx0x2)
    - [2.12.4. mv_pp_op_cpuid_get_supported, OP=0x3, IDX=0x3](#2124-mv_pp_op_cpuid_get_supported-op0x3-idx0x3)
    - [2.12.5. mv_pp_op_cpuid_get_permissable, OP=0x3, IDX=0x4](#2125-mv_pp_op_cpuid_get_permissable-op0x3-idx0x4)
    - [2.12.6. mv_pp_op_cpuid_get_emulated, OP=0x3, IDX=0x5](#2126-mv_pp_op_cpuid_get_emulated-op0x3-idx0x5)
    - [2.12.7. mv_pp_op_reg_get_supported, OP=0x3, IDX=0x6](#2127-mv_pp_op_reg_get_supported-op0x3-idx0x6)
    - [2.12.8. mv_pp_op_reg_get_permissable, OP=0x3, IDX=0x7](#2128-mv_pp_op_reg_get_permissable-op0x3-idx0x7)
    - [2.12.9. mv_pp_op_reg_get_emulated, OP=0x3, IDX=0x8](#2129-mv_pp_op_reg_get_emulated-op0x3-idx0x8)
    - [2.12.10. mv_pp_op_msr_get_supported, OP=0x3, IDX=0x9](#21210-mv_pp_op_msr_get_supported-op0x3-idx0x9)
    - [2.12.11. mv_pp_op_msr_get_permissable, OP=0x3, IDX=0xA](#21211-mv_pp_op_msr_get_permissable-op0x3-idx0xa)
    - [2.12.12. mv_pp_op_msr_get_emulated, OP=0x3, IDX=0xB](#21212-mv_pp_op_msr_get_emulated-op0x3-idx0xb)
    - [2.12.13. mv_pp_op_tsc_get_khz, OP=0x3, IDX=0xC](#21213-mv_pp_op_tsc_get_khz-op0x3-idx0xc)
    - [2.12.14. mv_pp_op_tsc_set_khz, OP=0x3, IDX=0xD](#21214-mv_pp_op_tsc_set_khz-op0x3-idx0xd)
  - [2.13. Virtual Machine Hypercalls](#213-virtual-machine-hypercalls)
    - [2.13.1. mv_vm_op_create_vm, OP=0x4, IDX=0x0](#2131-mv_vm_op_create_vm-op0x4-idx0x0)
    - [2.13.2. mv_vm_op_destroy_vm, OP=0x4, IDX=0x1](#2132-mv_vm_op_destroy_vm-op0x4-idx0x1)
    - [2.13.3. mv_vm_op_vmid, OP=0x4, IDX=0x2](#2133-mv_vm_op_vmid-op0x4-idx0x2)
    - [2.13.4. mv_vm_op_io_clr_trap, OP=0x4, IDX=0x3](#2134-mv_vm_op_io_clr_trap-op0x4-idx0x3)
    - [2.13.5. mv_vm_op_io_set_trap, OP=0x4, IDX=0x4](#2135-mv_vm_op_io_set_trap-op0x4-idx0x4)
    - [2.13.6. mv_vm_op_io_clr_trap_all, OP=0x4, IDX=0x5](#2136-mv_vm_op_io_clr_trap_all-op0x4-idx0x5)
    - [2.13.7. mv_vm_op_io_set_trap_all, OP=0x4, IDX=0x6](#2137-mv_vm_op_io_set_trap_all-op0x4-idx0x6)
    - [2.13.8. mv_vm_op_mmio_map, OP=0x4, IDX=0x7](#2138-mv_vm_op_mmio_map-op0x4-idx0x7)
    - [2.13.9. mv_vm_op_mmio_unmap, OP=0x4, IDX=0x8](#2139-mv_vm_op_mmio_unmap-op0x4-idx0x8)
    - [2.13.10. mv_vm_op_mmio_clr_trap, OP=0x4, IDX=0x9](#21310-mv_vm_op_mmio_clr_trap-op0x4-idx0x9)
    - [2.13.11. mv_vm_op_mmio_set_trap, OP=0x4, IDX=0xA](#21311-mv_vm_op_mmio_set_trap-op0x4-idx0xa)
    - [2.13.12. mv_vm_op_mmio_clr_trap_all, OP=0x4, IDX=0xB](#21312-mv_vm_op_mmio_clr_trap_all-op0x4-idx0xb)
    - [2.13.13. mv_vm_op_mmio_set_trap_all, OP=0x4, IDX=0xC](#21313-mv_vm_op_mmio_set_trap_all-op0x4-idx0xc)
    - [2.13.14. mv_vm_op_msr_clr_trap, OP=0x4, IDX=0xD](#21314-mv_vm_op_msr_clr_trap-op0x4-idx0xd)
    - [2.13.15. mv_vm_op_msr_set_trap, OP=0x4, IDX=0xE](#21315-mv_vm_op_msr_set_trap-op0x4-idx0xe)
    - [2.13.16. mv_vm_op_msr_clr_trap_all, OP=0x4, IDX=0xF](#21316-mv_vm_op_msr_clr_trap_all-op0x4-idx0xf)
    - [2.13.17. mv_vm_op_msr_set_trap_all, OP=0x4, IDX=0x10](#21317-mv_vm_op_msr_set_trap_all-op0x4-idx0x10)
  - [2.14. Virtual Processor Hypercalls](#214-virtual-processor-hypercalls)
    - [2.14.1. mv_vp_op_create_vp, OP=0x5, IDX=0x0](#2141-mv_vp_op_create_vp-op0x5-idx0x0)
    - [2.14.2. mv_vp_op_destroy_vp, OP=0x5, IDX=0x1](#2142-mv_vp_op_destroy_vp-op0x5-idx0x1)
    - [2.14.3. mv_vp_op_vmid, OP=0x5, IDX=0x2](#2143-mv_vp_op_vmid-op0x5-idx0x2)
    - [2.14.4. mv_vp_op_vpid, OP=0x5, IDX=0x3](#2144-mv_vp_op_vpid-op0x5-idx0x3)
  - [2.15. Virtual Processor State Hypercalls](#215-virtual-processor-state-hypercalls)
    - [2.15.1. mv_vs_op_create_vs, OP=0x6, IDX=0x0](#2151-mv_vs_op_create_vs-op0x6-idx0x0)
    - [2.15.2. mv_vs_op_destroy_vs, OP=0x6, IDX=0x1](#2152-mv_vs_op_destroy_vs-op0x6-idx0x1)
    - [2.15.3. mv_vs_op_vmid, OP=0x6, IDX=0x2](#2153-mv_vs_op_vmid-op0x6-idx0x2)
    - [2.15.4. mv_vs_op_vpid, OP=0x6, IDX=0x3](#2154-mv_vs_op_vpid-op0x6-idx0x3)
    - [2.15.5. mv_vs_op_vsid, OP=0x6, IDX=0x4](#2155-mv_vs_op_vsid-op0x6-idx0x4)
    - [2.15.6. mv_vs_op_gva_to_gla, OP=0x6, IDX=0x5](#2156-mv_vs_op_gva_to_gla-op0x6-idx0x5)
    - [2.15.7. mv_vs_op_gla_to_gpa, OP=0x6, IDX=0x6](#2157-mv_vs_op_gla_to_gpa-op0x6-idx0x6)
    - [2.15.8. mv_vs_op_gva_to_gpa, OP=0x6, IDX=0x7](#2158-mv_vs_op_gva_to_gpa-op0x6-idx0x7)
    - [2.15.9. mv_vs_op_run, OP=0x6, IDX=0x8](#2159-mv_vs_op_run-op0x6-idx0x8)
      - [2.15.9.1. mv_exit_reason_t_failure](#21591-mv_exit_reason_t_failure)
      - [2.15.9.2. mv_exit_reason_t_unknown](#21592-mv_exit_reason_t_unknown)
      - [2.15.9.3. mv_exit_reason_t_hlt](#21593-mv_exit_reason_t_hlt)
      - [2.15.9.4. mv_exit_reason_t_io](#21594-mv_exit_reason_t_io)
      - [2.15.9.5. mv_exit_reason_t_mmio](#21595-mv_exit_reason_t_mmio)
    - [2.15.10. mv_vs_op_cpuid_get, OP=0x6, IDX=0x9](#21510-mv_vs_op_cpuid_get-op0x6-idx0x9)
    - [2.15.11. mv_vs_op_cpuid_set, OP=0x6, IDX=0xA](#21511-mv_vs_op_cpuid_set-op0x6-idx0xa)
    - [2.15.12. mv_vs_op_cpuid_get_list, OP=0x6, IDX=0xB](#21512-mv_vs_op_cpuid_get_list-op0x6-idx0xb)
    - [2.15.13. mv_vs_op_cpuid_set_list, OP=0x6, IDX=0xC](#21513-mv_vs_op_cpuid_set_list-op0x6-idx0xc)
    - [2.15.14. mv_vs_op_reg_get, OP=0x6, IDX=0xD](#21514-mv_vs_op_reg_get-op0x6-idx0xd)
    - [2.15.15. mv_vs_op_reg_set, OP=0x6, IDX=0xE](#21515-mv_vs_op_reg_set-op0x6-idx0xe)
    - [2.15.16. mv_vs_op_reg_get_list, OP=0x6, IDX=0xF](#21516-mv_vs_op_reg_get_list-op0x6-idx0xf)
    - [2.15.17. mv_vs_op_reg_set_list, OP=0x6, IDX=0x10](#21517-mv_vs_op_reg_set_list-op0x6-idx0x10)
    - [2.15.18. mv_vs_op_msr_get, OP=0x6, IDX=0x17](#21518-mv_vs_op_msr_get-op0x6-idx0x17)
    - [2.15.19. mv_vs_op_msr_set, OP=0x6, IDX=0x18](#21519-mv_vs_op_msr_set-op0x6-idx0x18)
    - [2.15.20. mv_vs_op_msr_get_list, OP=0x6, IDX=0x19](#21520-mv_vs_op_msr_get_list-op0x6-idx0x19)
    - [2.15.21. mv_vs_op_msr_set_list, OP=0x6, IDX=0x1A](#21521-mv_vs_op_msr_set_list-op0x6-idx0x1a)
    - [2.15.22. mv_vs_op_fpu_get, OP=0x6, IDX=0x1B](#21522-mv_vs_op_fpu_get-op0x6-idx0x1b)
    - [2.15.23. mv_vs_op_fpu_set, OP=0x6, IDX=0x1C](#21523-mv_vs_op_fpu_set-op0x6-idx0x1c)
    - [2.15.24. mv_vs_op_fpu_get_all, OP=0x6, IDX=0x1D](#21524-mv_vs_op_fpu_get_all-op0x6-idx0x1d)
    - [2.15.25. mv_vs_op_fpu_set_all, OP=0x6, IDX=0x1E](#21525-mv_vs_op_fpu_set_all-op0x6-idx0x1e)
    - [2.15.26. mv_vs_op_xsave_get, OP=0x6, IDX=0x1F](#21526-mv_vs_op_xsave_get-op0x6-idx0x1f)
    - [2.15.27. mv_vs_op_xsave_set, OP=0x6, IDX=0x20](#21527-mv_vs_op_xsave_set-op0x6-idx0x20)
    - [2.15.28. mv_vs_op_xsave_get_all, OP=0x6, IDX=0x21](#21528-mv_vs_op_xsave_get_all-op0x6-idx0x21)
    - [2.15.29. mv_vs_op_xsave_set_all, OP=0x6, IDX=0x22](#21529-mv_vs_op_xsave_set_all-op0x6-idx0x22)
    - [2.15.30. mv_vs_op_mp_state_get, OP=0x6, IDX=0x23](#21530-mv_vs_op_mp_state_get-op0x6-idx0x23)
    - [2.15.31. mv_vs_op_mp_state_set, OP=0x6, IDX=0x24](#21531-mv_vs_op_mp_state_set-op0x6-idx0x24)
    - [2.15.32. mv_vs_op_interrupt, OP=0x6, IDX=0x23](#21532-mv_vs_op_interrupt-op0x6-idx0x23)

# 1. Introduction

This specification defines the ABI between VM software and the MicroV hypervisor (including both root VMs and guest VMs). This includes the use of CPUID and Hypercalls. This specification does not define the ABI between the MicroV Microkernel and MicroV Extensions. Please see the Microkernel Syscall Specification for more information on the ABI supported by the MicroV Microkernel for writing custom hypervisor extensions. This specification also does not define the ABI for any support drivers like the MicroV Loader or the MicroV KVM Shim Driver. Please see the their specifications for more information.

This specification is specific to 64bit Intel and AMD processors conforming to the amd64 specification. Future revisions of this specification may include ARM64, RISC-V and PowerPC.

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
| PP | Physical Processor |
| VM | Virtual Machine |
| VP | Virtual Processor |
| VS | Virtual Processor State |
| PPID | Physical Processor Identifier |
| VMID | Virtual Machine Identifier |
| VPID | Virtual Processor Identifier |
| VSID | Virtual Processor State Identifier |
| SSID | Segment Selector Identifier |
| OS | Operating System |
| BIOS | Basic Input/Output System |
| UEFI | Unified Extensible Firmware Interface |
| Root VM | The first VM created when MicroV is launched. The OS/BIOS/UEFI that is running when MicroV is launch is placed in the Root VM. Sometimes this is called Dom0 or the Root Partition |
| Guest VM | Any additional VM created by MicroV. Sometimes called a DomU or Guest Partition |
| Root VP | A virtual processor assigned to the root VM |
| Guest VP | A virtual processor assigned to a guest VM |
| Root VS | A virtual processor state assigned to a root VP |
| Guest VS | A virtual processor state assigned to a guest VP |
| Parent VS | The VS that was active prior to mv_vs_op_run being called (if they are different) |
| Child VS | The VS that was made active by the call to mv_vs_op_run (if they are different) |
| SPA | A System Physical Address (SPA) refers to a physical address as seen by the system without paging, second level paging or segmentation |
| GPA | A Guest Physical Address (GPA) refers to a physical address as seen by a VM. For the Root VM, most GPA == SPA. For a Guest VM, converting from a GPA to an SPA required translating second level paging structures |
| GLA | A Guest Linear Address (GLA) refers to a linear address as seen by a VM. GLAs require guest paging structures to convert from a GLA to a GPA  |
| GVA | A Guest Virtual Address (GVA) refers to a virtual address as seen by a VM. GVAs require guest segmentation to convert from a GVA to a GLA. On architectures that do not support segmentation, a GVA is a GLA |
| Page Aligned | A region of memory whose address is divisible by 0x1000 |
| Page | A page aligned region of memory that is 0x1000 bytes in size |
| Host | Refers to the hypervisor. For MicroV, this consists of both the Bareflank Microkernel and the MicroV extension. Referred to VMX root or Ring -1 on Intel |
| Guest | Refers to software running under the control of the Host. Referred to as VMX non-root on Intel |

## 1.4. Constants, Structures, Enumerations and Bit Fields

### 1.4.1. Register Type

Defines which register a hypercall is requesting.

#### 1.4.1.1. Intel/AMD

**enum, int32_t: mv_reg_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| mv_reg_t_rax | 1 | defines the rax register |
| mv_reg_t_rbx | 2 | defines the rbx register |
| mv_reg_t_rcx | 3 | defines the rcx register |
| mv_reg_t_rdx | 4 | defines the rdx register |
| mv_reg_t_rbp | 5 | defines the rbp register |
| mv_reg_t_rsi | 6 | defines the rsi register |
| mv_reg_t_rdi | 7 | defines the rdi register |
| mv_reg_t_r8 | 8 | defines the r8 register |
| mv_reg_t_r9 | 9 | defines the r9 register |
| mv_reg_t_r10 | 10 | defines the r10 register |
| mv_reg_t_r11 | 11 | defines the r11 register |
| mv_reg_t_r12 | 12 | defines the r12 register |
| mv_reg_t_r13 | 13 | defines the r13 register |
| mv_reg_t_r14 | 14 | defines the r14 register |
| mv_reg_t_r15 | 15 | defines the r15 register |
| mv_reg_t_rsp | 16 | defines the rsp register |
| mv_reg_t_rip | 17 | defines the rip register |
| mv_reg_t_rflags | 18 | defines the rflags register |
| mv_reg_t_es_selector | 19 | defines the es_selector register |
| mv_reg_t_es_attrib | 20 | defines the es_attrib register |
| mv_reg_t_es_limit | 21 | defines the es_limit register |
| mv_reg_t_es_base | 22 | defines the es_base register |
| mv_reg_t_cs_selector | 23 | defines the cs_selector register |
| mv_reg_t_cs_attrib | 24 | defines the cs_attrib register |
| mv_reg_t_cs_limit | 25 | defines the cs_limit register |
| mv_reg_t_cs_base | 26 | defines the cs_base register |
| mv_reg_t_ss_selector | 27 | defines the ss_selector register |
| mv_reg_t_ss_attrib | 28 | defines the ss_attrib register |
| mv_reg_t_ss_limit | 29 | defines the ss_limit register |
| mv_reg_t_ss_base | 30 | defines the ss_base register |
| mv_reg_t_ds_selector | 31 | defines the ds_selector register |
| mv_reg_t_ds_attrib | 32 | defines the ds_attrib register |
| mv_reg_t_ds_limit | 33 | defines the ds_limit register |
| mv_reg_t_ds_base | 34 | defines the ds_base register |
| mv_reg_t_fs_selector | 35 | defines the fs_selector register |
| mv_reg_t_fs_attrib | 36 | defines the fs_attrib register |
| mv_reg_t_fs_limit | 37 | defines the fs_limit register |
| mv_reg_t_fs_base | 38 | defines the fs_base register |
| mv_reg_t_gs_selector | 39 | defines the gs_selector register |
| mv_reg_t_gs_attrib | 40 | defines the gs_attrib register |
| mv_reg_t_gs_limit | 41 | defines the gs_limit register |
| mv_reg_t_gs_base | 42 | defines the gs_base register |
| mv_reg_t_ldtr_selector | 43 | defines the ldtr_selector register |
| mv_reg_t_ldtr_attrib | 44 | defines the ldtr_attrib register |
| mv_reg_t_ldtr_limit | 45 | defines the ldtr_limit register |
| mv_reg_t_ldtr_base | 46 | defines the ldtr_base register |
| mv_reg_t_tr_selector | 47 | defines the tr_selector register |
| mv_reg_t_tr_attrib | 48 | defines the tr_attrib register |
| mv_reg_t_tr_limit | 49 | defines the tr_limit register |
| mv_reg_t_tr_base | 50 | defines the tr_base register |
| mv_reg_t_gdtr_selector | 51 | defines the gdtr_selector register |
| mv_reg_t_gdtr_attrib | 52 | defines the gdtr_attrib register |
| mv_reg_t_gdtr_limit | 53 | defines the gdtr_limit register |
| mv_reg_t_gdtr_base | 54 | defines the gdtr_base register |
| mv_reg_t_idtr_selector | 55 | defines the idtr_selector register |
| mv_reg_t_idtr_attrib | 56 | defines the idtr_attrib register |
| mv_reg_t_idtr_limit | 57 | defines the idtr_limit register |
| mv_reg_t_idtr_base | 58 | defines the idtr_base register |
| mv_reg_t_dr0 | 59 | defines the dr0 register |
| mv_reg_t_dr1 | 60 | defines the dr1 register |
| mv_reg_t_dr2 | 61 | defines the dr2 register |
| mv_reg_t_dr3 | 62 | defines the dr3 register |
| mv_reg_t_dr6 | 63 | defines the dr6 register |
| mv_reg_t_dr7 | 64 | defines the dr7 register |
| mv_reg_t_cr0 | 65 | defines the cr0 register |
| mv_reg_t_cr2 | 66 | defines the cr2 register |
| mv_reg_t_cr3 | 67 | defines the cr3 register |
| mv_reg_t_cr4 | 68 | defines the cr4 register |
| mv_reg_t_cr8 | 69 | defines the cr8 register |
| mv_reg_t_xcr0 | 70 | defines the xcr0 register (Intel Only) |

### 1.4.2. Register Type

Defines different bit sizes for address, operands, etc.

**enum, int32_t: mv_bit_size_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| mv_bit_size_t_8 | 0 | indicates 8 bits |
| mv_bit_size_t_16 | 1 | indicates 16 bits |
| mv_bit_size_t_32 | 2 | indicates 32 bits |
| mv_bit_size_t_64 | 3 | indicates 64 bits |

### 1.4.3. Register Descriptor Lists

A register descriptor list (RDL) describes a list of registers that either need to be read or written. Each RDL consists of a list of entries with each entry describing one register to read/write. Like all structures used in this ABI, the RDL must be placed inside the shared page. Not all registers require 64 bits for either the register index or the value itself. In all cases, unused bits are considered REVI. The meaning of the register and value fields is ABI dependent. For some ABIs, the reg field refers to a mv_reg_t while in other cases it refers to an architecture specific register like MSRs on x86 which have it's index type. The value field for some ABIs is the value read or the value to be written to the requested register. In other cases, it is a boolean, enum or bit field describing attributes about the register such as whether the register is supported, emulated or permissable. Registers 0-7 in the mv_rdl_t are NOT entries, but instead input/output registers for the ABIs that need additional input and output registers. If any of these registers is not used by a specific ABI, it is REVI.

**const, uint64_t: MV_RDL_MAX_ENTRIES**
| Value | Description |
| :---- | :---------- |
| 250 | Defines the max number of entires in the RDL |

**struct: mv_rdl_entry_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| reg | uint64_t | 0x0 | 8 bytes | An mv_reg_t or MSR index |
| val | uint64_t | 0x8 | 8 bytes | The value read or to be written |

The format of the RDL as follows:

**struct: mv_rdl_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| reg0 | uint64_t | 0x0 | 8 bytes | ABI dependent. REVI if unused |
| reg1 | uint64_t | 0x8 | 8 bytes | ABI dependent. REVI if unused |
| reg2 | uint64_t | 0x10 | 8 bytes | ABI dependent. REVI if unused |
| reg3 | uint64_t | 0x18 | 8 bytes | ABI dependent. REVI if unused |
| reg4 | uint64_t | 0x20 | 8 bytes | ABI dependent. REVI if unused |
| reg5 | uint64_t | 0x28 | 8 bytes | ABI dependent. REVI if unused |
| reg6 | uint64_t | 0x30 | 8 bytes | ABI dependent. REVI if unused |
| reg7 | uint64_t | 0x38 | 8 bytes | ABI dependent. REVI if unused |
| reserved1 | uint64_t | 0x40 | 8 bytes | REVI |
| reserved2 | uint64_t | 0x48 | 8 bytes | REVI |
| reserved3 | uint64_t | 0x50 | 8 bytes | REVI |
| num_entries | uint64_t | 0x58 | 8 bytes | The number of entries in the RDL |
| entries | mv_rdl_entry_t[MV_RDL_MAX_ENTRIES] | 0x60 | ABI dependent | Each entry in the RDL |

### 1.4.4. Memory Descriptor Lists

A memory descriptor list (MDL) describes a discontiguous region of guest physical memory. Each MDL consists of a list of entries with each entry describing one contiguous region of guest physical memory. By combining multiple entries into a list, software is capable of describing both contiguous and discontiguous regions of guest physical memory. Like all structures used in this ABI, the MDL must be placed inside the shared page. The meaning of the dst and src fields is ABI dependent. Both the dst and src fields could be GVAs, GLAs or GPAs (virtual, linear or physical). The bytes field describes the total number of bytes in the contiguous memory region. For some ABIs, this field must be page aligned. The flags field is also ABI dependent. For example, for map hypercalls, this field refers to map flags. Registers 0-7 in the mv_mdl_t are NOT entries, but instead input/output registers for the ABIs that need additional input and output registers. If any of these registers is not used by a specific ABI, it is REVI.

**const, uint64_t: MV_MDL_MAX_ENTRIES**
| Value | Description |
| :---- | :---------- |
| 125 | Defines the max number of entires in the MDL |

**struct: mv_mdl_entry_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| dst | uint64_t | 0x0 | 8 bytes | The GPA to map the memory to |
| src | uint64_t | 0x8 | 8 bytes | The GPA to map the memory from |
| bytes | uint64_t | 0x8 | 8 bytes | The total number of bytes  |
| flags | uint64_t | 0x8 | 8 bytes | How to map dst to src |

The format of the MDL as follows:

**struct: mv_mdl_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| reg0 | uint64_t | 0x0 | 8 bytes | ABI dependent. REVI if unused |
| reg1 | uint64_t | 0x8 | 8 bytes | ABI dependent. REVI if unused |
| reg2 | uint64_t | 0x10 | 8 bytes | ABI dependent. REVI if unused |
| reg3 | uint64_t | 0x18 | 8 bytes | ABI dependent. REVI if unused |
| reg4 | uint64_t | 0x20 | 8 bytes | ABI dependent. REVI if unused |
| reg5 | uint64_t | 0x28 | 8 bytes | ABI dependent. REVI if unused |
| reg6 | uint64_t | 0x30 | 8 bytes | ABI dependent. REVI if unused |
| reg7 | uint64_t | 0x38 | 8 bytes | ABI dependent. REVI if unused |
| reserved1 | uint64_t | 0x40 | 8 bytes | REVI |
| reserved2 | uint64_t | 0x48 | 8 bytes | REVI |
| reserved3 | uint64_t | 0x50 | 8 bytes | REVI |
| num_entries | uint64_t | 0x58 | 8 bytes | The number of entries in the MDL |
| entries | mv_mdl_entry_t[MV_MDL_MAX_ENTRIES] | 0x60 | ABI dependent | Each entry in the MDL |

### 1.4.5. Map Flags

The map flags are used by some of the hypercalls as both inputs to a hypercall as well as outputs from a hypercall to provide information about how a memory is or should be mapped.

| Bit | Name | Description |
| :-- | :--- | :---------- |
|  0 | MV_MAP_FLAG_READ_ACCESS | Indicates the map has read access |
|  1 | MV_MAP_FLAG_WRITE_ACCESS | Indicates the map has write access |
|  2 | MV_MAP_FLAG_EXECUTE_ACCESS | Indicates the map has execute access |
|  3 | MV_MAP_FLAG_USER | Indicates the map has user privileges  |
| 8:4 | revi | REVI |
|  9 | MV_MAP_FLAG_4K_PAGE | Indicates the map is 4k in size  |
| 10 | MV_MAP_FLAG_2M_PAGE | Indicates the map is 2m in size  |
| 11 | MV_MAP_FLAG_1G_PAGE | Indicates the map is 1g in size  |
| 56:12 | revi | REVI |
| 57 | MV_MAP_FLAG_UNCACHEABLE | Indicates the map is mapped as UC |
| 58 | MV_MAP_FLAG_UNCACHEABLE_MINUS | Indicates the map is mapped as UC- |
| 59 | MV_MAP_FLAG_WRITE_COMBINING | Indicates the map is mapped as WC |
| 60 | MV_MAP_FLAG_WRITE_COMBINING_PLUS | Indicates the map is mapped as WC+ |
| 61 | MV_MAP_FLAG_WRITE_THROUGH | Indicates the map is mapped as WT |
| 62 | MV_MAP_FLAG_WRITE_BACK | Indicates the map is mapped as WB |
| 63 | MV_MAP_FLAG_WRITE_PROTECTED | Indicates the map is mapped as WP |

## 1.5. ID Constants

The following defines some ID constants.

**const, uint16_t: MV_INVALID_ID**
| Value | Description |
| :---- | :---------- |
| 0xFFFF | Defines an invalid ID for an extension, VM, VP, VS and PP |

**const, uint16_t: MV_SELF_ID**
| Value | Description |
| :---- | :---------- |
| 0xFFFE | Defines the ID for "self" |

**const, uint16_t: MV_ALL_ID**
| Value | Description |
| :---- | :---------- |
| 0xFFFD | Defines the ID for "all" |

**const, uint16_t: MV_BS_PPID**
| Value | Description |
| :---- | :---------- |
| 0x0 | Defines the bootstrap physical processor ID |

**const, uint16_t: MV_ROOT_VMID**
| Value | Description |
| :---- | :---------- |
| 0x0 | Defines the root virtual machine ID |

## 1.6. Endianness

This document only applies to 64bit Intel and AMD systems conforming to the amd64 architecture. As such, this document is limited to little endian.

## 1.7. Physical Processor (PP)

TBD

## 1.8. Virtual Machine (VM)

A Virtual Machine or VM virtually represents a physical computer and stores the resources that are shared between one or more Virtual Processors called the Virtual Machine State or VMS. MicroV is capable of executing multiple VMs simultaneously on the same physical machine. In some configurations these VMs might share the same physical cores/threads and in other configurations, each VM is given dedicated access to one or more physical cores/threads, and either share the rest of hardware, or the rest of hardware is divided up between VMs using something like an IOMMU (or some combination of the two).

There are different types of VMs. The root VM is the initial VM created by the MicroV Microkernel and executes whatever operating system was executing at the time MicroV was started. In some configurations (early boot), MicroV is started from BIOS/UEFI and demotes BIOS/UEFI into the root VM. From there, BIOS/UEFI might boot an additional operating system such as Windows or Linux inside the root VM. In other configurations (late launch), an operating system such as Windows or Linux has already booted and MicroV is started some time later. In this configuration MicroV demotes the current operating system into the root VM and executes from there.

The early boot configuration of MicroV provides better security as well as early access to memory resources reducing fragmentation and increasing the efficiency of the overall system (reduces shattering of large pages). The late launch configuration of MicroV is easier to develop for.

All additional VMs that are created from the root VM are called guest VMs. Guest VMs are not capable of creating additional guest VMs (VMs can only be created by the root VM). That is, MicroV uses a breath of many, depth of one approach.

## 1.9. Virtual Processor (VP)

A Virtual Processor or VP virtually represents a physical core/thread on the system. It is the "thing" that is scheduled to execute code and contains one or more Virtual Processor States or VSs that store the actual state of the VP and execute the actual code on behalf of a VP. Each time a VP is scheduled for execution, it replaces the state on the physical core/thread with one of the VSs it owns. Once the VP is done executing, the current state of the physical core/thread is saved back to the VS in use, allowing another VP to execute as needed.

There are different types of VPs. The root VPs are created when MicroV is first started and one and only one root VP is created for every physical core/thread on the system. Root VPs are owned by the Root VM. MicroV does not provide the ability to create additional root VPs.

Any additional VPs that are created are called guest VPs which are owned and executed by the root VPs. Guest VPs cannot create additional guest VPs (meaning guest VPs must be created by a root VP). When a root VP executes a guest VP using the mv_vp_run_vp hypercall, it is said to be "donating" its execution time to the guest VP. This allows, for example, applications running in the root VM to execute guest VMs, whose time is billed to the application making the call to mv_vp_run_vp.

Unlike guest VMs who only have a single owning root VM, guest VPs can be owned by a single but different root VP at any given time. When a root VP executes a guest VP, the root VP becomes the parent VP and the guest VP becomes the child VP. During execution of a guest VP the parent/child relationship does not change. Once the guest VP's execution is complete the parent/child relationship is released and the scheduler is free to transfer ownership of a guest VP from one root VP to another. This transfer of ownership usually occurs during VP migration and is due to the fact that a guest VM is not required to have the same number of guest VPs compared to the number of root VPs which reflects the physical number of cores/threads on the system. As a result, the scheduler is free to move guest VPs to different root VPs as needed to optimize performance, resulting in a VP migration.

## 1.10. Virtual Processor State (VS)

TBD

# 2. Hypercall Interface

The following section defines the hypercall interface used by this specification, and therefore MicroV.

## 2.1. Legal Hypercall Environments

The kernel and userspace can execute hypercalls from 64bit mode. 32bit mode is currently not supported.

## 2.2. Alignment Requirements

Most GPAs are required to be page aligned. When this occurs, the hypercall documentation will state that bits 11:0 are REVZ. If this is not documented, software can safely assume that the lower 12 bits of the GPA are valid and can be provided.

If a hypercall must provide input/output larger than what is supported from a register only hypercall, a structure will be used instead. When this occurs, software must place the structure in a page (that is page aligned) at offset 0 of the page, providing the GPA of the page as input. Hypercalls that accept more than one page use the MDL format listed above.

## 2.3. Hypercall Status Codes

Every hypercall returns a mv_status_t to indicate the success or failure of a hypercall after execution. The following defines the layout of mv_status_t:

**uint64_t: mv_status_t**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:48 | MV_STATUS_SIG | Contains 0x0000 on success, 0xDEAD on failure |
| 47:16 | MV_STATUS_FLAGS | Contains the flags associated with the mv_status_t |
| 15:0 | MV_STATUS_VALUE | Contains the value of the mv_status_t |

MV_STATUS_VALUE defines success or which type of error occurred. MV_STATUS_FLAGS provides additional information about why the error occurred.

### 2.3.1. MV_STATUS_SUCCESS, VALUE=0

**const, mv_status_t: MV_STATUS_SUCCESS**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Indicates the hypercall returned successfully |

### 2.3.2. MV_STATUS_FAILURE, VALUE=1

**const, mv_status_t: MV_STATUS_FAILURE_UNKNOWN**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010001 | Indicates an unknown error occurred |

**const, mv_status_t: MV_STATUS_FAILURE_UNSUPPORTED**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020001 | Indicates the hypercall is unsupported |

**const, mv_status_t: MV_STATUS_FAILURE_INVALID_HANDLE**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000040001 | Indicates the provided handle is invalid |

### 2.3.3. MV_STATUS_INVALID_PERM, VALUE=2

**const, mv_status_t: MV_STATUS_INVALID_PERM_DENIED**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010002 | Indicates the policy engine denied the hypercall |

### 2.3.4. MV_STATUS_INVALID_PARAMS, VALUE=3

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG0**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010003 | Indicates input reg0 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG1**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020003 | Indicates input reg1 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG2**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000040003 | Indicates input reg2 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_INPUT_REG3**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000080003 | Indicates input reg3 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG0**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000100003 | Indicates output reg0 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG1**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000200003 | Indicates output reg1 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG2**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000400003 | Indicates output reg2 is invalid |

**const, mv_status_t: MV_STATUS_INVALID_OUTPUT_REG3**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000800003 | Indicates output reg3 is invalid |

### 2.3.5. MV_STATUS_RETRY, VALUE=0x6

**const, mv_status_t: MV_STATUS_RETRY_CONTINUATION**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000100004 | Indicates software should execute the hypercall again |

**const, mv_status_t: MV_STATUS_RETRY_CONTINUATION_SCC**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000200004 | Indicates software should execute the hypercall again when it is ready |

### 2.3.6. MV_STATUS_EXIT, VALUE=0x6

**const, mv_status_t: MV_STATUS_EXIT_FAILURE**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010005 | Indicates that mv_exit_failure_t contains more info |

**const, mv_status_t: MV_STATUS_EXIT_UNKNOWN**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020005 | Indicates that mv_exit_unknown_t contains more info |

## 2.4. Hypercall Inputs

Before software can execute a hypercall, it must first open a handle to the hypercall interface by executing the mv_handle_op_open_handle hypercall. This handle must be provided as the first argument to each hypercall in R10 (i.e., REG0) and can be released using the mv_handle_op_close_handle hypercall.

**R10: REG_HANDLE**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:0 | MV_HANDLE | The result of mv_handle_op_open_handle |

Every hypercall must provide information about the hypercall by filling out RAX as follows:

**RAX: REG_HYPERCALL**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:48 | MV_HYPERCALL_SIG | 0x764D = "Mv" |
| 47:32 | MV_HYPERCALL_FLAGS | Contains the hypercall's flags |
| 31:16 | MV_HYPERCALL_OP | Contains the hypercall's opcode |
| 15:0 | MV_HYPERCALL_IDX | Contains the hypercall's index |

**const, uint64_t: MV_HYPERCALL_SIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000000000 | Defines the MV_HYPERCALL_SIG field for RAX |

**const, uint64_t: MV_HYPERCALL_SIG_MASK**
| Value | Description |
| :---- | :---------- |
| 0xFFFF000000000000 | Defines a mask for MV_HYPERCALL_SIG |

**const, uint64_t: MV_HYPERCALL_FLAGS_MASK**
| Value | Description |
| :---- | :---------- |
| 0x0000FFFF00000000 | Defines a mask for MV_HYPERCALL_FLAGS |

**const, uint64_t: MV_HYPERCALL_OPCODE_MASK**
| Value | Description |
| :---- | :---------- |
| 0xFFFF0000FFFF0000 | Defines a mask for MV_HYPERCALL_OP |

**const, uint64_t: MV_HYPERCALL_OPCODE_NOSIG_MASK**
| Value | Description |
| :---- | :---------- |
| 0x00000000FFFF0000 | Defines a mask for MV_HYPERCALL_OP (with no signature added) |

**const, uint64_t: MV_HYPERCALL_INDEX_MASK**
| Value | Description |
| :---- | :---------- |
| 0x000000000000FFFF | Defines a mask for MV_HYPERCALL_IDX |

MV_HYPERCALL_SIG is used to ensure the hypercall is, in fact, a MicroV specific hypercall. MV_HYPERCALL_FLAGS is used to provide additional hypercall options.

MV_HYPERCALL_OP determines which opcode the hypercall belongs to, logically grouping hypercalls based on their function. MV_HYPERCALL_OP is also used internally within MicroV to dispatch the hypercall to the proper handler. MV_HYPERCALL_IDX, when combined with MV_HYPERCALL_OP, uniquely identifies a specific hypercall. This specification tightly packs the values assigned to both MV_HYPERCALL_IDX and MV_HYPERCALL_OP to ensure MicroV (and variants) can use jump tables instead of branch logic.

The following defines the input registers for x64 based systems (i.e., x86_64 and amd64):

**Arguments:**
| Register Name | Description |
| :------------ | :---------- |
| R10 | Set to the result of mv_handle_op_open_handle |
| R11 | Stores the value of REG1 (hypercall specific) |
| R12 | Stores the value of REG2 (hypercall specific) |
| R13 | Stores the value of REG3 (hypercall specific) |

All unused registers by any hypercall are considered REVI.

**const, uint64_t: MV_HYPERCALL_FLAGS_SCC**
| Value | Description |
| :---- | :---------- |
| 0x0000000100000000 | Defines the software controlled continuation flag |

## 2.5. Hypercall Outputs

After executing a hypercall, a mv_status_t is returned in RAX to indicate if the hypercall succeeded or failed and why.

**RAX: REG_RETURN**
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

## 2.6. Hypercall Opcodes

The following sections define the different opcodes that are supported by this specification. Note that each opcode includes the hypercall signature making it easier to validate if the hypercall is supported or not.

### 2.6.1. ID Support

**const, uint64_t: MV_ID_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000000000 | Defines the hypercall opcode for mv_id_op hypercalls |

**const, uint64_t: MV_ID_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall opcode for mv_id_op hypercalls with no signature |

### 2.6.2. Handle Support

**const, uint64_t: MV_HANDLE_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000010000 | Defines the hypercall opcode for mv_handle_op hypercalls |

**const, uint64_t: MV_HANDLE_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000010000 | Defines the hypercall opcode for mv_handle_op hypercalls with no signature |

### 2.6.3. Debug Support

**const, uint64_t: MV_DEBUG_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000020000 | Defines the hypercall opcode for mv_debug_op hypercalls |

**const, uint64_t: MV_DEBUG_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000020000 | Defines the hypercall opcode for mv_debug_op hypercalls with no signature |

### 2.6.4. Physical Processors

**const, uint64_t: MV_PP_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000030000 | Defines the hypercall opcode for mv_pp_op hypercalls |

**const, uint64_t: MV_PP_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000030000 | Defines the hypercall opcode for mv_pp_op hypercalls with no signature |

### 2.6.5. Virtual Machines

**const, uint64_t: MV_VM_OP**
| Value | Description |
| :---- | :---------- |
| 0x764D000000040000 | Defines the hypercall opcode for mv_vm_op hypercalls |

**const, uint64_t: MV_VM_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000040000 | Defines the hypercall opcode for mv_vm_op hypercalls with no signature |

### 2.6.6. Virtual Processors

**const, uint64_t: MV_VP_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000050000 | Defines the hypercall opcode for mv_vp_op hypercalls |

**const, uint64_t: MV_VP_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000050000 | Defines the hypercall opcode for mv_vp_op hypercalls with no signature |

### 2.6.7. Virtual Processor State

**const, uint64_t: MV_VS_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000060000 | Defines the hypercall opcode for mv_vs_op hypercalls |

**const, uint64_t: MV_VS_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000060000 | Defines the hypercall opcode for mv_vs_op hypercalls with no signature |

## 2.7. Hypercall Specification IDs

The following defines the specification IDs used when opening a handle. These provide software with a means to define which specification it implements. mv_id_op_version returns which version of this spec MicroV supports. For example, if the returned version is 0x2, it means that it supports version #1 of this spec, in which case, an extension can open a handle with MV_SPEC_ID1_VAL. If the returned version is 0x6, it would mean that an extension could open a handle with MV_SPEC_ID1_VAL or MV_SPEC_ID2_VAL. Likewise, if the returned version is 0x4, it means that MV_SPEC_ID1_VAL is no longer supported, and the extension must open the handle with MV_SPEC_ID2_VAL.

**const, uint32_t: MV_SPEC_ID1_VAL**
| Value | Description |
| :---- | :---------- |
| 0x3123764D | Defines the ID for version #1 of this spec |

**const, uint32_t: MV_SPEC_ID1_MASK**
| Value | Description |
| :---- | :---------- |
| 0x2 | Defines the mask for checking support for version #1 of this spec |

**const, uint32_t: MV_ALL_SPECS_SUPPORTED_VAL**
| Value | Description |
| :---- | :---------- |
| 0x2 | Defines all versions supported |

**const, uint32_t: MV_INVALID_VERSION**
| Value | Description |
| :---- | :---------- |
| 0x80000000 | Defines an invalid version |

## 2.8. Hypercall Continuation

Some hypercalls might take a long time to execute. Since MicroV does not service interrupts, interrupts are disabled while a hypercall is being processed. If a hypercall takes to long, this can have adverse effects on software if interrupts need to perform work while the hypercall is attempting to process.

To prevent this from occurring, long running hypercalls resume software periodically without advancing the instruction pointer. When this is done, MicroV will return MV_STATUS_RETRY_CONTINUATION from the hypercall. This forces the hypercall to be executed again, allowing MicroV to resume its execution.

In some cases, software might want more control on how a continuation is handled. For example, if software needs to perform additional actions above and beyond servicing interrupts. To support this, the MV_HYPERCALL_FLAGS_SCC flag can be set, telling MicroV to advance the instruction pointer and return MV_STATUS_RETRY_CONTINUATION_SCC, indicating to software that a continuation is required and software should retry the hypercall when it is ready.

If MV_STATUS_RETRY_CONTINUATION is returned, software must immediately execute the previous hypercall with the same inputs. Providing different inputs is undefined and may lead to corruption or an error. No other hypercalls are allowed to be called until the hypercall that needs a continuation has completed. Attempting to do so is undefined and may lead to corruption or an error.

If MV_STATUS_RETRY_CONTINUATION_SCC is returned, software is free to execute whatever hypercalls it wants. MicroV will store the inputs associated with the hypercall that needs the continuation. If this same hypercall is made with the same inputs, MicroV will perform the continuation. If the same hypercall is made with different inputs, MicroV will either cancel the previous hypercall and execute the new one, or return an error. Support for cancellations is ABI specific, including how any previously committed state is handled.

Continuations can occur more than once. Continuations can also be mixed. For example, if the MV_HYPERCALL_FLAGS_SCC flag is set, MicroV has the right to return MV_STATUS_RETRY_CONTINUATION, meaning MicroV is not obligated to support this flag, even between continuations. This is needed because in some cases, long running hypercalls might contain moments where MV_STATUS_RETRY_CONTINUATION_SCC can be supported, and moments where it cannot. It is up to MicroV to decide.

## 2.9. ID Hypercalls

### 2.9.1. mv_id_op_version, OP=0x0, IDX=0x0

This hypercall tells MicroV to return the version of the spec that it supports.

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Returns which versions of the spec MicroV supports |

**const, uint64_t: MV_ID_OP_VERSION_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for mv_id_op_version |

### 2.9.2. mv_id_op_get_capability, OP=0x0, IDX=0x1

TBD

**const, uint64_t: MV_ID_OP_GET_CAPABILITY_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for mv_id_op_get_capability |

### 2.9.3. mv_id_op_clr_capability, OP=0x0, IDX=0x2

TBD

**const, uint64_t: MV_ID_OP_CLR_CAPABILITY_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for mv_id_op_clr_capability |

### 2.9.4. mv_id_op_set_capability, OP=0x0, IDX=0x3

TBD

**const, uint64_t: MV_ID_OP_SET_CAPABILITY_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for mv_id_op_set_capability |

### 2.9.5. mv_id_op_has_capability, OP=0x0, IDX=0x4

Returns MV_STATUS_SUCCESS if the capability is supported. Returns MV_STATUS_FAILURE_UNSUPPORTED if the capability is not supported.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The capability to query |

**const, uint64_t: MV_ID_OP_HAS_CAPABILITY_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the index for mv_id_op_has_capability |

## 2.10. Handle Hypercalls

### 2.10.1. mv_handle_op_open_handle, OP=0x1, IDX=0x0

This hypercall returns the handle that is required to execute the remaining hypercalls.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 31:0 | The version of this spec that software supports |
| REG0 | 63:32 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value to set REG0 to for most other hypercalls |

**const, uint64_t: MV_HANDLE_OP_OPEN_HANDLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for mv_handle_op_open_handle |

**const, uint64_t: MV_INVALID_HANDLE**
| Value | Description |
| :---- | :---------- |
| 0xFFFFFFFFFFFFFFFF | Defines an invalid handle |

### 2.10.2. mv_handle_op_close_handle, OP=0x1, IDX=0x1

This hypercall closes a previously opened handle.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**const, uint64_t: MV_HANDLE_OP_CLOSE_HANDLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for mv_handle_op_close_handle |

## 2.11. Debug Hypercalls

### 2.11.1. mv_debug_op_out, OP=0x2, IDX=0x0

This hypercall tells MicroV to output reg0 and reg1 to the console device MicroV is currently using for debugging. The purpose of this hypercall is to provide a simple means for debugging issues with the guest and can be used by a VM from both userspace and the kernel, even when the operating system is not fully bootstrapped or is in a failure state.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The first value to output to MicroV's console |
| REG1 | 63:0 | The second value to output to MicroV's console |

**const, uint64_t: MV_DEBUG_OP_OUT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for mv_debug_op_out |

## 2.12. Physical Processor Hypercalls

TBD

### 2.12.1. mv_pp_op_ppid, OP=0x3, IDX=0x0

This hypercall returns the ID of the PP that executed this hypercall.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting PPID |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_PP_OP_PPID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for mv_pp_op_ppid |

### 2.12.2. mv_pp_op_clr_shared_page_gpa, OP=0x3, IDX=0x1

This hypercall tells MicroV to clear the GPA of the current PP's shared page.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**const, uint64_t: MV_PP_OP_CLR_SHARED_PAGE_GPA_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for mv_pp_op_clr_shared_page_gpa |

### 2.12.3. mv_pp_op_set_shared_page_gpa, OP=0x3, IDX=0x2

This hypercall tells MicroV to set the GPA of the current PP's shared page.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 11:0 | REVZ |
| REG1 | 63:12 | The GPA to set the requested PP's shared page to |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |

**const, uint64_t: MV_PP_OP_SET_SHARED_PAGE_GPA_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for mv_pp_op_set_shared_page_gpa |

### 2.12.4. mv_pp_op_cpuid_get_supported, OP=0x3, IDX=0x3

TBD

**const, uint64_t: MV_PP_OP_CPUID_GET_SUPPORTED_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for mv_pp_op_cpuid_get_supported |

### 2.12.5. mv_pp_op_cpuid_get_permissable, OP=0x3, IDX=0x4

TBD

**const, uint64_t: MV_PP_OP_CPUID_GET_PERMISSABLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the index for mv_pp_op_cpuid_get_permissable |

### 2.12.6. mv_pp_op_cpuid_get_emulated, OP=0x3, IDX=0x5

TBD

**const, uint64_t: MV_PP_OP_CPUID_GET_EMULATED_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the index for mv_pp_op_cpuid_get_emulated |

### 2.12.7. mv_pp_op_reg_get_supported, OP=0x3, IDX=0x6

TBD

**const, uint64_t: MV_PP_OP_REG_GET_SUPPORTED_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the index for mv_pp_op_reg_get_supported |

### 2.12.8. mv_pp_op_reg_get_permissable, OP=0x3, IDX=0x7

TBD

**const, uint64_t: MV_PP_OP_REG_GET_PERMISSABLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the index for mv_pp_op_reg_get_permissable |

### 2.12.9. mv_pp_op_reg_get_emulated, OP=0x3, IDX=0x8

TBD

**const, uint64_t: MV_PP_OP_REG_GET_EMULATED_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the index for mv_pp_op_reg_get_emulated |

### 2.12.10. mv_pp_op_msr_get_supported, OP=0x3, IDX=0x9

TBD

**const, uint64_t: MV_PP_OP_MSR_GET_SUPPORTED_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the index for mv_pp_op_msr_get_supported |

### 2.12.11. mv_pp_op_msr_get_permissable, OP=0x3, IDX=0xA

TBD

**const, uint64_t: MV_PP_OP_MSR_GET_PERMISSABLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000A | Defines the index for mv_pp_op_msr_get_permissable |

### 2.12.12. mv_pp_op_msr_get_emulated, OP=0x3, IDX=0xB

TBD

**const, uint64_t: MV_PP_OP_MSR_GET_EMULATED_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000B | Defines the index for mv_pp_op_msr_get_emulated |

### 2.12.13. mv_pp_op_tsc_get_khz, OP=0x3, IDX=0xC

TBD

**const, uint64_t: MV_PP_OP_TSC_GET_KHZ_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000C | Defines the index for mv_pp_op_tsc_get_khz |

### 2.12.14. mv_pp_op_tsc_set_khz, OP=0x3, IDX=0xD

TBD

**const, uint64_t: MV_PP_OP_TSC_SET_KHZ_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000D | Defines the index for mv_pp_op_tsc_set_khz |

## 2.13. Virtual Machine Hypercalls

TBD

### 2.13.1. mv_vm_op_create_vm, OP=0x4, IDX=0x0

This hypercall tells MicroV to create a VM and return its ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting ID of the newly created VM |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_CREATE_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for mv_vm_op_create_vm |

### 2.13.2. mv_vm_op_destroy_vm, OP=0x4, IDX=0x1

This hypercall tells MicroV to destroy a VM given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_DESTROY_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for mv_vm_op_destroy_vm |

### 2.13.3. mv_vm_op_vmid, OP=0x4, IDX=0x2

This hypercall returns the ID of the VM that executed this hypercall.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting ID |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_VMID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for mv_vm_op_vmid |

### 2.13.4. mv_vm_op_io_clr_trap, OP=0x4, IDX=0x3

TBD

**const, uint64_t: MV_VM_OP_IO_CLR_TRAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for mv_vm_op_io_clr_trap |

### 2.13.5. mv_vm_op_io_set_trap, OP=0x4, IDX=0x4

TBD

**const, uint64_t: MV_VM_OP_IO_SET_TRAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the index for mv_vm_op_io_set_trap |

### 2.13.6. mv_vm_op_io_clr_trap_all, OP=0x4, IDX=0x5

TBD

**const, uint64_t: MV_VM_OP_IO_CLR_TRAP_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the index for mv_vm_op_io_clr_trap_all |

### 2.13.7. mv_vm_op_io_set_trap_all, OP=0x4, IDX=0x6

TBD

**const, uint64_t: MV_VM_OP_IO_SET_TRAP_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the index for mv_vm_op_io_set_trap_all |

### 2.13.8. mv_vm_op_mmio_map, OP=0x4, IDX=0x7

This hypercall is used to map a range of physically discontiguous guest memory from one VM to another using a Memory Descriptor List (MDL) in the shared page. For this ABI, the dst field in the mv_mdl_entry_t refers to the GPA to map the contiguous memory region described by the entry to. The src field in the mv_mdl_entry_t refers to the GPA to map the contiguous memory region from. The dst and src VMIDs must be different. If the src VMID is not MV_ROOT_VMID, the map is considered a foreign map and is currently not supported (although will be in the future to support device domains). The bytes field in the mv_mdl_entry_t must be page aligned and cannot be 0. The flags field in the mv_mdl_entry_t refers to Map Flags and only apply to the destination (meaning source mappings are not affected by this hypercall). The only flags that are supported by this hypercall are the access/permission flags and the capability flags. Of these flags, MicroV may reject the use of certain flags based on MicroV's configuration and which CPU architecture is in use. mv_id_op_get_capability can be used to determine which specific flags are supported by MicroV. Care should be taken to ensure that both the dst and src memory is mapped with the same cacheability. In general, the safest option is to map MV_MAP_FLAG_WRITE_BACK from the src to MV_MAP_FLAG_WRITE_BACK in the dst. This ABI does not use any of the reg 0-7 fields in the mv_mdl_t. Double maps (i.e., mapping memory that is already mapped) is undefined and may result in MicroV returning an error.

**Warning:**<br>
This hypercall is slow and may require a Hypercall Continuation. See Hypercall Continuations for more information.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the dst VM to map memory to |
| REG1 | 63:16 | REVI |
| REG2 | 15:0 | The ID of the src VM to map memory from |
| REG2 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_MMIO_MAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the index for mv_vm_op_mmio_map |

### 2.13.9. mv_vm_op_mmio_unmap, OP=0x4, IDX=0x8

This hypercall is used to unmap a range of physically discontiguous guest memory from a VM. For this ABI, the dst field in the mv_mdl_entry_t refers to the GPA of the contiguous memory region to unmap. The src field is ignored. The bytes field in the mv_mdl_entry_t must be page aligned and cannot be 0. The flags field is ignored. This ABI does not use any of the reg 0-7 fields in the mv_mdl_t. Double unmaps (i.e., unmapping memory that is already unmapped) is undefined and may result in MicroV returning an error. To ensure the unmap is seen by the processor, this hypercall performs a TLB invalidation of all of the memory described in the MDL. MicroV reserves the right to invalidate the entire TLB and cache if needed. If a VM has more than one VP, this hypercall may perform a remote TLB invalidation. How remote TLB invalidations are performed by MicroV is undefined and left to MicroV to determine.

**Warning:**<br>
This hypercall is slow and may require a Hypercall Continuation. See Hypercall Continuations for more information.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to unmap memory from |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_MMIO_UNMAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the index for mv_vm_op_mmio_unmap |

### 2.13.10. mv_vm_op_mmio_clr_trap, OP=0x4, IDX=0x9

TBD

**const, uint64_t: MV_VM_OP_MMIO_CLR_TRAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the index for mv_vm_op_mmio_clr_trap |

### 2.13.11. mv_vm_op_mmio_set_trap, OP=0x4, IDX=0xA

TBD

**const, uint64_t: MV_VM_OP_MMIO_SET_TRAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000A | Defines the index for mv_vm_op_mmio_set_trap |

### 2.13.12. mv_vm_op_mmio_clr_trap_all, OP=0x4, IDX=0xB

TBD

**const, uint64_t: MV_VM_OP_MMIO_CLR_TRAP_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000B | Defines the index for mv_vm_op_mmio_clr_trap_all |

### 2.13.13. mv_vm_op_mmio_set_trap_all, OP=0x4, IDX=0xC

TBD

**const, uint64_t: MV_VM_OP_MMIO_SET_TRAP_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000C | Defines the index for mv_vm_op_mmio_set_trap_all |

### 2.13.14. mv_vm_op_msr_clr_trap, OP=0x4, IDX=0xD

TBD

**const, uint64_t: MV_VM_OP_MSR_CLR_TRAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000D | Defines the index for mv_vm_op_msr_clr_trap |

### 2.13.15. mv_vm_op_msr_set_trap, OP=0x4, IDX=0xE

TBD

**const, uint64_t: MV_VM_OP_MSR_SET_TRAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000E | Defines the index for mv_vm_op_msr_set_trap |

### 2.13.16. mv_vm_op_msr_clr_trap_all, OP=0x4, IDX=0xF

TBD

**const, uint64_t: MV_VM_OP_MSR_CLR_TRAP_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000F | Defines the index for mv_vm_op_msr_clr_trap_all |

### 2.13.17. mv_vm_op_msr_set_trap_all, OP=0x4, IDX=0x10

TBD

**const, uint64_t: MV_VM_OP_MSR_SET_TRAP_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000010 | Defines the index for mv_vm_op_msr_set_trap_all |

## 2.14. Virtual Processor Hypercalls

TBD

### 2.14.1. mv_vp_op_create_vp, OP=0x5, IDX=0x0

This hypercall tells MicroV to create a VP given the ID of the VM the VP will be assigned to. Upon success, this hypercall returns the ID of the newly created VP.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to assign the newly created VP to |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VPID of the newly created VP |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VP_OP_CREATE_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for mv_vp_op_create_vp |

### 2.14.2. mv_vp_op_destroy_vp, OP=0x5, IDX=0x1

This hypercall tells MicroV to destroy a VP given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VP to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VP_OP_DESTROY_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for mv_vp_op_destroy_vp |

### 2.14.3. mv_vp_op_vmid, OP=0x5, IDX=0x2

This hypercall returns the ID of the VM the requested VP is assigned to.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VP to query |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting ID |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VP_OP_VMID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for mv_vp_op_vmid |

### 2.14.4. mv_vp_op_vpid, OP=0x5, IDX=0x3

This hypercall returns the ID of the VP that executed this hypercall.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VPID |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VP_OP_VPID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for mv_vp_op_vpid |


## 2.15. Virtual Processor State Hypercalls

TBD

### 2.15.1. mv_vs_op_create_vs, OP=0x6, IDX=0x0

This hypercall tells MicroV to create a VS given the ID of the VP the VS will be assigned to. Upon success, this hypercall returns the ID of the newly created VS.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VP to assign the newly created VS to |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VSID of the newly created VS |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_CREATE_VS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the index for mv_vs_op_create_vs |

### 2.15.2. mv_vs_op_destroy_vs, OP=0x6, IDX=0x1

This hypercall tells MicroV to destroy a VS given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_DESTROY_VS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the index for mv_vs_op_destroy_vs |

### 2.15.3. mv_vs_op_vmid, OP=0x6, IDX=0x2

This hypercall returns the ID of the VM the requested VS is assigned to.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to query |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting ID |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_VMID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the index for mv_vs_op_vmid |

### 2.15.4. mv_vs_op_vpid, OP=0x6, IDX=0x3

This hypercall returns the ID of the VP the requested VS is assigned to.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to query |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting ID |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_VPID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the index for mv_vs_op_vpid |

### 2.15.5. mv_vs_op_vsid, OP=0x6, IDX=0x4

This hypercall returns the ID of the VS that executed this hypercall.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting ID |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_VSID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the index for mv_vs_op_vsid |

### 2.15.6. mv_vs_op_gva_to_gla, OP=0x6, IDX=0x5

Reserved

This is reserved but not supported in this version of the MicroV spec.
This hypercall tells MicroV to translate the provided guest virtual address (GVA) to a guest linear address (GLA). To perform this translation, MicroV will use the current state of CR0, CR4, EFER, the GDT and the segment registers. To perform this translation, software must provide the ID of the VS whose state will be used during translation, the segment register to use, and the the GVA to translate. How the translation occurs depends on whether or not the VS is in 16bit real mode, 32bit protected mode, or 64bit long mode. In 16bit real mode, the segment registers are used for the translation. In 32bit protected mode, the segment registers and the GDT are used for the translation. 64bit long mode is the same as 32bit protected mode with the difference being that certain segments will return an error as they are not supported (e.g., ES and DS). If the translation fails for any reason, the resulting GLA is undefined.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to use for the translation |
| REG1 | 31:16 | The SSID of the segment to use for the translation |
| REG1 | 63:32 | REVI |
| REG2 | 63:0 | The GVA to translate |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The translated GLA |

**const, uint64_t: MV_VS_OP_GVA_TO_GLA_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the index for mv_vs_op_gva_to_gla |

### 2.15.7. mv_vs_op_gla_to_gpa, OP=0x6, IDX=0x6

This hypercall tells MicroV to translate the provided guest linear address (GLA) to a guest physical address (GPA). To perform this translation, MicroV will perform a linear to physical address conversion using the current state of CR0, CR3, and CR4. To perform this translation, software must provide the ID of the VS whose state will be used during translation and the the GLA to translate. How the translation occurs depends on whether or not the VS is in 16bit real mode, 32bit protected mode, 32bit protected mode with paging enabled, or 64bit long mode. If the VS is in 16bit real mode or 32bit protected mode with paging disabled, no translation is performed and the provided GLA is returned as the GPA. If the VS is in 32bit protected mode with paging enabled or 64bit long mode, MicroV will walk the guest page tables pointed to by CR3 in the VS and return the resulting GPA and GPA flags used to map the GLA to the GPA (caching flags are not included). If the translation fails for any reason, the resulting GPA is undefined.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to use for the translation |
| REG1 | 63:16 | REVI |
| REG2 | 11:0 | REVZ |
| REG2 | 63:12 | The GLA to translate |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 11:0 | The map flags that are used to map the GLA to the GPA |
| REG0 | 63:12 | The translated GPA |

**const, uint64_t: MV_VS_OP_GLA_TO_GPA_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the index for mv_vs_op_gla_to_gpa |

### 2.15.8. mv_vs_op_gva_to_gpa, OP=0x6, IDX=0x7

Reserved

This is reserved but not supported in this version of the MicroV spec. If MicroV where to actually implement this ABI, it would have to either make assumptions as to what to do between the GVA to GLA translation and GLA to GPA translation, or handle all edge cases, which is a lot to sign up too. Trying to make this sort of generic ABI is likely to cause problems that seem simple at first, but come back to haunt you later. It makes more sense to have software make whatever assumptions it wants between each step than to actually support this. Two hypercalls is a small price to pay, especially since most of the time, software can ignore the GVA to GLA translation if it wants.

Internal to MicroV an API like this should never be implemented as a GVA to GLA translation is wildly different from a GLA to GPA conversion. One uses segmentation and translation errors use a segmentation specific exception while the other uses paging and translation errors use a page fault exception. When a translation is done, it must be done in two steps as the inject of an exception will depend on which step fails.

**const, uint64_t: MV_VS_OP_GVA_TO_GPA_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the index for mv_vs_op_gva_to_gpa |

### 2.15.9. mv_vs_op_run, OP=0x6, IDX=0x8

This hypercall executes a VM's VP using the requested VS. The VM and VP that are executed is determined by which VM and VP were assigned during the creation of the VP and VS. This hypercall does not return until an exit condition occurs, or an error is encountered. The exit condition can be identified using the output REG0 which defines the "exit reason". Whenever mv_vs_op_run is executed, MicroV reads the shared page using a mv_run_t as input. When mv_vs_op_run returns, and no error has occurred, the shared page's contents depends on the exit condition. For some exit conditions, the shared page is ignored. In other cases, a structure specific to the exit condition is returned providing software with the information that it needs to handle the exit.

**Warning:**<br>
This hypercall is slow and may require a Hypercall Continuation. See Hypercall Continuations for more information.

**struct: mv_run_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| reserved | uint8_t | 0x0 | 4096 bytes | REVI |

**enum, int32_t: mv_exit_reason_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| mv_exit_reason_t_failure | 0 | returned on error  |
| mv_exit_reason_t_unknown | 1 | an unknown/unsupported VMExit has occurred |
| mv_exit_reason_t_hlt | 2 | a halt event has occurred |
| mv_exit_reason_t_io | 3 | a IO event has occurred |
| mv_exit_reason_t_mmio | 4 | a MMIO event has occurred |

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to run |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | A mv_exit_reason_t describing the reason for the exit |

**const, uint64_t: MV_VS_OP_RUN_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the index for mv_vs_op_run |

#### 2.15.9.1. mv_exit_reason_t_failure

If mv_vs_op_run returns an error with an exit reason of mv_exit_reason_t_failure, mv_exit_failure_t can be used to determine why the error occurred if MV_STATUS_EXIT_FAILURE is returned.

**struct: mv_exit_failure_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| reserved | uint8_t | 0x0 | 4096 bytes | REVI |

#### 2.15.9.2. mv_exit_reason_t_unknown

If mv_vs_op_run returns an error with an exit reason of mv_exit_reason_t_unknown, mv_exit_unknown_t can be used to determine why the error occurred if MV_STATUS_EXIT_UNKNOWN is returned.

**struct: mv_exit_unknown_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| info0 | uint64_t | 0x0 | 8 bytes | architecture specific information |
| info1 | uint64_t | 0x0 | 8 bytes | architecture specific information |
| info2 | uint64_t | 0x0 | 8 bytes | architecture specific information |
| info3 | uint64_t | 0x0 | 8 bytes | architecture specific information |
| reserved | uint8_t | 0x0 | 4064 bytes | REVI |

#### 2.15.9.3. mv_exit_reason_t_hlt

If mv_vs_op_run returns success with an exit reason of mv_exit_reason_t_hlt, it means that the VM has executed a halt event and mv_exit_hlt_t can be used to determine how to handle the event. For example, the VM might have issued a shutdown or reset command. Halt events can also occur when the VM or MicroV encounters a crash. For example, on x86, if a triple fault has occurred, MicroV will return mv_hlt_t_vm_crash. If MicroV itself encounters an error that it cannot recover from, it will return mv_hlt_t_microv_crash.

**enum, int32_t: mv_hlt_t**
| Name | Value | Description |
| :--- | :---- | :---------- |
| mv_hlt_t_shutdown | 0 | shutdown event |
| mv_hlt_t_reset | 1 | reset event |
| mv_hlt_t_vm_crash | 2 | crash event due to the VM |
| mv_hlt_t_microv_crash | 3 | crash event due to MicroV |

**struct: mv_exit_hlt_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| reason | mv_hlt_t | 0x0 | 8 bytes | describes the reason for the halt |
| reserved | uint8_t | 0x0 | 4088 bytes | REVI |

#### 2.15.9.4. mv_exit_reason_t_io

If mv_vs_op_run returns success with an exit reason of mv_exit_reason_t_io, it means that the VM has executed IO and mv_exit_io_t can be used to determine how to handle the event.

**const, uint64_t: MV_EXIT_IO_IN**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | The mv_exit_io_t defines an input access |

**const, uint64_t: MV_EXIT_IO_OUT**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | The mv_exit_io_t defines an output access |

**struct: mv_exit_io_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| addr | uint64_t | 0x0 | 8 bytes | The address of the IO register |
| data | uint64_t | 0x8 | 8 bytes | The data to read/write |
| reps | uint64_t | 0x10 | 8 bytes | The number of repetitions to make |
| type | uint64_t | 0x18 | 8 bytes | MV_EXIT_IO flags |
| dst_size | mv_bit_size_t | 0x20 | 1 byte | defines the bit size of the dst |
| src_size | mv_bit_size_t | 0x21 | 1 byte | defines the bit size of the src |
| reserved | uint8_t | 0x22 | 4062 bytes | REVI |

#### 2.15.9.5. mv_exit_reason_t_mmio

TBD

### 2.15.10. mv_vs_op_cpuid_get, OP=0x6, IDX=0x9

TBD

**const, uint64_t: MV_VS_OP_CPUID_GET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the index for mv_vs_op_cpuid_get |

### 2.15.11. mv_vs_op_cpuid_set, OP=0x6, IDX=0xA

TBD

**const, uint64_t: MV_VS_OP_CPUID_SET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000A | Defines the index for mv_vs_op_cpuid_set |

### 2.15.12. mv_vs_op_cpuid_get_list, OP=0x6, IDX=0xB

TBD

**const, uint64_t: MV_VS_OP_CPUID_GET_LIST_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000B | Defines the index for mv_vs_op_cpuid_get_list |

### 2.15.13. mv_vs_op_cpuid_set_list, OP=0x6, IDX=0xC

TBD

**const, uint64_t: MV_VS_OP_CPUID_SET_LIST_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000C | Defines the index for mv_vs_op_cpuid_set_list |

### 2.15.14. mv_vs_op_reg_get, OP=0x6, IDX=0xD

This hypercall tells MicroV to return the value of a requested register. Not all registers values require 64 bits. Any unused bits are REVI.

*Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to query |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | An mv_reg_t describing the register to get |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value read from the requested register |

**const, uint64_t: MV_VS_OP_REG_GET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000D | Defines the index for mv_vs_op_reg_get |

### 2.15.15. mv_vs_op_reg_set, OP=0x6, IDX=0xE

This hypercall tells MicroV to set the value of a requested register. Not all registers values require 64 bits. Any unused bits are REVI.

*Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to set |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | An mv_reg_t describing the register to set |
| REG3 | 63:0 | The value to write to the requested register |

**const, uint64_t: MV_VS_OP_REG_SET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000E | Defines the index for mv_vs_op_reg_set |

### 2.15.16. mv_vs_op_reg_get_list, OP=0x6, IDX=0xF

This hypercall tells MicroV to return the values of multiple requested registers using a Register Descriptor List (RDL) in the shared page. For this ABI, the reg field of each mv_rdl_entry_t refers to an mv_reg_t. The val field refers to the returned value of the requested register in that entry. Not all registers values require 64 bits. Any unused bits are REVI. This ABI does not use any of the reg 0-7 fields in the mv_rdl_t.

*Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_REG_GET_LIST_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000F | Defines the index for mv_vs_op_reg_get_list |

### 2.15.17. mv_vs_op_reg_set_list, OP=0x6, IDX=0x10

This hypercall tells MicroV to set the values of multiple requested registers using a Register Descriptor List (RDL) in the shared page. For this ABI, the reg field of each mv_rdl_entry_t refers to an mv_reg_t. The val field refers to the value to set the requested register in that entry to. Not all registers values require 64 bits. Any unused bits are REVI. This ABI does not use any of the reg 0-7 fields in the mv_rdl_t.

*Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to set |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_REG_SET_LIST_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000010 | Defines the index for mv_vs_op_reg_set_list |

### 2.15.18. mv_vs_op_msr_get, OP=0x6, IDX=0x17

This hypercall tells MicroV to return the value of a requested MSR.

*Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to query |
| REG1 | 63:16 | REVI |
| REG2 | 31:0 | The index of the MSR to get |
| REG2 | 63:32 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value read from the MSR |

**const, uint64_t: MV_VS_OP_MSR_GET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000017 | Defines the index for mv_vs_op_msr_get |

### 2.15.19. mv_vs_op_msr_set, OP=0x6, IDX=0x18

This hypercall tells MicroV to set the value of a requested MSR.

*Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to set |
| REG1 | 63:16 | REVI |
| REG2 | 31:0 | The index of the MSR to set |
| REG2 | 63:32 | REVI |
| REG3 | 63:0 | The value to write to the requested MSR |

**const, uint64_t: MV_VS_OP_MSR_SET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000018 | Defines the index for mv_vs_op_msr_set |

### 2.15.20. mv_vs_op_msr_get_list, OP=0x6, IDX=0x19

This hypercall tells MicroV to return the values of multiple requested MSRs using a Register Descriptor List (RDL) in the shared page. For this ABI, the reg field of each mv_rdl_entry_t refers to the index of the MSR. The val field refers to the returned value of the requested MSR in that entry. This ABI does not use any of the reg 0-7 fields in the mv_rdl_t.

*Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_MSR_GET_LIST_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000019 | Defines the index for mv_vs_op_msr_get_list |

### 2.15.21. mv_vs_op_msr_set_list, OP=0x6, IDX=0x1A

This hypercall tells MicroV to set the values of multiple requested MSRs using a Register Descriptor List (RDL) in the shared page. For this ABI, the reg field of each mv_rdl_entry_t refers to the index of the MSR. The val field refers to the value to set the requested MSR in that entry to. This ABI does not use any of the reg 0-7 fields in the mv_rdl_t.

*Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VS to set |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VS_OP_MSR_SET_LIST_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000001A | Defines the index for mv_vs_op_msr_set_list |

### 2.15.22. mv_vs_op_fpu_get, OP=0x6, IDX=0x1B

TBD

**const, uint64_t: MV_VS_OP_FPU_GET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000001B | Defines the index for mv_vs_op_fpu_get |

### 2.15.23. mv_vs_op_fpu_set, OP=0x6, IDX=0x1C

TBD

**const, uint64_t: MV_VS_OP_FPU_SET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000001C | Defines the index for mv_vs_op_fpu_set |

### 2.15.24. mv_vs_op_fpu_get_all, OP=0x6, IDX=0x1D

TBD

**const, uint64_t: MV_VS_OP_FPU_GET_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000001D | Defines the index for mv_vs_op_fpu_get_all |

### 2.15.25. mv_vs_op_fpu_set_all, OP=0x6, IDX=0x1E

TBD

**const, uint64_t: MV_VS_OP_FPU_SET_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000001E | Defines the index for mv_vs_op_fpu_set_all |

### 2.15.26. mv_vs_op_xsave_get, OP=0x6, IDX=0x1F

TBD

**const, uint64_t: MV_VS_OP_XSAVE_GET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000001F | Defines the index for mv_vs_op_xsave_get |

### 2.15.27. mv_vs_op_xsave_set, OP=0x6, IDX=0x20

TBD

**const, uint64_t: MV_VS_OP_XSAVE_SET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000020 | Defines the index for mv_vs_op_xsave_set |

### 2.15.28. mv_vs_op_xsave_get_all, OP=0x6, IDX=0x21

TBD

**const, uint64_t: MV_VS_OP_XSAVE_GET_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000021 | Defines the index for mv_vs_op_xsave_get_all |

### 2.15.29. mv_vs_op_xsave_set_all, OP=0x6, IDX=0x22

TBD

**const, uint64_t: MV_VS_OP_XSAVE_SET_ALL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000022 | Defines the index for mv_vs_op_xsave_set_all |

### 2.15.30. mv_vs_op_mp_state_get, OP=0x6, IDX=0x23

TBD

**const, uint64_t: MV_VS_OP_MP_STATE_GET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000023 | Defines the index for mv_vs_op_mp_state_get |

### 2.15.31. mv_vs_op_mp_state_set, OP=0x6, IDX=0x24

TBD

**const, uint64_t: MV_VS_OP_MP_STATE_SET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000024 | Defines the index for mv_vs_op_mp_state_set |

### 2.15.32. mv_vs_op_interrupt, OP=0x6, IDX=0x23

TBD

**const, uint64_t: MV_VS_OP_INTERRUPT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000023 | Defines the index for mv_vs_op_interrupt |
