## Table of Contents <!-- omit in toc -->

- [1. Introduction](#1-introduction)
  - [1.1. Reserved Values](#11-reserved-values)
  - [1.2. Document Revision](#12-document-revision)
  - [1.3. Glossary](#13-glossary)
  - [1.4. ID Types](#14-id-types)
  - [1.5. Memory Address Types](#15-memory-address-types)
  - [1.6. Constants, Structures, Enumerations and Bit Fields](#16-constants-structures-enumerations-and-bit-fields)
    - [1.6.1. Specification IDs](#161-specification-ids)
    - [1.6.2. Handle Type](#162-handle-type)
    - [1.6.3. Register Type](#163-register-type)
    - [1.6.4. GPA Flags](#164-gpa-flags)
    - [1.6.5. Memory Descriptor Lists](#165-memory-descriptor-lists)
  - [1.7. ID Constants](#17-id-constants)
  - [1.8. Endianness](#18-endianness)
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
    - [2.2.9. CPUID_4000_XX03_EAX](#229-cpuid_4000_xx03_eax)
    - [2.2.9. CPUID_4000_XX03_EBX](#229-cpuid_4000_xx03_ebx)
    - [2.2.11. CPUID_4000_XX03_ECX](#2211-cpuid_4000_xx03_ecx)
    - [2.2.11. CPUID_4000_XX03_EDX](#2211-cpuid_4000_xx03_edx)
- [3. Virtual Machines](#3-virtual-machines)
  - [3.1. Virtual Machine ID (VMID)](#31-virtual-machine-id-vmid)
- [4. Virtual Processors](#4-virtual-processors)
  - [4.1. Virtual Processor ID (VPID)](#41-virtual-processor-id-vpid)
- [5. Virtual Processor States](#5-virtual-processor-states)
  - [5.1. Virtual Processor State ID (VPSID)](#51-virtual-processor-state-id-vpsid)
- [6. Hypercall Interface](#6-hypercall-interface)
  - [6.1. Hypercall Continuation](#61-hypercall-continuation)
  - [6.2. Legal Hypercall Environments](#62-legal-hypercall-environments)
  - [6.3. Alignment Requirements](#63-alignment-requirements)
  - [6.4. Hypercall Status Codes](#64-hypercall-status-codes)
    - [6.4.1. MV_STATUS_SUCCESS, VALUE=0](#641-mv_status_success-value0)
    - [6.4.2. MV_STATUS_FAILURE, VALUE=1](#642-mv_status_failure-value1)
    - [6.4.3. MV_STATUS_INVALID_PERM, VALUE=2](#643-mv_status_invalid_perm-value2)
    - [6.4.4. MV_STATUS_INVALID_PARAMS, VALUE=3](#644-mv_status_invalid_params-value3)
    - [6.4.5. MV_STATUS_RETRY, VALUE=0x6](#645-mv_status_retry-value0x6)
  - [6.5. Hypercall Inputs](#65-hypercall-inputs)
  - [6.6. Hypercall Outputs](#66-hypercall-outputs)
  - [6.7. Hypercall Opcodes](#67-hypercall-opcodes)
    - [6.7.1. Debug Support](#671-debug-support)
    - [6.7.2. Handle Support](#672-handle-support)
    - [6.7.2. Physical Processors](#672-physical-processors)
    - [6.7.3. Virtual Machines](#673-virtual-machines)
    - [6.7.4. Virtual Processors](#674-virtual-processors)
    - [6.7.5. Virtual Processor State](#675-virtual-processor-state)
  - [6.8. Debug Hypercalls](#68-debug-hypercalls)
    - [6.8.1. mv_debug_op_out, OP=0x0, IDX=0x0](#681-mv_debug_op_out-op0x0-idx0x0)
  - [6.9. Handle Hypercalls](#69-handle-hypercalls)
    - [6.9.1. mv_handle_op_open_handle, OP=0x1, IDX=0x0](#691-mv_handle_op_open_handle-op0x1-idx0x0)
    - [6.9.2. mv_handle_op_close_handle, OP=0x1, IDX=0x1](#692-mv_handle_op_close_handle-op0x1-idx0x1)
  - [6.9. PP Hypercalls](#69-pp-hypercalls)
    - [6.9.2. mv_pp_op_set_shared_page, OP=0x1, IDX=0x2](#692-mv_pp_op_set_shared_page-op0x1-idx0x2)
    - [6.11.4. mv_pp_op_get_supported_cpuids, OP=0x4, IDX=0x4](#6114-mv_pp_op_get_supported_cpuids-op0x4-idx0x4)
    - [6.11.4. mv_pp_op_get_supported_cpuids, OP=0x4, IDX=0x4](#6114-mv_pp_op_get_supported_cpuids-op0x4-idx0x4-1)
    - [6.11.4. mv_pp_op_get_permissable_cpuids, OP=0x4, IDX=0x4](#6114-mv_pp_op_get_permissable_cpuids-op0x4-idx0x4)
    - [6.11.4. mv_pp_op_get_emulated_cpuids, OP=0x4, IDX=0x4](#6114-mv_pp_op_get_emulated_cpuids-op0x4-idx0x4)
    - [6.11.4. mv_pp_op_get_supported_regs, OP=0x4, IDX=0x4](#6114-mv_pp_op_get_supported_regs-op0x4-idx0x4)
    - [6.11.4. mv_pp_op_get_permissable_regs, OP=0x4, IDX=0x4](#6114-mv_pp_op_get_permissable_regs-op0x4-idx0x4)
    - [6.11.4. mv_pp_op_get_emulated_regs, OP=0x4, IDX=0x4](#6114-mv_pp_op_get_emulated_regs-op0x4-idx0x4)
    - [6.11.4. mv_pp_op_get_tsc_khz, OP=0x4, IDX=0x11](#6114-mv_pp_op_get_tsc_khz-op0x4-idx0x11)
    - [6.11.4. mv_pp_op_set_tsc_khz, OP=0x4, IDX=0x12](#6114-mv_pp_op_set_tsc_khz-op0x4-idx0x12)
    - [6.11.4. mv_vm_op_supported_regs, OP=0x2, IDX=0x5](#6114-mv_vm_op_supported_regs-op0x2-idx0x5)
    - [6.11.4. mv_vm_op_supported_regs_get, OP=0x2, IDX=0x6](#6114-mv_vm_op_supported_regs_get-op0x2-idx0x6)
    - [6.11.4. mv_vm_op_supported_regs_set, OP=0x2, IDX=0x7](#6114-mv_vm_op_supported_regs_set-op0x2-idx0x7)
    - [6.11.4. mv_vm_op_supported_msrs, OP=0x2, IDX=0x8](#6114-mv_vm_op_supported_msrs-op0x2-idx0x8)
    - [6.11.4. mv_vm_op_supported_msrs_get, OP=0x2, IDX=0x9](#6114-mv_vm_op_supported_msrs_get-op0x2-idx0x9)
    - [6.11.4. mv_vm_op_supported_msrs_set, OP=0x2, IDX=0xA](#6114-mv_vm_op_supported_msrs_set-op0x2-idx0xa)
  - [6.10. VM Hypercalls](#610-vm-hypercalls)
    - [6.10.1. mv_vm_op_create_vm, OP=0x2, IDX=0x0](#6101-mv_vm_op_create_vm-op0x2-idx0x0)
    - [6.10.2. mv_vm_op_destroy_vm, OP=0x2, IDX=0x1](#6102-mv_vm_op_destroy_vm-op0x2-idx0x1)
    - [6.10.3. mv_vm_op_vmid, OP=0x2, IDX=0x2](#6103-mv_vm_op_vmid-op0x2-idx0x2)
    - [6.10.4. mv_vm_op_mmio_map, OP=0x2, IDX=0x3](#6104-mv_vm_op_mmio_map-op0x2-idx0x3)
    - [6.10.5. mv_vm_op_mmio_unmap, OP=0x2, IDX=0x4](#6105-mv_vm_op_mmio_unmap-op0x2-idx0x4)
    - [6.10.5. mv_vm_op_mmio_trap, OP=0x2, IDX=0x4](#6105-mv_vm_op_mmio_trap-op0x2-idx0x4)
    - [6.11.4. mv_vm_op_create_irqchip, OP=0x2, IDX=0xA](#6114-mv_vm_op_create_irqchip-op0x2-idx0xa)
    - [6.11.4. mv_vm_op_get_irqchip, OP=0x2, IDX=0xA](#6114-mv_vm_op_get_irqchip-op0x2-idx0xa)
    - [6.11.4. mv_vm_op_set_irqchip, OP=0x2, IDX=0xA](#6114-mv_vm_op_set_irqchip-op0x2-idx0xa)
    - [6.11.4. mv_vm_op_get_irq_mode, OP=0x2, IDX=0xA](#6114-mv_vm_op_get_irq_mode-op0x2-idx0xa)
    - [6.11.4. mv_vm_op_set_irq_mode, OP=0x2, IDX=0xA](#6114-mv_vm_op_set_irq_mode-op0x2-idx0xa)
    - [6.11.4. mv_vm_op_get_irq_routing, OP=0x2, IDX=0xA](#6114-mv_vm_op_get_irq_routing-op0x2-idx0xa)
    - [6.11.4. mv_vm_op_set_irq_routing, OP=0x2, IDX=0xA](#6114-mv_vm_op_set_irq_routing-op0x2-idx0xa)
    - [6.11.4. mv_vm_op_queue_irq, OP=0x2, IDX=0xA](#6114-mv_vm_op_queue_irq-op0x2-idx0xa)
  - [6.11. VP Hypercalls](#611-vp-hypercalls)
    - [6.11.1. mv_vp_op_create_vp, OP=0x3, IDX=0x0](#6111-mv_vp_op_create_vp-op0x3-idx0x0)
    - [6.11.2. mv_vp_op_destroy_vp, OP=0x3, IDX=0x1](#6112-mv_vp_op_destroy_vp-op0x3-idx0x1)
    - [6.11.3. mv_vp_op_vmid, OP=0x3, IDX=0x2](#6113-mv_vp_op_vmid-op0x3-idx0x2)
    - [6.11.4. mv_vp_op_vpid, OP=0x3, IDX=0x3](#6114-mv_vp_op_vpid-op0x3-idx0x3)
  - [6.12. VPS Hypercalls](#612-vps-hypercalls)
    - [6.11.4. mv_vps_op_cpuid_get, OP=0x4, IDX=0x4](#6114-mv_vps_op_cpuid_get-op0x4-idx0x4)
    - [6.11.4. mv_vps_op_cpuid_set, OP=0x4, IDX=0x5](#6114-mv_vps_op_cpuid_set-op0x4-idx0x5)
    - [6.11.4. mv_vps_op_reg_get, OP=0x4, IDX=0x6](#6114-mv_vps_op_reg_get-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_reg_set, OP=0x4, IDX=0x7](#6114-mv_vps_op_reg_set-op0x4-idx0x7)
    - [6.11.4. mv_vps_op_reg_trap, OP=0x4, IDX=0x6](#6114-mv_vps_op_reg_trap-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_regs_general_get, OP=0x4, IDX=0x6](#6114-mv_vps_op_regs_general_get-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_regs_general_set, OP=0x4, IDX=0x6](#6114-mv_vps_op_regs_general_set-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_regs_system_get, OP=0x4, IDX=0x6](#6114-mv_vps_op_regs_system_get-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_regs_system_set, OP=0x4, IDX=0x6](#6114-mv_vps_op_regs_system_set-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_regs_debug_get, OP=0x4, IDX=0x6](#6114-mv_vps_op_regs_debug_get-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_regs_debug_set, OP=0x4, IDX=0x6](#6114-mv_vps_op_regs_debug_set-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_fpu_get, OP=0x4, IDX=0xA](#6114-mv_vps_op_fpu_get-op0x4-idx0xa)
    - [6.11.4. mv_vps_op_fpu_set, OP=0x4, IDX=0xB](#6114-mv_vps_op_fpu_set-op0x4-idx0xb)
    - [6.11.4. mv_vps_op_xsave_get, OP=0x4, IDX=0xC](#6114-mv_vps_op_xsave_get-op0x4-idx0xc)
    - [6.11.4. mv_vps_op_xsave_set, OP=0x4, IDX=0xD](#6114-mv_vps_op_xsave_set-op0x4-idx0xd)
    - [6.11.4. mv_vps_op_lapic_get_all, OP=0x4, IDX=0xC](#6114-mv_vps_op_lapic_get_all-op0x4-idx0xc)
    - [6.11.4. mv_vps_op_lapic_set_all, OP=0x4, IDX=0xD](#6114-mv_vps_op_lapic_set_all-op0x4-idx0xd)
    - [6.11.4. mv_vps_op_lapic_get_reg, OP=0x4, IDX=0xC](#6114-mv_vps_op_lapic_get_reg-op0x4-idx0xc)
    - [6.11.4. mv_vps_op_lapic_set_reg, OP=0x4, IDX=0xD](#6114-mv_vps_op_lapic_set_reg-op0x4-idx0xd)
    - [6.11.4. mv_vps_op_lapic_add, OP=0x4, IDX=0xC](#6114-mv_vps_op_lapic_add-op0x4-idx0xc)
    - [6.11.4. mv_vps_op_lapic_top, OP=0x4, IDX=0xD](#6114-mv_vps_op_lapic_top-op0x4-idx0xd)
    - [6.11.4. mv_vps_op_lapic_eoi, OP=0x4, IDX=0xD](#6114-mv_vps_op_lapic_eoi-op0x4-idx0xd)
    - [6.11.4. mv_vps_op_status_get, OP=0x4, IDX=0x12](#6114-mv_vps_op_status_get-op0x4-idx0x12)
    - [6.11.4. mv_vps_op_status_set, OP=0x4, IDX=0x12](#6114-mv_vps_op_status_set-op0x4-idx0x12)
    - [6.11.4. mv_vps_op_status_set, OP=0x4, IDX=0x12](#6114-mv_vps_op_status_set-op0x4-idx0x12-1)
    - [6.12.1. mv_vps_op_run, OP=0x8, IDX=0x2](#6121-mv_vps_op_run-op0x8-idx0x2)
    - [6.11.1. mv_vps_op_create_vps, OP=0x4, IDX=0x0](#6111-mv_vps_op_create_vps-op0x4-idx0x0)
    - [6.11.2. mv_vps_op_destroy_vps, OP=0x4, IDX=0x1](#6112-mv_vps_op_destroy_vps-op0x4-idx0x1)
    - [6.11.3. mv_vps_op_vpid, OP=0x4, IDX=0x2](#6113-mv_vps_op_vpid-op0x4-idx0x2)
    - [6.11.4. mv_vps_op_vpsid, OP=0x4, IDX=0x3](#6114-mv_vps_op_vpsid-op0x4-idx0x3)
    - [6.11.4. mv_vps_op_get_cpuid, OP=0x4, IDX=0x4](#6114-mv_vps_op_get_cpuid-op0x4-idx0x4)
    - [6.11.4. mv_vps_op_set_cpuid, OP=0x4, IDX=0x5](#6114-mv_vps_op_set_cpuid-op0x4-idx0x5)
    - [6.11.4. mv_vps_op_get_reg, OP=0x4, IDX=0x6](#6114-mv_vps_op_get_reg-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_set_reg, OP=0x4, IDX=0x7](#6114-mv_vps_op_set_reg-op0x4-idx0x7)
    - [6.11.4. mv_vps_op_get_general_regs, OP=0x4, IDX=0x6](#6114-mv_vps_op_get_general_regs-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_set_general_regs, OP=0x4, IDX=0x6](#6114-mv_vps_op_set_general_regs-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_get_system_regs, OP=0x4, IDX=0x6](#6114-mv_vps_op_get_system_regs-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_set_system_regs, OP=0x4, IDX=0x6](#6114-mv_vps_op_set_system_regs-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_get_debug_regs, OP=0x4, IDX=0x6](#6114-mv_vps_op_get_debug_regs-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_set_debug_regs, OP=0x4, IDX=0x6](#6114-mv_vps_op_set_debug_regs-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_get_msr, OP=0x4, IDX=0x8](#6114-mv_vps_op_get_msr-op0x4-idx0x8)
    - [6.11.4. mv_vps_op_set_msr, OP=0x4, IDX=0x9](#6114-mv_vps_op_set_msr-op0x4-idx0x9)
    - [6.11.4. mv_vps_op_get_msrs, OP=0x4, IDX=0x8](#6114-mv_vps_op_get_msrs-op0x4-idx0x8)
    - [6.11.4. mv_vps_op_set_msrs, OP=0x4, IDX=0x8](#6114-mv_vps_op_set_msrs-op0x4-idx0x8)
    - [6.11.4. mv_vps_op_trap_reg, OP=0x4, IDX=0x6](#6114-mv_vps_op_trap_reg-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_trap_msr, OP=0x4, IDX=0x6](#6114-mv_vps_op_trap_msr-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_trap_io, OP=0x4, IDX=0x6](#6114-mv_vps_op_trap_io-op0x4-idx0x6)
    - [6.11.4. mv_vps_op_get_fpu, OP=0x4, IDX=0xA](#6114-mv_vps_op_get_fpu-op0x4-idx0xa)
    - [6.11.4. mv_vps_op_set_fpu, OP=0x4, IDX=0xB](#6114-mv_vps_op_set_fpu-op0x4-idx0xb)
    - [6.11.4. mv_vps_op_get_xsave, OP=0x4, IDX=0xC](#6114-mv_vps_op_get_xsave-op0x4-idx0xc)
    - [6.11.4. mv_vps_op_set_xsave, OP=0x4, IDX=0xD](#6114-mv_vps_op_set_xsave-op0x4-idx0xd)
    - [6.11.4. mv_vps_op_queue_interrupt, OP=0x4, IDX=0x10](#6114-mv_vps_op_queue_interrupt-op0x4-idx0x10)
    - [6.11.4. mv_vps_op_get_tsc_khz, OP=0x4, IDX=0x11](#6114-mv_vps_op_get_tsc_khz-op0x4-idx0x11)
    - [6.11.4. mv_vps_op_set_tsc_khz, OP=0x4, IDX=0x12](#6114-mv_vps_op_set_tsc_khz-op0x4-idx0x12)
    - [6.11.4. mv_vps_op_get_mp_state, OP=0x4, IDX=0x12](#6114-mv_vps_op_get_mp_state-op0x4-idx0x12)
    - [6.11.4. mv_vps_op_set_mp_state, OP=0x4, IDX=0x12](#6114-mv_vps_op_set_mp_state-op0x4-idx0x12)
    - [6.11.4. mv_vps_op_get_lapic, OP=0x4, IDX=0x12](#6114-mv_vps_op_get_lapic-op0x4-idx0x12)
    - [6.11.4. mv_vps_op_set_lapic, OP=0x4, IDX=0x12](#6114-mv_vps_op_set_lapic-op0x4-idx0x12)
    - [6.12.1. mv_vps_op_run, OP=0x8, IDX=0x2](#6121-mv_vps_op_run-op0x8-idx0x2-1)

# 1. Introduction

This specification defines the ABI between VM software and the MicroV hypervisor (including both root VMs and guest VMs). This includes the use of CPUID and Hypercalls. This specification does not define the ABI between the Bareflank Microkernel and Bareflank Extensions. Please see the Microkernel Syscall Specification for more information on the ABI supported by the Bareflank Microkernel for writing custom hypervisor extensions. This specification also does not define the ABI for any support drivers like the Bareflank Loader or the MicroV KVM Shim Driver. Please see the their specifications for more information.

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
| VM | Virtual Machine |
| VP | Virtual Processor |
| VPS | Virtual Processor State |
| PP | Physical Processor |
| VMID | Virtual Machine Identifier |
| VPID | Virtual Processor Identifier |
| VPSID | Virtual Processor State Identifier |
| PPID | Physical Processor Identifier |
| OS | Operating System |
| BIOS | Basic Input/Output System |
| UEFI | Unified Extensible Firmware Interface |
| SPA | A System Physical Address (SPA) refers to a physical address as seen by the system without the addition of virtualization |
| GPA | A Guest Physical Address (GPA) refers to a physical address as seen by a VM and requires a translation to convert to a SPA |
| GVA | A Guest Virtual Address (GVA) refers to a virtual address as seen by a VM and requires a guest controlled translation to convert to a GPA |
| Page Aligned | A region of memory whose address is divisible by 0x1000 |
| Page | A page aligned region of memory that is 0x1000 bytes in size |
| Host | Refers to the hypervisor (i.e., the code responsible for executing different virtual machines on the same physical hardware). For MicroV, this is the Bareflank Microkernel and its associated extensions. Sometimes referred to as VMX root |
| Root VM | The first VM created when MicroV is launched. The OS/BIOS/UEFI that is running when MicroV is launch is placed in the Root VM. Sometimes this is called Dom0 or the Root Partition |
| Guest VM | Any additional VM created by MicroV. Sometimes called a DomU or Guest Partition |

## 1.4. ID Types

| Name | Type |
| :--- | :--- |
| Virtual Machine ID (VMID) | uint64_t |
| Virtual Processor ID (VPID) | uint64_t |
| Virtual Processor State ID (VPSID) | uint64_t |
| Physical Processor ID (PPID) | uint64_t |
| Extension ID (EXTID) | uint64_t |

## 1.5. Memory Address Types

| Name | Type |
| :--- | :--- |
| System Physical Address (SPA) | uint64_t |
| Guest Physical Address (GPA) | uint64_t |
| Guest Virtual Address (GVA) | uint64_t |

## 1.6. Constants, Structures, Enumerations and Bit Fields

### 1.6.1. Specification IDs

The following defines the specification IDs used when opening a handle. These provide software with a means to define which specification it talks.

**const, uint32_t: MV_SPEC_ID1_VAL**
| Value | Description |
| :---- | :---------- |
| 0x3123764D | Defines the ID for version #1 of this spec |

### 1.6.2. Handle Type

The mv_handle_t structure is an opaque structure containing the handle used by most of the hypercalls in this specification.

**struct: mv_handle_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| hndl | uint64_t | 0x0 | 8 bytes | The handle returned by mv_handle_op_open_handle |

### 1.6.3. Register Type

Defines which register a hypercall is requesting.

**enum, uint64_t: bf_reg_t**
| Name | Value | Description |
| :--- | :---- | :---------- |

TBD

### 1.6.4. GPA Flags

The GPA flags are used by some of the hypercalls as both inputs to a hypercall as well as outputs from a hypercall to provide information about how a GPA should be or is mapped. These flags can also be used to define UEFI Memory Map and E820 Memory Map types.

| Bit | Name | Description |
| :-- | :--- | :---------- |
| 0 | MV_GPA_FLAG_READ_ACCESS | Indicates the GPA has read access |
| 1 | MV_GPA_FLAG_WRITE_ACCESS | Indicates the GPA has write access |
| 2 | MV_GPA_FLAG_EXECUTE_ACCESS | Indicates the GPA has execute access |
| 8 | MV_GPA_FLAG_UNCACHEABLE | Indicates the GPA is mapped as UC |
| 9 | MV_GPA_FLAG_UNCACHEABLE_MINUS | Indicates the GPA is mapped as UC- |
| 10 | MV_GPA_FLAG_WRITE_COMBINING | Indicates the GPA is mapped as WC |
| 11 | MV_GPA_FLAG_WRITE_COMBINING_PLUS | Indicates the GPA is mapped as WC+ |
| 12 | MV_GPA_FLAG_WRITE_THROUGH | Indicates the GPA is mapped as WT |
| 13 | MV_GPA_FLAG_WRITE_BACK | Indicates the GPA is mapped as WB |
| 14 | MV_GPA_FLAG_WRITE_PROTECTED | Indicates the GPA is mapped as WP |
| 63:15 | revz | REVZ |

### 1.6.5. Memory Descriptor Lists

A memory descriptor list (MDL) describes a discontiguous region of guest physical memory. Each MDL consists of a list of entries with each entry describing one contiguous region of guest physical memory. By combining multiple entries into a list, software is capable of describing both contiguous and discontiguous regions of guest physical memory. Like all structures used in this ABI, the MDL must be placed inside the shared page and therefore the total number of entries allowed in the list depends on the ABI being used.

**struct: mv_mdl_entry_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| gpa | uint64_t | 0x0 | 8 bytes | The starting gpa of the memory range |
| size | uint64_t | 0x8 | 8 bytes | The number of bytes in the memory range |
| flags | uint64_t | 0x10 | 8 bytes | See GPA Flags |
| reserved | uint64_t | 0x18 | 8 bytes | REVI |

The format of the MDL as follows:

**struct: mv_mdl_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| num_entries | uint64_t | 0x0 | 8 bytes | The number of entries in the MDL |
| reserved1 | uint64_t | 0x8 | 8 bytes | REVI |
| reserved2 | uint64_t | 0x10 | 8 bytes | REVI |
| reserved3 | uint64_t | 0x18 | 8 bytes | REVI |
| entries | mv_mdl_entry_t[] | 0x20 | ABI dependent | Each entry in the MDL |

## 1.7. ID Constants

The following defines some ID constants.

**const, uint16_t: MV_INVALID_ID**
| Value | Description |
| :---- | :---------- |
| 0xFFFF | Defines an invalid ID for an extension, VM, VP, VPS and PP |

**const, uint16_t: MV_BS_PPID**
| Value | Description |
| :---- | :---------- |
| 0x0 | Defines the bootstrap physical processor ID |

**const, uint16_t: MV_ROOT_VMID**
| Value | Description |
| :---- | :---------- |
| 0x0 | Defines the root virtual machine ID |

## 1.8. Endianness

This document only applies to 64bit Intel and AMD systems conforming to the amd64 architecture. As such, this document is limited to little endian.

# 2. Feature and Interface Discovery

## 2.1. Hypervisor Discovery

Hypervisor discovery is defined by the [Hypervisor Top Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs). Reading CPUID_0000_0001_ECX bit 31 will indicate if software is executing in a virtualized environment. If bit 31 is set, software can safely read CPUID_4000_0000 to the value returned by CPUID_4000_0000_EAX if the hypervisor conforms to the [Hypervisor Top Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs).

The CPUID leaves in this section describe how to determine if the hypervisor is MicroV as well as which version of MicroV software is running on.

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

**const, uint32_t: MV_CPUID_MIN_LEAF_VAL**
| Value | Description |
| :---- | :---------- |
| 0x40000202 | Defines the minimum expected return value of mv_max_cpuid_leaf |

**const, uint32_t: MV_CPUID_MAX_LEAF_VAL**
| Value | Description |
| :---- | :---------- |
| 0x4000FFFF | Defines the maximum expected return value of mv_max_cpuid_leaf |

**const, uint32_t: MV_CPUID_INIT_VAL**
| Value | Description |
| :---- | :---------- |
| 0x40000200 | Defines the first CPUID to scan from |

**const, uint32_t: MV_CPUID_INC_VAL**
| Value | Description |
| :---- | :---------- |
| 0x100 | Defines increment used when scanning CPUID |

### 2.2.2. CPUID_4000_XX00_EBX

This CPUID query returns "BfMi".

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | MV_VENDOR_ID1 | Returns 0x694D764D - "BfMi"|

**const, uint32_t: MV_CPUID_VENDOR_ID1_VAL**
| Value | Description |
| :---- | :---------- |
| 0x694D764D | Defines the expected return value of mv_vendor_id1 |

### 2.2.3. CPUID_4000_XX00_ECX

This CPUID query returns "croV".

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | MV_VENDOR_ID2 | Returns 0x566F7263 - "croV" |

**const, uint32_t: MV_CPUID_VENDOR_ID2_VAL**
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

### 2.2.9. CPUID_4000_XX03_EAX

This CPUID query returns MicroV's PP and VM limits. These can be used by software to create static arrays for each resource is desired as MicroV will not be capable of handling more than what is reported.

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 15:0 | MICROV_MAX_PPS | Returns HYPERVISOR_MAX_PPS |
| 31:16 | MICROV_MAX_VMS | Returns HYPERVISOR_MAX_VMS |

### 2.2.9. CPUID_4000_XX03_EBX

This CPUID query returns MicroV's VP and VPS limits. These can be used by software to create static arrays for each resource is desired as MicroV will not be capable of handling more than what is reported.

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 15:0 | MICROV_MAX_VPS | Returns HYPERVISOR_MAX_VPS |
| 31:16 | MICROV_MAX_VPSS | Returns HYPERVISOR_MAX_VPSS |

### 2.2.11. CPUID_4000_XX03_ECX

Reserved

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | REVZ | Returns 0 |

### 2.2.11. CPUID_4000_XX03_EDX

Reserved

| Bits | Name | Description |
| :--- | :--- | :---------- |
| 31:0 | REVZ | Returns 0 |

# 3. Virtual Machines

A Virtual Machine or VM virtually represents a physical computer and stores the resources that are shared between one or more Virtual Processors called the Virtual Machine State or VMS. MicroV is capable of executing multiple VMs simultaneously on the same physical machine. In some configurations these VMs might share the same physical cores/threads and in other configurations, each VM is given dedicated access to one or more physical cores/threads, and either share the rest of hardware, or the rest of hardware is divided up between VMs using something like an IOMMU (or some combination of the two).

There are different types of VMs. The root VM is the initial VM created by the Bareflank Microkernel and executes whatever operating system was executing at the time MicroV was started. In some configurations (early boot), MicroV is started from BIOS/UEFI and demotes BIOS/UEFI into the root VM. From there, BIOS/UEFI might boot an additional operating system such as Windows or Linux inside the root VM. In other configurations (late launch), an operating system such as Windows or Linux has already booted and MicroV is started some time later. In this configuration MicroV demotes the current operating system into the root VM and executes from there.

The early boot configuration of MicroV provides better security as well as early access to memory resources reducing fragmentation and increasing the efficiency of the overall system (reduces shattering of large pages). The late launch configuration of MicroV is easier to develop for.

All additional VMs that are created from the root VM are called guest VMs. Guest VMs are not capable of creating additional guest VMs (VMs can only be created by the root VM). That is, MicroV uses a breath of many, depth of one approach.

## 3.1. Virtual Machine ID (VMID)

The Virtual Machine ID (VMID) is a 16bit number that uniquely identifies a VM.

# 4. Virtual Processors

A Virtual Processor or VP virtually represents a physical core/thread on the system. It is the "thing" that is scheduled to execute code and contains one or more Virtual Processor States or VPSs that store the actual state of the VP and execute the actual code on behalf of a VP. Each time a VP is scheduled for execution, it replaces the state on the physical core/thread with one of the VPSs it owns. Once the VP is done executing, the current state of the physical core/thread is saved back to the VPS in use, allowing another VP to execute as needed.

There are different types of VPs. The root VPs are created when MicroV is first started and one and only one root VP is created for every physical core/thread on the system. Root VPs are owned by the Root VM. MicroV does not provide the ability to create additional root VPs.

Any additional VPs that are created are called guest VPs which are owned and executed by the root VPs. Guest VPs cannot create additional guest VPs (meaning guest VPs must be created by a root VP). When a root VP executes a guest VP using the mv_vp_run_vp hypercall, it is said to be "donating" its execution time to the guest VP. This allows, for example, applications running in the root VM to execute guest VMs, whose time is billed to the application making the call to mv_vp_run_vp.

Unlike guest VMs who only have a single owning root VM, guest VPs can be owned by a single but different root VP at any given time. When a root VP executes a guest VP, the root VP becomes the parent VP and the guest VP becomes the child VP. During execution of a guest VP the parent/child relationship does not change. Once the guest VP's execution is complete the parent/child relationship is released and the scheduler is free to transfer ownership of a guest VP from one root VP to another. This transfer of ownership usually occurs during VP migration and is due to the fact that a guest VM is not required to have the same number of guest VPs compared to the number of root VPs which reflects the physical number of cores/threads on the system. As a result, the scheduler is free to move guest VPs to different root VPs as needed to optimize performance, resulting in a VP migration.

## 4.1. Virtual Processor ID (VPID)

The Virtual Processor ID (VPID) is a 16bit number that uniquely identifies a VP.

# 5. Virtual Processor States

TBD

## 5.1. Virtual Processor State ID (VPSID)

The Virtual Processor State ID (VPSID) is a 16bit number that uniquely identifies a VPS.

# 6. Hypercall Interface

The following section defines the hypercall interface used by this specification, and therefore MicroV.

## 6.1. Hypercall Continuation

Some hypercalls might take a long time to execute. Since MicroV does not service interrupts, interrupts are disabled while a hypercall is being processed. If a hypercall takes to long, this can have adverse effects on software if interrupts need to perform work while the hypercall is attempting to process.

To prevent this from occurring, long running hypercalls resume software periodically without advancing the instruction pointer. This forces the hypercall to be executed again, allowing the hypervisor to resume its execution. For this reason, some hypercalls might generate more than one VMExit, and more importantly, software should not rely on a hypercall completing before other operations can take place (e.g., servicing interrupts).

In some cases, software might want more control on how a continuation is handled. For example, if software needs to perform additional actions above and beyond servicing interrupts. To support this, the MV_HYPERCALL_FLAGS_SCC flag can be set, telling the hypervisor to advance the instruction pointer and return MV_STATUS_RETRY_CONTINUATION, indicating to software that a continuation is required and software should retry the hypercall when it is ready.

## 6.2. Legal Hypercall Environments

The kernel and userspace can execute hypercalls from 64bit mode. 32bit mode is currently not supported.

## 6.3. Alignment Requirements

Most GPAs are required to be page aligned. When this occurs, the hypercall documentation will state that bits 11:0 are REVZ. If this is not documented, software can safely assume that the lower 12 bits of the GPA are valid and can be provided.

If a hypercall must provide input/output larger than what is supported from a register only hypercall, a structure will be used instead. When this occurs, software must place the structure in a page (that is page aligned) at offset 0 of the page, providing the GPA of the page as input. Hypercalls that accept more than one page use the MDL format listed above.

## 6.4. Hypercall Status Codes

Every hypercall returns a mv_status_t to indicate the success or failure of a hypercall after execution. The following defines the layout of mv_status_t:

**uint64_t: mv_status_t**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:48 | MV_STATUS_SIG | Contains 0x0000 on success, 0xDEAD on failure |
| 47:16 | MV_STATUS_FLAGS | Contains the flags associated with the mv_status_t |
| 15:0 | MV_STATUS_VALUE | Contains the value of the mv_status_t |

MV_STATUS_VALUE defines success or which type of error occurred. MV_STATUS_FLAGS provides additional information about why the error occurred.

### 6.4.1. MV_STATUS_SUCCESS, VALUE=0

**const, bf_status_t: MV_STATUS_SUCCESS**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Used to indicated that the hypercall returned successfully |

### 6.4.2. MV_STATUS_FAILURE, VALUE=1

**const, bf_status_t: MV_STATUS_FAILURE_UNKNOWN**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010001 | Indicates an unknown error occurred |

**const, bf_status_t: MV_STATUS_FAILURE_UNSUPPORTED**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020001 | Indicates the hypercall is unsupported |

**const, bf_status_t: MV_STATUS_FAILURE_INVALID_HANDLE**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000040001 | Indicates the provided handle is invalid |

### 6.4.3. MV_STATUS_INVALID_PERM, VALUE=2

**const, bf_status_t: MV_STATUS_INVALID_PERM_EXT**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010002 | Indicates the VM is not allowed to execute this hypercall |

**const, bf_status_t: MV_STATUS_INVALID_PERM_DENIED**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020002 | Indicates the policy engine denied the hypercall |

### 6.4.4. MV_STATUS_INVALID_PARAMS, VALUE=3

**const, bf_status_t: MV_STATUS_INVALID_PARAMS0**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000010003 | Indicates param 0 is invalid |

**const, bf_status_t: MV_STATUS_INVALID_PARAMS1**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000020003 | Indicates param 1 is invalid |

**const, bf_status_t: MV_STATUS_INVALID_PARAMS2**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000040003 | Indicates param 2 is invalid |

**const, bf_status_t: MV_STATUS_INVALID_PARAMS3**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000080003 | Indicates param 3 is invalid |

**const, bf_status_t: MV_STATUS_INVALID_PARAMS4**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000100003 | Indicates param 4 is invalid |

**const, bf_status_t: MV_STATUS_INVALID_PARAMS5**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000200003 | Indicates param 5 is invalid |

### 6.4.5. MV_STATUS_RETRY, VALUE=0x6

**const, bf_status_t: MV_STATUS_RETRY_CONTINUATION**
| Value | Description |
| :---- | :---------- |
| 0xDEAD000000100004 | Used to indicate to software that it should execute the hypercall again |

## 6.5. Hypercall Inputs

Before software can execute a hypercall, it must first open a handle to the hypercall interface by executing the mv_handle_op_open_handle hypercall. This handle must be provided as the first argument to each hypercall in R10 (i.e., REG0) and can be released using the mv_handle_op_close_handle hypercall.

**R10:**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:0 | MV_HANDLE | The result of mv_handle_op_open_handle |

Every hypercall must provide information about the hypercall by filling out RAX as follows:

**RAX:**
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

MV_HYPERCALL_SIG is used to ensure the hypercall is, in fact, a Bareflank specific hypercall. MV_HYPERCALL_FLAGS is used to provide additional hypercall options.

MV_HYPERCALL_OP determines which opcode the hypercall belongs to, logically grouping hypercalls based on their function. MV_HYPERCALL_OP is also used internally within the microkernel to dispatch the hypercall to the proper handler. MV_HYPERCALL_IDX, when combined with MV_HYPERCALL_OP, uniquely identifies a specific hypercall. This specification tightly packs the values assigned to both MV_HYPERCALL_IDX and MV_HYPERCALL_OP to ensure Bareflank (and variants) can use jump tables instead of branch logic.

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

## 6.6. Hypercall Outputs

After executing a hypercall, a bf_status_t is returned in RAX to indicate if the hypercall succeeded or failed and why.

**RAX:**
| Bits | Name | Description |
| :--- | :--- | :---------- |
| 63:0 | MV_STATUS | Contains the value of bf_status_t |

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

## 6.7. Hypercall Opcodes

The following sections define the different opcodes that are supported by this specification. Note that each opcode includes the hypercall signature making it easier to validate if the hypercall is supported or not.

### 6.7.1. Debug Support

**const, uint64_t: MV_DEBUG_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000000000 | Defines the hypercall opcode for mv_debug_op hypercalls |

**const, uint64_t: MV_DEBUG_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall opcode for mv_debug_op hypercalls with no signature |

### 6.7.2. Handle Support

**const, uint64_t: MV_HANDLE_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000010000 | Defines the hypercall opcode for mv_handle_op hypercalls |

**const, uint64_t: MV_HANDLE_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000010000 | Defines the hypercall opcode for mv_handle_op hypercalls with no signature |

### 6.7.2. Physical Processors

**const, uint64_t: MV_PP_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000020000 | Defines the hypercall opcode for mv_pp_op hypercalls |

**const, uint64_t: MV_PP_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000020000 | Defines the hypercall opcode for mv_pp_op hypercalls with no signature |

### 6.7.3. Virtual Machines

**const, uint64_t: MV_VM_OP**
| Value | Description |
| :---- | :---------- |
| 0x764D000000030000 | Defines the hypercall opcode for mv_vm_op hypercalls |

**const, uint64_t: MV_VM_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000030000 | Defines the hypercall opcode for mv_vm_op hypercalls with no signature |

### 6.7.4. Virtual Processors

**const, uint64_t: MV_VP_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000040000 | Defines the hypercall opcode for mv_vp_op hypercalls |

**const, uint64_t: MV_VP_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000040000 | Defines the hypercall opcode for mv_vp_op hypercalls with no signature |

### 6.7.5. Virtual Processor State

**const, uint64_t: MV_VPS_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000050000 | Defines the hypercall opcode for mv_vps_op hypercalls |

**const, uint64_t: MV_VPS_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000050000 | Defines the hypercall opcode for mv_vps_op hypercalls with no signature |

## 6.8. Debug Hypercalls

### 6.8.1. mv_debug_op_out, OP=0x0, IDX=0x0

This hypercall tells the hypervisor to output R10 and R11 to the console device the hypervisor is currently using for debugging. The purpose of this hypercall is to provide a simple means for debugging issues with the guest and can be used by a VM from both user-space and the kernel, even when the operating system is not fully bootstrapped or is in a failure state.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The first value to output to the hypervisor's console |
| REG1 | 63:0 | The second value to output to the hypervisor's console |

**const, uint64_t: MV_DEBUG_OP_OUT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_debug_op_out |

## 6.9. Handle Hypercalls

### 6.9.1. mv_handle_op_open_handle, OP=0x1, IDX=0x0

This hypercall returns a handle which is required to execute the remaining hypercalls.

Some versions of MicroV might provide a certain degree of backwards compatibility which can be queried using CPUID_4000_XX01_EAX. The version argument of this hypercall provides software with means to tell the hypervisor which version of this spec it is trying to use. If software provides a version that MicroV doesn't support (i.e., a version that is not listed by CPUID_4000_XX01_EAX), this hypercall will fail.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:32 | REVI |
| REG0 | 31:0 | The version of this spec that software supports |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The value to set REG0 to for all other hypercalls (minus debugging hypercalls) |

**const, uint64_t: MV_HANDLE_OP_OPEN_HANDLE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_handle_op_open_handle |

### 6.9.2. mv_handle_op_close_handle, OP=0x1, IDX=0x1

This hypercall closes a previously opened handle.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**const, uint64_t: MV_HANDLE_OP_CLOSE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_handle_op_close_handle |

## 6.9. PP Hypercalls

### 6.9.2. mv_pp_op_set_shared_page, OP=0x1, IDX=0x2

This hypercall assigns a provided shared page to the provided physical processor (PP). All hypercalls made on any given PP must be made using the shared page assigned to the PP. Note that this shared page is only needed when a hypercall cannot be executed using registers only. All structures mapped into this page must start at offset 0 of the page, meaning each structure must be page aligned.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the PP to assign the shared page to |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The GPA of the shared page |

**const, uint64_t: MV_HANDLE_OP_SHARED_PAGE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the hypercall index for mv_pp_op_set_shared_page |

### 6.11.4. mv_pp_op_get_supported_cpuids, OP=0x4, IDX=0x4

Given the initial leaf (EAX) and subleaf (ECX), this hypercall will return the resulting values of EAX, EBX, ECX and EDX from the point of view of the requested VPS.

In addition to the input registers, the caller must also fill out an mv_cpuid_t located in the shared page associated with the PP the caller is calling from.

**struct: mv_cpuid_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| leaf | uint32_t | 0x0 | 4 bytes | The value of EAX before calling cpuid |
| subleaf | uint32_t | 0x4 | 4 bytes | The value of ECX before calling cpuid |
| eax | uint32_t | 0x8 | 4 bytes | The value of EAX after calling cpuid |
| ebx | uint32_t | 0xC | 4 bytes | The value of EBX after calling cpuid |
| ecx | uint32_t | 0x10 | 4 bytes | The value of ECX after calling cpuid |
| edx | uint32_t | 0x14 | 4 bytes | The value of EDX after calling cpuid |

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_GET_CPUID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the hypercall index for mv_pp_op_get_supported_cpuid |

### 6.11.4. mv_pp_op_get_supported_cpuids, OP=0x4, IDX=0x4
### 6.11.4. mv_pp_op_get_permissable_cpuids, OP=0x4, IDX=0x4
### 6.11.4. mv_pp_op_get_emulated_cpuids, OP=0x4, IDX=0x4

### 6.11.4. mv_pp_op_get_supported_regs, OP=0x4, IDX=0x4
### 6.11.4. mv_pp_op_get_permissable_regs, OP=0x4, IDX=0x4
### 6.11.4. mv_pp_op_get_emulated_regs, OP=0x4, IDX=0x4

### 6.11.4. mv_pp_op_get_tsc_khz, OP=0x4, IDX=0x11
### 6.11.4. mv_pp_op_set_tsc_khz, OP=0x4, IDX=0x12



### 6.11.4. mv_vm_op_supported_regs, OP=0x2, IDX=0x5

This hypercall will return a mv_supported_regs_t located in the shared page associated with the PP the caller is calling from that defines which registers are supported by MicroV for the requested VM.

Note that the requested VM can either be MV_ROOT_VMID, a guest VMID, or MV_INVALID_ID. If MV_ROOT_VMID is provided, mv_vm_op_supported_regs will return the supported registers for the root VM. If a guest VMID or MV_INVALID_ID is provided, mv_vm_op_supported_regs will return the supported registers for any guest VM, meaning all guest VMs share the same supported registers. If a guest VMID is not available yet, MV_INVALID_ID can be used.

**const, uint64_t: MV_SUPPORTED_REGS_T_SIZE**
| Value | Description |
| :---- | :---------- |
| 0x1000 | Defines the total number of bytes defining which registers are supported |

**struct: mv_supported_regs_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| supported | uint8_t[MV_SUPPORTED_REGS_T_SIZE] | 0x0 | 0x1000 bytes | Defines which registers are supported |

Each bit in the mv_supported_regs_t corresponds with a register in mv_reg_t. If the register is supported, it's associated bit is enabled (using the mv_reg_t enum value as the bit location).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_SUPPORTED_REGS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the hypercall index for mv_vm_op_supported_regs |

### 6.11.4. mv_vm_op_supported_regs_get, OP=0x2, IDX=0x6

This hypercall will return a mv_supported_regs_t located in the shared page associated with the PP the caller is calling from that defines which registers MicroV allows the caller to call mv_vps_op_get_reg on. The result will always be a subset of the results of mv_vm_op_supported_regs.

Note that the requested VM can either be MV_ROOT_VMID, a guest VMID, or MV_INVALID_ID. If MV_ROOT_VMID is provided, mv_vm_op_supported_regs_get will return the supported registers for the root VM. If a guest VMID or MV_INVALID_ID is provided, mv_vm_op_supported_regs_get will return the supported registers for any guest VM, meaning all guest VMs share the same supported registers. If a guest VMID is not available yet, MV_INVALID_ID can be used.

**const, uint64_t: MV_SUPPORTED_REGS_T_SIZE**
| Value | Description |
| :---- | :---------- |
| 0x1000 | Defines the total number of bytes defining which registers are supported |

**struct: mv_supported_regs_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| supported | uint8_t[MV_SUPPORTED_REGS_T_SIZE] | 0x0 | 0x1000 bytes | Defines which registers are supported |

Each bit in the mv_supported_regs_t corresponds with a register in mv_reg_t. If the register is supported, it's associated bit is enabled (using the mv_reg_t enum value as the bit location).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_GET_SUPPORTED_REGS_GET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the hypercall index for mv_vm_op_supported_regs_get |

### 6.11.4. mv_vm_op_supported_regs_set, OP=0x2, IDX=0x7

This hypercall will return a mv_supported_regs_t located in the shared page associated with the PP the caller is calling from that defines which registers MicroV allows the caller to call mv_vps_op_set_reg on. The result will always be a subset of the results of mv_vm_op_supported_regs.

Note that the requested VM can either be MV_ROOT_VMID, a guest VMID, or MV_INVALID_ID. If MV_ROOT_VMID is provided, mv_vm_op_supported_regs_set will return the supported registers for the root VM. If a guest VMID or MV_INVALID_ID is provided, mv_vm_op_supported_regs_set will return the supported registers for any guest VM, meaning all guest VMs share the same supported registers. If a guest VMID is not available yet, MV_INVALID_ID can be used.

**const, uint64_t: MV_SUPPORTED_REGS_T_SIZE**
| Value | Description |
| :---- | :---------- |
| 0x1000 | Defines the total number of bytes defining which registers are supported |

**struct: mv_supported_regs_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| supported | uint8_t[MV_SUPPORTED_REGS_T_SIZE] | 0x0 | 0x1000 bytes | Defines which registers are supported |

Each bit in the mv_supported_regs_t corresponds with a register in mv_reg_t. If the register is supported, it's associated bit is enabled (using the mv_reg_t enum value as the bit location).

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_GET_SUPPORTED_REGS_SET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the hypercall index for mv_vm_op_supported_regs_set |

### 6.11.4. mv_vm_op_supported_msrs, OP=0x2, IDX=0x8

This hypercall will return a mv_supported_msrs_t located in the shared page associated with the PP the caller is calling from that defines which MSRs are supported by MicroV for the requested VM.

Note that the requested VM can either be MV_ROOT_VMID, a guest VMID, or MV_INVALID_ID. If MV_ROOT_VMID is provided, mv_vm_op_supported_msrs_set will return the supported MSRs for the root VM. If a guest VMID or MV_INVALID_ID is provided, mv_vm_op_supported_msrs_set will return the supported MSRs for any guest VM, meaning all guest VMs share the same supported MSRs. If a guest VMID is not available yet, MV_INVALID_ID can be used.

**const, uint64_t: MV_SUPPORTED_MSRS_T_SIZE**
| Value | Description |
| :---- | :---------- |
| 0x400 | Defines the total number of bytes defining which MSRs are supported in a range |

**struct: mv_supported_msrs_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| range1 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x0 | 0x400 bytes | Defines supported MSRs 0x00000000 - 0x00001FFF |
| range2 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x400 | 0x400 bytes | Defines supported MSRs 0xC0000000 - 0xC0001FFF |
| range3 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x800 | 0x400 bytes | Defines supported MSRs 0xC0010000 - 0xC0011FFF |

Each bit in the mv_supported_msrs_t corresponds with an MSR. If the MSR is supported, it's associated bit is enabled.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_SUPPORTED_MSRS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the hypercall index for mv_vm_op_supported_msrs |

### 6.11.4. mv_vm_op_supported_msrs_get, OP=0x2, IDX=0x9

This hypercall will return a mv_supported_msrs_t located in the shared page associated with the PP the caller is calling from that defines which MSRs MicroV allows the caller to call mv_vps_op_get_msr on. The result will always be a subset of the results of mv_vm_op_supported_msrs.

Note that the requested VM can either be MV_ROOT_VMID, a guest VMID, or MV_INVALID_ID. If MV_ROOT_VMID is provided, mv_vm_op_supported_msrs_get will return the supported MSRs for the root VM. If a guest VMID or MV_INVALID_ID is provided, mv_vm_op_supported_msrs_get will return the supported MSRs for any guest VM, meaning all guest VMs share the same supported MSRs. If a guest VMID is not available yet, MV_INVALID_ID can be used.

**const, uint64_t: MV_SUPPORTED_MSRS_T_SIZE**
| Value | Description |
| :---- | :---------- |
| 0x400 | Defines the total number of bytes defining which MSRs are supported in a range |

**struct: mv_supported_msrs_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| range1 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x0 | 0x400 bytes | Defines supported MSRs 0x00000000 - 0x00001FFF |
| range2 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x400 | 0x400 bytes | Defines supported MSRs 0xC0000000 - 0xC0001FFF |
| range3 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x800 | 0x400 bytes | Defines supported MSRs 0xC0010000 - 0xC0011FFF |

Each bit in the mv_supported_msrs_t corresponds with an MSR. If the MSR is supported, it's associated bit is enabled.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_SUPPORTED_MSRS_GET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the hypercall index for mv_vm_op_supported_msrs_get |

### 6.11.4. mv_vm_op_supported_msrs_set, OP=0x2, IDX=0xA

This hypercall will return a mv_supported_msrs_t located in the shared page associated with the PP the caller is calling from that defines which MSRs MicroV allows the caller to call mv_vps_op_set_msr on. The result will always be a subset of the results of mv_vm_op_supported_msrs.

Note that the requested VM can either be MV_ROOT_VMID, a guest VMID, or MV_INVALID_ID. If MV_ROOT_VMID is provided, mv_vm_op_supported_msrs_set will return the supported MSRs for the root VM. If a guest VMID or MV_INVALID_ID is provided, mv_vm_op_supported_msrs_set will return the supported MSRs for any guest VM, meaning all guest VMs share the same supported MSRs. If a guest VMID is not available yet, MV_INVALID_ID can be used.

**const, uint64_t: MV_SUPPORTED_MSRS_T_SIZE**
| Value | Description |
| :---- | :---------- |
| 0x400 | Defines the total number of bytes defining which MSRs are supported in a range |

**struct: mv_supported_msrs_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| range1 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x0 | 0x400 bytes | Defines supported MSRs 0x00000000 - 0x00001FFF |
| range2 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x400 | 0x400 bytes | Defines supported MSRs 0xC0000000 - 0xC0001FFF |
| range3 | uint8_t[MV_SUPPORTED_MSRS_T_SIZE] | 0x800 | 0x400 bytes | Defines supported MSRs 0xC0010000 - 0xC0011FFF |

Each bit in the mv_supported_msrs_t corresponds with an MSR. If the MSR is supported, it's associated bit is enabled.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_SUPPORTED_MSRS_SET_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000A | Defines the hypercall index for mv_vm_op_supported_msrs_set |















## 6.10. VM Hypercalls

### 6.10.1. mv_vm_op_create_vm, OP=0x2, IDX=0x0

This hypercall tells MicroV to create a VM and return its ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VMID of the newly created VM |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_CREATE_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_vm_op_create_vm |

### 6.10.2. mv_vm_op_destroy_vm, OP=0x2, IDX=0x1

This hypercall tells MicroV to destroy a VM given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The VMID of the VM to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VM_OP_DESTROY_VM_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_vm_op_destroy_vm |

### 6.10.3. mv_vm_op_vmid, OP=0x2, IDX=0x2

This hypercall returns the ID of the VM that executed this hypercall.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting VMID |

**const, uint64_t: MV_VM_OP_VMID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the hypercall index for mv_vm_op_vmid |

### 6.10.4. mv_vm_op_mmio_map, OP=0x2, IDX=0x3

This hypercall is used to map a range of physically discontiguous guest memory from one VM to another. The caller must provide the ID of the source VM and an MDL describing the memory to map from, and the ID of the destination VM and an MDL describing the memory to map to. MicroV will convert the GPAs described by the source MDL to SPAs. MicroV will then map these SPAs into the GPAs described by the destination MDL. This hypercall only modifies the destination's view of physical memory (meaning the destination's view of guest virtual memory is not modified by this hypercall). The source VM's view of guest physical and guest virtual memory is not modified.

By default, this hypercall maps memory into the destination as read-only, MV_GPA_FLAG_WRITE_BACK unless flags are added to the destination MDL entries. Source MDL entry flags are ignored.

In addition to the input registers, the caller must also fill out an mv_map_t located in the shared page associated with the PP the caller is calling from.

**const, uint64_t: MV_MAP_T_MAX_MDL_ENTRIES_SRC**
| Value | Description |
| :---- | :---------- |
| 63 | Defines the max number of entries in the src's MDL |

**const, uint64_t: MV_MAP_T_MAX_MDL_ENTRIES_DST**
| Value | Description |
| :---- | :---------- |
| 63 | Defines the max number of entries in the dst's MDL |

**struct: mv_map_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| num_entries_src | uint64_t | 0x0 | 8 bytes | The number src entires |
| reserved1 | uint64_t | 0x8 | 8 bytes | REVI |
| reserved2 | uint64_t | 0x10 | 8 bytes | REVI |
| reserved3 | uint64_t | 0x18 | 8 bytes | REVI |
| entries_src | mv_mdl_entry_t[MV_MAP_T_MAX_MDL_ENTRIES_SRC] | 0x20 | 0x7E0 | Each entry in the MDL |
| num_entries_dst | uint64_t | 0x800 | 8 bytes | The number dst entires |
| reserved1 | uint64_t | 0x808 | 8 bytes | REVI |
| reserved2 | uint64_t | 0x810 | 8 bytes | REVI |
| reserved3 | uint64_t | 0x818 | 8 bytes | REVI |
| entries_dst | mv_mdl_entry_t[MV_MAP_T_MAX_MDL_ENTRIES_DST] | 0x820 | 0x7E0 | Each entry in the MDL |

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the source VM |
| REG1 | 63:16 | REVZ |
| REG2 | 15:0 | The ID of the destination VM |
| REG2 | 63:16 | REVZ |

**const, uint64_t: MV_VM_OP_MAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000003 | Defines the hypercall index for mv_vm_op_mmio_map |

### 6.10.5. mv_vm_op_mmio_unmap, OP=0x2, IDX=0x4

This hypercall is used to unmap a range of physically discontiguous guest memory. The caller must provide the ID of the VM and an MDL describing the memory to unmap. This hypercall only modifies the VM's view of physical memory (meaning the VM's view of guest virtual memory is not modified by this hypercall). MDL entry flags are ignored.

In addition to the input registers, the caller must also fill out an mv_unmap_t located in the shared page associated with the PP the caller is calling from.

**const, uint64_t: MV_UNMAP_T_MAX_MDL_ENTRIES**
| Value | Description |
| :---- | :---------- |
| 127 | Defines the max number of entries in the src's MDL |

**struct: mv_unmap_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| num_entries | uint64_t | 0x0 | 8 bytes | The number entires |
| reserved1 | uint64_t | 0x8 | 8 bytes | REVI |
| reserved2 | uint64_t | 0x10 | 8 bytes | REVI |
| reserved3 | uint64_t | 0x18 | 8 bytes | REVI |
| entries | mv_mdl_entry_t[MV_UNMAP_T_MAX_MDL_ENTRIES] | 0x20 | 0xFE0 | Each entry in the MDL |

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VM whose memory to unmap |
| REG1 | 63:16 | REVZ |

**const, uint64_t: MV_VM_OP_UNMAP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000004 | Defines the hypercall index for mv_vm_op_mmio_unmap |

### 6.10.5. mv_vm_op_mmio_trap, OP=0x2, IDX=0x4



### 6.11.4. mv_vm_op_create_irqchip, OP=0x2, IDX=0xA
### 6.11.4. mv_vm_op_get_irqchip, OP=0x2, IDX=0xA
### 6.11.4. mv_vm_op_set_irqchip, OP=0x2, IDX=0xA
### 6.11.4. mv_vm_op_get_irq_mode, OP=0x2, IDX=0xA
### 6.11.4. mv_vm_op_set_irq_mode, OP=0x2, IDX=0xA
### 6.11.4. mv_vm_op_get_irq_routing, OP=0x2, IDX=0xA
### 6.11.4. mv_vm_op_set_irq_routing, OP=0x2, IDX=0xA
### 6.11.4. mv_vm_op_queue_irq, OP=0x2, IDX=0xA

## 6.11. VP Hypercalls

### 6.11.1. mv_vp_op_create_vp, OP=0x3, IDX=0x0

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
| 0x0000000000000000 | Defines the hypercall index for mv_vp_op_create_vp |

### 6.11.2. mv_vp_op_destroy_vp, OP=0x3, IDX=0x1

This hypercall tells MicroV to destroy a VP given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The VPID of the VP to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VP_OP_DESTROY_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_vp_op_destroy_vp |

### 6.11.3. mv_vp_op_vmid, OP=0x3, IDX=0x2

This hypercall returns the ID of the VM the requested VP is assigned to.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The VPID of the VP to query |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting VMID |

**const, uint64_t: MV_VP_OP_VMID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the hypercall index for mv_vp_op_vmid |

### 6.11.4. mv_vp_op_vpid, OP=0x3, IDX=0x3

This hypercall returns the ID of the VP that executed this hypercall.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting VPID |

**const, uint64_t: MV_VP_OP_VPID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the hypercall index for mv_vp_op_vpid |

## 6.12. VPS Hypercalls

### 6.11.4. mv_vps_op_cpuid_get, OP=0x4, IDX=0x4
### 6.11.4. mv_vps_op_cpuid_set, OP=0x4, IDX=0x5
### 6.11.4. mv_vps_op_reg_get, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_reg_set, OP=0x4, IDX=0x7
### 6.11.4. mv_vps_op_reg_trap, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_regs_general_get, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_regs_general_set, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_regs_system_get, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_regs_system_set, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_regs_debug_get, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_regs_debug_set, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_fpu_get, OP=0x4, IDX=0xA
### 6.11.4. mv_vps_op_fpu_set, OP=0x4, IDX=0xB
### 6.11.4. mv_vps_op_xsave_get, OP=0x4, IDX=0xC
### 6.11.4. mv_vps_op_xsave_set, OP=0x4, IDX=0xD
### 6.11.4. mv_vps_op_lapic_get_all, OP=0x4, IDX=0xC
### 6.11.4. mv_vps_op_lapic_set_all, OP=0x4, IDX=0xD
### 6.11.4. mv_vps_op_lapic_get_reg, OP=0x4, IDX=0xC
### 6.11.4. mv_vps_op_lapic_set_reg, OP=0x4, IDX=0xD
### 6.11.4. mv_vps_op_lapic_add, OP=0x4, IDX=0xC
### 6.11.4. mv_vps_op_lapic_top, OP=0x4, IDX=0xD
### 6.11.4. mv_vps_op_lapic_eoi, OP=0x4, IDX=0xD
### 6.11.4. mv_vps_op_status_get, OP=0x4, IDX=0x12
### 6.11.4. mv_vps_op_status_set, OP=0x4, IDX=0x12
### 6.11.4. mv_vps_op_status_set, OP=0x4, IDX=0x12
### 6.12.1. mv_vps_op_run, OP=0x8, IDX=0x2





























### 6.11.1. mv_vps_op_create_vps, OP=0x4, IDX=0x0

This hypercall tells MicroV to create a VPS given the ID of the VP the VPS will be assigned to. Upon success, this hypercall returns the ID of the newly created VPS.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VP to assign the newly created VPS to |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 15:0 | The resulting VPSID of the newly created VPS |
| REG0 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_CREATE_VPS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000000 | Defines the hypercall index for mv_vps_op_create_vps |

### 6.11.2. mv_vps_op_destroy_vps, OP=0x4, IDX=0x1

This hypercall tells MicroV to destroy a VPS given an ID.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to destroy |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_DESTROY_VPS_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000001 | Defines the hypercall index for mv_vps_op_destroy_vps |

### 6.11.3. mv_vps_op_vpid, OP=0x4, IDX=0x2

This hypercall returns the ID of the VP the requested VPS is assigned to.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The VPSID of the VPS to query |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting VPID |

**const, uint64_t: MV_VPS_OP_VPID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the hypercall index for mv_vps_op_vpid |

### 6.11.4. mv_vps_op_vpsid, OP=0x4, IDX=0x3

This hypercall returns the ID of the VPS that executed this hypercall.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting VPSID |

**const, uint64_t: MV_VPS_OP_VPSID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000003 | Defines the hypercall index for mv_vps_op_vpsid |

### 6.11.4. mv_vps_op_get_cpuid, OP=0x4, IDX=0x4

Given the initial leaf (EAX) and subleaf (ECX), this hypercall will return the resulting values of EAX, EBX, ECX and EDX from the point of view of the requested VPS.

In addition to the input registers, the caller must also fill out an mv_cpuid_t located in the shared page associated with the PP the caller is calling from.

**struct: mv_cpuid_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| leaf | uint32_t | 0x0 | 4 bytes | The value of EAX before calling cpuid |
| subleaf | uint32_t | 0x4 | 4 bytes | The value of ECX before calling cpuid |
| eax | uint32_t | 0x8 | 4 bytes | The value of EAX after calling cpuid |
| ebx | uint32_t | 0xC | 4 bytes | The value of EBX after calling cpuid |
| ecx | uint32_t | 0x10 | 4 bytes | The value of ECX after calling cpuid |
| edx | uint32_t | 0x14 | 4 bytes | The value of EDX after calling cpuid |

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_GET_CPUID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000004 | Defines the hypercall index for mv_vps_op_get_cpuid |

### 6.11.4. mv_vps_op_set_cpuid, OP=0x4, IDX=0x5

Given the initial leaf (EAX) and subleaf (ECX), this hypercall will set the resulting values of EAX, EBX, ECX and EDX from the point of view of the requested VPS. Note that MicroV is not required to accept all values set by this hypercall. To determine how MicroV has configured CPUID, a call to mv_vps_op_get_cpuid should be made. Software is free to attempt to enable/disable or change the results of mv_vps_op_get_cpuid using mv_vps_op_set_cpuid but MicroV is also free to deny any and all changes. A call to mv_vps_op_get_cpuid can be made to determine which changes were accepted.

In addition to the input registers, the caller must also fill out an mv_cpuid_t located in the shared page associated with the PP the caller is calling from.

**struct: mv_cpuid_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| leaf | uint32_t | 0x0 | 4 bytes | The value of EAX before calling cpuid |
| subleaf | uint32_t | 0x4 | 4 bytes | The value of ECX before calling cpuid |
| eax | uint32_t | 0x8 | 4 bytes | The value of EAX after calling cpuid |
| ebx | uint32_t | 0xC | 4 bytes | The value of EBX after calling cpuid |
| ecx | uint32_t | 0x10 | 4 bytes | The value of ECX after calling cpuid |
| edx | uint32_t | 0x14 | 4 bytes | The value of EDX after calling cpuid |

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to set |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_SET_CPUID_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000005 | Defines the hypercall index for mv_vps_op_set_cpuid |

### 6.11.4. mv_vps_op_get_reg, OP=0x4, IDX=0x6

Given an mv_reg_t, this hypercall will return the value of the requested register. Use mv_vm_op_supported_regs_get to determine which registers are allowed by the calling VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to query |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | An mv_reg_t describing the register to query |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting value of the requested register |

**const, uint64_t: MV_VPS_OP_GET_REG_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000006 | Defines the hypercall index for mv_vps_op_get_reg |

### 6.11.4. mv_vps_op_set_reg, OP=0x4, IDX=0x7

Given an mv_reg_t, this hypercall will set the value of the requested register. Use mv_vm_op_supported_regs_set to determine which registers are allowed by the calling VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to set |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | An mv_reg_t describing the register to set |
| REG3 | 63:0 | The value to set the requested register to |

**const, uint64_t: MV_VPS_OP_SET_REG_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000007 | Defines the hypercall index for mv_vps_op_set_reg |


### 6.11.4. mv_vps_op_get_general_regs, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_set_general_regs, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_get_system_regs, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_set_system_regs, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_get_debug_regs, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_set_debug_regs, OP=0x4, IDX=0x6

### 6.11.4. mv_vps_op_get_msr, OP=0x4, IDX=0x8

Given an MSR index, this hypercall will return the value of the requested MSR. Use mv_vm_op_supported_msrs_get to determine which MSRs are allowed by the calling VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to query |
| REG1 | 63:16 | REVI |
| REG2 | 31:0 | An MSR index describing the MSR to query |
| REG2 | 63:32 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting value of the requested MSR |

**const, uint64_t: MV_VPS_OP_GET_MSR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000008 | Defines the hypercall index for mv_vps_op_get_msr |

### 6.11.4. mv_vps_op_set_msr, OP=0x4, IDX=0x9

Given an MSR index, this hypercall will set the value of the requested MSR. Use mv_vm_op_supported_msrs_set to determine which MSRs are allowed by the calling VM.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to set |
| REG1 | 63:16 | REVI |
| REG2 | 31:0 | An MSR index describing the MSR to set |
| REG2 | 63:32 | REVI |
| REG3 | 63:0 | The value to set the requested MSR to |

**const, uint64_t: MV_VPS_OP_SET_MSR_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000009 | Defines the hypercall index for mv_vps_op_set_msr |

### 6.11.4. mv_vps_op_get_msrs, OP=0x4, IDX=0x8
### 6.11.4. mv_vps_op_set_msrs, OP=0x4, IDX=0x8

### 6.11.4. mv_vps_op_trap_reg, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_trap_msr, OP=0x4, IDX=0x6
### 6.11.4. mv_vps_op_trap_io, OP=0x4, IDX=0x6


### 6.11.4. mv_vps_op_get_fpu, OP=0x4, IDX=0xA

This hypercall will return VPS's FXSAVE region located in the shared page associated with the PP the caller is calling from. The format of the FXSAVE region is defined by the Intel and AMD manuals. This hypercall may not always be allowed, or certain values in the FXSAVE region might be set to 0.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_GET_FPU_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000A | Defines the hypercall index for mv_vps_op_get_fpu |

### 6.11.4. mv_vps_op_set_fpu, OP=0x4, IDX=0xB

This hypercall will set VPS's FXSAVE region located in the shared page associated with the PP the caller is calling from. The format of the FXSAVE region is defined by the Intel and AMD manuals. This hypercall may not always be allowed, or certain values in the FXSAVE region might be ignored.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to set |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_SET_FPU_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000B | Defines the hypercall index for mv_vps_op_set_fpu |

### 6.11.4. mv_vps_op_get_xsave, OP=0x4, IDX=0xC

This hypercall will return VPS's XSAVE region located in the shared page associated with the PP the caller is calling from. The format of the XSAVE region is defined by the Intel and AMD manuals. This hypercall may not always be allowed, or certain values in the XSAVE region might be set to 0.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to query |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_GET_XSAVE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000C | Defines the hypercall index for mv_vps_op_get_xsave |

### 6.11.4. mv_vps_op_set_xsave, OP=0x4, IDX=0xD

This hypercall will set VPS's XSAVE region located in the shared page associated with the PP the caller is calling from. The format of the XSAVE region is defined by the Intel and AMD manuals. This hypercall may not always be allowed, or certain values in the XSAVE region might be ignored.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to set |
| REG1 | 63:16 | REVI |

**const, uint64_t: MV_VPS_OP_SET_XSAVE_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x000000000000000D | Defines the hypercall index for mv_vps_op_set_xsave |

### 6.11.4. mv_vps_op_queue_interrupt, OP=0x4, IDX=0x10

Queues an interrupt to be injected into the VPS when possible.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to set |
| REG1 | 63:16 | REVI |
| REG2 | 63:0 | The interrupt vector to queue |

**const, uint64_t: MV_VPS_OP_QUEUE_INTERRUPT_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000010 | Defines the hypercall index for mv_vps_op_queue_interrupt |

### 6.11.4. mv_vps_op_get_tsc_khz, OP=0x4, IDX=0x11

Returns the VPS's TSC frequency in KHz.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to query |
| REG1 | 63:16 | REVI |

**Output:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | The resulting TSC frequency in KHz |

**const, uint64_t: MV_VPS_OP_GET_TSC_KHZ_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000011 | Defines the hypercall index for mv_vps_op_get_tsc_khz |

### 6.11.4. mv_vps_op_set_tsc_khz, OP=0x4, IDX=0x12

Set the VPS's TSC frequency in KHz.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The ID of the VPS to query |
| REG1 | 63:16 | REVI |
| REG0 | 63:0 | The TSC frequency in KHz to set the VPS to |

**const, uint64_t: MV_VPS_OP_SET_TSC_KHZ_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000012 | Defines the hypercall index for mv_vps_op_set_tsc_khz |

### 6.11.4. mv_vps_op_get_mp_state, OP=0x4, IDX=0x12
### 6.11.4. mv_vps_op_set_mp_state, OP=0x4, IDX=0x12
### 6.11.4. mv_vps_op_get_lapic, OP=0x4, IDX=0x12
### 6.11.4. mv_vps_op_set_lapic, OP=0x4, IDX=0x12

### 6.12.1. mv_vps_op_run, OP=0x8, IDX=0x2

This hypercall is used to run a guest VPS. The only VM that is allowed to execute this hypercall is the root VM.

In addition to the input registers, the caller must also fill out an mv_run_t located in the shared page associated with the PP the caller is calling from. When this hypercall returns, MicroV will have filled in mv_run_t with information needed to handle the return condition, meaning mv_run_t is used for both input and output.

**struct: mv_run_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| exit_on_interrupt_window | uint8_t | 0x0 | 1 byte | returns on the next interrupt window |
| reserved1 | uint8_t[15] | 0x1 | 15 bytes | REVI |
| exit_reason | uint64_t | 0x10 | 8 bytes | stores the reason for returning |
| rflags | uint64_t | 0x18 | 8 byte | the value of rflags |






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

**const, uint64_t: MV_VP_MANAGEMENT_OP_RUN_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the hypercall index for mv_vp_run_vp |

When mv_vp_run_vp returns, a return reason is provided which are defiined as follows
