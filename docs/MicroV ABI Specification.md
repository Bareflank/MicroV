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
    - [6.7.3. Virtual Machines](#673-virtual-machines)
    - [6.7.4. Virtual Processors](#674-virtual-processors)
    - [6.7.5. Virtual Processor State](#675-virtual-processor-state)
  - [6.8. Debug Hypercalls](#68-debug-hypercalls)
    - [6.8.1. mv_debug_op_out, OP=0x0, IDX=0x0](#681-mv_debug_op_out-op0x0-idx0x0)
  - [6.9. Handle Hypercalls](#69-handle-hypercalls)
    - [6.9.1. mv_handle_op_open_handle, OP=0x1, IDX=0x0](#691-mv_handle_op_open_handle-op0x1-idx0x0)
    - [6.9.2. mv_handle_op_close_handle, OP=0x1, IDX=0x1](#692-mv_handle_op_close_handle-op0x1-idx0x1)
  - [6.10. VM Hypercalls](#610-vm-hypercalls)
    - [2.11.2. mv_vm_op_create_vm, OP=0x2, IDX=0x0](#2112-mv_vm_op_create_vm-op0x2-idx0x0)
    - [2.11.3. mv_vm_op_destroy_vm, OP=0x2, IDX=0x1](#2113-mv_vm_op_destroy_vm-op0x2-idx0x1)
    - [6.10.3. mv_vm_op_vmid, OP=0x2, IDX=0x2](#6103-mv_vm_op_vmid-op0x2-idx0x2)
    - [6.10.4. mv_vm_op_map_mdl, OP=0x2, IDX=0x1](#6104-mv_vm_op_map_mdl-op0x2-idx0x1)
    - [6.10.5. mv_vm_op_unmap_mdl, OP=0x2, IDX=0x2](#6105-mv_vm_op_unmap_mdl-op0x2-idx0x2)
    - [6.10.6. mv_vm_op_set_gpa_flags_mdl, OP=0x2, IDX=0x3](#6106-mv_vm_op_set_gpa_flags_mdl-op0x2-idx0x3)
  - [6.11. VP Hypercalls](#611-vp-hypercalls)
    - [2.12.2. mv_vp_op_create_vp, OP=0x3, IDX=0x0](#2122-mv_vp_op_create_vp-op0x3-idx0x0)
    - [2.12.3. mv_vp_op_destroy_vp, OP=0x3, IDX=0x1](#2123-mv_vp_op_destroy_vp-op0x3-idx0x1)
    - [6.10.3. mv_vp_op_vmid, OP=0x2, IDX=0x2](#6103-mv_vp_op_vmid-op0x2-idx0x2)
    - [6.10.3. mv_vp_op_vpid, OP=0x2, IDX=0x3](#6103-mv_vp_op_vpid-op0x2-idx0x3)
  - [6.12. VPS Hypercalls](#612-vps-hypercalls)
    - [6.13.3. mv_vps_run_vp, OP=0x8, IDX=0x2](#6133-mv_vps_run_vp-op0x8-idx0x2)

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
| 3 | MV_GPA_FLAG_DONATE | Indicates the GPA should be donated |
| 4 | MV_GPA_FLAG_ZOMBIE | Indicates crashed source VMs become zombified |
| 8 | MV_GPA_FLAG_UNCACHEABLE | Indicates the GPA is mapped as UC |
| 9 | MV_GPA_FLAG_UNCACHEABLE_MINUS | Indicates the GPA is mapped as UC- |
| 10 | MV_GPA_FLAG_WRITE_COMBINING | Indicates the GPA is mapped as WC |
| 11 | MV_GPA_FLAG_WRITE_COMBINING_PLUS | Indicates the GPA is mapped as WC+ |
| 12 | MV_GPA_FLAG_WRITE_THROUGH | Indicates the GPA is mapped as WT |
| 13 | MV_GPA_FLAG_WRITE_BACK | Indicates the GPA is mapped as WB |
| 14 | MV_GPA_FLAG_WRITE_PROTECTED | Indicates the GPA is mapped as WP |
| 63:15 | revz | REVZ |

### 1.6.5. Memory Descriptor Lists

A memory descriptor list describes a discontiguous region of guest physical memory. Memory descriptor lists are used to describe for example an e820 map, or a region of memory that should be mapped, unmapped or copied by the hypercalls described in this specification.

An MDL consists of a 4k page of memory, capable of storing MV_MDL_MAP_MAX_NUM_ENTRIES, with each entry describing one contiguous region of guest physical memory. By combining multiple entries into a list, software is capable of describing a discontiguous region of guest physical memory.

**const, uint64_t: MV_MDL_MAP_MAX_NUM_ENTRIES**
| Value | Description |
| :---- | :---------- |
| 169 | Defines the max number of entries in an MDL |

Each entry in the MDL defines a contiguous region of the guest's physical memory, and each entry in the MDL is defined as follows:

**struct: mv_mdl_entry_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| gpa | uint64_t | 0x0 | 8 bytes | The starting gpa of the memory range |
| size | uint64_t | 0x8 | 8 bytes | The number of bytes in the memory range |
| flags | uint64_t | 0x10 | 8 bytes | Flags used to describe the memory range as well as operations to perform on the memory range depending on the hypercall |

The format of the MDL in the 4k page is as follows:

**struct: mv_mdl_t**
| Name | Type | Offset | Size | Description |
| :--- | :--- | :----- | :--- | :---------- |
| num_entries | uint64_t | 0x0 | 8 bytes | The number of entries in the MDL |
| next | uint64_t | 0x8 | 8 bytes | The GPA of the next mv_mdl_t in the list |
| revz | uint64_t | 0x18 | 24 bytes | REVZ |
| entries | mv_mdl_entry_t[MV_MDL_MAP_MAX_NUM_ENTRIES] | 0x28 | 4056 bytes | Each entry in the MDL |

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

### 6.7.3. Virtual Machines

**const, uint64_t: MV_VM_OP**
| Value | Description |
| :---- | :---------- |
| 0x764D000000020000 | Defines the hypercall opcode for mv_vm_op hypercalls |

**const, uint64_t: MV_VM_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000020000 | Defines the hypercall opcode for mv_vm_op hypercalls with no signature |

### 6.7.4. Virtual Processors

**const, uint64_t: MV_VP_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000030000 | Defines the hypercall opcode for mv_vp_op hypercalls |

**const, uint64_t: MV_VP_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000030000 | Defines the hypercall opcode for mv_vp_op hypercalls with no signature |

### 6.7.5. Virtual Processor State

**const, uint64_t: MV_VPS_OP_VAL**
| Value | Description |
| :---- | :---------- |
| 0x764D000000040000 | Defines the hypercall opcode for mv_vps_op hypercalls |

**const, uint64_t: MV_VPS_OP_NOSIG_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000040000 | Defines the hypercall opcode for mv_vps_op hypercalls with no signature |

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

## 6.10. VM Hypercalls

### 2.11.2. mv_vm_op_create_vm, OP=0x2, IDX=0x0

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

### 2.11.3. mv_vm_op_destroy_vm, OP=0x2, IDX=0x1

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

### 6.10.4. mv_vm_op_map_mdl, OP=0x2, IDX=0x1

This hypercall is used to map a range of physically discontiguous memory. The caller must provide the source VMID (i.e., the VM to map memory from), and a destination VMID (i.e., the VM to map memory to). In addition, the caller must provide the source GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory to map from), and the destination GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory to map to). Finally, the caller must provide flags associated with how memory should be mapped and the total number of bytes between the source MDL and the destination MDL must be the same.

**Donate Vs. Shared:**
If MV_GPA_FLAG_DONATE is set, the memory will be donated from the source VM to the destination VM, meaning the source VM will no longer have access to the donated memory once the hypercall is complete.

If MV_GPA_FLAG_DONATE is not set (the default), the source memory range is mapped into both the source and destination, meaning both VMs will share the same system physical memory range from the source VM, allowing them to pass data between them. Sharing memory between two different VMs introduces a dependency between these VMs. If the source VM should crash, the memory being shared with the destination VM becomes a problem. MicroV provides two different approaches to handling this situation. By default, if the source VM crashes, MicroV will also kill the destination VM by instructing the root VM to execute mv_vp_op_kill on the destination VM before destroying the source VM. This default behavior prevents memory leaks, and other potential security issues. If the destination VM is the root VM or if this hypercall is called with MV_GPA_FLAG_ZOMBIE, the source VM will not be destroyed and instead will remain as a zombie until the destination VM finally unmaps the memory, allowing the source VM to finally be destroyed.

**Permissions:**
If MV_GPA_FLAG_DONATE is set, the destination VM's memory is set to read-only unless MV_GPA_FLAG_WRITE_ACCESS and or MV_GPA_FLAG_EXECUTE_ACCESS provided.

If MV_GPA_FLAG_DONATE is not set (the default), the source VM's memory is always set to read/write/execute and the destination VM's memory is set to read-only unless MV_GPA_FLAG_WRITE_ACCESS and or MV_GPA_FLAG_EXECUTE_ACCESS provided.

Note that in both cases, these permissions only apply to MicroV's use of second-level paging (EPT for Intel and NPT for AMD). The OS in each VM can further restrict permissions of this memory as needed.

**Caching:**
If MV_GPA_FLAG_DONATE is set, the destination VM's memory is set to MV_GPA_FLAG_WRITE_BACK unless another cachability flag is provided.

If MV_GPA_FLAG_DONATE is not set, the source VM's memory is always set to MV_GPA_FLAG_WRITE_BACK and the destination VM's memory is set to MV_GPA_FLAG_WRITE_BACK unless another cachability flag is provided.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The source VMID |
| REG1 | 63:16 | REVZ |
| REG2 | 63:12 | The source GPA of the MDL |
| REG2 | 11:0 | REVZ |
| REG3 | 15:0 | The destination VMID |
| REG3 | 63:16 | REVZ |
| REG4 | 63:12 | The destination GPA of the MDL |
| REG4 | 11:0 | REVZ |
| REG5 | 63:0 | The GPA flags used to determine how to map the range |

**const, uint64_t: MV_VM_OP_MAP_MDL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000001 | Defines the hypercall index for mv_vm_op_map_mdl |

### 6.10.5. mv_vm_op_unmap_mdl, OP=0x2, IDX=0x2

This hypercall is used to unmap a previously mapped range of physically discontiguous memory. The caller must provide the source VMID (i.e., the VM the memory was mapped from), and a destination VMID (i.e., the VM the memory was mapped to). In addition, the caller must provide the source GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory that was mapped from the source), and the destination GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory to unmap from the destination). Finally, the total number of bytes between the source MDL and the destination MDL must be the same.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The source VMID |
| REG1 | 63:16 | REVZ |
| REG2 | 63:12 | The source GPA of the MDL |
| REG2 | 11:0 | REVZ |
| REG3 | 15:0 | The destination VMID |
| REG3 | 63:16 | REVZ |
| REG4 | 63:12 | The destination GPA of the MDL |
| REG4 | 11:0 | REVZ |

**const, uint64_t: MV_VM_OP_UNMAP_MDL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000002 | Defines the hypercall index for mv_vm_op_unmap_mdl |

### 6.10.6. mv_vm_op_set_gpa_flags_mdl, OP=0x2, IDX=0x3

This hypercall is used to change the map a range of physically discontiguous memory. The caller must provide the source VMID (i.e., the VM to map memory from), and a destination VMID (i.e., the VM to map memory to). In addition, the caller must provide the source GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory to map from), and the destination GPA of an MDL (i.e., the GPA of an MDL that describes the range of memory to map to). Finally, the caller must provide flags associated with how memory should be mapped and the total number of bytes between the source MDL and the destination MDL must be the same.

**Donate Vs. Shared:**
If MV_GPA_FLAG_DONATE is set, the memory will be donated from the source VM to the destination VM, meaning the source VM will no longer have access to the donated memory once the hypercall is complete.

If MV_GPA_FLAG_DONATE is not set (the default), the source memory range is mapped into both the source and destination, meaning both VMs will share the same system physical memory range from the source VM, allowing them to pass data between them. Sharing memory between two different VMs introduces a dependency between these VMs. If the source VM should crash, the memory being shared with the destination VM becomes a problem. MicroV provides two different approaches to handling this situation. By default, if the source VM crashes, MicroV will also kill the destination VM by instructing the root VM to execute mv_vp_op_kill on the destination VM before destroying the source VM. This default behavior prevents memory leaks, and other potential security issues. If the destination VM is the root VM or if this hypercall is called with MV_GPA_FLAG_ZOMBIE, the source VM will not be destroyed and instead will remain as a zombie until the destination VM finally unmaps the memory, allowing the source VM to finally be destroyed.

**Permissions:**
If MV_GPA_FLAG_DONATE is set, the destination VM's memory is set to read-only unless MV_GPA_FLAG_WRITE_ACCESS and or MV_GPA_FLAG_EXECUTE_ACCESS provided.

If MV_GPA_FLAG_DONATE is not set (the default), the source VM's memory is always set to read/write/execute and the destination VM's memory is set to read-only unless MV_GPA_FLAG_WRITE_ACCESS and or MV_GPA_FLAG_EXECUTE_ACCESS provided.

Note that in both cases, these permissions only apply to MicroV's use of second-level paging (EPT for Intel and NPT for AMD). The OS in each VM can further restrict permissions of this memory as needed.

**Caching:**
If MV_GPA_FLAG_DONATE is set, the destination VM's memory is set to MV_GPA_FLAG_WRITE_BACK unless another cachability flag is provided.

If MV_GPA_FLAG_DONATE is not set, the source VM's memory is always set to MV_GPA_FLAG_WRITE_BACK and the destination VM's memory is set to MV_GPA_FLAG_WRITE_BACK unless another cachability flag is provided.

**Input:**
| Register Name | Bits | Description |
| :------------ | :--- | :---------- |
| REG0 | 63:0 | Set to the result of mv_handle_op_open_handle |
| REG1 | 15:0 | The source VMID |
| REG1 | 63:16 | REVZ |
| REG2 | 63:12 | The source GPA of the MDL |
| REG2 | 11:0 | REVZ |
| REG3 | 15:0 | The destination VMID |
| REG3 | 63:16 | REVZ |
| REG4 | 63:12 | The destination GPA of the MDL |
| REG4 | 11:0 | REVZ |
| REG5 | 63:0 | The GPA flags used to determine how to map the range |

**const, uint64_t: MV_VM_OP_MAP_MDL_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x00000000000000003 | Defines the hypercall index for mv_vm_op_gpa_flags_mdl |

## 6.11. VP Hypercalls

### 2.12.2. mv_vp_op_create_vp, OP=0x3, IDX=0x0

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

### 2.12.3. mv_vp_op_destroy_vp, OP=0x3, IDX=0x1

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

### 6.10.3. mv_vp_op_vmid, OP=0x2, IDX=0x2

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

### 6.10.3. mv_vp_op_vpid, OP=0x2, IDX=0x3

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

mv_vps_op_get_cpuid
mv_vps_op_set_cpuid

mv_vps_op_get_reg
mv_vps_op_set_reg

mv_vps_op_get_msr
mv_vps_op_set_msr
mv_vps_op_get_supported_msrs
mv_vps_op_get_supported_feature_msrs

mv_vps_op_get_fpu
mv_vps_op_set_fpu
mv_vps_op_get_xsave
mv_vps_op_set_xsave

mv_vps_op_virt_to_phys

mv_vps_op_queue_irq

mv_vps_op_set_identity_map

mv_vps_op_get_tsc_khz

### 6.13.3. mv_vps_run_vp, OP=0x8, IDX=0x2

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

**const, uint64_t: MV_VP_MANAGEMENT_OP_RUN_VP_IDX_VAL**
| Value | Description |
| :---- | :---------- |
| 0x0000000000000002 | Defines the hypercall index for mv_vp_run_vp |

When mv_vp_run_vp returns, a return reason is provided which are defiined as follows

**enum, uint32_t: mv_vp_exit_t**
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

If mv_vp_exit_t_external_interrupt is returned, software should execute mv_vp_run_vp again as soon as possible. If mv_vp_exit_t_yield is returned, software should run mv_vp_run_vp again after sleeping for REG1 number of nanoseconds. If mv_vp_exit_t_retry is returned, software should execute mv_vp_run_vp again after yielding to the OS. Software could also use a backoff model, adding a sleep whose time increases as mv_vp_run_vp continues to return mv_vp_exit_t_retry. REG1 can be used to determine the uniqueness of mv_vp_exit_t_retry. mv_vp_exit_t_hlt tells software to destroy the VP and that software finished without any errors while mv_vp_exit_t_fault tells software to destroy the VP and that an error actually occured with the error code being returned in REG1. mv_vp_exit_t_sync_tsc tells software that it needs to synchronize the the wallclock and TSC.

```c
static inline uint64_t
mv_vp_run_vp(
    struct mv_handle_t const *const handle,    /* IN */
    uint64_t const vpid,                    /* IN */
    uint64_t *const reason,                 /* OUT */
    uint64_t *const arg)                    /* OUT */
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

    return _mv_vp_run_vp(handle->hndl, vpid, reason, arg);
}
```
