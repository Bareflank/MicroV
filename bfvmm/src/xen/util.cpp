//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <atomic>
#include <string.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <printv.h>
#include <xen/util.h>
#include <xen/vcpu.h>

#include <public/domctl.h>
#include <public/event_channel.h>
#include <public/grant_table.h>
#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>
#include <public/memory.h>
#include <public/physdev.h>
#include <public/platform.h>
#include <public/sysctl.h>
#include <public/vcpu.h>
#include <public/version.h>
#include <public/xsm/flask_op.h>

extern "C" uint64_t _rdrand64(uint64_t *data) noexcept;

#define HYPERCALL_RAX_MAX (__HYPERVISOR_arch_7 + 1)
static const char *hypercall_str[HYPERCALL_RAX_MAX] = {
    [__HYPERVISOR_set_trap_table] = "set_trap_table",
    [__HYPERVISOR_mmu_update] = "mmu_update",
    [__HYPERVISOR_set_gdt] = "set_gdt",
    [__HYPERVISOR_stack_switch] = "stack_switch",
    [__HYPERVISOR_set_callbacks] = "set_callbacks",
    [__HYPERVISOR_fpu_taskswitch] = "fpu_taskswitch",
    [__HYPERVISOR_sched_op_compat] = "sched_op_compat",
    [__HYPERVISOR_platform_op] = "platform_op",
    [__HYPERVISOR_set_debugreg] = "set_debugreg",
    [__HYPERVISOR_get_debugreg] = "get_debugreg",
    [__HYPERVISOR_update_descriptor] = "update_descriptor",
    [__HYPERVISOR_memory_op] = "memory_op",
    [__HYPERVISOR_multicall] = "multicall",
    [__HYPERVISOR_update_va_mapping] = "update_va_mapping",
    [__HYPERVISOR_set_timer_op] = "set_timer_op",
    [__HYPERVISOR_event_channel_op_compat] = "event_channel_op_compat",
    [__HYPERVISOR_xen_version] = "xen_version",
    [__HYPERVISOR_console_io] = "console_io",
    [__HYPERVISOR_physdev_op_compat] = "physdev_op_compat",
    [__HYPERVISOR_grant_table_op] = "grant_table_op",
    [__HYPERVISOR_vm_assist] = "vm_assist",
    [__HYPERVISOR_update_va_mapping_otherdomain] = "update_va_mapping_otherdomain",
    [__HYPERVISOR_iret] = "iret",
    [__HYPERVISOR_vcpu_op] = "vcpu_op",
    [__HYPERVISOR_set_segment_base] = "set_segment_base",
    [__HYPERVISOR_mmuext_op] = "mmuext_op",
    [__HYPERVISOR_xsm_op] = "xsm_op",
    [__HYPERVISOR_nmi_op] = "nmi_op",
    [__HYPERVISOR_sched_op] = "sched_op",
    [__HYPERVISOR_callback_op] = "callback_op",
    [__HYPERVISOR_xenoprof_op] = "xenoprof_op",
    [__HYPERVISOR_event_channel_op] = "event_channel_op",
    [__HYPERVISOR_physdev_op] = "physdev_op",
    [__HYPERVISOR_hvm_op] = "hvm_op",
    [__HYPERVISOR_sysctl] = "sysctl",
    [__HYPERVISOR_domctl] = "domctl",
    [__HYPERVISOR_kexec_op] = "kexec_op",
    [__HYPERVISOR_tmem_op] = "tmem_op",
    [__HYPERVISOR_argo_op] = "argo_op",
    [__HYPERVISOR_xenpmu_op] = "xenpmu_op",
    [__HYPERVISOR_dm_op] = "dm_op",
    [__HYPERVISOR_arch_0] = "arch_0",
    [__HYPERVISOR_arch_1] = "arch_1",
    [__HYPERVISOR_arch_2] = "arch_2",
    [__HYPERVISOR_arch_3] = "arch_3",
    [__HYPERVISOR_arch_4] = "arch_4",
    [__HYPERVISOR_arch_5] = "arch_5",
    [__HYPERVISOR_arch_6] = "arch_6",
    [__HYPERVISOR_arch_7] = "arch_7"
};

#define XENPF_MAX (XENPF_get_symbol + 1)
static const char *xenpf_str[XENPF_MAX] = {
    [XENPF_settime32] = "settime32",
    [XENPF_settime64] = "settime64",
    [XENPF_add_memtype] = "add_memtype",
    [XENPF_del_memtype] = "del_memtype",
    [XENPF_read_memtype] = "read_memtype",
    [XENPF_microcode_update] = "microcode_update",
    [XENPF_platform_quirk] = "platform_quirk",
    [XENPF_efi_runtime_call] = "efi_runtime_call",
    [XENPF_firmware_info] = "firmware_info",
    [XENPF_enter_acpi_sleep] = "enter_acpi_sleep",
    [XENPF_change_freq] = "change_freq",
    [XENPF_getidletime] = "getidletime",
    [XENPF_set_processor_pminfo] = "set_processor_pminfo",
    [XENPF_get_cpuinfo] = "get_cpuinfo",
    [XENPF_get_cpu_version] = "get_cpu_version",
    [XENPF_cpu_online] = "cpu_online",
    [XENPF_cpu_offline] = "cpu_offline",
    [XENPF_cpu_hotadd] = "cpu_hotadd",
    [XENPF_mem_hotadd] = "mem_hotadd",
    [XENPF_core_parking] = "core_parking",
    [XENPF_resource_op] = "resource_op",
    [XENPF_get_symbol] = "get_symbol"
};

#define XENMEM_MAX (XENMEM_acquire_resource + 1)
static const char *xenmem_str[XENMEM_MAX] = {
    [XENMEM_increase_reservation] = "increase_reservation",
    [XENMEM_decrease_reservation] = "decrease_reservation",
    [XENMEM_populate_physmap] = "populate_physmap",
    [XENMEM_exchange] = "exchange",
    [XENMEM_maximum_ram_page] = "maximum_ram_page",
    [XENMEM_current_reservation] = "current_reservation",
    [XENMEM_maximum_reservation] = "maximum_reservation",
    [XENMEM_maximum_gpfn] = "maximum_gpfn",
    [XENMEM_machphys_mfn_list] = "machphys_mfn_list",
    [XENMEM_machphys_compat_mfn_list] = "machphys_compat_mfn_list",
    [XENMEM_machphys_mapping] = "machphys_mapping",
    [XENMEM_add_to_physmap] = "add_to_physmap",
    [XENMEM_add_to_physmap_batch] = "add_to_physmap_batch",
    [XENMEM_remove_from_physmap] = "remove_from_physmap",
    [XENMEM_memory_map] = "memory_map",
    [XENMEM_machine_memory_map] = "machine_memory_map",
    [XENMEM_set_memory_map] = "set_memory_map",
    [XENMEM_set_pod_target] = "set_pod_target",
    [XENMEM_get_pod_target] = "get_pod_target",
    [XENMEM_get_sharing_freed_pages] = "get_sharing_freed_pages",
    [XENMEM_get_sharing_shared_pages] = "get_sharing_shared_pages",
    [XENMEM_paging_op] = "paging_op",
    [XENMEM_access_op] = "access_op",
    [XENMEM_sharing_op] = "sharing_op",
    [XENMEM_claim_pages] = "claim_pages",
    [XENMEM_reserved_device_memory_map] = "reserved_device_memory_map",
    [XENMEM_acquire_resource] = "acquire_resource",
    [XENMEM_get_vnumainfo] = "get_vnumainfo"
};

#define XENVER_MAX (XENVER_build_id + 1)
static const char *xenver_str[XENVER_MAX] = {
    [XENVER_version] = "version",
    [XENVER_extraversion] = "extraversion",
    [XENVER_compile_info] = "compile_info",
    [XENVER_capabilities] = "capabilities",
    [XENVER_changeset] = "changeset",
    [XENVER_platform_parameters] = "platform_parameters",
    [XENVER_get_features] = "get_features",
    [XENVER_pagesize] = "pagesize",
    [XENVER_guest_handle] = "guest_handle",
    [XENVER_commandline] = "commandline",
    [XENVER_build_id] = "build_id"
};

#define GNTTAB_MAX (GNTTABOP_cache_flush + 1)
static const char *gnttab_str[GNTTAB_MAX] = {
    [GNTTABOP_map_grant_ref] = "map_grant_ref",
    [GNTTABOP_unmap_grant_ref] = "unmap_grant_ref",
    [GNTTABOP_setup_table] = "setup_table",
    [GNTTABOP_dump_table] = "dump_table",
    [GNTTABOP_transfer] = "transfer",
    [GNTTABOP_copy] = "copy",
    [GNTTABOP_query_size] = "query_size",
    [GNTTABOP_unmap_and_replace] = "unmap_and_replace",
    [GNTTABOP_set_version] = "set_version",
    [GNTTABOP_get_status_frames] = "get_status_frames",
    [GNTTABOP_get_version] = "get_version",
    [GNTTABOP_swap_grant_ref] = "swap_grant_ref",
    [GNTTABOP_cache_flush] = "cache_flush"
};

#define VMASST_MAX (VMASST_TYPE_m2p_strict + 1)
static const char *vmasst_str[VMASST_MAX] = {
    [VMASST_TYPE_4gb_segments] = "4gb_segments",
    [VMASST_TYPE_4gb_segments_notify] = "4gb_segments_notify",
    [VMASST_TYPE_writable_pagetables] = "writable_pagetables",
    [VMASST_TYPE_pae_extended_cr3] = "pae_extended_cr3",
    [VMASST_TYPE_architectural_iopl] = "architectural_iopl",
    [VMASST_TYPE_runstate_update_flag] = "runstate_update_flag",
    [VMASST_TYPE_m2p_strict] = "m2p_strict"
};

#define VCPU_MAX (VCPUOP_register_vcpu_time_memory_area + 1)
static const char *vcpu_str[VCPU_MAX] = {
    [VCPUOP_initialise] = "initialise",
    [VCPUOP_up] = "up",
    [VCPUOP_down] = "down",
    [VCPUOP_is_up] = "is_up",
    [VCPUOP_get_runstate_info] = "get_runstate_info",
    [VCPUOP_register_runstate_memory_area] = "register_runstate_memory_area",
    [VCPUOP_set_periodic_timer] = "set_periodic_timer",
    [VCPUOP_stop_periodic_timer] = "stop_periodic_timer",
    [VCPUOP_set_singleshot_timer] = "set_singleshot_timer",
    [VCPUOP_stop_singleshot_timer] = "stop_singleshot_timer",
    [VCPUOP_register_vcpu_info] = "register_vcpu_info",
    [VCPUOP_send_nmi] = "send_nmi",
    [VCPUOP_get_physid] = "get_physid",
    [VCPUOP_register_vcpu_time_memory_area] = "register_vcpu_time_memory_area"
};

#define FLASK_MAX (FLASK_DEVICETREE_LABEL + 1)
static const char *flask_str[FLASK_MAX] = {
    [FLASK_LOAD] = "load",
    [FLASK_GETENFORCE] = "getenforce",
    [FLASK_SETENFORCE] = "setenforce",
    [FLASK_CONTEXT_TO_SID] = "context_to_sid",
    [FLASK_SID_TO_CONTEXT] = "sid_to_context",
    [FLASK_ACCESS] = "access",
    [FLASK_CREATE] = "create",
    [FLASK_RELABEL] = "relabel",
    [FLASK_USER] = "user",
    [FLASK_POLICYVERS] = "policyvers",
    [FLASK_GETBOOL] = "getbool",
    [FLASK_SETBOOL] = "setbool",
    [FLASK_COMMITBOOLS] = "commitbools",
    [FLASK_MLS] = "mls",
    [FLASK_DISABLE] = "disable",
    [FLASK_GETAVC_THRESHOLD] = "getavc_threshold",
    [FLASK_SETAVC_THRESHOLD] = "setavc_threshold",
    [FLASK_AVC_HASHSTATS] = "avc_hashstats",
    [FLASK_AVC_CACHESTATS] = "avc_cachestats",
    [FLASK_MEMBER] = "member",
    [FLASK_ADD_OCONTEXT] = "add_ocontext",
    [FLASK_DEL_OCONTEXT] = "del_ocontext",
    [FLASK_GET_PEER_SID] = "get_peer_sid",
    [FLASK_RELABEL_DOMAIN] = "relabel_domain",
    [FLASK_DEVICETREE_LABEL] = "devicetree_label"
};

#define EVTCHN_MAX (EVTCHNOP_set_priority + 1)
static const char *evtchn_str[EVTCHN_MAX] = {
    [EVTCHNOP_bind_interdomain] = "bind_interdomain",
    [EVTCHNOP_bind_virq] = "bind_virq",
    [EVTCHNOP_bind_pirq] = "bind_pirq",
    [EVTCHNOP_close] = "close",
    [EVTCHNOP_send] = "send",
    [EVTCHNOP_status] = "status",
    [EVTCHNOP_alloc_unbound] = "alloc_unbound",
    [EVTCHNOP_bind_ipi] = "bind_ipi",
    [EVTCHNOP_bind_vcpu] = "bind_vcpu",
    [EVTCHNOP_unmask] = "unmask",
    [EVTCHNOP_reset] = "reset",
    [EVTCHNOP_init_control] = "init_control",
    [EVTCHNOP_expand_array] = "expand_array",
    [EVTCHNOP_set_priority] = "set_priority"
};

#define PHYSDEV_MAX (PHYSDEVOP_release_msix + 1)
static const char *physdev_str[PHYSDEV_MAX] = {
    [PHYSDEVOP_eoi] = "eoi",
    [PHYSDEVOP_pirq_eoi_gmfn_v1] = "pirq_eoi_gmfn_v1",
    [PHYSDEVOP_pirq_eoi_gmfn_v2] = "pirq_eoi_gmfn_v2",
    [PHYSDEVOP_irq_status_query] = "irq_status_query",
    [PHYSDEVOP_set_iopl] = "set_iopl",
    [PHYSDEVOP_set_iobitmap] = "set_iobitmap",
    [PHYSDEVOP_apic_read] = "apic_read",
    [PHYSDEVOP_apic_write] = "apic_write",
    [PHYSDEVOP_alloc_irq_vector] = "alloc_irq_vector",
    [PHYSDEVOP_free_irq_vector] = "free_irq_vector",
    [PHYSDEVOP_map_pirq] = "map_pirq",
    [PHYSDEVOP_unmap_pirq] = "unmap_pirq",
    [PHYSDEVOP_manage_pci_add] = "manage_pci_add",
    [PHYSDEVOP_manage_pci_remove] = "manage_pci_remove",
    [PHYSDEVOP_restore_msi] = "restore_msi",
    [PHYSDEVOP_manage_pci_add_ext] = "manage_pci_add_ext",
    [PHYSDEVOP_setup_gsi] = "setup_gsi",
    [PHYSDEVOP_get_free_pirq] = "get_free_pirq",
    [PHYSDEVOP_pci_mmcfg_reserved] = "pci_mmcfg_reserved",
    [PHYSDEVOP_pci_device_add] = "pci_device_add",
    [PHYSDEVOP_pci_device_remove] = "pci_device_remove",
    [PHYSDEVOP_restore_msi_ext] = "restore_msi_ext",
    [PHYSDEVOP_prepare_msix] = "prepare_msix",
    [PHYSDEVOP_release_msix] = "release_msix",
    [PHYSDEVOP_dbgp_op] = "dbgp_op"
};

#define HVM_MAX (HVMOP_altp2m + 1)
static const char *hvm_str[HVM_MAX] = {
    [HVMOP_set_param] = "set_param",
    [HVMOP_get_param] = "get_param",
    [HVMOP_flush_tlbs] = "flush_tlbs",
    [HVMOP_pagetable_dying] = "pagetable_dying",
    [HVMOP_get_time] = "get_time",
    [HVMOP_xentrace] = "xentrace",
    [HVMOP_set_mem_access] = "set_mem_access",
    [HVMOP_get_mem_access] = "get_mem_access",
    [HVMOP_get_mem_type] = "get_mem_type",
    [HVMOP_set_evtchn_upcall_vector] = "set_evtchn_upcall_vector",
    [HVMOP_guest_request_vm_event] = "guest_request_vm_event",
    [HVMOP_altp2m] = "altp2m"
};

static const char *hvm_param_str[HVM_NR_PARAMS] = {
    [HVM_PARAM_CALLBACK_IRQ] = "callback_irq",
    [HVM_PARAM_STORE_PFN] = "store_pfn",
    [HVM_PARAM_STORE_EVTCHN] = "store_evtchn",
    [HVM_PARAM_PAE_ENABLED] = "pae_enabled",
    [HVM_PARAM_IOREQ_PFN] = "ioreq_pfn",
    [HVM_PARAM_BUFIOREQ_PFN] = "bufioreq_pfn",
    [HVM_PARAM_VIRIDIAN] = "viridian",
    [HVM_PARAM_TIMER_MODE] = "timer_mode",
    [HVM_PARAM_HPET_ENABLED] = "hpet_enabled",
    [HVM_PARAM_IDENT_PT] = "ident_pt",
    [HVM_PARAM_ACPI_S_STATE] = "acpi_s_state",
    [HVM_PARAM_VM86_TSS] = "vm86_tss",
    [HVM_PARAM_VPT_ALIGN] = "vpt_align",
    [HVM_PARAM_CONSOLE_PFN] = "console_pfn",
    [HVM_PARAM_CONSOLE_EVTCHN] = "console_evtchn",
    [HVM_PARAM_ACPI_IOPORTS_LOCATION] = "acpi_ioports_location",
    [HVM_PARAM_MEMORY_EVENT_CR0] = "memory_event_cr0",
    [HVM_PARAM_MEMORY_EVENT_CR3] = "memory_event_cr3",
    [HVM_PARAM_MEMORY_EVENT_CR4] = "memory_event_cr4",
    [HVM_PARAM_MEMORY_EVENT_INT3] = "memory_event_int3",
    [HVM_PARAM_MEMORY_EVENT_SINGLE_STEP] = "memory_event_single_step",
    [HVM_PARAM_MEMORY_EVENT_MSR] = "memory_event_msr",
    [HVM_PARAM_NESTEDHVM] = "nestedhvm",
    [HVM_PARAM_PAGING_RING_PFN] = "paging_ring_pfn",
    [HVM_PARAM_MONITOR_RING_PFN] = "monitor_ring_pfn",
    [HVM_PARAM_SHARING_RING_PFN] = "sharing_ring_pfn",
    [HVM_PARAM_TRIPLE_FAULT_REASON] = "triple_fault_reason",
    [HVM_PARAM_IOREQ_SERVER_PFN] = "ioreq_server_pfn",
    [HVM_PARAM_NR_IOREQ_SERVER_PAGES] = "nr_ioreq_server_pages",
    [HVM_PARAM_VM_GENERATION_ID_ADDR] = "vm_generation_id_addr",
    [HVM_PARAM_ALTP2M] = "altp2m",
    [HVM_PARAM_X87_FIP_WIDTH] = "x87_fip_width",
    [HVM_PARAM_VM86_TSS_SIZED] = "vm86_tss_sized",
    [HVM_PARAM_MCA_CAP] = "mca_cap"
};

#define SYSCTL_MAX (XEN_SYSCTL_get_cpu_policy + 1)
static const char *sysctl_str[SYSCTL_MAX] = {
    [XEN_SYSCTL_readconsole] = "readconsole",
    [XEN_SYSCTL_tbuf_op] = "tbuf_op",
    [XEN_SYSCTL_physinfo] = "physinfo",
    [XEN_SYSCTL_sched_id] = "sched_id",
    [XEN_SYSCTL_perfc_op] = "perfc_op",
    [XEN_SYSCTL_getdomaininfolist] = "getdomaininfolist",
    [XEN_SYSCTL_debug_keys] = "debug_keys",
    [XEN_SYSCTL_getcpuinfo] = "getcpuinfo",
    [XEN_SYSCTL_availheap] = "availheap",
    [XEN_SYSCTL_get_pmstat] = "get_pmstat",
    [XEN_SYSCTL_cpu_hotplug] = "cpu_hotplug",
    [XEN_SYSCTL_pm_op] = "pm_op",
    [XEN_SYSCTL_page_offline_op] = "page_offline_op",
    [XEN_SYSCTL_lockprof_op] = "lockprof_op",
    [XEN_SYSCTL_cputopoinfo] = "cputopoinfo",
    [XEN_SYSCTL_numainfo] = "numainfo",
    [XEN_SYSCTL_cpupool_op] = "cpupool_op",
    [XEN_SYSCTL_scheduler_op] = "scheduler_op",
    [XEN_SYSCTL_coverage_op] = "coverage_op",
    [XEN_SYSCTL_psr_cmt_op] = "psr_cmt_op",
    [XEN_SYSCTL_pcitopoinfo] = "pcitopoinfo",
    [XEN_SYSCTL_psr_alloc] = "psr_alloc",
    [XEN_SYSCTL_get_cpu_levelling_caps] = "get_cpu_levelling_caps",
    [XEN_SYSCTL_get_cpu_featureset] = "get_cpu_featureset",
    [XEN_SYSCTL_livepatch_op] = "livepatch_op",
    [XEN_SYSCTL_set_parameter] = "set_parameter",
    [XEN_SYSCTL_get_cpu_policy] = "get_cpu_policy"
};

#define DOMCTL_MAX (XEN_DOMCTL_get_cpu_policy + 1)
static const char *domctl_str[DOMCTL_MAX] = {
    [XEN_DOMCTL_createdomain] = "createdomain",
    [XEN_DOMCTL_destroydomain] = "destroydomain",
    [XEN_DOMCTL_pausedomain] = "pausedomain",
    [XEN_DOMCTL_unpausedomain] = "unpausedomain",
    [XEN_DOMCTL_getdomaininfo] = "getdomaininfo",
    [XEN_DOMCTL_setvcpuaffinity] = "setvcpuaffinity",
    [XEN_DOMCTL_shadow_op] = "shadow_op",
    [XEN_DOMCTL_max_mem] = "max_mem",
    [XEN_DOMCTL_setvcpucontext] = "setvcpucontext",
    [XEN_DOMCTL_getvcpucontext] = "getvcpucontext",
    [XEN_DOMCTL_getvcpuinfo] = "getvcpuinfo",
    [XEN_DOMCTL_max_vcpus] = "max_vcpus",
    [XEN_DOMCTL_scheduler_op] = "scheduler_op",
    [XEN_DOMCTL_setdomainhandle] = "setdomainhandle",
    [XEN_DOMCTL_setdebugging] = "setdebugging",
    [XEN_DOMCTL_irq_permission] = "irq_permission",
    [XEN_DOMCTL_iomem_permission] = "iomem_permission",
    [XEN_DOMCTL_ioport_permission] = "ioport_permission",
    [XEN_DOMCTL_hypercall_init] = "hypercall_init",
    [XEN_DOMCTL_arch_setup] = "arch_setup",
    [XEN_DOMCTL_settimeoffset] = "settimeoffset",
    [XEN_DOMCTL_getvcpuaffinity] = "getvcpuaffinity",
    [XEN_DOMCTL_real_mode_area] = "real_mode_area",
    [XEN_DOMCTL_resumedomain] = "resumedomain",
    [XEN_DOMCTL_sendtrigger] = "sendtrigger",
    [XEN_DOMCTL_subscribe] = "subscribe",
    [XEN_DOMCTL_gethvmcontext] = "gethvmcontext",
    [XEN_DOMCTL_sethvmcontext] = "sethvmcontext",
    [XEN_DOMCTL_set_address_size] = "set_address_size",
    [XEN_DOMCTL_get_address_size] = "get_address_size",
    [XEN_DOMCTL_assign_device] = "assign_device",
    [XEN_DOMCTL_bind_pt_irq] = "bind_pt_irq",
    [XEN_DOMCTL_memory_mapping] = "memory_mapping",
    [XEN_DOMCTL_ioport_mapping] = "ioport_mapping",
    [XEN_DOMCTL_set_ext_vcpucontext] = "set_ext_vcpucontext",
    [XEN_DOMCTL_get_ext_vcpucontext] = "get_ext_vcpucontext",
    [XEN_DOMCTL_set_opt_feature] = "set_opt_feature",
    [XEN_DOMCTL_test_assign_device] = "test_assign_device",
    [XEN_DOMCTL_set_target] = "set_target",
    [XEN_DOMCTL_deassign_device] = "deassign_device",
    [XEN_DOMCTL_unbind_pt_irq] = "unbind_pt_irq",
    [XEN_DOMCTL_set_cpuid] = "set_cpuid",
    [XEN_DOMCTL_get_device_group] = "get_device_group",
    [XEN_DOMCTL_set_machine_address_size] = "set_machine_address_size",
    [XEN_DOMCTL_get_machine_address_size] = "get_machine_address_size",
    [XEN_DOMCTL_suppress_spurious_page_faults] = "suppress_spurious_page_faults",
    [XEN_DOMCTL_debug_op] = "debug_op",
    [XEN_DOMCTL_gethvmcontext_partial] = "gethvmcontext_partial",
    [XEN_DOMCTL_vm_event_op] = "vm_event_op",
    [XEN_DOMCTL_mem_sharing_op] = "mem_sharing_op",
    [XEN_DOMCTL_disable_migrate] = "disable_migrate",
    [XEN_DOMCTL_gettscinfo] = "gettscinfo",
    [XEN_DOMCTL_settscinfo] = "settscinfo",
    [XEN_DOMCTL_getpageframeinfo3] = "getpageframeinfo3",
    [XEN_DOMCTL_setvcpuextstate] = "setvcpuextstate",
    [XEN_DOMCTL_getvcpuextstate] = "getvcpuextstate",
    [XEN_DOMCTL_set_access_required] = "set_access_required",
    [XEN_DOMCTL_audit_p2m] = "audit_p2m",
    [XEN_DOMCTL_set_virq_handler] = "set_virq_handler",
    [XEN_DOMCTL_set_broken_page_p2m] = "set_broken_page_p2m",
    [XEN_DOMCTL_setnodeaffinity] = "setnodeaffinity",
    [XEN_DOMCTL_getnodeaffinity] = "getnodeaffinity",
    [XEN_DOMCTL_cacheflush] = "cacheflush",
    [XEN_DOMCTL_get_vcpu_msrs] = "get_vcpu_msrs",
    [XEN_DOMCTL_set_vcpu_msrs] = "set_vcpu_msrs",
    [XEN_DOMCTL_setvnumainfo] = "setvnumainfo",
    [XEN_DOMCTL_psr_cmt_op] = "psr_cmt_op",
    [XEN_DOMCTL_monitor_op] = "monitor_op",
    [XEN_DOMCTL_psr_alloc] = "psr_alloc",
    [XEN_DOMCTL_soft_reset] = "soft_reset",
    [XEN_DOMCTL_vuart_op] = "vuart_op",
    [XEN_DOMCTL_get_cpu_policy] = "get_cpu_policy"
};

namespace microv {

static void debug_xenpf(microv_vcpu *vcpu)
{
    auto op = vcpu->map_arg<xen_platform_op_t>(vcpu->rdi());
    if (op->cmd >= XENPF_MAX) {
        printf("UNKNOWN(cmd=%u)", op->cmd);
    } else {
        printf("%s", xenpf_str[op->cmd]);
    }
}

static void debug_xenmem(microv_vcpu *vcpu)
{
    if (vcpu->rdi() >= XENMEM_MAX) {
        printf("UNKNOWN(rdi=%lu)", vcpu->rdi());
    } else {
        printf("%s", xenmem_str[vcpu->rdi()]);
    }
}

static void debug_xenver(microv_vcpu *vcpu)
{
    if (vcpu->rdi() >= XENVER_MAX) {
        printf("UNKNOWN(rdi=%lu)", vcpu->rdi());
    } else {
        printf("%s", xenver_str[vcpu->rdi()]);
    }
}

static void debug_gnttab(microv_vcpu *vcpu)
{
    if (vcpu->rdi() >= GNTTAB_MAX) {
        printf("UNKNOWN(rdi=%lu)", vcpu->rdi());
    } else {
        printf("%s", gnttab_str[vcpu->rdi()]);
    }

}

static void debug_vmasst(microv_vcpu *vcpu)
{
    if (vcpu->rdi() == VMASST_CMD_enable) {
        printf("enable:");
    } else {
        printf("disable:");
    }

    if (vcpu->rsi() >= VMASST_MAX) {
        printf("UNKNOWN(rsi=%lu)", vcpu->rsi());
    } else {
        printf("%s", vmasst_str[vcpu->rsi()]);
    }
}

static void debug_vcpu(microv_vcpu *vcpu)
{
    if (vcpu->rdi() >= VCPU_MAX) {
        printf("UNKNOWN(rdi=%lu)", vcpu->rdi());
    } else {
        printf("%s", vcpu_str[vcpu->rdi()]);
    }

}

static void debug_flask(microv_vcpu *vcpu)
{
    auto op = vcpu->map_arg<xen_flask_op_t>(vcpu->rdi());
    if (op->cmd >= FLASK_MAX) {
        printf("UNKNOWN(cmd=%u)", op->cmd);
    } else {
        printf("%s", flask_str[op->cmd]);
    }
}

static void debug_evtchn(microv_vcpu *vcpu)
{
    if (vcpu->rdi() >= EVTCHN_MAX) {
        printf("UNKNOWN(rdi=%lu)", vcpu->rdi());
    } else {
        printf("%s", evtchn_str[vcpu->rdi()]);
    }
}

static void debug_physdev(microv_vcpu *vcpu)
{
    if (vcpu->rdi() >= PHYSDEV_MAX) {
        printf("UNKNOWN(rdi=%lu)", vcpu->rdi());
    } else {
        printf("%s", physdev_str[vcpu->rdi()]);
    }
}

static void debug_hvm(microv_vcpu *vcpu)
{
    const auto rdi = vcpu->rdi();

    if (rdi >= HVM_MAX) {
        printf("UNKNOWN(rdi=%lu)", rdi);
        return;
    } else {
        printf("%s", hvm_str[rdi]);
    }

    if (rdi == HVMOP_set_param || rdi == HVMOP_get_param) {
        auto param = vcpu->map_arg<xen_hvm_param_t>(vcpu->rsi());
        if (param->index >= HVM_NR_PARAMS) {
            return;
        }

        printf(":%s:domid=0x%x", hvm_param_str[param->index], param->domid);
    }
}

static void debug_sysctl(microv_vcpu *vcpu)
{
    auto ctl = vcpu->map_arg<xen_sysctl_t>(vcpu->rdi());

    if (ctl->cmd >= SYSCTL_MAX) {
        printf("UNKNOWN(cmd=%u)", ctl->cmd);
    } else {
        printf("%s", sysctl_str[ctl->cmd]);
    }
}

static void debug_domctl(microv_vcpu *vcpu)
{
    auto ctl = vcpu->map_arg<xen_domctl_t>(vcpu->rdi());

    if (ctl->cmd >= DOMCTL_MAX) {
        printf("UNKNOWN(cmd=%u)", ctl->cmd);
    } else {
        printf("%s:domid=0x%x", domctl_str[ctl->cmd], ctl->domain);
    }
}

void debug_xen_hypercall(xen_vcpu *xenv)
{
    auto vcpu = xenv->m_uv_vcpu;
    auto rax = vcpu->rax();
    auto domid = xenv->m_xen_dom->m_id;

    printv("xen(domid=0x%x):%s:", domid, hypercall_str[rax]);

    switch (rax) {
    case __HYPERVISOR_platform_op:
        debug_xenpf(vcpu);
        break;
    case __HYPERVISOR_memory_op:
        debug_xenmem(vcpu);
        break;
    case __HYPERVISOR_xen_version:
        debug_xenver(vcpu);
        break;
    case __HYPERVISOR_grant_table_op:
        debug_gnttab(vcpu);
        break;
    case __HYPERVISOR_vm_assist:
        debug_vmasst(vcpu);
        break;
    case __HYPERVISOR_vcpu_op:
        debug_vcpu(vcpu);
        break;
    case __HYPERVISOR_xsm_op:
        debug_flask(vcpu);
        break;
    case __HYPERVISOR_event_channel_op:
        debug_evtchn(vcpu);
        break;
    case __HYPERVISOR_physdev_op:
        debug_physdev(vcpu);
        break;
    case __HYPERVISOR_hvm_op:
        debug_hvm(vcpu);
        break;
    case __HYPERVISOR_sysctl:
        debug_sysctl(vcpu);
        break;
    case __HYPERVISOR_domctl:
        debug_domctl(vcpu);
        break;
    default:
        printf("UNIMPLEMENTED");
    }

    printf("\n");
}

static uint64_t rdrand64(uint64_t *data) noexcept
{
    constexpr int retries = 8;
    int i = 0;
    uint64_t success = 0;
    uint64_t rand = 0;

    do {
        success = _rdrand64(&rand);
    } while (++i < retries && !success);

    if (success) {
        *data = rand;
        return 1;
    }

    return 0;
}

xen_domid_t make_xen_domid() noexcept
{
    static_assert(std::atomic<xen_domid_t>::is_always_lock_free);
    static std::atomic<xen_domid_t> domid = 1;

    return domid.fetch_add(1);
}

void make_xen_uuid(xen_uuid_t *uuid)
{
    uint64_t low, high, success;

    static_assert(sizeof(*uuid) == 16);
    static_assert(sizeof(*uuid) == sizeof(low) + sizeof(high));

    success = rdrand64(&low);
    success &= rdrand64(&high);

    if (!success) {
        throw std::runtime_error("make_xen_uuid: RDRAND failed");
    }

    memcpy(uuid, &low, sizeof(low));
    memcpy((uint8_t *)uuid + sizeof(low), &high, sizeof(high));
}

}
