# SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT
#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

TARGET_MODULE := microv_shim
VENDOR_ID := $(shell lscpu | grep 'Vendor ID')

ifneq ($(KERNELRELEASE),)
	obj-m := $(TARGET_MODULE).o
	EXTRA_CFLAGS += -DLINUX_KERNEL

    $(TARGET_MODULE)-objs += src/entry.o
    $(TARGET_MODULE)-objs += src/platform.o
	$(TARGET_MODULE)-objs += ../src/g_mut_hndl.o
	$(TARGET_MODULE)-objs += ../src/g_mut_shared_pages.o
	$(TARGET_MODULE)-objs += ../src/handle_device_kvm_get_device_attr.o
	$(TARGET_MODULE)-objs += ../src/handle_device_kvm_has_device_attr.o
	$(TARGET_MODULE)-objs += ../src/handle_device_kvm_set_device_attr.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_check_extension.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_create_vm.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_destroy_vm.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_get_api_version.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_get_emulated_cpuid.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_get_msr_feature_index_list.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_get_msr_index_list.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_get_msrs.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_get_supported_cpuid.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_get_vcpu_mmap_size.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_memory_encrypt_op.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_memory_encrypt_reg_region.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_memory_encrypt_unreg_region.o
	$(TARGET_MODULE)-objs += ../src/handle_system_kvm_x86_get_mce_cap_supported.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_enable_cap.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_cpuid2.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_fpu.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_lapic.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_mp_state.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_msrs.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_nested_state.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_one_reg.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_regs.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_sregs.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_supported_hv_cpuid.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_tsc_khz.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_vcpu_events.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_xcrs.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_get_xsave.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_interrupt.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_kvmclock_ctrl.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_nmi.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_run.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_cpuid2.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_cpuid.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_fpu.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_guest_debug.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_lapic.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_mp_state.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_msrs.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_nested_state.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_one_reg.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_regs.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_signal_mask.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_sregs.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_tsc_khz.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_vcpu_events.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_xcrs.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_set_xsave.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_smi.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_translate.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_x86_set_mce.o
	$(TARGET_MODULE)-objs += ../src/handle_vcpu_kvm_x86_setup_mce.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_check_extension.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_clear_dirty_log.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_create_device.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_create_irqchip.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_create_pit2.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_create_vcpu.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_destroy_vcpu.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_get_clock.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_get_debugregs.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_get_device_attr.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_get_dirty_log.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_get_irqchip.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_get_pit2.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_has_device_attr.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_hyperv_eventfd.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_ioeventfd.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_irqfd.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_irq_line.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_register_coalesced_mmio.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_reinject_control.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_boot_cpu_id.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_clock.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_debugregs.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_device_attr.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_gsi_routing.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_identity_map_addr.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_irqchip.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_pit2.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_pmu_event_filter.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_tss_addr.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_set_user_memory_region.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_signal_msi.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_unregister_coalesced_mmio.o
	$(TARGET_MODULE)-objs += ../src/handle_vm_kvm_xen_hvm_config.o
	$(TARGET_MODULE)-objs += ../src/serial_write.o
	$(TARGET_MODULE)-objs += ../src/shared_page_for_current_pp.o
	$(TARGET_MODULE)-objs += ../src/shim_fini.o
	$(TARGET_MODULE)-objs += ../src/shim_init.o
    $(TARGET_MODULE)-objs += ../src/x64/serial_init.o

	EXTRA_CFLAGS += -I$(src)/include
	EXTRA_CFLAGS += -I$(src)/include/std
	EXTRA_CFLAGS += -I$(src)/include/platform_interface
	EXTRA_CFLAGS += -I$(src)/../include
	EXTRA_CFLAGS += -I$(src)/../../hypercall/include
	EXTRA_CFLAGS += -I$(src)/../../hypercall/src
	EXTRA_CFLAGS += -I$(CMAKE_BINARY_DIR)/include

    EXTRA_AFLAGS += -I$(CMAKE_BINARY_DIR)/include

  	ifneq (,$(findstring AuthenticAMD,$(VENDOR_ID)))
        $(TARGET_MODULE)-objs += src/x64/intrinsic_inb.o
        $(TARGET_MODULE)-objs += src/x64/intrinsic_outb.o
        $(TARGET_MODULE)-objs += src/x64/serial_write_c.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_debug_op_out_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_handle_op_close_handle_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_handle_op_open_handle_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_id_op_version_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_pp_op_set_shared_page_gpa_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vm_op_create_vm_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vm_op_destroy_vm_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vm_op_mmio_map_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vm_op_mmio_unmap_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vp_op_create_vp_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vp_op_destroy_vp_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vs_op_create_vs_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vs_op_destroy_vs_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vs_op_gla_to_gpa_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vs_op_gva_to_gla_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vs_op_reg_get_list_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vs_op_reg_set_list_impl.o

    	EXTRA_CFLAGS += -I$(src)/include/x64
		EXTRA_CFLAGS += -I$(src)/include/x64/amd
    	EXTRA_CFLAGS += -I$(src)/../include/x64
		EXTRA_CFLAGS += -I$(src)/../include/x64/amd
		EXTRA_CFLAGS += -I$(src)/../../hypercall/include/x64
		EXTRA_CFLAGS += -I$(src)/../../hypercall/include/x64/amd
	endif

	ifneq (,$(findstring GenuineIntel,$(VENDOR_ID)))
        $(TARGET_MODULE)-objs += src/x64/intrinsic_inb.o
        $(TARGET_MODULE)-objs += src/x64/intrinsic_outb.o
        $(TARGET_MODULE)-objs += src/x64/serial_write_c.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_debug_op_out_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_handle_op_close_handle_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_handle_op_open_handle_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_id_op_version_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_pp_op_clr_shared_page_gpa_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_pp_op_set_shared_page_gpa_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vm_op_create_vm_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vm_op_destroy_vm_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vm_op_mmio_map_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vm_op_mmio_unmap_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vp_op_create_vp_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vp_op_destroy_vp_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vs_op_create_vs_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vs_op_destroy_vs_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vs_op_gla_to_gpa_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vs_op_gva_to_gla_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vs_op_reg_get_list_impl.o
        $(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vs_op_reg_set_list_impl.o

    	EXTRA_CFLAGS += -I$(src)/include/x64
		EXTRA_CFLAGS += -I$(src)/include/x64/intel
    	EXTRA_CFLAGS += -I$(src)/../include/x64
		EXTRA_CFLAGS += -I$(src)/../include/x64/intel
		EXTRA_CFLAGS += -I$(src)/../../hypercall/include/x64
		EXTRA_CFLAGS += -I$(src)/../../hypercall/include/x64/intel
	endif

else
	BUILDSYSTEM_DIR := /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

all:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
	rm -f ../src/*.o*
	rm -f ../src/.*.o*
	rm -f ../src/x64/*.o*
	rm -f ../src/x64/.*.o*
	rm -f ../src/x64/amd/*.o*
	rm -f ../src/x64/amd/.*.o*
	rm -f ../src/x64/intel/*.o*
	rm -f ../src/x64/intel/.*.o*

load:
	@insmod ./$(TARGET_MODULE).ko

unload:
	-@rmmod ./$(TARGET_MODULE).ko

endif
