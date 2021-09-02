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

    $(TARGET_MODULE)-objs += src/entry.o
    $(TARGET_MODULE)-objs += src/platform.o
    $(TARGET_MODULE)-objs += ../src/x64/serial_init.o
    $(TARGET_MODULE)-objs += ../src/g_hndl.o
    $(TARGET_MODULE)-objs += ../src/serial_write.o
    $(TARGET_MODULE)-objs += ../src/shim_fini.o
    $(TARGET_MODULE)-objs += ../src/shim_init.o
    $(TARGET_MODULE)-objs += ../src/handle_system_kvm_get_vcpu_mmap_size.o
    $(TARGET_MODULE)-objs += ../src/handle_system_kvm_create_vm.o
    $(TARGET_MODULE)-objs += ../src/handle_system_kvm_destroy_vm.o
    $(TARGET_MODULE)-objs += ../src/handle_vm_kvm_create_vcpu.o
	
	EXTRA_CFLAGS += -I$(src)/include
	EXTRA_CFLAGS += -I$(src)/include/std
	EXTRA_CFLAGS += -I$(src)/include/platform_interface
	EXTRA_CFLAGS += -I$(src)/../include
	EXTRA_CFLAGS += -I$(src)/../../hypercall/include/c
	EXTRA_CFLAGS += -I$(src)/../../hypercall/src/c
	EXTRA_CFLAGS += -I$(CMAKE_BINARY_DIR)/include

    EXTRA_AFLAGS += -I$(CMAKE_BINARY_DIR)/include

  	ifneq (,$(findstring AuthenticAMD,$(VENDOR_ID)))
        $(TARGET_MODULE)-objs += src/x64/intrinsic_inb.o
        $(TARGET_MODULE)-objs += src/x64/intrinsic_outb.o
        $(TARGET_MODULE)-objs += src/x64/serial_write_c.o
        $(TARGET_MODULE)-objs += src/x64/vmcall.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_debug_op_out_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_handle_op_close_handle_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_handle_op_open_handle_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_id_op_version_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vps_op_gla_to_gpa_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/amd/mv_vps_op_gva_to_gla_impl.o

    	EXTRA_CFLAGS += -I$(src)/include/x64
		EXTRA_CFLAGS += -I$(src)/include/x64/amd
    	EXTRA_CFLAGS += -I$(src)/../include/x64
		EXTRA_CFLAGS += -I$(src)/../include/x64/amd
		EXTRA_CFLAGS += -I$(src)/../../hypercall/include/c/x64
		EXTRA_CFLAGS += -I$(src)/../../hypercall/include/c/x64/amd
	endif

	ifneq (,$(findstring GenuineIntel,$(VENDOR_ID)))
        $(TARGET_MODULE)-objs += src/x64/intrinsic_inb.o
        $(TARGET_MODULE)-objs += src/x64/intrinsic_outb.o
        $(TARGET_MODULE)-objs += src/x64/serial_write_c.o
        $(TARGET_MODULE)-objs += src/x64/vmcall.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_debug_op_out_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_handle_op_close_handle_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_handle_op_open_handle_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_id_op_version_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vps_op_gla_to_gpa_impl.o
		$(TARGET_MODULE)-objs += ../../hypercall/src/linux/x64/intel/mv_vps_op_gva_to_gla_impl.o

    	EXTRA_CFLAGS += -I$(src)/include/x64
		EXTRA_CFLAGS += -I$(src)/include/x64/intel
    	EXTRA_CFLAGS += -I$(src)/../include/x64
		EXTRA_CFLAGS += -I$(src)/../include/x64/intel
		EXTRA_CFLAGS += -I$(src)/../../hypercall/include/c/x64
		EXTRA_CFLAGS += -I$(src)/../../hypercall/include/c/x64/intel
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
