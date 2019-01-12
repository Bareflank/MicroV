/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BOOTPARAMS_H
#define BOOTPARAMS_H

#include <bftypes.h>

#pragma pack(push, 1)

// -----------------------------------------------------------------------------
// Setup Header
// -----------------------------------------------------------------------------

struct setup_header {
	uint8_t	    setup_sects;
	uint16_t	root_flags;
	uint32_t	syssize;
	uint16_t	ram_size;
	uint16_t	vid_mode;
	uint16_t	root_dev;
	uint16_t	boot_flag;
	uint16_t	jump;
	uint32_t	header;
	uint16_t	version;
	uint32_t	realmode_swtch;
	uint16_t	start_sys_seg;
	uint16_t	kernel_version;
	uint8_t	    type_of_loader;
	uint8_t	    loadflags;
	uint16_t	setup_move_size;
	uint32_t	code32_start;
	uint32_t	ramdisk_image;
	uint32_t	ramdisk_size;
	uint32_t	bootsect_kludge;
	uint16_t	heap_end_ptr;
	uint8_t	    ext_loader_ver;
	uint8_t	    ext_loader_type;
	uint32_t	cmd_line_ptr;
	uint32_t	initrd_addr_max;
	uint32_t	kernel_alignment;
	uint8_t	    relocatable_kernel;
	uint8_t	    min_alignment;
	uint16_t	xloadflags;
	uint32_t	cmdline_size;
	uint32_t	hardware_subarch;
	uint64_t	hardware_subarch_data;
	uint32_t	payload_offset;
	uint32_t	payload_length;
	uint64_t	setup_data;
	uint64_t	pref_address;
	uint32_t	init_size;
	uint32_t	handover_offset;
};

// -----------------------------------------------------------------------------
// E820 Entry
// -----------------------------------------------------------------------------

#define E820_MAX_ENTRIES_ZEROPAGE 128

struct boot_e820_entry {
	uint64_t addr;
	uint64_t size;
	uint32_t type;
};

// -----------------------------------------------------------------------------
// bootparams
// -----------------------------------------------------------------------------

struct boot_params {
	uint8_t                     screen_info[0x40];
	uint8_t                     apm_bios_info[0x14];
	uint8_t                     _pad2[4];
	uint64_t                    tboot_addr;
	uint8_t                     ist_info[0x10];
	uint8_t                     _pad3[16];
	uint8_t                     hd0_info[16];
	uint8_t                     hd1_info[16];
	uint8_t                     sys_desc_table[0x10];
	uint8_t                     olpc_ofw_header[0x10];
	uint32_t                    ext_ramdisk_image;
	uint32_t                    ext_ramdisk_size;
	uint32_t                    ext_cmd_line_ptr;
	uint8_t                     _pad4[116];
	uint8_t                     edid_info[0x80];
    uint8_t                     efi_info[0x20];
	uint32_t                    alt_mem_k;
	uint32_t                    scratch;
	uint8_t                     e820_entries;
	uint8_t                     eddbuf_entries;
	uint8_t                     edd_mbr_sig_buf_entries;
	uint8_t                     kbd_status;
	uint8_t                     secure_boot;
	uint8_t                     _pad5[2];
	uint8_t                     sentinel;
	uint8_t                     _pad6[1];
	struct setup_header         hdr;
	uint8_t                     _pad7[0x290-0x1f1-sizeof(struct setup_header)];
	uint32_t                    edd_mbr_sig_buffer[16];
	struct boot_e820_entry      e820_table[E820_MAX_ENTRIES_ZEROPAGE];
	uint8_t                     _pad8[48];
	uint8_t                     eddbuf[0x1EC];
	uint8_t                     _pad9[276];
};

#pragma pack(pop)

#endif
