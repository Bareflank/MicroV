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

/** ======================================================================== **/
/** 16bit to 32bit Preamble                                                  **/
/** ======================================================================== **/

    .code16
    .intel_syntax noprefix

    .globl  _start
    .type   _start, @function
_start:
    cli

    /**
     * NOTE:
     * - Load the GDT.
     */
    lgdt [gdtr]

    /**
     * NOTE:
     * - Turn protected mode on. This does not turn on paging, so we still
     *   have a flat view of memory.
     */
    mov eax, cr0
    or al, 1
    mov cr0, eax

    /**
     * NOTE:
     * - Even though protected mode is enabled, we are not actually executing
     *   32bit instructions yet. This is because we need to update the hidden
     *   segment registers to reflect 32bit mode. AMD's manual does a good
     *   job talking about how the hidden registers work, but basically the
     *   only way to can actually load these registers is to perform a far
     *   jump. Using the selector of the CS GDT entry, since protected mode is
     *   enabled, the CPU will perform the jump and update the hidden segment
     *   registers for us.
     *
     * - For some reason, LLVM doesn't seem to have an intel syntax version
     *   of a far jump, so we do it with AT&T syntax instead. Uhg!!!.
     */
    .att_syntax
    ljmp $0x8, $_start32

    .code32
    .intel_syntax noprefix

_start32:

    /**
     * NOTE:
     * - We are now in 32bit protected mode, executing 32 bit instructions.
     *   This is why above, we use .code32, because we now need to run 32bit
     *   instructions. From here, we want to ensure that all of the segment
     *   registers are properly loaded. This way, the instructions all work
     *   as we would expected them to with a flat memory model.
     */
    mov ax, 0x10
    mov es, ax
    mov ss, ax
    mov ds, ax
    mov fs, ax
    mov gs, ax

    /**
     * NOTE:
     * - That's it. We can now jump to the actual integration test code.
     */
    jmp main

gdtr:
    .word   gdt_end - gdt_start - 1
    .quad   gdt_start
gdt_start:
    .quad 0x0000000000000000
    .quad 0x00CF9A000000FFFF    /* CS */
    .quad 0x00CF93000000FFFF    /* ES, SS, DS, FS, GS */
    .quad 0x00000000FFFFFFFF
gdt_end:

/** ======================================================================== **/
/** Main 32bit Entry Point                                                   **/
/** ======================================================================== **/

    .code32
    .intel_syntax noprefix

main:
    xor ax, ax

loop:
	out 0x10, ax
	inc ax
	jmp loop

    .size _start, .-_start
