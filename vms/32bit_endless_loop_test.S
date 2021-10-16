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
    lidt [idtr]

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
     * - We also need to set up the stack so that we can push and pop
     */

    lea esp, stack_end

    /**
     * NOTE:
     * - That's it. We can now jump to the actual integration test code.
     */
    .att_syntax
    ljmp $0x8, $main

    .size _start, .-_start

gdtr:
    .word   gdt_end - gdt_start - 1
    .quad   gdt_start
gdt_start:
    .quad 0x0000000000000000
    .quad 0x00CF9A000000FFFF    /* CS */
    .quad 0x00CF93000000FFFF    /* ES, SS, DS, FS, GS */
    .quad 0x0000890001000068
gdt_end:

idtr:
    .word   idt_end - idt_start - 1
    .quad   idt_start
idt_start:

    /* exception vectors */
    .quad 0x0000000000000000    /* vector 0 */
    .quad 0x0000000000000000    /* vector 1 */
    .quad 0x0000000000000000    /* vector 2 */
    .quad 0x0000000000000000    /* vector 3 */
    .quad 0x0000000000000000    /* vector 4 */
    .quad 0x0000000000000000    /* vector 5 */
    .quad 0x0000000000000000    /* vector 6 */
    .quad 0x0000000000000000    /* vector 7 */
    .quad 0x0000000000000000    /* vector 8 */
    .quad 0x0000000000000000    /* vector 9 */
    .quad 0x0000000000000000    /* vector 10 */
    .quad 0x0000000000000000    /* vector 11 */
    .quad 0x0000000000000000    /* vector 12 */
    .quad 0x0000000000000000    /* vector 13 */
    .quad 0x0000000000000000    /* vector 14 */
    .quad 0x0000000000000000    /* vector 15 */
    .quad 0x0000000000000000    /* vector 16 */
    .quad 0x0000000000000000    /* vector 17 */
    .quad 0x0000000000000000    /* vector 18 */
    .quad 0x0000000000000000    /* vector 19 */
    .quad 0x0000000000000000    /* vector 20 */
    .quad 0x0000000000000000    /* vector 21 */
    .quad 0x0000000000000000    /* vector 22 */
    .quad 0x0000000000000000    /* vector 23 */
    .quad 0x0000000000000000    /* vector 24 */
    .quad 0x0000000000000000    /* vector 25 */
    .quad 0x0000000000000000    /* vector 26 */
    .quad 0x0000000000000000    /* vector 27 */
    .quad 0x0000000000000000    /* vector 28 */
    .quad 0x0000000000000000    /* vector 29 */
    .quad 0x0000000000000000    /* vector 30 */
    .quad 0x0000000000000000    /* vector 31 */

    /* intr vectors */
    .word isr32
    .word 0x0008
    .word 0x8E00
    .word 0x0000

    .zero 0x1000

idt_end:

stack_begin:
    .zero 0x1000
stack_end:

/** ======================================================================== **/
/** Main 32bit Entry Point                                                   **/
/** ======================================================================== **/

    .code32
    .intel_syntax noprefix

main:
    xor ax, ax
    sti

loop:
    mov ax, 0x23
	out 0x10, ax
	jmp loop

    .size main, .-main



    .code32
    .intel_syntax noprefix

    .globl  isr32
    .type   isr32, @function
isr32:

    push eax

    mov ax, 0x42
	out 0x11, ax
	iret

    .size isr32, .-isr32
