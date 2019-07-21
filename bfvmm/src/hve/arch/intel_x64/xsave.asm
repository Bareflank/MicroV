;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

bits 64
default rel

global xstate_save:function
global xstate_load:function

section .text

; void xstate_save(uint64_t xcr0, uint64_t rfbm, void *area);
;
; @xcr0 is the value of xcr0 programmed by the vcpu
; @rfbm is the mask of state components that need to be saved
; @area is the base address of the XSAVE area to save to
;
xstate_save:
    mov r11, rdx

    mov rax, rdi
    mov rdx, rdi
    shr rdx, 32
    xor rcx, rcx
    xsetbv

    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    xsave [r11]
    ret

; void xstate_load(uint64_t xcr0, uint64_t rfbm, void *area);
;
; @xcr0 is the value of xcr0 programmed by the vcpu
; @rfbm is the mask of state components that need to be loaded
; @area is the base address of the XSAVE area to load from
;
xstate_load:
    mov r11, rdx

    mov rax, rdi
    mov rdx, rdi
    shr rdx, 32
    xor rcx, rcx
    xsetbv

    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    xrstor [r11]
    ret
