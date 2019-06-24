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

section .text

global _xgetbv
_xgetbv:
    mov rcx, rdi
    xgetbv
    shl rdx, 32
    or rax, rdx
    ret

global _xsetbv
_xsetbv:
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    mov rcx, rdi
    xsetbv
    ret

global _xsave
_xsave:
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    xsave [rdi]
    ret

global _xsaves
_xsaves:
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    xsaves [rdi]
    ret

global _xrstor
_xrstor:
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    xrstor [rdi]
    ret

global _xrstors
_xrstors:
    mov rax, rsi
    mov rdx, rsi
    shr rdx, 32
    xrstors [rdi]
    ret
