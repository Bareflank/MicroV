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

extern _start_c
global _start:function

%define STACK_CANARY 0xABCDEF1234567890

section .text

; We arrive here using the driver's stack
; int64_t _start(uint64_t stack, crt_info_t *crt_info);
_start:

    cli

    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    push rbp
    mov rbp, rsp

; NOTE:
;
; We use the OSTYPE instead of the ABI type because the ABI for the VMM is
; SYSV, but in this case the OS is Windows. The whole point of this file
; is to transtion from the OSTYPE to the VMM.
;

%ifdef WIN64
    mov rsp, rcx    ; stack
    mov r13, rdx    ; crt_info
%else
    mov rsp, rdi    ; stack
    mov r13, rsi    ; crt_info
%endif

    mov r12, [rsp + 0x11] ; load xsave_info base address
    mov r11, [r12 + 0x40] ; check if ready
    test r11, r11
    jnz xsave_ready
    mov rdi, r12
    call prepare_xsave
    test rax, rax
    jz xsave_ready
    jmp leave_start

; At this point we know that cpuid supports XSAVE and OSXSAVE is enabled
; in CR4. Also every field in the xsave_info has been initialized
xsave_ready:

    ; Save the current guest xcr0
    xor rcx, rcx
    xgetbv
    shl rdx, 32
    or rax, rdx
    mov r14, rax

    ; Hardware xcr0 should *always* equal info->guest_xcr0 at this point.
    ; If not it means that the xsetbv exit handler bookkeeping has gone astray
    mov rbx, [r12 + 0x18]
    cmp rbx, r14
    je push_guest_fields
    mov rax, 0x8000000000000090
    jmp leave_start

push_guest_fields:
    ; First we have to save the guest xsave info fields on the stack
    mov rax, [r12 + 0x08]
    mov rbx, [r12 + 0x18]
    mov rcx, [r12 + 0x28]
    push rax
    push rbx
    push rcx

    mov rax, STACK_CANARY
    push rax

    ; Save current state to the guest area
    mov rax, [r12 + 0x18]
    mov rdx, [r12 + 0x18]
    shr rdx, 32
    mov rdi, [r12 + 0x08]
    xsave [rdi]

    ; Overwrite the guest xsave fields with the host's
    mov rax, [r12 + 0x00] ; host_area
    mov rbx, [r12 + 0x10] ; host_xcr0
    mov rcx, [r12 + 0x20] ; host_size
    mov [r12 + 0x08], rax
    mov [r12 + 0x18], rbx
    mov [r12 + 0x28], rcx

    ; Load state from host area
    mov rax, [r12 + 0x10]
    mov rdx, [r12 + 0x10]
    shr rdx, 32
    xor rcx, rcx
    xsetbv
    mov rdi, [r12 + 0x00]
    xrstor [rdi]
    lfence

    mov rdi, r13
    call _start_c wrt ..plt
    mov r11, rax

    ; Store current state to the host area
    mov rax, [r12 + 0x10]
    mov rdx, [r12 + 0x10]
    shr rdx, 32
    mov rdi, [r12 + 0x00]
    xsave [rdi]

    ; Restore the guest xcr0
    mov rax, r14
    mov rdx, r14
    shr rdx, 32
    xor rcx, rcx
    xsetbv

    ; Put the canary in r13
    pop r13

    ; Restore the guest xsave_info fields
    pop rcx ; guest_size
    pop rbx ; guest_xcr0
    pop rax ; guest_area
    mov [r12 + 0x08], rax
    mov [r12 + 0x18], rbx
    mov [r12 + 0x28], rcx

    ; Load state from the guest area
    mov rax, [r12 + 0x18]
    mov rdx, [r12 + 0x18]
    shr rdx, 32
    mov rdi, [r12 + 0x08]
    xrstor [rdi]

    mov rbx, STACK_CANARY
    cmp r13, rbx
    jne stack_overflow

    mov rax, r11
    jmp leave_start

stack_overflow:
    mov rax, 0x8000000000000010
    jmp leave_start

; int64_t prepare_xsave(xsave_info *info)
prepare_xsave:
    ; Make sure cpuid supports xsave feature set
    mov rax, 1
    mov rcx, 0
    cpuid
    and rcx, 1 << 26
    test rcx, rcx
    jnz check_host_xcr0
    mov rax, 0x8000000000000050
    ret

check_host_xcr0:
    mov rax, 0xD
    mov rcx, 0
    cpuid
    shl rdx, 32
    or rax, rdx
    mov rbx, [rdi + 0x10]
    not rax
    test rax, rbx
    jz check_host_size
    mov rax, 0x8000000000000060
    ret

check_host_size:
    mov rax, [rdi + 0x20]
    cmp rax, rcx
    je check_guest_size
    mov rax, 0x8000000000000070
    ret

check_guest_size:
    mov rax, [rdi + 0x28]
    cmp rax, rcx
    je enable_xsave
    mov rax, 0x8000000000000080
    ret

enable_xsave:
    mov rax, cr4
    or rax, 1 << 18
    mov cr4, rax

    xor rcx, rcx
    xgetbv
    shl rdx, 32
    or rax, rdx
    mov [rdi + 0x18], rax

    ; Initialize the xsave area for the host
    mov rax, [rdi + 0x10]
    mov rdx, [rdi + 0x10]
    shr rdx, 32
    xsetbv
    mov rcx, [rdi + 0x00]
    xsave [rcx]

    ; Restore guest xcr0
    mov rax, [rdi + 0x18]
    mov rdx, [rdi + 0x18]
    shr rdx, 32
    xor rcx, rcx
    xsetbv

    mov rax, 1
    mov [rdi + 0x40], rax
    xor rax, rax
    ret

leave_start:
    leave
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    sti
    ret
