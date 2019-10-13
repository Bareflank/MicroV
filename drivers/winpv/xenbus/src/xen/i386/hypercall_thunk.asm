                        page    ,132
                        title   Hypercall Thunks

                        .686p
                        .model  FLAT
                        .code

                        extrn   _Hypercall:dword

                        ; uintptr_t __stdcall hypercall2(uint32_t ord, uintptr_t arg1, uintptr_t arg2);
                        public _hypercall2@12
_hypercall2@12    	proc
                        push    ebp
                        mov     ebp, esp
                        push    ebx
                        mov     eax, [ebp + 08h]                ; ord
                        mov     ebx, [ebp + 0ch]                ; arg1
                        mov     ecx, [ebp + 10h]                ; arg2
                        shl     eax, 5
                        add     eax, dword ptr [_Hypercall]
                        call    eax
                        pop     ebx
                        leave
                        ret     0Ch
_hypercall2@12    	endp

                        ; uintptr_t __stdcall hypercall3(uint32_t ord, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
                        public _hypercall3@16
_hypercall3@16    	proc
                        push    ebp
                        mov     ebp, esp
                        push    ebx
                        mov     eax, [ebp + 08h]                ; ord
                        mov     ebx, [ebp + 0ch]                ; arg1
                        mov     ecx, [ebp + 10h]                ; arg2
                        mov     edx, [ebp + 14h]                ; arg3
                        shl     eax, 5
                        add     eax, dword ptr [_Hypercall]
                        call    eax
                        pop     ebx
                        leave
                        ret     10h
_hypercall3@16    	endp

                        end


