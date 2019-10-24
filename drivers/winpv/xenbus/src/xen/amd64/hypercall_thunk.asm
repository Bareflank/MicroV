                        page    ,132
                        title   Hypercall Thunks

                        .code

                        extrn   Hypercall:qword

                        ; uintptr_t __stdcall hypercall2(uint32_t ord, uintptr_t arg1, uintptr_t arg2);
                        public hypercall2
hypercall2        	proc
	                push rdi
	                push rsi
	                mov rdi, rdx                            ; arg1
	                mov rax, qword ptr [Hypercall]
	                shl rcx, 5                              ; ord
	                add rax, rcx
	                mov rsi, r8                             ; arg2
	                call rax
	                pop rsi
	                pop rdi
	                ret
hypercall2        	endp

                        ; uintptr_t __stdcall hypercall3(uint32_t ord, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
                        public hypercall3
hypercall3 		proc
	                push rdi
	                push rsi
	                mov rdi, rdx                            ; arg1
	                mov rax, qword ptr [Hypercall]
	                shl rcx, 5                              ; ord
	                add rax, rcx
	                mov rsi, r8                             ; arg2
	                mov rdx, r9                             ; arg3
	                call rax
	                pop rsi
	                pop rdi
	                ret
hypercall3 		endp

                        end


