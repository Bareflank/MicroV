; // Copyright (c) Citrix Systems Inc.
; // All rights reserved.
; //
; // Redistribution and use in source and binary forms,
; // with or without modification, are permitted provided
; // that the following conditions are met:
; //
; // *   Redistributions of source code must retain the above
; //     copyright notice, this list of conditions and the
; //     following disclaimer.
; // *   Redistributions in binary form must reproduce the above
; //     copyright notice, this list of conditions and the
; //     following disclaimer in the documentation and/or other
; //     materials provided with the distribution.
; //
; // THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
; // CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
; // INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
; // MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
; // DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
; // CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
; // SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
; // BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
; // SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
; // INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
; // WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
; // NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
; // OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
; // SUCH DAMAGE.

MessageIdTypedef=DWORD

SeverityNames=(
	Success=0x0:STATUS_SEVERITY_SUCCESS
	Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
	Warning=0x2:STATUS_SEVERITY_WARNING
	Error=0x3:STATUS_SEVERITY_ERROR
	)


FacilityNames=(
	System=0x0:FACILITY_SYSTEM
	Runtime=0x2:FACILITY_RUNTIME
	Stubs=0x3:FACILITY_STUBS
	Io=0x4:FACILITY_IO_ERROR_CODE
	)

MessageId=0x1
Severity=Informational
Facility=System
SymbolicName=MONITOR_LOG
Language=English
%1
.
