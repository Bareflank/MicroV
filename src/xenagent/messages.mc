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

MessageId=0x0001
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_POWEROFF
Language=English
The tools requested that the local VM shut itself down.
.

MessageId=0x0002
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_REBOOT
Language=English
The tools requested that the local VM reboot.
.

MessageId=0x0003
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_S4
Language=English
The tools requested that the local VM enter power state S4.
.

MessageId=0x0004
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_S3
Language=English
The tools requested that the local VM enter power state S3.
.

MessageId=0x0005
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_WMI
Language=English
The tools noticed that WMI became non-functional.
.

MessageId=0x0006
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_STARTED
Language=English
The tools initiated.
.

MessageId=0x0007
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_UNSUSPENDED
Language=English
The tools returned from suspend.
.

MessageId=0x0008
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_UNEXPECTED
Language=English
The tools experienced an unexpected error.
.

MessageId=0x0009
Facility=System
Severity=Informational
SymbolicName=EVENT_XENUSER_MODE_SWITCH
Language=English
The tools requested a mode switch.
.
