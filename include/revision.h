/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _REVISION_H
#define _REVISION_H

// Key:
// S  - XENBUS_SUSPEND_INTERFACE
// SI - XENBUS_SHARED_INFO_INTERFACE
// E  - XENBUS_EVTCHN_INTERFACE
// D  - XENBUS_DEBUG_INTEFACE
// ST - XENBUS_STORE_INTERFACE
// R  - XENBUS_RANGE_SET_INTERFACE
// C  - XENBUS_CACHE_INTERFACE
// G  - XENBUS_GNTTAB_INTERFACE
// U  - XENBUS_UNPLUG_INTERFACE
// CO - XENBUS_CONSOLE_INTERFACE
// EM - XENFILT_EMULATED_INTERFACE

//                    REVISION   S  SI   E   D  ST   R   C   G   U  CO  EM
#define DEFINE_REVISION_TABLE                                                \
    DEFINE_REVISION(0x08000009,  1,  2,  4,  1,  1,  1,  1,  1,  1,  0,  1), \
    DEFINE_REVISION(0x0800000A,  1,  2,  5,  1,  1,  1,  1,  1,  1,  0,  1), \
    DEFINE_REVISION(0x0800000B,  1,  2,  5,  1,  2,  1,  1,  2,  1,  0,  1), \
    DEFINE_REVISION(0x09000000,  1,  2,  5,  1,  2,  1,  1,  2,  1,  0,  1), \
    DEFINE_REVISION(0x09000001,  1,  2,  6,  1,  2,  1,  1,  2,  1,  1,  1), \
    DEFINE_REVISION(0x09000002,  1,  2,  7,  1,  2,  1,  1,  2,  1,  1,  1), \
    DEFINE_REVISION(0x09000003,  1,  2,  8,  1,  2,  1,  1,  2,  1,  1,  1), \
    DEFINE_REVISION(0x09000004,  1,  2,  8,  1,  2,  1,  1,  3,  1,  1,  1), \
    DEFINE_REVISION(0x09000005,  1,  2,  8,  1,  2,  1,  2,  4,  1,  1,  1), \
    DEFINE_REVISION(0x09000006,  1,  3,  8,  1,  2,  1,  2,  4,  1,  1,  1), \
    DEFINE_REVISION(0x09000007,  1,  3,  8,  1,  2,  1,  2,  4,  1,  1,  2)

#endif  // _REVISION_H
