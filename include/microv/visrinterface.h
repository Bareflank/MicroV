/*
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MICROV_VISRINTERFACE_H
#define MICROV_VISRINTERFACE_H

#include <bftypes.h>
#include "hypercall.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

#ifndef VISR_NAME
#define VISR_NAME "visr"
#endif

#ifndef VISR_DEVICETYPE
#define VISR_DEVICETYPE 0xFEED
#endif

#define IOCTL_VISR_REGISTER_EVENT_CMD 0x901

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__) || defined(_WIN64)

#include <initguid.h>

struct visr_register_event {
    HANDLE event;
};

DEFINE_GUID(GUID_DEVINTERFACE_visr,
    0x0156f59a, 0xdf90, 0x4ac6, 0x85, 0xad, 0xcf, 0xd9, 0x34, 0x25, 0x65, 0xc5);

#define IOCTL_VISR_REGISTER_EVENT CTL_CODE(VISR_DEVICETYPE, IOCTL_VISR_REGISTER_EVENT_CMD, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
