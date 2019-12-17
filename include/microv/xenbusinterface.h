/*
 * Copyright (C) 2019 Assured Information Security, Inc.
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

#ifndef MICROV_XENBUSINTERFACE_H
#define MICROV_XENBUSINTERFACE_H

#include <bftypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XENBUS_ACQUIRE_CMD 0x801
#define XENBUS_DEVICETYPE  0x02a /* FILE_DEVICE_BUS_EXTENDER */

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__) || defined(_WIN64)

#ifndef INITGUID
#include <initguid.h>
#endif

DEFINE_GUID(GUID_DEVINTERFACE_XENBUS,
            0x6ff82786,
            0x6a1c,
            0x4a69,
            0x9f, 0x6a, 0x13, 0x2e, 0x0d, 0xa9, 0x86, 0x0b);

#define IOCTL_XENBUS_ACQUIRE CTL_CODE(XENBUS_DEVICETYPE,                   \
                                      XENBUS_ACQUIRE_CMD,                  \
                                      METHOD_IN_DIRECT,                    \
                                      FILE_READ_DATA | FILE_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
