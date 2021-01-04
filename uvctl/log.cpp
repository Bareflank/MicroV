//
// Copyright (C) 2020 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "log.h"

#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>

#ifndef _WIN64
#include <stdarg.h>
#else
#include <malloc.h>
#include <windows.h>
#endif

static int log_mode = UVCTL_LOG_STDOUT;
static std::mutex log_mutex;

static inline void log_msg_stdout(const char *buf)
{
    std::cout << buf;
}

static inline void log_msg_windows_svc(const char *buf)
{
#ifdef _WIN64
    OutputDebugString(buf);
#endif
}

static inline void log_raw_stdout(char *buf, int size)
{
    std::cout.write(buf, size);
    std::cout.flush();
}

static inline void log_raw_windows_svc(char *buf, int size)
{
#ifdef _WIN64
    if (buf[size - 1] == 0) {
        OutputDebugString(buf);
        return;
    }

    // If the buffer isn't NULL-terminated, make it that way
    // so we can use OutputDebugString.
    char *tmp = (char *)malloc(size + 1);

    if (!tmp) {
        // Print what we can...
        buf[size - 1] = 0;
        OutputDebugString(buf);
    } else {
        std::memcpy(tmp, buf, size);
        tmp[size] = 0;
        OutputDebugString(tmp);
        free(tmp);
    }
#endif
}

void log_set_mode(int mode) noexcept
{
    try {
        std::lock_guard lock(log_mutex);
        log_mode = mode;
    } catch (std::exception &e) {
        std::cerr << __func__ << ": failed (what=" << e.what() << ")\n";
    }
}

void log_msg(const char *fmt, ...) noexcept
{
    try {
        constexpr uint32_t LOG_MSG_SIZE = 256U;
        char msg[LOG_MSG_SIZE];
        va_list args;

        std::lock_guard lock(log_mutex);

        va_start(args, fmt);
        vsnprintf(msg, sizeof(msg), fmt, args);
        va_end(args);

        switch (log_mode) {
        case UVCTL_LOG_STDOUT:
            log_msg_stdout(msg);
            break;
        case UVCTL_LOG_WINDOWS_SVC:
            log_msg_windows_svc(msg);
            break;
        default:
            log_msg_stdout(msg);
            break;
        }
    } catch (std::exception &e) {
        std::cerr << __func__ << ": failed (what=" << e.what() << ")\n";
    }
}

void log_raw(char *buf, int size) noexcept
{
    try {
        if (size == 0) {
            return;
        }

        if (size >= INT_MAX) {
            return;
        }

        std::lock_guard lock(log_mutex);

        switch (log_mode) {
        case UVCTL_LOG_STDOUT:
            log_raw_stdout(buf, size);
            break;
        case UVCTL_LOG_WINDOWS_SVC:
            log_raw_windows_svc(buf, size);
            break;
        default:
            log_raw_stdout(buf, size);
            break;
        }
    } catch (std::exception &e) {
        std::cerr << __func__ << ": failed (what=" << e.what() << ")\n";
    }
}
