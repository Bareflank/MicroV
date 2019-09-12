//
// Copyright (C) 2019 Assured Information Security, Inc.
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

#ifndef MICROV_CLFLUSH_H
#define MICROV_CLFLUSH_H

#include <arch/intel_x64/barrier.h>
#include <arch/x64/cpuid.h>
#include <bfgsl.h>

extern "C" void _clwb(void *p) noexcept;
extern "C" void _clflush(void *p) noexcept;
extern "C" void _clflushopt(void *p) noexcept;

static inline void __clwb(void *p) noexcept
{
    ::intel_x64::mb();
    _clwb(p);
    ::intel_x64::mb();
}

static inline void __clflush(void *p) noexcept
{
    ::intel_x64::mb();
    _clflush(p);
    ::intel_x64::mb();
}

static inline void __clflushopt(void *p) noexcept
{
    ::intel_x64::mb();
    _clflushopt(p);
    ::intel_x64::mb();
}

inline void (*clwb)(void *) noexcept;
inline void (*clflush)(void *) noexcept;
inline unsigned int clsize{};

static inline void init_cache_ops()
{
    const auto leaf1 = ::x64::cpuid::get(1, 0, 0, 0);
    const auto leaf7 = ::x64::cpuid::get(7, 0, 0, 0);

    if (leaf7.rbx & (1UL << 23)) {
        clflush = __clflushopt;
    } else {
        expects(leaf1.rdx & (1UL << 19));
        clflush = __clflush;
    }

    clwb = (leaf7.rbx & (1UL << 24)) ? __clwb : clflush;
    clsize = ((leaf1.rbx & 0xFF00) >> 8) * 8;
}

static inline void clflush_range(void *p, unsigned int bytes) noexcept
{
    for (auto i = 0UL; i < bytes; i += clsize) {
        clflush((char *)p + i);
    }
}

static inline void clwb_range(void *p, unsigned int bytes) noexcept
{
    for (auto i = 0UL; i < bytes; i += clsize) {
        clwb((char *)p + i);
    }
}

#endif
