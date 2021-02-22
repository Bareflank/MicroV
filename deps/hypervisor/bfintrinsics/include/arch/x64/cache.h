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

#ifndef CACHE_X64_H
#define CACHE_X64_H

#include <cstdint>
#include "cpuid.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" void _invd(void) noexcept;
extern "C" void _wbinvd(void) noexcept;
extern "C" void _clflush(void *addr) noexcept;
extern "C" void _clflushopt(void *addr) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace cache
{

using pointer = void *;
using integer_pointer = uintptr_t;

inline uint32_t line_size;
inline void (*__clflush)(pointer);

inline void init_cache_ops()
{
    const auto leaf1 = ::x64::cpuid::get(1, 0, 0, 0);
    const auto leaf7 = ::x64::cpuid::get(7, 0, 0, 0);

    if (leaf7.rbx & (1UL << 23)) {
        __clflush = _clflushopt;
    } else {
        expects(leaf1.rdx & (1UL << 19));
        __clflush = _clflush;
    }

    line_size = ((leaf1.rbx & 0xFF00) >> 8) * 8;
}

inline void clflush_range(pointer p, uint32_t bytes) noexcept
{
    for (auto i = 0UL; i < bytes; i += line_size) {
        auto addr = reinterpret_cast<uint8_t *>(p) + i;
        __clflush(reinterpret_cast<pointer>(addr));
    }
}

inline void clflush(pointer p) noexcept
{ __clflush(p); }

inline void clflush(integer_pointer p) noexcept
{ __clflush(reinterpret_cast<pointer>(p)); }

inline void invd() noexcept
{ _invd(); }

inline void wbinvd() noexcept
{ _wbinvd(); }

}
}

// *INDENT-ON*

#endif
