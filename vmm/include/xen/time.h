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

#ifndef MICROV_XEN_TIME_H
#define MICROV_XEN_TIME_H

#include "types.h"
#include <public/xen.h>

/*
 * nanosecond <-> tsc conversion (from public/xen.h):
 *
 * ns = ((ticks << tsc_shift) * tsc_to_system_mul) >> 32
 * ns << 32 = (ticks << tsc_shift) * tsc_to_system_mul
 * ((ns << 32) / tsc_to_system_mul) = ticks << tsc_shift
 * ((ns << 32) / tsc_to_system_mul) >> tsc_shift = ticks
 *
 * CPU frequency (Hz):
 *   ((10^9 << 32) / tsc_to_system_mul) >> tsc_shift
 */

/* convert seconds to nanoseconds */
static constexpr uint64_t s_to_ns(uint64_t sec) noexcept
{
    return sec * 1000000000ULL;
}

/* convert tsc ticks to nanoseconds */
static inline uint64_t tsc_to_ns(uint64_t ticks,
                                 uint64_t shft,
                                 uint64_t mult) noexcept
{
    return ((ticks << shft) * mult) >> 32;
}

/* convert nanoseconds to tsc ticks */
static inline uint64_t ns_to_tsc(uint64_t ns,
                                 uint64_t shft,
                                 uint64_t mult) noexcept
{
    return ((ns << 32) / mult) >> shft;
}

/* convert tsc ticks to VMX preemption timer ticks */
static inline uint64_t tsc_to_pet(uint64_t tsc, uint64_t pet_shift) noexcept
{
    return tsc >> pet_shift;
}

/* Taken from xen/include/asm-x86/div64.h */
#define do_div(n, base)                                                        \
    ({                                                                         \
        uint32_t __base = (base);                                              \
        uint32_t __rem;                                                        \
        __rem = ((uint64_t)(n)) % __base;                                      \
        (n) = ((uint64_t)(n)) / __base;                                        \
        __rem;                                                                 \
    })

#endif
