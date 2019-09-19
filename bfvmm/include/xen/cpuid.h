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

#ifndef MICROV_XEN_CPUID_H
#define MICROV_XEN_CPUID_H

#include "types.h"
#include <public/arch-x86/cpufeatureset.h>

namespace microv {

constexpr uint32_t xen_cpufeat_to_word(uint32_t feat)
{
    constexpr auto word_shift = 5U;
    return feat >> word_shift;
}

constexpr auto xen_last_cpufeat = XEN_X86_FEATURE_AVX512_BF16;
constexpr auto xen_cpufeat_words = xen_cpufeat_to_word(xen_last_cpufeat) + 1;

/*
 * xen_init_cpufeatures
 *
 * Initialize the various cpufeaturesets for the VMM and guests
 */
void xen_init_cpufeatures() noexcept;

/*
 * xen_get_pvh_cpufeatures
 *
 * Return the default cpufeatures of a PVH guest in @cpufeat
 */
void xen_get_pvh_cpufeatures(uint32_t cpufeat[xen_cpufeat_words]) noexcept;

}

#endif
