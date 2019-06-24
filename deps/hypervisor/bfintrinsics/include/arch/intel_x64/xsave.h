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

#ifndef XSAVE_INTEL_X64_H
#define XSAVE_INTEL_X64_H

#include <bftypes.h>
#include <bfdebug.h>
#include <bfbitmanip.h>

#include "crs.h"
#include "cpuid.h"

extern "C" uint64_t _xgetbv(uint32_t xcr) noexcept;
extern "C" void _xsetbv(uint32_t xcr, uint64_t val) noexcept;
extern "C" void _xsave(void *area, uint64_t rfbm) noexcept;
extern "C" void _xsaves(void *area, uint64_t rfbm) noexcept;
extern "C" void _xrstor(void *area, uint64_t rfbm) noexcept;
extern "C" void _xrstors(void *area, uint64_t rfbm) noexcept;

// *INDENT-OFF*

namespace intel_x64 {

enum xstate_bit {
    xstate_x87,
    xstate_sse,
    xstate_avx,
    xstate_bndreg,
    xstate_bndcsr,
    xstate_opmask,
    xstate_zmm_hi256,
    xstate_hi16_zmm,
    xstate_pt,
    xstate_pkru,
    xstate_hdc = 13
};

inline uint64_t read_xcr0() noexcept
{ return _xgetbv(0); }

inline uint64_t read_xinuse() noexcept
{ return _xgetbv(1); }

inline void write_xcr0(uint64_t val) noexcept
{ _xsetbv(0, val); }

inline void xsave(void *area, uint64_t rfbm) noexcept
{ _xsave(area, rfbm); }

inline void xsaves(void *area, uint64_t rfbm) noexcept
{ _xsaves(area, rfbm); }

inline void xrstor(void *area, uint64_t rfbm) noexcept
{ _xrstor(area, rfbm); }

inline void xrstors(void *area, uint64_t rfbm) noexcept
{ _xrstors(area, rfbm); }

inline bool xsave_supported() noexcept
{ return ::intel_x64::cpuid::feature_information::ecx::xsave::is_enabled(); }

inline void enable_xsave() noexcept
{ ::intel_x64::cr4::osxsave::enable(); }

inline void disable_xsave() noexcept
{ ::intel_x64::cr4::osxsave::disable(); }

/*
 * @param sub0 - subleaf 0 of leaf 0xD
 */
inline bool xsave_managed(
    const struct ::x64::cpuid::cpuid_regs &sub0,
    uint64_t bit) noexcept
{
    auto bitmap = (sub0.rdx << 32) | sub0.rax;
    return is_bit_set(bitmap, bit);
}

inline uint64_t xsave_max_size(
    const struct ::x64::cpuid::cpuid_regs &sub0) noexcept
{ return sub0.rcx; }

inline uint64_t xsave_current_size(
    const struct ::x64::cpuid::cpuid_regs &sub0) noexcept
{ return sub0.rbx; }

inline bool xsaveopt_supported(
    const struct ::x64::cpuid::cpuid_regs &sub1) noexcept
{ return is_bit_set(sub1.rax, 0); }

inline bool xsavec_supported(
    const struct ::x64::cpuid::cpuid_regs &sub1) noexcept
{ return is_bit_set(sub1.rax, 1); }

inline bool xinuse_supported(
    const struct ::x64::cpuid::cpuid_regs &sub1) noexcept
{ return is_bit_set(sub1.rax, 2); }

inline bool xsaves_supported(
    const struct ::x64::cpuid::cpuid_regs &sub1) noexcept
{ return is_bit_set(sub1.rax, 3); }

inline uint64_t xsaves_current_size(
    const struct ::x64::cpuid::cpuid_regs &sub1) noexcept
{ return sub1.rbx; }

inline bool xsaves_managed(
    const struct ::x64::cpuid::cpuid_regs &sub1,
    uint64_t bit) noexcept
{
    auto bitmap = (sub1.rdx << 32) | sub1.rcx;
    return is_bit_set(bitmap, bit);
}

// *INDENT-ON*

}

#endif
