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

#ifndef XSAVE_INTEL_X64_MICROV_H
#define XSAVE_INTEL_X64_MICROV_H

#include <array>
#include <memory>
#include <arch/intel_x64/xsave.h>

namespace microv::intel_x64 {

using namespace ::intel_x64;
class vcpu;

enum xsave_bit : uint64_t {
    x87 = 0,
    sse = 1,
    avx = 2,
    bndreg = 3,
    bndcsr = 4,
    opmask = 5,
    zmm_hi256 = 6,
    hi16_zmm = 7,
    pt = 8,
    pkru = 9,
    hdc = 13
};
constexpr auto MAX_XSAVE_STATE = hdc + 1;

struct xsave_state {
    bool supported;
    bool user;
    uint8_t bit;
    uint8_t align;
    size_t size;
    size_t offset;
};

class xsave {
public:
    xsave(microv::intel_x64::vcpu *vcpu);
    ~xsave() = default;

    xsave(xsave &&) = default;
    xsave &operator=(xsave &&) = default;

    xsave(const xsave &) = delete;
    xsave &operator=(const xsave &) = delete;

private:
    /* size required for xcr0 states */
    size_t m_max_size{};
    size_t m_cur_size{};

    page_ptr<uint8_t> m_area;
    microv::intel_x64::vcpu *m_vcpu{};
    std::array<struct xsave_state, MAX_XSAVE_STATE> m_state{};
};

inline void dump_xsave_bitmap(uint64_t bitmap) noexcept
{
    bfdebug_subbool(0, "x87", is_bit_set(bitmap, xsave_bit::x87));
    bfdebug_subbool(0, "sse", is_bit_set(bitmap, xsave_bit::sse));
    bfdebug_subbool(0, "avx", is_bit_set(bitmap, xsave_bit::avx));
    bfdebug_subbool(0, "bndreg", is_bit_set(bitmap, xsave_bit::bndreg));
    bfdebug_subbool(0, "bndcsr", is_bit_set(bitmap, xsave_bit::bndcsr));
    bfdebug_subbool(0, "zmm_hi256", is_bit_set(bitmap, xsave_bit::zmm_hi256));
    bfdebug_subbool(0, "hi16_zmm", is_bit_set(bitmap, xsave_bit::hi16_zmm));
    bfdebug_subbool(0, "pt", is_bit_set(bitmap, xsave_bit::pt));
    bfdebug_subbool(0, "pkru", is_bit_set(bitmap, xsave_bit::pkru));
    bfdebug_subbool(0, "hdc", is_bit_set(bitmap, xsave_bit::hdc));
}

}

#endif
