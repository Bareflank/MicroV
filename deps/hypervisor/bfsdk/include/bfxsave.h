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

/**
 * @file bfxsave.h
 */

#ifndef BFXSAVE
#define BFXSAVE

#include <bftypes.h>
#include <bfconstants.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

#define XSAVE_LEGACY_MASK 0x3ULL
#define XSAVE_AVX_MASK (0x4ULL | XSAVE_LEGACY_MASK)
#define XSAVE_AVX512_MASK ((0x7ULL << 5) | XSAVE_AVX_MASK)

#if defined(BFVMM_AVX512)
#define XSAVE_BUILD_XCR0 XSAVE_AVX512_MASK
#elif defined(BFVMM_AVX)
#define XSAVE_BUILD_XCR0 XSAVE_AVX_MASK
#else
#define XSAVE_BUILD_XCR0 XSAVE_LEGACY_MASK
#endif

/**
 * struct xsave_info
 *
 * Contains information for managing threads' XSAVE state
 */
struct xsave_info {
    uint8_t *host_area;   /* 0x00 */
    uint8_t *guest_area;  /* 0x08 */
    uint64_t host_xcr0;   /* 0x10 */
    uint64_t guest_xcr0;  /* 0x18 */
    uint64_t host_size;   /* 0x20 */
    uint64_t guest_size;  /* 0x28 */
    uint64_t pcpuid;      /* 0x30 */
    uint64_t vcpuid;      /* 0x38 */
    uint64_t ready;       /* 0x40 */
    uint64_t cpuid_xcr0;  /* 0x48 */
};

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
