/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MV_TYPES_H
#define MV_TYPES_H

#include <inttypes.h>    // IWYU pragma: export
#include <stdint.h>      // IWYU pragma: export
#include <types.h>       // IWYU pragma: export

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __clang__
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wcast-align"
#pragma clang diagnostic ignored "-Wcast-qual"
#endif

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

    /** @brief Defines the type used for returning status from a hypercall */
    typedef uint64_t mv_status_t;

    /**
     * <!-- description -->
     *   @brief See bsl::touch() for more information.
     */
    static inline void
    mv_touch(void) NOEXCEPT
    {}

#ifdef __cplusplus
#define FALLTHROUGH [[fallthrough]]
#else
#ifdef __clang__
#define FALLTHROUGH                                                                                \
    mv_touch();                                                                                    \
    __attribute__((__fallthrough__))
#elif defined(__GNUC__)
#define FALLTHROUGH                                                                                \
    mv_touch();                                                                                    \
    __attribute__((__fallthrough__))
#else
#define FALLTHROUGH
#endif
#endif

#ifdef __cplusplus
#define CONSTEXPR constexpr
#else
#define CONSTEXPR static inline
#endif

#ifdef __cplusplus
#define NODISCARD [[nodiscard]]
#else
#ifdef __clang__
#define NODISCARD __attribute__((warn_unused_result))
#else
#define NODISCARD
#endif
#endif

#ifdef __cplusplus
#define NULLPTR nullptr
#else
#define NULLPTR ((void *)0)
#endif

#ifndef NULL
#define NULL NULLPTR
#endif

#ifdef __cplusplus
}
#endif

#endif
