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

#ifndef MICROV_MATH_H
#define MICROV_MATH_H

#include <type_traits>
#include <bftypes.h>

constexpr auto is_power_of_2(const uint64_t n)
{ return (n > 0) && ((n & (n - 1)) == 0); }

constexpr auto next_power_of_2(uint64_t n)
{
    while (!is_power_of_2(n)) {
        n++;
    }
    return n;
}

template<
    uint64_t s,
    typename std::enable_if_t<is_power_of_2(s)> * = nullptr
    >
constexpr auto log2()
{
    for (auto i = 0; i < 64; i++) {
        if (((1ULL << i) & s) == s) {
            return i;
        }
    }

    return 0;
}

#endif
