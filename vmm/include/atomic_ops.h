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

#ifndef MICROV_ATOMIC_OPS_H
#define MICROV_ATOMIC_OPS_H

#include <atomic>
#include <cstdint>

namespace microv {

static inline bool test_and_set_bit(std::atomic<uint32_t> *word,
                                    uint32_t bit) noexcept
{
    uint32_t mask = 1 << bit;

    return (word->fetch_or(mask) & mask) != 0;
}

static inline bool test_bit(std::atomic<uint32_t> *word, uint32_t bit) noexcept
{
    uint32_t mask = 1 << bit;

    return (word->load() & mask) != 0;
}

static inline void clear_bit(std::atomic<uint32_t> *word, uint32_t bit) noexcept
{
    uint32_t mask = ~(1 << bit);

    word->fetch_and(mask);
}

static inline void set_bit(std::atomic<uint32_t> *word, uint32_t bit) noexcept
{
    uint32_t mask = (1 << bit);

    word->fetch_or(mask);
}

static inline uint32_t read_atomic(std::atomic<uint32_t> *word) noexcept
{
    return word->load();
}

static inline void write_atomic(std::atomic<uint32_t> *word,
                                uint32_t val) noexcept
{
    word->store(val);
}

}

#endif
