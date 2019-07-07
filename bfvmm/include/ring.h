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

#ifndef MICROV_RING_H
#define MICROV_RING_H

#include <array>
#include <bfgsl.h>
#include <bfmath.h>
#include <bftypes.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace microv {

template<
    size_t size,
    typename std::enable_if_t<is_power_of_2(size)>* = nullptr>
class ring {
public:
    ring() = default;
    ~ring() = default;

    size_t put(const gsl::span<char> &span)
    {
        size_t i = 0;
        auto buf = span.data();

        while (next(m_enq) != m_deq && i < span.size()) {
            this->push(buf[i++]);
        }

        return i;
    }

    size_t get(const gsl::span<char> &span)
    {
        size_t i = 0;
        auto buf = span.data();

        while (m_enq != m_deq && i < span.size()) {
            buf[i++] = this->pop();
        }

        return i;
    }

private:

    size_t next(size_t pos)
    {
        return (pos + 1) & (size - 1);
    }

    void push(char c)
    {
        m_buf[m_enq] = c;
        m_enq = next(m_enq);
    }

    char pop()
    {
        char c = m_buf[m_deq];
        m_deq = next(m_deq);
        return c;
    }

    size_t m_enq{};
    size_t m_deq{};
    std::array<char, size> m_buf{};

public:
    ring(ring &&) = default;
    ring &operator=(ring &&) = default;
    ring(const ring &) = delete;
    ring &operator=(const ring &) = delete;
};
}

#endif
