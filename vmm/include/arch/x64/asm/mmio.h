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

#ifndef MICROV_X64_MMIO_H
#define MICROV_X64_MMIO_H

#include <cstdint>
#include <compiler.h>

namespace microv {

static inline uint64_t read64(volatile void __iomem *addr)
{
    uint64_t ret;

    __asm volatile("movq %1, %0"
                   : "=r"(ret)
                   : "m"(*(volatile uint64_t *)addr)
                   : "memory");

    return ret;
}

static inline uint32_t read32(volatile void __iomem *addr)
{
    uint32_t ret;

    __asm volatile("movl %1, %0"
                   : "=r"(ret)
                   : "m"(*(volatile uint32_t *)addr)
                   : "memory");

    return ret;
}

static inline uint16_t read16(volatile void __iomem *addr)
{
    uint16_t ret;

    __asm volatile("movw %1, %0"
                   : "=r"(ret)
                   : "m"(*(volatile uint16_t *)addr)
                   : "memory");

    return ret;
}

static inline uint8_t read8(volatile void __iomem *addr)
{
    uint8_t ret;

    __asm volatile("movb %1, %0"
                   : "=r"(ret)
                   : "m"(*(volatile uint8_t *)addr)
                   : "memory");

    return ret;
}

static inline uint64_t read64_relaxed(volatile void __iomem *addr)
{
    uint64_t ret;

    __asm volatile("movq %1, %0"
                   : "=r"(ret)
                   : "m"(*(volatile uint64_t *)addr));

    return ret;
}

static inline uint32_t read32_relaxed(volatile void __iomem *addr)
{
    uint32_t ret;

    __asm volatile("movl %1, %0"
                   : "=r"(ret)
                   : "m"(*(volatile uint32_t *)addr));

    return ret;
}

static inline uint16_t read16_relaxed(volatile void __iomem *addr)
{
    uint16_t ret;

    __asm volatile("movw %1, %0"
                   : "=r"(ret)
                   : "m"(*(volatile uint16_t *)addr));

    return ret;
}

static inline uint8_t read8_relaxed(volatile void __iomem *addr)
{
    uint8_t ret;

    __asm volatile("movb %1, %0"
                   : "=r"(ret)
                   : "m"(*(volatile uint8_t *)addr));

    return ret;
}

static inline void write64(uint64_t val, volatile void __iomem *addr)
{
    __asm volatile("movq %0, %1"
                   :
                   : "r"(val), "m"(*(volatile uint64_t *)addr)
                   : "memory");
}

static inline void write32(uint32_t val, volatile void __iomem *addr)
{
    __asm volatile("movl %0, %1"
                   :
                   : "r"(val), "m"(*(volatile uint32_t *)addr)
                   : "memory");
}

static inline void write16(uint16_t val, volatile void __iomem *addr)
{
    __asm volatile("movw %0, %1"
                   :
                   : "r"(val), "m"(*(volatile uint16_t *)addr)
                   : "memory");
}

static inline void write8(uint8_t val, volatile void __iomem *addr)
{
    __asm volatile("movb %0, %1"
                   :
                   : "r"(val), "m"(*(volatile uint8_t *)addr)
                   : "memory");
}

static inline void write64_relaxed(uint64_t val, volatile void __iomem *addr)
{
    __asm volatile("movq %0, %1"
                   :
                   : "r"(val), "m"(*(volatile uint64_t *)addr));
}

static inline void write32_relaxed(uint32_t val, volatile void __iomem *addr)
{
    __asm volatile("movl %0, %1"
                   :
                   : "r"(val), "m"(*(volatile uint32_t *)addr));
}

static inline void write16_relaxed(uint16_t val, volatile void __iomem *addr)
{
    __asm volatile("movw %0, %1"
                   :
                   : "r"(val), "m"(*(volatile uint16_t *)addr));
}

static inline void write8_relaxed(uint8_t val, volatile void __iomem *addr)
{
    __asm volatile("movb %0, %1"
                   :
                   : "r"(val), "m"(*(volatile uint8_t *)addr));
}

}

#endif
