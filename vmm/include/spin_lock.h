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

#ifndef MICROV_SPINLOCK_H
#define MICROV_SPINLOCK_H

#include <cstring>
#include <atomic>

namespace microv {

struct spin_lock {
    std::atomic_flag flag = ATOMIC_FLAG_INIT;

    spin_lock() noexcept
    {
        memset(&flag, 0, sizeof(flag));
    }

    void lock() noexcept
    {
        while (flag.test_and_set()) {
            __asm volatile("pause");
        }
    }

    void unlock() noexcept
    {
        flag.clear();
    }

    spin_lock(spin_lock &&) = delete;
    spin_lock(const spin_lock &) = delete;
    spin_lock &operator=(spin_lock &&) = delete;
    spin_lock &operator=(const spin_lock &) = delete;
};

static inline void spin_acquire(struct spin_lock *lock) noexcept
{
    lock->lock();
}

static inline void spin_release(struct spin_lock *lock) noexcept
{
    lock->unlock();
}

}

#endif
