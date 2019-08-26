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

#include <atomic>
#include <string.h>
#include <printv.h>
#include <xen/util.h>

extern "C" uint64_t _rdrand64(uint64_t *data) noexcept;

static uint64_t rdrand64(uint64_t *data) noexcept
{
    constexpr int retries = 8;
    int i = 0;
    uint64_t success = 0;
    uint64_t rand = 0;

    do {
        success = _rdrand64(&rand);
    } while (++i < retries && !success);

    if (success) {
        *data = rand;
        return 1;
    }

    return 0;
}

domid_t make_xen_domid() noexcept
{
    static_assert(std::atomic<domid_t>::is_always_lock_free);
    static std::atomic<domid_t> domid = 0;

    return domid.fetch_add(1);
}

void make_xen_uuid(xen_uuid_t *uuid)
{
    uint64_t low, high, success;

    static_assert(sizeof(*uuid) == 16);
    static_assert(sizeof(*uuid) == sizeof(low) + sizeof(high));

    success = rdrand64(&low);
    success &= rdrand64(&high);

    if (!success) {
        throw std::runtime_error("make_xen_uuid: RDRAND failed");
    }

    memcpy(uuid, &low, sizeof(low));
    memcpy((uint8_t *)uuid + sizeof(low), &high, sizeof(high));
}
