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

#ifndef MICROV_PAGE_H
#define MICROV_PAGE_H

#include <bftypes.h>
#include <bfvmm/memory_manager/memory_manager.h>

namespace microv {

constexpr size_t UV_PAGE_SIZE = 0x1000;
constexpr size_t UV_PAGE_FROM = 12;

static inline uint64_t uv_frame(uintptr_t addr)
{
    return addr >> UV_PAGE_FROM;
}

static inline uint64_t uv_addr(uint64_t frame)
{
    return frame << UV_PAGE_FROM;
}

/* uv_pg_src - who allocated the page? */
enum uv_pg_src : uint64_t {
    pg_src_none,
    pg_src_root, /* Allocated from the root domain */
    pg_src_vmm   /* Allocated from the VMM */
};

class page {
public:
    static constexpr uint64_t invalid_frame = ~0U;

    page(uint64_t id) noexcept
    {
        this->id = id;
    }

    page(uint64_t id, uint64_t hfn) noexcept
    {
        this->id = id;
        this->hfn = hfn;
        this->src = pg_src_root;
    }

    page(uint64_t id, void *ptr)
    {
        this->id = id;
        this->ptr = ptr;
        this->hfn = uv_frame(g_mm->virtptr_to_physint(ptr));
        this->src = pg_src_vmm;
    }

    bool mapped_in_vmm() const noexcept
    {
        return ptr != nullptr;
    }

    bool backed() const noexcept
    {
        return src != pg_src_none && hfn != invalid_frame;
    }

    void *ptr{nullptr};
    uint64_t id{0};
    uint64_t hfn{invalid_frame};
    uint64_t src{pg_src_none};
    uint64_t refcnt{1};
};

}

#endif
