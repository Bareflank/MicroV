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

#ifndef MICROV_IOMMU_ENTRY_H
#define MICROV_IOMMU_ENTRY_H

#include <bfgsl.h>
#include <cstdint>
#include "../page.h"

namespace microv {

struct iommu_entry {
    uint64_t data[2];
} __attribute__((packed));

inline bool rte_present(const struct iommu_entry *rte)
{
    return (rte->data[0] & 1) != 0;
}

inline void rte_set_present(struct iommu_entry *rte)
{
    rte->data[0] |= 1;
}

inline void rte_clear_present(struct iommu_entry *rte)
{
    rte->data[0] &= ~1ULL;
}

inline void rte_set_ctp(struct iommu_entry *rte, uintptr_t ctp)
{
    expects(uv_align_page(ctp) == ctp);
    rte->data[0] |= ctp;
}

inline uintptr_t rte_ctp(struct iommu_entry *rte)
{
    return uv_align_page(rte->data[0]);
}

inline bool cte_present(const struct iommu_entry *cte)
{
    return (cte->data[0] & 1) != 0;
}

inline void cte_set_present(struct iommu_entry *cte)
{
    cte->data[0] |= 1;
}

inline void cte_clear_present(struct iommu_entry *cte)
{
    cte->data[0] &= ~1ULL;
}

/* Context entry translation types */
#define CTE_TT_U 0U /* Untranslated only */
#define CTE_TT_UTT 1U /* Untranslated, Translated and Translation requests */
#define CTE_TT_PT 2U /* Pass-through */

inline void cte_set_tt(struct iommu_entry *cte, unsigned int tt)
{
    cte->data[0] &= ~0xCULL;
    cte->data[0] |= tt << 2;
}

inline void cte_set_slptptr(struct iommu_entry *cte, uintptr_t slptptr)
{
    expects(uv_align_page(slptptr) == slptptr);
    cte->data[0] |= slptptr;
}

inline uintptr_t cte_slptptr(struct iommu_entry *cte)
{
    return uv_align_page(cte->data[0]);
}

inline void cte_set_aw(struct iommu_entry *cte, unsigned int aw)
{
    cte->data[1] &= ~0x7ULL;
    cte->data[1] |= aw;
}

inline void cte_set_did(struct iommu_entry *cte, unsigned int did)
{
    cte->data[1] &= ~0xFFFF00ULL;
    cte->data[1] |= did << 8;
}

}

#endif
