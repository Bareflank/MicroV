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

#ifndef MICROV_IOMMU_H
#define MICROV_IOMMU_H

#include <bftypes.h>
#include <bfvmm/hve/arch/x64/unmapper.h>
#include <bfvmm/memory_manager/memory_manager.h>

#include "dmar.h"
#include "regs.h"

namespace microv {

using namespace iommu_regs;

class iommu {
public:
    using entry_t = struct { uint64_t data[2]; };

    static constexpr size_t page_size = 4096;

    iommu(struct drhd *drhd);
    ~iommu() = default;

    iommu(iommu &&) = default;
    iommu &operator=(iommu &&) = default;

    iommu(const iommu &) = delete;
    iommu &operator=(const iommu &) = delete;

private:
    struct drhd *drhd{};
    uintptr_t reg_base{};

    uint32_t ver{};
    uint64_t cap{};
    uint64_t ecap{};

    size_t iotlb_reg_off{};
    static constexpr size_t iotlb_reg_num = 2;
    static constexpr size_t iotlb_reg_len = 8;
    static constexpr size_t iotlb_reg_bytes = iotlb_reg_num * iotlb_reg_len;

    size_t frcd_reg_off{};
    size_t frcd_reg_num{};
    size_t frcd_reg_bytes{};
    static constexpr size_t frcd_reg_len = 16;

    uint64_t read64(size_t offset)
    {
        return *reinterpret_cast<volatile uint64_t *>(reg_base + offset);
    }

    uint32_t read32(size_t offset)
    {
        return *reinterpret_cast<volatile uint32_t *>(reg_base + offset);
    }

    void write64(size_t offset, uint64_t val)
    {
        *reinterpret_cast<volatile uint64_t *>(reg_base + offset) = val;
    }

    void write32(size_t offset, uint32_t val)
    {
        *reinterpret_cast<volatile uint32_t *>(reg_base + offset) = val;
    }

    uint32_t read_gcmd() { return read32(gcmd_offset); }
    uint32_t read_gsts() { return read32(gsts_offset); }
    uint64_t read_rtaddr() { return read64(rtaddr_offset); }
    uint64_t read_ccmd() { return read64(ccmd_offset); }

    void write_gcmd(uint32_t val) { write32(gcmd_offset, val); }
    void write_rtaddr(uint64_t val) { write64(rtaddr_offset, val); }
    void write_ccmd(uint64_t val) { write64(ccmd_offset, val); }
};

extern char *mcfg_hva;
extern size_t mcfg_len;

int probe_acpi();
int probe_iommu();

}

#endif
