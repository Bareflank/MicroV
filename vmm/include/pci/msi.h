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

#ifndef MICROV_PCI_MSI_H
#define MICROV_PCI_MSI_H

#include "cfg.h"

namespace microv {

/* MSI message control fields*/
inline uint32_t msi_nr_msg_capable(uint32_t cap)
{
    const auto pow = (cap & 0x000E'0000) >> 17;
    return 1UL << pow;
}

inline uint32_t msi_nr_msg_enabled(uint32_t cap)
{
    const auto pow = (cap & 0x0070'0000) >> 20;
    return 1UL << pow;
}

inline bool msi_64bit(uint32_t cap)
{
    return (cap & 0x0080'0000) != 0;
}

inline bool msi_per_vector_masking(uint32_t cap)
{
    return (cap & 0x0100'0000) != 0;
}

inline bool msi_enabled(uint32_t cap)
{
    return (cap & 0x0001'0000) != 0;
}

inline uint32_t msi_disable(uint32_t cap)
{
    return cap & ~0x0001'0000;
}

inline uint32_t msi_enable(uint32_t cap)
{
    return cap | 0x0001'0000;
}

/* MSI addr fields */
inline uint32_t msi_dm(uint32_t addr)
{
    return (addr >> 2) & 1;
}

inline uint32_t msi_rh(uint32_t addr)
{
    return (addr >> 3) & 1;
}

inline uint8_t msi_destid(uint32_t addr)
{
    return (addr >> 12) & 0xFF;
}

/* MSI data fields */
inline uint32_t msi_vector(uint32_t data)
{
    return data & 0xFF;
}

inline uint32_t msi_deliv_mode(uint32_t data)
{
    return (data >> 8) & 0x7;
}

inline uint32_t msi_level(uint32_t data)
{
    return (data >> 14) & 1;
}

inline uint32_t msi_trig_mode(uint32_t data)
{
    return (data >> 15) & 1;
}

struct pci_dev;

struct msi_desc {
    uint32_t reg[4]{};
    struct pci_dev *pdev{};

    bool is_enabled() const { return msi_enabled(reg[0]); }
    bool is_64bit() const { return msi_64bit(reg[0]); }
    uint32_t destid() const { return msi_destid(reg[1]); }
    uint32_t dest_mode() const { return msi_dm(reg[1]); }
    uint32_t redir_hint() const { return msi_rh(reg[1]); }
    uint32_t vector() const { return msi_vector(reg[3]); }
    uint32_t deliv_mode() const { return msi_deliv_mode(reg[3]); }
    uint32_t trigger_mode() const { return msi_trig_mode(reg[3]); }

    msi_desc() = default;
    msi_desc(const msi_desc &other) = default;
    msi_desc(msi_desc &&other) = default;
    msi_desc &operator=(const msi_desc &other) = default;
    msi_desc &operator=(msi_desc &&other) = default;
};

using msi_key_t = uint64_t; /* root_vector */
using msi_val_t = std::pair<const msi_desc *, const msi_desc *>;
using msi_map_t = std::unordered_map<msi_key_t, msi_val_t>;

inline void validate_msi(const struct msi_desc *msid)
{
    const auto vector = msid->vector();
    const auto destid = msid->destid();

    expects(msid->pdev);
    expects(vector >= 0x20);
    expects(vector <= 0xFF);
    expects(destid <= 0xFF);
//    expects((destid & (destid - 1)) == 0);
}

}
#endif
