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
inline uint32_t msi_mult_capable(uint32_t cap)
{
    return (cap >> 17) & 0x7;
}

inline uint32_t msi_mult_enable(uint32_t cap)
{
    return (cap >> 20) & 0x7;
}

inline bool msi_64bit(uint32_t cap)
{
    return cap & 0x80'0000;
}

inline bool msi_enabled(uint32_t cap)
{
    return cap & 0x01'0000;
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
    struct pci_dev *pdev;
    uint32_t cap;
    uint32_t data;
    uint32_t addr[2];

    bool is_64bit() const { return msi_64bit(cap); }
    uint32_t destid() const { return msi_destid(addr[0]); }
    uint32_t vector() const { return msi_vector(data); }
    uint32_t deliv_mode() const { return msi_deliv_mode(data); }
    struct pci_dev *dev() const { return pdev; }

    msi_desc(struct pci_dev *pdev,
             uint32_t cap, uint32_t data, uint32_t addr0, uint32_t addr1)
    {
        expects(!msi_rh(addr0));       /* no redirection */
        expects(!msi_trig_mode(data)); /* edge triggered */

        this->pdev = pdev;
        this->cap = cap;
        this->data = data;
        this->addr[0] = addr0;
        this->addr[1] = addr1;

        if (this->deliv_mode() == 1) {
            bfalert_info(0, "MSI using lowest-priority delivery");
        } else if (this->deliv_mode()) {
            bfalert_nhex(0, "MSI using unsupported delivery", deliv_mode());
        }
    }

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

    expects(msid->dev());
    expects(vector >= 0x20);
    expects(vector <= 0xFF);
    expects(destid <= 0xFF);
    expects((destid & (destid - 1)) == 0);
}

}
#endif
