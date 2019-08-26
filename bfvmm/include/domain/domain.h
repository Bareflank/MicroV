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

#ifndef DOMAIN_MICROV_H
#define DOMAIN_MICROV_H

#include <bftypes.h>
#include <bfobject.h>
#include <bfgpalayout.h>
#include <bfhypercall.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace microv
{

struct domain_info : public bfobject {
    virtual ~domain_info() = default;

    /* DOMF_* flags (see bfhypercall.h) */
    uint64_t flags{};

    /* Time of domain creation */
    uint64_t wc_sec{};
    uint64_t wc_nsec{};
    uint64_t tsc;

    /* Bytes of RAM */
    uint64_t ram{};

    void copy(const domain_info *info)
    {
        flags = info->flags;
        wc_sec = info->wc_sec;
        wc_nsec = info->wc_nsec;
        tsc = info->tsc;
        ram = info->ram;
    }

    bool is_xen_dom() const noexcept
    {
        return flags & DOMF_EXEC_XENPVH;
    }

    bool is_xenstore() const noexcept
    {
        return flags & DOMF_XENSTORE;
    }

    bool using_hvc() const noexcept
    {
        return flags & DOMF_XENHVC;
    }

    bool is_ndvm() const noexcept
    {
        return flags & DOMF_NDVM;
    }

    uint64_t total_ram() const noexcept
    {
        return ram;
    }

    uint64_t total_ram_pages() const noexcept
    {
        return this->total_ram() >> UVG_PAGE_SHIFT;
    }

    uint64_t max_mfn() const noexcept
    {
        return this->total_ram_pages() - 1;
    }
};

/// Domain
///
class domain : public bfobject {
public:
    using id_t = domainid_t;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    domain(id_t domainid);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    virtual ~domain() = default;

    /// Run
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    VIRTUAL void run(bfobject *obj = nullptr);

    /// Halt
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    VIRTUAL void hlt(bfobject *obj = nullptr);

    /// Init vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    VIRTUAL void init(bfobject *obj = nullptr);

    /// Fini vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj object that can be passed around as needed
    ///     by extensions of Bareflank
    ///
    VIRTUAL void fini(bfobject *obj = nullptr);

    /// Get ID
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the domain ID
    ///
    id_t id() const noexcept;

    /// Generate Domain ID
    ///
    /// Note:
    ///
    /// Xen has a max ID of 0x7FEF, which means that we would have
    /// a similar upper limit. For now this is not an issue, but if we
    /// get to a point where we support a large number of really small
    /// VMs, we could hit this limit and will need to address this.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns a new, unique domain id
    ///
    static id_t generate_domainid() noexcept
    {
        static std::atomic<id_t> s_id = 1;
        return s_id.fetch_add(1);
    }

    /// Set Entry
    ///
    /// Sets the entry point (GPA) of the VM. This can be usd by a vCPU
    /// to set it's entry point.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address of the VM's entry point
    ///
    void set_entry(uintptr_t gpa) noexcept;

    /// Get Entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the VM's entry point
    ///
    uintptr_t entry() const noexcept;

private:

    id_t m_id;
    uintptr_t m_entry;

public:

    /// @cond

    domain(domain &&) = delete;
    domain &operator=(domain &&) = delete;

    domain(const domain &) = delete;
    domain &operator=(const domain &) = delete;

    /// @endcond
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

constexpr domain::id_t invalid_domainid = INVALID_DOMAINID;
constexpr domain::id_t self = SELF;

}

#endif
