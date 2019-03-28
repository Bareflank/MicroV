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

#ifndef DOMAIN_BOXY_H
#define DOMAIN_BOXY_H

#include <bftypes.h>
#include <bfobject.h>
#include <bfhypercall.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy
{

/// Domain
///
class domain : public bfobject
{
public:

    using domainid_type = domainid_t;

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    domain(domainid_type domainid);

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
    domainid_type id() const noexcept;

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
    static domainid_type generate_domainid() noexcept
    {
        static domainid_type s_id = 1;
        return s_id++;
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

    domainid_type m_id;
    uintptr_t m_entry;

public:

    /// @cond

    domain(domain &&) = default;
    domain &operator=(domain &&) = default;

    domain(const domain &) = delete;
    domain &operator=(const domain &) = delete;

    /// @endcond
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

constexpr domain::domainid_type invalid_domainid = INVALID_DOMAINID;
constexpr domain::domainid_type self = SELF;

}

#endif
