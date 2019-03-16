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

#ifndef DOMAIN_FACTORY_BOXY_H
#define DOMAIN_FACTORY_BOXY_H

#include <memory>
#include "domain.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy
{

/// Domain Factory
///
class domain_factory
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    domain_factory() noexcept = default;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~domain_factory() = default;

    /// Make vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param domainid the domainid for the domain to create
    /// @param obj object passed to the domain
    /// @return returns a pointer to a newly created vCPU.
    ///
    virtual std::unique_ptr<domain> make(
        domain::domainid_type domainid, bfobject *obj = nullptr);

public:

    /// @cond

    domain_factory(domain_factory &&) noexcept = default;
    domain_factory &operator=(domain_factory &&) noexcept = default;

    domain_factory(const domain_factory &) = delete;
    domain_factory &operator=(const domain_factory &) = delete;

    /// @endcond
};

}

#endif
