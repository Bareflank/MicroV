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

#ifndef IOCTL_H
#define IOCTL_H

#include <memory>

#include <bfgsl.h>
#include <bfbuilderinterface.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// IOCTL Private Base
///
/// Only needed for dynamic cast
///
class ioctl_private_base
{
public:

    /// Default Constructor
    ///
    ioctl_private_base() = default;

    /// Default Destructor
    ///
    virtual ~ioctl_private_base() = default;
};

/// IOCTL
///
/// Calls into the bareflank driver entry to perform a desired action. Note
/// that for this class to function, the driver entry must be loaded, and
/// bfm must be executed with the proper permissions.
///
class ioctl
{
public:

    using file_type = std::vector<gsl::byte>;
    using size_type = std::size_t;

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ioctl();

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~ioctl() = default;

    /// Create VM from bzImage
    ///
    /// Creates a virtual machine given a Linux bzImage.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param args the args needed to create the VM
    ///
    void call_ioctl_create_vm_from_bzimage(create_vm_from_bzimage_args &args);

    /// Destroy VM
    ///
    /// Destroys a VM given a domain ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param domainid the domain to destroy
    ///
    void call_ioctl_destroy(domainid_t domainid) noexcept;

private:

    std::unique_ptr<ioctl_private_base> m_d;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
