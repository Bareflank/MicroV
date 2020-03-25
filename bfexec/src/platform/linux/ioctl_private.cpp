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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-vararg
//
// Reason:
//    The Linux APIs require the use of var-args, so this test has to be
//    disabled.
//

#include <iostream>
#include <ioctl_private.h>

#include <bfgsl.h>
#include <bfdriverinterface.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

int
bfm_ioctl_open_bareflank()
{ return open("/dev/bareflank", O_RDWR); }

int
bfm_ioctl_open_bareflank_builder()
{ return open("/dev/bareflank_builder", O_RDWR); }

int64_t
bfm_write_ioctl(int fd, unsigned long request, const void *data)
{
    return ioctl(fd, request, data);
}

int64_t
bfm_write_read_ioctl(int fd, unsigned long request, void *data)
{
    return ioctl(fd, request, data);
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private()
{
    if ((fd1 = bfm_ioctl_open_bareflank()) < 0) {
        throw std::runtime_error("failed to open to the bareflank driver");
    }

    if ((fd2 = bfm_ioctl_open_bareflank_builder()) < 0) {
        throw std::runtime_error("failed to open to the bareflank builder driver");
    }
}

ioctl_private::~ioctl_private()
{
    close(fd1);
    close(fd2);
}

void
ioctl_private::call_ioctl_create_vm_from_bzimage(
    create_vm_from_bzimage_args &args)
{
    if (bfm_write_ioctl(fd2, IOCTL_CREATE_VM_FROM_BZIMAGE, &args) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_CREATE_VM_FROM_BZIMAGE");
    }
}

void
ioctl_private::call_ioctl_destroy(domainid_t domainid) noexcept
{
    if (bfm_write_ioctl(fd2, IOCTL_DESTROY, &domainid) < 0) {
        std::cerr << "[ERROR] ioctl failed: IOCTL_DESTROY\n";
    }
}

uint64_t
ioctl_private::call_ioctl_vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4)
{
    ioctl_vmcall_args_t args = {r1, r2, r3, r4};

    if (bfm_write_read_ioctl(fd1, IOCTL_VMCALL, &args) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_VMCALL");
    }

    return args.reg1;
}
