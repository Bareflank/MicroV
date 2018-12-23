//
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef FILE_H
#define FILE_H

#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

namespace bfn
{

class file
{
    using pointer = const char *;
    using size_type = std::size_t;

public:

    file(const std::string &filename) :
        m_path{filename}
    {
        fd = open(m_path.c_str(), O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("failed to open file");
        }

        fstat(fd, &m_statbuf);

        m_addr = mmap(NULL, size(), PROT_READ, MAP_SHARED, fd, 0);
        if (m_addr == MAP_FAILED) {
            throw std::runtime_error("failed to map file");
        }
    }

    ~file()
    {
        munmap(m_addr, size());
        close(fd);
    }

    pointer
    data() const noexcept
    { return static_cast<pointer>(m_addr); }

    size_type
    size() const noexcept
    { return m_statbuf.st_size; }

    const std::string &
    path() const noexcept
    { return m_path; }

private:

    int fd;
    void *m_addr;
    std::string m_path;
    struct stat m_statbuf;
};

}

#endif
