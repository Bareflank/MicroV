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

#ifndef FILE_H
#define FILE_H

#include <string>
#include <vector>
#include <fstream>

namespace bfn
{

class file
{
    using pointer = const char *;
    using size_type = std::size_t;

public:

    file(const std::string &filename) :
        m_path{filename},
        m_file{filename, std::ios::in | std::ios::binary},
        m_data{std::istreambuf_iterator<char>(m_file), std::istreambuf_iterator<char>()}
    { }

    ~file()
    { }

    pointer
    data() const noexcept
    { return m_data.data(); }

    size_type
    size() const noexcept
    { return m_data.size(); }

    const std::string &
    path() const noexcept
    { return m_path; }

private:

    std::string m_path;
    std::fstream m_file;
    std::vector<char> m_data;
};

}

#endif
