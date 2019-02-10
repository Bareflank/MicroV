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

#include "cxxopts.hpp"

using args_type = cxxopts::ParseResult;

inline bool verbose = false;
inline cxxopts::Options options("bfexec", "execute a virtual machine");

inline args_type
parse_args(int argc, char *argv[])
{
    using namespace cxxopts;

    options.add_options()
    ("h,help", "Print this help menu")
    ("v,verbose", "Enable verbose output")
    ("affinity", "The host CPU to execute the VM on", value<uint64_t>(), "[core #]")
    ("kernel", "The VM's kernel", value<std::string>(), "[path]")
    ("initrd", "The VM's initrd", value<std::string>(), "[path]")
    ("ram", "The VM's total RAM", value<uint64_t>(), "[MB]")
    ("cmdline", "Additional Linux command line arguments", value<std::string>(), "[text]")
    ("uart", "Give the VM an emulated UART", value<uint64_t>(), "[port #]")
    ("pt_uart", "Pass-through a host UART to the VM", value<uint64_t>(), "[port #]");

    auto args = options.parse(argc, argv);

    if (args.count("help")) {
        std::cout << options.help() << '\n';
        exit(EXIT_SUCCESS);
    }

    if (args.count("verbose")) {
        verbose = true;
    }

    if (!args.count("kernel")) {
        throw std::runtime_error("must specify 'kernel'");
    }

    if (args.count("uart") && args.count("pt_uart")) {
        throw std::runtime_error("must specify 'uart' or 'pt_uart'");
    }

    return args;
}


