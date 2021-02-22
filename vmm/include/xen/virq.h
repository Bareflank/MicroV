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

#ifndef MICROV_XEN_VIRQ_H
#define MICROV_XEN_VIRQ_H

#include <array>
#include <public/xen.h>

namespace microv {

struct virq {
    const char *name;
    bool used;
    bool dom0;
    bool global;
};

inline std::array<struct virq, NR_VIRQS> virq_info = {
    {{"timer", true, false, false},     {"debug", true, false, false},
     {"console", true, true, true},     {"dom_exc", true, true, true},
     {"tbuf", true, true, true},        {"unused5", false, false, false},
     {"debugger", true, true, true},    {"xenoprof", true, false, false},
     {"con_ring", true, true, true},    {"pcpu_state", true, true, true},
     {"mem_event", true, true, true},   {"argo", true, false, true},
     {"enomem", true, true, true},      {"xenpmu", true, false, false},
     {"unused14", false, false, false}, {"unused15", false, false, false},
     {"arch0", true, false, true},      {"arch1", true, false, true},
     {"arch2", true, false, true},      {"arch3", true, false, true},
     {"arch4", true, false, true},      {"arch5", true, false, true},
     {"arch6", true, false, true},      {"arch7", true, false, true}}};

}
#endif
