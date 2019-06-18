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

#ifndef DOMAIN_MANAGER_MICROV_H
#define DOMAIN_MANAGER_MICROV_H

#include <bfmanager.h>

#include "domain.h"
#include "domain_factory.h"

/// Domain Manager Macro
///
/// The following macro can be used to quickly call the domain manager as
/// this class will likely be called by a lot of code. This call is guaranteed
/// to not be NULL
///
/// @expects none
/// @ensures ret != nullptr
///
#define g_dm                                                                    \
    bfmanager<                                                                  \
    microv::domain,                                                               \
    microv::domain_factory,                                                       \
    microv::domain::domainid_type>::instance()

#endif
