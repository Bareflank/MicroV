/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef MV_RDL_T_H
#define MV_RDL_T_H

#include <mv_constants.h>
#include <mv_rdl_entry_t.h>
#include <stdint.h>

/**
 * @struct mv_rdl_t
 *
 * <!-- description -->
 *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
 *   @var mv_rdl_t::reg0 
 *   Member reg0 holds Registers which is ABI dependent. REVI if unused
 *   @var mv_rdl_t::reg1
 *   Member reg1 holds Registers which is ABI dependent. REVI if unused
 *   @var mv_rdl_t::reg2
 *   Member reg2 holds Registers which is ABI dependent. REVI if unused
 *   @var mv_rdl_t::reg3
 *   Member reg3 holds Registers which is ABI dependent. REVI if unused
 *   @var mv_rdl_t::reg4
 *   Member reg4 holds Registers which is ABI dependent. REVI if unused
 *   @var mv_rdl_t::reg5
 *   Member reg5 holds Registers which is ABI dependent. REVI if unused
 *   @var mv_rdl_t::reg6
 *   Member reg6 holds Registers which is ABI dependent. REVI if unused
 *   @var mv_rdl_t::reg7
 *   Member reg7 holds Registers which is ABI dependent. REVI if unused
 *   @var mv_rdl_t::reserved1
 *   Member reserved1 holds reserved for REVI
 *   @var mv_rdl_t::reserved2
 *   Member reserved2 holds reserved for REVI
 *   @var mv_rdl_t::reserved3
 *   Member reserved3 holds reserved for REVI
 *   @var mv_rdl_t::num_entries
 *   Member num_entries holds the number of entries in the RDL
 *   @var mv_rdl_t::entries
 *   Member entries holds Each entry in the RDL
*/

struct mv_rdl_t
{
    uint64_t reg0;
    uint64_t reg1;
    uint64_t reg2;
    uint64_t reg3;
    uint64_t reg4;
    uint64_t reg5;
    uint64_t reg6;
    uint64_t reg7;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t reserved3;
    uint64_t num_entries;
    struct mv_rdl_entry_t entries[MV_RDL_MAX_ENTRIES];
};

#endif
