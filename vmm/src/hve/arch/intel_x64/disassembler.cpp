//
// Copyright (C) 2020 Assured Information Security, Inc.
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

#include <hve/arch/intel_x64/disassembler.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <bfgsl.h>
#include <printv.h>
#include <cstdint>

namespace microv::intel_x64
{

#define pr_err() cs_strerror(cs_errno(handle))

disassembler::disassembler()
{
    expects(cs_open(CS_ARCH_X86, CS_MODE_64, &m_handle_64) == CS_ERR_OK);
    expects(cs_open(CS_ARCH_X86, CS_MODE_32, &m_handle_32) == CS_ERR_OK);
    expects(cs_open(CS_ARCH_X86, CS_MODE_16, &m_handle_16) == CS_ERR_OK);

    expects(cs_option(m_handle_64, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
    expects(cs_option(m_handle_32, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
    expects(cs_option(m_handle_16, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
}

disassembler::~disassembler()
{
    cs_close(&m_handle_64);
    cs_close(&m_handle_32);
    cs_close(&m_handle_16);
}

disassembler::handle
disassembler::mode_to_handle(int32_t mode) const noexcept
{
    switch (mode) {
    case insn_mode_16bit:
        return m_handle_16;
    case insn_mode_32bit:
        return m_handle_32;
    case insn_mode_64bit:
        return m_handle_64;
    default:
        return 0;
    }
}

disassembler::insn_t *
disassembler::disasm_single(const uint8_t *buf,
                            uint64_t gva,
                            uint64_t len,
                            int32_t mode)
{
    auto handle = this->mode_to_handle(mode);
    if (!handle) {
        return nullptr;
    }

    auto insn = cs_malloc(handle);
    if (!insn) {
        printv("%s: cs_malloc failed: %s\n", __func__, pr_err());
        return nullptr;
    }

    auto code_gva = gva;
    auto code_len = len;
    auto code_buf = buf;

    if (!cs_disasm_iter(handle, &code_buf, &code_len, &code_gva, insn)) {
        printv("%s: cs_disasm_iter failed: %s\n", __func__, pr_err());
        cs_free(insn, 1);
        return nullptr;
    }

    return insn;
}

void
disassembler::free_insn(insn_t *insn)
{
    if (!insn) {
        return;
    }

    cs_free(insn, 1);
}

::microv::intel_x64::disassembler *disasm()
{
    static microv::intel_x64::disassembler disasm{};
    return &disasm;
}

void init_disasm()
{
    expects(disasm() != nullptr);
}

}

