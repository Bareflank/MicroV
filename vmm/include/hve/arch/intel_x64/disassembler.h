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

#ifndef DISASSEMBLER_INTEL_X64_MICROV_H
#define DISASSEMBLER_INTEL_X64_MICROV_H

#include <capstone/capstone.h>
#include <cstdint>

namespace microv::intel_x64 {

class disassembler {
public:
    using insn_t = struct cs_insn;
    using operand_t = struct cs_x86_op;

    /// insn_mode
    ///
    /// The mode used to interpret the instruction's bytes. This is the
    /// mode the processor was in when the instruction was executed.
    ///
    enum insn_mode { insn_mode_16bit, insn_mode_32bit, insn_mode_64bit };

    /// disassembler
    ///
    /// Constructs a disassembler that is capable of disassembling
    /// x86 instructions in 16, 32, and 64-bit mode.
    ///
    disassembler();

    /// ~disassembler
    ///
    /// Releases the resources of this disassembler
    ///
    ~disassembler();

    /// disasm_single
    ///
    /// Disassemble the instruction provided in the buffer
    ///
    /// @param buf the buffer containing the instruction's bytes
    /// @param addr the address of the instruction in the address space of
    ///        the code that executed it, e.g., the guest virtual address
    ///        of the instruction from a guest vcpu.
    /// @param len the number of bytes of the instruction (i.e. the size
    ///        of buf)
    /// @param mode the mode in which the instruction should be interpreted.
    ///        This should be a value from enum insn_mode.
    /// @return != nullptr on success, nullptr on failure. On success, the
    ///         caller is responsible for freeing the pointer via
    ///         disassembler::free_insn.
    ///
    insn_t *disasm_single(const uint8_t *buf,
                          uint64_t addr,
                          uint64_t len,
                          int32_t mode);

    /// free_insn
    ///
    /// Free a previously disassembled instruction
    ///
    /// @param insn the insn to free
    ///
    void free_insn(insn_t *insn);

    /// @cond

    disassembler(disassembler &&) = delete;
    disassembler(const disassembler &) = delete;
    disassembler &operator=(disassembler &&) = delete;
    disassembler &operator=(const disassembler &) = delete;

    /// @endcond

private:
    using handle = ::csh;

    handle mode_to_handle(int32_t mode) const noexcept;

    handle m_handle_64{0};
    handle m_handle_32{0};
    handle m_handle_16{0};
};

::microv::intel_x64::disassembler *disasm();
void init_disasm();

}

#endif
