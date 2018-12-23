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

#ifndef LAPIC_INTEL_X64_HYPERKERNEL_H
#define LAPIC_INTEL_X64_HYPERKERNEL_H

#include <bfgpalayout.h>

#include <eapis/hve/arch/intel_x64/lapic.h>
#include <bfvmm/memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HYPERKERNEL_HVE
#ifdef SHARED_HYPERKERNEL_HVE
#define EXPORT_HYPERKERNEL_HVE EXPORT_SYM
#else
#define EXPORT_HYPERKERNEL_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HYPERKERNEL_HVE
#endif

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class vcpu;

class EXPORT_HYPERKERNEL_HVE lapic
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu associated with this lapic
    ///
    /// @cond
    ///
    explicit lapic(gsl::not_null<vcpu *> vcpu);

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~lapic() = default;

    /// Initialize
    ///
    /// We have to initialize later on during the construction process to give
    /// EPT time to set up, so this function must be called manually after
    /// EPTP has been set. This will initialize the local APIC and get it
    /// ready to access guest reads and writes
    ///
    /// @expects
    /// @ensures
    ///
    void init();

    /// APIC ID
    ///
    /// The APIC ID and the vCPU ID do not need to agree, and on some systems
    /// they don't. This provides that level of flexibility by returning the
    /// APIC's ID
    ///
    /// TODO:
    ///
    /// Note that each domain will have to generate APIC IDs for us so that
    /// the APIC IDs start from 0 on each VM. For now this returns 0 as we
    /// don't support more than on vCPU. Once we attempt to add more than one
    /// vCPU, we will need to implement this. Note also that ACPI and the
    /// MP tables will have to be updated
    ///
    /// @return APIC ID
    ///
    uint32_t id() const
    { return this->read(eapis::intel_x64::lapic::id::indx); }

    /// APIC Base
    ///
    /// This function returns the APIC base for this APIC as a GPA. The HPA is
    /// maintained internally to this class and is not accessible.
    ///
    /// TODO:
    ///
    /// The APIC base is relocatable. For now the guest is not attempting to
    /// relocate the APIC base. If they do, we will have to unmap the GPA and
    /// then remap the GPA to the new APIC base, which means we will also have
    /// to store the APIC base instead of just returning a hardcoded addr.
    ///
    /// @return APIC base GPA
    ///
    uint32_t base() const
    { return LAPIC_GPA; }

    /// Read
    ///
    /// Read the value from a register
    ///
    /// @param idx the index of the register to read
    //
    /// @note the index is a dword offset, not a byte offset
    ///
    uint32_t read(uint32_t idx) const
    { return m_lapic_view[idx]; }

    /// Write
    ///
    /// Write the value to a register
    ///
    /// @param idx the index of the register to write
    /// @param val the value to write
    ///
    /// @note the index is a dword offset, not a byte offset
    ///
    void write(uint32_t idx, uint32_t val)
    { m_lapic_view[idx] = val; }

private:

    vcpu *m_vcpu;

    page_ptr<uint32_t> m_lapic_page;
    gsl::span<uint32_t> m_lapic_view;
};

class EXPORT_HYPERKERNEL_HVE insn_decoder
{
public:

    enum reg { eax, ecx, edx, ebx, esp, ebp, esi, edi };

    ///
    /// Prefix used to override 32-bit operands while in long mode
    ///
    static constexpr auto size_override = 0x67;
    static constexpr std::array<uint8_t, 3> mov_opcode = {
        0x89, // MOV r/m32, r32   (MR)
    };

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu associated with this insn_decoder
    /// @param buf the bytes associated with this insn_decoder
    /// @param len the number of bytes associated with this insn_decoder
    ///
    explicit insn_decoder(
        const gsl::not_null<uint8_t *> buf,
        size_t len)
        :
        m_buf{buf}
    {
        expects(len >= 2 && len <= 15);
        m_len = len;
    }

    auto mod(uint64_t modrm)
    { return (modrm & 0xC0U) >> 6; }

    auto reg(uint64_t modrm)
    { return (modrm & 0x31U) >> 3; }

    auto rm(uint64_t modrm)
    { return (modrm & 0x07U) >> 0; }

    // Need effective address computation for r/m32 dest op
    // if we're paranoid about valid xAPIC access instructions
    int64_t mov_mr_src_op()
    {
        expects(m_pos >= 1);
        expects(m_pos <= 2);
        expects(m_pos < m_len);

        uint8_t modrm = m_buf[m_pos];
        return reg(modrm);
    }

    int64_t src_op()
    {
        m_pos = (m_buf[0] == size_override) ? 1 : 0;

        switch (m_buf[m_pos++]) {
            case mov_opcode[0]:
                return mov_mr_src_op();
            default:
                printf("unhandled insn: ");
                for (auto i = 0; i < m_len; i++) {
                    printf("%02x", m_buf[i]);
                }
                printf("\n");
                throw std::runtime_error("unhandled insn");
        }
    }

    /// @endcond

private:

    uint8_t *m_buf{};
    size_t m_len{};
    size_t m_pos{};
};
}

#endif
