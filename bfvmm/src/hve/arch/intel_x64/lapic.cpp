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

#include <intrinsics.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/lapic.h>

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

namespace lapic_n = ::eapis::intel_x64::lapic;

lapic::lapic(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_lapic_page{make_page<uint32_t>()},
    m_lapic_view{m_lapic_page.get(), 0x1000 / 4}
{ }

void
lapic::init()
{
    auto hpa = g_mm->virtptr_to_physint(m_lapic_page.get());
    m_vcpu->map_4k_ro(this->base(), hpa);

    this->write(lapic_n::id::indx, lapic_n::id::reset_val);
    this->write(lapic_n::version::indx, lapic_n::version::reset_val);
    this->write(lapic_n::dfr::indx, lapic_n::dfr::reset_val);

    this->write(lapic_n::lvt::cmci::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::timer::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::lint0::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::lint1::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::error::indx, lapic_n::lvt::reset_val);

    this->write(lapic_n::svr::indx, lapic_n::svr::reset_val);
}

}
