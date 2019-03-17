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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmexit/vmcall.h>

namespace boxy::intel_x64
{

vmcall_handler::vmcall_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::vmcall,
        ::handler_delegate_t::create<vmcall_handler, &vmcall_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
vmcall_handler::add_handler(
    const handler_delegate_t &d)
{ m_handlers.push_back(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

static bool
vmcall_error(gsl::not_null<vcpu *> vcpu, const std::string &str)
{
    bfdebug_transaction(0, [&](std::string * msg) {

        bferror_lnbr(0, msg);
        bferror_info(0, ("vmcall error: " + str).c_str(), msg);
        bferror_brk1(0, msg);

        if ((vcpu->rax() & 0xFFFF000000000000) == 0xBF5C000000000000) {
            bferror_subnhex(0, "rax", vcpu->rax(), msg);
            bferror_subnhex(0, "rbx", vcpu->rbx(), msg);
            bferror_subnhex(0, "rcx", vcpu->rcx(), msg);
            bferror_subnhex(0, "rdx", vcpu->rdx(), msg);
        }
        else {
            bferror_subnhex(0, "rax", vcpu->rax(), msg);
            bferror_subnhex(0, "rdi", vcpu->rdi(), msg);
        }
    });

    if (vcpu->is_domU()) {
        vcpu->halt(str);
    }

    vcpu->set_rax(FAILURE);
    return true;
}

bool
vmcall_handler::handle(vcpu_t *vcpu)
{
    auto ___ = gsl::finally([&] {
        vcpu->load();
    });

    vcpu->advance();

    try {
        for (const auto &d : m_handlers) {
            if (d(m_vcpu)) {
                return true;
            }
        }
    }
    catchall({
        return vmcall_error(m_vcpu, "vmcall threw exception");
    })

    return vmcall_error(m_vcpu, "unknown vmcall");
}

}
