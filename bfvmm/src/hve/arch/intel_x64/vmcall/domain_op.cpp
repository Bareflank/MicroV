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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vmcall/domain_op.h>

namespace boxy::intel_x64
{

vmcall_domain_op_handler::vmcall_domain_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_domain_op_handler, dispatch)
    );
}

void
vmcall_domain_op_handler::domain_op__create_domain(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        vcpu->set_rax(domain::generate_domainid());
        g_dm->create(vcpu->rax(), nullptr);
    }
    catchall({
        vcpu->set_rax(INVALID_DOMAINID);
    })
}

void
vmcall_domain_op_handler::domain_op__destroy_domain(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__destroy_domain: self not supported");
        }

        g_dm->destroy(vcpu->rbx(), nullptr);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__set_uart(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__set_uart: self not supported");
        }

        get_domain(vcpu->rbx())->set_uart(
            gsl::narrow_cast<uart::port_type>(vcpu->rcx())
        );

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__set_pt_uart(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__set_pt_uart: self not supported");
        }

        get_domain(vcpu->rbx())->set_pt_uart(
            gsl::narrow_cast<uart::port_type>(vcpu->rcx())
        );

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__dump_uart(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto buffer =
            vcpu->map_gva_4k<char>(vcpu->rcx(), UART_MAX_BUFFER);

        auto bytes_transferred =
            get_domain(vcpu->rbx())->dump_uart(
                gsl::span(buffer.get(), UART_MAX_BUFFER)
            );

        vcpu->set_rax(bytes_transferred);
    }
    catchall({
        vcpu->set_rax(0);
    })
}

void
vmcall_domain_op_handler::domain_op__share_page_r(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__share_page: self not supported");
        }

        auto [hpa, unused] =
            vcpu->gpa_to_hpa(vcpu->rcx());

        get_domain(vcpu->rbx())->map_4k_r(vcpu->rdx(), hpa);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__share_page_rw(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__share_page: self not supported");
        }

        auto [hpa, unused] =
            vcpu->gpa_to_hpa(vcpu->rcx());

        get_domain(vcpu->rbx())->map_4k_rw(vcpu->rdx(), hpa);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__share_page_rwe(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__share_page: self not supported");
        }

        auto [hpa, unused] =
            vcpu->gpa_to_hpa(vcpu->rcx());

        get_domain(vcpu->rbx())->map_4k_rwe(vcpu->rdx(), hpa);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__donate_page_r(
    gsl::not_null<vcpu *> vcpu)
{
    // TODO:
    //
    // We need to remove the gpa from the current domain before the gpa is
    // donated to the other guest. For now, this function is identical to
    // sharing as both domains have access to the backing page.
    //

    try {
        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__donate_page: self not supported");
        }

        auto [hpa, unused] =
            vcpu->gpa_to_hpa(vcpu->rcx());

        get_domain(vcpu->rbx())->map_4k_r(vcpu->rdx(), hpa);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__donate_page_rw(
    gsl::not_null<vcpu *> vcpu)
{
    // TODO:
    //
    // We need to remove the gpa from the current domain before the gpa is
    // donated to the other guest. For now, this function is identical to
    // sharing as both domains have access to the backing page.
    //

    try {
        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__donate_page: self not supported");
        }

        auto [hpa, unused] =
            vcpu->gpa_to_hpa(vcpu->rcx());

        get_domain(vcpu->rbx())->map_4k_rw(vcpu->rdx(), hpa);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__donate_page_rwe(
    gsl::not_null<vcpu *> vcpu)
{
    // TODO:
    //
    // We need to remove the gpa from the current domain before the gpa is
    // donated to the other guest. For now, this function is identical to
    // sharing as both domains have access to the backing page.
    //

    try {

        if (vcpu->rbx() == self || vcpu->rbx() == vcpu->domid()) {
            throw std::runtime_error(
                "domain_op__donate_page: self not supported");
        }

        auto [hpa, unused] =
            vcpu->gpa_to_hpa(vcpu->rcx());

        get_domain(vcpu->rbx())->map_4k_rwe(vcpu->rdx(), hpa);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

#define domain_op__reg(reg)                                                     \
    void                                                                        \
    vmcall_domain_op_handler::domain_op__ ## reg(                               \
        gsl::not_null<vcpu *> vcpu)                                             \
    {                                                                           \
        try {                                                                   \
            vcpu->set_rax(get_domain(vcpu->rbx())->reg());                      \
        }                                                                       \
        catchall({                                                              \
            vcpu->set_rax(FAILURE);                                             \
        })                                                                      \
    }

#define domain_op__set_reg(reg)                                                 \
    void                                                                        \
    vmcall_domain_op_handler::domain_op__set_ ## reg(                           \
        gsl::not_null<vcpu *> vcpu)                                             \
    {                                                                           \
        try {                                                                   \
            get_domain(vcpu->rbx())->set_ ## reg(vcpu->rcx());                  \
            vcpu->set_rax(SUCCESS);                                             \
        }                                                                       \
        catchall({                                                              \
            vcpu->set_rax(FAILURE);                                             \
        })                                                                      \
    }

domain_op__reg(rax);
domain_op__set_reg(rax);
domain_op__reg(rbx);
domain_op__set_reg(rbx);
domain_op__reg(rcx);
domain_op__set_reg(rcx);
domain_op__reg(rdx);
domain_op__set_reg(rdx);
domain_op__reg(rbp);
domain_op__set_reg(rbp);
domain_op__reg(rsi);
domain_op__set_reg(rsi);
domain_op__reg(rdi);
domain_op__set_reg(rdi);
domain_op__reg(r08);
domain_op__set_reg(r08);
domain_op__reg(r09);
domain_op__set_reg(r09);
domain_op__reg(r10);
domain_op__set_reg(r10);
domain_op__reg(r11);
domain_op__set_reg(r11);
domain_op__reg(r12);
domain_op__set_reg(r12);
domain_op__reg(r13);
domain_op__set_reg(r13);
domain_op__reg(r14);
domain_op__set_reg(r14);
domain_op__reg(r15);
domain_op__set_reg(r15);
domain_op__reg(rip);
domain_op__set_reg(rip);
domain_op__reg(rsp);
domain_op__set_reg(rsp);
domain_op__reg(gdt_base);
domain_op__set_reg(gdt_base);
domain_op__reg(gdt_limit);
domain_op__set_reg(gdt_limit);
domain_op__reg(idt_base);
domain_op__set_reg(idt_base);
domain_op__reg(idt_limit);
domain_op__set_reg(idt_limit);
domain_op__reg(cr0);
domain_op__set_reg(cr0);
domain_op__reg(cr3);
domain_op__set_reg(cr3);
domain_op__reg(cr4);
domain_op__set_reg(cr4);
domain_op__reg(ia32_efer);
domain_op__set_reg(ia32_efer);
domain_op__reg(ia32_pat);
domain_op__set_reg(ia32_pat);

domain_op__reg(es_selector);
domain_op__set_reg(es_selector);
domain_op__reg(es_base);
domain_op__set_reg(es_base);
domain_op__reg(es_limit);
domain_op__set_reg(es_limit);
domain_op__reg(es_access_rights);
domain_op__set_reg(es_access_rights);
domain_op__reg(cs_selector);
domain_op__set_reg(cs_selector);
domain_op__reg(cs_base);
domain_op__set_reg(cs_base);
domain_op__reg(cs_limit);
domain_op__set_reg(cs_limit);
domain_op__reg(cs_access_rights);
domain_op__set_reg(cs_access_rights);
domain_op__reg(ss_selector);
domain_op__set_reg(ss_selector);
domain_op__reg(ss_base);
domain_op__set_reg(ss_base);
domain_op__reg(ss_limit);
domain_op__set_reg(ss_limit);
domain_op__reg(ss_access_rights);
domain_op__set_reg(ss_access_rights);
domain_op__reg(ds_selector);
domain_op__set_reg(ds_selector);
domain_op__reg(ds_base);
domain_op__set_reg(ds_base);
domain_op__reg(ds_limit);
domain_op__set_reg(ds_limit);
domain_op__reg(ds_access_rights);
domain_op__set_reg(ds_access_rights);
domain_op__reg(fs_selector);
domain_op__set_reg(fs_selector);
domain_op__reg(fs_base);
domain_op__set_reg(fs_base);
domain_op__reg(fs_limit);
domain_op__set_reg(fs_limit);
domain_op__reg(fs_access_rights);
domain_op__set_reg(fs_access_rights);
domain_op__reg(gs_selector);
domain_op__set_reg(gs_selector);
domain_op__reg(gs_base);
domain_op__set_reg(gs_base);
domain_op__reg(gs_limit);
domain_op__set_reg(gs_limit);
domain_op__reg(gs_access_rights);
domain_op__set_reg(gs_access_rights);
domain_op__reg(tr_selector);
domain_op__set_reg(tr_selector);
domain_op__reg(tr_base);
domain_op__set_reg(tr_base);
domain_op__reg(tr_limit);
domain_op__set_reg(tr_limit);
domain_op__reg(tr_access_rights);
domain_op__set_reg(tr_access_rights);
domain_op__reg(ldtr_selector);
domain_op__set_reg(ldtr_selector);
domain_op__reg(ldtr_base);
domain_op__set_reg(ldtr_base);
domain_op__reg(ldtr_limit);
domain_op__set_reg(ldtr_limit);
domain_op__reg(ldtr_access_rights);
domain_op__set_reg(ldtr_access_rights);

#define dispatch_case(name)                                                     \
    case __enum_domain_op__ ## name:                                            \
        this->domain_op__ ## name(vcpu);                                        \
        return true;

bool
vmcall_domain_op_handler::dispatch(
    gsl::not_null<vcpu *> vcpu)
{
    if (bfopcode(vcpu->rax()) != __enum_domain_op) {
        return false;
    }

    switch (vcpu->rax()) {
        dispatch_case(create_domain)
        dispatch_case(destroy_domain)

        dispatch_case(set_uart)
        dispatch_case(set_pt_uart)
        dispatch_case(dump_uart)

        dispatch_case(share_page_r)
        dispatch_case(share_page_rw)
        dispatch_case(share_page_rwe)
        dispatch_case(donate_page_r)
        dispatch_case(donate_page_rw)
        dispatch_case(donate_page_rwe)

        dispatch_case(rax);
        dispatch_case(set_rax);
        dispatch_case(rbx);
        dispatch_case(set_rbx);
        dispatch_case(rcx);
        dispatch_case(set_rcx);
        dispatch_case(rdx);
        dispatch_case(set_rdx);
        dispatch_case(rbp);
        dispatch_case(set_rbp);
        dispatch_case(rsi);
        dispatch_case(set_rsi);
        dispatch_case(rdi);
        dispatch_case(set_rdi);
        dispatch_case(r08);
        dispatch_case(set_r08);
        dispatch_case(r09);
        dispatch_case(set_r09);
        dispatch_case(r10);
        dispatch_case(set_r10);
        dispatch_case(r11);
        dispatch_case(set_r11);
        dispatch_case(r12);
        dispatch_case(set_r12);
        dispatch_case(r13);
        dispatch_case(set_r13);
        dispatch_case(r14);
        dispatch_case(set_r14);
        dispatch_case(r15);
        dispatch_case(set_r15);
        dispatch_case(rip);
        dispatch_case(set_rip);
        dispatch_case(rsp);
        dispatch_case(set_rsp);
        dispatch_case(gdt_base);
        dispatch_case(set_gdt_base);
        dispatch_case(gdt_limit);
        dispatch_case(set_gdt_limit);
        dispatch_case(idt_base);
        dispatch_case(set_idt_base);
        dispatch_case(idt_limit);
        dispatch_case(set_idt_limit);
        dispatch_case(cr0);
        dispatch_case(set_cr0);
        dispatch_case(cr3);
        dispatch_case(set_cr3);
        dispatch_case(cr4);
        dispatch_case(set_cr4);
        dispatch_case(ia32_efer);
        dispatch_case(set_ia32_efer);
        dispatch_case(ia32_pat);
        dispatch_case(set_ia32_pat);

        dispatch_case(es_selector);
        dispatch_case(set_es_selector);
        dispatch_case(es_base);
        dispatch_case(set_es_base);
        dispatch_case(es_limit);
        dispatch_case(set_es_limit);
        dispatch_case(es_access_rights);
        dispatch_case(set_es_access_rights);
        dispatch_case(cs_selector);
        dispatch_case(set_cs_selector);
        dispatch_case(cs_base);
        dispatch_case(set_cs_base);
        dispatch_case(cs_limit);
        dispatch_case(set_cs_limit);
        dispatch_case(cs_access_rights);
        dispatch_case(set_cs_access_rights);
        dispatch_case(ss_selector);
        dispatch_case(set_ss_selector);
        dispatch_case(ss_base);
        dispatch_case(set_ss_base);
        dispatch_case(ss_limit);
        dispatch_case(set_ss_limit);
        dispatch_case(ss_access_rights);
        dispatch_case(set_ss_access_rights);
        dispatch_case(ds_selector);
        dispatch_case(set_ds_selector);
        dispatch_case(ds_base);
        dispatch_case(set_ds_base);
        dispatch_case(ds_limit);
        dispatch_case(set_ds_limit);
        dispatch_case(ds_access_rights);
        dispatch_case(set_ds_access_rights);
        dispatch_case(fs_selector);
        dispatch_case(set_fs_selector);
        dispatch_case(fs_base);
        dispatch_case(set_fs_base);
        dispatch_case(fs_limit);
        dispatch_case(set_fs_limit);
        dispatch_case(fs_access_rights);
        dispatch_case(set_fs_access_rights);
        dispatch_case(gs_selector);
        dispatch_case(set_gs_selector);
        dispatch_case(gs_base);
        dispatch_case(set_gs_base);
        dispatch_case(gs_limit);
        dispatch_case(set_gs_limit);
        dispatch_case(gs_access_rights);
        dispatch_case(set_gs_access_rights);
        dispatch_case(tr_selector);
        dispatch_case(set_tr_selector);
        dispatch_case(tr_base);
        dispatch_case(set_tr_base);
        dispatch_case(tr_limit);
        dispatch_case(set_tr_limit);
        dispatch_case(tr_access_rights);
        dispatch_case(set_tr_access_rights);
        dispatch_case(ldtr_selector);
        dispatch_case(set_ldtr_selector);
        dispatch_case(ldtr_base);
        dispatch_case(set_ldtr_base);
        dispatch_case(ldtr_limit);
        dispatch_case(set_ldtr_limit);
        dispatch_case(ldtr_access_rights);
        dispatch_case(set_ldtr_access_rights);

        default:
            break;
    };

    throw std::runtime_error("unknown domain opcode");
}

}
