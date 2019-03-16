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

#ifndef VMCALL_DOMAIN_INTEL_X64_BOXY_H
#define VMCALL_DOMAIN_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class vmcall_domain_op_handler
{
public:

    vmcall_domain_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_domain_op_handler() = default;

private:

    void domain_op__create_domain(vcpu *vcpu);
    void domain_op__destroy_domain(vcpu *vcpu);

    void domain_op__set_uart(vcpu *vcpu);
    void domain_op__set_pt_uart(vcpu *vcpu);
    void domain_op__dump_uart(vcpu *vcpu);

    void domain_op__share_page_r(vcpu *vcpu);
    void domain_op__share_page_rw(vcpu *vcpu);
    void domain_op__share_page_rwe(vcpu *vcpu);
    void domain_op__donate_page_r(vcpu *vcpu);
    void domain_op__donate_page_rw(vcpu *vcpu);
    void domain_op__donate_page_rwe(vcpu *vcpu);

    void domain_op__rax(vcpu *vcpu);
    void domain_op__set_rax(vcpu *vcpu);
    void domain_op__rbx(vcpu *vcpu);
    void domain_op__set_rbx(vcpu *vcpu);
    void domain_op__rcx(vcpu *vcpu);
    void domain_op__set_rcx(vcpu *vcpu);
    void domain_op__rdx(vcpu *vcpu);
    void domain_op__set_rdx(vcpu *vcpu);
    void domain_op__rbp(vcpu *vcpu);
    void domain_op__set_rbp(vcpu *vcpu);
    void domain_op__rsi(vcpu *vcpu);
    void domain_op__set_rsi(vcpu *vcpu);
    void domain_op__rdi(vcpu *vcpu);
    void domain_op__set_rdi(vcpu *vcpu);
    void domain_op__r08(vcpu *vcpu);
    void domain_op__set_r08(vcpu *vcpu);
    void domain_op__r09(vcpu *vcpu);
    void domain_op__set_r09(vcpu *vcpu);
    void domain_op__r10(vcpu *vcpu);
    void domain_op__set_r10(vcpu *vcpu);
    void domain_op__r11(vcpu *vcpu);
    void domain_op__set_r11(vcpu *vcpu);
    void domain_op__r12(vcpu *vcpu);
    void domain_op__set_r12(vcpu *vcpu);
    void domain_op__r13(vcpu *vcpu);
    void domain_op__set_r13(vcpu *vcpu);
    void domain_op__r14(vcpu *vcpu);
    void domain_op__set_r14(vcpu *vcpu);
    void domain_op__r15(vcpu *vcpu);
    void domain_op__set_r15(vcpu *vcpu);
    void domain_op__rip(vcpu *vcpu);
    void domain_op__set_rip(vcpu *vcpu);
    void domain_op__rsp(vcpu *vcpu);
    void domain_op__set_rsp(vcpu *vcpu);
    void domain_op__gdt_base(vcpu *vcpu);
    void domain_op__set_gdt_base(vcpu *vcpu);
    void domain_op__gdt_limit(vcpu *vcpu);
    void domain_op__set_gdt_limit(vcpu *vcpu);
    void domain_op__idt_base(vcpu *vcpu);
    void domain_op__set_idt_base(vcpu *vcpu);
    void domain_op__idt_limit(vcpu *vcpu);
    void domain_op__set_idt_limit(vcpu *vcpu);
    void domain_op__cr0(vcpu *vcpu);
    void domain_op__set_cr0(vcpu *vcpu);
    void domain_op__cr3(vcpu *vcpu);
    void domain_op__set_cr3(vcpu *vcpu);
    void domain_op__cr4(vcpu *vcpu);
    void domain_op__set_cr4(vcpu *vcpu);
    void domain_op__ia32_efer(vcpu *vcpu);
    void domain_op__set_ia32_efer(vcpu *vcpu);
    void domain_op__ia32_pat(vcpu *vcpu);
    void domain_op__set_ia32_pat(vcpu *vcpu);

    void domain_op__es_selector(vcpu *vcpu);
    void domain_op__set_es_selector(vcpu *vcpu);
    void domain_op__es_base(vcpu *vcpu);
    void domain_op__set_es_base(vcpu *vcpu);
    void domain_op__es_limit(vcpu *vcpu);
    void domain_op__set_es_limit(vcpu *vcpu);
    void domain_op__es_access_rights(vcpu *vcpu);
    void domain_op__set_es_access_rights(vcpu *vcpu);
    void domain_op__cs_selector(vcpu *vcpu);
    void domain_op__set_cs_selector(vcpu *vcpu);
    void domain_op__cs_base(vcpu *vcpu);
    void domain_op__set_cs_base(vcpu *vcpu);
    void domain_op__cs_limit(vcpu *vcpu);
    void domain_op__set_cs_limit(vcpu *vcpu);
    void domain_op__cs_access_rights(vcpu *vcpu);
    void domain_op__set_cs_access_rights(vcpu *vcpu);
    void domain_op__ss_selector(vcpu *vcpu);
    void domain_op__set_ss_selector(vcpu *vcpu);
    void domain_op__ss_base(vcpu *vcpu);
    void domain_op__set_ss_base(vcpu *vcpu);
    void domain_op__ss_limit(vcpu *vcpu);
    void domain_op__set_ss_limit(vcpu *vcpu);
    void domain_op__ss_access_rights(vcpu *vcpu);
    void domain_op__set_ss_access_rights(vcpu *vcpu);
    void domain_op__ds_selector(vcpu *vcpu);
    void domain_op__set_ds_selector(vcpu *vcpu);
    void domain_op__ds_base(vcpu *vcpu);
    void domain_op__set_ds_base(vcpu *vcpu);
    void domain_op__ds_limit(vcpu *vcpu);
    void domain_op__set_ds_limit(vcpu *vcpu);
    void domain_op__ds_access_rights(vcpu *vcpu);
    void domain_op__set_ds_access_rights(vcpu *vcpu);
    void domain_op__fs_selector(vcpu *vcpu);
    void domain_op__set_fs_selector(vcpu *vcpu);
    void domain_op__fs_base(vcpu *vcpu);
    void domain_op__set_fs_base(vcpu *vcpu);
    void domain_op__fs_limit(vcpu *vcpu);
    void domain_op__set_fs_limit(vcpu *vcpu);
    void domain_op__fs_access_rights(vcpu *vcpu);
    void domain_op__set_fs_access_rights(vcpu *vcpu);
    void domain_op__gs_selector(vcpu *vcpu);
    void domain_op__set_gs_selector(vcpu *vcpu);
    void domain_op__gs_base(vcpu *vcpu);
    void domain_op__set_gs_base(vcpu *vcpu);
    void domain_op__gs_limit(vcpu *vcpu);
    void domain_op__set_gs_limit(vcpu *vcpu);
    void domain_op__gs_access_rights(vcpu *vcpu);
    void domain_op__set_gs_access_rights(vcpu *vcpu);
    void domain_op__tr_selector(vcpu *vcpu);
    void domain_op__set_tr_selector(vcpu *vcpu);
    void domain_op__tr_base(vcpu *vcpu);
    void domain_op__set_tr_base(vcpu *vcpu);
    void domain_op__tr_limit(vcpu *vcpu);
    void domain_op__set_tr_limit(vcpu *vcpu);
    void domain_op__tr_access_rights(vcpu *vcpu);
    void domain_op__set_tr_access_rights(vcpu *vcpu);
    void domain_op__ldtr_selector(vcpu *vcpu);
    void domain_op__set_ldtr_selector(vcpu *vcpu);
    void domain_op__ldtr_base(vcpu *vcpu);
    void domain_op__set_ldtr_base(vcpu *vcpu);
    void domain_op__ldtr_limit(vcpu *vcpu);
    void domain_op__set_ldtr_limit(vcpu *vcpu);
    void domain_op__ldtr_access_rights(vcpu *vcpu);
    void domain_op__set_ldtr_access_rights(vcpu *vcpu);

    bool dispatch(vcpu *vcpu);

private:

    vcpu *m_vcpu;

public:

    /// @cond

    vmcall_domain_op_handler(vmcall_domain_op_handler &&) = default;
    vmcall_domain_op_handler &operator=(vmcall_domain_op_handler &&) = default;

    vmcall_domain_op_handler(const vmcall_domain_op_handler &) = delete;
    vmcall_domain_op_handler &operator=(const vmcall_domain_op_handler &) = delete;

    /// @endcond
};

}

#endif
