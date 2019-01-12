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
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_BOXY_HVE
#ifdef SHARED_BOXY_HVE
#define EXPORT_BOXY_HVE EXPORT_SYM
#else
#define EXPORT_BOXY_HVE IMPORT_SYM
#endif
#else
#define EXPORT_BOXY_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class EXPORT_BOXY_HVE vmcall_domain_op_handler
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

    void domain_op__create_domain(gsl::not_null<vcpu *> vcpu);
    void domain_op__destroy_domain(gsl::not_null<vcpu *> vcpu);

    void domain_op__set_uart(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_pt_uart(gsl::not_null<vcpu *> vcpu);
    void domain_op__dump_uart(gsl::not_null<vcpu *> vcpu);

    void domain_op__share_page_r(gsl::not_null<vcpu *> vcpu);
    void domain_op__share_page_rw(gsl::not_null<vcpu *> vcpu);
    void domain_op__share_page_rwe(gsl::not_null<vcpu *> vcpu);
    void domain_op__donate_page_r(gsl::not_null<vcpu *> vcpu);
    void domain_op__donate_page_rw(gsl::not_null<vcpu *> vcpu);
    void domain_op__donate_page_rwe(gsl::not_null<vcpu *> vcpu);

    void domain_op__rax(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rax(gsl::not_null<vcpu *> vcpu);
    void domain_op__rbx(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rbx(gsl::not_null<vcpu *> vcpu);
    void domain_op__rcx(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rcx(gsl::not_null<vcpu *> vcpu);
    void domain_op__rdx(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rdx(gsl::not_null<vcpu *> vcpu);
    void domain_op__rbp(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rbp(gsl::not_null<vcpu *> vcpu);
    void domain_op__rsi(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rsi(gsl::not_null<vcpu *> vcpu);
    void domain_op__rdi(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rdi(gsl::not_null<vcpu *> vcpu);
    void domain_op__r08(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_r08(gsl::not_null<vcpu *> vcpu);
    void domain_op__r09(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_r09(gsl::not_null<vcpu *> vcpu);
    void domain_op__r10(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_r10(gsl::not_null<vcpu *> vcpu);
    void domain_op__r11(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_r11(gsl::not_null<vcpu *> vcpu);
    void domain_op__r12(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_r12(gsl::not_null<vcpu *> vcpu);
    void domain_op__r13(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_r13(gsl::not_null<vcpu *> vcpu);
    void domain_op__r14(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_r14(gsl::not_null<vcpu *> vcpu);
    void domain_op__r15(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_r15(gsl::not_null<vcpu *> vcpu);
    void domain_op__rip(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rip(gsl::not_null<vcpu *> vcpu);
    void domain_op__rsp(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_rsp(gsl::not_null<vcpu *> vcpu);
    void domain_op__gdt_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_gdt_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__gdt_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_gdt_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__idt_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_idt_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__idt_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_idt_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__cr0(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_cr0(gsl::not_null<vcpu *> vcpu);
    void domain_op__cr3(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_cr3(gsl::not_null<vcpu *> vcpu);
    void domain_op__cr4(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_cr4(gsl::not_null<vcpu *> vcpu);
    void domain_op__ia32_efer(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ia32_efer(gsl::not_null<vcpu *> vcpu);
    void domain_op__ia32_pat(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ia32_pat(gsl::not_null<vcpu *> vcpu);

    void domain_op__es_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_es_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__es_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_es_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__es_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_es_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__es_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_es_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__cs_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_cs_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__cs_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_cs_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__cs_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_cs_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__cs_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_cs_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__ss_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ss_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__ss_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ss_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__ss_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ss_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__ss_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ss_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__ds_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ds_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__ds_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ds_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__ds_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ds_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__ds_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ds_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__fs_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_fs_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__fs_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_fs_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__fs_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_fs_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__fs_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_fs_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__gs_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_gs_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__gs_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_gs_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__gs_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_gs_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__gs_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_gs_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__tr_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_tr_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__tr_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_tr_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__tr_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_tr_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__tr_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_tr_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__ldtr_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ldtr_selector(gsl::not_null<vcpu *> vcpu);
    void domain_op__ldtr_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ldtr_base(gsl::not_null<vcpu *> vcpu);
    void domain_op__ldtr_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ldtr_limit(gsl::not_null<vcpu *> vcpu);
    void domain_op__ldtr_access_rights(gsl::not_null<vcpu *> vcpu);
    void domain_op__set_ldtr_access_rights(gsl::not_null<vcpu *> vcpu);

    bool dispatch(gsl::not_null<vcpu *> vcpu);

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
