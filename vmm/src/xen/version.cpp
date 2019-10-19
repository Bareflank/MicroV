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
#include <stdlib.h>
#include <compiler.h>
#include <xen/domain.h>
#include <xen/vcpu.h>
#include <xen/version.h>

#define XEN_MAJOR 4UL
#define XEN_MINOR 13UL

namespace microv {

xen_version::xen_version(xen_vcpu *xen) :
    m_xen_vcpu{xen},
    m_xen_dom{xen->m_xen_dom},
    m_uv_vcpu{xen->m_uv_vcpu}
{ }

bool xen_version::changeset()
{
    auto chg = m_uv_vcpu->map_arg<xen_changeset_info_t>(m_uv_vcpu->rsi());
    std::strncpy((char *)chg.get(), MICROV_CHANGESET, XEN_CHANGESET_INFO_LEN);
    m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_version::get_features()
{
    auto info = m_uv_vcpu->map_arg<xen_feature_info_t>(m_uv_vcpu->rsi());
    if (info->submap_idx >= XENFEAT_NR_SUBMAPS) {
        m_uv_vcpu->set_rax(-EINVAL);
        return true;
    }

    info->submap = 0;
    info->submap |= (1 << XENFEAT_writable_page_tables);
    info->submap |= (1 << XENFEAT_writable_descriptor_tables);
    info->submap |= (1 << XENFEAT_auto_translated_physmap);
    info->submap |= (1 << XENFEAT_supervisor_mode_kernel);
    info->submap |= (1 << XENFEAT_pae_pgdir_above_4gb);
    //info->submap |= (1 << XENFEAT_mmu_pt_update_preserve_ad);
    //info->submap |= (1 << XENFEAT_highmem_assist);
    info->submap |= (1 << XENFEAT_gnttab_map_avail_bits);
    info->submap |= (1 << XENFEAT_hvm_callback_vector);
    info->submap |= (1 << XENFEAT_hvm_safe_pvclock);
    //info->submap |= (1 << XENFEAT_hvm_pirqs);
    info->submap |= (1 << XENFEAT_dom0);
    //info->submap |= (1 << XENFEAT_memory_op_vnode_supported);
    //info->submap |= (1 << XENFEAT_ARM_SMCCC_supported);
    info->submap |= (1 << XENFEAT_linux_rsdp_unrestricted);

    m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_version::version()
{
    m_uv_vcpu->set_rax((XEN_MAJOR << 16) | XEN_MINOR);
    return true;
}

bool xen_version::compile_info()
{
    static_assert(sizeof(xen_compile_info_t::compiler) == 64);
    static_assert(sizeof(xen_compile_info_t::compile_by) == 16);
    static_assert(sizeof(xen_compile_info_t::compile_domain) == 32);
    static_assert(sizeof(xen_compile_info_t::compile_date) == 32);

    auto info = m_uv_vcpu->map_arg<xen_compile_info_t>(m_uv_vcpu->rsi());
    std::strncpy((char *)info->compiler, MICROV_COMPILER, 64);
    std::strncpy((char *)info->compile_by, MICROV_COMPILE_BY, 16);
    std::strncpy((char *)info->compile_domain, MICROV_COMPILE_DOMAIN, 32);
    std::strncpy((char *)info->compile_date, MICROV_COMPILE_DATE, 32);

    info->compiler[63] = 0;
    info->compile_by[15] = 0;
    info->compile_domain[31] = 0;
    info->compile_date[31] = 0;

    m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_version::extraversion()
{
    auto extra = m_uv_vcpu->map_arg<xen_extraversion_t>(m_uv_vcpu->rsi());
    std::strncpy((char *)extra.get(), "-microv", XEN_EXTRAVERSION_LEN);
    m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_version::pagesize()
{
    m_uv_vcpu->set_rax(UV_PAGE_SIZE);
    return true;
}

bool xen_version::guest_handle()
{
    auto hdl = m_uv_vcpu->map_arg<xen_domain_handle_t>(m_uv_vcpu->rsi());
    expects(sizeof(*hdl.get()) == sizeof(m_xen_dom->m_uuid));
    memcpy(hdl.get(), &m_xen_dom->m_uuid, sizeof(m_xen_dom->m_uuid));
    m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_version::capabilities()
{
    const char *str = "hvm-3.0-x86_64 hvm-3.0-x86_32";
    auto caps = m_uv_vcpu->map_arg<xen_capabilities_info_t>(m_uv_vcpu->rsi());
    std::strncpy((char *)caps.get(), str, sizeof(*caps.get()));
    m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_version::platform_parameters()
{
    auto params = m_uv_vcpu->map_arg<xen_platform_parameters_t>(m_uv_vcpu->rsi());
    params->virt_start = HYPERVISOR_VIRT_START;
    m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_version::commandline()
{
    auto cmdline = m_uv_vcpu->map_arg<xen_commandline_t>(m_uv_vcpu->rsi());
    memset((char *)cmdline.get(), 0, sizeof(*cmdline.get()));
    m_uv_vcpu->set_rax(0);
    return true;
}

bool xen_version::build_id()
{
    m_uv_vcpu->set_rax(0);
    return true;
}

}
