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

#include <mutex>

#include <hve/arch/intel_x64/vcpu.h>
#include <printv.h>
#include <public/domctl.h>
#include <public/sysctl.h>
#include <xen/cpupool.h>
#include <xen/vcpu.h>

namespace microv {

std::mutex cpupool_mutex;
std::unordered_map<xen_cpupoolid_t,
                   std::unique_ptr<class xen_cpupool>> cpupool_map;

static void __add_domain(xen_cpupoolid_t id, xen_domid_t domid)
{

}

void xen_cpupool_add_domain(xen_cpupoolid_t id, xen_domid_t domid)
{
    std::lock_guard lock(cpupool_mutex);

    auto itr = cpupool_map.find(id);
    if (itr == cpupool_map.end()) {
        cpupool_map.try_emplace(id, std::make_unique<class xen_cpupool>(id));
        itr = cpupool_map.find(id);
    }

    auto pool = itr->second.get();
    pool->add_domain(domid);
}

void xen_cpupool_rm_domain(xen_cpupoolid_t id, xen_domid_t domid)
{
    std::lock_guard lock(cpupool_mutex);

    auto itr = cpupool_map.find(id);
    if (itr == cpupool_map.end()) {
        return;
    }

    auto pool = itr->second.get();
    pool->rm_domain(domid);

    if (!pool->nr_domains()) {
        cpupool_map.erase(id);
    }
}

int xen_cpupool_mv_domain(xen_cpupoolid_t old_id,
                          xen_cpupoolid_t new_id,
                          xen_domid_t domid)
{
    std::lock_guard lock(cpupool_mutex);

    auto old_itr = cpupool_map.find(old_id);
    auto new_itr = cpupool_map.find(new_id);

    if (old_itr == cpupool_map.end()) {
        bferror_nhex(0, "mv_domain: cpupool not found:", old_id);
        return -EINVAL;
    }

    if (new_itr == cpupool_map.end()) {
        cpupool_map.try_emplace(new_id,
                                std::make_unique<class xen_cpupool>(new_id));
        new_itr = cpupool_map.find(new_id);
    }

    auto old_pool = old_itr->second.get();
    auto new_pool = new_itr->second.get();

    old_pool->rm_domain(domid);
    new_pool->add_domain(domid);

    if (!old_pool->nr_domains()) {
        cpupool_map.erase(old_id);
    }

    return 0;
}

static bool cpupool_move_domain(xen_vcpu *vcpu, struct xen_sysctl *ctl)
{
    auto op = &ctl->u.cpupool_op;
    auto uvv = vcpu->m_uv_vcpu;
    auto dom = get_xen_domain(op->domid);

    if (!dom) {
        printv("cpupool: domid 0x%x not found\n", op->domid);
        uvv->set_rax(-EINVAL);
        return true;
    }

    auto ret = dom->move_cpupool(vcpu, ctl);
    put_xen_domain(op->domid);

    return ret;
}

static bool cpupool_info(xen_vcpu *vcpu, struct xen_sysctl *ctl)
{
    std::lock_guard lock(cpupool_mutex);

    auto op = &ctl->u.cpupool_op;
    auto uvv = vcpu->m_uv_vcpu;
    auto itr = cpupool_map.find(op->cpupool_id);

    if (itr == cpupool_map.end()) {
        printv("cpupool: cpupool_id 0x%x not found\n", op->cpupool_id);
        uvv->set_rax(-ENOENT);
        return true;
    }

    auto pool = itr->second.get();
    op->n_dom = pool->nr_domains();
    op->sched_id = pool->m_sched_id;

    expects(op->cpumap.nr_bits == 8);
    auto bytes = op->cpumap.nr_bits / 8;
    auto cpumap = uvv->map_gva_4k<uint8_t>(op->cpumap.bitmap.p, bytes);
    *cpumap.get() = 0;

    uvv->set_rax(0);
    return true;
}

bool xen_cpupool_op(xen_vcpu *vcpu, struct xen_sysctl *ctl)
{
    auto op = &ctl->u.cpupool_op;

    printv("cpupool: op:0x%x poolid:0x%x schedid:0x%x domid:0x%x cpu:0x%x\n",
            op->op, op->cpupool_id, op->sched_id, op->domid, op->cpu);

    switch (op->op) {
    case XEN_SYSCTL_CPUPOOL_OP_MOVEDOMAIN:
        return cpupool_move_domain(vcpu, ctl);
    case XEN_SYSCTL_CPUPOOL_OP_INFO:
        return cpupool_info(vcpu, ctl);
    default:
        bfalert_nhex(0, "unhandled cpupool op:", op->op);
        vcpu->m_uv_vcpu->set_rax(-EFAULT);
        return true;
    }
}

xen_cpupool::xen_cpupool(xen_cpupoolid_t id)
{
    m_id = id;
    m_sched_id = 0;
}

uint32_t xen_cpupool::nr_domains() const
{
    return m_domid_set.size();
}

void xen_cpupool::add_domain(xen_domid_t domid)
{
    m_domid_set.emplace(domid);
}

void xen_cpupool::rm_domain(xen_domid_t domid)
{
    m_domid_set.erase(domid);
}

}
