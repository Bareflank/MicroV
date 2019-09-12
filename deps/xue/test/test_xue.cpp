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
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <array>
#include <catch2/catch.hpp>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <xue.h>

constexpr auto power_of_two(size_t size)
{
    return size > 0 && (size & (size - 1)) == 0;
}

static_assert(power_of_two(XUE_TRB_PER_PAGE));
static_assert(power_of_two(XUE_TRB_RING_CAP));
static_assert(sizeof(struct xue_trb) == 16);
static_assert(sizeof(struct xue_dbc_ctx) == 64 * 3);
static_assert(sizeof(struct xue_dbc_reg) == 64);
static_assert(XUE_TRB_RING_CAP * sizeof(struct xue_trb) == XUE_PAGE_SIZE);

constexpr auto xhc_dev{1UL};
constexpr auto xhc_fun{0UL};
constexpr auto xhc_bdf{(1UL << 31) | (xhc_dev << 11) | (xhc_fun << 8)};
constexpr auto xhc_mmio_size = (1UL << 16);

uint32_t pci_bdf{};
uint32_t pci_reg{};

std::array<uint32_t, 64> xhc_cfg{};
std::array<uint8_t, xhc_mmio_size> xhc_mmio{};
std::array<uint32_t, 4> known_xhc_list{
    (XUE_XHC_DEV_Z370 << 16) | XUE_XHC_VEN_INTEL,
    (XUE_XHC_DEV_Z390 << 16) | XUE_XHC_VEN_INTEL,
    (XUE_XHC_DEV_WILDCAT_POINT << 16) | XUE_XHC_VEN_INTEL,
    (XUE_XHC_DEV_SUNRISE_POINT << 16) | XUE_XHC_VEN_INTEL
};

constexpr auto dbc_offset = 0x8000U;
struct xue_dbc_reg *dbc_regs{};

static void *alloc_dma(void *sys, uint64_t order)
{
    (void)sys;

    const int prot = PROT_READ | PROT_WRITE;
    const int flag = MAP_PRIVATE | MAP_ANON | MAP_POPULATE;
    const int size = XUE_PAGE_SIZE << order;

    void *ret = mmap(0, size, prot, flag, -1, 0);
    if (ret == MAP_FAILED) {
        printf("Failed to alloc_pages");
        return NULL;
    }

    return ret;
}

static void free_dma(void *sys, void *addr, uint64_t order)
{
    (void)sys;
    munmap(addr, XUE_PAGE_SIZE << order);
}

static void *map_xhc(void *sys, uint64_t phys, size_t size)
{
    (void)sys;
    (void)phys;
    (void)size;

    return reinterpret_cast<void *>(xhc_mmio.data());
}

static uint32_t ind(void *sys, uint32_t port)
{
    (void)sys;

    if (port != 0xCFC || pci_bdf != xhc_bdf) {
        return 0;
    }

    return xhc_cfg.at(pci_reg);
}

static void outd(void *sys, uint32_t port, uint32_t data)
{
    (void)sys;

    if (port == 0xCF8) {
        pci_bdf = data & 0xFFFFFF00;
        pci_reg = (data & 0xFC) >> 2;
        return;
    }

    if (port == 0xCFC) {
        if (pci_bdf != xhc_bdf) {
            return;
        }
        xhc_cfg.at(pci_reg) = data;
    }
}

static void setup_mmio()
{
    uint32_t *hccp1 = reinterpret_cast<uint32_t *>(xhc_mmio.data() + 0x10);
    *hccp1 = (dbc_offset >> 2) << 16;

    dbc_regs = reinterpret_cast<struct xue_dbc_reg *>(xhc_mmio.data() + dbc_offset);
    dbc_regs->id = 0xA;
    dbc_regs->ctrl |= 1;
}

static void clear_mmio()
{
    uint32_t *hccp1 = reinterpret_cast<uint32_t *>(xhc_mmio.data() + 0x10);
    *hccp1 = 0;
}

static void setup_ops(struct xue_ops *ops)
{
    ops->alloc_dma = alloc_dma;
    ops->free_dma = free_dma;
    ops->map_xhc = map_xhc;
    ops->ind = ind;
    ops->outd = outd;
}

static void setup_pci()
{
    xhc_cfg.at(2) = (XUE_XHC_CLASSC << 8);
    xhc_cfg.at(3) = 0;
    xhc_cfg.at(4) = 4;
}

//----------------------------------------------------------------------------
// Test cases
//----------------------------------------------------------------------------

TEST_CASE("xue_mset")
{
    std::array<uint8_t, 16> a{};
    xue_mset(a.data(), 42, a.size());

    for (auto c : a) {
        CHECK(c == 42);
    }
}

TEST_CASE("xue_mcpy")
{
    std::array<uint8_t, 16> a{};
    std::array<uint8_t, 16> b{};

    for (auto &c : a) {
        c = 42;
    }

    for (auto c : b) {
        CHECK(c == 0);
    }

    xue_mcpy(b.data(), a.data(), b.size());

    for (auto c : b) {
        CHECK(c == 42);
    }
}

TEST_CASE("xue_open - invalid args")
{
    struct xue xue{};
    struct xue_ops ops{};

    CHECK(xue_open(NULL, NULL, NULL) == 0);
    CHECK(xue_open(&xue, NULL, NULL) == 0);
    CHECK(xue_open(NULL, &ops, NULL) == 0);
}

TEST_CASE("xue_open - init ops")
{
    struct xue xue{};
    struct xue_ops ops{};

    CHECK(xue_open(&xue, &ops, NULL) == 0);

    CHECK(xue.ops->alloc_dma == xue_sys_alloc_dma);
    CHECK(xue.ops->free_dma == xue_sys_free_dma);
    CHECK(xue.ops->map_xhc == xue_sys_map_xhc);
    CHECK(xue.ops->unmap_xhc == xue_sys_unmap_xhc);
    CHECK(xue.ops->outd == xue_sys_outd);
    CHECK(xue.ops->ind == xue_sys_ind);
    CHECK(xue.ops->virt_to_dma == xue_sys_virt_to_dma);
    CHECK(xue.ops->sfence == xue_sys_sfence);
}

TEST_CASE("xue_open - alloc failure")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.map_xhc = map_xhc;
    ops.ind = ind;
    ops.outd = outd;

    setup_pci();
    setup_mmio();

    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_open(&xue, &ops, NULL) == 0);
    }
}

TEST_CASE("xue_open - init_dbc failure")
{
    struct xue xue{};
    struct xue_ops ops{};

    setup_ops(&ops);
    setup_pci();
    clear_mmio();

    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_open(&xue, &ops, NULL) == 0);
    }
}

TEST_CASE("xue_open - success")
{
    struct xue xue{};
    struct xue_ops ops{};

    setup_ops(&ops);
    setup_pci();
    setup_mmio();

    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_open(&xue, &ops, NULL) == 1);
        xue_close(&xue);
    }
}

TEST_CASE("xue_init_xhc - not found")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = +[](void *, uint32_t) { return 0U; };
    xue_init_ops(&xue, &ops);

    CHECK(xue_init_xhc(&xue) == 0);
}

TEST_CASE("xue_init_xhc - invalid header")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = ind;
    ops.outd = outd;
    xue_init_ops(&xue, &ops);

    xhc_cfg.at(3) = 0xFF0000;

    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) == 0);
    }
}

TEST_CASE("xue_init_xhc - invalid class code")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = ind;
    ops.outd = outd;
    xue_init_ops(&xue, &ops);

    xhc_cfg.at(2) = (XUE_XHC_CLASSC << 8) + 1;
    xhc_cfg.at(3) = 0;

    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) == 0);
    }
}

TEST_CASE("xue_init_xhc - invalid BAR")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = ind;
    ops.outd = outd;
    xue_init_ops(&xue, &ops);

    xhc_cfg.at(2) = (XUE_XHC_CLASSC << 8);
    xhc_cfg.at(3) = 0;

    xhc_cfg.at(4) = 1;
    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) == 0);
    }

    xhc_cfg.at(4) = 0;
    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) == 0);
    }
}

TEST_CASE("xue_init_xhc - success")
{
    struct xue xue{};
    struct xue_ops ops{};

    ops.ind = ind;
    ops.outd = outd;
    ops.map_xhc = map_xhc;

    xue_init_ops(&xue, &ops);
    setup_pci();

    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_init_xhc(&xue) != 0);
    }
}

TEST_CASE("xue_trb_ring_init")
{
    struct xue xue{};
    struct xue_ops ops{};
    struct xue_trb_ring prod_ring;
    struct xue_trb_ring cons_ring;

    ops.alloc_dma = alloc_dma;
    ops.free_dma = free_dma;

    xue_init_ops(&xue, &ops);
    xue_alloc(&xue);

    prod_ring.trb = xue.dbc_oring.trb;
    cons_ring.trb = xue.dbc_ering.trb;

    xue_trb_ring_init(&xue, &prod_ring, 1, XUE_DB_OUT);
    xue_trb_ring_init(&xue, &cons_ring, 0, XUE_DB_INVAL);

    CHECK(!xue_trb_ring_full(&prod_ring));
    CHECK(!xue_trb_ring_full(&cons_ring));

    CHECK(prod_ring.enq == 0);
    CHECK(prod_ring.deq == 0);
    CHECK(prod_ring.cyc == 1);
    CHECK(prod_ring.db == XUE_DB_OUT);

    CHECK(cons_ring.enq == 0);
    CHECK(cons_ring.deq == 0);
    CHECK(cons_ring.cyc == 1);
    CHECK(cons_ring.db == XUE_DB_INVAL);

    struct xue_trb *prod_end = &prod_ring.trb[XUE_TRB_RING_CAP - 1];
    CHECK(xue_trb_type(prod_end) == xue_trb_link);

    xue_free(&xue);
}

TEST_CASE("xue_push_trb")
{
    struct xue xue{};
    struct xue_ops ops{};
    struct xue_trb_ring ring;

    ops.alloc_dma = alloc_dma;
    ops.free_dma = free_dma;

    xue_init_ops(&xue, &ops);
    xue_alloc(&xue);

    ring.trb = xue.dbc_oring.trb;
    xue_trb_ring_init(&xue, &ring, 1, XUE_DB_OUT);

    CHECK(ring.enq == 0);
    CHECK(ring.cyc == 1);

    for (auto i = 0UL; i < XUE_TRB_RING_CAP; i++) {
        xue_push_trb(&ring, i, 1);
    }

    CHECK(ring.enq == 1);
    CHECK(ring.cyc == 0);

    xue_free(&xue);
}

TEST_CASE("xue_push_work")
{
    struct xue xue{};
    struct xue_ops ops{};
    struct xue_work_ring ring;

    ops.alloc_dma = alloc_dma;
    ops.free_dma = free_dma;

    xue_init_ops(&xue, &ops);
    xue_alloc(&xue);

    ring.enq = 0;
    ring.deq = 0;
    ring.buf = xue.dbc_owork.buf;

    CHECK(xue_work_ring_size(&ring) == 0);
    CHECK(!xue_work_ring_full(&ring));

    for (auto i = 0UL; i < XUE_WORK_RING_CAP; i++) {
        char buf[1] = {1};
        if (i < XUE_WORK_RING_CAP - 1) {
            CHECK(xue_push_work(&ring, buf, 1) == 1);
        } else {
            CHECK(xue_push_work(&ring, buf, 1) == 0);
        }
    }

    CHECK(ring.enq == XUE_WORK_RING_CAP - 1);
    CHECK(xue_work_ring_full(&ring));
    CHECK(xue_work_ring_size(&ring) == XUE_WORK_RING_CAP - 1);

    xue_free(&xue);
}

TEST_CASE("xue_pop_events")
{
    struct xue xue{};
    struct xue_ops ops{};
    struct xue_dbc_reg reg{};
    struct xue_trb_ring *evt;
    struct xue_trb_ring *out;

    ops.alloc_dma = alloc_dma;
    ops.free_dma = free_dma;

    xue_init_ops(&xue, &ops);
    xue_alloc(&xue);
    xue.dbc_reg = &reg;
    xue.dbc_reg->erdp = 0x2000;

    evt = &xue.dbc_ering;
    out = &xue.dbc_oring;

    xue_trb_ring_init(&xue, evt, 0, XUE_DB_INVAL);
    xue_trb_ring_init(&xue, out, 1, XUE_DB_OUT);

    struct xue_trb tfre{};
    struct xue_trb psce{};

    xue_trb_set_type(&tfre, xue_trb_tfre);
    xue_trb_set_type(&psce, xue_trb_psce);

    xue_trb_set_cyc(&tfre, evt->cyc);
    xue_trb_set_cyc(&psce, evt->cyc);

    tfre.status = xue_trb_cc_success << 24;
    tfre.params = 0x1010;

    evt->trb[0] = tfre;
    evt->trb[1] = psce;

    CHECK(!xue_trb_ring_full(evt));

    xue_pop_events(&xue);

    CHECK(out->deq == 1);
    CHECK(evt->deq == 2);
    CHECK(evt->cyc == 1);
    CHECK(xue.dbc_reg->erdp == 0x2020);
}

TEST_CASE("xue_flush")
{
    struct xue xue{};
    struct xue_ops ops{};

    setup_ops(&ops);
    setup_pci();
    setup_mmio();

    for (auto dev_ven : known_xhc_list) {
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_open(&xue, &ops, NULL) == 1);

        dbc_regs->ctrl &= ~(1UL << XUE_CTRL_DCR);
        CHECK((xue.dbc_reg->ctrl & (1UL << XUE_CTRL_DCR)) == 0);
        xue_flush(&xue, &xue.dbc_oring, &xue.dbc_owork);
        CHECK(xue.dbc_oring.enq == 0);
        CHECK(xue.dbc_oring.deq == 0);
        CHECK(xue.dbc_ering.enq == 0);
        CHECK(xue.dbc_ering.deq == 0);

        dbc_regs->ctrl |= (1UL << XUE_CTRL_DCR);
        dbc_regs->ctrl |= (1UL << XUE_CTRL_DRC);
        CHECK((xue.dbc_reg->ctrl & (1UL << XUE_CTRL_DCR)) != 0);
        CHECK((xue.dbc_reg->ctrl & (1UL << XUE_CTRL_DRC)) != 0);
        xue_flush(&xue, &xue.dbc_oring, &xue.dbc_owork);
        CHECK((xue.dbc_reg->ctrl & (1UL << XUE_CTRL_DRC)) != 0);
        CHECK((xue.dbc_reg->portsc & (1UL << XUE_PSC_PED)) != 0);
        CHECK(xue.dbc_oring.enq == 0);
        CHECK(xue.dbc_oring.deq == 0);

        dbc_regs->ctrl &= ~(1UL << XUE_CTRL_DRC);
        xue.dbc_oring.enq = 0;
        xue.dbc_oring.deq = 1;
        CHECK(xue_trb_ring_full(&xue.dbc_oring));
        xue_flush(&xue, &xue.dbc_oring, &xue.dbc_owork);
        CHECK(xue_trb_ring_full(&xue.dbc_oring));

        xue.dbc_oring.enq = 5;
        xue.dbc_oring.deq = 5;
        CHECK(!xue_trb_ring_full(&xue.dbc_oring));

        xue.dbc_owork.enq = 5;
        xue.dbc_owork.deq = 5;
        xue_flush(&xue, &xue.dbc_oring, &xue.dbc_owork);
        CHECK(xue.dbc_owork.enq == 5);
        CHECK(xue.dbc_owork.deq == 5);

        xue.dbc_owork.enq = 9;
        xue.dbc_owork.deq = 2;
        xue_flush(&xue, &xue.dbc_oring, &xue.dbc_owork);
        CHECK(xue.dbc_owork.enq == 9);
        CHECK(xue.dbc_owork.deq == 9);
        CHECK(xue.dbc_oring.enq == 6);

        xue.dbc_owork.deq = 64;
        xue_flush(&xue, &xue.dbc_oring, &xue.dbc_owork);
        CHECK(xue.dbc_owork.deq == 9);
        CHECK(xue.dbc_oring.enq == 8);
        CHECK(xue.dbc_ering.enq == 0);
        CHECK(xue.dbc_ering.deq == 0);

        xue_close(&xue);
    }
}

TEST_CASE("xue_write")
{
    struct xue_ops ops{};

    setup_ops(&ops);
    setup_pci();
    setup_mmio();

    char buf[4] = {'f', 'o', 'o', 0};

    for (auto dev_ven : known_xhc_list) {
        struct xue xue{};
        xhc_cfg.at(0) = dev_ven;
        CHECK(xue_open(&xue, &ops, NULL) == 1);

        CHECK(xue_write(&xue, NULL, 1) == 0);
        CHECK(xue_write(&xue, buf, 0) == 0);
        CHECK(xue_write(&xue, buf, 4) == 4);

        CHECK(!memcmp((const char *)&xue.dbc_owork.buf[0], buf, 4));
        CHECK(xue.dbc_owork.deq == 4);
        CHECK(xue.dbc_owork.enq == 4);
        CHECK(xue.dbc_oring.enq == 1);
        CHECK(xue.dbc_oring.deq == 0);

        xue_close(&xue);
    }
}
