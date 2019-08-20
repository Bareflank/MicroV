/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef XUE_H
#define XUE_H

/* @cond */

#define XUE_PAGE_SIZE 4096ULL

/* Supported xHC PCI configurations */
#define XUE_XHC_CLASSC 0xC0330ULL
#define XUE_XHC_VEN_INTEL 0x8086ULL
#define XUE_XHC_DEV_Z370 0xA2AFULL
#define XUE_XHC_DEV_Z390 0xA36DULL
#define XUE_XHC_DEV_WILDCAT_POINT 0x9CB1ULL
#define XUE_XHC_DEV_SUNRISE_POINT 0x9D2FULL

/* DbC idVendor and idProduct */
#define XUE_DBC_VENDOR 0x1D6B
#define XUE_DBC_PRODUCT 0x0010
#define XUE_DBC_PROTOCOL 0x0000

/* DCCTRL fields */
#define XUE_CTRL_DCR 0
#define XUE_CTRL_HOT 2
#define XUE_CTRL_HIT 3
#define XUE_CTRL_DRC 4
#define XUE_CTRL_DCE 31

/* DCPORTSC fields */
#define XUE_PSC_PED 1
#define XUE_PSC_CSC 17
#define XUE_PSC_PRC 21
#define XUE_PSC_PLC 22
#define XUE_PSC_CEC 23

#define XUE_PSC_ACK_MASK                                                       \
    ((1UL << XUE_PSC_CSC) | (1UL << XUE_PSC_PRC) | (1UL << XUE_PSC_PLC) |      \
     (1UL << XUE_PSC_CEC))

static inline int known_xhc(uint32_t dev_ven)
{
    switch (dev_ven) {
    case (XUE_XHC_DEV_Z370 << 16) | XUE_XHC_VEN_INTEL:
    case (XUE_XHC_DEV_Z390 << 16) | XUE_XHC_VEN_INTEL:
    case (XUE_XHC_DEV_WILDCAT_POINT << 16) | XUE_XHC_VEN_INTEL:
    case (XUE_XHC_DEV_SUNRISE_POINT << 16) | XUE_XHC_VEN_INTEL:
        return 1;
    default:
        return 0;
    }
}

/* Xue system id */
enum {
    xue_sysid_linux,
    xue_sysid_windows,
    xue_sysid_efi,
    xue_sysid_xen,
    xue_sysid_test
};

/* Userspace testing */
#if defined(XUE_TEST)
#include <cstdint>
#include <cstdio>

#define xue_debug(...) printf("xue debug: " __VA_ARGS__)
#define xue_alert(...) printf("xue alert: " __VA_ARGS__)
#define xue_error(...) printf("xue error: " __VA_ARGS__)
#define XUE_SYSID xue_sysid_test

extern "C" {
static inline int xue_sys_init(void *) { return 1; }
static inline void xue_sys_sfence(void *) {}
static inline void xue_sys_lfence(void *) {}
static inline void xue_sys_pause(void *) {}
static inline void *xue_sys_map_xhc(void *, uint64_t, uint64_t) { return NULL; }
static inline void xue_sys_unmap_xhc(void *sys, void *, uint64_t) {}
static inline void *xue_sys_alloc_dma(void *, uint64_t) { return NULL; }
static inline void xue_sys_free_dma(void *sys, void *, uint64_t) {}
static inline void xue_sys_outd(void *sys, uint32_t, uint32_t) {}
static inline uint32_t xue_sys_ind(void *, uint32_t) { return 0; }
static inline uint64_t xue_sys_virt_to_dma(void *, const void *virt)
{
    return (uint64_t)virt;
}
}

#endif

/* Bareflank VMM */
#if defined(VMM)
#include <arch/intel_x64/barrier.h>
#include <arch/intel_x64/pause.h>
#include <arch/x64/portio.h>
#include <cstdio>
#include <debug/serial/serial_ns16550a.h>
#include <memory_manager/arch/x64/cr3.h>
#include <memory_manager/memory_manager.h>

static_assert(XUE_PAGE_SIZE == BAREFLANK_PAGE_SIZE);

#define xue_printf(...)                                                        \
    do {                                                                       \
        char buf[256];                                                         \
        snprintf(buf, 256, __VA_ARGS__);                                       \
        for (int i = 0; i < 256; i++) {                                        \
            if (buf[i]) {                                                      \
                bfvmm::DEFAULT_COM_DRIVER::instance()->write(buf[i]);          \
            } else {                                                           \
                break;                                                         \
            }                                                                  \
        }                                                                      \
    } while (0)

#define xue_debug(...) xue_printf("xue debug: " __VA_ARGS__)
#define xue_alert(...) xue_printf("xue alert: " __VA_ARGS__)
#define xue_error(...) xue_printf("xue error: " __VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

static inline int xue_sys_init(void *) { return 1; }
static inline void xue_sys_sfence(void *) { wmb(); }
static inline void xue_sys_lfence(void *) { rmb(); }
static inline void xue_sys_pause(void *) { _pause(); }

static inline uint64_t xue_sys_virt_to_dma(void *sys, const void *virt)
{
    (void)sys;
    return g_mm->virtptr_to_physint((void *)virt);
}

static inline void *xue_sys_alloc_dma(void *sys, uint64_t order)
{
    (void)sys;
    return g_mm->alloc(XUE_PAGE_SIZE << order);
}

static inline void xue_sys_free_dma(void *sys, void *addr, uint64_t order)
{
    (void)sys;
    (void)order;

    g_mm->free(addr);
}

static inline void *xue_sys_map_xhc(void *sys, uint64_t phys, uint64_t count)
{
    (void)sys;

    void *virt = g_mm->alloc_map(count);

    for (uint64_t i = 0U; i < count; i += XUE_PAGE_SIZE) {
        using attr_t = bfvmm::x64::cr3::mmap::attr_type;
        using mem_t = bfvmm::x64::cr3::mmap::memory_type;

        g_cr3->map_4k((uint64_t)virt + i, phys + i, attr_t::read_write,
                      mem_t::uncacheable);
    }

    return virt;
}

static inline void xue_sys_unmap_xhc(void *sys, void *virt, uint64_t count)
{
    (void)sys;

    for (uint64_t i = 0U; i < count; i += XUE_PAGE_SIZE) {
        g_cr3->unmap((uint64_t)virt + i);
    }

    g_mm->free_map(virt);
}

static inline void xue_sys_outd(void *sys, uint32_t port, uint32_t data)
{
    (void)sys;
    _outd(port, data);
}

static inline uint32_t xue_sys_ind(void *sys, uint32_t port)
{
    (void)sys;
    return _ind(port);
}

#ifdef __cplusplus
}
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Linux driver */
#if defined(MODULE) && defined(__linux__)
#include <asm/io.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>

#define xue_debug(...) printk(KERN_DEBUG "xue debug: " __VA_ARGS__)
#define xue_alert(...) printk(KERN_ALERT "xue alert: " __VA_ARGS__)
#define xue_error(...) printk(KERN_ERR "xue error: " __VA_ARGS__)
#define XUE_SYSID xue_sysid_linux

static inline int xue_sys_init(void *sys) { return 1; }
static inline void xue_sys_sfence(void *sys) { wmb(); }
static inline void xue_sys_lfence(void *sys) { rmb(); }

static inline void xue_sys_pause(void *sys)
{
    (void)sys;
    __asm volatile("pause" ::: "memory");
}

static inline void *xue_sys_alloc_dma(void *sys, uint64_t order)
{
    return (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, order);
}

static inline void xue_sys_free_dma(void *sys, void *addr, uint64_t order)
{
    free_pages((unsigned long)addr, order);
}

static inline void *xue_sys_map_xhc(void *sys, uint64_t phys, uint64_t count)
{
    return ioremap(phys, (long unsigned int)count);
}

static inline void xue_sys_unmap_xhc(void *sys, void *virt, uint64_t count)
{
    (void)count;
    iounmap((volatile void *)virt);
}

static inline void xue_sys_outd(void *sys, uint32_t port, uint32_t data)
{
    outl(data, port);
}

static inline uint32_t xue_sys_ind(void *sys, uint32_t port)
{
    return inl((int32_t)port);
}

static inline uint64_t xue_sys_virt_to_dma(void *sys, const void *virt)
{
    return virt_to_phys((volatile void *)virt);
}

#endif

/* Windows driver */
#if defined(_WIN32)
#include <basetsd.h>
typedef INT8 int8_t;
typedef INT16 int16_t;
typedef INT32 int32_t;
typedef INT64 int64_t;
typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef UINT_PTR uintptr_t;
typedef INT_PTR intptr_t;

#define XUE_SYSID xue_sysid_windows

#define xue_debug(...)                                                         \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,                         \
               "xue debug: " __VA_ARGS__)
#define xue_alert(...)                                                         \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,                         \
               "xue alert: " __VA_ARGS__)
#define xue_error(...)                                                         \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                        \
               "xue error: " __VA_ARGS__)

static inline int xue_sys_init(void *sys)
{
    (void)sys;

    xue_error("Xue cannot be used from windows drivers");
    return 0;
}

static inline void xue_sys_sfence(void *sys)
{
    (void)sys;
    xue_error("Xue cannot be used from windows drivers");
}

static inline void xue_sys_lfence(void *sys)
{
    (void)sys;
    xue_error("Xue cannot be used from windows drivers");
}

static inline void xue_sys_pause(void *sys)
{
    (void)sys;
    xue_error("Xue cannot be used from windows drivers");
}

static inline void *xue_sys_alloc_dma(void *sys, uint64_t order)
{
    (void)sys;
    (void)order;

    xue_error("Xue cannot be used from windows drivers");
    return NULL;
}

static inline void xue_sys_free_dma(void *sys, void *addr, uint64_t order)
{
    (void)sys;
    (void)addr;
    (void)order;

    xue_error("Xue cannot be used from windows drivers");
}

static inline void *xue_sys_map_xhc(void *sys, uint64_t phys, uint64_t count)
{
    (void)sys;
    (void)phys;
    (void)count;

    xue_error("Xue cannot be used from windows drivers");
    return NULL;
}

static inline void xue_sys_unmap_xhc(void *sys, void *virt, uint64_t count)
{
    (void)sys;
    (void)virt;
    (void)count;

    xue_error("Xue cannot be used from windows drivers");
}

static inline void xue_sys_outd(void *sys, uint32_t port, uint32_t data)
{
    (void)sys;
    (void)port;
    (void)data;

    xue_error("Xue cannot be used from windows drivers");
}

static inline uint32_t xue_sys_ind(void *sys, uint32_t port)
{
    (void)sys;
    (void)port;

    xue_error("Xue cannot be used from windows drivers");
    return 0U;
}

static inline uint64_t xue_sys_virt_to_dma(void *sys, const void *virt)
{
    (void)sys;
    (void)virt;

    xue_error("Xue cannot be used from windows drivers");
    return 0U;
}

#endif

/* UEFI driver (based on gnuefi) */
#if defined(EFI)
#include <efilib.h>

#define xue_debug(...) Print(L"xue debug: " __VA_ARGS__)
#define xue_alert(...) Print(L"xue alert: " __VA_ARGS__)
#define xue_error(...) Print(L"xue error: " __VA_ARGS__)
#define XUE_SYSID xue_sysid_efi

/* NOTE: see xue_alloc_dma for the number of buffers created by alloc_dma */
#define XUE_DMA_DESC_CAP 7

struct xue_efi_dma {
    UINTN pages;
    EFI_PHYSICAL_ADDRESS dma_addr;
    VOID *cpu_addr;
    VOID *mapping;
};

struct xue_efi {
    EFI_HANDLE img_hand;
    EFI_HANDLE pci_hand;
    EFI_PCI_IO *pci_io;
    struct xue_efi_dma dma_desc[XUE_DMA_DESC_CAP];
};

static inline int xue_sys_init(void *sys)
{
    EFI_STATUS rc;
    EFI_HANDLE *hand;
    UINTN nr_hand;
    UINTN i;

    struct xue_efi *efi = (struct xue_efi *)sys;
    ZeroMem((VOID *)&efi->dma_desc, sizeof(efi->dma_desc));

    rc = LibLocateHandle(ByProtocol, &PciIoProtocol, NULL, &nr_hand, &hand);
    if (EFI_ERROR(rc)) {
        xue_error("LocateHandle failed: 0x%llx\n", rc);
        return 0;
    }

    for (i = 0; i < nr_hand; i++) {
        UINT32 dev_ven;
        EFI_PCI_IO *pci_io = NULL;

        rc = gBS->OpenProtocol(hand[i], &PciIoProtocol, (VOID **)&pci_io,
                               efi->img_hand, NULL,
                               EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(rc)) {
            continue;
        }

        rc = pci_io->Pci.Read(pci_io, EfiPciIoWidthUint32, 0, 1, &dev_ven);
        if (EFI_ERROR(rc)) {
            gBS->CloseProtocol(hand[i], &PciIoProtocol, efi->img_hand, NULL);
            continue;
        }

        if (known_xhc(dev_ven)) {
            efi->pci_hand = hand[i];
            efi->pci_io = pci_io;
            return 1;
        }
    }

    xue_error("Failed to open PCI_IO_PROTOCOL on any known xHC\n");
    return 0;
}

static inline void *xue_sys_alloc_dma(void *sys, uint64_t order)
{
    const EFI_ALLOCATE_TYPE atype = AllocateAnyPages;
    const EFI_MEMORY_TYPE mtype = EfiRuntimeServicesData;
    const UINTN attrs = EFI_PCI_ATTRIBUTE_MEMORY_CACHED;
    const UINTN pages = 1UL << order;

    struct xue_efi_dma *dma = NULL;
    struct xue_efi *efi = (struct xue_efi *)sys;
    EFI_PCI_IO *pci = efi->pci_io;
    EFI_STATUS rc = 0;
    VOID *addr = NULL;
    UINTN i = 0;

    for (; i < XUE_DMA_DESC_CAP; i++) {
        dma = &efi->dma_desc[i];
        if (!dma->cpu_addr) {
            break;
        }
        dma = NULL;
    }

    if (!dma) {
        xue_error("Out of DMA descriptors\n");
        return NULL;
    }

    rc = pci->AllocateBuffer(pci, atype, mtype, pages, &addr, attrs);
    if (EFI_ERROR(rc)) {
        xue_error("AllocateBuffer failed: 0x%llx\n", rc);
        return NULL;
    }

    dma->pages = pages;
    dma->cpu_addr = addr;

    return addr;
}

static inline void xue_sys_free_dma(void *sys, void *addr, uint64_t order)
{
    (void)order;

    struct xue_efi_dma *dma = NULL;
    struct xue_efi *efi = (struct xue_efi *)sys;
    EFI_PCI_IO *pci = efi->pci_io;
    EFI_STATUS rc = 0;
    UINTN i = 0;

    for (; i < XUE_DMA_DESC_CAP; i++) {
        dma = &efi->dma_desc[i];
        if (dma->cpu_addr == addr) {
            break;
        }
        dma = NULL;
    }

    if (!dma) {
        return;
    }

    if (dma->mapping) {
        rc = pci->Unmap(pci, dma->mapping);
        if (EFI_ERROR(rc)) {
            xue_error("pci->Unmap failed: 0x%llx\n", rc);
        }
    }

    rc = pci->FreeBuffer(pci, dma->pages, addr);
    if (EFI_ERROR(rc)) {
        xue_error("FreeBuffer failed: 0x%llx\n", rc);
    }

    ZeroMem((VOID *)dma, sizeof(*dma));
}

static inline uint64_t xue_sys_virt_to_dma(void *sys, const void *virt)
{
    UINTN i = 0;
    UINTN needed = 0;
    UINTN mapped = 0;
    struct xue_efi *efi = (struct xue_efi *)sys;
    struct xue_efi_dma *dma = NULL;
    EFI_PHYSICAL_ADDRESS dma_addr = 0;
    EFI_PCI_IO *pci = efi->pci_io;
    EFI_STATUS rc = 0;
    VOID *mapping = NULL;

    for (i = 0; i < XUE_DMA_DESC_CAP; i++) {
        dma = &efi->dma_desc[i];
        if (dma->cpu_addr == virt) {
            break;
        }
        dma = NULL;
    }

    if (!dma) {
        xue_error("CPU addr 0x%llx not found in DMA descriptor\n", virt);
        return 0;
    }

    if (dma->dma_addr && dma->mapping) {
        return dma->dma_addr;
    }

    needed = dma->pages << EFI_PAGE_SHIFT;
    mapped = needed;
    rc = pci->Map(pci, EfiPciIoOperationBusMasterCommonBuffer, (void *)virt,
                  &mapped, &dma_addr, &mapping);
    if (EFI_ERROR(rc) || mapped != needed) {
        xue_error("pci->Map failed: rc: 0x%llx, mapped: %llu, needed: %llu\n",
                  rc, mapped, needed);
        return 0;
    }

    dma->dma_addr = dma_addr;
    dma->mapping = mapping;

    if ((const void *)dma_addr != virt) {
        xue_alert("Non-identity DMA mapping: dma: 0x%llx cpu: 0x%llx\n",
                  dma_addr, virt);
    }

    return dma_addr;
}

static inline void xue_sys_outd(void *sys, uint32_t port, uint32_t val)
{
    (void)sys;

    __asm volatile("movq %0, %%rdx\n\t"
                   "movq %1, %%rax\n\t"
                   "outl %%eax, %%dx\n\t"
                   :
                   : "g"((uint64_t)port), "g"((uint64_t)val));
}

static inline uint32_t xue_sys_ind(void *sys, uint32_t port)
{
    (void)sys;
    uint32_t ret;

    __asm volatile("xorq %%rax, %%rax\n\t"
                   "movq %1, %%rdx\n\t"
                   "inl %%dx, %%eax\n\t"
                   : "=a"(ret)
                   : "g"((uint64_t)port));
    return ret;
}

static inline void *xue_sys_map_xhc(void *sys, uint64_t phys, uint64_t count)
{
    (void)sys;
    (void)count;

    return (void *)phys;
}

static inline void xue_sys_unmap_xhc(void *sys, void *virt, uint64_t count)
{
    (void)sys;
    (void)virt;
    (void)count;
}

static inline void xue_sys_sfence(void *sys)
{
    (void)sys;
    __asm volatile("sfence" ::: "memory");
}

static inline void xue_sys_lfence(void *sys)
{
    (void)sys;
    __asm volatile("lfence" ::: "memory");
}

static inline void xue_sys_pause(void *sys)
{
    (void)sys;
    __asm volatile("pause" ::: "memory");
}
#endif

#if defined(__XEN__) && !defined(VMM)

#include <asm/fixmap.h>
#include <asm/io.h>
#include <xen/mm.h>
#include <xen/types.h>

#define xue_debug(...) printk("xue debug: " __VA_ARGS__)
#define xue_alert(...) printk("xue alert: " __VA_ARGS__)
#define xue_error(...) printk("xue error: " __VA_ARGS__)
#define XUE_SYSID xue_sysid_xen

static inline int xue_sys_init(void *sys) { return 1; }
static inline void xue_sys_sfence(void *sys) { wmb(); }
static inline void xue_sys_lfence(void *sys) { rmb(); }
static inline void xue_sys_unmap_xhc(void *sys, void *virt, uint64_t count) {}
static inline void xue_sys_free_dma(void *sys, void *addr, uint64_t order) {}

static inline void xue_sys_pause(void *sys)
{
    (void)sys;
    __asm volatile("pause" ::: "memory");
}

static inline void *xue_sys_alloc_dma(void *sys, uint64_t order)
{
    return NULL;
}

static inline uint32_t xue_sys_ind(void *sys, uint32_t port)
{
    return inl(port);
}

static inline void xue_sys_outd(void *sys, uint32_t port, uint32_t data)
{
    outl(data, port);
}

static inline uint64_t xue_sys_virt_to_dma(void *sys, const void *virt)
{
    return virt_to_maddr(virt);
}

static void *xue_sys_map_xhc(void *sys, uint64_t phys, uint64_t size)
{
    size_t i;

    if (size != MAX_XHCI_PAGES * XUE_PAGE_SIZE) {
        return NULL;
    }

    for (i = FIX_XHCI_END; i >= FIX_XHCI_BEGIN; i--) {
        set_fixmap_nocache(i, phys);
        phys += XUE_PAGE_SIZE;
    }

    /*
     * The fixmap grows downward, so the lowest virt is
     * at the highest index
     */
    return fix_to_virt(FIX_XHCI_END);
}

#endif

/******************************************************************************
 * TRB ring (summarized from the manual):
 *
 * TRB rings are circular queues of TRBs shared between the xHC and the driver.
 * Each ring has one producer and one consumer. The DbC has one event
 * ring and two transfer rings; one IN and one OUT.
 *
 * The DbC hardware is the producer on the event ring, and
 * xue is the consumer. This means that event TRBs are read-only from
 * the xue.
 *
 * OTOH, xue is the producer of transfer TRBs on the two transfer
 * rings, so xue enqueues transfers, and the hardware dequeues
 * them. The dequeue pointer of a transfer ring is read by
 * xue by examining the latest transfer event TRB on the event ring. The
 * transfer event TRB contains the address of the transfer TRB that generated
 * the event.
 *
 * To make each transfer ring circular, the last TRB must be a link TRB, which
 * points to the beginning of the next queue. Note that this implementation
 * does not support multiple segments, so each link TRB points back to the
 * beginning of its own segment.
 ******************************************************************************/

/* TRB types */
enum {
    xue_trb_norm = 1,
    xue_trb_link = 6,
    xue_trb_tfre = 32,
    xue_trb_psce = 34
};

/* TRB completion codes */
enum { xue_trb_cc_success = 1, xue_trb_cc_trb_err = 5 };

/* DbC endpoint types */
enum { xue_ep_bulk_out = 2, xue_ep_bulk_in = 6 };

/* DMA/MMIO structures */
#pragma pack(push, 1)
struct xue_trb {
    uint64_t params;
    uint32_t status;
    uint32_t ctrl;
};

struct xue_erst_segment {
    uint64_t base;
    uint16_t size;
    uint8_t rsvdz[6];
};

#define XUE_CTX_SIZE 16
#define XUE_CTX_BYTES (XUE_CTX_SIZE * 4)

struct xue_dbc_ctx {
    uint32_t info[XUE_CTX_SIZE];
    uint32_t ep_out[XUE_CTX_SIZE];
    uint32_t ep_in[XUE_CTX_SIZE];
};

struct xue_dbc_reg {
    uint32_t id;
    uint32_t db;
    uint32_t erstsz;
    uint32_t rsvdz;
    uint64_t erstba;
    uint64_t erdp;
    uint32_t ctrl;
    uint32_t st;
    uint32_t portsc;
    uint32_t rsvdp;
    uint64_t cp;
    uint32_t ddi1;
    uint32_t ddi2;
};
#pragma pack(pop)

#define XUE_TRB_MAX_TFR (XUE_PAGE_SIZE << 4)
#define XUE_TRB_PER_PAGE (XUE_PAGE_SIZE / sizeof(struct xue_trb))

/* Defines the size in bytes of TRB rings as 2^XUE_TRB_RING_ORDER * 4096 */
#ifndef XUE_TRB_RING_ORDER
#define XUE_TRB_RING_ORDER 0
#endif
#define XUE_TRB_RING_CAP (XUE_TRB_PER_PAGE * (1ULL << XUE_TRB_RING_ORDER))
#define XUE_TRB_RING_BYTES (XUE_TRB_RING_CAP * sizeof(struct xue_trb))
#define XUE_TRB_RING_MASK (XUE_TRB_RING_BYTES - 1U)

struct xue_trb_ring {
    struct xue_trb *trb; /* Array of TRBs */
    uint32_t enq; /* The offset of the enqueue ptr */
    uint32_t deq; /* The offset of the dequeue ptr */
    uint8_t cyc; /* Cycle state toggled on each wrap-around */
    uint8_t db; /* Doorbell target */
};

#define XUE_DB_OUT 0x0
#define XUE_DB_IN 0x1
#define XUE_DB_INVAL 0xFF

/* Defines the size in bytes of work rings as 2^XUE_WORK_RING_ORDER * 4096 */
#ifndef XUE_WORK_RING_ORDER
#define XUE_WORK_RING_ORDER 3
#endif
#define XUE_WORK_RING_CAP (XUE_PAGE_SIZE * (1ULL << XUE_WORK_RING_ORDER))

#if XUE_WORK_RING_CAP > XUE_TRB_MAX_TFR
#error "XUE_WORK_RING_ORDER must be at most 4"
#endif

struct xue_work_ring {
    uint8_t *buf;
    uint32_t enq;
    uint32_t deq;
    uint64_t dma;
};

/* @endcond */

/**
 * Set of system-specific operations required by xue to initialize and
 * control the DbC. An instance of this structure must be passed to
 * xue_open. Any field that is NULL will default to the xue_sys_*
 * implementation defined for the target platform. <em>Any non-NULL field will
 * simply be called</em>.
 */
struct xue_ops {
    /**
     * Perform system-specific init operations
     *
     * @param sys a pointer to a system-specific data structure
     * @return != 0 iff successful
     */
    int (*init)(void *sys);

    /**
     * Allocate pages for read/write DMA
     *
     * @param sys a pointer to a system-specific data structure
     * @param order allocate 2^order pages
     * @return a cpu-relative virtual address for accessing the DMA buffer
     */
    void *(*alloc_dma)(void *sys, uint64_t order);

    /**
     * Free pages previously allocated with alloc_dma
     *
     * @param sys a pointer to a system-specific data structure
     * @param addr the cpu-relative address of the DMA range to free
     * @param order the order of the set of pages to free
     */
    void (*free_dma)(void *sys, void *addr, uint64_t order);

    /**
     * Map in the xHC MMIO region as uncacheable memory
     *
     * @param sys a pointer to a system-specific data structure
     * @param phys the value from the xHC's BAR
     * @param size the number of bytes to map in
     * @return the mapped virtual address
     */
    void *(*map_xhc)(void *sys, uint64_t phys, uint64_t size);

    /**
     * Unmap xHC MMIO region
     *
     * @param sys a pointer to a system-specific data structure
     * @param virt the MMIO address to unmap
     */
    void (*unmap_xhc)(void *sys, void *virt, uint64_t size);

    /**
     * Write 32 bits to IO port
     *
     * @param sys a pointer to a system-specific data structure
     * @param port the port to write to
     * @param data the data to write
     */
    void (*outd)(void *sys, uint32_t port, uint32_t data);

    /**
     * Read 32 bits from IO port
     *
     * @param sys a pointer to a system-specific data structure
     * @param port the port to read from
     * @return the data read from the port
     */
    uint32_t (*ind)(void *sys, uint32_t port);

    /**
     * Translate a virtual address to a DMA address
     *
     * @param sys a pointer to a system-specific data structure
     * @param virt the address returned from a previous alloc_dma call
     * @return the resulting bus-relative DMA address
     */
    uint64_t (*virt_to_dma)(void *sys, const void *virt);

    /**
     * Perform a write memory barrier
     * @param sys a pointer to a system-specific data structure
     */
    void (*sfence)(void *sys);

    /**
     * Perform a read memory barrier
     * @param sys a pointer to a system-specific data structure
     */
    void (*lfence)(void *sys);

    /**
     * Pause CPU execution
     * @param sys a pointer to a system-specific data structure
     */
    void (*pause)(void *sys);
};

/* @cond */

struct xue {
    struct xue_ops *ops;
    void *sys;

    struct xue_dbc_reg *dbc_reg;
    struct xue_dbc_ctx *dbc_ctx;
    struct xue_erst_segment *dbc_erst;
    struct xue_trb_ring dbc_ering;
    struct xue_trb_ring dbc_oring;
    struct xue_trb_ring dbc_iring;
    struct xue_work_ring dbc_owork;
    char *dbc_str;

    uint32_t xhc_cf8;
    uint64_t xhc_mmio_phys;
    uint64_t xhc_mmio_size;
    uint64_t xhc_dbc_offset;
    void *xhc_mmio;

    int dma_allocated;
    int open;
    int sysid;
};

static inline void *xue_mset(void *dest, int c, uint64_t size)
{
    uint64_t i;
    char *d = (char *)dest;

    for (i = 0; i < size; i++) {
        d[i] = (char)c;
    }

    return dest;
}

static inline void *xue_mcpy(void *dest, const void *src, uint64_t size)
{
    uint64_t i;
    char *d = (char *)dest;
    const char *s = (const char *)src;

    for (i = 0; i < size; i++) {
        d[i] = s[i];
    }

    return dest;
}

static inline uint32_t xue_pci_read(struct xue *xue, uint32_t cf8, uint32_t reg)
{
    void *sys = xue->sys;
    uint32_t addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);

    xue->ops->outd(sys, 0xCF8, addr);
    return xue->ops->ind(sys, 0xCFC);
}

static inline void xue_pci_write(struct xue *xue, uint32_t cf8, uint32_t reg,
                                 uint32_t val)
{
    void *sys = xue->sys;
    uint32_t addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);

    xue->ops->outd(sys, 0xCF8, addr);
    xue->ops->outd(sys, 0xCFC, val);
}

static inline int xue_init_xhc(struct xue *xue)
{
    uint32_t bar0;
    uint64_t bar1;
    uint64_t devfn;

    struct xue_ops *ops = xue->ops;
    void *sys = xue->sys;
    xue->xhc_cf8 = 0;

    /*
     * Search PCI bus 0 for the xHC. All the host controllers supported so far
     * are part of the chipset and are on bus 0.
     */
    for (devfn = 0; devfn < 256; devfn++) {
        uint32_t dev = (devfn & 0xF8) >> 3;
        uint32_t fun = devfn & 0x07;
        uint32_t cf8 = (1UL << 31) | (dev << 11) | (fun << 8);
        uint32_t hdr = (xue_pci_read(xue, cf8, 3) & 0xFF0000U) >> 16;

        if (hdr == 0 || hdr == 0x80) {
            if ((xue_pci_read(xue, cf8, 2) >> 8) == XUE_XHC_CLASSC) {
                xue->xhc_cf8 = cf8;
                break;
            }
        }
    }

    if (!xue->xhc_cf8) {
        xue_error("Compatible xHC not found on bus 0\n");
        return 0;
    }

    /* ...we found it, so parse the BAR and map the registers */
    bar0 = xue_pci_read(xue, xue->xhc_cf8, 4);
    bar1 = xue_pci_read(xue, xue->xhc_cf8, 5);

    /* IO BARs not allowed; BAR must be 64-bit */
    if ((bar0 & 0x1) != 0 || ((bar0 & 0x6) >> 1) != 2) {
        return 0;
    }

    xue_pci_write(xue, xue->xhc_cf8, 4, 0xFFFFFFFF);
    xue->xhc_mmio_size = ~(xue_pci_read(xue, xue->xhc_cf8, 4) & 0xFFFFFFF0) + 1;
    xue_pci_write(xue, xue->xhc_cf8, 4, bar0);

    xue->xhc_mmio_phys = (bar0 & 0xFFFFFFF0) | (bar1 << 32);
    xue->xhc_mmio = ops->map_xhc(sys, xue->xhc_mmio_phys, xue->xhc_mmio_size);

    return xue->xhc_mmio != NULL;
}

/**
 * The first register of the debug capability is found by traversing the
 * host controller's capability list (xcap) until a capability
 * with ID = 0xA is found. The xHCI capability list begins at address
 * mmio + (HCCPARAMS1[31:16] << 2)
 */
static inline struct xue_dbc_reg *xue_find_dbc(struct xue *xue)
{
    uint32_t *xcap;
    uint32_t next;
    uint32_t id;
    uint8_t *mmio = (uint8_t *)xue->xhc_mmio;
    uint32_t *hccp1 = (uint32_t *)(mmio + 0x10);
    const uint32_t DBC_ID = 0xA;

    /**
     * Paranoid check against a zero value. The spec mandates that
     * at least one "supported protocol" capability must be implemented,
     * so this should always be false.
     */
    if ((*hccp1 & 0xFFFF0000) == 0) {
        return NULL;
    }

    xcap = (uint32_t *)(mmio + (((*hccp1 & 0xFFFF0000) >> 16) << 2));
    next = (*xcap & 0xFF00) >> 8;
    id = *xcap & 0xFF;

    /**
     * Table 7-1 states that 'next' is relative to
     * the current value of xcap and is a dword offset.
     */
    while (id != DBC_ID && next) {
        xcap += next;
        id = *xcap & 0xFF;
        next = (*xcap & 0xFF00) >> 8;
    }

    if (id != DBC_ID) {
        return NULL;
    }

    xue->xhc_dbc_offset = (uint64_t)xcap - (uint64_t)mmio;
    return (struct xue_dbc_reg *)xcap;
}

/**
 * Fields with the same interpretation for every TRB type (section 4.11.1).
 * These are the fields defined in the TRB template, minus the ENT bit. That
 * bit is the toggle cycle bit in link TRBs, so it shouldn't be in the
 * template.
 */
static inline uint32_t xue_trb_cyc(const struct xue_trb *trb)
{
    return trb->ctrl & 0x1;
}

static inline uint32_t xue_trb_type(const struct xue_trb *trb)
{
    return (trb->ctrl & 0xFC00) >> 10;
}

static inline void xue_trb_set_cyc(struct xue_trb *trb, uint32_t c)
{
    trb->ctrl &= ~0x1UL;
    trb->ctrl |= c;
}

static inline void xue_trb_set_type(struct xue_trb *trb, uint32_t t)
{
    trb->ctrl &= ~0xFC00UL;
    trb->ctrl |= (t << 10);
}

/* Fields for normal TRBs */
static inline void xue_trb_norm_set_buf(struct xue_trb *trb, uint64_t addr)
{
    trb->params = addr;
}

static inline void xue_trb_norm_set_len(struct xue_trb *trb, uint32_t len)
{
    trb->status &= ~0x1FFFFUL;
    trb->status |= len;
}

static inline void xue_trb_norm_set_ioc(struct xue_trb *trb)
{
    trb->ctrl |= 0x20;
}

/**
 * Fields for Transfer Event TRBs (see section 6.4.2.1). Note that event
 * TRBs are read-only from software
 */
static inline uint64_t xue_trb_tfre_ptr(const struct xue_trb *trb)
{
    return trb->params;
}

static inline uint32_t xue_trb_tfre_cc(const struct xue_trb *trb)
{
    return trb->status >> 24;
}

/* Fields for link TRBs (section 6.4.4.1) */
static inline void xue_trb_link_set_rsp(struct xue_trb *trb, uint64_t rsp)
{
    trb->params = rsp;
}

static inline void xue_trb_link_set_tc(struct xue_trb *trb)
{
    trb->ctrl |= 0x2;
}

static inline void xue_trb_ring_init(const struct xue *xue,
                                     struct xue_trb_ring *ring, int producer,
                                     int doorbell)
{
    xue_mset(ring->trb, 0, XUE_TRB_RING_CAP * sizeof(ring->trb[0]));

    ring->enq = 0;
    ring->deq = 0;
    ring->cyc = 1;
    ring->db = (uint8_t)doorbell;

    /*
     * Producer implies transfer ring, so we have to place a
     * link TRB at the end that points back to trb[0]
     */
    if (producer) {
        struct xue_trb *trb = &ring->trb[XUE_TRB_RING_CAP - 1];
        xue_trb_set_type(trb, xue_trb_link);
        xue_trb_link_set_tc(trb);
        xue_trb_link_set_rsp(trb, xue->ops->virt_to_dma(xue->sys, ring->trb));
    }
}

static inline int xue_trb_ring_full(const struct xue_trb_ring *ring)
{
    return ((ring->enq + 1) & (XUE_TRB_RING_CAP - 1)) == ring->deq;
}

static inline int xue_work_ring_full(const struct xue_work_ring *ring)
{
    return ((ring->enq + 1) & (XUE_WORK_RING_CAP - 1)) == ring->deq;
}

static inline uint64_t xue_work_ring_size(const struct xue_work_ring *ring)
{
    if (ring->enq >= ring->deq) {
        return ring->enq - ring->deq;
    }

    return XUE_WORK_RING_CAP - ring->deq + ring->enq;
}

static inline void xue_push_trb(struct xue_trb_ring *ring, uint64_t dma,
                                uint64_t len)
{
    struct xue_trb trb;

    if (ring->enq == XUE_TRB_RING_CAP - 1) {
        ring->enq = 0;
        ring->cyc ^= 1;
    }

    trb.params = 0;
    trb.status = 0;
    trb.ctrl = 0;

    xue_trb_set_type(&trb, xue_trb_norm);
    xue_trb_set_cyc(&trb, ring->cyc);

    xue_trb_norm_set_buf(&trb, dma);
    xue_trb_norm_set_len(&trb, (uint32_t)len);
    xue_trb_norm_set_ioc(&trb);

    ring->trb[ring->enq++] = trb;
}

static inline int64_t xue_push_work(struct xue_work_ring *ring, const char *buf,
                                    int64_t len)
{
    int64_t i = 0;

    while (!xue_work_ring_full(ring) && i < len) {
        ring->buf[ring->enq] = buf[i++];
        ring->enq = (ring->enq + 1) & (XUE_WORK_RING_CAP - 1);
    }

    return i;
}

/*
 * Note that if IN transfer support is added, then this
 * will need to be changed; it assumes an OUT transfer ring only
 */
static inline void xue_pop_events(struct xue *xue)
{
    const int trb_shift = 4;

    void *sys = xue->sys;
    struct xue_ops *ops = xue->ops;
    struct xue_dbc_reg *reg = xue->dbc_reg;
    struct xue_trb_ring *er = &xue->dbc_ering;
    struct xue_trb_ring *tr = &xue->dbc_oring;
    struct xue_trb *event = &er->trb[er->deq];
    uint64_t erdp = reg->erdp;

    ops->lfence(sys);

    while (xue_trb_cyc(event) == er->cyc) {
        switch (xue_trb_type(event)) {
        case xue_trb_tfre:
            if (xue_trb_tfre_cc(event) != xue_trb_cc_success) {
                xue_alert("tfre error cc: %u\n", xue_trb_tfre_cc(event));
                break;
            }
            tr->deq =
                (xue_trb_tfre_ptr(event) & XUE_TRB_RING_MASK) >> trb_shift;
            break;
        case xue_trb_psce:
            reg->portsc |= (XUE_PSC_ACK_MASK & reg->portsc);
            break;
        default:
            break;
        }

        er->cyc = (er->deq == XUE_TRB_RING_CAP - 1) ? er->cyc ^ 1 : er->cyc;
        er->deq = (er->deq + 1) & (XUE_TRB_RING_CAP - 1);
        event = &er->trb[er->deq];
    }

    erdp &= ~XUE_TRB_RING_MASK;
    erdp |= (er->deq << trb_shift);
    ops->sfence(sys);
    reg->erdp = erdp;
}

/**
 * xue_init_ep
 *
 * Initializes the endpoint as specified in sections 7.6.3.2 and 7.6.9.2.
 * Each endpoint is Bulk, so the MaxPStreams, LSA, HID, CErr, FE,
 * Interval, Mult, and Max ESIT Payload fields are all 0.
 *
 * Max packet size: 1024
 * Max burst size: debug mbs (from dbc_reg->ctrl register)
 * EP type: 2 for OUT bulk, 6 for IN bulk
 * TR dequeue ptr: physical base address of transfer ring
 * Avg TRB length: software defined (see 4.14.1.1 for suggested defaults)
 */
static inline void xue_init_ep(uint32_t *ep, uint64_t mbs, uint32_t type,
                               uint64_t ring_dma)
{
    xue_mset(ep, 0, XUE_CTX_BYTES);

    ep[1] = (1024 << 16) | ((uint32_t)mbs << 8) | (type << 3);
    ep[2] = (ring_dma & 0xFFFFFFFF) | 1;
    ep[3] = ring_dma >> 32;
    ep[4] = 3 * 1024;
}

/* Initialize the DbC info with USB string descriptor addresses */
static inline void xue_init_strings(struct xue *xue, uint32_t *info)
{
    uint64_t *sda;

    /* clang-format off */
    const char strings[] = {
        6,  3, 9, 0, 4, 0,
        8,  3, 'A', 0, 'I', 0, 'S', 0,
        30, 3, 'X', 0, 'u', 0, 'e', 0, ' ', 0,
               'D', 0, 'b', 0, 'C', 0, ' ', 0,
               'D', 0, 'e', 0, 'v', 0, 'i', 0, 'c', 0, 'e', 0,
        4, 3, '0', 0
    };
    /* clang-format on */

    xue_mcpy(xue->dbc_str, strings, sizeof(strings));

    sda = (uint64_t *)&info[0];
    sda[0] = xue->ops->virt_to_dma(xue->sys, xue->dbc_str);
    sda[1] = sda[0] + 6;
    sda[2] = sda[0] + 6 + 8;
    sda[3] = sda[0] + 6 + 8 + 30;
    info[8] = (4 << 24) | (30 << 16) | (8 << 8) | 6;
}

static inline void xue_dump(struct xue *xue)
{
    struct xue_ops *op = xue->ops;
    struct xue_dbc_reg *r = xue->dbc_reg;

    xue_debug("XUE DUMP:\n");
    xue_debug("    ctrl: 0x%x stat: 0x%x psc: 0x%x\n", r->ctrl, r->st,
              r->portsc);
    xue_debug("    id: 0x%x, db: 0x%x\n", r->id, r->db);
#if defined(__XEN__) || defined(VMM)
    xue_debug("    erstsz: %u, erstba: 0x%lx\n", r->erstsz, r->erstba);
    xue_debug("    erdp: 0x%lx, cp: 0x%lx\n", r->erdp, r->cp);
#else
    xue_debug("    erstsz: %u, erstba: 0x%llx\n", r->erstsz, r->erstba);
    xue_debug("    erdp: 0x%llx, cp: 0x%llx\n", r->erdp, r->cp);
#endif
    xue_debug("    ddi1: 0x%x, ddi2: 0x%x\n", r->ddi1, r->ddi2);
    xue_debug("    erstba == virt_to_dma(erst): %d\n",
              r->erstba == op->virt_to_dma(xue->sys, xue->dbc_erst));
    xue_debug("    erdp == virt_to_dma(erst[0].base): %d\n",
              r->erdp == xue->dbc_erst[0].base);
    xue_debug("    cp == virt_to_dma(ctx): %d\n",
              r->cp == op->virt_to_dma(xue->sys, xue->dbc_ctx));
}

static inline void xue_enable_dbc(struct xue *xue)
{
    void *sys = xue->sys;
    struct xue_ops *ops = xue->ops;
    struct xue_dbc_reg *reg = xue->dbc_reg;

    ops->sfence(sys);
    reg->ctrl |= (1UL << XUE_CTRL_DCE);
    while ((reg->ctrl & (1UL << XUE_CTRL_DCE)) == 0) {
        ops->pause(sys);
    }

    reg->portsc |= (1UL << XUE_PSC_PED);

    /*
     * TODO:
     *
     * There is a slight difference in behavior between enabling the DbC from
     * pre and post-EFI. From post-EFI, if the cable is connected when the DbC
     * is enabled, the host automatically enumerates the DbC. Pre-EFI, you
     * have to plug the cable in after the DCE bit is set on some systems
     * for it to enumerate.
     *
     * I suspect the difference is due to the state of the port prior to
     * initializing the DbC. Section 4.19.1.2.4.2 seems like a good place to
     * start a deeper investigation into this.
     */
    if (xue->sysid == xue_sysid_efi) {
        xue_debug("Please insert the debug cable to continue...\n");
    }

    while ((reg->ctrl & (1UL << XUE_CTRL_DCR)) == 0) {
        ops->pause(sys);
    }
}

static inline void xue_disable_dbc(struct xue *xue)
{
    void *sys = xue->sys;
    struct xue_ops *ops = xue->ops;
    struct xue_dbc_reg *reg = xue->dbc_reg;

    reg->portsc &= ~(1UL << XUE_PSC_PED);
    ops->sfence(sys);
    reg->ctrl &= ~(1UL << XUE_CTRL_DCE);

    while (reg->ctrl & (1UL << XUE_CTRL_DCE)) {
        ops->pause(sys);
    }
}

static inline int xue_init_dbc(struct xue *xue)
{
    uint64_t erdp = 0;
    uint64_t out = 0;
    uint64_t in = 0;
    uint64_t mbs = 0;
    struct xue_ops *op = xue->ops;
    struct xue_dbc_reg *reg = xue_find_dbc(xue);

    if (!reg) {
        return 0;
    }

    xue->dbc_reg = reg;
    xue_disable_dbc(xue);

    xue_trb_ring_init(xue, &xue->dbc_ering, 0, XUE_DB_INVAL);
    xue_trb_ring_init(xue, &xue->dbc_oring, 1, XUE_DB_OUT);
    xue_trb_ring_init(xue, &xue->dbc_iring, 1, XUE_DB_IN);

    erdp = op->virt_to_dma(xue->sys, xue->dbc_ering.trb);
    if (!erdp) {
        return 0;
    }

    xue_mset(xue->dbc_erst, 0, sizeof(*xue->dbc_erst));
    xue->dbc_erst->base = erdp;
    xue->dbc_erst->size = XUE_TRB_RING_CAP;

    mbs = (reg->ctrl & 0xFF0000) >> 16;
    out = op->virt_to_dma(xue->sys, xue->dbc_oring.trb);
    in = op->virt_to_dma(xue->sys, xue->dbc_iring.trb);

    xue_mset(xue->dbc_ctx, 0, sizeof(*xue->dbc_ctx));
    xue_init_strings(xue, xue->dbc_ctx->info);
    xue_init_ep(xue->dbc_ctx->ep_out, mbs, xue_ep_bulk_out, out);
    xue_init_ep(xue->dbc_ctx->ep_in, mbs, xue_ep_bulk_in, in);

    reg->erstsz = 1;
    reg->erstba = op->virt_to_dma(xue->sys, xue->dbc_erst);
    reg->erdp = erdp;
    reg->cp = op->virt_to_dma(xue->sys, xue->dbc_ctx);
    reg->ddi1 = (XUE_DBC_VENDOR << 16) | XUE_DBC_PROTOCOL;
    reg->ddi2 = XUE_DBC_PRODUCT;

    return 1;
}

static inline void xue_free(struct xue *xue)
{
    void *sys = xue->sys;
    struct xue_ops *ops = xue->ops;

    if (!ops->free_dma) {
        return;
    }

    ops->free_dma(sys, xue->dbc_str, 0);
    ops->free_dma(sys, xue->dbc_owork.buf, XUE_WORK_RING_ORDER);
    ops->free_dma(sys, xue->dbc_iring.trb, XUE_TRB_RING_ORDER);
    ops->free_dma(sys, xue->dbc_oring.trb, XUE_TRB_RING_ORDER);
    ops->free_dma(sys, xue->dbc_ering.trb, XUE_TRB_RING_ORDER);
    ops->free_dma(sys, xue->dbc_erst, 0);
    ops->free_dma(sys, xue->dbc_ctx, 0);
    xue->dma_allocated = 0;

    ops->unmap_xhc(sys, xue->xhc_mmio, xue->xhc_mmio_size);
}

static inline int xue_alloc(struct xue *xue)
{
    void *sys = xue->sys;
    struct xue_ops *ops = xue->ops;

    if (xue->dma_allocated) {
        return 1;
    }

    if (!ops->alloc_dma) {
        return 1;
    } else if (!ops->free_dma) {
        return 0;
    }

    xue->dbc_ctx = (struct xue_dbc_ctx *)ops->alloc_dma(xue->sys, 0);
    if (!xue->dbc_ctx) {
        return 0;
    }

    xue->dbc_erst = (struct xue_erst_segment *)ops->alloc_dma(xue->sys, 0);
    if (!xue->dbc_erst) {
        goto free_ctx;
    }

    xue->dbc_ering.trb =
        (struct xue_trb *)ops->alloc_dma(sys, XUE_TRB_RING_ORDER);
    if (!xue->dbc_ering.trb) {
        goto free_erst;
    }

    xue->dbc_oring.trb =
        (struct xue_trb *)ops->alloc_dma(sys, XUE_TRB_RING_ORDER);
    if (!xue->dbc_oring.trb) {
        goto free_etrb;
    }

    xue->dbc_iring.trb =
        (struct xue_trb *)ops->alloc_dma(sys, XUE_TRB_RING_ORDER);
    if (!xue->dbc_iring.trb) {
        goto free_otrb;
    }

    xue->dbc_owork.buf = (uint8_t *)ops->alloc_dma(sys, XUE_WORK_RING_ORDER);
    if (!xue->dbc_owork.buf) {
        goto free_itrb;
    }

    xue->dbc_str = (char *)ops->alloc_dma(sys, 0);
    if (!xue->dbc_str) {
        goto free_owrk;
    }

    xue->dma_allocated = 1;
    return 1;

free_owrk:
    ops->free_dma(sys, xue->dbc_owork.buf, XUE_WORK_RING_ORDER);
free_itrb:
    ops->free_dma(sys, xue->dbc_iring.trb, XUE_TRB_RING_ORDER);
free_otrb:
    ops->free_dma(sys, xue->dbc_oring.trb, XUE_TRB_RING_ORDER);
free_etrb:
    ops->free_dma(sys, xue->dbc_ering.trb, XUE_TRB_RING_ORDER);
free_erst:
    ops->free_dma(sys, xue->dbc_erst, 0);
free_ctx:
    ops->free_dma(sys, xue->dbc_ctx, 0);

    return 0;
}

#define xue_set_op(op)                                                         \
    do {                                                                       \
        if (!ops->op) {                                                        \
            ops->op = xue_sys_##op;                                            \
        }                                                                      \
    } while (0)

static inline void xue_init_ops(struct xue *xue, struct xue_ops *ops)
{
    xue_set_op(init);
    xue_set_op(alloc_dma);
    xue_set_op(free_dma);
    xue_set_op(map_xhc);
    xue_set_op(unmap_xhc);
    xue_set_op(outd);
    xue_set_op(ind);
    xue_set_op(virt_to_dma);
    xue_set_op(sfence);
    xue_set_op(lfence);
    xue_set_op(pause);

    xue->ops = ops;
}

static inline void xue_init_work_ring(struct xue *xue,
                                      struct xue_work_ring *wrk)
{
    wrk->enq = 0;
    wrk->deq = 0;
    wrk->dma = xue->ops->virt_to_dma(xue->sys, wrk->buf);
}

/* @endcond */

/**
 * Initialize the DbC and enable it for transfers. First map in the DbC
 * registers from the host controller's MMIO region. Then allocate and map
 * DMA for the event and transfer rings. Finally, enable the DbC for
 * the host to enumerate. On success, the DbC is ready to send packets.
 *
 * @param xue the xue to open (!= NULL)
 * @param ops the xue ops to use (!= NULL)
 * @param sys the system-specific data (may be NULL)
 * @return 1 iff xue_open succeeded
 */
static inline int64_t xue_open(struct xue *xue, struct xue_ops *ops, void *sys)
{
    if (!xue || !ops) {
        return 0;
    }

    xue_init_ops(xue, ops);
    xue->sys = sys;

    if (!ops->init(sys)) {
        return 0;
    }

    if (!xue_init_xhc(xue)) {
        return 0;
    }

    if (!xue_alloc(xue)) {
        return 0;
    }

    if (!xue_init_dbc(xue)) {
        xue_free(xue);
        return 0;
    }

    xue_init_work_ring(xue, &xue->dbc_owork);
    xue_enable_dbc(xue);
    xue->open = 1;

    return 1;
}

/**
 * Commit the pending transfer TRBs to the DbC. This notifies
 * the DbC of any previously-queued data on the work ring and
 * rings the doorbell.
 *
 * @param xue the xue to flush
 * @param trb the ring containing the TRBs to transfer
 * @param wrk the work ring containing data to be flushed
 */
static inline void xue_flush(struct xue *xue, struct xue_trb_ring *trb,
                             struct xue_work_ring *wrk)
{
    struct xue_dbc_reg *reg = xue->dbc_reg;
    uint32_t db = (reg->db & 0xFFFF00FF) | (trb->db << 8);

    if (xue->open && !(reg->ctrl & (1UL << XUE_CTRL_DCE))) {
        if (!xue_init_dbc(xue)) {
            xue_free(xue);
            return;
        }

        xue_init_work_ring(xue, &xue->dbc_owork);
        xue_enable_dbc(xue);
    }

    xue_pop_events(xue);

    if (!(reg->ctrl & (1UL << XUE_CTRL_DCR))) {
        xue_error("DbC not configured");
        return;
    }

    if (reg->ctrl & (1UL << XUE_CTRL_DRC)) {
        reg->ctrl |= (1UL << XUE_CTRL_DRC);
        reg->portsc |= (1UL << XUE_PSC_PED);
        xue->ops->sfence(xue->sys);
    }

    if (xue_trb_ring_full(trb)) {
        return;
    }

    if (wrk->enq == wrk->deq) {
        return;
    } else if (wrk->enq > wrk->deq) {
        xue_push_trb(trb, wrk->dma + wrk->deq, wrk->enq - wrk->deq);
        wrk->deq = wrk->enq;
    } else {
        xue_push_trb(trb, wrk->dma + wrk->deq, XUE_WORK_RING_CAP - wrk->deq);
        wrk->deq = 0;
        if (wrk->enq > 0 && !xue_trb_ring_full(trb)) {
            xue_push_trb(trb, wrk->dma, wrk->enq);
            wrk->deq = wrk->enq;
        }
    }

    xue->ops->sfence(xue->sys);
    reg->db = db;
}

/**
 * Queue the data referenced by the given buffer to the DbC. A transfer TRB
 * will be created and the DbC will be notified that data is available for
 * writing to the debug host.
 *
 * @param xue the xue to write to
 * @param buf the data to write
 * @param size the length in bytes of buf
 * @return the number of bytes written
 */
static inline int64_t xue_write(struct xue *xue, const char *buf, uint64_t size)
{
    int64_t ret;

    if (!buf || size <= 0) {
        return 0;
    }

    ret = xue_push_work(&xue->dbc_owork, buf, size);
    if (!ret) {
        return 0;
    }

    xue_flush(xue, &xue->dbc_oring, &xue->dbc_owork);
    return ret;
}

/**
 * Queue a single character to the DbC. A transfer TRB will be created
 * if the character is a newline and the DbC will be notified that data is
 * available for writing to the debug host.
 *
 * @param xue the xue to write to
 * @param c the character to write
 * @return the number of bytes written
 */
static inline int64_t xue_putc(struct xue *xue, char c)
{
    if (!xue_push_work(&xue->dbc_owork, &c, 1)) {
        return 0;
    }

    if (c == '\n') {
        xue_flush(xue, &xue->dbc_oring, &xue->dbc_owork);
    }

    return 1;
}

/**
 * Disable the DbC and free DMA and MMIO resources back to the host system.
 *
 * @param xue the xue to close
 */
static inline void xue_close(struct xue *xue)
{
    xue_disable_dbc(xue);
    xue_free(xue);
    xue->open = 0;
}

#ifdef __cplusplus
}
#endif
#endif
