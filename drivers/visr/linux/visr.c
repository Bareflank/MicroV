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
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/pci.h>

#include <microv/hypercall.h>
#include <microv/pci.h>

#define MODULENAME "uv-pci"
#define IRQ_FLAGS (PCI_IRQ_MSI)

static const struct pci_device_id uv_id_table[] = {
    { PCI_DEVICE(MICROV_PCI_VENDOR, PCI_ANY_ID) },
    {}
};

static irqreturn_t uv_handle_irq(int irq, void *data)
{
    struct pci_dev *pdev = data;

    uint64_t bdf = ((uint64_t)pdev->bus->number << 16) |
                   ((uint64_t)pdev->devfn << 8);

    __event_op__send_bdf(bdf);
    return IRQ_HANDLED;
}

static int uv_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    int rc, i;
    int nr_vecs;

    int bus = pdev->bus->number;
    int dev = pdev->devfn >> 3;
    int fun = pdev->devfn & 0x7;

    rc = pcim_enable_device(pdev);
    if (rc < 0) {
        printk("uv-pci %02x:%02x.%02x: failed to enable device",
                bus, dev, fun);
    }

    nr_vecs = 1;
    rc = pci_alloc_irq_vectors(pdev, nr_vecs, nr_vecs, IRQ_FLAGS);
    if (rc < nr_vecs) {
        printk("uv-pci %02x:%02x.%02x: failed to alloc irq vectors, rc=%d",
                bus, dev, fun, rc);
        return -ENODEV;
    }

    printk("uv-pci %02x:%02x.%02x: allocated %u vectors\n",
           bus, dev, fun, rc);

    for (i = 0; i < rc; i++) {
        if (pci_request_irq(pdev, i, uv_handle_irq, NULL, pdev, MODULENAME)) {
            printk("uv-pci %02x:%02x.%02x: pci_request_irq failed",
                   bus, dev, fun);
            return -ENODEV;
        }
    }

    return 0;
}

static void uv_pci_remove(struct pci_dev *pdev)
{
    pci_free_irq_vectors(pdev);
    pci_disable_device(pdev);
}

static struct pci_driver uv_pci_driver = {
    .name = MODULENAME,
    .id_table = uv_id_table,
    .probe = uv_pci_probe,
    .remove = uv_pci_remove
};

MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, uv_id_table);
module_pci_driver(uv_pci_driver);
