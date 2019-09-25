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
    int rc = pcim_enable_device(pdev);
    if (rc < 0) {
        printk("uv-pci: failed to enable device");
    }

    rc = pci_alloc_irq_vectors(pdev, 1, 1, IRQ_FLAGS);
    if (rc != 1) {
        printk("uv-pci: failed to alloc irq vectors");
        return -ENODEV;
    }

    rc = pci_request_irq(pdev, 0, uv_handle_irq, NULL, pdev, MODULENAME);
    if (rc < 0) {
        printk("uv-pci: pci_request_irq failed");
    }

    return rc;
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
