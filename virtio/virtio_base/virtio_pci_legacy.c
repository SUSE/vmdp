/*
 * Copyright IBM Corp. 2007
 *
 * Authors:
 *  Anthony Liguori  <aliguori@us.ibm.com>
 *  Windows porting - Yan Vugenfirer <yvugenfi@redhat.com>
 *
 * Copyright 2017-2020 SUSE LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ntddk.h>
#include <virtio_dbg_print.h>
#include <virtio_pci.h>
#include <virtio_ring.h>

static struct virtio_device_ops_s virtio_pci_device_ops;

static void
virtio_dev_legacy_get_config(virtio_device_t *vdev,
                             unsigned int offset, void *buf, unsigned int len) {
    ULONG_PTR ioaddr;
    uint8_t *ptr = buf;
    unsigned int i;

    ioaddr = vdev->addr + vdev->msix_used_offset + VIRTIO_PCI_CONFIG + offset;
    RPRINTK(DPRTL_PCI, ("%s %s: read port %x len %d\n",
                        vdev->drv_name, __func__, ioaddr, len));
    for (i = 0; i < len; i++) {
        ptr[i] = virtio_ioread8(ioaddr + i);
    }
}

static void
virtio_dev_legacy_set_config(virtio_device_t *vdev,
                             unsigned offset, const void *buf, unsigned len) {
    const uint8_t *ptr = buf;
    ULONG_PTR ioaddr;
    unsigned i;

    ioaddr = vdev->addr + vdev->msix_used_offset + VIRTIO_PCI_CONFIG + offset;
    RPRINTK(DPRTL_PCI, ("%s %s: write port %x len %d\n",
                        vdev->drv_name, __func__, ioaddr, len));
    for (i = 0; i < len; i++) {
        virtio_iowrite8(ioaddr + i, ptr[i]);
    }
}

static uint8_t
virtio_dev_legacy_get_status(virtio_device_t *vdev) {
    RPRINTK(DPRTL_PCI, ("%s %s: read port %x\n",
                        vdev->drv_name, __func__,
                        vdev->addr + VIRTIO_PCI_STATUS));
    return virtio_ioread8(vdev->addr + VIRTIO_PCI_STATUS);
}

static void
virtio_dev_legacy_set_status(virtio_device_t *vdev, uint8_t status) {
    RPRINTK(DPRTL_PCI, ("%s %s: write port %x, status %x\n",
                        vdev->drv_name, __func__,
                        vdev->addr + VIRTIO_PCI_STATUS, status));
    virtio_iowrite8(vdev->addr + VIRTIO_PCI_STATUS, status);
}

static void
virtio_dev_legacy_reset(virtio_device_t *vdev) {
    /* 0 status means a reset. */
    RPRINTK(DPRTL_PCI, ("%s %s: write port %x\n",
                        vdev->drv_name, __func__,
                        vdev->addr + VIRTIO_PCI_STATUS));
    virtio_iowrite8(vdev->addr + VIRTIO_PCI_STATUS, 0);
}

static uint64_t
virtio_dev_legacy_get_features(virtio_device_t *vdev) {
    ULONG features;

    features = virtio_ioread32(vdev->addr + VIRTIO_PCI_HOST_FEATURES);
    RPRINTK(DPRTL_PCI, ("%s %s: port %x, features %x\n",
                        vdev->drv_name, __func__,
                        vdev->addr + VIRTIO_PCI_HOST_FEATURES,
                        features));
    return features;
}

static NTSTATUS
virtio_dev_legacy_set_features(virtio_device_t *vdev, uint64_t features) {
    /* Give virtio_ring a chance to accept features. */
    vring_transport_features(&features);

    virtio_iowrite32(vdev->addr + VIRTIO_PCI_GUEST_FEATURES,
                     (uint32_t)features);

    return STATUS_SUCCESS;
}

static NTSTATUS
virtio_dev_legacy_query_vq_alloc(virtio_device_t *vdev,
                                 unsigned qidx,
                                 uint16_t *pnum,
                                 unsigned long *pring_size,
                                 unsigned long *pheap_size) {
    uint16_t num;

    /* Select the queue we're interested in */
    virtio_iowrite16(vdev->addr + VIRTIO_PCI_QUEUE_SEL, (uint16_t)qidx);

    /* Check if queue is either not available or already active. */
    num = virtio_ioread16(vdev->addr + VIRTIO_PCI_QUEUE_NUM);
    if (!num || virtio_ioread32(vdev->addr + VIRTIO_PCI_QUEUE_PFN)) {
        return STATUS_NOT_FOUND;
    }

    *pnum = num;
    if (pring_size != NULL) {
        *pring_size = vring_size(num, VIRTIO_PCI_VRING_ALIGN);
    }
    if (pheap_size != NULL) {
        *pheap_size = sizeof(void *) * num + sizeof(virtio_queue_t);
    }

    return STATUS_SUCCESS;
}

static uint16_t
virtio_dev_legacy_set_config_vector(virtio_device_t *vdev, uint16_t vector)
{
    /* Setup the vector used for configuration events */
    virtio_iowrite16(vdev->addr + VIRTIO_MSI_CONFIG_VECTOR, vector);

    /* Verify we had enough resources to assign the vector */
    /* Will also flush the write out to device */
    return virtio_ioread16(vdev->addr + VIRTIO_MSI_CONFIG_VECTOR);
}

static uint16_t
virtio_dev_legacy_set_queue_vector(virtio_device_t *vdev,
                                   uint16_t qidx,
                                   uint16_t vector)
{
    virtio_iowrite16(vdev->addr + VIRTIO_PCI_QUEUE_SEL, qidx);
    virtio_iowrite16(vdev->addr + VIRTIO_MSI_QUEUE_VECTOR, vector);
    return virtio_ioread16(vdev->addr + VIRTIO_MSI_QUEUE_VECTOR);
}

static NTSTATUS
virtio_dev_legacy_vq_activate(virtio_device_t *vdev,
                              virtio_queue_t *vq,
                              uint16_t msi_vector)
{
    PHYSICAL_ADDRESS pa;
    ULONG page_num;

    pa = MmGetPhysicalAddress(vq->vring.desc);
    page_num = (ULONG)(pa.QuadPart >> VIRTIO_PCI_QUEUE_ADDR_SHIFT);
    RPRINTK(DPRTL_PCI, ("%s %s: activate q, pa 0x%x%x, pagenum 0x%x\n",
                        vdev->drv_name, __func__,
         pa.u.HighPart, pa.u.LowPart, page_num));
    RPRINTK(DPRTL_PCI, ("%s %s: write port %x, idx %x\n",
                        vdev->drv_name, __func__,
                        vdev->addr + VIRTIO_PCI_QUEUE_SEL, vq->qidx));
    virtio_iowrite16(vdev->addr + VIRTIO_PCI_QUEUE_SEL, vq->qidx);
    RPRINTK(DPRTL_PCI, ("%s %s: write port %x, page_num %x\n",
                        vdev->drv_name, __func__,
                        vdev->addr + VIRTIO_PCI_QUEUE_PFN, page_num));
    virtio_iowrite32(vdev->addr + VIRTIO_PCI_QUEUE_PFN, page_num);

    if (msi_vector != VIRTIO_MSI_NO_VECTOR) {
        msi_vector = virtio_dev_legacy_set_queue_vector(vdev,
                                                        vq->qidx,
                                                        msi_vector);
        if (msi_vector == VIRTIO_MSI_NO_VECTOR) {
            PRINTK(("%s %s: Failed to set vector %d\n",
                    vdev->drv_name, __func__, msi_vector));
            return STATUS_UNSUCCESSFUL;
        }
    }
    return STATUS_SUCCESS;
}

static virtio_queue_t *
virtio_dev_legacy_vq_setup(virtio_device_t *vdev, uint16_t qidx,
    virtio_queue_t *vq, void *vring_mem, uint16_t num, uint16_t msi_vector,
    BOOLEAN use_event_idx)
{
    NTSTATUS status;
    uint16_t i;
    BOOLEAN alloced_mem;

    alloced_mem = FALSE;
    if (vq == NULL) {
        status = virtio_dev_legacy_query_vq_alloc(vdev, qidx, &num, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            return NULL;
        }
        vq = VIRTIO_ALLOC(sizeof(virtio_queue_t) + (sizeof(void *) * num));
        if (vq == NULL) {
            return NULL;
        }

        VIRTIO_ALLOC_CONTIGUOUS(vring_mem,
            vring_size(num, VIRTIO_PCI_VRING_ALIGN));
        if (vring_mem == NULL) {
            VIRTIO_FREE(vq);
            return NULL;
        }
        alloced_mem = TRUE;
    }

    memset(vq, 0, sizeof(virtio_queue_t) + (sizeof(void *) * num));
    memset(vring_mem, 0, vring_size(num, VIRTIO_PCI_VRING_ALIGN));

    RPRINTK(DPRTL_PCI, ("%s %s: vring_init\n", vdev->drv_name, __func__));
    vring_init(&vq->vring, num, vring_mem, VIRTIO_PCI_VRING_ALIGN);

    vq->vdev = vdev;
    vq->qidx = qidx;
    vq->port = (uint32_t)vdev->addr;
    vq->num_free = num;
    vq->free_head = 0;
    vq->use_event_idx = use_event_idx;

    RPRINTK(DPRTL_PCI, ("%s %s: init descriptors\n", vdev->drv_name, __func__));
    for (i = 0; i < num - 1; i++) {
        vq->vring.desc[i].next = i + 1;
    }

    vq->notification_addr = (void *)(vdev->addr + VIRTIO_PCI_QUEUE_NOTIFY);

    /* activate the queue */
    status = virtio_dev_legacy_vq_activate(vdev, vq, msi_vector);
    if (!NT_SUCCESS(status)) {
        if (alloced_mem == TRUE) {
            if (vring_mem != NULL) {
                VIRTIO_FREE(vring_mem);
            }
            if (vq != NULL) {
                VIRTIO_FREE(vq);
            }
        }
        return NULL;
    }

    RPRINTK(DPRTL_PCI, ("%s %s: OUT\n", vdev->drv_name, __func__));
    return vq;
}

static void
virtio_dev_legacy_vq_delete(virtio_queue_t *vq, uint32_t free_mem)
{
    virtio_device_t *vdev = vq->vdev;
    virtio_iowrite16(vdev->addr + VIRTIO_PCI_QUEUE_SEL, vq->qidx);

    if (vdev->msix_used_offset) {
        virtio_iowrite16(vdev->addr + VIRTIO_MSI_QUEUE_VECTOR,
                         VIRTIO_MSI_NO_VECTOR);
        /* Flush the write out to device */
        virtio_ioread8(vdev->addr + VIRTIO_PCI_ISR);
    }

    /* Select and deactivate the queue */
    virtio_iowrite32(vdev->addr + VIRTIO_PCI_QUEUE_PFN, 0);

    if (free_mem && vq) {
        if (vq->vring.desc) {
            VIRTIO_FREE_CONTIGUOUS(vq->vring.desc);
        }
        VIRTIO_FREE(vq);
    }
}

NTSTATUS
virtio_dev_legacy_init(virtio_device_t *vdev,
                       virtio_bar_t *vbar,
                       PUCHAR pci_config_buf) {

    vdev->addr = (ULONG_PTR)vbar[0].va;

    if (!vdev->addr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    vdev->isr = (u8 *)vdev->addr + VIRTIO_PCI_ISR;

    virtio_pci_device_ops.get_config = virtio_dev_legacy_get_config;
    virtio_pci_device_ops.set_config = virtio_dev_legacy_set_config;
    virtio_pci_device_ops.get_config_generation = NULL;
    virtio_pci_device_ops.get_status = virtio_dev_legacy_get_status;
    virtio_pci_device_ops.set_status = virtio_dev_legacy_set_status;
    virtio_pci_device_ops.reset = virtio_dev_legacy_reset;
    virtio_pci_device_ops.get_features = virtio_dev_legacy_get_features;
    virtio_pci_device_ops.set_features = virtio_dev_legacy_set_features;
    virtio_pci_device_ops.set_config_vector = virtio_dev_legacy_set_config_vector;
    virtio_pci_device_ops.set_queue_vector = virtio_dev_legacy_set_queue_vector;
    virtio_pci_device_ops.query_queue_alloc = virtio_dev_legacy_query_vq_alloc;
    virtio_pci_device_ops.setup_queue = virtio_dev_legacy_vq_setup;
    virtio_pci_device_ops.delete_queue = virtio_dev_legacy_vq_delete;
    virtio_pci_device_ops.activate_queue = virtio_dev_legacy_vq_activate;

    vdev->dev_op = &virtio_pci_device_ops;

    return STATUS_SUCCESS;
}
