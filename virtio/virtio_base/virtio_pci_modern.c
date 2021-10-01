/*
 * Copyright IBM Corp. 2007
 * Copyright Red Hat, Inc. 2014
 *
 * Authors:
 *  Anthony Liguori  <aliguori@us.ibm.com>
 *  Rusty Russell <rusty@rustcorp.com.au>
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * Copyright 2017-2021 SUSE LLC
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
#include <virtio_utils.h>
#include <virtio_pci.h>
#include <virtio_queue_ops.h>

static struct virtio_device_ops_s virtio_pci_device_ops;

static void *
virtio_modern_map_capability(virtio_bar_t *vbar,
                             PUCHAR pci_config_buf,
                             int cap_offset,
                             size_t minlen,
                             uint32_t alignment,
                             uint32_t start,
                             uint32_t size,
                             size_t *len)
{
    uint8_t bar;
    uint32_t bar_offset, bar_length;
    void *addr;

    PCI_READ_CONFIG_BYTE(pci_config_buf,
        cap_offset + offsetof(virtio_pci_cap_t, bar), bar);
    PCI_READ_CONFIG_DWORD(pci_config_buf,
        cap_offset + offsetof(virtio_pci_cap_t, offset), bar_offset);
    PCI_READ_CONFIG_DWORD(pci_config_buf,
        cap_offset + offsetof(virtio_pci_cap_t, length), bar_length);

    RPRINTK(DPRTL_PCI,
            ("%s: cap_offset %d, mlen %d, align %d start 0x%x size %d\n",
             __func__, cap_offset, minlen, alignment, start, size));
    RPRINTK(DPRTL_PCI,
            ("%s: bar %d, bar_offset %d, bar_len %d\n",
             __func__, bar, bar_offset, bar_length));


    if (start + minlen > bar_length) {
        PRINTK(("bar %i is not large enough to map %zu bytes at offset %u\n",
                 bar, minlen, start));
        return NULL;
    }

    bar_length -= start;
    bar_offset += start;

    if (bar_offset & (alignment - 1)) {
        PRINTK(("bar %i offset %u not aligned to %u\n",
                bar, bar_offset, alignment));
        return NULL;
    }

    if (bar_length > size) {
        bar_length = size;
    }

    if (len) {
        *len = bar_length;
    }

    if (bar_offset + minlen > vbar[bar].len) {
        PRINTK(("bar %i is not large enough to map %zu bytes at offset %u\n",
                bar, minlen, bar_offset));
        return NULL;
    }

    addr = (PUCHAR)vbar[bar].va + bar_offset;
    if (addr == NULL) {
        PRINTK(("unable to map %u bytes at bar %i offset %u\n",
                bar_length, bar, bar_offset));
    }
    RPRINTK(DPRTL_PCI, ("%s: addr 0x%p\n", __func__, addr));
    return addr;
}

static void *
virtio_modern_map_simple_capability(virtio_bar_t *vbar,
                                    PUCHAR pci_config_buf,
                                    int cap_offset,
                                    size_t length,
                                    uint32_t alignment)
{
    return virtio_modern_map_capability(
        vbar,
        pci_config_buf,
        cap_offset,
        length,             /* minlen */
        alignment,
        0,                  /* offset */
        (uint32_t)length,   /* size is equal to minlen */
        NULL);              /* not interested in the full length */
}

static void
virtio_dev_modern_get_config(virtio_device_t *vdev,
                             unsigned offset, void *buf, unsigned len)
{
    uint8_t *ptr;
    ULONG i;

    if (!vdev->config) {
        PRINTK(("%s: Device has no config to read\n", vdev->drv_name));
        return;
    }
    if ((size_t)offset + (size_t)len > vdev->config_len) {
        PRINTK(("%s: Can't read beyond the config length\n", vdev->drv_name));
        return;
    }

    switch (len) {
    case 1:
        *(uint8_t *)buf = virtio_ioread8((ULONG_PTR)(vdev->config + offset));
        break;
    case 2:
        *(uint16_t *)buf = virtio_ioread16((ULONG_PTR)(vdev->config + offset));
        break;
    case 4:
        *(uint32_t *)buf = virtio_ioread32((ULONG_PTR)(vdev->config + offset));
        break;
    default:
        ptr = buf;
        for (i = 0; i < len; i++, offset++) {
            ptr[i] = virtio_ioread8((ULONG_PTR)(vdev->config + offset));
        }
        break;
    }
}

static void
virtio_dev_modern_set_config(virtio_device_t *vdev, unsigned offset,
                             const void *buf, unsigned len)
{
    uint8_t *ptr;
    ULONG i;

    if (!vdev->config) {
        PRINTK(("%s: Device has no config to write\n", vdev->drv_name));
        return;
    }
    if ((size_t)offset + (size_t)len > vdev->config_len) {
        PRINTK(("%s: Can't write beyond the config length\n", vdev->drv_name));
        return;
    }

    switch (len) {
    case 1:
        virtio_iowrite8((ULONG_PTR)(vdev->config + offset), *(uint8_t *)buf);
        break;
    case 2:
        virtio_iowrite16((ULONG_PTR)(vdev->config + offset), *(uint16_t *)buf);
        break;
    case 4:
        virtio_iowrite32((ULONG_PTR)(vdev->config + offset), *(uint32_t *)buf);
        break;
    default:
        ptr = (uint8_t *)buf;
        for (i = 0; i < len; i++, offset++) {
            virtio_iowrite8((ULONG_PTR)(vdev->config + offset), ptr[i]);
        }
        break;
    }
}

static uint32_t
virtio_dev_modern_get_generation(virtio_device_t *vdev)
{
    return virtio_ioread8((ULONG_PTR)&vdev->common->config_generation);
}

static uint8_t
virtio_dev_modern_get_status(virtio_device_t *vdev)
{
    return virtio_ioread8((ULONG_PTR)&vdev->common->device_status);
}

static void
virtio_dev_modern_set_status(virtio_device_t *vdev, uint8_t status)
{
    /* We should never be setting status to 0. */
    if (status == 0) {
        PRINTK(("%s %s: error, trying to set setatus to 0\n",
                vdev->drv_name, __func__));
        return;
    }
    virtio_iowrite8((ULONG_PTR)&vdev->common->device_status, status);
}

static void virtio_dev_modern_reset(virtio_device_t *vdev)
{
    /* 0 status means a reset. */
    virtio_iowrite8((ULONG_PTR)&vdev->common->device_status, 0);

    /*
     * After writing 0 to device_status, the driver MUST wait for a read of
     * device_status to return 0 before reinitializing the device.
     * This will flush out the status write, and flush in device writes,
     * including MSI-X interrupts, if any.
     */
    while (virtio_ioread8((ULONG_PTR)&vdev->common->device_status)) {
        virtio_sleep(1);
    }
}

static uint64_t
virtio_dev_modern_get_features(virtio_device_t *vdev)
{
    uint64_t features;

    virtio_iowrite32((ULONG_PTR)&vdev->common->device_feature_select, 0);
    features = virtio_ioread32((ULONG_PTR)&vdev->common->device_feature);
    virtio_iowrite32((ULONG_PTR)&vdev->common->device_feature_select, 1);
    features |=
        ((uint64_t)virtio_ioread32((ULONG_PTR)&vdev->common->device_feature)
            << 32);

    return features;
}

static NTSTATUS
virtio_dev_modern_set_features(virtio_device_t *vdev, u64 features)
{
    /* Give virtio_ring a chance to accept features. */
    vring_transport_features(&features);

    if (features && !virtio_is_feature_enabled(features, VIRTIO_F_VERSION_1)) {
        PRINTK(("%s: modern interface missing VIRTIO_F_VERSION_1 %llx\n",
                vdev->drv_name, features));
        return STATUS_INVALID_PARAMETER;
    }

    virtio_iowrite32((ULONG_PTR)&vdev->common->guest_feature_select, 0);
    virtio_iowrite32((ULONG_PTR)&vdev->common->guest_feature,
                     (uint32_t)features);
    virtio_iowrite32((ULONG_PTR)&vdev->common->guest_feature_select, 1);
    virtio_iowrite32((ULONG_PTR)&vdev->common->guest_feature, features >> 32);

    return STATUS_SUCCESS;
}

static uint16_t
virtio_dev_modern_set_config_vector(virtio_device_t *vdev, uint16_t vector)
{
    /* Setup the vector used for configuration events */
    virtio_iowrite16((ULONG_PTR)&vdev->common->msix_config, vector);

    /* Verify we had enough resources to assign the vector */
    /* Will also flush the write out to device */
    return virtio_ioread16((ULONG_PTR)&vdev->common->msix_config);
}

static uint16_t
virtio_dev_modern_set_queue_vector(virtio_device_t *vdev,
                                   uint16_t qidx,
                                   uint16_t vector)
{
    volatile virtio_pci_common_cfg_t *cfg = vdev->common;

    virtio_iowrite16((ULONG_PTR)&cfg->queue_select, qidx);
    virtio_iowrite16((ULONG_PTR)&cfg->queue_msix_vector, vector);
    return virtio_ioread16((ULONG_PTR)&cfg->queue_msix_vector);
}

static void
virtio_dev_modern_query_vq_size(unsigned int num,
                                unsigned int packed_ring,
                                unsigned long *pring_size,
                                unsigned long *pqueue_size)
{
    if (pring_size != NULL) {
        if (packed_ring) {
            *pring_size = vring_size_packed(num, SMP_CACHE_BYTES);
        } else {
            *pring_size = vring_size_split(num, SMP_CACHE_BYTES);
        }
    }
    if (pqueue_size != NULL) {
        if (packed_ring) {
            *pqueue_size = vring_control_block_size_packed(num);
        } else {
            *pqueue_size = sizeof(void *) * num + sizeof(virtio_queue_split_t);
        }
    }
}

static NTSTATUS
virtio_dev_modern_query_vq_alloc(virtio_device_t *vdev,
                                 unsigned qidx,
                                 uint16_t *pnum,
                                 unsigned long *pring_size,
                                 unsigned long *pqueue_size)
{
    volatile virtio_pci_common_cfg_t *cfg = vdev->common;
    uint16_t num;

    if (qidx >= virtio_ioread16((ULONG_PTR)&cfg->num_queues)) {
        return STATUS_NOT_FOUND;
    }

    /* Select the queue we're interested in */
    virtio_iowrite16((ULONG_PTR)&cfg->queue_select, (uint16_t)qidx);

    /* Check if queue is either not available or already active. */
    num = virtio_ioread16((ULONG_PTR)&cfg->queue_size);
    /*
     * QEMU has a bug where queues don't revert to inactive on device
     * reset. Skip checking the queue_enable field until it is fixed.
     */
    if (!num) {
        return STATUS_NOT_FOUND;
    }

    if (num & (num - 1)) {
        PRINTK(("%s %s: bad queue size %u", vdev->drv_name, __func__, num));
        return STATUS_INVALID_PARAMETER;
    }

    *pnum = num;

    virtio_dev_modern_query_vq_size(num,
                                    vdev->packed_ring,
                                    pring_size,
                                    pqueue_size);

    return STATUS_SUCCESS;
}

static NTSTATUS
virtio_dev_modern_vq_activate(virtio_device_t *vdev,
                              virtio_queue_t *vq,
                              uint16_t msi_vector,
                              BOOLEAN queue_notify_off)
{
    PHYSICAL_ADDRESS pa;
    volatile virtio_pci_common_cfg_t *cfg;
    void *ring;
    void *avail;
    void *used;
    uint16_t num;
    uint16_t off;

    cfg = vdev->common;
    num = (uint16_t)vq->num;

    RPRINTK(DPRTL_PCI, ("%s %s:\n", vdev->drv_name, __func__));

    vq_get_ring_mem_desc(vq, &ring, &avail, &used);

    /* activate the queue */
    RPRINTK(DPRTL_PCI, ("\twrite cfg->queue_size %p num %d\n",
                        cfg->queue_size, num));
    virtio_iowrite16((ULONG_PTR)&cfg->queue_size, num);

    RPRINTK(DPRTL_PCI, ("\twrite vring_mem\n"));
    pa = MmGetPhysicalAddress(ring);
    VIRTIO_IOWRITE64_LOHI(pa.QuadPart,
                          &cfg->queue_desc_lo,
                          &cfg->queue_desc_hi);
    RPRINTK(DPRTL_PCI, ("\twrite avail\n"));
    pa = MmGetPhysicalAddress(avail);
    VIRTIO_IOWRITE64_LOHI(pa.QuadPart,
                          &cfg->queue_avail_lo,
                          &cfg->queue_avail_hi);
    RPRINTK(DPRTL_PCI, ("\twrite used\n"));
    pa = MmGetPhysicalAddress(used);
    VIRTIO_IOWRITE64_LOHI(pa.QuadPart,
                          &cfg->queue_used_lo,
                          &cfg->queue_used_hi);

    do {
        if (queue_notify_off) {
            RPRINTK(DPRTL_PCI, ("\tread notify offset\n"));
            off = virtio_ioread16((ULONG_PTR)&cfg->queue_notify_off);
            if (vdev->notify_base) {
                /* get offset of notification word for this vq */
                /* offset should not wrap */
                RPRINTK(DPRTL_PCI, ("\tnotify offset %d, multi %d len %d\n",
                        off, vdev->notify_offset_multiplier + 2,
                        vdev->notify_len));
                if ((uint64_t)off * vdev->notify_offset_multiplier + 2
                        > vdev->notify_len) {
                    PRINTK((
                        "%p: bad notification offset %u (x %u) "
                        "for queue %u > %zd",
                        vdev,
                        off, vdev->notify_offset_multiplier,
                        vq->qidx, vdev->notify_len));
                    break;
                }
                vq->notification_addr = (void *)(vdev->notify_base +
                    ((uintptr_t)off *
                        (uintptr_t)vdev->notify_offset_multiplier));
                RPRINTK(DPRTL_PCI, ("\tnotification_addr %p\n",
                                    vq->notification_addr));
            } else {
                vq->notification_addr = vdev->notification_addr;
            }

            if (!vq->notification_addr) {
                PRINTK(("%s %s: Could not get the notification address.\n",
                        vdev->drv_name, __func__));
                break;
            }
        }

        if (msi_vector != VIRTIO_MSI_NO_VECTOR) {
            RPRINTK(DPRTL_PCI, ("\tvirtio_dev_modern_set_queue_vector %d\n",
                                msi_vector));
            msi_vector = virtio_dev_modern_set_queue_vector(vdev,
                                                            vq->qidx,
                                                            msi_vector);
            if (msi_vector == VIRTIO_MSI_NO_VECTOR) {
                PRINTK(("%s %s: Could not get the msi vector.\n",
                        vdev->drv_name, __func__));
                break;
            }
        }

        /* enable the queue */
        RPRINTK(DPRTL_PCI, ("\tvdev->common->queue_enable\n"));
        virtio_iowrite16((ULONG_PTR)&vdev->common->queue_enable, 1);

        return STATUS_SUCCESS;
    } while (FALSE);

    return STATUS_UNSUCCESSFUL;
}

static virtio_queue_t *
virtio_dev_modern_vq_setup(virtio_device_t *vdev,
                           uint16_t qidx,
                           virtio_queue_t *vq,
                           void *vring_mem,
                           uint16_t num,
                           uint16_t msi_vector)
{
    PHYSICAL_ADDRESS pa;
    void *vq_addr;
    NTSTATUS status;
    unsigned long ring_size;
    unsigned long queue_size;
    uint16_t off;
    uint16_t i;
    BOOLEAN alloced_mem;

    RPRINTK(DPRTL_PCI,
            ("%s %s: qidx %d vq %p vr %p\n\tnum %d msi_vec %d use_evt %d\n",
             vdev->drv_name, __func__, qidx, vq, vring_mem,
             num, msi_vector, vdev->event_suppression_enabled));
    alloced_mem = FALSE;
    if (vq == NULL) {
        RPRINTK(DPRTL_PCI, ("\tneed to alloc\n"));
        status = virtio_dev_modern_query_vq_alloc(vdev,
                                                  qidx,
                                                  &num,
                                                  &ring_size,
                                                  &queue_size);
        if (!NT_SUCCESS(status)) {
            return NULL;
        }
        VIRTIO_ALLOC(vq, queue_size);
        if (vq == NULL) {
            return NULL;
        }

        VIRTIO_ALLOC_CONTIGUOUS(vring_mem, ring_size);
        if (vring_mem == NULL) {
            VIRTIO_FREE(vq);
            return NULL;
        }
        alloced_mem = TRUE;
    } else {
        virtio_dev_modern_query_vq_size(num,
                                        vdev->packed_ring,
                                        &ring_size,
                                        &queue_size);
    }

    RPRINTK(DPRTL_PCI, ("\tzero out vq (%d) ring (%d)\n",
                        queue_size, ring_size));
    memset(vq, 0, queue_size);
    memset(vring_mem, 0, ring_size);

    RPRINTK(DPRTL_PCI, ("\tvring_init\n"));
    if (vdev->packed_ring) {
        vring_vq_setup_packed(vdev,
                              vq,
                              vring_mem,
                              SMP_CACHE_BYTES,
                              num,
                              qidx,
                              vdev->event_suppression_enabled);
    } else {
        vring_vq_setup_split(vdev,
                             vq,
                             vring_mem,
                             SMP_CACHE_BYTES,
                             num,
                             qidx,
                             vdev->event_suppression_enabled);
    }

    status = virtio_dev_modern_vq_activate(vdev, vq, msi_vector, TRUE);
    if (status == STATUS_SUCCESS) {
        RPRINTK(DPRTL_PCI, ("%s %s: OUT\n", vdev->drv_name, __func__));
        return vq;
    }

    /* Error case, clean up. */
    PRINTK(("%s %s: Error\n", vdev->drv_name, __func__));
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

static void virtio_dev_modern_vq_delete(virtio_queue_t *vq, uint32_t free_mem)
{
    void *ring;
    virtio_device_t *vdev = vq->vdev;

    virtio_iowrite16((ULONG_PTR)&vdev->common->queue_select, vq->qidx);

    if (vdev->msix_used_offset) {
        virtio_iowrite16((ULONG_PTR)&vdev->common->queue_msix_vector,
                         VIRTIO_MSI_NO_VECTOR);
        /* Flush the write out to device */
        virtio_ioread16((ULONG_PTR)&vdev->common->queue_msix_vector);
    }

    if (free_mem && vq) {
        vq_get_ring_mem_desc(vq, &ring, NULL, NULL);
        if (ring != NULL) {
            VIRTIO_FREE_CONTIGUOUS(ring);
        }
        VIRTIO_FREE(vq);
    }
}


static uint8_t
find_next_pci_vendor_capability(PUCHAR pci_config_buf, uint8_t offset)
{
    uint8_t id = 0;
    int iterations = 48;

    PCI_READ_CONFIG_BYTE(pci_config_buf, offset, offset);

    while (iterations-- && offset >= 0x40) {
        offset &= ~3;
        PCI_READ_CONFIG_BYTE(pci_config_buf,
            offset + offsetof(PCI_CAPABILITIES_HEADER, CapabilityID), id);
        if (id == 0xFF) {
            break;
        }
        if (id == PCI_CAPABILITY_ID_VENDOR_SPECIFIC) {
            return offset;
        }
        PCI_READ_CONFIG_BYTE(pci_config_buf,
            offset + offsetof(PCI_CAPABILITIES_HEADER, Next), offset);
    }
    return 0;
}

static uint8_t
find_first_pci_vendor_capability(PUCHAR pci_config_buf)
{
    uint8_t hdr_type, offset;
    uint16_t status;

    PCI_READ_CONFIG_BYTE(pci_config_buf,
        offsetof(PCI_COMMON_HEADER, HeaderType), hdr_type);
    PCI_READ_CONFIG_WORD(pci_config_buf,
        offsetof(PCI_COMMON_HEADER, Status), status);
    if ((status & PCI_STATUS_CAPABILITIES_LIST) == 0) {
        return 0;
    }

    switch (hdr_type & ~PCI_MULTIFUNCTION) {
    case PCI_BRIDGE_TYPE:
        offset = offsetof(PCI_COMMON_HEADER, u.type1.CapabilitiesPtr);
        break;
    case PCI_CARDBUS_BRIDGE_TYPE:
        offset = offsetof(PCI_COMMON_HEADER, u.type2.CapabilitiesPtr);
        break;
    default:
        offset = offsetof(PCI_COMMON_HEADER, u.type0.CapabilitiesPtr);
        break;
    }

    if (offset != 0) {
        offset = find_next_pci_vendor_capability(pci_config_buf, offset);
    }
    return offset;
}

/*
 * Populate Offsets with virtio vendor capability offsets within the
 * PCI config space
 */
static void find_pci_vendor_capabilities(virtio_bar_t *vbar,
                                         PUCHAR pci_config_buf,
                                         int *Offsets,
                                         size_t nOffsets)
{
    uint8_t cfg_type;
    uint8_t bar;
    uint8_t offset;

    offset = find_first_pci_vendor_capability(pci_config_buf);
    while (offset > 0) {
        PCI_READ_CONFIG_BYTE(pci_config_buf,
            offset + offsetof(virtio_pci_cap_t, cfg_type), cfg_type);
        PCI_READ_CONFIG_BYTE(pci_config_buf,
            offset + offsetof(virtio_pci_cap_t, bar), bar);

        if (bar < PCI_TYPE0_ADDRESSES
                && cfg_type < nOffsets
                && vbar[bar].len > 0) {
            Offsets[cfg_type] = offset;
        }

        offset = find_next_pci_vendor_capability(pci_config_buf,
                     offset + offsetof(PCI_CAPABILITIES_HEADER, Next));
    }
}

/* Modern device initialization */
NTSTATUS
virtio_dev_modern_init(virtio_device_t *vdev,
                       virtio_bar_t *vbar,
                       PUCHAR pci_config_buf)
{
    int capabilities[VIRTIO_PCI_CAP_PCI_CFG];
    uint32_t notify_length;
    uint32_t notify_offset;
    uint16_t off;

    vdev->addr = 0;

    RtlZeroMemory(capabilities, sizeof(capabilities));
    find_pci_vendor_capabilities(vbar, pci_config_buf,
                                 capabilities, VIRTIO_PCI_CAP_PCI_CFG);

    /* Check for a common config, if not found use legacy mode */
    if (!capabilities[VIRTIO_PCI_CAP_COMMON_CFG]) {
        RPRINTK(DPRTL_PCI, ("%s %s: device not found\n",
                            vdev->drv_name, __func__));
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    /* Check isr and notify caps, if not found fail */
    if (!capabilities[VIRTIO_PCI_CAP_ISR_CFG]
            || !capabilities[VIRTIO_PCI_CAP_NOTIFY_CFG]) {
        PRINTK(("%s %s: missing capabilities %i/%i/%i\n",
            vdev->drv_name, __func__,
            capabilities[VIRTIO_PCI_CAP_COMMON_CFG],
            capabilities[VIRTIO_PCI_CAP_ISR_CFG],
            capabilities[VIRTIO_PCI_CAP_NOTIFY_CFG]));
        return STATUS_INVALID_PARAMETER;
    }

    /* Map bars according to the capabilities */
    vdev->common = virtio_modern_map_simple_capability(vbar,
        pci_config_buf,
        capabilities[VIRTIO_PCI_CAP_COMMON_CFG],
        sizeof(virtio_pci_common_cfg_t), 4);
    if (!vdev->common) {
        PRINTK(("%s %s: common not found\n", vdev->drv_name, __func__));
        return STATUS_INVALID_PARAMETER;
    }
    RPRINTK(DPRTL_PCI, ("%s %s: vdev->common 0x%p, status %d\n",
                        vdev->drv_name, __func__, vdev->common,
                        vdev->common->device_status));

    vdev->isr = virtio_modern_map_simple_capability(vbar,
        pci_config_buf,
        capabilities[VIRTIO_PCI_CAP_ISR_CFG],
        sizeof(uint8_t), 1);
    if (!vdev->isr) {
        PRINTK(("%s %s: isr not found\n", vdev->drv_name, __func__));
        return STATUS_INVALID_PARAMETER;
    }
    RPRINTK(DPRTL_PCI, ("%s %s: vdev->isr 0x%p\n",
                        vdev->drv_name, __func__, vdev->isr));

    /* Read notify_off_multiplier from config space. */
    PCI_READ_CONFIG_DWORD(pci_config_buf,
        capabilities[VIRTIO_PCI_CAP_NOTIFY_CFG]
            + offsetof(virtio_pci_notify_cap_t, notify_off_multiplier),
        vdev->notify_offset_multiplier);

    /* Read notify length and offset from config space. */
    PCI_READ_CONFIG_DWORD(pci_config_buf,
        capabilities[VIRTIO_PCI_CAP_NOTIFY_CFG]
            + offsetof(virtio_pci_notify_cap_t, cap.length),
        notify_length);
    PCI_READ_CONFIG_DWORD(pci_config_buf,
        capabilities[VIRTIO_PCI_CAP_NOTIFY_CFG]
            + offsetof(virtio_pci_notify_cap_t, cap.offset),
        notify_offset);

    /*
     * Map the notify capability if it's small enough.
     * Otherwise, map each VQ individually later.
     */
    if (notify_length + (notify_offset % PAGE_SIZE) <= PAGE_SIZE) {
        vdev->notify_base = virtio_modern_map_capability(vbar,
            pci_config_buf,
            capabilities[VIRTIO_PCI_CAP_NOTIFY_CFG], 2, 2,
            0, notify_length,
            &vdev->notify_len);
        if (!vdev->notify_base) {
            PRINTK(("%s %s: notify_base not found\n",
                    vdev->drv_name, __func__));
            return STATUS_INVALID_PARAMETER;
        }
        RPRINTK(DPRTL_PCI, ("%s %s: vdev->notify_base 0x%p\n",
                            vdev->drv_name, __func__, vdev->notify_base));
    } else {
        vdev->notify_base = NULL;
        vdev->notify_map_cap = capabilities[VIRTIO_PCI_CAP_NOTIFY_CFG];

        off = virtio_ioread16((ULONG_PTR)&vdev->common->queue_notify_off);
        vdev->notification_addr = virtio_modern_map_capability(vbar,
            pci_config_buf,
            vdev->notify_map_cap,
            2,
            2,
            off * vdev->notify_offset_multiplier,
            2,
            NULL);
    }

    /* Map the device config capability, the PAGE_SIZE size is a guess */
    if (capabilities[VIRTIO_PCI_CAP_DEVICE_CFG]) {
        vdev->config = virtio_modern_map_capability(vbar,
            pci_config_buf,
            capabilities[VIRTIO_PCI_CAP_DEVICE_CFG], 0, 4,
            0, PAGE_SIZE,
            &vdev->config_len);
        if (!vdev->config) {
            PRINTK(("%s %s: config not found\n", vdev->drv_name, __func__));
            return STATUS_INVALID_PARAMETER;
        }
        RPRINTK(DPRTL_PCI, ("%s %s: vdev->config 0x%p\n",
                            vdev->drv_name, __func__, vdev->config));
    }

    virtio_pci_device_ops.get_config = virtio_dev_modern_get_config;
    virtio_pci_device_ops.set_config = virtio_dev_modern_set_config;
    virtio_pci_device_ops.get_config_generation =
        virtio_dev_modern_get_generation;
    virtio_pci_device_ops.get_status = virtio_dev_modern_get_status;
    virtio_pci_device_ops.set_status = virtio_dev_modern_set_status;
    virtio_pci_device_ops.reset = virtio_dev_modern_reset;
    virtio_pci_device_ops.get_features = virtio_dev_modern_get_features;
    virtio_pci_device_ops.set_features = virtio_dev_modern_set_features;
    virtio_pci_device_ops.set_config_vector =
        virtio_dev_modern_set_config_vector;
    virtio_pci_device_ops.set_queue_vector = virtio_dev_modern_set_queue_vector;
    virtio_pci_device_ops.query_queue_alloc = virtio_dev_modern_query_vq_alloc;
    virtio_pci_device_ops.setup_queue = virtio_dev_modern_vq_setup;
    virtio_pci_device_ops.delete_queue = virtio_dev_modern_vq_delete;
    virtio_pci_device_ops.activate_queue = virtio_dev_modern_vq_activate;
    vdev->dev_op = &virtio_pci_device_ops;

    return STATUS_SUCCESS;
}
