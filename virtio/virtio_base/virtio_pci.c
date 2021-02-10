/*
 * Copyright IBM Corp. 2007
 * Copyright Red Hat, Inc. 2014
 *
 * Authors:
 *  Anthony Liguori  <aliguori@us.ibm.com>
 *  Rusty Russell <rusty@rustcorp.com.au>
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * Copyright 2011-2012 Novell, Inc.
 * Copyright 2012-2021 SUSE LLC
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
#include <initguid.h>
#include <wdmguid.h>
#include <virtio_dbg_print.h>
#include <virtio_pci.h>


uint8_t
virtio_ioread8(ULONG_PTR ulRegister)
{
    if (ulRegister & ~PORT_MASK) {
        return READ_REGISTER_UCHAR((PUCHAR)ulRegister);
    } else {
        return READ_PORT_UCHAR((PUCHAR)ulRegister);
    }
}

uint16_t
virtio_ioread16(ULONG_PTR ulRegister)
{
    if (ulRegister & ~PORT_MASK) {
        return READ_REGISTER_USHORT((PUSHORT)ulRegister);
    } else {
        return READ_PORT_USHORT((PSHORT)ulRegister);
    }
}

uint32_t
virtio_ioread32(ULONG_PTR ulRegister)
{
    if (ulRegister & ~PORT_MASK) {
        return READ_REGISTER_ULONG((PULONG)ulRegister);
    } else {
        return READ_PORT_ULONG((PULONG)ulRegister);
    }
}

void
virtio_iowrite8(ULONG_PTR ulRegister, uint8_t val)
{
    if (ulRegister & ~PORT_MASK) {
        WRITE_REGISTER_UCHAR((PUCHAR)ulRegister, val);
    } else {
        WRITE_PORT_UCHAR((PUCHAR)ulRegister, val);
    }
}

void
virtio_iowrite16(ULONG_PTR ulRegister, uint16_t val)
{
    if (ulRegister & ~PORT_MASK) {
        WRITE_REGISTER_USHORT((PUSHORT)ulRegister, val);
    } else {
        WRITE_PORT_USHORT((PSHORT)ulRegister, val);
    }
}

void
virtio_iowrite32(ULONG_PTR ulRegister, uint32_t val)
{
    if (ulRegister & ~PORT_MASK) {
        WRITE_REGISTER_ULONG((PULONG)ulRegister, val);
    } else {
        WRITE_PORT_ULONG((PULONG)ulRegister, val);
    }
}

BOOLEAN
virtio_device_has_host_feature(virtio_device_t *vdev, uint64_t feature)
{
    RPRINTK(DPRTL_PCI, ("%s %s: feature %llx\n",
                        vdev->drv_name, __func__, feature));
    return !!(VIRTIO_DEVICE_GET_FEATURES(vdev) & (1ULL << feature));
}

NTSTATUS
virtio_device_set_guest_feature_list(virtio_device_t *vdev, uint64_t list)
{
    NTSTATUS status;
    uint8_t dev_status;

    RPRINTK(DPRTL_PCI, ("%s %s: features %llx\n",
                        vdev->drv_name, __func__, list));

    vdev->event_suppression_enabled = virtio_is_feature_enabled(
        list, VIRTIO_RING_F_EVENT_IDX);

    vdev->packed_ring = virtio_is_feature_enabled(list, VIRTIO_F_RING_PACKED);

    status = VIRTIO_DEVICE_SET_FEATURES(vdev, list);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (!virtio_is_feature_enabled(list, VIRTIO_F_VERSION_1)) {
        return status;
    }

    virtio_device_add_status(vdev, VIRTIO_CONFIG_S_FEATURES_OK);
    dev_status = VIRTIO_DEVICE_GET_STATUS(vdev);
    if (!(dev_status & VIRTIO_CONFIG_S_FEATURES_OK)) {
        PRINTK(("%s %s: failed to set feature list 0x%llx, status 0x%x\n",
                vdev->drv_name, __func__, list, dev_status));
        status = STATUS_INVALID_PARAMETER;
    }
    return status;
}

void
virtio_device_reset_features(virtio_device_t *vdev)
{
    /* 0 status means a reset. */
    RPRINTK(DPRTL_PCI, ("%s %s:\n", vdev->drv_name, __func__));
    VIRTIO_DEVICE_SET_FEATURES(vdev, 0);
}

void
virtio_device_add_status(virtio_device_t *vdev, uint8_t status)
{
    RPRINTK(DPRTL_PCI, ("%s %s: status %x\n",
                        vdev->drv_name, __func__, status));
    VIRTIO_DEVICE_SET_STATUS(vdev, VIRTIO_DEVICE_GET_STATUS(vdev) | status);
}

void
virtio_device_remove_status(virtio_device_t *vdev, uint8_t status)
{
    RPRINTK(DPRTL_PCI, ("%s %s: status %x\n",
                        vdev->drv_name, __func__, status));
    VIRTIO_DEVICE_SET_STATUS(vdev, VIRTIO_DEVICE_GET_STATUS(vdev) & (~status));
}

/*
 * A small wrapper to also acknowledge the interrupt when it's handled.
 * I really need an EIO hook for the vring so I can ack the interrupt once we
 * know that we'll be handling the IRQ but before we invoke the callback since
 * the callback may notify the host which results in the host attempting to
 * raise an interrupt that we would then mask once we acknowledged the
 * interrupt.
 * changed: status is a bitmap rather than boolean value
 */
ULONG
virtio_device_read_isr_status(virtio_device_t *vdev)
{
    ULONG status;

    DPRINTK(DPRTL_INT, ("%s %s: read port %p\n",
                        vdev->drv_name, __func__, vdev->isr));
    status = virtio_ioread8((ULONG_PTR)vdev->isr);
    return status;
}

int
virtio_get_bar_index(PPCI_COMMON_HEADER p_header, PHYSICAL_ADDRESS pa)
{
    PHYSICAL_ADDRESS BAR;
    int iBar;
    int i;

    for (i = 0; i < PCI_TYPE0_ADDRESSES; i++) {
        BAR.LowPart = p_header->u.type0.BaseAddresses[i];

        iBar = i;
        if (BAR.LowPart & PCI_ADDRESS_IO_SPACE) {
            /* I/O space */
            BAR.LowPart &= PCI_ADDRESS_IO_ADDRESS_MASK;
            BAR.HighPart = 0;
        } else if ((BAR.LowPart & PCI_ADDRESS_MEMORY_TYPE_MASK)
                   == PCI_TYPE_64BIT) {
            /* memory space 64-bit */
            BAR.LowPart &= PCI_ADDRESS_MEMORY_ADDRESS_MASK;
            BAR.HighPart = p_header->u.type0.BaseAddresses[++i];
        } else {
            /* memory space 32-bit */
            BAR.LowPart &= PCI_ADDRESS_MEMORY_ADDRESS_MASK;
            BAR.HighPart = 0;
        }

        if (BAR.QuadPart == pa.QuadPart) {
            return iBar;
        }
    }
    return -1;
}

/* This routine gets the bus interface standard information from the PDO. */
static NTSTATUS
virtio_get_pci_bus_interface_standard(PDEVICE_OBJECT device_object,
    PBUS_INTERFACE_STANDARD bus_interface_standard)
{
    KEVENT event;
    NTSTATUS status;
    PIRP irp;
    IO_STATUS_BLOCK io_status_block;
    PIO_STACK_LOCATION irp_stack;
    PDEVICE_OBJECT target_object;

    RPRINTK(DPRTL_PCI, ("%s entered.\n", __func__));
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    target_object = IoGetAttachedDeviceReference(device_object);
    irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       target_object,
                                       NULL,
                                       0,
                                       NULL,
                                       &event,
                                       &io_status_block);
    if (irp != NULL) {
        irp_stack = IoGetNextIrpStackLocation(irp);
        irp_stack->MinorFunction = IRP_MN_QUERY_INTERFACE;
        irp_stack->Parameters.QueryInterface.InterfaceType =
            (LPGUID)&GUID_BUS_INTERFACE_STANDARD;
        irp_stack->Parameters.QueryInterface.Size =
            sizeof(BUS_INTERFACE_STANDARD);
        irp_stack->Parameters.QueryInterface.Version = 1;
        irp_stack->Parameters.QueryInterface.Interface =
            (PINTERFACE)bus_interface_standard;
        irp_stack->Parameters.QueryInterface.InterfaceSpecificData = NULL;

        /*
         * Initialize the status to error in case the bus driver does not
         * set it correctly.
         */
        irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        status = IoCallDriver(target_object, irp);
        if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
            status = io_status_block.Status;
        }
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Done with reference */
    ObDereferenceObject(target_object);
    RPRINTK(DPRTL_PCI, ("%s: out %x\n", __func__, status));
    return status;
}

NTSTATUS
virtio_get_pci_config_space(PDEVICE_OBJECT device_object,
                            uint8_t *pci_config_space,
                            ULONG len)
{
    BUS_INTERFACE_STANDARD bus_interface_standard;
    NTSTATUS status;
    ULONG bytes;

    status = virtio_get_pci_bus_interface_standard(device_object,
                                                   &bus_interface_standard);
    if (NT_SUCCESS(status)) {
        bytes = bus_interface_standard.GetBusData(
                bus_interface_standard.Context,
                PCI_WHICHSPACE_CONFIG,
                pci_config_space,
                0,
                len);
        bus_interface_standard.InterfaceDereference(
                (PVOID)bus_interface_standard.Context);
        if (bytes == 0) {
            return STATUS_UNSUCCESSFUL;
        }
    }
    return status;
}

void
virtio_sleep(unsigned int msecs)
{
    LARGE_INTEGER delay;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() <= APC_LEVEL) {
        delay.QuadPart = Int32x32To64(msecs, -10000);
        status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    if (!NT_SUCCESS(status)) {
        /* fall back to busy wait if we're not allowed to sleep */
        KeStallExecutionProcessor(1000 * msecs);
    }
}

NTSTATUS
virtio_device_init(virtio_device_t *vdev,
                   virtio_bar_t *vbar,
                   PUCHAR pci_config_buf,
                   char *drv_name,
                   BOOLEAN msi_enabled)
{
    NTSTATUS status;

    memset(vdev, 0, sizeof(virtio_device_t));

    vdev->drv_name = drv_name;
    vdev->msix_used_offset = msi_enabled ? VIRTIO_PCI_CONFIG_MSI_OFFSET : 0;

    RPRINTK(DPRTL_ON, ("%s %s: try modern init\n", vdev->drv_name, __func__));
    status = virtio_dev_modern_init(vdev, vbar, pci_config_buf);
    if (status == STATUS_DEVICE_NOT_CONNECTED) {
        /* fall back to legacy virtio device */
        PRINTK(("%s %s: fall back to legacy init\n", vdev->drv_name, __func__));
        status = virtio_dev_legacy_init(vdev, vbar, pci_config_buf);
    }

    if (NT_SUCCESS(status)) {
        /* Always start by resetting the device */
        VIRTIO_DEVICE_RESET(vdev);

        /* Acknowledge that we've seen the device. */
        virtio_device_add_status(vdev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

        /* If we are here, we must have found a driver for the device */
        virtio_device_add_status(vdev, VIRTIO_CONFIG_S_DRIVER);
    }
    return status;
}
