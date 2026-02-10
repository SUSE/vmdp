/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2026 SUSE LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "vrng.h"
#include <win_maddr.h>

PKINTERRUPT DriverInterruptObj;

NTSTATUS
wdm_device_virtio_init(IN FDO_DEVICE_EXTENSION *fdx)
{
    uint64_t guest_features;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    guest_features = 0;


    fdx->host_features = VIRTIO_DEVICE_GET_FEATURES(&fdx->vdev);
    PRINTK(("%s: host features 0x%llx\n",
            VDEV_DRIVER_NAME, fdx->host_features));

    if (virtio_is_feature_enabled(fdx->host_features, VIRTIO_F_VERSION_1)) {
        virtio_feature_enable(guest_features, VIRTIO_F_VERSION_1);
    }
    if (virtio_is_feature_enabled(fdx->host_features, VIRTIO_F_ANY_LAYOUT)) {
        virtio_feature_enable(guest_features, VIRTIO_F_ANY_LAYOUT);
    }
    PRINTK(("%s: setting guest features 0x%llx\n",
            VDEV_DRIVER_NAME, guest_features));
    virtio_device_set_guest_feature_list(&fdx->vdev, guest_features);

    RPRINTK(DPRTL_INIT, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return STATUS_SUCCESS;
}

static NTSTATUS
vrng_q_init(IN FDO_DEVICE_EXTENSION *fdx)
{
    NTSTATUS status;
    USHORT queues_vector;

    RPRINTK(DPRTL_INIT, ("--> %s\n", __func__));

    queues_vector = fdx->int_info[0].message_signaled ? 0 :
        VIRTIO_MSI_NO_VECTOR;

    if (!fdx->vq) {
        fdx->vq = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                            0,
                                            NULL,
                                            NULL,
                                            0,
                                            queues_vector);
        RPRINTK(DPRTL_INIT, ("  vq %p\n", fdx->vq));
    } else {
        VIRTIO_DEVICE_QUEUE_ACTIVATE(&fdx->vdev,
                                     fdx->vq,
                                     queues_vector,
                                     FALSE);
    }

    if (fdx->vq != NULL) {
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_UNSUCCESSFUL;
    }

    RPRINTK(DPRTL_INIT, ("<-- %s: status %x\n", __func__, status));
    return status;
}

NTSTATUS
wdm_device_powerup(IN FDO_DEVICE_EXTENSION *fdx)
{
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
#ifdef DBG
    dbg_print_mask |= DPRTL_DPC;
#endif

    wdm_finish_init(fdx);

    status = vrng_q_init(fdx);
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s %s: failed 0%x\n",
            VDEV_DRIVER_NAME, __func__, status));
        return status;
    }
    vq_start_interrupts(fdx->vq);

    virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER_OK);

#ifdef DBG
    dbg_print_mask &= ~DPRTL_DPC;
#endif
    PRINTK(("%s: powered on\n", VDEV_DRIVER_NAME));
    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return STATUS_SUCCESS;
}

static void
vrng_return_vq_entries(FDO_DEVICE_EXTENSION *fdx)
{
    read_buffer_entry_t *entry;
    PIO_STACK_LOCATION  stack;
    KIRQL irql;

    RPRINTK(DPRTL_TRC, ("--> %s\n", __func__));
    fdx->read_buffers_list.Next = NULL;
    entry = (read_buffer_entry_t *)vq_detach_unused_buf(fdx->vq);
    while (entry != NULL) {
        if (entry->request != NULL) {
            RPRINTK(DPRTL_TRC, ("%s: Canceling entry %p request %p\n",
                    __func__, entry, entry->request));
            stack = IoGetCurrentIrpStackLocation(entry->request);
            entry->request->IoStatus.Information = 0;
            entry->request->IoStatus.Status = STATUS_CANCELLED;
            IoAcquireCancelSpinLock(&irql);
            IoSetCancelRoutine(entry->request, NULL);
            IoReleaseCancelSpinLock(irql);
            vrng_complete_request(entry->request, IO_NO_INCREMENT);
        }
        ExFreePoolWithTag(entry->buffer, VRNG_POOL_TAG);
        ExFreePoolWithTag(entry, VRNG_POOL_TAG);
        entry = (read_buffer_entry_t *)vq_detach_unused_buf(fdx->vq);
    }
    RPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
}

static void
vrng_delete_queue(virtio_queue_t **ppvq)
{
    DPRINTK(DPRTL_TRC, ("--> %s\n", __func__));

    if (*ppvq) {
        VIRTIO_DEVICE_QUEUE_DELETE((*ppvq)->vdev, *ppvq, TRUE);
        *ppvq = NULL;
    }

    DPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
}

static void
vrng_shutdown_queues(FDO_DEVICE_EXTENSION *fdx)
{
    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    virtio_device_remove_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER_OK);

    RPRINTK(DPRTL_ON, (" is_hos_multiport\n"));
    if (fdx->vq) {
        RPRINTK(DPRTL_ON, (" delete queue ivq %p\n", fdx->vq));
        vrng_delete_queue(&fdx->vq);
    }

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

void
wdm_device_powerdown(FDO_DEVICE_EXTENSION *fdx)
{
    KLOCK_QUEUE_HANDLE lh;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    KeAcquireInStackQueuedSpinLock(&fdx->vq_lock, &lh);
    if (fdx->vq) {
        vq_stop_interrupts(fdx->vq);
        vrng_return_vq_entries(fdx);

    }
    vrng_shutdown_queues(fdx);
    KeReleaseInStackQueuedSpinLock(&lh);

    PRINTK(("%s: powered down\n", VDEV_DRIVER_NAME));
    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
}

NTSTATUS
vrng_fdo_pnp(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;
    PIO_STACK_LOCATION stack;
    PCM_PARTIAL_RESOURCE_LIST raw, translated;

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IRP_MJ_PNP == stack->MajorFunction);

    switch (stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s: IRP_MN_START_DEVICE.\n", __func__));
        status = wdm_send_irp_synchronous(fdx->LowerDevice, Irp);

        if  (NT_SUCCESS(status)) {
            raw = &stack->Parameters.StartDevice
                .AllocatedResources->List[0].PartialResourceList;

            translated = &stack->Parameters.StartDevice
                .AllocatedResourcesTranslated->List[0].PartialResourceList;

            wdm_start_device(DeviceObject, raw, translated);
        }

        Irp->IoStatus.Status = status;
        vrng_complete_request(Irp, IO_NO_INCREMENT);

        RPRINTK(DPRTL_ON, ("<-- %s: IRP_MN_START_DEVICE return status %x\n",
                           __func__, status));
        return status;

    case IRP_MN_QUERY_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_QUERY_STOP_DEVICE.\n", __func__));
        fdx->pnpstate = StopPending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        RPRINTK(DPRTL_ON,
            ("%s: IRP_MN_CANCEL_STOP_DEVICE.\n", __func__));
        if (fdx->pnpstate == StopPending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s: IRP_MN_STOP_DEVICE.\n", __func__));
        /* TODO: Irps and resources */

        wdm_fdo_stop_device(DeviceObject);

        fdx->pnpstate = Stopped;
        Irp->IoStatus.Status = STATUS_SUCCESS;

        RPRINTK(DPRTL_ON, ("<-- %s: IRP_MN_STOP_DEVICE.\n", __func__));
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_QUERY_REMOVE_DEVICE.\n", __func__));
        fdx->pnpstate = RemovePending;
        Irp->IoStatus.Status = status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_CANCEL_REMOVE_DEVICE.\n", __func__));
        if (fdx->pnpstate == RemovePending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_SURPRISE_REMOVAL.\n", __func__));
        fdx->pnpstate = SurpriseRemovePending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s: IRP_MN_REMOVE_DEVICE.\n", __func__));

        wdm_fdo_stop_device(DeviceObject);
        wdm_fdo_remove_device(DeviceObject);
        fdx->pnpstate = Deleted;

        RPRINTK(DPRTL_ON, ("<-- %s: IRP_MN_REMOVE_DEVICE.\n", __func__));

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fdx->LowerDevice, Irp);

        RPRINTK(DPRTL_ON, ("%s: irql %d, dev %p.\n", __func__,
            KeGetCurrentIrql(), DeviceObject));

        /* Seems we crash if we try to print from here down. */
        IoDetachDevice(fdx->LowerDevice);

        /*
         * The DeviceObject, aka gfdo, should be able to be set to NULL
         * eventhough there is an interaction between xnebus and xenblk.
         */
        IoDeleteDevice(DeviceObject);

        return status;

    default:
        RPRINTK(DPRTL_PNP,
            ("%s: default irp %x.\n", __func__, stack->MinorFunction));
        break;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(fdx->LowerDevice, Irp);

    return status;
}
