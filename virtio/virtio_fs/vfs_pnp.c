/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2022-2026 SUSE LLC
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

#include "vfs.h"
#include <win_maddr.h>

PKINTERRUPT DriverInterruptObj;

NTSTATUS
wdm_device_virtio_init(IN FDO_DEVICE_EXTENSION *fdx)
{
    uint64_t guest_features;
    uint64_t host_features;
    uint8_t dev_status;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    guest_features = 0;


    host_features = VIRTIO_DEVICE_GET_FEATURES(&fdx->vdev);
    PRINTK(("%s: host features 0x%llx\n",
            VDEV_DRIVER_NAME, host_features));

    if (virtio_is_feature_enabled(host_features, VIRTIO_F_VERSION_1)) {
        virtio_feature_enable(guest_features, VIRTIO_F_VERSION_1);
    }
    if (virtio_is_feature_enabled(host_features, VIRTIO_F_ANY_LAYOUT)) {
        virtio_feature_enable(guest_features, VIRTIO_F_ANY_LAYOUT);
    }
    if (virtio_is_feature_enabled(host_features, VIRTIO_RING_F_EVENT_IDX)) {
        virtio_feature_enable(guest_features, VIRTIO_RING_F_EVENT_IDX);
    }
    if (virtio_is_feature_enabled(host_features, VIRTIO_RING_F_INDIRECT_DESC)) {
        virtio_feature_enable(guest_features, VIRTIO_RING_F_INDIRECT_DESC);
        fdx->use_indirect = TRUE;
    } else {
        fdx->use_indirect = FALSE;
    }

    /* make sure that we always follow the status bit-setting protocol */
    dev_status = VIRTIO_DEVICE_GET_STATUS(&fdx->vdev);
    if (!(dev_status & VIRTIO_CONFIG_S_ACKNOWLEDGE)) {
        virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_ACKNOWLEDGE);
    }
    if (!(dev_status & VIRTIO_CONFIG_S_DRIVER)) {
        virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER);
    }

    PRINTK(("%s: setting guest features 0x%llx\n",
            VDEV_DRIVER_NAME, guest_features));
    virtio_device_set_guest_feature_list(&fdx->vdev, guest_features);

    VIRTIO_DEVICE_GET_CONFIG(&fdx->vdev,
        FIELD_OFFSET(virtio_fs_config_t, request_queues),
        &fdx->num_queues,
        sizeof(fdx->num_queues));
    PRINTK(("%s: request queues %d num_queues %d\n",
            VDEV_DRIVER_NAME,
            fdx->num_queues,
            VQ_TYPE_MAX));

    fdx->num_queues = VQ_TYPE_MAX ;

    RPRINTK(DPRTL_INIT, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return STATUS_SUCCESS;
}

static BOOLEAN
vfs_alloc_indirect_area(FDO_DEVICE_EXTENSION *fdx)
{
    fdx->indirect_va = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                     VFS_INDIRECT_AREA_PAGES * PAGE_SIZE,
                                     VFS_POOL_TAG);
    if (fdx->indirect_va == NULL) {
        return FALSE;
    }

    fdx->indirect_pa = MmGetPhysicalAddress(fdx->indirect_va);

    return TRUE;
}

static NTSTATUS
vfs_q_init(IN FDO_DEVICE_EXTENSION *fdx)
{
    NTSTATUS status;
    uint32_t i;
    USHORT queues_vector;

    RPRINTK(DPRTL_INIT, ("--> %s\n", __func__));

    status = STATUS_SUCCESS;
    for (i = 0; i < fdx->num_queues; i++) {
        queues_vector = fdx->int_info[i].message_signaled ? (USHORT)i :
            (USHORT)VIRTIO_MSI_NO_VECTOR;
        if (fdx->vqs[i] == NULL) {
            fdx->vqs[i] = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                                    (uint16_t)i,
                                                    NULL,
                                                    NULL,
                                                    0,
                                                    queues_vector);
            RPRINTK(DPRTL_INIT, ("  vqs[%d] %p\n", i, fdx->vqs[i]));
        } else {
            VIRTIO_DEVICE_QUEUE_ACTIVATE(&fdx->vdev,
                                         fdx->vqs[i],
                                         queues_vector,
                                         FALSE);
        }
    }

    if (fdx->vqs[fdx->num_queues - 1] == NULL) {
        status = STATUS_NOT_FOUND;
    }

    RPRINTK(DPRTL_INIT, ("<-- %s: status %x\n", __func__, status));
    return status;
}

NTSTATUS
wdm_device_powerup(IN FDO_DEVICE_EXTENSION *fdx)
{
    NTSTATUS status;
    uint32_t i;
#ifdef DBG
    uint32_t starting_dbg_mask;

    starting_dbg_mask = dbg_print_mask;
    dbg_print_mask |= DPRTL_DPC;
#endif

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    fdx->vqs = (virtio_queue_t **)EX_ALLOC_POOL(
       VPOOL_NON_PAGED,
       fdx->num_queues * sizeof(virtio_queue_t *),
       VFS_POOL_TAG);

    if (fdx->vqs == NULL) {
        PRINTK(("%s: EX_ALLOC_POOL for vqs failed\n", __func__));
        wdm_unmap_io_space(fdx);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(fdx->vqs, 0, fdx->num_queues * sizeof(virtio_queue_t *));

    fdx->qlock = (KSPIN_LOCK *)EX_ALLOC_POOL(
       VPOOL_NON_PAGED,
       fdx->num_queues * sizeof(KSPIN_LOCK),
       VFS_POOL_TAG);

    if (fdx->qlock == NULL) {
        PRINTK(("%s: EX_ALLOC_POOL for qlock failed\n", __func__));
        wdm_unmap_io_space(fdx);
        ExFreePoolWithTag(fdx->vqs, VFS_POOL_TAG);
        fdx->vqs = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(fdx->qlock, 0, fdx->num_queues * sizeof(KSPIN_LOCK));
    for (i = 0; i < fdx->num_queues; i++) {
        KeInitializeSpinLock(&fdx->qlock[i]);
    }
    KeInitializeSpinLock(&fdx->req_lock);

    if (fdx->use_indirect) {
        if (vfs_alloc_indirect_area(fdx) == FALSE) {
            PRINTK(("%s %s : Failed to allocate indirect area\n",
                    VDEV_DRIVER_NAME, __func__));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    wdm_finish_init(fdx);

    status = vfs_q_init(fdx);
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s %s: failed 0%x\n",
            VDEV_DRIVER_NAME, __func__, status));
        return status;
    }
    for (i = 0; i < fdx->num_queues; i++) {
        vq_start_interrupts(fdx->vqs[i]);
    }

    virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER_OK);

#ifdef DBG
    dbg_print_mask = starting_dbg_mask;
#endif
    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return STATUS_SUCCESS;
}

static void
vfs_return_vq_entries(virtio_queue_t *vq)
{
    virtio_fs_request_t *entry;
    KIRQL irql;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    entry = (virtio_fs_request_t *)vq_detach_unused_buf(vq);
    while (entry != NULL) {
        if (entry->irp != NULL) {
            RPRINTK(DPRTL_ON, ("    Canceling request %p\n",
                    __func__, entry->irp));
            entry->irp->IoStatus.Information = 0;
            entry->irp->IoStatus.Status = STATUS_CANCELLED;
            IoAcquireCancelSpinLock(&irql);
            IoSetCancelRoutine(entry->irp, NULL);
            IoReleaseCancelSpinLock(irql);
            vfs_complete_request(entry->irp, IO_NO_INCREMENT);
        }
        vfs_free_request(entry);
        entry = (virtio_fs_request_t *)vq_detach_unused_buf(vq);
    }
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

static void
vfs_delete_queue(virtio_queue_t **ppvq)
{
    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    if (*ppvq) {
        VIRTIO_DEVICE_QUEUE_DELETE((*ppvq)->vdev, *ppvq, TRUE);
        *ppvq = NULL;
    }

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

static void
vfs_shutdown_queues(FDO_DEVICE_EXTENSION *fdx)
{
    KLOCK_QUEUE_HANDLE lh;
    unsigned int i;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    virtio_device_remove_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER_OK);
    VIRTIO_DEVICE_RESET(&fdx->vdev);

    for (i = 0; i < fdx->num_queues; i++) {
        KeAcquireInStackQueuedSpinLock(&fdx->qlock[i], &lh);
        RPRINTK(DPRTL_ON, (" delete queue ivq %p\n", fdx->vqs[i]));
        vfs_delete_queue(&fdx->vqs[i]);
        KeReleaseInStackQueuedSpinLock(&lh);
    }

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

void
wdm_device_powerdown(FDO_DEVICE_EXTENSION *fdx)
{
    KLOCK_QUEUE_HANDLE lh;
    uint32_t i;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    if (fdx->vqs == NULL) {
        RPRINTK(DPRTL_ON, ("<-- %s %s vqa is null\n",
                           VDEV_DRIVER_NAME, __func__));
        return;
    }
    if (fdx->qlock == NULL) {
        RPRINTK(DPRTL_ON, ("<-- %s %s qlock is null\n",
                           VDEV_DRIVER_NAME, __func__));
        return;
    }

    for (i = 0; i < fdx->num_queues; i++) {
        KeAcquireInStackQueuedSpinLock(&fdx->qlock[i], &lh);
        if (fdx->vqs[i] != NULL) {
            vq_stop_interrupts(fdx->vqs[i]);
            fdx->request_list.Next = NULL;
            vfs_return_vq_entries(fdx->vqs[i]);

        }
        KeReleaseInStackQueuedSpinLock(&lh);
    }

    vfs_shutdown_queues(fdx);

    if (fdx->use_indirect && fdx->indirect_va != NULL) {
        RPRINTK(DPRTL_ON, ("--- Free indirect space\n"));
        ExFreePoolWithTag(fdx->indirect_va, VFS_POOL_TAG);
        fdx->indirect_va = NULL;
    }

    ExFreePoolWithTag(fdx->vqs, VFS_POOL_TAG);
    fdx->vqs = NULL;

    ExFreePoolWithTag(fdx->qlock, VFS_POOL_TAG);
    fdx->qlock = NULL;

    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
}

static void
vfs_complete_held_requests(PDEVICE_OBJECT DeviceObject,
                           FDO_DEVICE_EXTENSION *fdx)
{
    virtio_fs_hold_request_t *hold_irp;
    KLOCK_QUEUE_HANDLE lh;

    while (!IsListEmpty(&fdx->hold_list)) {
        KeAcquireInStackQueuedSpinLock(&fdx->req_lock, &lh);
        hold_irp = (virtio_fs_hold_request_t *)RemoveHeadList(
            &fdx->hold_list);
        KeReleaseInStackQueuedSpinLock(&lh);
        RPRINTK(DPRTL_UNEXPD, ("  ** complete held requests - irp %p\n",
                               hold_irp->irp));
        vfs_dispatch_device_control(DeviceObject, hold_irp->irp);
        ExFreePoolWithTag(hold_irp, VFS_POOL_TAG);
    }
}

static void
vfs_free_held_requests(FDO_DEVICE_EXTENSION *fdx)
{
    virtio_fs_hold_request_t *hold_irp;
    KLOCK_QUEUE_HANDLE lh;
    KIRQL irql;

    while (!IsListEmpty(&fdx->hold_list)) {
        KeAcquireInStackQueuedSpinLock(&fdx->req_lock, &lh);
        hold_irp = (virtio_fs_hold_request_t *)RemoveHeadList(
            &fdx->hold_list);
        KeReleaseInStackQueuedSpinLock(&lh);
        RPRINTK(DPRTL_UNEXPD, ("  ** free held requests - irp %p\n",
                               hold_irp->irp));
        hold_irp->irp->IoStatus.Information = 0;
        hold_irp->irp->IoStatus.Status = STATUS_CANCELLED;
        IoAcquireCancelSpinLock(&irql);
        IoSetCancelRoutine(hold_irp->irp, NULL);
        IoReleaseCancelSpinLock(irql);
        vfs_complete_request(hold_irp->irp, IO_NO_INCREMENT);
        ExFreePoolWithTag(hold_irp, VFS_POOL_TAG);
    }
}

static void
vfs_remove_device(PDEVICE_OBJECT DeviceObject, FDO_DEVICE_EXTENSION *fdx)
{
    wdm_fdo_stop_device(DeviceObject);
    wdm_fdo_remove_device(DeviceObject);
    wdm_unmap_io_space(fdx);
    vfs_free_held_requests(fdx);

}

NTSTATUS
vfs_fdo_pnp(
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
        RPRINTK(DPRTL_ON, ("--> %s: IRP_MN_START_DEVICE - Irql %d\n", __func__,
                           KeGetCurrentIrql()));
        status = wdm_send_irp_synchronous(fdx->LowerDevice, Irp);

        if  (NT_SUCCESS(status)) {
            raw = &stack->Parameters.StartDevice
                .AllocatedResources->List[0].PartialResourceList;

            translated = &stack->Parameters.StartDevice
                .AllocatedResourcesTranslated->List[0].PartialResourceList;

            wdm_start_device(DeviceObject, raw, translated);
        }

        Irp->IoStatus.Status = status;
        vfs_complete_request(Irp, IO_NO_INCREMENT);

        vfs_complete_held_requests(DeviceObject, fdx);

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
        vfs_complete_held_requests(DeviceObject, fdx);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s: IRP_MN_STOP_DEVICE.\n", __func__));

        fdx->pnpstate = Stopped;
        wdm_fdo_stop_device(DeviceObject);

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
        vfs_complete_held_requests(DeviceObject, fdx);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_SURPRISE_REMOVAL.\n", __func__));
        fdx->pnpstate = SurpriseRemovePending;
        vfs_remove_device(DeviceObject, fdx);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s: IRP_MN_REMOVE_DEVICE.\n", __func__));
        if (fdx->pnpstate != SurpriseRemovePending) {
            fdx->pnpstate = Deleted;
            vfs_remove_device(DeviceObject, fdx);
        } else {
            fdx->pnpstate = Deleted;
        }

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
