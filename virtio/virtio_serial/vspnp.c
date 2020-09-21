/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2014-2020 SUSE LLC
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

#include "vserial.h"
#include <win_maddr.h>

PKINTERRUPT DriverInterruptObj;
unsigned int gdevice_id;
PFDO_DEVICE_EXTENSION gfdx;

NTSTATUS
vserial_add_device(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT pdo)
{
    NTSTATUS status;
    PDEVICE_OBJECT fdo;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    status = IoCreateDevice(
        DriverObject,
        sizeof(FDO_DEVICE_EXTENSION),
        NULL,
        FILE_DEVICE_BUS_EXTENDER,     /* bus driver */
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                        /* exclusive */
        &fdo);
    if (!NT_SUCCESS(status)) {
        RPRINTK(DPRTL_ON, ("\tIoCreateDevice returned 0x%x\n", status));
        return status;
    }

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;
    RtlZeroMemory(fdx, sizeof(FDO_DEVICE_EXTENSION));

    RPRINTK(DPRTL_ON,
            ("VSerialAddDevice: DriverObject = %p, pdo = %p, fdo = %p\n",
             DriverObject, pdo, fdo));
    RPRINTK(DPRTL_ON,
            ("VSerialAddDevice: fdx = %p, obj = %p\n",
             fdx, fdo->DriverObject));

    status = IoRegisterDeviceInterface(
        pdo,
        (LPGUID)&GUID_DEVCLASS_PORT_DEVICE,
        NULL,
        &fdx->ifname);
    if (!NT_SUCCESS(status)) {
        PRINTK(("vserialdrv.sys: IoRegisterDeviceInterface failed (%x)",
            status));
        IoDeleteDevice(fdo);
        return status;
    }

    RPRINTK(DPRTL_ON, ("  fdx->ifname: %ws\n", fdx->ifname.Buffer));
    fdx->LowerDevice = IoAttachDeviceToDeviceStack(fdo, pdo);
    if (fdx->LowerDevice == NULL) {
        IoDeleteDevice(fdo);
        return STATUS_NO_SUCH_DEVICE;
    }

    fdx->Pdo = pdo;
    fdx->Self = fdo;
    fdx->IsFdo = TRUE;
    fdx->sig = 0xccddeeff;
    fdx->device_id = gdevice_id++;

    KeInitializeDpc(&fdx->int_dpc, vserial_int_dpc, fdx);
    IoInitializeRemoveLock(&fdx->RemoveLock, 0, 0, 0);
    fdx->pnpstate = NotStarted;
    fdx->devpower = PowerDeviceD0;
    fdx->syspower = PowerSystemWorking;

    ExInitializeFastMutex(&fdx->Mutex);
    KeInitializeSpinLock(&fdx->qlock);
    KeInitializeSpinLock(&fdx->cvq_lock);
    InitializeListHead(&fdx->list_of_pdos);

    fdo->Flags |=  DO_POWER_PAGABLE;

    fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return STATUS_SUCCESS;
}

static void
vserial_delete_queue(virtio_queue_t **ppvq)
{
    RPRINTK(DPRTL_TRC, ("--> %s\n", __func__));

    if (*ppvq) {
        VIRTIO_DEVICE_QUEUE_DELETE((*ppvq)->vdev, *ppvq, TRUE);
        *ppvq = NULL;
    }

    RPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
}

static void
vserial_shutdown_queues(FDO_DEVICE_EXTENSION *fdx)
{
    unsigned int nr_ports;
    unsigned int i;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    virtio_device_remove_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER_OK);
    VIRTIO_DEVICE_RESET(&fdx->vdev);

    RPRINTK(DPRTL_ON, (" is_hos_multiport\n"));
    if (fdx->is_host_multiport) {
        if (fdx->c_ivq) {
            RPRINTK(DPRTL_ON, (" delete queue ivq %p\n", fdx->c_ivq));
            vserial_delete_queue(&fdx->c_ivq);
        }
        if (fdx->c_ovq) {
            RPRINTK(DPRTL_ON, (" delete queue ovq %p\n", fdx->c_ovq));
            vserial_delete_queue(&fdx->c_ovq);
        }
    }

    nr_ports = fdx->console_config.max_nr_ports;
    RPRINTK(DPRTL_ON, (" nr_ports queue ovq %d\n",
                       fdx->console_config.max_nr_ports));
    for (i = 0; i < nr_ports; i++) {
        if (fdx->in_vqs && fdx->in_vqs[i]) {
            vserial_delete_queue(&(fdx->in_vqs[i]));
        }

        if (fdx->out_vqs && fdx->out_vqs[i]) {
            vserial_delete_queue(&(fdx->out_vqs[i]));
        }
    }

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}


void
wdm_device_powerdown(FDO_DEVICE_EXTENSION *fdx)
{
    port_buffer_t *buf;
    KLOCK_QUEUE_HANDLE lh;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    KeAcquireInStackQueuedSpinLock(&fdx->cvq_lock, &lh);
    if (fdx->c_ivq) {
        vring_stop_interrupts(fdx->c_ivq);

        while (buf = (port_buffer_t *)vring_detach_unused_buf(fdx->c_ivq)) {
            vserial_free_buffer(buf);
        }
    }

    vserial_shutdown_queues(fdx);
    KeReleaseInStackQueuedSpinLock(&lh);

    PRINTK(("%s: powered down\n", VDEV_DRIVER_NAME));
    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
}

NTSTATUS
wdm_device_virtio_init(IN FDO_DEVICE_EXTENSION *fdx)
{
    uint64_t guest_features_list;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    fdx->vdev.maxQueues = VSERIAL_NUMBER_OF_QUEUES;

    VIRTIO_DEVICE_RESET(&fdx->vdev);
    virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

    if (fdx->vdev.msix_used_offset) {
        VIRTIO_DEVICE_SET_CONFIG_VECTOR(&fdx->vdev,
                                        (USHORT)(VIRTIO_SERIAL_MAX_INTS));
    }

    fdx->console_config.max_nr_ports = 1;

    fdx->host_features = VIRTIO_DEVICE_GET_FEATURES(&fdx->vdev);
    PRINTK(("%s: host features 0x%llx\n",
            VDEV_DRIVER_NAME, fdx->host_features));
    guest_features_list = 0;
    fdx->is_host_multiport = virtio_is_feature_enabled(fdx->host_features,
                                 VIRTIO_CONSOLE_F_MULTIPORT);
    if (fdx->is_host_multiport) {
        virtio_feature_enable(guest_features_list, VIRTIO_CONSOLE_F_MULTIPORT);
        VIRTIO_DEVICE_GET_CONFIG(&fdx->vdev,
            FIELD_OFFSET(CONSOLE_CONFIG, max_nr_ports),
            &fdx->console_config.max_nr_ports,
            sizeof(fdx->console_config.max_nr_ports));
        RPRINTK(DPRTL_ON, ("  max_nr_ports: %d\n",
            fdx->console_config.max_nr_ports));
        if (fdx->console_config.max_nr_ports > fdx->vdev.maxQueues / 2) {
            fdx->console_config.max_nr_ports = fdx->vdev.maxQueues / 2;
            RPRINTK(DPRTL_ON, ("  max_nr_ports restricted to: %d\n",
                fdx->console_config.max_nr_ports));
        }
    }
    RPRINTK(DPRTL_ON, ("  is_host_multiport: %x\n", fdx->is_host_multiport));

    if (virtio_is_feature_enabled(fdx->host_features, VIRTIO_F_VERSION_1)) {
        virtio_feature_enable(guest_features_list, VIRTIO_F_VERSION_1);
    }

    PRINTK(("%s: setting guest features 0x%llx\n",
            VDEV_DRIVER_NAME, guest_features_list));
    virtio_device_set_guest_feature_list(&fdx->vdev, guest_features_list);

    fdx->in_vqs = (virtio_queue_t **)ExAllocatePoolWithTag(
       NonPagedPoolNx,
       fdx->console_config.max_nr_ports * sizeof(virtio_queue_t *),
       VSERIAL_POOL_TAG);

    if (fdx->in_vqs == NULL) {
        RPRINTK(DPRTL_ON, ("  ExAllocatePoolWithTag failed\n"));
        wdm_unmap_io_space(fdx);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(fdx->in_vqs, 0,
        fdx->console_config.max_nr_ports * sizeof(virtio_queue_t *));

    fdx->out_vqs = (virtio_queue_t **)ExAllocatePoolWithTag(
       NonPagedPoolNx,
       fdx->console_config.max_nr_ports * sizeof(virtio_queue_t *),
       VSERIAL_POOL_TAG);

    if (fdx->out_vqs == NULL) {
        RPRINTK(DPRTL_ON, ("ExAllocatePoolWithTag failed\n"));
        ExFreePool(fdx->in_vqs);
        wdm_unmap_io_space(fdx);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(fdx->out_vqs, 0,
        fdx->console_config.max_nr_ports * sizeof(virtio_queue_t *));
    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return STATUS_SUCCESS;
}

static NTSTATUS
vserial_q_init(IN FDO_DEVICE_EXTENSION *fdx)
{
    NTSTATUS status;
    uint32_t i;
    uint32_t j;
    uint32_t num_ports;
    USHORT control_vector;
    USHORT queues_vector;
    USHORT vector;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    status = STATUS_SUCCESS;

    control_vector = fdx->int_info[0].message_signaled ? 0 :
        VIRTIO_MSI_NO_VECTOR;

    queues_vector = (control_vector != VIRTIO_MSI_NO_VECTOR) ?
        (fdx->int_info[1].vector ? 1 : VIRTIO_MSI_NO_VECTOR) :
        VIRTIO_MSI_NO_VECTOR;

    RPRINTK(DPRTL_ON, ("  cv %d, qv %d\n", control_vector, queues_vector));

    num_ports = fdx->console_config.max_nr_ports;
    if (fdx->is_host_multiport) {
        num_ports++;
    }

    for (i = 0, j = 0; i < num_ports; i++) {
        if (i == VIRTIO_SERIAL_CONTROL_PORT_INDEX) {
            if (!fdx->c_ivq) {
                fdx->c_ivq = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                                       i * 2,
                                                       NULL,
                                                       NULL,
                                                       0,
                                                       control_vector,
                                                       FALSE);
                RPRINTK(DPRTL_ON, ("  c_ivq %p\n", fdx->c_ivq));
            } else {
                VIRTIO_DEVICE_QUEUE_ACTIVATE(&fdx->vdev,
                                             fdx->c_ivq,
                                             control_vector);
            }

            if (!fdx->c_ovq) {
                fdx->c_ovq = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                                       (i * 2) + 1,
                                                       NULL,
                                                       NULL,
                                                       0,
                                                       control_vector,
                                                       FALSE);
                RPRINTK(DPRTL_ON, ("  c_ovq %p\n", fdx->c_ovq));
            } else {
                VIRTIO_DEVICE_QUEUE_ACTIVATE(&fdx->vdev,
                                             fdx->c_ovq,
                                             control_vector);
            }
        } else {
            if (!fdx->in_vqs[j]) {
                fdx->in_vqs[j] = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                                           (i * 2),
                                                           NULL,
                                                           NULL,
                                                           0,
                                                           queues_vector,
                                                           FALSE);
            } else {
                VIRTIO_DEVICE_QUEUE_ACTIVATE(&fdx->vdev,
                                             fdx->in_vqs[j],
                                             queues_vector);
            }

            if (!fdx->out_vqs[j]) {
                fdx->out_vqs[j] = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                                            (i * 2) + 1,
                                                            NULL,
                                                            NULL,
                                                            0,
                                                            queues_vector,
                                                            FALSE);
            } else {
                VIRTIO_DEVICE_QUEUE_ACTIVATE(&fdx->vdev,
                                             fdx->out_vqs[j],
                                             queues_vector);
            }
            ++j;
        }
    }

    if (fdx->is_host_multiport && (fdx->c_ovq == NULL)) {
        status = STATUS_NOT_FOUND;
    }

    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
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

    status = vserial_q_init(fdx);
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s %s: failed 0%x\n",
            VDEV_DRIVER_NAME, __func__, status));
        return status;
    }
    vserial_fill_queue(fdx->c_ivq, &fdx->cvq_lock);
    vring_start_interrupts(fdx->c_ivq);

    virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER_OK);

    vserial_ctrl_msg_send(fdx, VIRTIO_CONSOLE_BAD_ID,
        VIRTIO_CONSOLE_DEVICE_READY, 1);

    RPRINTK(DPRTL_ON, ("  wait for create event.\n"));

#ifdef DBG
    dbg_print_mask &= ~DPRTL_DPC;
#endif
    PRINTK(("%s: powered on\n", VDEV_DRIVER_NAME));
    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return STATUS_SUCCESS;
}

static VOID
FDORemoveDevice(IN PDEVICE_OBJECT fdo)
{
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry, listHead, nextEntry;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;

    listHead = &fdx->list_of_pdos;

    RPRINTK(DPRTL_ON, ("  start for loop.\n"));
    for (entry = listHead->Flink, nextEntry = entry->Flink;
            entry != listHead;
            entry = nextEntry, nextEntry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);

        RPRINTK(DPRTL_ON, ("  remove entry list.\n"));
        RemoveEntryList (&pdx->Link);
        if (pdx->pnpstate == SurpriseRemovePending) {
            RPRINTK(DPRTL_ON, (" susprise remove %d.\n",
              pdx->port_id));
            InitializeListHead (&pdx->Link);
            pdx->ParentFdo  = NULL;
            pdx->ReportedMissing = TRUE;
            continue;
        }
        fdx->NumPDOs--;
        RPRINTK(DPRTL_ON, (" vserial_destroy_pdo %d.\n",
          pdx->port_id));
        vserial_destroy_pdo(pdx->Self);
    }
    RPRINTK(DPRTL_ON, ("  done with for loop.\n"));

    wdm_fdo_stop_device(fdo);

    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
}

NTSTATUS
FDO_Pnp(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp)
{
    NTSTATUS status;
    ULONG length, prevcount, numNew, i;
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PIO_STACK_LOCATION stack;
    PCM_PARTIAL_RESOURCE_LIST raw, translated;
    PLIST_ENTRY entry, listHead, nextEntry;
    PDEVICE_RELATIONS relations, oldRelations;

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IRP_MJ_PNP == stack->MajorFunction);

    switch (stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s %s: IRP_MN_START_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));
        status = wdm_send_irp_synchronous(fdx->LowerDevice, Irp);

        if  (NT_SUCCESS(status)) {
            raw = &stack->Parameters.StartDevice
                .AllocatedResources->List[0].PartialResourceList;

            translated = &stack->Parameters.StartDevice
                .AllocatedResourcesTranslated->List[0].PartialResourceList;

            status = wdm_start_device(DeviceObject, raw, translated);

#ifdef DBG
            if  (NT_SUCCESS(status)) {
                /* Check if we missed the ctrl message from powerup. */
                if (VRING_HAS_UNCONSUMED_RESPONSES(fdx->c_ivq)) {
                    PRINTK(("%s %s: there's a message buffer to be processed\n",
                            VDEV_DRIVER_NAME, __func__));
                    if (virtio_device_read_isr_status(&fdx->vdev) > 0) {
                        PRINTK(("\tthere's an int pending\n"));
                    }
                }
            }
            /* a kick does't do anything. */
#endif
        }

        Irp->IoStatus.Status = status;
        vserial_complete_request(Irp, IO_NO_INCREMENT);

        RPRINTK(DPRTL_ON, ("<-- %s %s: IRP_MN_START_DEVICE return status %x\n",
                           VDEV_DRIVER_NAME, __func__, status));
        return status;

    case IRP_MN_QUERY_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("%s %s: IRP_MN_QUERY_STOP_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));
        fdx->pnpstate = StopPending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("%s %s: IRP_MN_CANCEL_STOP_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));
        if (fdx->pnpstate == StopPending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s %s: IRP_MN_STOP_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));
        /* TODO: Irps and resources */

        wdm_fdo_stop_device(DeviceObject);

        fdx->pnpstate = Stopped;
        Irp->IoStatus.Status = STATUS_SUCCESS;

        RPRINTK(DPRTL_ON, ("<-- %s %s: IRP_MN_STOP_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("%s %s: IRP_MN_QUERY_REMOVE_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));
        fdx->pnpstate = RemovePending;
        Irp->IoStatus.Status = status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("%s %s: IRP_MN_CANCEL_REMOVE_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));
        if (fdx->pnpstate == RemovePending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        RPRINTK(DPRTL_ON, ("%s %s%: IRP_MN_SURPRISE_REMOVAL.\n",
                           VDEV_DRIVER_NAME, __func__));
        fdx->pnpstate = SurpriseRemovePending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s %s: IRP_MN_REMOVE_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));

        FDORemoveDevice(DeviceObject);
        wdm_fdo_remove_device(DeviceObject);
        fdx->pnpstate = Deleted;

        RPRINTK(DPRTL_ON, ("<-- %s %s: IRP_MN_REMOVE_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fdx->LowerDevice, Irp);

        RPRINTK(DPRTL_ON, ("F%s %s: irql %d, dev %p.\n",
                           VDEV_DRIVER_NAME, __func__,
                           KeGetCurrentIrql(), DeviceObject));

        /* Seems we crash if we try to print from here down. */
        IoDetachDevice(fdx->LowerDevice);

        /* The DeviceObject, aka gfdo, should be able to be set to NULL
         * eventhough there is an interaction between xnebus and xenblk.
         */
        IoDeleteDevice(DeviceObject);

        return status;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        RPRINTK(DPRTL_ON, ("--> %s %s: Query device relation, type %x.\n",
                VDEV_DRIVER_NAME, __func__,
                stack->Parameters.QueryDeviceRelations.Type));

        if (stack->Parameters.QueryDeviceRelations.Type != BusRelations) {
            break;
        }

        ExAcquireFastMutex(&fdx->Mutex);

        /* upper drivers may already presented a relation,
         * we should keep the existing ones and add ours.
         */
        oldRelations = (PDEVICE_RELATIONS) Irp->IoStatus.Information;
        if (oldRelations) {
            prevcount = oldRelations->Count;
            if (!fdx->NumPDOs) {
                ExReleaseFastMutex(&fdx->Mutex);
                break;
            }
        } else {
            prevcount = 0;
        }
        RPRINTK(DPRTL_ON, ("%s %s: relation, prevcount %x.\n",
                           VDEV_DRIVER_NAME, __func__, prevcount));

        numNew = 0;
        for (entry = fdx->list_of_pdos.Flink;
             entry != &fdx->list_of_pdos;
             entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            numNew++;
            RPRINTK(DPRTL_ON, ("%s %s: new relation, id %d.\n",
                               VDEV_DRIVER_NAME, __func__, pdx->port_id));
        }

        length = sizeof(DEVICE_RELATIONS) +
            (((size_t)numNew + (size_t)prevcount) * sizeof(PDEVICE_OBJECT)) - 1;

        relations = (PDEVICE_RELATIONS) ExAllocatePoolWithTag(
          NonPagedPoolNx, length, VSERIAL_POOL_TAG);

        if (relations == NULL) {
            ExReleaseFastMutex(&fdx->Mutex);
            PRINTK(("%s %s: BusRelation fail due to not no memory.\n",
                    VDEV_DRIVER_NAME, __func__));
            Irp->IoStatus.Status = status = STATUS_INSUFFICIENT_RESOURCES;
            vserial_complete_request(Irp, IO_NO_INCREMENT);
            return status;
        }

        if (prevcount) {
            RtlCopyMemory(relations->Objects, oldRelations->Objects,
                prevcount * sizeof(PDEVICE_OBJECT));
        }

        relations->Count = prevcount + numNew;

        for (entry = fdx->list_of_pdos.Flink;
             entry != &fdx->list_of_pdos;
             entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            if (pdx->Present) {
                relations->Objects[prevcount] = pdx->Self;
                RPRINTK(DPRTL_ON, ("%s %s: new relation ObRef %s, self %p.\n",
                                   VDEV_DRIVER_NAME, __func__,
                                   pdx->instance_id, pdx->Self));
                ObReferenceObject(pdx->Self);
                prevcount++;
                RPRINTK(DPRTL_ON,
                        ("%s %s: adding relation, id %d.\n",
                         VDEV_DRIVER_NAME, __func__, pdx->port_id));
            }
        }

        if (oldRelations) {
            ExFreePool(oldRelations);
        }

        Irp->IoStatus.Information = (ULONG_PTR) relations;

        ExReleaseFastMutex(&fdx->Mutex);

        RPRINTK(DPRTL_ON,
                ("<-- %s %s : presenting to pnp manager new relations: %d.\n",
                 VDEV_DRIVER_NAME, __func__, relations->Count));

        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    default:
        RPRINTK(DPRTL_PNP,
            ("%s %s: default irp %x.\n",
             VDEV_DRIVER_NAME, __func__, stack->MinorFunction));
        break;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(fdx->LowerDevice, Irp);

    return status;
}
