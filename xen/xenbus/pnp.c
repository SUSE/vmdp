/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2020 SUSE LLC
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

#include "xenbus.h"
#include <win_maddr.h>

PKINTERRUPT DriverInterruptObj;

static IO_COMPLETION_ROUTINE XenbusIoCompletion;

static NTSTATUS SendIrpSynchronous(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp);

static NTSTATUS FDOStartDevice(
    IN PDEVICE_OBJECT fdo,
    IN PCM_PARTIAL_RESOURCE_LIST raw,
    IN PCM_PARTIAL_RESOURCE_LIST translated);

static VOID FDOStopDevice(IN PDEVICE_OBJECT fdo);
static VOID FDORemoveDevice(IN PDEVICE_OBJECT fdo);

NTSTATUS
FDO_Pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
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
        RPRINTK(DPRTL_PNP, ("FDO_Pnp: IRP_MN_START_DEVICE.\n"));
        status = SendIrpSynchronous(fdx->LowerDevice, Irp);

        if  (NT_SUCCESS(status)) {
            raw = &stack->Parameters.StartDevice
                .AllocatedResources->List[0].PartialResourceList;
            translated = &stack->Parameters.StartDevice
                .AllocatedResourcesTranslated->List[0].PartialResourceList;
            FDOStartDevice(DeviceObject, raw, translated);
        }

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return status;

    case IRP_MN_QUERY_STOP_DEVICE:
        RPRINTK(DPRTL_PNP, ("FDO_Pnp:IRP_MN_QUERY_STOP_DEVICE.\n"));
        fdx->pnpstate = StopPending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        RPRINTK(DPRTL_PNP, ("FDO_Pnp: IRP_MN_CANCEL_STOP_DEVICE.\n"));
        if (fdx->pnpstate == StopPending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("FDO_Pnp: IRP_MN_STOP_DEVICE.\n"));

        FDOStopDevice(DeviceObject);

        fdx->pnpstate = Stopped;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("FDO_Pnp: IRP_MN_QUERY_REMOVE_DEVICE.\n"));
        Irp->IoStatus.Status = status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("FDO_Pnp: IRP_MN_CANCEL_REMOVE_DEVICE.\n"));
        if (fdx->pnpstate == RemovePending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        RPRINTK(DPRTL_ON, ("FDO_Pnp: IRP_MN_SURPRISE_REMOVAL.\n"));
        fdx->pnpstate = SurpriseRemovePending;
        FDORemoveDevice(DeviceObject);

        ExAcquireFastMutex(&fdx->Mutex);

        /*
         * Test the alloc of gfdx was successful.  If not do the best
         * we can with fdx.
         */
        if (gfdx) {
            listHead = &gfdx->ListOfPDOs;
        } else {
            listHead = &fdx->ListOfPDOs;
        }

        for (entry = listHead->Flink, nextEntry = entry->Flink;
              entry != listHead;
              entry = nextEntry, nextEntry = entry->Flink) {
            PPDO_DEVICE_EXTENSION pdx =
                CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            if (pdx->Type != vbd && pdx->Type != vscsi) {
                RemoveEntryList(&pdx->Link);
                InitializeListHead(&pdx->Link);
                pdx->ParentFdo = NULL;
                pdx->ReportedMissing = TRUE;
                if (gfdx)  {
                    gfdx->NumPDOs--;
                } else {
                    fdx->NumPDOs--;
                }
            }
        }

        ExReleaseFastMutex(&fdx->Mutex);

        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("FDO_Pnp: IRP_MN_REMOVE_DEVICE.\n"));
        if (fdx->pnpstate != SurpriseRemovePending) {
            FDOStopDevice(DeviceObject);
            FDORemoveDevice(DeviceObject);
        }

        fdx->pnpstate = Deleted;

        ExAcquireFastMutex(&fdx->Mutex);

        if (gfdx) {
            listHead = &gfdx->ListOfPDOs;
        } else {
            listHead = &fdx->ListOfPDOs;
        }

        RPRINTK(DPRTL_ON, ("FDO_Pnp: IRP_MN_REMOVE_DEVICE start for loop.\n"));
        for (entry = listHead->Flink, nextEntry = entry->Flink;
              entry != listHead;
              entry = nextEntry, nextEntry = entry->Flink) {
            PPDO_DEVICE_EXTENSION pdx =
                CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);

            if (pdx->Type != vbd && pdx->Type != vscsi) {
                RPRINTK(DPRTL_ON,
                        ("FDO_Pnp: IRP_MN_REMOVE_DEVICE remove entry list.\n"));
                RemoveEntryList (&pdx->Link);
                if (pdx->pnpstate == SurpriseRemovePending) {
                    RPRINTK(DPRTL_ON,
                            (" IRP_MN_REMOVE_DEVICE susprise remove %s.\n",
                             pdx->Nodename));
                    InitializeListHead (&pdx->Link);
                    pdx->ParentFdo  = NULL;
                    pdx->ReportedMissing = TRUE;
                    continue;
                }
                fdx->NumPDOs--;
                RPRINTK(DPRTL_ON,
                        (" IRP_MN_REMOVE_DEVICE destroy %s.\n", pdx->Nodename));
                XenbusDestroyPDO(pdx->Self);
            }
        }

        ExReleaseFastMutex(&fdx->Mutex);

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fdx->LowerDevice, Irp);

        RPRINTK(DPRTL_ON, ("FDO_Pnp: irql %d, gfdo %p, dev %p.\n",
                KeGetCurrentIrql(), gfdo, DeviceObject));

        /* Seems we crash if we try to print from here down. */
        IoDetachDevice(fdx->LowerDevice);

        /*
         * The DeviceObject, aka gfdo, should be able to be set to NULL
         * eventhough there is an interaction between xnebus and xenblk.
         */
        xs_cleanup();
        gfdo = NULL;
        IoDeleteDevice(DeviceObject);

        return status;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        if (stack->Parameters.QueryDeviceRelations.Type != BusRelations) {
            break;
        }

        RPRINTK(DPRTL_ON, ("FDO_Pnp: Query bus relation.\n"));

        ExAcquireFastMutex(&fdx->Mutex);

        /*
         * Upper drivers may already presented a relation,
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
        RPRINTK(DPRTL_ON, ("FDO_Pnp: relation, prevcount %x.\n", prevcount));

        numNew = 0;
        for (entry = fdx->ListOfPDOs.Flink;
              entry != &fdx->ListOfPDOs;
              entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            if (pdx->Present && pdx->origin == created) {
                numNew++;
            }
            RPRINTK(DPRTL_ON, ("FDO_Pnp: new relation %s.\n", pdx->Nodename));
        }

        length = sizeof(DEVICE_RELATIONS) +
            (((uintptr_t)numNew + (uintptr_t)prevcount)
                * sizeof(PDEVICE_OBJECT)) - 1;

        relations = (PDEVICE_RELATIONS)EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                                     length,
                                                     XENBUS_POOL_TAG);

        if (relations == NULL) {
            ExReleaseFastMutex(&fdx->Mutex);
            PRINTK(("FDO_Pnp: BusRelation fail due to not no memory.\n"));
            Irp->IoStatus.Status = status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return status;
        }

        if (prevcount) {
            RtlCopyMemory(relations->Objects, oldRelations->Objects,
                          prevcount * sizeof(PDEVICE_OBJECT));
        }

        relations->Count = prevcount + numNew;

        for (entry = fdx->ListOfPDOs.Flink;
              entry != &fdx->ListOfPDOs;
              entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            if (pdx->Present && pdx->origin == created) {
                relations->Objects[prevcount] = pdx->Self;
                RPRINTK(DPRTL_ON, ("FDO_Pnp: new relation ObRef %s, self %p.\n",
                                   pdx->Nodename, pdx->Self));
                ObReferenceObject(pdx->Self);
                prevcount++;
                RPRINTK(DPRTL_ON, ("FDO_Pnp: adding relation %s.\n",
                                   pdx->Nodename));
            }
        }

        if (oldRelations) {
            ExFreePool(oldRelations);
        }

        Irp->IoStatus.Information = (ULONG_PTR) relations;

        ExReleaseFastMutex(&fdx->Mutex);

        RPRINTK(DPRTL_ON,
            ("%s: %x irql %d cpu %d present to pnp manager new relations %d.\n",
            __func__,
            stack->MinorFunction, KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber(),
            relations->Count));

        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    default:
        RPRINTK(DPRTL_PNP,
                ("FDO_Pnp: default irp %x.\n", stack->MinorFunction));
        break;
    }

    IoSkipCurrentIrpStackLocation(Irp);

    status = IoCallDriver(fdx->LowerDevice, Irp);

    RPRINTK(DPRTL_PNP, ("FDO_Pnp: returning status %x\n", status));
    return status;
}

static NTSTATUS
SendIrpSynchronous(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    KEVENT event;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(
      Irp,
      XenbusIoCompletion,
      &event,
      TRUE,
      TRUE,
      TRUE);
    status = IoCallDriver(DeviceObject, Irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(
          &event,
          Executive,
          KernelMode,
          FALSE,
          NULL);
        status = Irp->IoStatus.Status;
    }

    return status;
}

static NTSTATUS
XenbusIoCompletion(IN PDEVICE_OBJECT DeviceObject,
                   IN PIRP Irp,
                   IN PVOID Context)
{
    if (Irp->PendingReturned == TRUE && Context != NULL) {
        KeSetEvent((PKEVENT) Context, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
FDOSetResources(IN PFDO_DEVICE_EXTENSION fdx,
                IN PCM_PARTIAL_RESOURCE_LIST raw,
                IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    PHYSICAL_ADDRESS portBase;
    PHYSICAL_ADDRESS memBase;
    xenbus_pv_port_options_t options;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR resource;
    KINTERRUPT_MODE mode;
    ULONG nres, i;
    NTSTATUS status;
    uint32_t mmiolen;
    BOOLEAN irqshared;

    RPRINTK(DPRTL_ON, ("FDOSetResources: in\n"));
    if (fdx->initialized == SHARED_INFO_INITIALIZED) {
        RPRINTK(DPRTL_ON, ("FDOSetResources: out - already initialized\n"));
        return STATUS_SUCCESS;
    }
    resource = translated->PartialDescriptors;
    nres = translated->Count;

    portBase.QuadPart = 0;
    memBase.QuadPart = 0;
    mmiolen = 0;
    irqshared = FALSE;
    for (i = 0; i < nres; i++, resource++) {
        switch (resource->Type) {
        case CmResourceTypePort:
            portBase = resource->u.Port.Start;
            fdx->NumPorts = resource->u.Port.Length;
            fdx->MappedPort =
                (resource->Flags & CM_RESOURCE_PORT_IO) == 0;
            break;

        case CmResourceTypeInterrupt:
            fdx->irql = (KIRQL) resource->u.Interrupt.Level;
            fdx->vector = resource->u.Interrupt.Vector;
            fdx->affinity = resource->u.Interrupt.Affinity;
            mode = (resource->Flags == CM_RESOURCE_INTERRUPT_LATCHED) ?
                Latched : LevelSensitive;
            irqshared =
                resource->ShareDisposition == CmResourceShareShared;
            break;

        case CmResourceTypeMemory:
            memBase = resource->u.Memory.Start;
            mmiolen = resource->u.Memory.Length;
            break;

        case CmResourceTypeDma:
            break;
        }
    }

    /* retrieve the IRQ of the evtchn-pci device  */
    resource = raw->PartialDescriptors;
    nres = raw->Count;
    for (i = 0; i < nres; i++, resource++) {
        switch (resource->Type) {
        case CmResourceTypeInterrupt:
            fdx->dirql = resource->u.Interrupt.Level;
            fdx->dvector = resource->u.Interrupt.Vector;
            fdx->daffinity = resource->u.Interrupt.Affinity;
            break;
        }
    }

    /* I/O initialization */
    if (fdx->MappedPort) {
        fdx->PortBase = (PUCHAR)mm_map_io_space(
            portBase,
            fdx->NumPorts,
            MmNonCached);
        if (!fdx->PortBase) {
            PRINTK(("FDOSetResources: MmMpapIoSpace port failed\n"));
            return STATUS_NO_MEMORY;
        }
    } else {
        fdx->PortBase = (PUCHAR) portBase.QuadPart;
    }

    if (memBase.QuadPart) {
        fdx->mem = mm_map_io_space(memBase, mmiolen, MmNonCached);
        if (!fdx->mem) {
            PRINTK(("FDOSetResources: MmMpapIoSpace mem failed\n"));
            return STATUS_NO_MEMORY;
        }
    }

    status = xenbus_xen_shared_init(memBase.QuadPart, fdx->mem, mmiolen,
        fdx->dvector, OP_MODE_NORMAL);
    if (!NT_SUCCESS(status)) {
        if (fdx->PortBase && fdx->MappedPort) {
            MmUnmapIoSpace(fdx->PortBase, fdx->NumPorts);
        }
        fdx->PortBase = NULL;
        return status;
    }

    PRINTK(
        ("XenBus resources: vector %x, irql %x, dev %x, aff %x sharing %d.\n",
         fdx->vector, fdx->irql, fdx->dvector, fdx->affinity, irqshared));

    status = IoConnectInterrupt(
        &DriverInterruptObj,
        XenbusOnInterrupt,
        (PVOID) fdx,
        NULL,
        fdx->vector,
        (KIRQL)fdx->irql,
        (KIRQL)fdx->irql,
        LevelSensitive,
        irqshared,
        fdx->affinity,
        FALSE);

    if (!NT_SUCCESS(status)) {
        PRINTK(("XENBUS: IoConnectInterrupt fail.\n"));
        return status;
    }

    status = set_callback_irq(fdx->dvector);

    return status;
}

static NTSTATUS
FDOStartDevice(IN PDEVICE_OBJECT fdo,
               IN PCM_PARTIAL_RESOURCE_LIST raw,
               IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;
    POWER_STATE powerState;

    RPRINTK(DPRTL_ON,
            ("XENBUS: FDOStartDevice IN, fdo = %p, gfdo = %p.\n", fdo , gfdo));
    fdx = (PFDO_DEVICE_EXTENSION)fdo->DeviceExtension;

    status = IoSetDeviceInterfaceState(&fdx->ifname, TRUE);
    if (!NT_SUCCESS(status)) {
        PRINTK(("xenbusdrv.sys: IosetDeviceInterfaceState failed: 0x%x\n",
            status));
    }

    status = FDOSetResources(fdx, raw, translated);

    powerState.DeviceState = PowerDeviceD0;
    PoSetPowerState (fdo, DevicePowerState, powerState);
    fdx->power_state = PowerSystemWorking;
    fdx->pnpstate = Started;

    RPRINTK(DPRTL_ON, ("XENBUS: start FDO device successfully: %x.\n", status));

    return status;
}

static VOID
FDOStopDevice(IN PDEVICE_OBJECT fdo)
{
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("XENBUS: entring FDOStopDevice.\n"));
    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;
    fdx->pnpstate = Stopped;

    RPRINTK(DPRTL_ON, ("XENBUS: FDO stop device successfully.\n"));
}


static VOID
FDORemoveDevice(IN PDEVICE_OBJECT fdo)
{
    PFDO_DEVICE_EXTENSION fdx;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("XENBUS: entering FDORemoveDevice.\n"));

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;

    if (fdx->ifname.Buffer != NULL) {
        status = IoSetDeviceInterfaceState(&fdx->ifname, FALSE);
        if (status != STATUS_SUCCESS) {
            PRINTK(("FDORemoveDevice: IoSetDeviceInterfaceState %x\n", status));
        }

        ExFreePool(fdx->ifname.Buffer);
        RtlZeroMemory(&fdx->ifname, sizeof(UNICODE_STRING));
    }

    gfdx = (PFDO_DEVICE_EXTENSION)EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                                sizeof(FDO_DEVICE_EXTENSION),
                                                XENBUS_POOL_TAG);
    if (gfdx) {
        InitializeListHead(&gfdx->ListOfPDOs);
        xenbus_copy_fdx(gfdx, fdx);
    }

    RPRINTK(DPRTL_ON, ("XENBUS: leaving FDORemoveDevice.\n"));
}
