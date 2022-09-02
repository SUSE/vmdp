/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2022 SUSE LLC
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

#include "pvcrash.h"

static KBUGCHECK_CALLBACK_RECORD bugcheck_cbr;
static KBUGCHECK_CALLBACK_RECORD bugcheck_mem_cbr;
static KBUGCHECK_REASON_CALLBACK_RECORD dump_cbr;
static KBUGCHECK_REASON_CALLBACK_RECORD dump_mem_cbr;

static NTSTATUS
pvcrash_io_completion(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp,
  IN PVOID Context)
{
    if (Irp->PendingReturned == TRUE && Context != NULL) {
        KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
pvcrash_send_irp_synchronous(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp)
{
    NTSTATUS status;
    KEVENT event;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(
      Irp,
      pvcrash_io_completion,
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
pvcrash_prepare_hardware(
   IN FDO_DEVICE_EXTENSION *fdx,
   IN PCM_PARTIAL_RESOURCE_LIST raw,
   IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    PHYSICAL_ADDRESS pa;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR resource;
    void *va;
    ULONG nres, i;
    ULONG len;
    NTSTATUS status;
    BOOLEAN port_space;

    status = STATUS_SUCCESS;
    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    resource = translated->PartialDescriptors;
    nres = translated->Count;
    RPRINTK(DPRTL_INIT, ("    Number of resources %d\n", nres));

    for (i = 0, status = STATUS_SUCCESS;
            i < nres && status == STATUS_SUCCESS;
            i++, resource++) {
        switch (resource->Type) {
        case CmResourceTypePort:
        case CmResourceTypeMemory:
            port_space = !!(resource->Flags & CM_RESOURCE_PORT_IO);
            RPRINTK(DPRTL_INIT, ("    i %d: port space %d\n", i, port_space));

            if (port_space) {
                pa = resource->u.Port.Start;
                len = resource->u.Port.Length;
                va = (void *)pa.u.LowPart;
            } else {
                pa = resource->u.Memory.Start;
                len = resource->u.Memory.Length;
                va = mm_map_io_space(pa, len, MmNonCached);
                if (va == NULL) {
                    PRINTK(("    MmMpapIoSpace port failed for 0xllx\n",
                            pa.QuadPart));
                    status = STATUS_NO_MEMORY;
                    break;
                }
            }

            fdx->IoBaseAddress = va;
            fdx->IoRange = len;
            fdx->mapped_port = !port_space;

            if (fdx->mapped_port) {
                g_pvcrash_mem_addr = fdx->IoBaseAddress;
                fdx->supported_crash_features = *(PUCHAR)(fdx->IoBaseAddress);
            } else {
                g_pvcrash_port_addr = fdx->IoBaseAddress;
                fdx->supported_crash_features = READ_PORT_UCHAR(
                    (PUCHAR)(fdx->IoBaseAddress));
            }

            RPRINTK(DPRTL_INIT,
                    ("    i %d: port pa %llx va %p len %d features 0x%x\n",
                    i, pa.QuadPart, va, len, fdx->supported_crash_features));
            break;

        default:
            RPRINTK(DPRTL_INIT, ("    resource type default: %x, i %d\n",
                resource->Type, i));
            break;
        }
    }
    RPRINTK(DPRTL_INIT, ("<-- %s %s: status %x\n",
                         VDEV_DRIVER_NAME, __func__, status));
    return status;
}

static void
pvcrash_register_callbacks(FDO_DEVICE_EXTENSION *fdx)
{
    PKBUGCHECK_CALLBACK_ROUTINE bugcheck_callback;
    PKBUGCHECK_REASON_CALLBACK_ROUTINE bugcheck_reason_callback;
    KBUGCHECK_CALLBACK_RECORD *bugchk_cbr;
    KBUGCHECK_REASON_CALLBACK_RECORD *reason_cbr;
    BOOLEAN res;
    BOOLEAN res_bchk;

    if (fdx->mapped_port) {
        bugchk_cbr = &bugcheck_mem_cbr;
        reason_cbr = &dump_mem_cbr;
        KeInitializeCallbackRecord(&bugcheck_mem_cbr);
        KeInitializeCallbackRecord(&dump_mem_cbr);
        bugcheck_callback = pvcrash_notify_mem_bugcheck;
        bugcheck_reason_callback = pvcrash_on_dump_mem_bugCheck;
    } else {
        bugchk_cbr = &bugcheck_cbr;
        reason_cbr = &dump_cbr;
        KeInitializeCallbackRecord(&bugcheck_cbr);
        KeInitializeCallbackRecord(&dump_cbr);
        bugcheck_callback = pvcrash_notify_bugcheck;
        bugcheck_reason_callback = pvcrash_on_dump_bugCheck;
    }

    if (fdx->supported_crash_features & PVPANIC_PANICKED) {
        res = KeRegisterBugCheckCallback(bugchk_cbr,
                                         bugcheck_callback ,
                                         fdx->IoBaseAddress,
                                         sizeof(PVOID),
                                         (PUCHAR)("pvcrash_nodify"));
        if (res == FALSE) {
            PRINTK(("%s: KeRegisterBugCheckCallback failed\n",
                    VDEV_DRIVER_NAME));
        }
    }

    if (fdx->supported_crash_features & PVPANIC_CRASHLOADED) {
        res_bchk = KeRegisterBugCheckReasonCallback(
            reason_cbr,
            bugcheck_reason_callback ,
            KbCallbackDumpIo,
            (PUCHAR)("pvcrash_nodify"));
        if (res_bchk == FALSE) {
            PRINTK(("%s: KeRegisterBugCheckReasonCallback failed\n",
                    VDEV_DRIVER_NAME));
        }
    }
}

static void
pvcrash_deregister_callbacks(FDO_DEVICE_EXTENSION *fdx)
{
    KBUGCHECK_CALLBACK_RECORD *bugchk_cbr;
    KBUGCHECK_REASON_CALLBACK_RECORD *reason_cbr;

    if (fdx->mapped_port) {
        bugchk_cbr = &bugcheck_mem_cbr;
        reason_cbr = &dump_mem_cbr;
    } else {
        bugchk_cbr = &bugcheck_cbr;
        reason_cbr = &dump_cbr;
    }
    if (fdx->supported_crash_features & PVPANIC_PANICKED) {
        RPRINTK(DPRTL_ON, ("    KeDeregisterBugCheckCallback irql %d fdx %p\n",
            KeGetCurrentIrql(), fdx));
        KeDeregisterBugCheckCallback(bugchk_cbr);
    }

    if (fdx->supported_crash_features & PVPANIC_CRASHLOADED) {
        RPRINTK(DPRTL_ON, ("    KeDeregisterBugCheckReasonCallback\n"));
        KeDeregisterBugCheckReasonCallback(reason_cbr);
    }

    if (fdx->mapped_port && fdx->IoBaseAddress != NULL) {
        RPRINTK(DPRTL_ON, ("    MmUnmapIoSpace %p\n", fdx->IoBaseAddress));
        MmUnmapIoSpace(fdx->IoBaseAddress, fdx->IoRange);
    }
}

static NTSTATUS
pvcrash_start_device(
  IN PDEVICE_OBJECT fdo,
  IN PCM_PARTIAL_RESOURCE_LIST raw,
  IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;
    POWER_STATE powerState;

    fdx = (PFDO_DEVICE_EXTENSION)fdo->DeviceExtension;
    RPRINTK(DPRTL_ON, ("--> %s %s: (irql %d) fdo = %p\n",
                       VDEV_DRIVER_NAME, __func__, KeGetCurrentIrql(), fdo));

    do {
        status = IoSetDeviceInterfaceState(&fdx->ifname, TRUE);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: IosetDeviceInterfaceState failed: %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        status = pvcrash_prepare_hardware(fdx, raw, translated);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: pvcrash_prepare_haredware failed: %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        pvcrash_register_callbacks(fdx);

        powerState.DeviceState = PowerDeviceD0;
        PoSetPowerState (fdo, DevicePowerState, powerState);
        fdx->power_state = PowerSystemWorking;
        fdx->dpower_state = PowerDeviceD0;
        fdx->pnpstate = Started;

    } while (0);

    RPRINTK(DPRTL_ON, ("<-- %s %s: status 0x%x\n",
                       VDEV_DRIVER_NAME, __func__, status));

    return status;
}

NTSTATUS
pvcrash_fdo_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    ULONG length, prevcount, numNew, i;
    PFDO_DEVICE_EXTENSION fdx;
    PIO_STACK_LOCATION stack;
    PCM_PARTIAL_RESOURCE_LIST raw, translated;
    PLIST_ENTRY entry, listHead, nextEntry;
    PDEVICE_RELATIONS relations, oldRelations;

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IRP_MJ_PNP == stack->MajorFunction);

    switch (stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s: IRP_MN_START_DEVICE.\n", __func__));
        status = pvcrash_send_irp_synchronous(fdx->LowerDevice, Irp);

        if  (NT_SUCCESS(status)) {
            raw = &stack->Parameters.StartDevice
                .AllocatedResources->List[0].PartialResourceList;

            translated = &stack->Parameters.StartDevice
                .AllocatedResourcesTranslated->List[0].PartialResourceList;

            pvcrash_start_device(DeviceObject, raw, translated);
        }

        Irp->IoStatus.Status = status;
        pvcrash_complete_request(Irp, IO_NO_INCREMENT);

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
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_STOP_DEVICE.\n", __func__));
        /* TODO: Irps and resources */

        if (fdx->ifname.Buffer != NULL) {
            status = IoSetDeviceInterfaceState(&fdx->ifname, FALSE);
            if (status != STATUS_SUCCESS) {
                PRINTK(("%s: IoSetDeviceInterfaceState failed: %x\n",
                        VDEV_DRIVER_NAME, status));
            }
        }
        fdx->pnpstate = Stopped;
        Irp->IoStatus.Status = STATUS_SUCCESS;
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
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_REMOVE_DEVICE.\n", __func__));

        fdx->pnpstate = Deleted;
        Irp->IoStatus.Status = STATUS_SUCCESS;

        if (fdx->ifname.Buffer != NULL) {
            status = IoSetDeviceInterfaceState(&fdx->ifname, FALSE);
            if (status != STATUS_SUCCESS) {
                PRINTK(("%s: IoSetDeviceInterfaceState failed: %x\n",
                        VDEV_DRIVER_NAME, status));
            }
            ExFreePool(fdx->ifname.Buffer);
            RtlZeroMemory(&fdx->ifname, sizeof(UNICODE_STRING));
        }

        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fdx->LowerDevice, Irp);

        pvcrash_deregister_callbacks(fdx);


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
