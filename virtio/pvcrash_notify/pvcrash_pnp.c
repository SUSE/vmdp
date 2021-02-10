/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2021 SUSE LLC
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
static KBUGCHECK_REASON_CALLBACK_RECORD dump_cbr;

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
    UCHAR features;
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
            g_pvcrash_port_addr = fdx->IoBaseAddress;

            features = READ_PORT_UCHAR((PUCHAR)(fdx->IoBaseAddress));
            if ((features & (PVPANIC_PANICKED | PVPANIC_CRASHLOADED))
                    == (PVPANIC_PANICKED | PVPANIC_CRASHLOADED)) {
                fdx->support_crash_loaded = TRUE;
            }

            RPRINTK(DPRTL_INIT,
                    ("    i %d: port pa %llx va %p len %d features 0x%x\n",
                    i, pa.QuadPart, va, len, features));
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


static NTSTATUS
pvcrash_start_device(
  IN PDEVICE_OBJECT fdo,
  IN PCM_PARTIAL_RESOURCE_LIST raw,
  IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;
    POWER_STATE powerState;
    DECLARE_UNICODE_STRING_SIZE(symbolic_link_name, 128);
    DECLARE_UNICODE_STRING_SIZE(device_name, 128);
    BOOLEAN res;
    BOOLEAN res_bchk;

    fdx = (PFDO_DEVICE_EXTENSION)fdo->DeviceExtension;
    RPRINTK(DPRTL_ON, ("--> %s %s: (irql %d) fdo = %p\n",
                       VDEV_DRIVER_NAME, __func__, KeGetCurrentIrql(), fdo));

    do {
        status = RtlUnicodeStringPrintf(&symbolic_link_name,
           L"%ws", PVPANIC_DOS_DEVICE_NAME);
        status = RtlUnicodeStringPrintf(&device_name,
           L"%ws", PVCRASH_DEVICE_NAME);
        RPRINTK(DPRTL_ON, ("    IoCreateSymbolicLink with:\n"));
        RPRINTK(DPRTL_ON, ("      %ws\n      %ws\n",
            symbolic_link_name.Buffer, device_name.Buffer));

        status = IoCreateSymbolicLink(&symbolic_link_name, &device_name);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: IoCreateSymbolicLink %ws failed 0x%x\n",
                VDEV_DRIVER_NAME, symbolic_link_name.Buffer, status));
            break;
        }

        status = pvcrash_prepare_hardware(fdx, raw, translated);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: pvcrash_prepare_haredware failed: %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }
        KeInitializeCallbackRecord(&bugcheck_cbr);
        res = KeRegisterBugCheckCallback(&bugcheck_cbr,
                                         pvcrash_notify_bugcheck,
                                         fdx->IoBaseAddress,
                                         sizeof(PVOID),
                                         (PUCHAR)("pvcrash_nodify"));
        if (res == FALSE) {
            PRINTK(("%s: KeRegisterBugCheckCallback failed\n",
                    VDEV_DRIVER_NAME));
        }

        KeInitializeCallbackRecord(&dump_cbr);
        if (fdx->support_crash_loaded) {
            res_bchk = KeRegisterBugCheckReasonCallback(
                &dump_cbr,
                pvcrash_on_dump_bugCheck,
                KbCallbackDumpIo,
                (PUCHAR)("pvcrash_nodify"));
        }
        if (res_bchk == FALSE) {
            PRINTK(("%s: KeRegisterBugCheckReasonCallback failed\n",
                    VDEV_DRIVER_NAME));
        }

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
    DECLARE_UNICODE_STRING_SIZE(symbolic_link_name, 128);

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

        RtlUnicodeStringPrintf(&symbolic_link_name,
           L"%ws", PVPANIC_DOS_DEVICE_NAME);
        status = IoDeleteSymbolicLink(&symbolic_link_name);
        if (status != STATUS_SUCCESS) {
            PRINTK(("%s: IoDeleteSymbolicLink for %ws failed %p\n",
                    VDEV_DRIVER_NAME, symbolic_link_name, status));
        }

        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fdx->LowerDevice, Irp);

        RPRINTK(DPRTL_ON, ("    KeDeregisterBugCheckCallback irql %d dev %p\n",
            KeGetCurrentIrql(), DeviceObject));
        KeDeregisterBugCheckCallback(&bugcheck_cbr);

        if (fdx->support_crash_loaded) {
            RPRINTK(DPRTL_ON, ("    KeDeregisterBugCheckReasonCallback\n"));
            KeDeregisterBugCheckReasonCallback(&dump_cbr);
        }

        if (fdx->mapped_port && fdx->IoBaseAddress != NULL) {
            RPRINTK(DPRTL_ON, ("    MmUnmapIoSpace %p\n", fdx->IoBaseAddress));
            MmUnmapIoSpace(fdx->IoBaseAddress, fdx->IoRange);
        }

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
