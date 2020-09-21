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
#include <wdmguid.h>

static NTSTATUS PDOQueryDeviceCaps(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp);
static NTSTATUS PDOForwardIrpSynchronous(IN PPDO_DEVICE_EXTENSION pdx,
    IN PIRP Irp);

static NTSTATUS PDOQueryDeviceId(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp);

static NTSTATUS PDOQueryDeviceText(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp);

static NTSTATUS PDOQueryResources(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp);

static NTSTATUS PDOQueryResourceRequirements(IN PPDO_DEVICE_EXTENSION pdx,
    IN PIRP Irp);

static NTSTATUS PDOQueryDeviceRelations(IN PPDO_DEVICE_EXTENSION pdx,
    IN PIRP Irp);

static NTSTATUS PDOQueryBusInformation(IN PPDO_DEVICE_EXTENSION pdx,
    IN PIRP Irp);

static NTSTATUS PDOQueryInterface(IN PPDO_DEVICE_EXTENSION pdx,
    IN PIRP Irp);

static NTSTATUS GetDeviceCapabilities(IN PDEVICE_OBJECT DeviceObject,
    IN PDEVICE_CAPABILITIES DeviceCapabilities);

static TRANSLATE_BUS_ADDRESS PDOTranslateBusAddress;
static GET_DMA_ADAPTER PDOGetDmaAdapter;
static GET_SET_DEVICE_DATA PDOSetBusData;
static GET_SET_DEVICE_DATA PDOGetBusData;
static IO_COMPLETION_ROUTINE PDOSignalCompletion;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, PDO_Pnp)
#pragma alloc_text(PAGE, PDOQueryDeviceCaps)
#pragma alloc_text(PAGE, PDOQueryDeviceId)
#pragma alloc_text(PAGE, PDOQueryDeviceText)
#pragma alloc_text(PAGE, PDOQueryResources)
#pragma alloc_text(PAGE, PDOQueryResourceRequirements)
#pragma alloc_text(PAGE, PDOQueryDeviceRelations)
#pragma alloc_text(PAGE, PDOQueryBusInformation)
#pragma alloc_text(PAGE, PDOQueryInterface)
#pragma alloc_text(PAGE, GetDeviceCapabilities)
#endif

#define VENDORNAME L"Virtio"
#define VSERIAL_MODEL L"virtual Serial"

NTSTATUS
PDO_Pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PPDO_DEVICE_EXTENSION pdx;
    PIO_STACK_LOCATION stack;
    POWER_STATE powerState;


    PAGED_CODE();

    status = STATUS_SUCCESS;
    pdx = (PPDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    RPRINTK(DPRTL_PNP,
        ("--> %s: DeviceObject %p, pdx %p, %d, irql %d\n",
        __func__, DeviceObject, pdx, pdx->port_id, KeGetCurrentIrql()));

    switch (stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_START_DEVICE\n"));

        status = vserial_port_register_interfaces(pdx);

        pdx->devpower = PowerDeviceD0;
        pdx->pnpstate = Started;
        powerState.DeviceState = PowerDeviceD0;
        PoSetPowerState (pdx->Self, DevicePowerState, powerState);
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_START_DEVICE\n"));
        break;

    case IRP_MN_STOP_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_STOP_DEVICE\n"));
        pdx->pnpstate = Stopped;
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_QUERY_STOP_DEVICE\n"));
        pdx->pnpstate = StopPending;
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_CANCEL_STOP_DEVICE\n"));
        if (pdx->pnpstate == StopPending) {
            pdx->pnpstate = Started;
        }
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_QUERY_REMOVE_DEVICE\n"));
        if (pdx->InterfaceRefCount != 0) {
            status = STATUS_UNSUCCESSFUL;
            break;
        }
        pdx->pnpstate = RemovePending;
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_CANCEL_REMOVE_DEVICE\n"));
        if (pdx->pnpstate == RemovePending) {
            pdx->pnpstate = Started;
        }
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_SURPRISE_REMOVAL\n"));
        pdx->pnpstate = SurpriseRemovePending;
        vserial_port_close(pdx);
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_REMOVE_DEVICE\n"));
        /* TODO: review this section of code */
        if (pdx->ReportedMissing) {
            PFDO_DEVICE_EXTENSION fdx;

            pdx->pnpstate = Deleted;
            if (pdx->ParentFdo) {
                fdx = pdx->ParentFdo->DeviceExtension;
                ExAcquireFastMutex(&fdx->Mutex);
                RemoveEntryList(&pdx->Link);
                fdx->NumPDOs--;
                ExReleaseFastMutex(&fdx->Mutex);
            }
            RPRINTK(DPRTL_PNP,
                ("PDO_Pnp: IRP_MN_REMOVE_DEVICE XenbusDestroyPDO %d\n",
                pdx->port_id));
            vserial_destroy_pdo(DeviceObject);
            break;
        }
        if (pdx->Present) {
            pdx->pnpstate = NotStarted;
        }
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_QUERY_CAPABILITIES:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_QUERY_CAPABILITIES\n"));
        status = PDOQueryDeviceCaps(pdx, Irp);
        break;

    case IRP_MN_QUERY_ID:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_QUERY_ID\n"));
        status = PDOQueryDeviceId(pdx, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp:IRP_MN_QUERY_DEVICE_RELATIONS\n"));
        status = PDOQueryDeviceRelations(pdx, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_TEXT:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_QUERY_DEVICE_TEXT\n"));
        status = PDOQueryDeviceText(pdx, Irp);
        break;

    case IRP_MN_QUERY_RESOURCES:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_QUERY_RESOURCES\n"));
        status = PDOQueryResources(pdx, Irp);
        break;

    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
        RPRINTK(DPRTL_PNP,
            ("PDO_Pnp: IRP_MN_QUERY_RESOURCE_REQUIREMENTS\n"));
        status = PDOQueryResourceRequirements(pdx, Irp);
        break;

    case IRP_MN_QUERY_BUS_INFORMATION:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_QUERY_BUS_INFORMATION\n"));
        status = PDOQueryBusInformation(pdx, Irp);
        break;

    case IRP_MN_QUERY_INTERFACE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_QUERY_INTERFACE\n"));
        status = PDOQueryInterface(pdx, Irp);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        RPRINTK(DPRTL_PNP,
            ("PDO_Pnp: IRP_MN_DEVICE_USAGE_NOTIFICATION\n"));
        /* TODO: We are here failing this Irp. For future VBD support,
         * it is possible that Windows may put a page file on a VBD device,
         * So we must properly handle this Irp in the future.
         */
        switch (stack->Parameters.UsageNotification.Type) {

            case DeviceUsageTypePaging: {

                BOOLEAN setPagable;

                if (stack->Parameters.UsageNotification.InPath &&
                   pdx->pnpstate != Started) {

                    /* Device isn't started.  Don't allow adding a
                     * paging file, but allow a removal of one.
                     */
                    status = STATUS_DEVICE_NOT_READY;
                    break;
                }

                /* Ensure that this user thread is not suspended while we
                 *  are holding the PathCountEvent.
                 */
                KeEnterCriticalRegion();

                status = KeWaitForSingleObject(&pdx->PathCountEvent,
                                               Executive, KernelMode,
                                               FALSE, NULL);
                ASSERT(NT_SUCCESS(status));
                status = STATUS_SUCCESS;

                /* If the volume is removable we should try to lock it in
                 * place or unlock it once per paging path count
                 */
                if (pdx->IsFdo) {
                    PRINTK(("PDO_Pnp: pdx->IsFdo lock.\n"));
                }

                /* if removing last paging device, need to set DO_POWER_PAGABLE
                 * bit here, and possible re-set it below on failure.
                 */
                setPagable = FALSE;

                if (!stack->Parameters.UsageNotification.InPath &&
                    pdx->PagingPathCount == 1) {

                    /* removing last paging file
                     * must have DO_POWER_PAGABLE bits set, but only
                     * if noone set the DO_POWER_INRUSH bit
                     */
                    if ((DeviceObject->Flags & DO_POWER_INRUSH) != 0) {
                        RPRINTK(DPRTL_PNP,
                            ("PDO_pnp (%p,%p): Last "
                            "paging file removed, but "
                            "DO_POWER_INRUSH was set, so NOT "
                            "setting DO_POWER_PAGABLE\n",
                            DeviceObject, Irp));
                    } else {
                        RPRINTK(DPRTL_PNP,
                            ("PDO_pnp (%p,%p): Last "
                            "paging file removed, "
                            "setting DO_POWER_PAGABLE\n",
                            DeviceObject, Irp));
                        DeviceObject->Flags |= DO_POWER_PAGABLE;
                        setPagable = TRUE;
                    }

                }

                /* forward the irp before finishing handling the
                 * special cases
                 */
                status = PDOForwardIrpSynchronous(pdx, Irp);

                /* now deal with the failure and success cases.
                 * note that we are not allowed to fail the irp
                 * once it is sent to the lower drivers.
                 */
                if (NT_SUCCESS(status)) {

                    IoAdjustPagingPathCount(
                        &pdx->PagingPathCount,
                        stack->Parameters.UsageNotification.InPath);

                    if (stack->Parameters.UsageNotification.InPath) {
                        if (pdx->PagingPathCount == 1) {
                            RPRINTK(DPRTL_PNP,
                                ("PDO_pnp (%p,%p): "
                                "Clearing PAGABLE bit\n",
                                DeviceObject, Irp));
                            DeviceObject->Flags &= ~DO_POWER_PAGABLE;
                        }
                    }

                } else {

                    /* cleanup the changes done above */
                    if (setPagable == TRUE) {
                        RPRINTK(DPRTL_PNP,
                            ("PDO_pnp (%p,%p): Unsetting "
                            "PAGABLE bit due to irp failure\n",
                            DeviceObject, Irp));
                        DeviceObject->Flags &= ~DO_POWER_PAGABLE;
                        setPagable = FALSE;

                        /* disables prefast warning; defensive coding... */
                        UNREFERENCED_PARAMETER(setPagable);
                    }

                    /* relock or unlock the media if needed. */
                    if (pdx->IsFdo) {
                        PRINTK(("PDO_Pnp: pdx->IsFdo unlock.\n"));
                    }
                }

                /* set the event so the next one can occur. */
                KeSetEvent(&pdx->PathCountEvent,
                           IO_NO_INCREMENT, FALSE);
                KeLeaveCriticalRegion();
                break;
            }

            case DeviceUsageTypeHibernation: {

                IoAdjustPagingPathCount(
                    &pdx->HibernationPathCount,
                    stack->Parameters.UsageNotification.InPath
                    );
                status = PDOForwardIrpSynchronous(pdx, Irp);
                if (!NT_SUCCESS(status)) {
                    IoAdjustPagingPathCount(
                        &pdx->HibernationPathCount,
                        !stack->Parameters.UsageNotification.InPath
                        );
                }

                break;
            }

            case DeviceUsageTypeDumpFile: {
                IoAdjustPagingPathCount(
                    &pdx->DumpPathCount,
                    stack->Parameters.UsageNotification.InPath
                    );
                status = PDOForwardIrpSynchronous(pdx, Irp);
                if (!NT_SUCCESS(status)) {
                    IoAdjustPagingPathCount(
                        &pdx->DumpPathCount,
                        !stack->Parameters.UsageNotification.InPath
                        );
                }

                break;
            }

            default: {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
        break;

    case IRP_MN_EJECT:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_EJECT\n"));
        /* We don't handle this Irp yet, leave IoStatus.Status untouched. */
        status = Irp->IoStatus.Status;
        break;

    default:
        RPRINTK(DPRTL_PNP,
            ("PDO_Pnp: default %x\n", stack->MinorFunction));
        status = Irp->IoStatus.Status;
        break;
    }

    Irp->IoStatus.Status = status;
    vserial_complete_request(Irp, IO_NO_INCREMENT);
    RPRINTK(DPRTL_PNP, ("<-- %s: status %x\n", __func__, status));
    return status;
}

static NTSTATUS
PDOSignalCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Event)
{
    if (Event) {
        KeSetEvent((PKEVENT)Event, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
PDOSendIrpSynchronous(IN PDEVICE_OBJECT TargetDeviceObject, IN PIRP Irp)
{
    KEVENT event;
    NTSTATUS status;

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    ASSERT(TargetDeviceObject != NULL);
    ASSERT(Irp != NULL);
    ASSERT(Irp->StackCount >= TargetDeviceObject->StackSize);

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
    IoSetCompletionRoutine(Irp, PDOSignalCompletion, &event,
                           TRUE, TRUE, TRUE);

    status = IoCallDriver(TargetDeviceObject, Irp);

    if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&event,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);
        status = Irp->IoStatus.Status;
    }

    return status;
}

static NTSTATUS
PDOForwardIrpSynchronous(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION fdx;

    DPRINTK(DPRTL_TRC, ("<--> %s: ParentFdo = %p.\n",
        __func__, pdx->ParentFdo));
    fdx = (PFDO_DEVICE_EXTENSION) pdx->ParentFdo->DeviceExtension;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    return PDOSendIrpSynchronous(fdx->LowerDevice, Irp);
}

static NTSTATUS
PDOQueryDeviceCaps(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    PDEVICE_CAPABILITIES devcap;
    DEVICE_CAPABILITIES parentcap;
    NTSTATUS status;

    PAGED_CODE();

    /* XXX: I don't fully understand Windows power management mechanism yet.
     * This chunck of code is mainly directly copied from DDK samples. As we
     * really don't care more on power state of virtual devices, this may
     * simplified when it's get clear what kind of power management we need.
     */
    stack = IoGetCurrentIrpStackLocation(Irp);

    devcap = stack->Parameters.DeviceCapabilities.Capabilities;

    if (devcap->Version != 1 ||
        devcap->Size < sizeof(DEVICE_CAPABILITIES)) {
        return STATUS_UNSUCCESSFUL;
    }

    status = GetDeviceCapabilities(
      PDX_TO_FDX(pdx)->LowerDevice, &parentcap);
    RPRINTK(DPRTL_ON, ("  returned address %d, uinumber %d\n",
        parentcap.Address,
        parentcap.UINumber));

    if (!NT_SUCCESS(status)) {
        PRINTK(("QueryDeviceCaps fail: %x.\n", status));
        return status;
    }

    RtlCopyMemory(
      devcap->DeviceState,
      parentcap.DeviceState,
      (PowerSystemShutdown+1) * sizeof(DEVICE_POWER_STATE));

    RPRINTK(DPRTL_PNP,
        ("PDOQueryDeviceCaps default DeviceState 1 %x, 2 %x, 3 %x, h %x\n",
        devcap->DeviceState[PowerSystemSleeping1],
        devcap->DeviceState[PowerSystemSleeping2],
        devcap->DeviceState[PowerSystemSleeping3],
        devcap->DeviceState[PowerSystemHibernate]));
    RPRINTK(DPRTL_PNP,
        ("PDOQueryDeviceCaps default WakeFromD0 %x, d1 %x d2 %x d3 %x.\n",
        devcap->WakeFromD0,
        devcap->WakeFromD1,
        devcap->WakeFromD2,
        devcap->WakeFromD3));
    RPRINTK(DPRTL_PNP,
        ("PDOQueryDeviceCaps default DeviceWake %x, SystemWake %x.\n",
        devcap->DeviceWake, devcap->SystemWake));
    RPRINTK(DPRTL_PNP,
        ("PDOQueryDeviceCaps default DeviceD1 %x, D2 %x.\n",
        devcap->DeviceD1,
        devcap->DeviceD2));

    devcap->DeviceState[PowerSystemWorking] = PowerDeviceD0;

    if (devcap->DeviceState[PowerSystemSleeping1] != PowerDeviceD0) {
        devcap->DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
    }

    if (devcap->DeviceState[PowerSystemSleeping2] != PowerDeviceD0) {
        devcap->DeviceState[PowerSystemSleeping2] = PowerDeviceD3;
    }

    if (devcap->DeviceState[PowerSystemSleeping3] != PowerDeviceD0) {
        devcap->DeviceState[PowerSystemSleeping3] = PowerDeviceD3;
    }

    devcap->DeviceWake = PowerDeviceD1;

    devcap->DeviceD1 = TRUE;
    devcap->DeviceD2 = FALSE;

    /* Specifies whether the device can respond to an external wake
     * signal while in the D0, D1, D2, and D3 state.
     * Set these bits explicitly.
     */
    devcap->WakeFromD0 = FALSE;
    devcap->WakeFromD1 = TRUE; /* Yes we can */
    devcap->WakeFromD2 = FALSE;
    devcap->WakeFromD3 = FALSE;

    devcap->D1Latency = 0;
    devcap->D2Latency = 0;
    devcap->D3Latency = 0;

    devcap->LockSupported = FALSE;
    devcap->EjectSupported = TRUE;
    devcap->Removable = TRUE;
    devcap->DockDevice = FALSE;
    devcap->UniqueID = FALSE;
    devcap->SilentInstall = TRUE;
    devcap->RawDeviceOK = TRUE;
    devcap->SurpriseRemovalOK = TRUE;

    devcap->NoDisplayInUI = TRUE;
    devcap->HardwareDisabled = FALSE;

    devcap->Address = pdx->device_id;
    devcap->UINumber = pdx->port_id;

    return STATUS_SUCCESS;
}

static NTSTATUS
PDOQueryDeviceId(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    PWCHAR buffer;
    ULONG length;
    NTSTATUS status;
    ANSI_STRING astr;
    UNICODE_STRING ustr;
    DECLARE_CONST_UNICODE_STRING(device_id, PORT_DEVICE_ID);

    PAGED_CODE();

    stack = IoGetCurrentIrpStackLocation(Irp);

    switch (stack->Parameters.QueryId.IdType) {
    case BusQueryDeviceID:
    case BusQueryHardwareIDs:
        RPRINTK(DPRTL_PNP, ("BusQueryDeviceID/HardwareIDs.\n"));
        length = device_id.Length + sizeof(WCHAR) + sizeof(WCHAR); /* 2 NULLs */

        buffer = ExAllocatePoolWithTag(NonPagedPoolNx, length, VSERIAL_POOL_TAG);

        if (!buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlZeroMemory(buffer, length);
        RtlStringCchCopyW(buffer, device_id.Length, device_id.Buffer);

        RPRINTK(DPRTL_ON, ("  device/hardware id = %ws\n", buffer));
        Irp->IoStatus.Information = (ULONG_PTR) buffer;
        status = STATUS_SUCCESS;
        break;

    case BusQueryInstanceID:
        RPRINTK(DPRTL_PNP, ("BusQueryInstacneID.\n"));
        RtlInitAnsiString(&astr, pdx->instance_id);
        length = strlen(pdx->instance_id) + 1;
        status = RtlAnsiStringToUnicodeString(&ustr, &astr, TRUE);
        if (status != STATUS_SUCCESS) {
            break;
        }
        buffer = ExAllocatePoolWithTag(NonPagedPoolNx, length *sizeof(WCHAR),
            VSERIAL_POOL_TAG);
        if (!buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlStringCchCopyW(buffer, length, ustr.Buffer);
        RtlFreeUnicodeString(&ustr);

        RPRINTK(DPRTL_ON, ("  instance id = %ws\n", buffer));
        Irp->IoStatus.Information = (ULONG_PTR) buffer;
        status = STATUS_SUCCESS;
        break;

    default:
        status = Irp->IoStatus.Status;
    }

    return status;
}

static NTSTATUS
PDOQueryDeviceText(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PWCHAR buffer, model;
    USHORT length;
    PIO_STACK_LOCATION stack;
    NTSTATUS status;

    PAGED_CODE();

    stack = IoGetCurrentIrpStackLocation(Irp);

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    switch (stack->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription:
        switch (stack->Parameters.QueryDeviceText.LocaleId) {
        default:
        case 0x00000409:  /* English */
            model = VSERIAL_MODEL;

            length = (wcslen(L"vportXXpYY") + 2) * sizeof(WCHAR); /* 2 nulls */
            buffer = ExAllocatePoolWithTag(NonPagedPoolNx,
                                           length,
                                           VSERIAL_POOL_TAG);
            if (buffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                PRINTK(("PDOQueryDeviceText failed to allocate memory\n"));
                break;
            }

            RtlStringCchPrintfW(buffer, length, L"vport%up%u", pdx->device_id,
                pdx->port_id);

            RPRINTK(DPRTL_ON, ("  text desc = %ws\n", buffer));
            Irp->IoStatus.Information = (ULONG_PTR) buffer;
            status = STATUS_SUCCESS;
            break;
        }
        break;
    case DeviceTextLocationInformation:
        length = (wcslen(VSERIAL_TEXT_LOCATION_NAME_WSTR) + 2) * sizeof(WCHAR);
        buffer = ExAllocatePoolWithTag(NonPagedPoolNx, length, VSERIAL_POOL_TAG);
        if (buffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            PRINTK(("PDOQueryDeviceText Location failed to alloc memory\n"));
            break;
        }

        RtlStringCchPrintfW(buffer, length, VSERIAL_TEXT_LOCATION_NAME_WSTR);

        RPRINTK(DPRTL_ON, ("  text location info = %ws\n", buffer));
        Irp->IoStatus.Information = (ULONG_PTR) buffer;
        status = STATUS_SUCCESS;
        break;
    default:
        RPRINTK(DPRTL_ON, ("  unknown query text type %x\n",
            stack->Parameters.QueryDeviceText.DeviceTextType));
        status = Irp->IoStatus.Status;
        break;
    }

    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
    return status;
}


/* we need no resource for virtual devices */
static NTSTATUS
PDOQueryResources(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PAGED_CODE();

    return Irp->IoStatus.Status;
}

static NTSTATUS
PDOQueryResourceRequirements(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PAGED_CODE();

    return Irp->IoStatus.Status;
}

static NTSTATUS
PDOQueryDeviceRelations(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    PDEVICE_RELATIONS deviceRelations;
    NTSTATUS status;

    PAGED_CODE();

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    stack = IoGetCurrentIrpStackLocation (Irp);

    switch (stack->Parameters.QueryDeviceRelations.Type) {
    case TargetDeviceRelation:
        RPRINTK(DPRTL_ON, ("  TargetDeviceRelation\n"));
        deviceRelations = (PDEVICE_RELATIONS)
            ExAllocatePoolWithTag (NonPagedPoolNx,
                                   sizeof(DEVICE_RELATIONS),
                                   VSERIAL_POOL_TAG);
        if (!deviceRelations) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* There is only one PDO pointer in the structure
         * for this relation type. The PnP Manager removes
         * the reference to the PDO when the driver or application
         * un-registers for notification on the device.
         */
        deviceRelations->Count = 1;
        deviceRelations->Objects[0] = pdx->Self;
        ObReferenceObject(pdx->Self);

        status = STATUS_SUCCESS;
        Irp->IoStatus.Information = (ULONG_PTR) deviceRelations;
        break;

    case BusRelations:
    case EjectionRelations:
    case RemovalRelations:
    default:
        RPRINTK(DPRTL_ON, ("  not handled %x\n",
            stack->Parameters.QueryDeviceRelations.Type));
        status = Irp->IoStatus.Status;
    }

    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
    return status;
}

static NTSTATUS
PDOQueryBusInformation(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{

    PPNP_BUS_INFORMATION busInfo;

    PAGED_CODE();

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    busInfo = ExAllocatePoolWithTag (
        NonPagedPoolNx,
        sizeof(PNP_BUS_INFORMATION),
        VSERIAL_POOL_TAG);

    if (busInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    busInfo->BusTypeGuid = GUID_DEVCLASS_PORT_DEVICE;
    busInfo->LegacyBusType = PNPBus;
    busInfo->BusNumber = pdx->device_id;

    Irp->IoStatus.Information = (ULONG_PTR)busInfo;

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return STATUS_SUCCESS;
}

static VOID
PDOInterfaceReference (__in PVOID Context)
{
    PPDO_DEVICE_EXTENSION pdx = (PPDO_DEVICE_EXTENSION)Context;

    InterlockedIncrement(&pdx->InterfaceRefCount);
    RPRINTK(DPRTL_ON, ("PDOInterfaceReference: %d cnt = %d\n",
         pdx->port_id, pdx->InterfaceRefCount));
}

static VOID
PDOInterfaceDereference (__in PVOID Context)
{
    PPDO_DEVICE_EXTENSION pdx = (PPDO_DEVICE_EXTENSION)Context;

    if (pdx) {
        InterlockedDecrement(&pdx->InterfaceRefCount);
        RPRINTK(DPRTL_ON, ("<--> %s: port_id %d cnt = %d\n",
            __func__, pdx->port_id, pdx->InterfaceRefCount));
    } else {
        RPRINTK(DPRTL_ON, ("<--> %s: pdx is null.\n", __func__));
    }
}

static BOOLEAN
PDOTranslateBusAddress(
    IN PVOID  Context,
    IN PHYSICAL_ADDRESS  BusAddress,
    IN ULONG  Length,
    IN OUT PULONG  AddressSpace,
    OUT PPHYSICAL_ADDRESS  TranslatedAddress)
{
    RPRINTK(DPRTL_ON, ("PDOTranslateBusAddress: %p\n", Context));
    *AddressSpace = 0;
    *TranslatedAddress = BusAddress;
    return TRUE;
}

static DMA_ADAPTER *
PDOGetDmaAdapter(
    PVOID  Context,
    DEVICE_DESCRIPTION  *DeviceDescriptor,
    OUT PULONG  NumberOfMapRegisters)
{
    DMA_ADAPTER *DmaAdapterObject;
    PPDO_DEVICE_EXTENSION pdx;


    RPRINTK(DPRTL_ON, ("--> %s: context %p\n", __func__, Context));
    pdx = (PPDO_DEVICE_EXTENSION)Context;
    *NumberOfMapRegisters = 0;
    if (pdx == NULL) {
        RPRINTK(DPRTL_ON, ("<-- %s: pdx == NULLn", __func__));
        return NULL;
    }
    RPRINTK(DPRTL_ON, (" PDOGetDmaAdapter calling IoGetDmaAdapter.\n"));
    DmaAdapterObject = IoGetDmaAdapter(
        ((PFDO_DEVICE_EXTENSION)pdx->ParentFdo->DeviceExtension)->Pdo,
        DeviceDescriptor,
        NumberOfMapRegisters);
    if (DmaAdapterObject == NULL) {
        RPRINTK(DPRTL_ON, (" PDOGetDmaAdapter IoGetDmaAdapter failed.\n"));
    }
    RPRINTK(DPRTL_ON, ("<-- %s: success, MapRegisters %d.\n",
         __func__, *NumberOfMapRegisters));
    return DmaAdapterObject;
}

static ULONG
PDOSetBusData(
    IN PVOID  Context,
    IN ULONG  DataType,
    IN PVOID  Buffer,
    IN ULONG  Offset,
    IN ULONG  Length)
{
    RPRINTK(DPRTL_ON, ("<--> %s: context %p\n", __func__, Context));
    return 0;
}

static ULONG
PDOGetBusData(
    IN PVOID  Context,
    IN ULONG  DataType,
    IN PVOID  Buffer,
    IN ULONG  Offset,
    IN ULONG  Length)
{
    RPRINTK(DPRTL_ON, ("<--> %s: context %p\n", __func__, Context));
    return 0;
}

static NTSTATUS
PDOQueryInterface(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    PINTERFACE interface;
    BUS_INTERFACE_STANDARD *std_interface;
    GUID *interfaceType;
    NTSTATUS    status = STATUS_SUCCESS;

    PAGED_CODE();

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    interfaceType = (GUID *) irpStack->Parameters.QueryInterface.InterfaceType;
    RPRINTK(DPRTL_ON, ("--> %s: GUID %x\n", __func__, interfaceType->Data1));
    if (IsEqualGUID(interfaceType, (PVOID)&GUID_VSERIAL_INTERFACE_STANDARD)) {
        RPRINTK(DPRTL_ON, ("PDOQueryInterface: %d,status = %x\n", pdx->port_id,
            Irp->IoStatus.Status));

        if (irpStack->Parameters.QueryInterface.Size < sizeof(INTERFACE)) {
            return STATUS_INVALID_PARAMETER;
        }

        interface = irpStack->Parameters.QueryInterface.Interface;

        interface->InterfaceReference   =
            (PINTERFACE_REFERENCE) PDOInterfaceReference;
        interface->InterfaceDereference =
            (PINTERFACE_DEREFERENCE) PDOInterfaceDereference;

        /* Must take a reference before returning */
        PDOInterfaceReference(pdx);
    } else if (IsEqualGUID(interfaceType,
                           (PVOID)&GUID_BUS_INTERFACE_STANDARD)) {
        if (irpStack->Parameters.QueryInterface.Size
                < sizeof(BUS_INTERFACE_STANDARD)) {
            RPRINTK(DPRTL_ON, ("<-- %s: STATUS_INVALID_PARAMETER\n", __func__));
            return STATUS_INVALID_PARAMETER;
        }

        std_interface = (BUS_INTERFACE_STANDARD *)
            irpStack->Parameters.QueryInterface.Interface;
        RPRINTK(DPRTL_ON,
            ("PDOQueryInterface: STANDARD %p, %d\n\ts %d\n\tv %d\n\tc %p\n",
            pdx, pdx->port_id, std_interface->Size, std_interface->Version,
            std_interface->Context));

        std_interface->Size = sizeof(BUS_INTERFACE_STANDARD);
        std_interface->Version = 1;
        std_interface->Context = pdx;
        std_interface->InterfaceReference   =
            (PINTERFACE_REFERENCE)PDOInterfaceReference;
        std_interface->InterfaceDereference =
            (PINTERFACE_DEREFERENCE)PDOInterfaceDereference;
        std_interface->TranslateBusAddress = PDOTranslateBusAddress;
        std_interface->GetDmaAdapter = PDOGetDmaAdapter;
        std_interface->SetBusData = PDOSetBusData;
        std_interface->GetBusData = PDOGetBusData;

        /* Must take a reference before returning */
        PDOInterfaceReference(pdx);
    } else {
        /* Interface type not supported */
        status = Irp->IoStatus.Status;
    }
    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
    return status;
}

static NTSTATUS
GetDeviceCapabilities(
  IN PDEVICE_OBJECT DeviceObject,
  IN PDEVICE_CAPABILITIES DeviceCapabilities)
{
    IO_STATUS_BLOCK     ioStatus;
    KEVENT              pnpEvent;
    NTSTATUS            status;
    PDEVICE_OBJECT      targetObject;
    PIO_STACK_LOCATION  irpStack;
    PIRP                pnpIrp;

    PAGED_CODE();

    /*
     * Initialize the capabilities that we will send down
     */
    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    RtlZeroMemory(DeviceCapabilities, sizeof(DEVICE_CAPABILITIES));
    DeviceCapabilities->Size = sizeof(DEVICE_CAPABILITIES);
    DeviceCapabilities->Version = 1;
    DeviceCapabilities->Address = -1;
    DeviceCapabilities->UINumber = -1;

    /* Initialize the event */
    KeInitializeEvent(&pnpEvent, NotificationEvent, FALSE);

    targetObject = IoGetAttachedDeviceReference(DeviceObject);

    /* Build an Irp */
    pnpIrp = IoBuildSynchronousFsdRequest(
        IRP_MJ_PNP,
        targetObject,
        NULL,
        0,
        NULL,
        &pnpEvent,
        &ioStatus
        );
    if (pnpIrp == NULL) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto GetDeviceCapabilitiesExit;

    }

    /* Pnp Irps all begin life as STATUS_NOT_SUPPORTED; */
    pnpIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    /* Get the top of stack */
    irpStack = IoGetNextIrpStackLocation(pnpIrp);

    /* Set the top of stack */
    RtlZeroMemory(irpStack, sizeof(IO_STACK_LOCATION));
    irpStack->MajorFunction = IRP_MJ_PNP;
    irpStack->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    irpStack->Parameters.DeviceCapabilities.Capabilities = DeviceCapabilities;

    /* Call the driver */
    status = IoCallDriver(targetObject, pnpIrp);
    if (status == STATUS_PENDING) {

        /* Block until the irp comes back.
         * Important thing to note here is when you allocate
         * the memory for an event in the stack you must do a
         * KernelMode wait instead of UserMode to prevent
         * the stack from getting paged out.
         */
        KeWaitForSingleObject(
            &pnpEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        status = ioStatus.Status;
    }

GetDeviceCapabilitiesExit:
    /* Done with reference */
    ObDereferenceObject(targetObject);
    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
    return status;
}
