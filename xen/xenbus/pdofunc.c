/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2026 SUSE LLC
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

#define VENDORNAME L"Xen"
#define VNIFMODEL L"virtual NIC"
#define VBDMODEL L"virtual disk"
#define VSDMODEL L"virtual scsi"
#define VUDMODEL L"virtual usb"
#define UNKNOWNMODEL L"unknown device"

static IO_COMPLETION_ROUTINE PDOSignalCompletion;

NTSTATUS
PDO_Pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PIO_STACK_LOCATION stack;
    POWER_STATE powerState;


    PAGED_CODE();

    pdx = (PPDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    RPRINTK(DPRTL_PNP,
            ("PDO_Pnp: DeviceObject %p, pdx %p, %s\n",
             DeviceObject, pdx, pdx->Nodename));

    switch (stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_START_DEVICE\n"));
        pdx->devpower = PowerDeviceD0;
        pdx->pnpstate = Started;
        powerState.DeviceState = PowerDeviceD0;
        PoSetPowerState (pdx->Self, DevicePowerState, powerState);
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_START_DEVICEed\n"));
        status = STATUS_SUCCESS;
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
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_REMOVE_DEVICE\n"));
        /* TODO: review this section of code */
        if (pdx->ReportedMissing) {
            if (pdx->ParentFdo) {
                fdx = pdx->ParentFdo->DeviceExtension;
            } else if (gfdo) {
                fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
            } else {
                PRINTK(("PDO IRP_MN_REMOVE_DEVICE: fdx = NULL\n"));
                fdx = NULL;
            }

            pdx->pnpstate = Deleted;
            if (fdx) {
                ExAcquireFastMutex(&fdx->Mutex);
                RemoveEntryList(&pdx->Link);
                fdx->NumPDOs--;
                ExReleaseFastMutex(&fdx->Mutex);
            }
            PRINTK(("PDO_Pnp: IRP_MN_REMOVE_DEVICE XenbusDestroyPDO %s\n",
                    pdx->Nodename));
            status = XenbusDestroyPDO(DeviceObject);
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
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_DEVICE_USAGE_NOTIFICATION\n"));
        /* We are not tracking the stack->Parameters.UsageNotification.Type, */
        /* DeviceUsageTypeHibernation or DeviceUsageTypeDumpFile, so just */
        /* complete the request with success. */
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_EJECT:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: IRP_MN_EJECT\n"));
        /*
         * We don't handle this Irp yet, so we leave IoStatus.Status untouched.
         */
        status = Irp->IoStatus.Status;
        break;

    default:
        RPRINTK(DPRTL_PNP, ("PDO_Pnp: default %x\n", stack->MinorFunction));
        status = Irp->IoStatus.Status;
        break;
    }


    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
PDOSignalCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp,
                    IN PVOID Event)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

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

    DPRINTK(DPRTL_ON, ("PDOForwardIrpSynchronous: ParentFdo = %p.\n",
                       pdx->ParentFdo));
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

    /*
     * XXX: I don't fully understand Windows power management mechanism yet.
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

    if (!NT_SUCCESS(status)) {
        PRINTK(("QueryDeviceCaps fail: %x.\n", status));
        return status;
    }

    RtlCopyMemory(
      devcap->DeviceState,
      parentcap.DeviceState,
      (PowerSystemShutdown + 1) * sizeof(DEVICE_POWER_STATE));

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

    /*
     * Specifies whether the device can respond to an external wake
     * signal while in the D0, D1, D2, and D3 state.
     * Set these bits explicitly.
     */

    devcap->WakeFromD0 = FALSE;
    devcap->WakeFromD1 = TRUE;
    devcap->WakeFromD2 = FALSE;
    devcap->WakeFromD3 = FALSE;

    devcap->D1Latency = 0;
    devcap->D2Latency = 0;
    devcap->D3Latency = 0;

    devcap->LockSupported = FALSE;
    devcap->EjectSupported = FALSE;
    devcap->HardwareDisabled = FALSE;
    devcap->Removable = FALSE;
    devcap->SurpriseRemovalOK = TRUE;
    devcap->UniqueID = TRUE;
    devcap->SilentInstall = FALSE;

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

    PAGED_CODE();

    stack = IoGetCurrentIrpStackLocation(Irp);

    switch (stack->Parameters.QueryId.IdType) {
    case BusQueryDeviceID:
        RPRINTK(DPRTL_PNP, ("BusQueryDeviceID.\n"));
        length = pdx->HardwareIDs.Length + 2 * sizeof(WCHAR);

        buffer = EX_ALLOC_POOL(VPOOL_NON_PAGED, length, XENBUS_POOL_TAG);

        if (!buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlZeroMemory(buffer, length);
        RtlStringCchCopyW(buffer, pdx->HardwareIDs.Length,
                          pdx->HardwareIDs.Buffer);

        Irp->IoStatus.Information = (ULONG_PTR) buffer;
        status = STATUS_SUCCESS;
        break;

    case BusQueryInstanceID:
        RPRINTK(DPRTL_PNP, ("BusQueryInstacneID.\n"));
        if (pdx->instance_id) {
            RtlInitAnsiString(&astr, pdx->instance_id);
            length = (USHORT)(strlen(pdx->instance_id) + 1);
        } else {
            RtlInitAnsiString(&astr, pdx->Nodename);
            length = (USHORT)(strlen(pdx->Nodename) + 1);
        }
        status = RtlAnsiStringToUnicodeString(&ustr, &astr, TRUE);
        if (status != STATUS_SUCCESS) {
            break;
        }
        buffer = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                               length * sizeof(WCHAR),
                               XENBUS_POOL_TAG);
        if (!buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlStringCchCopyW(buffer, length, ustr.Buffer);
        RtlFreeUnicodeString(&ustr);

        Irp->IoStatus.Information = (ULONG_PTR) buffer;
        status = STATUS_SUCCESS;
        break;

    case BusQueryHardwareIDs:
        RPRINTK(DPRTL_PNP, ("BusQueryHarwareIDs.\n"));
        length = pdx->HardwareIDs.Length + 2 * sizeof(WCHAR);

        buffer = EX_ALLOC_POOL(VPOOL_NON_PAGED, length, XENBUS_POOL_TAG);

        if (!buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlZeroMemory(buffer, length);
        RtlStringCchCopyW(buffer, pdx->HardwareIDs.Length,
                          pdx->HardwareIDs.Buffer);

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

    switch (stack->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription:
        switch (stack->Parameters.QueryDeviceText.LocaleId) {
        default:
        case 0x00000409:  /* English */
            switch (pdx->Type) {
            case vnif:
                model = VNIFMODEL;
                break;
            case vbd:
                model = VBDMODEL;
                break;
            case vscsi:
                model = VSDMODEL;
                break;
            case vusb:
                model = VUDMODEL;
                break;
            case unknown:
            default:
                model = UNKNOWNMODEL;
                break;
            }

            length = (USHORT)((wcslen(VENDORNAME) + 2 + wcslen(model) + 1));
            buffer = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                   length * sizeof(WCHAR),
                                   XENBUS_POOL_TAG);
            if (buffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            RtlStringCchPrintfW(buffer, length, L"%ws %ws", VENDORNAME,
                                model);

            Irp->IoStatus.Information = (ULONG_PTR) buffer;
            status = STATUS_SUCCESS;
            break;
        }
        break;
    default:
        status = Irp->IoStatus.Status;
        break;
    }

    return status;
}


/* we need no resource for virtual devices */
static NTSTATUS
PDOQueryResources(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PCM_RESOURCE_LIST resourceList;
    PCM_FULL_RESOURCE_DESCRIPTOR frd;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
    PFDO_DEVICE_EXTENSION fdx;
    ULONG  resourceListSize;

    PAGED_CODE();

    if (pdx->Type != vbd && pdx->Type != vscsi) {
        return Irp->IoStatus.Status;
    }
    if (pdx->ParentFdo == NULL) {
        return Irp->IoStatus.Status;
    }

    fdx = pdx->ParentFdo->DeviceExtension;

    resourceListSize = sizeof(CM_RESOURCE_LIST)
        + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);

    resourceList = EX_ALLOC_POOL(VPOOL_PAGED,
                                 resourceListSize,
                                 XENBUS_POOL_TAG);

    if (resourceList == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(resourceList, resourceListSize);
    resourceList->Count = 1;
    frd = &resourceList->List[0];

    frd->PartialResourceList.Version = 1;
    frd->PartialResourceList.Revision = 1;
    frd->PartialResourceList.Count = 2;

    prd = &frd->PartialResourceList.PartialDescriptors[0];
    prd->Type = CmResourceTypeMemory;
    prd->ShareDisposition = CmResourceShareShared;
    prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE;
    prd->u.Memory.Start.QuadPart = fdx->mmio;
    prd->u.Memory.Length = fdx->mmiolen;
    RPRINTK(DPRTL_ON, ("QueryResources: %llx\n",
                       prd->u.Memory.Start.QuadPart));

    /* If an interrupt is not presented, xenblk won't load. */
    prd = &frd->PartialResourceList.PartialDescriptors[1];
    prd->Type = CmResourceTypeInterrupt;
    prd->ShareDisposition = CmResourceShareShared;
    prd->Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
    prd->u.Interrupt.Level = fdx->dirql;
    prd->u.Interrupt.Vector = fdx->dvector;
    prd->u.Interrupt.Affinity = fdx->daffinity;
    RPRINTK(DPRTL_ON, ("Resources found: level %x vector %x\n",
                       prd->u.Interrupt.Level, prd->u.Interrupt.Vector));

    Irp->IoStatus.Information = (ULONG_PTR)resourceList;
    return STATUS_SUCCESS;
}

static NTSTATUS
PDOQueryResourceRequirements(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PIO_RESOURCE_REQUIREMENTS_LIST  resourceList;
    PIO_RESOURCE_DESCRIPTOR descriptor;
    PFDO_DEVICE_EXTENSION fdx;
    ULONG resourceListSize;
    NTSTATUS status;

    PAGED_CODE();

    if (pdx->Type != vbd && pdx->Type != vscsi) {
        return Irp->IoStatus.Status;
    }
    if (pdx->ParentFdo == NULL) {
        return Irp->IoStatus.Status;
    }

    RPRINTK(DPRTL_ON, ("PDOQueryResourceRequirements: %s\n", pdx->Nodename));

    fdx = pdx->ParentFdo->DeviceExtension;

    /*
     * Note the IO_RESOURCE_REQUIREMENTS_LIST structure includes
     * IO_RESOURCE_LIST  List[1]; if we specify more than one
     * resource, we must include IO_RESOURCE_LIST size
     * in the  resourceListSize calculation.
     */
    resourceListSize = sizeof(IO_RESOURCE_REQUIREMENTS_LIST)
        + sizeof(IO_RESOURCE_LIST);

    resourceList = EX_ALLOC_POOL(VPOOL_PAGED,
                                 resourceListSize,
                                 XENBUS_POOL_TAG);

    if (resourceList == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    RtlZeroMemory(resourceList, resourceListSize);

    resourceList->ListSize = resourceListSize;

    /* Initialize the list header. */
    resourceList->AlternativeLists = 1;

    resourceList->List[0].Version = 1;
    resourceList->List[0].Revision = 1;
    resourceList->List[0].Count = 2;

    descriptor = &resourceList->List[0].Descriptors[0];
    descriptor->Option = 0;
    descriptor->Type = CmResourceTypeMemory;
    descriptor->ShareDisposition = CmResourceShareShared;
    descriptor->Flags = CM_RESOURCE_MEMORY_READ_WRITE;
    descriptor->u.Memory.Length = fdx->mmiolen;
    descriptor->u.Memory.Alignment = 0x01;
    descriptor->u.Memory.MinimumAddress.QuadPart = fdx->mmio;
    descriptor->u.Memory.MaximumAddress.QuadPart = fdx->mmio;
    RPRINTK(DPRTL_ON, ("Mem: len %x, min %llx %llx, max %llx\n",
                       fdx->mmiolen - 1,
                       fdx->mmio,
                       descriptor->u.Memory.MinimumAddress.QuadPart,
                       descriptor->u.Memory.MaximumAddress.QuadPart));

    descriptor = &resourceList->List[0].Descriptors[1];
    descriptor->Option = 0;
    descriptor->Type = CmResourceTypeInterrupt;
    descriptor->ShareDisposition = CmResourceShareShared;
    descriptor->Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
    descriptor->u.Interrupt.MinimumVector = fdx->dvector;
    descriptor->u.Interrupt.MaximumVector = fdx->dvector;
    descriptor->u.Interrupt.AffinityPolicy = IrqPolicyAllProcessorsInMachine;
    descriptor->u.Interrupt.PriorityPolicy = IrqPriorityNormal;
    descriptor->u.Interrupt.TargetedProcessors = fdx->daffinity;

    Irp->IoStatus.Information = (ULONG_PTR)resourceList;
    return  STATUS_SUCCESS;
}

static NTSTATUS
PDOQueryDeviceRelations(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    PDEVICE_RELATIONS deviceRelations;
    NTSTATUS status;

    PAGED_CODE();

    stack = IoGetCurrentIrpStackLocation (Irp);

    switch (stack->Parameters.QueryDeviceRelations.Type) {
    case TargetDeviceRelation:
        deviceRelations = (PDEVICE_RELATIONS)
            EX_ALLOC_POOL(VPOOL_NON_PAGED,
                          sizeof(DEVICE_RELATIONS),
                          XENBUS_POOL_TAG);
        if (!deviceRelations) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /*
         * There is only one PDO pointer in the structure
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
        status = Irp->IoStatus.Status;
    }

    return status;
}

static NTSTATUS
PDOQueryBusInformation(IN PPDO_DEVICE_EXTENSION pdx, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(pdx);

    PPNP_BUS_INFORMATION busInfo;

    PAGED_CODE();

    busInfo = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                            sizeof(PNP_BUS_INFORMATION),
                            XENBUS_POOL_TAG);

    if (busInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    busInfo->BusTypeGuid = GUID_DEVCLASS_XENBUS;
    busInfo->LegacyBusType = Internal;
    busInfo->BusNumber = 1;

    Irp->IoStatus.Information = (ULONG_PTR)busInfo;

    return STATUS_SUCCESS;
}

static VOID
PDOInterfaceReference (__in PVOID Context)
{
    PPDO_DEVICE_EXTENSION pdx = (PPDO_DEVICE_EXTENSION)Context;

    InterlockedIncrement((LONG *)&pdx->InterfaceRefCount);
    RPRINTK(DPRTL_ON, ("PDOInterfaceReference: %s cnt = %d\n",
                       pdx->Nodename, pdx->InterfaceRefCount));
}

static VOID
PDOInterfaceDereference (__in PVOID Context)
{
    PPDO_DEVICE_EXTENSION pdx = (PPDO_DEVICE_EXTENSION)Context;

    if (pdx) {
        InterlockedDecrement((LONG *)&pdx->InterfaceRefCount);
        if (pdx->Nodename) {
            RPRINTK(DPRTL_ON, ("PDOInterfaceDereference: %s cnt  %d\n",
                               pdx->Nodename, pdx->InterfaceRefCount));
        } else {
            RPRINTK(DPRTL_ON,
                    ("PDOInterfaceDereference: pdx destroyed, cnt = %d\n",
                     pdx->InterfaceRefCount));
        }
    } else {
        RPRINTK(DPRTL_ON, ("PDOInterfaceDereference: pdx is null.\n"));
    }
}

static BOOLEAN
PDOTranslateBusAddress(IN PVOID  Context,
                       IN PHYSICAL_ADDRESS  BusAddress,
                       IN ULONG  Length,
                       IN OUT PULONG  AddressSpace,
                       OUT PPHYSICAL_ADDRESS  TranslatedAddress)
{
    UNREFERENCED_PARAMETER(Length);

    RPRINTK(DPRTL_ON, ("PDOTranslateBusAddress: %p\n", Context));
    *AddressSpace = 0;
    *TranslatedAddress = BusAddress;
    return TRUE;
}

static DMA_ADAPTER *
PDOGetDmaAdapter(PVOID  Context,
                 DEVICE_DESCRIPTION  *DeviceDescriptor,
                 OUT PULONG  NumberOfMapRegisters)
{
    DMA_ADAPTER *DmaAdapterObject;
    PPDO_DEVICE_EXTENSION pdx;


    RPRINTK(DPRTL_ON, ("PDOGetDmaAdapter: %p\n", Context));
    pdx = (PPDO_DEVICE_EXTENSION)Context;
    *NumberOfMapRegisters = 0;
    if (pdx == NULL) {
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
    RPRINTK(DPRTL_ON,
            (" PDOGetDmaAdapter IoGetDmaAdapter success, MapRegisters %d.\n",
             *NumberOfMapRegisters));
    return DmaAdapterObject;
}

static ULONG
PDOSetBusData(IN PVOID  Context,
              IN ULONG  DataType,
              IN PVOID  Buffer,
              IN ULONG  Offset,
              IN ULONG  Length)
{
    UNREFERENCED_PARAMETER(DataType);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Offset);
    UNREFERENCED_PARAMETER(Length);

    RPRINTK(DPRTL_ON, ("PDOSetBusData: %p\n", Context));
    return 0;
}

static ULONG
PDOGetBusData(IN PVOID  Context,
              IN ULONG  DataType,
              IN PVOID  Buffer,
              IN ULONG  Offset,
              IN ULONG  Length)
{
    UNREFERENCED_PARAMETER(DataType);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Offset);
    UNREFERENCED_PARAMETER(Length);

    RPRINTK(DPRTL_ON, ("PDOGetBusData: %p\n", Context));
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
    RPRINTK(DPRTL_ON, ("PDOQueryInterface: GUID %x\n",
                       interfaceType->Data1));
    if (IsEqualGUID(interfaceType, (PVOID) &GUID_XENBUS_INTERFACE_STANDARD)) {
        RPRINTK(DPRTL_ON, ("PDOQueryInterface: %s,status = %x\n",
                           pdx->Nodename, Irp->IoStatus.Status));

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
            return STATUS_INVALID_PARAMETER;
        }

        std_interface = (BUS_INTERFACE_STANDARD *)
            irpStack->Parameters.QueryInterface.Interface;
        RPRINTK(DPRTL_ON,
            ("PDOQueryInterface: STANDARD %p, %s\n\ts %d\n\tv %d\n\tc %p\n",
             pdx, pdx->Nodename, std_interface->Size, std_interface->Version,
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
    return status;
}

static NTSTATUS
GetDeviceCapabilities(IN PDEVICE_OBJECT DeviceObject,
                      IN PDEVICE_CAPABILITIES DeviceCapabilities)
{
    IO_STATUS_BLOCK     ioStatus;
    KEVENT              pnpEvent;
    NTSTATUS            status;
    PDEVICE_OBJECT      targetObject;
    PIO_STACK_LOCATION  irpStack;
    PIRP                pnpIrp;

    PAGED_CODE();

    /* Initialize the capabilities that we will send down */
    RtlZeroMemory(DeviceCapabilities, sizeof(DEVICE_CAPABILITIES));
    DeviceCapabilities->Size = sizeof(DEVICE_CAPABILITIES);
    DeviceCapabilities->Version = 1;
    DeviceCapabilities->Address = (ULONG)-1;
    DeviceCapabilities->UINumber = (ULONG)-1;

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
        &ioStatus);
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

        /*
         * Block until the irp comes back.
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
            NULL);
        status = ioStatus.Status;

    }

GetDeviceCapabilitiesExit:
    /* Done with reference */
    ObDereferenceObject(targetObject);
    return status;

}
