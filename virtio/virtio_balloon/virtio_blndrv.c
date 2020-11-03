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

#include "virtio_balloon.h"
#include <wdmguid.h>

DRIVER_ADD_DEVICE virtio_bln_add_device;

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH virtio_bln_dispatch_pnp;

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH virtio_bln_dispatch_power;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH virtio_bln_dispatch_create;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH virtio_bln_dispatch_close;

__drv_dispatchType(IRP_MJ_SYSTEM_CONTROL)
DRIVER_DISPATCH virtio_bln_dispatch_system_control;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH virtio_bln_dispatch_device_control;

static VOID virtio_bln_unload(IN PDRIVER_OBJECT DriverObject);

static NTSTATUS virtio_bln_dispatch_create_close(PDEVICE_OBJECT DeviceObject,
                                                 PIRP Irp);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, virtio_bln_unload)
#pragma alloc_text(PAGE, virtio_bln_add_device)
#pragma alloc_text(PAGE, virtio_bln_dispatch_create_close)
#endif

static IO_COMPLETION_ROUTINE virtio_bln_completion;

static NTSTATUS send_irp_synchronous(IN PDEVICE_OBJECT DeviceObject,
                                     IN PIRP Irp);

static NTSTATUS virtio_bln_start_device(IN PDEVICE_OBJECT fdo,
                                       IN PCM_PARTIAL_RESOURCE_LIST raw,
                                       IN PCM_PARTIAL_RESOURCE_LIST translated);

static VOID virtio_bln_remove_device(IN PDEVICE_OBJECT fdo);

PKINTERRUPT DriverInterruptObj;
uint32_t vbnctrl_flags = PVCTRL_USE_BALLOONING;

static uint32_t virtio_balloon_get_startup_params(void);

static void virtio_balloon_finish_fdx_init(PDEVICE_OBJECT fdo,
                                           vbln_dev_extn_t *fdx,
                                           PDEVICE_OBJECT pdo);


NTSTATUS
KvmDriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    DriverObject->DriverExtension->AddDevice = virtio_bln_add_device;
    DriverObject->DriverUnload = NULL;

    DriverObject->MajorFunction[IRP_MJ_PNP] = virtio_bln_dispatch_pnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = virtio_bln_dispatch_power;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = virtio_bln_dispatch_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = virtio_bln_dispatch_close;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] =
        virtio_bln_dispatch_system_control;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        virtio_bln_dispatch_device_control;

    DriverInterruptObj = NULL;

    if (virtio_balloon_get_startup_params() == 0) {
        PRINTK(("virtio_bal: start up params failed.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    if (!(vbnctrl_flags & PVCTRL_USE_BALLOONING)) {
        PRINTK(("virtio_bal: ballooning turned off.\n"));
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}


static VOID
virtio_bln_unload(IN PDRIVER_OBJECT DriverObject) {
    PRINTK(("VBLN: driver unload\n"));
    PAGED_CODE();
}

static NTSTATUS
virtio_bln_add_device(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT pdo)
{
    NTSTATUS status;
    PDEVICE_OBJECT fdo;
    vbln_dev_extn_t *fdx;
    UNICODE_STRING virtio_balloon_dev_name;
    uint32_t shutdown;
    uint32_t notify;

    PAGED_CODE();

    RPRINTK(DPRTL_ON, ("virtio_bal: Add Device\n"));

    RtlInitUnicodeString(&virtio_balloon_dev_name,
                         VIRTIO_BALLOON_DEVICE_NAME_WSTR);

    status = IoCreateDevice(DriverObject,
                            sizeof(vbln_dev_extn_t),
                            &virtio_balloon_dev_name,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,                        /* exclusive */
                            &fdo);
    if (!NT_SUCCESS(status)) {
        PRINTK(("virtio_bal: IoCreateDevice failed (%x)\n", status));
        return status;
    }

    fdx = (vbln_dev_extn_t *)fdo->DeviceExtension;
    RtlZeroMemory(fdx, sizeof(vbln_dev_extn_t));

    RPRINTK(DPRTL_ON,
            ("virtio_bln_add_device: DriverObject = %p, pdo = %p, fdo = %p\n",
            DriverObject, pdo, fdo));
    RPRINTK(DPRTL_ON, ("virtio_bln_add_device: fdx = %p, obj = %p\n",
            fdx, fdo->DriverObject));

    KeInitializeEvent(&fdx->inflate_event, SynchronizationEvent, FALSE);
    KeInitializeEvent(&fdx->deflate_event, SynchronizationEvent, FALSE);
    KeInitializeDpc(&fdx->dpc, virtio_bln_dpc, fdx);
    KeInitializeSpinLock(&fdx->balloon_lock);

    status = IoRegisterDeviceInterface(pdo,
                                      (LPGUID)&GUID_DEVINTERFACE_VIRTIO_BALLOON,
                                       NULL,
                                       &fdx->ifname);
    if (!NT_SUCCESS(status)) {
        PRINTK(("virtio_bal: IoRegisterDeviceInterface failed (%x)", status));
        IoDeleteDevice(fdo);
        return status;
    }

    fdx->LowerDevice = IoAttachDeviceToDeviceStack(fdo, pdo);
    if (fdx->LowerDevice == NULL) {
        PRINTK(("virtio_bal: IoAttachDeviceToDeviceStack failed (%x)",
                status));
        IoDeleteDevice(fdo);
        return STATUS_NO_SUCH_DEVICE;
    }

    fdx->num_pages = 0;
    fdx->presuspend_page_cnt = 1234;
    fdx->Pdo = pdo;
    fdx->Self = fdo;
    fdx->IsFdo = TRUE;
    fdx->worker_running = FALSE;
    fdx->backend_wants_mem_stats = FALSE;
    fdx->has_new_mem_stats = FALSE;
    fdx->sig = VIRTIO_BLN_SIG;

    fdx->pnpstate = NotStarted;
    fdx->devpower = PowerDeviceD0;
    fdx->syspower = PowerSystemWorking;

    fdx->mdl_list.head = NULL;
    fdx->mdl_list.tail = NULL;
    fdx->PendingSIrp = NULL;

    fdo->Flags |= DO_POWER_PAGABLE;
    fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    RPRINTK(DPRTL_ON, ("virtio_bln_add_device: success.\n"));
    return STATUS_SUCCESS;
}

static NTSTATUS
virtio_bln_dispatch_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    vbln_dev_extn_t *fdx;
    PIO_STACK_LOCATION stack;
    PCM_PARTIAL_RESOURCE_LIST raw;
    PCM_PARTIAL_RESOURCE_LIST translated;
    virtio_bln_work_item_t *vwork_item;
    NTSTATUS status;

    fdx = (vbln_dev_extn_t *)DeviceObject->DeviceExtension;
    RPRINTK(DPRTL_PNP, ("virtio_bln_dispatch_pnp irql %d, fdo %d\n",
            KeGetCurrentIrql(), fdx->IsFdo));

    if (fdx->pnpstate == Deleted) {
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NO_SUCH_DEVICE;
    }

    stack = IoGetCurrentIrpStackLocation(Irp);
    switch (stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        RPRINTK(DPRTL_PNP, ("virtio_bln_pnp: IRP_MN_START_DEVICE.\n"));

        status = send_irp_synchronous(fdx->LowerDevice, Irp);
        if (NT_SUCCESS(status)) {
            raw = &stack->Parameters.StartDevice
                .AllocatedResources->List[0].PartialResourceList;
            translated = &stack->Parameters.StartDevice
                .AllocatedResourcesTranslated->List[0].PartialResourceList;
            if (fdx->pnpstate == NotStarted) {
                status = wdm_start_device(DeviceObject, raw, translated);
                if (NT_SUCCESS(status)) {
                    vwork_item = ExAllocatePoolWithTag(NonPagedPoolNx,
                        sizeof(virtio_bln_work_item_t),
                        VIRTIO_BLN_POOL_TAG);
                    if (vwork_item) {
                        vwork_item->fdx = fdx;
                        vwork_item->work_item = NULL;
                        virtio_bln_worker(DeviceObject, vwork_item);
                    }
                }
            } else {
                RPRINTK(DPRTL_ON, (" Starting after a %d\n", fdx->pnpstate));
                fdx->pnpstate = Started;
            }
        }

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;

    case IRP_MN_QUERY_STOP_DEVICE:
        RPRINTK(DPRTL_PNP, ("virtio_bln_pnp:IRP_MN_QUERY_STOP_DEVICE.\n"));
        fdx->pnpstate = StopPending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        RPRINTK(DPRTL_PNP,
                ("virtio_bln_pnp: IRP_MN_CANCEL_STOP_DEVICE.\n"));
        if (fdx->pnpstate == StopPending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_STOP_DEVICE:
        RPRINTK(DPRTL_PNP, ("virtio_bln_pnp: IRP_MN_STOP_DEVICE.\n"));
        /* TODO: Irps and resources */

        fdx->pnpstate = Stopped;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        RPRINTK(DPRTL_PNP, ("virtio_bln_pnp: IRP_MN_QUERY_REMOVE_DEVICE\n"));
        fdx->pnpstate = RemovePending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        RPRINTK(DPRTL_PNP,
                ("virtio_bln_pnp: IRP_MN_CANCEL_REMOVE_DEVICE\n"));
        if (fdx->pnpstate == RemovePending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        RPRINTK(DPRTL_PNP, ("virtio_bln_pnp: IRP_MN_SURPRISE_REMOVAL.\n"));
        fdx->pnpstate = SurpriseRemovePending;
        virtio_bln_remove_device(DeviceObject);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        RPRINTK(DPRTL_PNP, ("virtio_bln_pnp: IRP_MN_REMOVE_DEVICE.\n"));

        if (fdx->pnpstate != SurpriseRemovePending) {
            virtio_bln_remove_device(DeviceObject);
        }
        fdx->pnpstate = Deleted;

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fdx->LowerDevice, Irp);

        /* Seems we crash if we try to print from here down. */
        IoDetachDevice(fdx->LowerDevice);
        IoDeleteDevice(DeviceObject);
        return status;

    default:
        RPRINTK(DPRTL_PNP,
                ("virtio_bln_pnp: default irp %x.\n", stack->MinorFunction));
        break;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(fdx->LowerDevice, Irp);

    return status;
}

static NTSTATUS
virtio_bln_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    if (Irp->PendingReturned == TRUE && Context != NULL) {
        KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
send_irp_synchronous(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    KEVENT event;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           virtio_bln_completion,
                           &event,
                           TRUE,
                           TRUE,
                           TRUE);
    status = IoCallDriver(DeviceObject, Irp);

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

NTSTATUS
wdm_device_powerup(PFDO_DEVICE_EXTENSION fdx)
{
    return STATUS_SUCCESS;
}

void
wdm_device_powerdown(PFDO_DEVICE_EXTENSION fdx)
{
}

static VOID
virtio_bln_remove_device(IN PDEVICE_OBJECT fdo)
{
    vbln_dev_extn_t *fdx;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("virtio_bln_remove_device: in.\n"));

    fdx = (vbln_dev_extn_t *)fdo->DeviceExtension;

    if (fdx->ifname.Buffer != NULL) {
        status = IoSetDeviceInterfaceState(&fdx->ifname, FALSE);
        if (status != STATUS_SUCCESS) {
            PRINTK(("virtio_bln_remove_device: IoSetDeviceInterfaceState %x\n",
                    status));
        }

        ExFreePool(fdx->ifname.Buffer);
        RtlZeroMemory(&fdx->ifname, sizeof(UNICODE_STRING));
    }
    virtio_bln_destroy(fdx);

    PRINTK(("VBLN: device removed.\n"));
}

static NTSTATUS
virtio_bln_dispatch_create_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack;
    vbln_dev_extn_t *fdx;

    PAGED_CODE();

    fdx = (vbln_dev_extn_t *)DeviceObject->DeviceExtension;
    status = STATUS_NO_SUCH_DEVICE;
    if (fdx->pnpstate != Deleted) {
        stack = IoGetCurrentIrpStackLocation(Irp);
        switch (stack->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            status = STATUS_SUCCESS;
            break;
        default:
            break;
        }
        Irp->IoStatus.Information = 0;
    }
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
virtio_bln_dispatch_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    RPRINTK(DPRTL_TRC, ("virtio_bln_dispatch_create: create\n"));
    return virtio_bln_dispatch_create_close(DeviceObject, Irp);
}

static NTSTATUS
virtio_bln_dispatch_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    RPRINTK(DPRTL_TRC, ("virtio_bln_dispatch_close: close\n"));
    return virtio_bln_dispatch_create_close(DeviceObject, Irp);
}

static NTSTATUS
virtio_bln_dispatch_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    vbln_dev_extn_t *fdx;

    RPRINTK(DPRTL_ON, ("virtio_bln_dispatch_system_control\n"));
    fdx = (vbln_dev_extn_t *)DeviceObject->DeviceExtension;
    if (!fdx->IsFdo) {
        /* The PDO, just complete the request with the current status */
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(fdx->LowerDevice, Irp);
}

static NTSTATUS
virtio_bln_dispatch_device_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    vbln_dev_extn_t *fdx;
    PIO_STACK_LOCATION stack;
    KLOCK_QUEUE_HANDLE lh;
    size_t length;
    size_t inlength;
    int i;

    status = STATUS_INVALID_PARAMETER;

    fdx = (vbln_dev_extn_t *)DeviceObject->DeviceExtension;
    RPRINTK(DPRTL_TRC, ("** virtio_bln_dispatch_system_control %p, pnp %x **\n",
                        fdx, fdx->pnpstate));

    stack = IoGetCurrentIrpStackLocation(Irp);
    length = stack->Parameters.DeviceIoControl.OutputBufferLength;
    inlength = stack->Parameters.DeviceIoControl.InputBufferLength;
    RPRINTK(DPRTL_TRC, ("  ioctl %x, in len %d, out len %d\n",
            stack->Parameters.DeviceIoControl.IoControlCode, inlength, length));

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_WANTS_MEMORY_UPDATES:
    {
        DWORD *update;

        if (length >= sizeof(DWORD)) {
            update = (DWORD *)Irp->AssociatedIrp.SystemBuffer;
            *update = 1;
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = length;
            RPRINTK(DPRTL_TRC, ("Balloon wants memroy stats reporting 1\n"));
        } else {
            PRINTK(("Balloon wants memroy stats buffer too small\n"));
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }
    case IOCTL_REPORT_MEMORY_USAGE:
    {
        virtio_bln_stat_t *mstat;

        if (!fdx->stats) {
            /* Most likely being called after a hibernate before init. */
            PRINTK(("Balloon memroy stats null\n"));
            status = STATUS_SUCCESS;
            break;
        }
        if (fdx->pnpstate != Started) {
            status = STATUS_SUCCESS;
            break;
        }
        if (inlength >= sizeof(virtio_bln_stat_t) * VIRTIO_BALLOON_S_NR) {
            mstat = (virtio_bln_stat_t *)Irp->AssociatedIrp.SystemBuffer;
            for (i = 0; i < VIRTIO_BALLOON_S_NR; i++) {
                fdx->stats[i].tag = mstat[i].tag;
                fdx->stats[i].val = mstat[i].val;
                RPRINTK(DPRTL_TRC, ("Mem stat %d: tag %d, val %lld\n",
                    i, fdx->stats[i].tag, fdx->stats[i].val));
                status = STATUS_SUCCESS;
            }

            KeAcquireInStackQueuedSpinLock(&fdx->balloon_lock, &lh);
            RPRINTK(DPRTL_ON, ("virtio_bln_ioctl: has new stats.\n"));
            fdx->has_new_mem_stats = TRUE;
            if (fdx->backend_wants_mem_stats) {
                RPRINTK(DPRTL_ON, ("virtio_bln_ioctl: update stats.\n"));
                virtio_bln_update_stats(fdx);
            }
            KeReleaseInStackQueuedSpinLock(&lh);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
            PRINTK(("Incoming stats buf too small: %d. Needed %d\n",
                    inlength, sizeof(virtio_bln_stat_t) * VIRTIO_BALLOON_S_NR));
        }
        break;
    }
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    RPRINTK(DPRTL_TRC, ("virtio_bln_dispatch_system_control out, %x\n",
                        status));
    return status;
}

static uint32_t
virtio_balloon_get_startup_params(void)
{
    RTL_QUERY_REGISTRY_TABLE paramTable[2] = { 0 };
    WCHAR wbuffer[SYSTEM_START_OPTIONS_LEN] = { 0 };
    UNICODE_STRING str;
    NTSTATUS status;
    uint32_t version;
    uint32_t index_offset;

    /* Read the registry to see if we are to actually us the PV drivers. */
    RPRINTK(DPRTL_ON, ("virtio_balloon_determine_pv_driver_usage\n"));
    str.Length = 0;
    str.MaximumLength = sizeof(wbuffer);
    str.Buffer = wbuffer;

    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    paramTable[0].Name = SYSTEM_START_OPTIONS_WSTR;
    paramTable[0].EntryContext = &str;
    paramTable[0].DefaultType = REG_SZ;
    paramTable[0].DefaultData = L"";
    paramTable[0].DefaultLength = 0;

    status = RtlQueryRegistryValues(RTL_REGISTRY_CONTROL
                                        | RTL_REGISTRY_OPTIONAL,
                                    NULL_WSTR,
                                    &paramTable[0],
                                    NULL,
                                    NULL);
    if (status == STATUS_SUCCESS) {
        RPRINTK(DPRTL_ON, ("SystemStartOptions = %ws.\n", wbuffer));
        if (wcsstr(wbuffer, SAFE_BOOT_WSTR)) {
            RPRINTK(DPRTL_ON, ("In safe mode, don't load virtio_balloon.\n"));
            return 0;
        }
    } else {
        PRINTK(("VBLN: Failed to read registry startup values: 0x%x.\n",
                status));
    }

    vbnctrl_flags = PVCTRL_USE_BALLOONING;
    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    paramTable[0].Name = PVCTRL_FLAGS_WSTR;
    paramTable[0].EntryContext = &vbnctrl_flags;
    paramTable[0].DefaultType = REG_DWORD;
    paramTable[0].DefaultData = &vbnctrl_flags;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES
                                        | RTL_REGISTRY_OPTIONAL,
                                    VIRTIO_BALLOON_DEVICE_KEY_WSTR,
                                    &paramTable[0],
                                    NULL,
                                    NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("VBLN: vbnctrl_flags = 0x%x.\n", vbnctrl_flags));
    } else {
        PRINTK(("VBLN: Failed to read registry vbnctrl_flags 0x%x.\n",
                status));
    }

    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    paramTable[0].Name = PVCTRL_DBG_PRINT_MASK_WSTR;
    paramTable[0].EntryContext = &dbg_print_mask;
    paramTable[0].DefaultType = REG_DWORD;
    paramTable[0].DefaultData = &dbg_print_mask;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES
                                        | RTL_REGISTRY_OPTIONAL,
                                    VIRTIO_BALLOON_DEVICE_KEY_WSTR,
                                    &paramTable[0],
                                    NULL,
                                    NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("VBLN: dbg_print_mask 0x%x.\n", dbg_print_mask));
    } else {
        PRINTK(("VBLN: Failed to read registry dbg_print_mask 0x%x.\n",
                status));
        PRINTK(("      Use default dbg_print_mask 0x%x.\n", dbg_print_mask));
    }

    return 1;
}
