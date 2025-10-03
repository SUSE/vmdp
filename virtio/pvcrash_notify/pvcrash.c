/*
 * Copyright (C) 2015-2017 Red Hat, Inc.
 *
 * Written By: Gal Hammer <ghammer@redhat.com>
 *
 * Copyright 2017-2025 SUSE LLC
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

#include "pvcrash.h"
#include <win_rtlq_flags.h>

DRIVER_INITIALIZE DriverEntry;

DRIVER_ADD_DEVICE pvcrash_add_device;

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH pvcrash_dispatch_pnp;

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH pvcrash_dispatch_power;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH pvcrash_dispatch_create;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH pvcrash_dispatch_close;

__drv_dispatchType(IRP_MJ_READ)
DRIVER_DISPATCH pvcrash_dispatch_read;

__drv_dispatchType(IRP_MJ_SYSTEM_CONTROL)
DRIVER_DISPATCH pvcrash_dispatch_system_control;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH pvcrash_dispatch_device_control;

static VOID pvcrash_unload(IN PDRIVER_OBJECT DriverObject);

static NTSTATUS pvcrash_dispatch_create_close(PDEVICE_OBJECT DeviceObject,
                                              PIRP Irp);

void (*printk)(char *_fmt, ...);

#ifdef DBG
uint32_t dbg_print_mask =
    DPRTL_ON | DPRTL_INIT | DPRTL_UNEXPD | DPRTL_PNP | DPRTL_PWR;
#else
uint32_t dbg_print_mask = DPRTL_OFF;
#endif

PVOID g_pvcrash_port_addr;
PVOID g_pvcrash_mem_addr;
BOOLEAN g_emit_crash_loaded_event;
BOOLEAN g_emit_mem_crash_loaded_event;

static NTSTATUS pvcrash_get_startup_params(void);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, pvcrash_unload)
#endif

NTSTATUS
DriverEntry (
  IN PDRIVER_OBJECT DriverObject,
  IN PUNICODE_STRING RegistryPath)
{
    printk = virtio_dbg_printk;
    KeInitializeSpinLock(&virtio_print_lock);

    PRINTK(("%s loading:\n  Version %s.\n",
            VDEV_DRIVER_NAME, VER_FILEVERSION_STR));
    if (pvcrash_get_startup_params() != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    DriverObject->DriverExtension->AddDevice = pvcrash_add_device;
    DriverObject->DriverUnload = NULL;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = pvcrash_dispatch_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = pvcrash_dispatch_close;
    DriverObject->MajorFunction[IRP_MJ_POWER] = pvcrash_dispatch_power;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] =
        pvcrash_dispatch_system_control;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        pvcrash_dispatch_device_control;
    DriverObject->MajorFunction[IRP_MJ_PNP] = pvcrash_dispatch_pnp;

    g_pvcrash_port_addr = NULL;
    g_pvcrash_mem_addr = NULL;
    g_emit_crash_loaded_event = FALSE;
    g_emit_mem_crash_loaded_event = FALSE;

    return STATUS_SUCCESS;
}

static NTSTATUS
pvcrash_get_startup_params(void)
{
    RTL_QUERY_REGISTRY_TABLE paramTable[2] = {0};
    WCHAR wbuffer[SYSTEM_START_OPTIONS_LEN] = {0};
    UNICODE_STRING str;
    NTSTATUS status;

    /* Read the registry to see if we are to actually us the PV drivers. */
    str.Length = 0;
    str.MaximumLength = sizeof(wbuffer);
    str.Buffer = wbuffer;

    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = SYSTEM_START_OPTIONS_WSTR;
    paramTable[0].EntryContext = &str;
    paramTable[0].DefaultType =
        (REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = L"";
    paramTable[0].DefaultLength = 0;

    status = RtlQueryRegistryValues(
        RTL_REGISTRY_CONTROL | RTL_REGISTRY_OPTIONAL,
        NULL_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status == STATUS_SUCCESS) {
        if (wcsstr(wbuffer, SAFE_BOOT_WSTR)) {
            PRINTK(("In safe mode, don't load %s.\n", VDEV_DRIVER_NAME));
            return STATUS_UNSUCCESSFUL;
        }
    } else {
        PRINTK(("%s: Failed to read registry startup values: 0x%x.\n",
            VDEV_DRIVER_NAME, status));
    }

    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = PVCTRL_DBG_PRINT_MASK_WSTR;
    paramTable[0].EntryContext = &dbg_print_mask;
    paramTable[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = &dbg_print_mask;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES
                                        | RTL_REGISTRY_OPTIONAL,
                                    PVCRASH_REG_PARAM_DEVICE_KEY_WSTR,
                                    &paramTable[0],
                                    NULL,
                                    NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("%s: Use registry dbg_print_mask 0x%x.\n",
                VDEV_DRIVER_NAME, dbg_print_mask));
    } else {
        PRINTK(("%s: Use default dbg_print_mask 0x%x.\n",
                VDEV_DRIVER_NAME, dbg_print_mask));
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
pvcrash_add_device(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT pdo)
{
    NTSTATUS status;
    PDEVICE_OBJECT fdo;
    PFDO_DEVICE_EXTENSION fdx;
    DECLARE_UNICODE_STRING_SIZE(device_name, 128);

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    status = RtlUnicodeStringPrintf(&device_name,
       L"%ws", PVCRASH_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        sizeof(FDO_DEVICE_EXTENSION),
        NULL,
        FILE_DEVICE_ACPI,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                      /* exclusive */
        &fdo);
    if (!NT_SUCCESS(status)) {
        PRINTK(("<-- %s: IoCreateDevice failed 0x%x\n", __func__, status));
        return status;
    }

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;
    RtlZeroMemory(fdx, sizeof(FDO_DEVICE_EXTENSION));

    RPRINTK(DPRTL_ON, ("    DriverObject = %p, pdo = %p, fdo = %p\n",
                       DriverObject, pdo, fdo));
    RPRINTK(DPRTL_ON, ("    fdx = %p, obj = %p\n", fdx, fdo->DriverObject));

    status = IoRegisterDeviceInterface(pdo,
                                       (LPGUID)&GUID_PVCRASH_NOTIFY,
                                       NULL,
                                       &fdx->ifname);
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s: IoRegisterDeviceInterface failed (%x)",
            __func__, status));
        IoDeleteDevice(fdo);
        return status;
    }

    fdx->LowerDevice = IoAttachDeviceToDeviceStack(fdo, pdo);
    if (fdx->LowerDevice == NULL) {
        IoDeleteDevice(fdo);
        RPRINTK(DPRTL_ON, ("<-- %s: STATUS_NO_SUCH_DEVICE\n", __func__));
        return STATUS_NO_SUCH_DEVICE;
    }

    fdx->Pdo = pdo;
    fdx->Self = fdo;
    fdx->IsFdo = TRUE;
    fdx->sig = 0xccddeeff;

    fdx->pnpstate = NotStarted;
    fdx->devpower = PowerDeviceD0;
    fdx->syspower = PowerSystemWorking;

    fdo->Flags |=  DO_POWER_PAGABLE;
    fdo->Flags |= DO_BUFFERED_IO;
    fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return STATUS_SUCCESS;
}


static VOID
pvcrash_unload(IN PDRIVER_OBJECT DriverObject)
{
    PRINTK(("%s\n", __func__));
    PAGED_CODE();
}

static NTSTATUS
pvcrash_dispatch_create_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
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
    pvcrash_complete_request(Irp, IO_NO_INCREMENT);

    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
    return status;
}

static NTSTATUS
pvcrash_dispatch_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    RPRINTK(DPRTL_ON, ("%s\n", __func__));
    return pvcrash_dispatch_create_close(DeviceObject, Irp);
}

static NTSTATUS
pvcrash_dispatch_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    RPRINTK(DPRTL_ON, ("%s\n", __func__));
    return pvcrash_dispatch_create_close(DeviceObject, Irp);
}

static NTSTATUS
pvcrash_dispatch_power(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    PCOMMON_DEVICE_EXTENSION pdx;
    NTSTATUS status;

    RPRINTK(DPRTL_PWR, ("--> %s\n", __func__));
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(irpStack->MajorFunction == IRP_MJ_POWER);

    pdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (pdx->pnpstate == Deleted) {
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        pvcrash_complete_request(Irp, IO_NO_INCREMENT);
        RPRINTK(DPRTL_ON, ("<-- %s: STATUS_NO_SUCH_DEVICE\n", __func__));
        return STATUS_NO_SUCH_DEVICE;
    }

    status = pvcrash_fdo_power(DeviceObject, Irp);

    RPRINTK(DPRTL_PWR, ("<-- %s: %x\n", __func__, status));
    return status;
}

static NTSTATUS
pvcrash_dispatch_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PCOMMON_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_PNP, ("--> %s\n", __func__));
    fdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (fdx->pnpstate == Deleted) {
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        pvcrash_complete_request(Irp, IO_NO_INCREMENT);
        return STATUS_NO_SUCH_DEVICE;
    }

    status = pvcrash_fdo_pnp(DeviceObject, Irp);

    RPRINTK(DPRTL_PWR, ("<-- %s: %x\n", __func__, status));
    return status;

}

static NTSTATUS
pvcrash_dispatch_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    if (!fdx->IsFdo) {
        /* The PDO, just complete the request with the current status */
        status = Irp->IoStatus.Status;
        pvcrash_complete_request(Irp, IO_NO_INCREMENT);
        return status;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return IoCallDriver(fdx->LowerDevice, Irp);
}

static NTSTATUS
pvcrash_dispatch_device_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;
    PIO_STACK_LOCATION stack;
    KLOCK_QUEUE_HANDLE lh;
    PVOID buffer;
    ULONG buf_len;
    ULONG length;
    int i;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    status = STATUS_INVALID_PARAMETER;

    fdx = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    stack = IoGetCurrentIrpStackLocation(Irp);

    buf_len = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_GET_CRASH_DUMP_HEADER:
        if (Irp->MdlAddress == NULL) {
            break;
        }
        buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress,
                                              PVCRASH_MDL_PAGE_PRIORITY);
        status = KeInitializeCrashDumpHeader(DUMP_TYPE_FULL,
                                             0,
                                             buffer,
                                             buf_len,
                                             &length);
        PRINTK(("%s: KeInitializeCrashDumpHeader length %d, status %x\n",
                VDEV_DRIVER_NAME, length, status));

        if (status == STATUS_INVALID_PARAMETER_4 && buffer != NULL
                && buf_len >= sizeof(ULONG)) {
            *(ULONG *)buffer = length;
            status = STATUS_BUFFER_TOO_SMALL;
        }
        Irp->IoStatus.Information = length;
        break;
    default:
        RPRINTK(DPRTL_ON, ("%s: Unknown IOCTL 0x%x\n",
                VDEV_DRIVER_NAME,
                stack->Parameters.DeviceIoControl.IoControlCode));
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    RPRINTK(DPRTL_ON, ("<--%s:, %x\n", __func__, status));
    return status;
}

/* Port based */
VOID
pvcrash_notify_bugcheck(IN PVOID buffer, IN ULONG len)
{
    PRINTK(("--> %s: Write %x to port %p length %d\n",
            __func__, PVPANIC_PANICKED, buffer, len));
    if ((buffer != NULL)
            && (len == sizeof(PVOID))
            && g_emit_crash_loaded_event == FALSE) {
        WRITE_PORT_UCHAR((PUCHAR)buffer, (UCHAR)(PVPANIC_PANICKED));
    }
    PRINTK(("<-- %s\n", __func__));
}

VOID
pvcrash_on_dump_bugCheck(KBUGCHECK_CALLBACK_REASON reason,
                         PKBUGCHECK_REASON_CALLBACK_RECORD record,
                         PVOID data,
                         ULONG length)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(length);

    PRINTK(("--> %s: Write %x to port %p crash_loaded_event %d\n",
            __func__,
            PVPANIC_CRASHLOADED,
            g_pvcrash_port_addr,
            g_emit_crash_loaded_event));

    /* Trigger the PVPANIC_CRASHLOADED event before the crash dump. */
    if ((g_pvcrash_port_addr != NULL)
            && (reason == KbCallbackDumpIo)
            && g_emit_crash_loaded_event == FALSE)
    {
        WRITE_PORT_UCHAR((PUCHAR)g_pvcrash_port_addr,
                         (UCHAR)(PVPANIC_CRASHLOADED));
        g_emit_crash_loaded_event = TRUE;
    }

    /* Deregister BugCheckReasonCallback after PVPANIC_CRASHLOADED trigger. */
    if (g_emit_crash_loaded_event == TRUE) {
        KeDeregisterBugCheckReasonCallback(record);
    }

    PRINTK(("<-- %s\n", __func__));
}

/* Mem based */
VOID
pvcrash_notify_mem_bugcheck(IN PVOID buffer, IN ULONG len)
{
    PRINTK(("--> %s: Write %x to port %p length %d\n",
            __func__, PVPANIC_PANICKED, buffer, len));
    if ((buffer != NULL)
            && (len == sizeof(PVOID))
            && g_emit_mem_crash_loaded_event == FALSE) {
        *(PUCHAR)buffer = (UCHAR)(PVPANIC_PANICKED);
    }
    PRINTK(("<-- %s\n", __func__));
}

VOID
pvcrash_on_dump_mem_bugCheck(KBUGCHECK_CALLBACK_REASON reason,
                             PKBUGCHECK_REASON_CALLBACK_RECORD record,
                             PVOID data,
                             ULONG length)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(length);

    PRINTK(("--> %s: Write %x to mem %p crash_loaded_event %d\n",
            __func__,
            PVPANIC_CRASHLOADED,
            g_pvcrash_mem_addr,
            g_emit_mem_crash_loaded_event));

    /* Trigger the PVPANIC_CRASHLOADED event before the crash dump. */
    if ((g_pvcrash_mem_addr != NULL)
            && (reason == KbCallbackDumpIo)
            && g_emit_mem_crash_loaded_event == FALSE) {
        *(PUCHAR)g_pvcrash_mem_addr = (UCHAR)(PVPANIC_CRASHLOADED);
        g_emit_mem_crash_loaded_event = TRUE;
    }

    /* Deregister BugCheckReasonCallback after PVPANIC_CRASHLOADED trigger. */
    if (g_emit_mem_crash_loaded_event == TRUE) {
        KeDeregisterBugCheckReasonCallback(record);
    }

    PRINTK(("<-- %s\n", __func__));
}

