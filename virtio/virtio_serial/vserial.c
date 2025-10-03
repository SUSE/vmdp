/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2014-2025 SUSE LLC
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
#include <win_rtlq_flags.h>

DRIVER_INITIALIZE DriverEntry;

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH vserial_dispatch_pnp;

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH vserial_dispatch_power;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH vserial_dispatch_create;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH vserial_dispatch_close;

__drv_dispatchType(IRP_MJ_READ)
DRIVER_DISPATCH vserial_dispatch_read;

__drv_dispatchType(IRP_MJ_WRITE)
DRIVER_DISPATCH vserial_dispatch_write;

__drv_dispatchType(IRP_MJ_SYSTEM_CONTROL)
DRIVER_DISPATCH vserial_dispatch_system_control;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH vserial_dispatch_device_control;

__drv_dispatchType(IRP_MJ_INTERNAL_DEVICE_CONTROL)
DRIVER_DISPATCH vserial_dispatch_internal_device_control;

static VOID VSerialUnload(IN PDRIVER_OBJECT DriverObject);

static NTSTATUS VSerialDispatchCreateClose(PDEVICE_OBJECT DeviceObject,
                                           PIRP Irp);

void (*printk)(char *_fmt, ...);

#ifdef DBG
uint32_t dbg_print_mask =
    DPRTL_ON | DPRTL_INIT | DPRTL_UNEXPD | DPRTL_PNP | DPRTL_PWR;
#else
uint32_t dbg_print_mask = DPRTL_OFF;
#endif

static NTSTATUS vserial_get_startup_params(void);

void **ginfo;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, VSerialUnload)
#endif

NTSTATUS
DriverEntry (
  IN PDRIVER_OBJECT DriverObject,
  IN PUNICODE_STRING RegistryPath)
{
    printk = virtio_dbg_printk;
    KeInitializeSpinLock(&virtio_print_lock);

    PRINTK(("VSerial loading:\n  Version %s.\n", VER_FILEVERSION_STR));
    if (vserial_get_startup_params() != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    DriverObject->DriverExtension->AddDevice = vserial_add_device;
    DriverObject->DriverUnload = NULL;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = vserial_dispatch_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = vserial_dispatch_close;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = vserial_dispatch_write;
    DriverObject->MajorFunction[IRP_MJ_READ] = vserial_dispatch_read;
    DriverObject->MajorFunction[IRP_MJ_POWER] = vserial_dispatch_power;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] =
        vserial_dispatch_system_control;
    DriverObject->MajorFunction[IRP_MJ_PNP] = vserial_dispatch_pnp;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        vserial_dispatch_device_control;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
        vserial_dispatch_internal_device_control;

    return STATUS_SUCCESS;
}


static VOID
VSerialUnload (IN PDRIVER_OBJECT DriverObject)
{
    PRINTK(("VSerialUnload\n"));
    PAGED_CODE();
}

static NTSTATUS
vserial_dispatch_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_PNP, ("VSerialDispatchPnp\n"));
    fdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (fdx->pnpstate == Deleted) {
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        vserial_complete_request(Irp, IO_NO_INCREMENT);
        return STATUS_NO_SUCH_DEVICE;
    }

    if (fdx->IsFdo) {
        return FDO_Pnp(DeviceObject, Irp);
    } else {
        return PDO_Pnp(DeviceObject, Irp);
    }
}

static NTSTATUS
VSerialDispatchCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (fdx->pnpstate == Deleted) {
        RPRINTK(DPRTL_ON, ("    STATUS_NO_SUCH_DEVICE\n", __func__));
        status = STATUS_NO_SUCH_DEVICE;
        goto END;
    } else {
        if (fdx->IsFdo) {
            status = STATUS_SUCCESS;
        } else {
            stack = IoGetCurrentIrpStackLocation(Irp);

            switch (stack->MajorFunction) {
            case IRP_MJ_CREATE:
                status = vserial_port_create((PPDO_DEVICE_EXTENSION)fdx);
                break;
            case IRP_MJ_CLOSE:
                vserial_port_close((PPDO_DEVICE_EXTENSION)fdx);
                RPRINTK(DPRTL_ON, ("  IRP_MJ_CLOSE\n"));
                status = STATUS_SUCCESS;
                break;

            default:
                RPRINTK(DPRTL_ON, ("%s: unknown major function %x\n",
                    __func__, stack->MajorFunction));
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
    }

    Irp->IoStatus.Information = 0;

 END:
    Irp->IoStatus.Status = status;
    vserial_complete_request(Irp, IO_NO_INCREMENT);

    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
    return status;
}

static NTSTATUS
vserial_dispatch_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return VSerialDispatchCreateClose(DeviceObject, Irp);
}

static NTSTATUS
vserial_dispatch_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return VSerialDispatchCreateClose(DeviceObject, Irp);
}

static NTSTATUS
vserial_dispatch_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION fdx;
    NTSTATUS status;

    fdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    DPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    if (fdx->IsFdo) {
        status = STATUS_SUCCESS;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        vserial_complete_request(Irp, IO_NO_INCREMENT);
    } else {
        status = vserial_port_read((PPDO_DEVICE_EXTENSION)fdx, Irp);
    }

    DPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return status;
}

static NTSTATUS
vserial_dispatch_write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION fdx;
    NTSTATUS status;

    fdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    DPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    if (fdx->IsFdo) {
        status = STATUS_SUCCESS;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        vserial_complete_request(Irp, IO_NO_INCREMENT);
    } else {
        status = vserial_port_write((PPDO_DEVICE_EXTENSION)fdx, Irp);
    }

    DPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return status;
}

static NTSTATUS
vserial_dispatch_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    if (!fdx->IsFdo) {
        /* The PDO, just complete the request with the current status */
        status = Irp->IoStatus.Status;
        vserial_complete_request(Irp, IO_NO_INCREMENT);
        return status;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return IoCallDriver(fdx->LowerDevice, Irp);
}

static NTSTATUS
vserial_dispatch_device_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PCOMMON_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    fdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    RPRINTK(DPRTL_TRC, ("<--> %s\n", __func__));
    if (fdx->IsFdo) {
        status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Status = status;
        vserial_complete_request(Irp, IO_NO_INCREMENT);
    } else {
        status = vserial_port_device_control((PPDO_DEVICE_EXTENSION)fdx, Irp);
    }

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return status;
}

static NTSTATUS
vserial_dispatch_internal_device_control(IN PDEVICE_OBJECT DeviceObject,
                                         IN PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("<--> %s\n", __func__));
    return vserial_dispatch_device_control(DeviceObject, Irp);
}

NTSTATUS
vserial_get_reg_value(PWSTR key, PWSTR name, DWORD *value)
{
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(uint32_t)];
    HANDLE registryKey;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    NTSTATUS status;
    ULONG len;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    status = vserial_open_key(key, &registryKey);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&valueName, name);
        status = ZwQueryValueKey(registryKey,
            &valueName,
            KeyValuePartialInformation,
            buffer,
            sizeof(buffer),
            &len);
        if (NT_SUCCESS(status)) {
            *value = *((uint32_t *)
                &(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
        }
        ZwClose(registryKey);
    }
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return status;
}

NTSTATUS
vserial_set_reg_value(PWSTR key, PWSTR name, DWORD value)
{
    HANDLE registryKey;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    status = vserial_open_key(key, &registryKey);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&valueName, name);
        status = ZwSetValueKey(registryKey,
            &valueName,
            0,
            REG_DWORD,
            &value,
            sizeof(uint32_t));
        ZwClose(registryKey);
    }
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return status;
}

NTSTATUS
vserial_open_key(PWSTR key_wstr, HANDLE *registryKey)
{
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;

    RtlInitUnicodeString(&keyName, key_wstr);

    InitializeObjectAttributes(&objectAttributes,
        &keyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    return ZwOpenKey(registryKey, KEY_ALL_ACCESS, &objectAttributes);
}

static NTSTATUS
vserial_get_startup_params(void)
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
            PRINTK(("In safe mode, don't load vserial.\n"));
            return STATUS_UNSUCCESSFUL;
        }
    } else {
        PRINTK(("vseerial: Failed to read registry startup values: 0x%x.\n",
            status));
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
                                    VSERIAL_REG_PARAM_DEVICE_KEY_WSTR,
                                    &paramTable[0],
                                    NULL,
                                    NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("%s: dbg_print_mask 0x%x.\n",
                VDEV_DRIVER_NAME, dbg_print_mask));
    } else {
        PRINTK(("%s: Failed to read registry dbg_print_mask 0x%x.\n",
                VDEV_DRIVER_NAME, status));
        PRINTK(("         Use default dbg_print_mask 0x%x.\n", dbg_print_mask));
    }
    return STATUS_SUCCESS;
}
