/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2020 SUSE LLC
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

#include "vrng.h"

DRIVER_INITIALIZE DriverEntry;

DRIVER_ADD_DEVICE vrng_add_device;

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH vrng_dispatch_pnp;

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH vrng_dispatch_power;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH vrng_dispatch_create;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH vrng_dispatch_close;

__drv_dispatchType(IRP_MJ_READ)
DRIVER_DISPATCH vrng_dispatch_read;

__drv_dispatchType(IRP_MJ_SYSTEM_CONTROL)
DRIVER_DISPATCH vrng_dispatch_system_control;

static VOID vrng_unload(IN PDRIVER_OBJECT DriverObject);

static NTSTATUS vrng_dispatch_create_close(PDEVICE_OBJECT DeviceObject,
                                           PIRP Irp);

void (*printk)(char *_fmt, ...);

#ifdef DBG
uint32_t dbg_print_mask =
    DPRTL_ON | DPRTL_INIT | DPRTL_UNEXPD | DPRTL_PNP | DPRTL_PWR;
#else
uint32_t dbg_print_mask = DPRTL_OFF;
#endif

static NTSTATUS vrng_get_startup_params(void);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, vrng_unload)
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
    if (vrng_get_startup_params() != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    DriverObject->DriverExtension->AddDevice = vrng_add_device;
    DriverObject->DriverUnload = NULL;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = vrng_dispatch_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = vrng_dispatch_close;
    DriverObject->MajorFunction[IRP_MJ_READ] = vrng_dispatch_read;
    DriverObject->MajorFunction[IRP_MJ_POWER] = vrng_dispatch_power;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] =
        vrng_dispatch_system_control;
    DriverObject->MajorFunction[IRP_MJ_PNP] = vrng_dispatch_pnp;

    return STATUS_SUCCESS;
}

static NTSTATUS
vrng_add_device(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT pdo)
{
    NTSTATUS status;
    PDEVICE_OBJECT fdo;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    status = IoCreateDevice(
        DriverObject,
        sizeof(FDO_DEVICE_EXTENSION),
        NULL,
        FILE_DEVICE_CRYPT_PROVIDER,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                        /* exclusive */
        &fdo);
    if (!NT_SUCCESS(status)) {
        RPRINTK(DPRTL_ON, ("\tIoCreateDevice returned 0x%x\n", status));
        return status;
    }

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;
    RtlZeroMemory(fdx, sizeof(FDO_DEVICE_EXTENSION));

    RPRINTK(DPRTL_ON, ("    DriverObject = %p, pdo = %p, fdo = %p\n",
                       DriverObject, pdo, fdo));
    RPRINTK(DPRTL_ON, ("    fdx = %p, obj = %p\n", fdx, fdo->DriverObject));

    status = IoRegisterDeviceInterface(pdo,
                                       (LPGUID)&GUID_DEVINTERFACE_VIRT_RNG,
                                       NULL,
                                       &fdx->ifname);
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s: IoRegisterDeviceInterface failed (%x)",
            __func__, status));
        IoDeleteDevice(fdo);
        return status;
    }

    RPRINTK(DPRTL_ON, ("    fdx->ifname: %ws\n", fdx->ifname.Buffer));
    fdx->LowerDevice = IoAttachDeviceToDeviceStack(fdo, pdo);
    if (fdx->LowerDevice == NULL) {
        IoDeleteDevice(fdo);
        return STATUS_NO_SUCH_DEVICE;
    }

    fdx->Pdo = pdo;
    fdx->Self = fdo;
    fdx->IsFdo = TRUE;
    fdx->sig = 0xccddeeff;

    KeInitializeDpc(&fdx->int_dpc, vrng_int_dpc, fdx);
    fdx->pnpstate = NotStarted;
    fdx->devpower = PowerDeviceD0;
    fdx->syspower = PowerSystemWorking;
    fdx->read_buffers_list.Next = NULL;
    KeInitializeSpinLock(&fdx->vq_lock);

    fdo->Flags |=  DO_POWER_PAGABLE;
    fdo->Flags |= DO_BUFFERED_IO;
    fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return STATUS_SUCCESS;
}


static VOID
vrng_unload (IN PDRIVER_OBJECT DriverObject)
{
    PRINTK(("vrng_unload\n"));
    PAGED_CODE();
}

static NTSTATUS
vrng_dispatch_create_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
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
    vrng_complete_request(Irp, IO_NO_INCREMENT);

    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
    return status;
}

static NTSTATUS
vrng_dispatch_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return vrng_dispatch_create_close(DeviceObject, Irp);
}

static NTSTATUS
vrng_dispatch_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return vrng_dispatch_create_close(DeviceObject, Irp);
}

static NTSTATUS
vrng_dispatch_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION fdx;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    status = vrng_read(fdx, Irp);
    if (status != STATUS_PENDING) {
        Irp->IoStatus.Status = status;
        vrng_complete_request(Irp, IO_NO_INCREMENT);
    }
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return status;
}

static NTSTATUS
vrng_dispatch_power(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
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
        vrng_complete_request(Irp, IO_NO_INCREMENT);
        RPRINTK(DPRTL_PWR, ("<-- %s: STATUS_NO_SUCH_DEVICE\n", __func__));
        return STATUS_NO_SUCH_DEVICE;
    }

    status = vrng_fdo_power(DeviceObject, Irp);

    RPRINTK(DPRTL_PWR, ("<-- %s: %x\n", __func__, status));
    return status;
}

static NTSTATUS
vrng_dispatch_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    if (!fdx->IsFdo) {
        /* The PDO, just complete the request with the current status */
        status = Irp->IoStatus.Status;
        vrng_complete_request(Irp, IO_NO_INCREMENT);
        return status;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
    return IoCallDriver(fdx->LowerDevice, Irp);
}

static NTSTATUS
vrng_dispatch_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_PNP, ("vrng_dispatch_pnp\n"));
    fdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (fdx->pnpstate == Deleted) {
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        vrng_complete_request(Irp, IO_NO_INCREMENT);
        return STATUS_NO_SUCH_DEVICE;
    }
    return vrng_fdo_pnp(DeviceObject, Irp);

}

static NTSTATUS
vrng_get_startup_params(void)
{
    RTL_QUERY_REGISTRY_TABLE paramTable[2] = {0};
    WCHAR wbuffer[SYSTEM_START_OPTIONS_LEN] = {0};
    UNICODE_STRING str;
    NTSTATUS status;

    /* Read the registry to see if we are to actually us the PV drivers. */
    str.Length = 0;
    str.MaximumLength = sizeof(wbuffer);
    str.Buffer = wbuffer;

    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    paramTable[0].Name = SYSTEM_START_OPTIONS_WSTR;
    paramTable[0].EntryContext = &str;
    paramTable[0].DefaultType = REG_SZ;
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
            PRINTK(("In safe mode, don't load vrng.\n"));
            return STATUS_UNSUCCESSFUL;
        }
    } else {
        PRINTK(("vseerial: Failed to read registry startup values: 0x%x.\n",
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
                                    VRNG_REG_PARAM_DEVICE_KEY_WSTR,
                                    &paramTable[0],
                                    NULL,
                                    NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("vritio_rng: registry parameter dbg_print_mask = 0x%x.\n",
                dbg_print_mask));
    } else {
        PRINTK(("vritio_rng: Failed to read registry dbg_print_mask 0x%x.\n",
                status));
        PRINTK(("            Use default dbg_print_mask 0x%x.\n",
                dbg_print_mask));
    }
    return STATUS_SUCCESS;
}
