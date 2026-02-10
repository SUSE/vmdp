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
#include "xen_support.h"
#include <win_rtlq_flags.h>

DRIVER_ADD_DEVICE XenbusAddDevice;

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH XenbusDispatchPnp;

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH XenbusDispatchPower;

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH XenbusDispatchCreate;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH XenbusDispatchClose;

__drv_dispatchType(IRP_MJ_SYSTEM_CONTROL)
DRIVER_DISPATCH XenbusDispatchSystemControl;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH XenbusDispatchDeviceControl;

DRIVER_UNLOAD XenbusUnload;

static NTSTATUS XenbusDispatchCreateClose(PDEVICE_OBJECT DeviceObject,
                                          PIRP Irp);

PUCHAR hypercall_page;
PDEVICE_OBJECT gfdo;
PFDO_DEVICE_EXTENSION gfdx;
void **ginfo;
void **gsinfo;
uint32_t use_pv_drivers;
uint32_t delayed_resource_try_cnt;
uint32_t pvctrl_flags;
uint32_t max_disk_targets;
uint32_t g_max_segments_per_request;
uint32_t gNR_GRANT_FRAMES;
uint32_t gNR_GRANT_ENTRIES;
uint32_t gGNTTAB_LIST_END;

static uint32_t xenbus_get_startup_params(void);

static void xenbus_finish_fdx_init(PDEVICE_OBJECT fdo,
    PFDO_DEVICE_EXTENSION fdx,
    PDEVICE_OBJECT pdo);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, XenbusUnload)
#pragma alloc_text(PAGE, XenbusAddDevice)
#pragma alloc_text(PAGE, XenbusUnload)
#pragma alloc_text(PAGE, XenbusDispatchCreateClose)
#pragma alloc_text(PAGE, XenbusDispatchDeviceControl)
#endif

NTSTATUS
XenDriverEntry (IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverExtension->AddDevice = XenbusAddDevice;
    DriverObject->DriverUnload = NULL;

    DriverObject->MajorFunction[IRP_MJ_PNP] = XenbusDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = XenbusDispatchPower;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = XenbusDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = XenbusDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] =
        XenbusDispatchSystemControl;
#ifdef XENBUS_HAS_IOCTLS
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        XenbusDispatchDeviceControl;
#endif

    if (xenbus_get_startup_params() == 0) {
        PRINTK(("Xenbus: returning STATUS_UNSUCCESSFUL\n"));
        return STATUS_UNSUCCESSFUL;
    }

    if (InitializeHypercallPage() == STATUS_SUCCESS) {
        ginfo = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                              max_disk_targets * sizeof(void *),
                              XENBUS_POOL_TAG);

        if (ginfo == NULL) {
            return STATUS_UNSUCCESSFUL;
        }
        gsinfo = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                               max_disk_targets * sizeof(void *),
                               XENBUS_POOL_TAG);

        if (gsinfo == NULL) {
            ExFreePool(ginfo);
            return STATUS_UNSUCCESSFUL;
        }

        g_gnttab_list = EX_ALLOC_POOL (
            VPOOL_NON_PAGED,
            gNR_GRANT_ENTRIES * sizeof(grant_ref_t),
            XENBUS_POOL_TAG);

        if (g_gnttab_list == NULL) {
            return STATUS_UNSUCCESSFUL;
        }

        memset(ginfo, 0, max_disk_targets * sizeof(void *));
        memset(gsinfo, 0, max_disk_targets * sizeof(void *));
    }

    return STATUS_SUCCESS;
}


VOID
XenbusUnload (IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PRINTK(("XenbusUnload\n"));
    PAGED_CODE();
}

NTSTATUS
XenbusAddDevice (IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT pdo)
{
    NTSTATUS status;
    PDEVICE_OBJECT fdo;
    PFDO_DEVICE_EXTENSION fdx;
    UNICODE_STRING xenbus_dev_name;
    uint32_t shutdown;
    uint32_t notify;

    PAGED_CODE();

    RPRINTK(DPRTL_ON, ("xenbusdrv.sys: Add Device\n"));

    RtlInitUnicodeString(&xenbus_dev_name, XENBUS_DEVICE_NAME_WSTR);

    status = IoCreateDevice(
        DriverObject,
        sizeof(FDO_DEVICE_EXTENSION),
        &xenbus_dev_name,
        FILE_DEVICE_BUS_EXTENDER,     /* bus driver */
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                        /* exclusive */
        &fdo);
    if (!NT_SUCCESS(status)) {
        PRINTK(("\tIoCreateDevice returned 0x%x\n", status));
        return status;
    }

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;
    RtlZeroMemory(fdx, sizeof(FDO_DEVICE_EXTENSION));

    RPRINTK(DPRTL_ON,
        ("XenbusAddDevice: DriverObject = %p, pdo = %p, fdo = %p\n",
         DriverObject, pdo, fdo));
    RPRINTK(DPRTL_ON, ("XenbusAddDevice: fdx = %p, obj = %p\n",
         fdx, fdo->DriverObject));

    status = IoRegisterDeviceInterface(
        pdo,
        (LPGUID)&GUID_DEVINTERFACE_XENBUS,
        NULL,
        &fdx->ifname);
    if (!NT_SUCCESS(status)) {
        PRINTK(("xenbusdrv.sys: IoRegisterDeviceInterface failed (%x)",
            status));
        IoDeleteDevice(fdo);
        return status;
    }

    fdx->LowerDevice = IoAttachDeviceToDeviceStack(fdo, pdo);
    if (fdx->LowerDevice == NULL) {
        IoDeleteDevice(fdo);
        return STATUS_NO_SUCH_DEVICE;
    }

    xenbus_finish_fdx_init(fdo, fdx, pdo);

    /* Setup to do xm shutdown or reboot via the registry. */
    shutdown = 0;
    notify = XENBUS_NO_SHUTDOWN_NOTIFICATION;
    xenbus_shutdown_setup(&shutdown, &notify);

    gfdo = fdo;
    if (gfdx) {
        xenbus_copy_fdx(fdx, gfdx);
        ExFreePool(gfdx);
        gfdx = NULL;
    }
    fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

NTSTATUS
XenbusDispatchPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_PNP, ("XenbusDispatchPnp\n"));
    fdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (fdx->pnpstate == Deleted) {
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NO_SUCH_DEVICE;
    }

    if (fdx->IsFdo) {
        return FDO_Pnp(DeviceObject, Irp);
    } else {
        return PDO_Pnp(DeviceObject, Irp);
    }
}

static NTSTATUS
XenbusDispatchCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack;
    PFDO_DEVICE_EXTENSION fdx;

    PAGED_CODE();

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (!fdx->IsFdo) {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto END;
    }

    if (fdx->pnpstate == Deleted) {
        status = STATUS_NO_SUCH_DEVICE;
        goto END;
    } else {
        stack = IoGetCurrentIrpStackLocation(Irp);

        switch (stack->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            status = STATUS_SUCCESS;
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Information = 0;

 END:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
XenbusDispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return XenbusDispatchCreateClose(DeviceObject, Irp);
}

NTSTATUS
XenbusDispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return XenbusDispatchCreateClose(DeviceObject, Irp);
}

NTSTATUS
XenbusDispatchSystemControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("XenbusDispatchSystemControl\n"));
    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    if (!fdx->IsFdo) {
        /* The PDO, just complete the request with the current status */
        status = Irp->IoStatus.Status;
        IoCompleteRequest (Irp, IO_NO_INCREMENT);
        return status;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(fdx->LowerDevice, Irp);
}

#ifdef XENBUS_HAS_IOCTLS
static NTSTATUS
XenbusDispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack;
    PFDO_DEVICE_EXTENSION fdx;
    xenbus_register_shutdown_event_t *ioctl;

    PAGED_CODE();

    RPRINTK(DPRTL_ON, ("XenbusDispatchDeviceControl\n"));
    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (fdx->IsFdo) {
        if (fdx->pnpstate != Deleted) {
            status = xenbus_ioctl(fdx, Irp);
        } else {
            status = STATUS_NO_SUCH_DEVICE;
        }
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    if (status != STATUS_PENDING) {
        RPRINTK(DPRTL_ON, ("   completing irp %x\n", status));
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    RPRINTK(DPRTL_ON, ("<== XenbusDispatchDeviceControl %x\n",
                      status));
    return status;
}
#endif

static uint32_t
xenbus_get_startup_params(void)
{
    RTL_QUERY_REGISTRY_TABLE paramTable[2] = {0};
    WCHAR wbuffer[SYSTEM_START_OPTIONS_LEN] = {0};
    UNICODE_STRING str;
    NTSTATUS status;
    uint32_t version;
    uint32_t index_offset;
    uint32_t updated_use_pv_drivers;

    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = PVCTRL_DBG_PRINT_MASK_WSTR;
    paramTable[0].EntryContext = &dbg_print_mask;
    paramTable[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = &dbg_print_mask;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
        XENBUS_DEVICE_KEY_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("Xenbus: registry parameter dbg_print_mask = 0x%x.\n",
            dbg_print_mask));
    } else {
        PRINTK(("Xenbus: Failed to read registry dbg_print_mask 0x%x.\n",
            status));
        PRINTK(("        Use default dbg_print_mask 0x%x.\n",
                dbg_print_mask));
    }

    /* Read the registry to see if we are to actually us the PV drivers. */
    RPRINTK(DPRTL_ON, ("xenbus_determine_pv_driver_usage\n"));
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

    use_pv_drivers = 0;
    updated_use_pv_drivers = 0;
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_CONTROL | RTL_REGISTRY_OPTIONAL,
        NULL_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status == STATUS_SUCCESS) {
        RPRINTK(DPRTL_ON, ("SystemStartOptions = %ws.\n", wbuffer));
        if (wcsstr(wbuffer, SAFE_BOOT_WSTR)) {
            RPRINTK(DPRTL_ON, ("In safe mode, don't load xenbus.\n"));
            return use_pv_drivers;
        }
    } else {
        PRINTK(("Xenbus: Failed to read registry startup values: 0x%x.\n",
            status));
    }

    /* We are not in safe mode, check the registry for use_pv_driers. */
    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = USE_PV_DRIVERS_WSTR;
    paramTable[0].EntryContext = &use_pv_drivers;
    paramTable[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = &use_pv_drivers;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
        XENBUS_DEVICE_KEY_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("Xenbus: registry parameter use_pv_drivers = 0x%x.\n",
            use_pv_drivers));
    } else {
        use_pv_drivers = 0;
        PRINTK(("Xenbus: Failed to read registry services parameter 0x%x.\n",
            status));
    }
    if (use_pv_drivers & XENBUS_LEGACY_PROBE_PV_OVERRIDE_DISK_MASK) {
        use_pv_drivers &= ~XENBUS_LEGACY_PROBE_PV_OVERRIDE_DISK_MASK;
        use_pv_drivers |= XENBUS_PROBE_PV_XVDISK;
        updated_use_pv_drivers = use_pv_drivers;
    }
    if (use_pv_drivers & XENBUS_PROBE_PV_XENBLK_MIGRATED_FLAG) {
        /* Remove the migrated flag and write the value back to the reg. */
        use_pv_drivers &= ~XENBUS_PROBE_PV_XENBLK_MIGRATED_FLAG;
        updated_use_pv_drivers = use_pv_drivers;

        /*
         * xenblk.sys has been renamed and so won't load.  Set the migrate
         * flag so that we can let the xensvc know to rename xenblk back.
         */
        use_pv_drivers = XENBUS_PROBE_PV_XENBLK_MIGRATED_FLAG;
    }
    if (use_pv_drivers & XENBUS_PROBE_WINDOWS_UPDATE_FLAG) {
        /* When doing a Windows update, can swap out the IDE for xenblk. */
        use_pv_drivers &= ~XENBUS_PROBE_WINDOWS_UPDATE_FLAG;
        updated_use_pv_drivers = use_pv_drivers;
        use_pv_drivers &= ~XENBUS_PROBE_PV_BOOT_VSCSI;
        use_pv_drivers |= XENBUS_PROBE_PV_XVDISK;
        PRINTK(("Xenbus: Doing a Windows Update. use_pv_drivers = 0x%x.\n",
            use_pv_drivers));
    }

    if (updated_use_pv_drivers) {
        status = xenbus_set_reg_value(XENBUS_FULL_DEVICE_KEY_WSTR,
            USE_PV_DRIVERS_WSTR,
            updated_use_pv_drivers);
        if (status == STATUS_SUCCESS) {
            PRINTK(("Xenbus: use_pv_drivers updated to = 0x%x.\n",
                updated_use_pv_drivers));
        } else {
            PRINTK(("Xenbus 0x%x: failed to set use_pv_drivers to 0x%x.\n",
                status, updated_use_pv_drivers));
        }
    }

    delayed_resource_try_cnt = DELAYED_RESOURCE_TRY_CNT_DEFAULT;
    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = XENBUS_TIMEOUT_WSTR;
    paramTable[0].EntryContext = &delayed_resource_try_cnt;
    paramTable[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = &delayed_resource_try_cnt;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
        XENBUS_DEVICE_KEY_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("Xenbus: registry parameter timeout = %d.\n",
            delayed_resource_try_cnt));
    } else {
        delayed_resource_try_cnt = DELAYED_RESOURCE_TRY_CNT_DEFAULT;
        PRINTK(("Xenbus: Failed to read registry timeout parameter 0x%x.\n",
            status));
    }

    pvctrl_flags = XENBUS_PVCTRL_USE_BALLOONING;
    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = XENBUS_PVCTRL_FLAGS_WSTR;
    paramTable[0].EntryContext = &pvctrl_flags;
    paramTable[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = &pvctrl_flags;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
        XENBUS_DEVICE_KEY_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("Xenbus: registry parameter pvctrl_flags = 0x%x.\n",
            pvctrl_flags));
    } else {
        pvctrl_flags = 0;
        PRINTK(("Xenbus: Failed to read registry pvctrl_flags 0x%x.\n",
            status));
    }

    max_disk_targets = XENBLK_DEFAULT_TARGETS;
    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = XENBLK_MAX_DISKS_WSTR;
    paramTable[0].EntryContext = &max_disk_targets;
    paramTable[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = &max_disk_targets;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
        XENBUS_DEVICE_KEY_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status == STATUS_SUCCESS) {
        PRINTK(("Xenbus: registry parameter max_disk_targets = 0x%x.\n",
            max_disk_targets));
    } else {
        max_disk_targets = XENBLK_DEFAULT_TARGETS;
        PRINTK(("Xenbus: Failed to read registry max_disk_targets 0x%x.\n",
            status));
    }

    g_max_segments_per_request = XENBLK_DEFAULT_MAX_SEGS;
    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = XENBLK_MAX_SEGS_PER_REQ_WSTR;
    paramTable[0].EntryContext = &g_max_segments_per_request;
    paramTable[0].DefaultType =
        (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = &g_max_segments_per_request;
    paramTable[0].DefaultLength = sizeof(uint32_t);
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
        XENBUS_DEVICE_KEY_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status == STATUS_SUCCESS) {
        if (g_max_segments_per_request > XENBLK_MAX_SEGS_PER_REQ
                || g_max_segments_per_request < XENBLK_MIN_SEGS_PER_REQ) {
            g_max_segments_per_request = XENBLK_DEFAULT_MAX_SEGS;
        }
        PRINTK(("Xenbus: registry parameter %ws = 0x%x.\n",
            XENBLK_MAX_SEGS_PER_REQ_WSTR, g_max_segments_per_request));
    } else {
        g_max_segments_per_request = XENBLK_DEFAULT_TARGETS;
        PRINTK(("Xenbus: Failed to read registry %ws 0x%x.\n",
            XENBLK_MAX_SEGS_PER_REQ_WSTR, status));
    }

    if (GetXenVersion(&version, &index_offset) == STATUS_SUCCESS) {
        /* Only support flexible grant entries if Xen 3.2 or greater. */
        if (version >= 0x30002) {
            gNR_GRANT_FRAMES = DEFAULT_NR_GRANT_FRAMES;
            paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                                | RTL_QUERY_REGISTRY_TYPECHECK;
            paramTable[0].Name = XENBUS_PVCTRL_GRANT_FRAMES_WSTR;
            paramTable[0].EntryContext = &gNR_GRANT_FRAMES;
            paramTable[0].DefaultType =
                (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
            paramTable[0].DefaultData = &gNR_GRANT_FRAMES;
            paramTable[0].DefaultLength = sizeof(uint32_t);
            status = RtlQueryRegistryValues(
                RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
                XENBUS_DEVICE_KEY_WSTR,
                &paramTable[0],
                NULL,
                NULL);
            if (status == STATUS_SUCCESS) {
                PRINTK(("Xenbus: registry parameter grant_frames = %d.\n",
                    gNR_GRANT_FRAMES));
                if (gNR_GRANT_FRAMES < MIN_NR_GRANT_FRAMES) {
                    gNR_GRANT_FRAMES = MIN_NR_GRANT_FRAMES;
                } else if (gNR_GRANT_FRAMES > MAX_NR_GRANT_FRAMES) {
                    gNR_GRANT_FRAMES = MAX_NR_GRANT_FRAMES;
                }
            } else {
                gNR_GRANT_FRAMES = DEFAULT_NR_GRANT_FRAMES;
                PRINTK(("Xenbus: Failed to read registry grant_frames 0x%x.\n",
                    status));
            }
        } else {
            gNR_GRANT_FRAMES = MIN_NR_GRANT_FRAMES;
        }
    } else {
        PRINTK(("Xenbus: Failed to get Xen version.\n"));
        gNR_GRANT_FRAMES = MIN_NR_GRANT_FRAMES;
    }
    gNR_GRANT_ENTRIES =
        ((uintptr_t)gNR_GRANT_FRAMES * PAGE_SIZE / sizeof(struct grant_entry));
    gGNTTAB_LIST_END = (gNR_GRANT_ENTRIES + 1);

    PRINTK(("Xenbus: using grant_frames = %d, entries = %d.\n",
            gNR_GRANT_FRAMES, gNR_GRANT_ENTRIES));

    return use_pv_drivers;
}

void
xenbus_copy_fdx(PFDO_DEVICE_EXTENSION dfdx, PFDO_DEVICE_EXTENSION sfdx)
{
    RPRINTK(DPRTL_ON, ("xenbus_copy_fdx: IN.\n"));
    while (!IsListEmpty(&sfdx->ListOfPDOs)) {
        InsertTailList(&dfdx->ListOfPDOs, RemoveHeadList(&sfdx->ListOfPDOs));
    }
    RPRINTK(DPRTL_ON, ("xenbus_copy_fdx: done with lists.\n"));
    dfdx->NumPDOs = sfdx->NumPDOs;
    dfdx->mmio = sfdx->mmio;
    dfdx->mem = sfdx->mem;
    dfdx->mmiolen = sfdx->mmiolen;
    dfdx->gnttab_list = sfdx->gnttab_list;
    dfdx->gnttab_free_head = sfdx->gnttab_free_head;
    dfdx->gnttab_free_count = sfdx->gnttab_free_count;
    dfdx->info = sfdx->info;
    dfdx->sinfo = sfdx->sinfo;
    dfdx->max_info_entries = sfdx->max_info_entries;
    dfdx->num_grant_frames = sfdx->num_grant_frames;
    dfdx->dirql = sfdx->dirql;
    dfdx->dvector = sfdx->dvector;
    dfdx->daffinity = sfdx->daffinity;
    dfdx->PortBase = sfdx->PortBase;
    dfdx->NumPorts = sfdx->NumPorts;
    dfdx->MappedPort = sfdx->MappedPort;
    dfdx->dbg_print_mask = sfdx->dbg_print_mask;
    RPRINTK(DPRTL_ON, ("xenbus_copy_fdx: OUT.\n"));
}

static void
xenbus_finish_fdx_init(PDEVICE_OBJECT fdo,
    PFDO_DEVICE_EXTENSION fdx,
    PDEVICE_OBJECT pdo)
{
    fdx->Pdo = pdo;
    fdx->Self = fdo;
    fdx->IsFdo = TRUE;
    fdx->sig = 0xaabbccdd;

    IoInitializeRemoveLock(&fdx->RemoveLock, 0, 0, 0);
    fdx->pnpstate = NotStarted;
    fdx->devpower = PowerDeviceD0;
    fdx->syspower = PowerSystemWorking;

    ExInitializeFastMutex(&fdx->Mutex);
    KeInitializeSpinLock(&fdx->qlock);
    InitializeListHead(&fdx->ListOfPDOs);
    InitializeListHead(&fdx->shutdown_requests);
    fdx->gnttab_list = g_gnttab_list;
    fdx->gnttab_free_count = &g_gnttab_free_count;
    fdx->gnttab_free_head = &g_gnttab_free_head;
    fdx->info = ginfo;
    fdx->sinfo = gsinfo;
    fdx->max_info_entries = max_disk_targets;
    fdx->num_grant_frames = gNR_GRANT_FRAMES;
    fdx->dbg_print_mask = dbg_print_mask;

    xenbus_prepare_shared_for_init(fdx, SHARED_INFO_NOT_INITIALIZED);

    fdo->Flags |=  DO_POWER_PAGABLE;
    fdo->Flags &= ~DO_DEVICE_INITIALIZING;
}

NTSTATUS
xenbus_get_reg_value(PWSTR key, PWSTR name, DWORD *value)
{
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(uint32_t)];
    HANDLE registryKey;
    UNICODE_STRING valueName;
    NTSTATUS status;
    ULONG len;

    RPRINTK(DPRTL_ON, ("xenbus_get_reg_value - IN: irql %d cpu %d\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));

    status = xenbus_open_key(key, &registryKey);
    if (NT_SUCCESS(status)) {
        RPRINTK(DPRTL_ON, ("xenbus_get_reg_value - RtlInitUnicodeString\n"));
        RtlInitUnicodeString(&valueName, name);

        RPRINTK(DPRTL_ON, ("xenbus_get_reg_value - ZwQueryValueKey\n"));
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
        RPRINTK(DPRTL_ON, ("xenbus_get_reg_value - ZwClose: %x\n", status));
        ZwClose(registryKey);
    }
    RPRINTK(DPRTL_ON, ("xenbus_get_reg_value - OUT: %x\n", status));
    return status;
}

NTSTATUS
xenbus_set_reg_value(PWSTR key, PWSTR name, DWORD value)
{
    HANDLE registryKey;
    UNICODE_STRING valueName;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("xenbus_set_reg_value - IN\n"));

    status = xenbus_open_key(key, &registryKey);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&valueName, name);
        status = ZwSetValueKey(registryKey,
            &valueName,
            0,
            REG_DWORD,
            &value,
            sizeof(uint32_t));
        if (!NT_SUCCESS(status)) {
            PRINTK(("Reg set value filed for %ws, %x\n", name, status));
        }
        ZwClose(registryKey);
    } else {
        PRINTK(("Reg open key failed for %ws, %x\n", key, status));
    }
    RPRINTK(DPRTL_ON, ("xenbus_set_reg_value - OUT\n"));
    return status;
}

NTSTATUS
xenbus_open_key(PWSTR key_wstr, HANDLE *registryKey)
{
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyName;

    RtlInitUnicodeString(&keyName, key_wstr);

    InitializeObjectAttributes(&objectAttributes,
        &keyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    return ZwCreateKey(registryKey,
                         KEY_ALL_ACCESS,
                         &objectAttributes,
                         0,
                         NULL,
                         REG_OPTION_NON_VOLATILE,
                         NULL);
}

void
xenbus_shutdown_setup(uint32_t *shutdown, uint32_t *notify)
{
    HANDLE registryKey;
    UNICODE_STRING valueName;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("xenbus_shutdown_setup- IN\n"));

    if (!shutdown && !notify) {
        return;
    }

    status = xenbus_open_key(XENBUS_FULL_DEVICE_KEY_WSTR, &registryKey);

    if (NT_SUCCESS(status)) {
        if (shutdown) {
            RtlInitUnicodeString(&valueName, XENBUS_SHUTDOWN_WSTR);

            status = ZwSetValueKey(registryKey,
                &valueName,
                0,
                REG_DWORD,
                shutdown,
                sizeof(uint32_t));
            if (!NT_SUCCESS(status)) {
                /*
                 * If we failed to write the string, no need to load.
                 * Others will not see the value.
                 */
                PRINTK(("xenbus: failed to set shutdown value.\n"));
            }
        }

        if (notify) {
            RtlInitUnicodeString(&valueName, XENBUS_SHUTDOWN_NOTIFICATION_WSTR);

            status = ZwSetValueKey(registryKey,
                &valueName,
                0,
                REG_DWORD,
                notify,
                sizeof(uint32_t));
            if (!NT_SUCCESS(status)) {
                /*
                 * If we failed to write the string, no need to load.
                 * Others will not see the value.
                 */
                PRINTK(("xenbus: failed to set shutdown_notification.\n"));
            }
        }

        ZwClose(registryKey);
    } else {
        PRINTK(("xenbus: failed to open xenbus key.\n"));
    }
    RPRINTK(DPRTL_ON, ("xenbus_shutdown_setup- OUT\n"));
}
