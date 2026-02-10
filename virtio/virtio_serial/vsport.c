/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2014-2026 SUSE LLC
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

IO_WORKITEM_ROUTINE vserial_port_remove_worker;
DRIVER_CANCEL vserial_port_read_request_cancel;
DRIVER_CANCEL vserial_port_write_request_cancel;

PPDO_DEVICE_EXTENSION
vserial_find_pdx_from_id(PFDO_DEVICE_EXTENSION fdx, unsigned int id)
{
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;

    for (entry = fdx->list_of_pdos.Flink;
            entry != &fdx->list_of_pdos;
            entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if (pdx->port_id == id) {
            return pdx;
        }
    }
    return NULL;
}

void
vserial_port_add(PDEVICE_OBJECT DeviceObject, PVOID context)
{
    WORKER_ITEM_CONTEXT *ctx = (WORKER_ITEM_CONTEXT *)context;
    DECLARE_UNICODE_STRING_SIZE(device_name, 256);
    PFDO_DEVICE_EXTENSION fdx;
    PDEVICE_OBJECT pdo;
    PPDO_DEVICE_EXTENSION pdx;
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int id;

    if (ctx == NULL) {
        return;
    }
    fdx = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    RPRINTK(DPRTL_ON, ("--> %s: (irql %d) in, %x, id %d, %x\n", __func__,
        KeGetCurrentIrql(), fdx->sig, ctx->Argument1, ctx->Argument2));

    id = (unsigned int)*(uintptr_t *)&ctx->Argument1;

    status = RtlUnicodeStringPrintf(&device_name,
        VSERIAL_PORT_DEVICE_FORMAT_NAME_WSTR,
        VSERIAL_PORT_DEVICE_NAME_WSTR,  id);
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s: RtlUnicodeStringPrintf failed device_name 0x%x\n",
            __func__, status));
        return;
    }

    RPRINTK(DPRTL_ON, ("  IoCreateDeviceSecure with device_name %ws\n",
        device_name.Buffer));

    status = IoCreateDeviceSecure(
        fdx->Self->DriverObject,
        sizeof(PDO_DEVICE_EXTENSION),
        &device_name, /* We want to use symbolic names so supply a dev name. */
        FILE_DEVICE_SERIAL_PORT,
        FILE_DEVICE_SECURE_OPEN,
        TRUE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        (LPCGUID)&GUID_SD_VSERIAL_PDO,
        &pdo);
    if (!NT_SUCCESS(status)) {
        PRINTK(("vserial_add_port: create pdo device fail for %d.\n", id));
        return;
    }
    RPRINTK(DPRTL_ON, ("%s: pdo %p, pdx %p\n",
        __func__, pdo, pdo->DeviceExtension));
    pdx = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

    pdx->IsFdo = FALSE;
    pdx->Self = pdo;
    pdx->sig = 0x11223344;
    pdx->ParentFdo = fdx->Self;

    pdx->Present = TRUE;
    pdx->ReportedMissing = FALSE;

    pdx->pnpstate = NotStarted;
    pdx->devpower = PowerDeviceD3;
    pdx->syspower = PowerSystemWorking;

    pdx->InterfaceRefCount = 0;

    pdx->port_id = id;
    pdx->device_id = fdx->device_id;
    RtlStringCbPrintfA(pdx->instance_id, VSERIAL_PORT_ID_LEN,
        "%02u", pdx->port_id);
    pdx->NameString.Buffer = NULL;
    pdx->NameString.Length = 0;
    pdx->NameString.MaximumLength = 0;

    pdx->InBuf = NULL;
    pdx->HostConnected = FALSE;
    pdx->GuestConnected = FALSE;
    pdx->OutVqFull = FALSE;

    pdx->BusDevice = fdx->Self;

    KeInitializeEvent(&pdx->name_event, SynchronizationEvent, FALSE);
    KeInitializeEvent(&pdx->port_opened_event, SynchronizationEvent, FALSE);

    pdo->Flags |= DO_POWER_PAGABLE;
    pdo->Flags |= DO_BUFFERED_IO;
    pdo->Flags &= ~DO_DEVICE_INITIALIZING;

    RPRINTK(DPRTL_ON, ("%s: Mutex\n", __func__));
    ExAcquireFastMutex(&fdx->Mutex);
    RPRINTK(DPRTL_ON, ("%s: insert pdo\n", __func__));
    InsertTailList(&fdx->list_of_pdos, &pdx->Link);
    fdx->NumPDOs++;
    ExReleaseFastMutex(&fdx->Mutex);

    KeInitializeSpinLock(&pdx->inbuf_lock);
    KeInitializeSpinLock(&pdx->ovq_lock);

    vserial_port_power_on(pdx);

    RPRINTK(DPRTL_ON, ("%s: IoInvalidateDeviceRelations\n", __func__));
    IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);

    IoFreeWorkItem(ctx->WorkItem);
    ExFreePool(ctx);
    PRINTK(("%s: port added for port id 0x%x\n",
            VDEV_DRIVER_NAME, pdx->port_id));
    return;
}

void
vserial_port_remove_worker(PDEVICE_OBJECT DeviceObject, PVOID context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    WORKER_ITEM_CONTEXT *ctx = (WORKER_ITEM_CONTEXT *)context;
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION port;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    if (ctx == NULL) {
        return;
    }
    fdx = NULL;
    port = (PPDO_DEVICE_EXTENSION)ctx->Argument1;
    if (port->ParentFdo) {
        fdx = port->ParentFdo->DeviceExtension;
        ExAcquireFastMutex(&fdx->Mutex);
        RemoveEntryList(&port->Link);
        fdx->NumPDOs--;
        ExReleaseFastMutex(&fdx->Mutex);
    }

    vserial_destroy_pdo(port->Self);
    if (fdx) {
        RPRINTK(DPRTL_ON, ("%s: IoInvalidateDeviceRelations\n", __func__));
        IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);
    }

    IoFreeWorkItem(ctx->WorkItem);
    ExFreePool(ctx);

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

void
vserial_port_remove(IN PFDO_DEVICE_EXTENSION fdx, IN PPDO_DEVICE_EXTENSION port)
{
    RPRINTK(DPRTL_ON,
        ("--> %s: DeviceId %d PortId %d\n",
        __func__, port->device_id, port->port_id));

    port->Removed = TRUE;
    vserial_queue_passive_level_callback(fdx,
        (PIO_WORKITEM_ROUTINE)vserial_port_remove_worker,
        (void *)port,
        (void *)fdx->sig);

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

void
vserial_port_init_console(PPDO_DEVICE_EXTENSION port)
{
    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    port->GuestConnected = TRUE;
    vserial_ctrl_msg_send(PDX_TO_FDX(port), port->port_id,
        VIRTIO_CONSOLE_PORT_OPEN, 1);
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

void
vserial_port_create_name(
    IN PFDO_DEVICE_EXTENSION fdx,
    IN PPDO_DEVICE_EXTENSION port,
    IN port_buffer_t *buf)
{
    UNREFERENCED_PARAMETER(fdx);

    size_t length;
    PVIRTIO_CONSOLE_CONTROL cpkt;
    char tmp[VSERIAL_MAX_NAME_LEN];

    RPRINTK(DPRTL_ON, ("--> %s: port instance id %s\n",
        __func__, port->instance_id));
    cpkt = (PVIRTIO_CONSOLE_CONTROL)((ULONG_PTR)buf->va_buf + buf->offset);
    if (port == NULL) {
        PRINTK(("vserial_create_port_name: no port for id %d\n", cpkt->id));
        return;
    }
    if (port->NameString.Buffer == NULL) {
        length = buf->len - buf->offset - sizeof(VIRTIO_CONSOLE_CONTROL);
        port->NameString.Length = (USHORT)length;
        port->NameString.MaximumLength = port->NameString.Length + 1;
        port->NameString.Buffer = (PCHAR)EX_ALLOC_POOL(
           VPOOL_NON_PAGED,
           port->NameString.MaximumLength,
           VSERIAL_POOL_TAG);
        if (port->NameString.Buffer) {
            RtlCopyMemory(port->NameString.Buffer,
                (PVOID)((LONG_PTR)buf->va_buf + buf->offset + sizeof(*cpkt)),
                length);
            port->NameString.Buffer[length] = '\0';
            RPRINTK(DPRTL_ON, ("\tname_size = %d, name = %s\n",
                length, port->NameString.Buffer));
        } else {
            PRINTK(("VIRTIO_CONSOLE_PORT_NAME failed allocation\n"));
        }
    } else {
        length = buf->len - buf->offset - sizeof(VIRTIO_CONSOLE_CONTROL);
        if (length > (VSERIAL_MAX_NAME_LEN - 2)) {
            length = VSERIAL_MAX_NAME_LEN - 2;
        }
        RtlCopyMemory(tmp,
            (PVOID)((LONG_PTR)buf->va_buf + buf->offset + sizeof(*cpkt)),
            length);
        tmp[length] = '\0';
        if (strncmp(port->NameString.Buffer, tmp, length - 1) != 0) {
            PRINTK(("vserial_create_port_name: cur name - %s\n",
                    port->NameString.Buffer));
            PRINTK(("                          new name - %s\n", tmp));
        }
    }
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

NTSTATUS
vserial_port_register_interfaces(PPDO_DEVICE_EXTENSION port)
{

    UNICODE_STRING device_unicode_string = {0};
    NTSTATUS status  = STATUS_SUCCESS;
    DECLARE_UNICODE_STRING_SIZE(symbolic_link_name, 128);
    DECLARE_UNICODE_STRING_SIZE(device_name, 128);
    LARGE_INTEGER timeout = {0};

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    do {
        if (port->devpower == PowerDeviceD0) {
            RPRINTK(DPRTL_ON, ("  interface already registered\n"));
            status = STATUS_SUCCESS;
            return status;
        }
        if (!port->NameString.Buffer) {
            PRINTK(("%s: Waiting for for port name.\n", __func__));
            timeout.QuadPart = -TEN_SEC_TIMEOUT;
            KeWaitForSingleObject(
                &port->name_event,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            if (!port->NameString.Buffer) {
                PRINTK(("%s: Timed out waiting for port name.\n", __func__));
                status = STATUS_UNSUCCESSFUL;
                return status;
            }
        }

        status = RtlAnsiStringToUnicodeString(&device_unicode_string,
            &port->NameString, TRUE);
        if (!NT_SUCCESS(status)) {
            PRINTK(("RtlAnsiStringToUnicodeString failed 0x%x\n", status));
            return status;
        }

        status = RtlUnicodeStringPrintf(&device_name,
            VSERIAL_PORT_DEVICE_FORMAT_NAME_WSTR,
            VSERIAL_PORT_DEVICE_NAME_WSTR,  port->port_id);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: RtlUnicodeStringPrintf failed device 0x%x\n",
                __func__, status));
            break;
        }

        status = RtlUnicodeStringPrintf(&symbolic_link_name,
           L"%ws%ws",
           L"\\DosDevices\\", device_unicode_string.Buffer);
        if (!NT_SUCCESS(status)) {
            PRINTK(("RtlUnicodeStringPrintf failed symbolic 0x%x\n", status));
            break;
        }

        RPRINTK(DPRTL_ON, ("  IoCreateSymbolicLink: sym %ws,\n    dev %ws\n",
            symbolic_link_name.Buffer,
            device_name.Buffer));

        status = IoCreateSymbolicLink(&symbolic_link_name, &device_name);
        if (!NT_SUCCESS(status)) {
            PRINTK(("IoCreateSymbolicLink %ws failed 0x%x\n",
                symbolic_link_name.Buffer, status));
            break;
        }

        status = IoRegisterDeviceInterface(
            port->Self,
            (LPGUID)&GUID_VIOSERIAL_PORT,
            NULL,
            &port->ifname);
        if (!NT_SUCCESS(status)) {
            PRINTK(("IoRegisterDeviceInterface failed for %ws, (%x)\n",
                port->ifname.Buffer, status));
            break;
        }
        status = IoSetDeviceInterfaceState(&port->ifname, TRUE);
        if (!NT_SUCCESS(status)) {
            PRINTK(("IoSetDeviceInterfaceStatefailed for ifname %ws, (%x)\n",
                port->ifname.Buffer, status));
            break;
        }
        RPRINTK(DPRTL_ON, ("  pdx->ifname: %ws\n", port->ifname.Buffer));
        PRINTK(("%s: created interface %ws for port id 0x%x\n",
            VDEV_DRIVER_NAME, symbolic_link_name.Buffer, port->port_id));

    } while (0);

    if (device_unicode_string.Buffer != NULL) {
        RtlFreeUnicodeString(&device_unicode_string);
    }
    RPRINTK(DPRTL_ON, ("<-- %s: status %x\n", __func__, status));
    return status;
}

NTSTATUS
vserial_port_create(PPDO_DEVICE_EXTENSION port)
{
    NTSTATUS status;
    KLOCK_QUEUE_HANDLE lh;
    LARGE_INTEGER timeout = {0};

    RPRINTK(DPRTL_ON, ("--> %s: Port id %d\n", __func__, port->port_id));

    if (port->Removed) {
        PRINTK(("Connect request on removed port id %d\n", port->port_id));
        status = STATUS_OBJECT_NO_LONGER_EXISTS;
    } else if (port->GuestConnected == TRUE) {
        PRINTK(("Guest already connected to port id %d\n", port->port_id));
        status = STATUS_OBJECT_NAME_EXISTS;
    } else {
        port->GuestConnected = TRUE;

        KeAcquireInStackQueuedSpinLock(&port->ovq_lock, &lh);
        vserial_reclaim_consumed_buffers(port);
        KeReleaseInStackQueuedSpinLock(&lh);

        KeClearEvent(&port->port_opened_event);

        RPRINTK(DPRTL_ON, ("%s: sending ctrl msg port open for %d\n",
                           __func__, port->port_id));

        vserial_ctrl_msg_send(PDX_TO_FDX(port), port->port_id,
            VIRTIO_CONSOLE_PORT_OPEN, 1);

        RPRINTK(DPRTL_ON, ("%s: waiting for port open to finish for %d\n",
                           __func__, port->port_id));

        timeout.QuadPart = -TEN_SEC_TIMEOUT;
        status = KeWaitForSingleObject(
            &port->port_opened_event,
            Executive,
            KernelMode,
            FALSE,
            &timeout);

        RPRINTK(DPRTL_ON, ("%s: done waiting for open for %d\n",
                           __func__, port->port_id));

        if (status == STATUS_TIMEOUT) {
            PRINTK(("%s: timed out waiting for port to open for %d\n",
                    __func__, port->port_id));
        } else {
            PRINTK(("%s: port opened for port id 0x%x\n",
                    VDEV_DRIVER_NAME, port->port_id));
        }
    }

    RPRINTK(DPRTL_ON, ("<-- %s: status 0x%x\n", __func__, status));
    return status;
}

void
vserial_port_close(PPDO_DEVICE_EXTENSION port)
{
    KLOCK_QUEUE_HANDLE lh;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    if (!port->Removed && port->GuestConnected) {
        vserial_ctrl_msg_send(PDX_TO_FDX(port), port->port_id,
            VIRTIO_CONSOLE_PORT_OPEN, 0);
    }
    port->GuestConnected = FALSE;

    KeAcquireInStackQueuedSpinLock(&port->inbuf_lock, &lh);
    vserial_port_discard_data_locked(port);
    KeReleaseInStackQueuedSpinLock(&lh);

    KeAcquireInStackQueuedSpinLock(&port->ovq_lock, &lh);
    vserial_reclaim_consumed_buffers(port);
    KeReleaseInStackQueuedSpinLock(&lh);

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

/* This procedure must be called with port InBuf spinlock held */
void
vserial_port_discard_data_locked(PPDO_DEVICE_EXTENSION port)
{
    virtio_queue_t *vq;
    port_buffer_t *buf = NULL;
    NTSTATUS  status = STATUS_SUCCESS;
    unsigned int len;
    unsigned int ret = 0;

    DPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    vq = PDX_TO_FDX(port)->in_vqs[port->port_id];

    if (port->InBuf) {
        buf = port->InBuf;
    } else if (vq) {
        buf = (port_buffer_t *)vq_get_buf(vq, &len);
    }

    while (buf) {
        status = vserial_add_in_buf(vq, buf);
        if (!NT_SUCCESS(status)) {
            ++ret;
            vserial_free_buffer(buf);
        }
        buf = (port_buffer_t *)vq_get_buf(vq, &len);
    }
    port->InBuf = NULL;
    if (ret > 0) {
        PRINTK(("%s::%d Failed to add %u buffers back to queue\n",
            __func__, __LINE__, ret));
    }
    DPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

/* This procedure must be called with port InBuf spinlock held */
BOOLEAN
vserial_port_has_data_locked(PPDO_DEVICE_EXTENSION port)
{
    DPRINTK(DPRTL_TRC, ("--> %s\n", __func__));

    if (port->InBuf) {
        DPRINTK(DPRTL_TRC, ("<-- %s: has InBuf, return TRUE\n", __func__));
        return TRUE;
    }
    port->InBuf = vserial_get_inf_buf(port);
    if (port->InBuf) {
        DPRINTK(DPRTL_TRC, ("<-- %s: has InBuf, return TRUE\n", __func__));
        return TRUE;
    }
    DPRINTK(DPRTL_TRC, ("<-- %s: FALSE\n", __func__));
    return FALSE;
}

void
vserial_port_pnp_notify(PPDO_DEVICE_EXTENSION port)
{
    port_status_change_t portStatus;
    TARGET_DEVICE_CUSTOM_NOTIFICATION *notification;
    ULONG requiredSize;
    NTSTATUS status;

    DPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    portStatus.Version = 1;
    portStatus.Reason = port->HostConnected;

    requiredSize = (sizeof(TARGET_DEVICE_CUSTOM_NOTIFICATION) - sizeof(UCHAR))
        + sizeof(port_status_change_t);

    notification = (PTARGET_DEVICE_CUSTOM_NOTIFICATION)
        EX_ALLOC_POOL(VPOOL_NON_PAGED, requiredSize, VSERIAL_POOL_TAG);

    if (notification == NULL) {
        PRINTK(("%s failed to alloc the notification\n", __func__));
        return;
    }

    RtlZeroMemory(notification, requiredSize);
    notification->Version = 1;
    notification->Size = (USHORT)(requiredSize);
    notification->FileObject = NULL;
    notification->NameBufferOffset = -1;
    notification->Event = GUID_VIOSERIAL_PORT_CHANGE_STATUS;
    RtlCopyMemory(notification->CustomDataBuffer, &portStatus,
        sizeof(port_status_change_t));
    if (port->pnpstate == Started) {
        status = IoReportTargetDeviceChangeAsynchronous(
           PDX_TO_FDX(port)->Pdo,
           notification,
           NULL,
           NULL);
        if (!NT_SUCCESS(status)) {
            PRINTK((
                "IoReportTargetDeviceChangeAsynchronous failed, 0x%x\n",
                status));
        }
    }
    ExFreePoolWithTag(notification, VSERIAL_POOL_TAG);
    DPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

void
vserial_port_read_request_cancel(PDEVICE_OBJECT pdo, PIRP request)
{
    PPDO_DEVICE_EXTENSION port;
    KLOCK_QUEUE_HANDLE lh;

    port = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

    DPRINTK(DPRTL_ON, ("--> %s: called on dev %p, port %p\n    request 0x%p\n",
        __func__, pdo, port, request));

    IoReleaseCancelSpinLock(request->CancelIrql);
    if (port->PendingReadRequest == request) {
        DPRINTK(DPRTL_ON, ("  complete_with_io\n"));
        KeAcquireInStackQueuedSpinLock(&port->inbuf_lock, &lh);
        port->PendingReadRequest = NULL;
        KeReleaseInStackQueuedSpinLock(&lh);
        request->IoStatus.Information = 0;
        request->IoStatus.Status = STATUS_CANCELLED;
        vserial_complete_request(request, IO_NO_INCREMENT);
        DPRINTK(DPRTL_ON, ("<-- %s: complete\n", __func__));
        return;
    }
    vserial_complete_request(request, IO_NO_INCREMENT);
    DPRINTK(DPRTL_ON, ("<-- %s: completed unknown request\n", __func__));
}

NTSTATUS
vserial_port_read(PPDO_DEVICE_EXTENSION port, IN PIRP request)
{
    PIO_STACK_LOCATION  stack;
    KLOCK_QUEUE_HANDLE lh;
    size_t len;
    NTSTATUS status;
    void *system_buffer;
    KIRQL irql;
    BOOLEAN nonBlock;


    stack = IoGetCurrentIrpStackLocation(request);
    nonBlock = (stack->FileObject->Flags & FO_SYNCHRONOUS_IO)
        != FO_SYNCHRONOUS_IO;
    DPRINTK(DPRTL_ON, ("--> %s: port %p, non block %d\n",
        __func__, port, nonBlock));

    len = stack->Parameters.Read.Length;
    system_buffer = request->AssociatedIrp.SystemBuffer;
    if (system_buffer == NULL) {
        DPRINTK(DPRTL_ON, ("<-- %s, no buffer provided, len = %d, %p\n",
            __func__, len, request->UserBuffer));
        request->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        vserial_complete_request(request, IO_NO_INCREMENT);
        DPRINTK(DPRTL_ON, ("<-- %s: STATUS_BUFFER_TOO_SMALL\n", __func__));
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = STATUS_SUCCESS;
    KeAcquireInStackQueuedSpinLock(&port->inbuf_lock, &lh);

    if (!vserial_port_has_data_locked(port)) {
        if (!port->HostConnected) {
            DPRINTK(DPRTL_ON, ("  not locked and host not connected\n"));
            status = STATUS_INSUFFICIENT_RESOURCES;
            request->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            vserial_complete_request(request, IO_NO_INCREMENT);
        } else {
            ASSERT(port->PendingReadRequest == NULL);
            IoAcquireCancelSpinLock(&irql);
            if (request->Cancel) {
                DPRINTK(DPRTL_ON, ("  request %p is canceled.\n", request));
                status = STATUS_CANCELLED;
                request->IoStatus.Status = STATUS_CANCELLED;
                vserial_complete_request(request, IO_NO_INCREMENT);
                IoReleaseCancelSpinLock(irql);
            } else {
                IoSetCancelRoutine(request, vserial_port_read_request_cancel);
                IoReleaseCancelSpinLock(irql);
                DPRINTK(DPRTL_ON, ("  not locked set pending read, %p\n",
                    request));
                status = STATUS_PENDING;
                request->IoStatus.Status = STATUS_PENDING;
                IoMarkIrpPending(request);
                port->PendingReadRequest = request;
            }
        }
    } else {
        len = vserial_fill_read_buffer_locked(port, system_buffer, len);
        DPRINTK(DPRTL_ON,
            ("    %s complete_with_io %x\n", __func__, len));
        if (len) {
            request->IoStatus.Information = len;
            request->IoStatus.Status = STATUS_SUCCESS;
        } else {
            DPRINTK(DPRTL_ON, ("  fill read buffed, insufficient resources\n"));
            status = STATUS_INSUFFICIENT_RESOURCES;
            request->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        vserial_complete_request(request, IO_NO_INCREMENT);
    }
    KeReleaseInStackQueuedSpinLock(&lh);

    DPRINTK(DPRTL_ON, ("<-- %s: status 0x%x\n", __func__, status));
    return status;
}

static BOOLEAN
vserial_will_write_block(PPDO_DEVICE_EXTENSION port)
{
    KLOCK_QUEUE_HANDLE lh;
    BOOLEAN ret = FALSE;

    DPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    if (!port->HostConnected) {
        DPRINTK(DPRTL_ON, ("<-- %s: not connected\n", __func__));
        return TRUE;
    }

    KeAcquireInStackQueuedSpinLock(&port->ovq_lock, &lh);
    vserial_reclaim_consumed_buffers(port);
    ret = port->OutVqFull;
    KeReleaseInStackQueuedSpinLock(&lh);
    DPRINTK(DPRTL_ON, ("<-- %s: status %d\n", __func__, ret));
    return ret;
}

void
vserial_port_write_request_cancel(PDEVICE_OBJECT pdo, PIRP request)
{
    PPDO_DEVICE_EXTENSION port;
    KLOCK_QUEUE_HANDLE lh;

    port = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

    DPRINTK(DPRTL_ON, ("--> %s: called on dev %p, port %p\n    request 0x%p\n",
        __func__, pdo, port, request));

    IoReleaseCancelSpinLock(request->CancelIrql);
    if (port->PendingWriteRequest == request) {
        DPRINTK(DPRTL_ON, ("  %s complete_with_io\n", __func__));
        KeAcquireInStackQueuedSpinLock(&port->inbuf_lock, &lh);
        port->PendingWriteRequest = NULL;
        KeReleaseInStackQueuedSpinLock(&lh);
        request->IoStatus.Information = 0;
        request->IoStatus.Status = STATUS_CANCELLED;
        vserial_complete_request(request, IO_NO_INCREMENT);
        DPRINTK(DPRTL_ON, ("<-- %s: STATUS_CANCELLED\n", __func__));
        return;
    }
    vserial_complete_request(request, IO_NO_INCREMENT);
    DPRINTK(DPRTL_ON, ("<-- %s: completed unknown request\n", __func__));
}

NTSTATUS
vserial_port_write(PPDO_DEVICE_EXTENSION port, IN PIRP request)
{
    PIO_STACK_LOCATION stack;
    void *in_buf;
    void *buffer;
    write_buffer_entry_t *entry;
    KIRQL irql;
    size_t len;

    stack = IoGetCurrentIrpStackLocation(request);
    len = stack->Parameters.Write.Length;
    DPRINTK(DPRTL_ON,
        ("--> %s: request %p length %d\n", __func__, request, len));
    in_buf = request->AssociatedIrp.SystemBuffer;
    if (in_buf == NULL) {
        PRINTK(("vserial_port_write: Failed to get input buffer\n"));
        request->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        vserial_complete_request(request, IO_NO_INCREMENT);
        DPRINTK(DPRTL_ON, ("<-- %s: STATUS_BUFFER_TOO_SMALL\n", __func__));
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (vserial_will_write_block(port)) {
        request->IoStatus.Status = STATUS_CANT_WAIT;
        vserial_complete_request(request, IO_NO_INCREMENT);
        DPRINTK(DPRTL_ON, ("<-- %s: STATUS_CANT_WAIT\n", __func__));
        return STATUS_CANT_WAIT;
    }

    IoAcquireCancelSpinLock(&irql);
    if (request->Cancel) {
        DPRINTK(DPRTL_ON, ("  request %p is canceled.\n", request));
        request->IoStatus.Status = STATUS_CANCELLED;
        vserial_complete_request(request, IO_NO_INCREMENT);
        IoReleaseCancelSpinLock(irql);
        DPRINTK(DPRTL_ON, ("<-- %s: STATUS_CANCELLED\n", __func__));
        return STATUS_CANCELLED;
    }
    IoSetCancelRoutine(request, vserial_port_write_request_cancel);
    IoReleaseCancelSpinLock(irql);

    buffer = EX_ALLOC_POOL(VPOOL_NON_PAGED, len, VSERIAL_POOL_TAG);

    if (buffer == NULL) {
        PRINTK(("Failed to write allocate.\n"));
        request->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        vserial_complete_request(request, IO_NO_INCREMENT);
        DPRINTK(DPRTL_ON, ("<-- %s: STATUS_INSUFFICIENT_RESOURCES\n",
                           __func__));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry = (write_buffer_entry_t *)EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                                  sizeof(write_buffer_entry_t),
                                                  VSERIAL_POOL_TAG);

    if (entry == NULL) {
        PRINTK(("Failed to allocate write buffer entry.\n"));
        ExFreePoolWithTag(buffer, VSERIAL_POOL_TAG);
        request->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        vserial_complete_request(request, IO_NO_INCREMENT);
        DPRINTK(DPRTL_ON, ("<-- %s: STATUS_INSUFFICIENT_RESOURCES\n",
                           __func__));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(buffer, in_buf, len);
    request->IoStatus.Information = len;
    request->IoStatus.Status = STATUS_PENDING;
    IoMarkIrpPending(request);

    entry->Buffer = buffer;
    PushEntryList(&port->WriteBuffersList, &entry->ListEntry);

    port->PendingWriteRequest = request;

    if (vserial_send_buffers(port, buffer, len) <= 0) {
        PSINGLE_LIST_ENTRY removed;

        PRINTK(("Failed to send user's buffer.\n"));

        ExFreePoolWithTag(buffer, VSERIAL_POOL_TAG);

        removed = PopEntryList(&port->WriteBuffersList);
        ExFreePoolWithTag(entry, VSERIAL_POOL_TAG);

        port->PendingWriteRequest = NULL;
        request->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        vserial_complete_request(request, IO_NO_INCREMENT);
        DPRINTK(DPRTL_ON, ("<-- %s: STATUS_INSUFFICIENT_RESOURCES\n",
                           __func__));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DPRINTK(DPRTL_ON, ("<-- %s: STATUS_PENDING\n", __func__));
    return STATUS_PENDING;
}

NTSTATUS
vserial_port_device_control(PPDO_DEVICE_EXTENSION port, IN PIRP request)
{
    port_info_t *port_info;
    PIO_STACK_LOCATION stack;
    size_t length;
    size_t name_size;
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    length = 0;
    stack = IoGetCurrentIrpStackLocation(request);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_GET_INFORMATION:
        name_size = 0;
        if (port->NameString.Buffer) {
            name_size = port->NameString.MaximumLength;
        }
        port_info = (port_info_t *)request->AssociatedIrp.SystemBuffer;
        length = stack->Parameters.DeviceIoControl.OutputBufferLength;
        RPRINTK(DPRTL_ON,
            ("  IOCTL_GET_INFORMATION: info %p, length %d\n",
             port_info, length));

        if (port_info == NULL) {
            PRINTK(("  IOCTL_GET_INFORMATION: Failed, no buffer\n"));
            length = sizeof(port_info_t) + name_size;
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }
        if (length < sizeof(port_info_t) + name_size) {
            RPRINTK(DPRTL_ON,
                ("  IOCTL_GET_INFORMATION: %d, %d\n",
                length, sizeof(port_info_t) + name_size));
            length = sizeof(port_info_t) + name_size;
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }
        RPRINTK(DPRTL_ON, ("  i id %d\n", port_info->id));
        RPRINTK(DPRTL_ON, ("  i full %d\n", port_info->out_vq_full));
        RPRINTK(DPRTL_ON, ("  i host %d\n", port_info->host_connected));
        RPRINTK(DPRTL_ON, ("  i guest %d\n", port_info->guest_connected));

        RtlZeroMemory(port_info, sizeof(port_info_t));
        port_info->id = port->port_id;
        port_info->out_vq_full = port->OutVqFull;
        port_info->host_connected = port->HostConnected;
        port_info->guest_connected = port->GuestConnected;

        if (name_size) {
            RtlZeroMemory(port_info->name, name_size);
            status = RtlStringCbCopyA(port_info->name, name_size - 1,
                port->NameString.Buffer);
            if (!NT_SUCCESS(status)) {
                PRINTK(("  IOCTL_GET_INFORMATION: copy failed 0x%x\n", status));
                name_size = 0;
            }
        }
        RPRINTK(DPRTL_ON, ("  o id %d\n", port_info->id));
        RPRINTK(DPRTL_ON, ("  o full %d\n", port_info->out_vq_full));
        RPRINTK(DPRTL_ON, ("  o host %d\n", port_info->host_connected));
        RPRINTK(DPRTL_ON, ("  o guest %d\n", port_info->guest_connected));
        if (name_size) {
            RPRINTK(DPRTL_ON, ("  o name: %s\n", port_info->name));
        }
        status = STATUS_SUCCESS;
        length =  sizeof(port_info_t) + name_size;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    request->IoStatus.Status = status;
    request->IoStatus.Information = length;
    vserial_complete_request(request, IO_NO_INCREMENT);
    RPRINTK(DPRTL_ON, ("<-- %s: status 0x%x length %d\n",
        __func__, status, length));
    return status;
}

NTSTATUS
vserial_port_power_on(PPDO_DEVICE_EXTENSION port)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));
    fdx = PDX_TO_FDX(port);

    if ((fdx->in_vqs == NULL) || (fdx->in_vqs[port->port_id] == NULL)) {
        RPRINTK(DPRTL_ON, ("<-- %s: NOT FOUND\n", __func__));
        return STATUS_NOT_FOUND;
    }
    status = vserial_fill_queue(fdx->in_vqs[port->port_id], &port->inbuf_lock);
    if (!NT_SUCCESS(status)) {
        RPRINTK(DPRTL_ON, ("<-- %s: fill_queue %x\n", __func__, status));
        return status;
    }

    vq_start_interrupts(fdx->in_vqs[port->port_id]);

    vserial_ctrl_msg_send(fdx, port->port_id, VIRTIO_CONSOLE_PORT_READY, 1);

    if (port->GuestConnected == TRUE) {
        vserial_ctrl_msg_send(fdx, port->port_id, VIRTIO_CONSOLE_PORT_OPEN, 1);
    }

    port->Removed = FALSE;

    RPRINTK(DPRTL_ON, ("<-- %s: success\n", __func__));
    return STATUS_SUCCESS;
}

NTSTATUS
vserial_port_power_off(PPDO_DEVICE_EXTENSION port)
{
    FDO_DEVICE_EXTENSION *fdx;
    port_buffer_t *buf;
    PSINGLE_LIST_ENTRY iter;
    KLOCK_QUEUE_HANDLE lh;
    KLOCK_QUEUE_HANDLE fdxlh;
    virtio_queue_t *in_vq;
    write_buffer_entry_t *entry;

    RPRINTK(DPRTL_ON, ("--> %s\n", __func__));

    if (port->Removed) {
        RPRINTK(DPRTL_ON, ("<-- %s: port %d alreay removed\n",
            __func__, port->port_id));
        return STATUS_SUCCESS;
    }
    port->Removed = TRUE;

    fdx = PDX_TO_FDX(port);
    KeAcquireInStackQueuedSpinLock(&fdx->cvq_lock, &fdxlh);
    in_vq = fdx->in_vqs[port->port_id];
    vq_stop_interrupts(in_vq);

    KeAcquireInStackQueuedSpinLock(&port->inbuf_lock, &lh);
    vserial_port_discard_data_locked(port);
    port->InBuf = NULL;
    KeReleaseInStackQueuedSpinLock(&lh);

    KeAcquireInStackQueuedSpinLock(&port->ovq_lock, &lh);
    vserial_reclaim_consumed_buffers(port);
    KeReleaseInStackQueuedSpinLock(&lh);

    if (in_vq) {
        buf = (port_buffer_t *)vq_detach_unused_buf(in_vq);
        while (buf != NULL) {
            vserial_free_buffer(buf);
            buf = (port_buffer_t *)vq_detach_unused_buf(in_vq);
        }
    }
    KeReleaseInStackQueuedSpinLock(&fdxlh);

    iter = PopEntryList(&port->WriteBuffersList);
    while (iter != NULL) {
        entry = CONTAINING_RECORD(iter, write_buffer_entry_t, ListEntry);
        ExFreePoolWithTag(entry->Buffer, VSERIAL_POOL_TAG);
        ExFreePoolWithTag(entry, VSERIAL_POOL_TAG);
        iter = PopEntryList(&port->WriteBuffersList);
    }

    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));

    return STATUS_SUCCESS;
}

void
vserial_destroy_pdo(PDEVICE_OBJECT pdo)
{
    PPDO_DEVICE_EXTENSION port;
    UNICODE_STRING device_unicode_string = {0};
    DECLARE_UNICODE_STRING_SIZE(symbolic_link_name, 256);
    NTSTATUS status;

    RPRINTK(DPRTL_ON, ("--> %s: irql %d\n", __func__, KeGetCurrentIrql()));
    port = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;
    vserial_port_power_off(port);
    if (port->NameString.Buffer) {
        do {
            status = RtlAnsiStringToUnicodeString(&device_unicode_string,
                &port->NameString, TRUE);
            if (!NT_SUCCESS(status)) {
                PRINTK(("RtlAnsiStringToUnicodeString failed 0x%x\n", status));
                break;
            }
            status = RtlUnicodeStringPrintf(&symbolic_link_name,
                L"%ws%ws",
                L"\\DosDevices\\", device_unicode_string.Buffer);
            if (!NT_SUCCESS(status)) {
                PRINTK(("RtlUnicodeStringPrintf failed symbolic 0x%x\n",
                        status));
                break;
            }
            status = IoDeleteSymbolicLink(&symbolic_link_name);
            if (!NT_SUCCESS(status)) {
                PRINTK(("IoDeleteSymbolicLink %ws failed, 0x%x\n",
                    symbolic_link_name.Buffer, status));
            }
            if (device_unicode_string.Buffer != NULL) {
                RtlFreeUnicodeString(&device_unicode_string);
            }
        } while (0);
        ExFreePool(port->NameString.Buffer);
    }

    IoDeleteDevice(pdo);
    RPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}
