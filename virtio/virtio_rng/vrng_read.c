/*
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

DRIVER_CANCEL vrng_read_request_cancel;

static void
vrng_read_request_cancel(PDEVICE_OBJECT DeviceObject, PIRP request)
{
    PFDO_DEVICE_EXTENSION fdx;
    PSINGLE_LIST_ENTRY iter;
    KLOCK_QUEUE_HANDLE lh;

    RPRINTK(DPRTL_ON, ("--> %s: called on request 0x%p\n", __func__, request));

    fdx = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    KeAcquireInStackQueuedSpinLock(&fdx->vq_lock, &lh);

    iter = &fdx->read_buffers_list;
    while (iter->Next != NULL) {
        read_buffer_entry_t *entry = CONTAINING_RECORD(iter->Next,
            read_buffer_entry_t, list_entry);

        if (request == entry->request) {
            RPRINTK(DPRTL_ON, ("Clear entry %p request.\n", entry));

            entry->request = NULL;
            break;
        } else {
            iter = iter->Next;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lh);
    IoReleaseCancelSpinLock(request->CancelIrql);
    request->IoStatus.Information = 0;
    request->IoStatus.Status = STATUS_CANCELLED;
    vrng_complete_request(request, IO_NO_INCREMENT);

    RPRINTK(DPRTL_ON, ("<-- %s: completed canceled request\n", __func__));
}

NTSTATUS
vrng_read(PFDO_DEVICE_EXTENSION fdx, PIRP request)
{
    virtio_buffer_descriptor_t sg;
    PIO_STACK_LOCATION stack;
    PSINGLE_LIST_ENTRY removed;
    read_buffer_entry_t *entry;
    KLOCK_QUEUE_HANDLE lh;
    KIRQL irql;
    NTSTATUS status;
    unsigned long len;
    int ret;

    DPRINTK(DPRTL_ON, ("--> %s: request %p\n", __func__, request));

    entry = (read_buffer_entry_t *)ExAllocatePoolWithTag(NonPagedPoolNx,
        sizeof(read_buffer_entry_t), VRNG_POOL_TAG);

    if (entry == NULL) {
        PRINTK(("Failed to allocate a read entry."));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    stack = IoGetCurrentIrpStackLocation(request);
    len = stack->Parameters.Read.Length;
    if (request->AssociatedIrp.SystemBuffer == NULL) {
        RPRINTK(DPRTL_UNEXPD, ("<-- %s, no buffer provided, len = %d, %p\n",
            __func__, len, request->UserBuffer));
        return STATUS_BUFFER_TOO_SMALL;
    }

    len = min(len, PAGE_SIZE);
    entry->buffer = ExAllocatePoolWithTag(NonPagedPoolNx, len, VRNG_POOL_TAG);

    if (entry->buffer == NULL) {
        PRINTK(("Failed to allocate a read buffer."));
        ExFreePoolWithTag(entry, VRNG_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->request = request;

    sg.phys_addr = MmGetPhysicalAddress(entry->buffer).QuadPart;
    sg.len = len;

    KeAcquireInStackQueuedSpinLock(&fdx->vq_lock, &lh);

    IoAcquireCancelSpinLock(&irql);
    if (request->Cancel) {
        status = STATUS_CANCELLED;
        IoReleaseCancelSpinLock(irql);
    } else {
        IoSetCancelRoutine(request, vrng_read_request_cancel);
        IoReleaseCancelSpinLock(irql);
        request->IoStatus.Information = len;
        request->IoStatus.Status = STATUS_PENDING;
        PushEntryList(&fdx->read_buffers_list, &entry->list_entry);
        ret = vring_add_buf(fdx->vq, &sg, 0, 1, entry);
        if (ret < 0) {
            RPRINTK(DPRTL_UNEXPD,
                    ("%s: Failed to add buffer to virt queue 0x%x\n",
                     __func__, ret));
            removed = PopEntryList(&fdx->read_buffers_list);
            ExFreePoolWithTag(entry->buffer, VRNG_POOL_TAG);
            ExFreePoolWithTag(entry, VRNG_POOL_TAG);

            IoAcquireCancelSpinLock(&irql);
            IoSetCancelRoutine(request, NULL);
            IoReleaseCancelSpinLock(irql);
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            IoMarkIrpPending(request);
            status = STATUS_PENDING;
            vring_kick(fdx->vq);
        }
    }

    KeReleaseInStackQueuedSpinLock(&lh);

    DPRINTK(DPRTL_ON, ("<-- %s: %x\n", __func__, status));
    return status;
}
