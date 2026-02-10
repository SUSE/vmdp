/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2026 SUSE LLC
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

void
vrng_read_request_cancel(PDEVICE_OBJECT DeviceObject, PIRP request)
{
    PFDO_DEVICE_EXTENSION fdx;
    PSINGLE_LIST_ENTRY iter;
    KLOCK_QUEUE_HANDLE lh;

    RPRINTK(DPRTL_RX, ("--> %s: cpu %d request %p status %x canceled %d\n",
                        __func__, KeGetCurrentProcessorNumber(),
                       request, request->IoStatus.Status, request->Cancel));

    fdx = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    KeAcquireInStackQueuedSpinLock(&fdx->vq_lock, &lh);

    iter = &fdx->read_buffers_list;
    while (iter->Next != NULL) {
        read_buffer_entry_t *entry = CONTAINING_RECORD(iter->Next,
            read_buffer_entry_t, list_entry);

        if (request == entry->request) {
            RPRINTK(DPRTL_RX, ("  Cancel entry %p request %p\n",
                               entry, entry->request));

            entry->request = NULL;
            break;
        } else {
            iter = iter->Next;
        }
    }

    request->IoStatus.Information = 0;
    request->IoStatus.Status = STATUS_CANCELLED;
    KeReleaseInStackQueuedSpinLock(&lh);
    IoReleaseCancelSpinLock(request->CancelIrql);
    vrng_complete_request(request, IO_NO_INCREMENT);

    RPRINTK(DPRTL_RX, ("<-- %s: cpu %d\n",
                       __func__, KeGetCurrentProcessorNumber()));
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

    RPRINTK(DPRTL_RX, ("--> %s: request %p cpu %d\n",
                       __func__, request, KeGetCurrentProcessorNumber()));

    entry = (read_buffer_entry_t *)EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                                 sizeof(read_buffer_entry_t),
                                                 VRNG_POOL_TAG);

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
    entry->buffer = EX_ALLOC_POOL(VPOOL_NON_PAGED, len, VRNG_POOL_TAG);

    if (entry->buffer == NULL) {
        PRINTK(("Failed to allocate a read buffer."));
        ExFreePoolWithTag(entry, VRNG_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->request = request;

    sg.phys_addr = MmGetPhysicalAddress(entry->buffer).QuadPart;
    sg.len = len;

    KeAcquireInStackQueuedSpinLock(&fdx->vq_lock, &lh);

    if (fdx->vq == NULL) {
        PRINTK(("%s: vq is NULL, return\n", __func__));
        ExFreePoolWithTag(entry->buffer, VRNG_POOL_TAG);
        ExFreePoolWithTag(entry, VRNG_POOL_TAG);
        KeReleaseInStackQueuedSpinLock(&lh);
        return STATUS_UNSUCCESSFUL;
    }

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
        RPRINTK(DPRTL_RX, ("%s: entry %p request %p\n",
                           __func__, entry, entry->request));
        ret = vq_add_buf(fdx->vq, &sg, 0, 1, entry);
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
            vq_kick(fdx->vq);
        }
    }

    KeReleaseInStackQueuedSpinLock(&lh);

    RPRINTK(DPRTL_RX, ("<-- %s: cpu %d\n",
                       __func__, KeGetCurrentProcessorNumber()));
    return status;
}
