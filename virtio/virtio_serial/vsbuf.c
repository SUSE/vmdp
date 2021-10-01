/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2014-2021 SUSE LLC
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

/* Number of descriptors that queue contains. */
#define QUEUE_DESCRIPTORS 128
static virtio_buffer_descriptor_t sg_buf[QUEUE_DESCRIPTORS];

static port_buffer_t *
vserial_alloc_buffer(IN size_t buf_size)
{
    port_buffer_t *buf;

    DPRINTK(DPRTL_TRC, ("--> %s\n", __func__));

    buf = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                        sizeof(port_buffer_t),
                        VSERIAL_POOL_TAG);
    if (buf == NULL) {
        RPRINTK(DPRTL_ON, ("%s: failed to alloc buf\n", __func__));
        return NULL;
    }

    buf->va_buf = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                buf_size,
                                VSERIAL_POOL_TAG);
    if (buf->va_buf == NULL) {
        RPRINTK(DPRTL_ON, ("%s: failed to alloc va_buf\n", __func__));
        ExFreePoolWithTag(buf, VSERIAL_POOL_TAG);
        return NULL;
    }
    buf->pa_buf = MmGetPhysicalAddress(buf->va_buf);
    buf->len = 0;
    buf->offset = 0;
    buf->size = buf_size;

    DPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
    return buf;
}

void
vserial_free_buffer(IN port_buffer_t *buf)
{
    DPRINTK(DPRTL_TRC, ("--> %s: buf %p\n", __func__, buf));
    if (buf) {
        DPRINTK(DPRTL_TRC, ("\tva_buf %p\n", buf->va_buf));
        if (buf->va_buf) {
            ExFreePoolWithTag(buf->va_buf, VSERIAL_POOL_TAG);
            buf->va_buf = NULL;
        }
        ExFreePoolWithTag(buf, VSERIAL_POOL_TAG);
    }
    DPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
}

size_t
vserial_send_buffers(PPDO_DEVICE_EXTENSION port,
    IN void *buffer,
    IN size_t length)
{
    virtio_queue_t *vq;
    void *buf;
    size_t len;
    KLOCK_QUEUE_HANDLE lh;
    int out;
    int ret;

    DPRINTK(DPRTL_ON, ("--> %s: buffer %p length %d\n",
        __func__, buffer, length));

    vq = PDX_TO_FDX(port)->out_vqs[port->port_id];
    if (BYTES_TO_PAGES(length) > QUEUE_DESCRIPTORS) {
        return 0;
    }

    KeAcquireInStackQueuedSpinLock(&port->ovq_lock, &lh);

    out = 0;
    buf = buffer;
    len = length;
    while (len > 0) {
        sg_buf[out].phys_addr = MmGetPhysicalAddress(buf).QuadPart;
        sg_buf[out].len = min(len, PAGE_SIZE);

        buf = (PVOID)((LONG_PTR)buf + sg_buf[out].len);
        len -= sg_buf[out].len;
        out++;
    }

    ret = vq_add_buf(vq, sg_buf, out, 0, buffer);
    vq_kick(vq);

    if (ret >= 0) {
        port->OutVqFull = (ret == 0);
    } else {
        length = 0;
        PRINTK(("Failed to add buffer to queue, %d\n", ret));
    }

    KeReleaseInStackQueuedSpinLock(&lh);

    DPRINTK(DPRTL_ON, ("<-- %s\n", __func__));

    return length;
}

NTSTATUS
vserial_add_in_buf(IN virtio_queue_t *vq, IN port_buffer_t *buf)
{
    NTSTATUS  status = STATUS_SUCCESS;
    virtio_buffer_descriptor_t sg;

    DPRINTK(DPRTL_TRC, ("--> %s: buf %p\n", __func__, buf));
    if (buf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (vq == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sg.phys_addr = buf->pa_buf.QuadPart;
    sg.len = buf->size;

    if (vq_add_buf(vq, &sg, 0, 1, buf) < 0) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    vq_kick(vq);
    DPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
    return status;
}

port_buffer_t *
vserial_get_inf_buf(PPDO_DEVICE_EXTENSION port)
{
    port_buffer_t *buf = NULL;
    virtio_queue_t *vq;
    unsigned int len;

    DPRINTK(DPRTL_TRC, ("--> %s\n", __func__));
    vq = PDX_TO_FDX(port)->in_vqs[port->port_id];

    if (vq) {
        buf = (port_buffer_t *)vq_get_buf(vq, &len);
        if (buf) {
            buf->len = len;
            buf->offset = 0;
        }
    }
    DPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
    return buf;
}

NTSTATUS
vserial_fill_queue(IN virtio_queue_t *vq, IN KSPIN_LOCK *lock)
{
    NTSTATUS status = STATUS_SUCCESS;
    port_buffer_t *buf = NULL;
    KLOCK_QUEUE_HANDLE lh;

    DPRINTK(DPRTL_TRC, ("--> %s: vq %p\n", __func__, vq));

    for (;;) {
        buf = vserial_alloc_buffer(PAGE_SIZE);
        if (buf == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KeAcquireInStackQueuedSpinLock(lock, &lh);
        status = vserial_add_in_buf(vq, buf);
        if (!NT_SUCCESS(status)) {
            vserial_free_buffer(buf);
            KeReleaseInStackQueuedSpinLock(&lh);
            break;
        }
        KeReleaseInStackQueuedSpinLock(&lh);
    }
    DPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
    return STATUS_SUCCESS;
}

void
vserial_reclaim_consumed_buffers(PPDO_DEVICE_EXTENSION port)
{
    PIRP request;
    PSINGLE_LIST_ENTRY iter;
    void *buffer;
    unsigned int len;
    virtio_queue_t *vq;
    KIRQL irql;
    PDRIVER_CANCEL cancel;
    write_buffer_entry_t *entry;

    vq = PDX_TO_FDX(port)->out_vqs[port->port_id];
    if (vq) {
        while ((buffer = vq_get_buf(vq, &len)) != NULL) {
            DPRINTK(DPRTL_TRC, ("--> %s\n", __func__));
            if (port->PendingWriteRequest != NULL) {
                request = port->PendingWriteRequest;
                port->PendingWriteRequest = NULL;

                DPRINTK(DPRTL_ON, ("  request %p, info %x\n",
                    request, request->IoStatus.Information));
                IoAcquireCancelSpinLock(&irql);
                DPRINTK(DPRTL_ON,
                    ("  before request: cancel %d, cancel routine %p\n",
                    request->Cancel, request->CancelRoutine));
                cancel = IoSetCancelRoutine(request, NULL);
                DPRINTK(DPRTL_ON,
                    ("  after  request: cancel %d, %p, cancel routine %p\n",
                    request->Cancel, cancel, request->CancelRoutine));
                IoReleaseCancelSpinLock(irql);
                if (cancel) {
                    request->IoStatus.Status = STATUS_SUCCESS;
                    request->IoStatus.Information =
                        request->IoStatus.Information;
                    DPRINTK(DPRTL_ON, ("  complete %p\n", request));
                    vserial_complete_request(request, IO_NO_INCREMENT);
                } else {
                    DPRINTK(DPRTL_ON, ("Request %p already cancelled.\n",
                        request));
                }
            }

            iter = &port->WriteBuffersList;
            while (iter->Next != NULL) {
                entry = CONTAINING_RECORD(iter->Next,
                    write_buffer_entry_t, ListEntry);
                if (buffer == entry->Buffer) {
                    iter->Next = entry->ListEntry.Next;
                    ExFreePoolWithTag(buffer, VSERIAL_POOL_TAG);
                    ExFreePoolWithTag(entry, VSERIAL_POOL_TAG);
                    break;
                } else {
                    iter = iter->Next;
                }
            }
            port->OutVqFull = FALSE;
        }
        DPRINTK(DPRTL_TRC, ("<-- %s: Full %d\n", __func__, port->OutVqFull));
    } else {
        DPRINTK(DPRTL_ON, ("<--> %s: vq == NULL for port %d\n", __func__,
                           port->port_id));
    }
}

/* This procedure must be called with port InBuf spinlock held */
SSIZE_T
vserial_fill_read_buffer_locked(IN PPDO_DEVICE_EXTENSION port,
    IN PVOID outbuf,
    IN SIZE_T count)
{
    port_buffer_t *buf;
    NTSTATUS status = STATUS_SUCCESS;

    DPRINTK(DPRTL_TRC, ("--> %s\n", __func__));

    if (!count || !vserial_port_has_data_locked(port)) {
        return 0;
    }

    buf = port->InBuf;
    count = min(count, buf->len - buf->offset);

    RtlCopyMemory(outbuf, (PVOID)((LONG_PTR)buf->va_buf + buf->offset), count);

    buf->offset += count;

    if (buf->offset == buf->len) {
        port->InBuf = NULL;

        status = vserial_add_in_buf(PDX_TO_FDX(port)->in_vqs[port->port_id],
            buf);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s::%d  VIOSerialAddInBuf failed\n",
                __func__, __LINE__));
        }
    }
    DPRINTK(DPRTL_TRC, ("<-- %s\n", __func__));
    return count;
}
