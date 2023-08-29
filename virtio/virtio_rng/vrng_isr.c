/*
 * Copyright (C) 2014-2017 Red Hat, Inc.
 *
 * Written By: Gal Hammer <ghammer@redhat.com>
 *
 * Copyright 2017-2021 SUSE LLC
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

#include "vrng.h"

void
vrng_int_dpc(PKDPC dpc, void *context, void *s1, void *s2)
{
    FDO_DEVICE_EXTENSION *fdx = (FDO_DEVICE_EXTENSION *)context;
    KLOCK_QUEUE_HANDLE lh;
    read_buffer_entry_t *entry;
    PIO_STACK_LOCATION  stack;
    PSINGLE_LIST_ENTRY iter;
    read_buffer_entry_t *current;
    DRIVER_CANCEL *cancel_routine;
    KIRQL irql;
    void *system_buffer;
    unsigned int len;

    RPRINTK(DPRTL_DPC, ("--> %s: cpu %d\n",
                       __func__, KeGetCurrentProcessorNumber()));

    if (fdx == NULL) {
        PRINTK(("<-- %s: fdx == NULL\n", __func__));
        return;
    }
    KeAcquireInStackQueuedSpinLock(&fdx->vq_lock, &lh);
    if (fdx->in_dpc == TRUE) {
        RPRINTK(DPRTL_DPC, ("<-- %s: fdx->in_dpc == TRUE\n", __func__));
        KeReleaseInStackQueuedSpinLock(&lh);
        return;
    }
    fdx->in_dpc = TRUE;

    for (;;) {
        if (fdx->vq == NULL) {
            KeReleaseInStackQueuedSpinLock(&lh);
            break;
        }

        entry =  (read_buffer_entry_t *)vq_get_buf(fdx->vq, &len);
        if (entry == NULL) {
            KeReleaseInStackQueuedSpinLock(&lh);
            break;
        }

        iter = &fdx->read_buffers_list;
        while (iter->Next != NULL) {
            current = CONTAINING_RECORD(iter->Next,
                                        read_buffer_entry_t,
                                        list_entry);
            if (entry == current) {
                RPRINTK(DPRTL_DPC, (" Found entry %p request %p buffer %p\n",
                                   entry, entry->request, entry->buffer));
                iter->Next = current->list_entry.Next;
                break;
            } else {
                iter = iter->Next;
            }
        }

        RPRINTK(DPRTL_DPC, ("%s: entry %p request %p\n",
                    __func__, entry, entry->request));
        if (entry->request != NULL && !entry->request->Cancel) {
            cancel_routine = IoSetCancelRoutine(entry->request, NULL);
            if (cancel_routine != NULL) {
                stack = IoGetCurrentIrpStackLocation(entry->request);
                len = min(len, (unsigned)stack->Parameters.Read.Length);
                system_buffer = entry->request->AssociatedIrp.SystemBuffer;
                RtlCopyMemory(system_buffer, entry->buffer, len);
                entry->request->IoStatus.Information = len;
                entry->request->IoStatus.Status = STATUS_SUCCESS;
                KeReleaseInStackQueuedSpinLock(&lh);
                vrng_complete_request(entry->request, IO_NO_INCREMENT);
                KeAcquireInStackQueuedSpinLock(&fdx->vq_lock, &lh);
            }
        }
        ExFreePoolWithTag(entry->buffer, VRNG_POOL_TAG);
        ExFreePoolWithTag(entry, VRNG_POOL_TAG);
    }
    RPRINTK(DPRTL_DPC, ("<-- %s: cpu %d\n",
                       __func__, KeGetCurrentProcessorNumber()));
    fdx->in_dpc = FALSE;
}

BOOLEAN
wdm_device_isr(IN PKINTERRUPT InterruptObject, IN PVOID context)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)context;
    ULONG cc;
    BOOLEAN int_serviced;

    DPRINTK(DPRTL_INT, ("--> %s: (irql %d)\n", __func__, KeGetCurrentIrql()));

    if (fdx == NULL) {
        return FALSE;
    }
    cc = virtio_device_read_isr_status(&fdx->vdev);
    if (cc > 0) {
        DPRINTK(DPRTL_ON, ("vrng_isr servicing int %x\n", cc));
        int_serviced = TRUE;
        KeInsertQueueDpc(&fdx->int_dpc, (void *)1, (void *)cc);
    } else {
        int_serviced = FALSE;
    }

    DPRINTK(DPRTL_INT, ("<-- %s: serviced interrupt = %d\n",
        __func__, int_serviced));
    return int_serviced;
}

BOOLEAN
wdm_device_interrupt_message_service(
    PKINTERRUPT Interrupt,
    PVOID context,
    ULONG  MessageId)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)context;
    ULONG cc;
    BOOLEAN int_serviced;

    if (fdx == NULL) {
        return FALSE;
    }

    cc = virtio_device_read_isr_status(&fdx->vdev);

    DPRINTK(DPRTL_INT, ("--> %s: irql %d, msg id %x, cc %x\n",
        __func__, KeGetCurrentIrql(), MessageId, cc));

    if (MessageId == 0 || cc > 0) {
        int_serviced = TRUE;
        cc = KeInsertQueueDpc(&fdx->int_dpc, (void *)MessageId, (void *)cc);
    } else {
        int_serviced = FALSE;
    }

    DPRINTK(DPRTL_INT, ("<-- %s: serviced interrupt = %d\n",
        __func__, int_serviced));

    return int_serviced;
}
