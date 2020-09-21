/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2014-2020 SUSE LLC
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

static void vserial_int_queues_dpc(FDO_DEVICE_EXTENSION *fdx);

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
        DPRINTK(DPRTL_ON, ("vserial_isr servicing int %x\n", cc));
        int_serviced = TRUE;

        /* When servicing from the ISR, alway provide S1 with a value
         * so that the int DPC will also call the queues DPC. Provide
         * s2 with a value to proccess the ctrl messages.
         */
        InterlockedExchange(&fdx->msg_int, cc);
        InterlockedExchange(&fdx->queue_int, 1);
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

    RPRINTK(DPRTL_INT, ("--> %s: irql %d, msg id %x, cc %x\n",
        __func__, KeGetCurrentIrql(), MessageId, cc));

    if (MessageId || cc > 0) {
        int_serviced = TRUE;
        if (cc) {
            InterlockedExchange(&fdx->msg_int, cc);
        }
        if (MessageId) {
            InterlockedExchange(&fdx->queue_int, MessageId);
        }
        cc = KeInsertQueueDpc(&fdx->int_dpc, (void *)MessageId, (void *)cc);
    } else {
        int_serviced = FALSE;
    }

    DPRINTK(DPRTL_INT, ("<-- %s: serviced interrupt = %d\n",
        __func__, int_serviced));

    return int_serviced;
}

void
vserial_int_dpc(PKDPC dpc, void *context, void *s1, void *s2)
{
    FDO_DEVICE_EXTENSION *fdx = (FDO_DEVICE_EXTENSION *)context;
    LONG msg_int;
    LONG queue_int;

    if (fdx == NULL) {
        return;
    }
    msg_int = InterlockedExchange(&fdx->msg_int, 0);
    queue_int = InterlockedExchange(&fdx->queue_int, 0);
    DPRINTK(DPRTL_DPC, ("--> %s: msg_int %d, queue_int %d\n",
                        __func__, msg_int, queue_int));

    if (msg_int) {
        /* If processing regular interrups, process them first. */
        vserial_ctrl_msg_get(fdx);
    }

    if (queue_int) {
        /* s1 will be set if there are message interrupts to be handled.
         * If called from the regular interrupt ISR s1 will always be set.
         * If caleed form the message IRS, it will be based on if there
         * a message interrupt or not.
         */
        DPRINTK(DPRTL_DPC, ("    %s: calling vserial_int_queues_dpc, mid %d\n",
            __func__, queue_int));
        vserial_int_queues_dpc(fdx);
    }

    DPRINTK(DPRTL_DPC, ("<-- %s\n", __func__));
}

static void
vserial_int_queues_dpc(FDO_DEVICE_EXTENSION *fdx)
{
    PPDO_DEVICE_EXTENSION port;
    PIO_STACK_LOCATION  stack;
    PLIST_ENTRY entry;
    KLOCK_QUEUE_HANDLE lh;
    KIRQL irql;
    PVOID buf;
    PIRP request;
    size_t len;

    DPRINTK(DPRTL_INT, ("--> %s\n", __func__));
    for (entry = fdx->list_of_pdos.Flink;
         entry != &fdx->list_of_pdos;
         entry = entry->Flink) {
        port = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);

        KeAcquireInStackQueuedSpinLock(&port->inbuf_lock, &lh);
        if (!port->InBuf) {
            port->InBuf = vserial_get_inf_buf(port);
        }

        if (!port->GuestConnected) {
            vserial_port_discard_data_locked(port);
        }

        DPRINTK(DPRTL_INT, ("    InBuf %p, pending %x\n",
            port->InBuf, port->PendingReadRequest));
        if (port->InBuf && port->PendingReadRequest) {
            request = port->PendingReadRequest;
            IoAcquireCancelSpinLock(&irql);
            if (!request->Cancel) {
                IoSetCancelRoutine(request, NULL);
                IoReleaseCancelSpinLock(irql);

                buf = request->AssociatedIrp.SystemBuffer;
                if (buf) {
                    stack = IoGetCurrentIrpStackLocation(request);
                    len = stack->Parameters.Read.Length;
                    port->PendingReadRequest = NULL;
                    request->IoStatus.Information =
                        vserial_fill_read_buffer_locked(port, buf, len);
                    request->IoStatus.Status = STATUS_SUCCESS;
                    vserial_complete_request(request, IO_NO_INCREMENT);
                } else {
                    RPRINTK(DPRTL_ON, ("Request %p failed to get buffer.\n",
                        request));
                }
            } else {
                IoReleaseCancelSpinLock(irql);
                RPRINTK(DPRTL_ON, ("Request %p already cancelled.\n", request));
            }
        }
        KeReleaseInStackQueuedSpinLock(&lh);

        KeAcquireInStackQueuedSpinLock(&port->ovq_lock, &lh);
        vserial_reclaim_consumed_buffers(port);
        KeReleaseInStackQueuedSpinLock(&lh);
    }
    DPRINTK(DPRTL_INT, ("<-- %s\n", __func__));
}
