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


static void
vserial_ctrl_msg_process(PFDO_DEVICE_EXTENSION fdx, port_buffer_t *buf)
{
    PVIRTIO_CONSOLE_CONTROL cpkt;
    PPDO_DEVICE_EXTENSION port;
    BOOLEAN connected;

    cpkt = (PVIRTIO_CONSOLE_CONTROL)((ULONG_PTR)buf->va_buf + buf->offset);
    DPRINTK(DPRTL_ON, ("--> %s: %x, event %d\n",
                       __func__, fdx->sig, cpkt->event));

    port = vserial_find_pdx_from_id(fdx, cpkt->id);

    if (!port && (cpkt->event != VIRTIO_CONSOLE_PORT_ADD)) {
        DPRINTK(DPRTL_ON, ("%s: invalid port %d for event %x\n",
            __func__, cpkt->id, cpkt->event));
        return;
    }

    switch (cpkt->event) {
    case VIRTIO_CONSOLE_PORT_ADD:
        if (port) {
            DPRINTK(DPRTL_ON, ("%s: port already exists, %d\n",
                __func__, cpkt->id));
            break;
        }
        if (cpkt->id >= fdx->console_config.max_nr_ports) {
            DPRINTK(DPRTL_ON, ("%s: port too large, %d\n",
                __func__, cpkt->id));
            break;
        }
        DPRINTK(DPRTL_ON, ("%s: vserial_add_port, id %d\n",
            __func__, cpkt->id));
        vserial_queue_passive_level_callback(fdx,
            (PIO_WORKITEM_ROUTINE)vserial_port_add,
            (void *)cpkt->id,
            (void *)fdx->sig);
        break;

    case VIRTIO_CONSOLE_PORT_REMOVE:
        DPRINTK(DPRTL_ON, ("%s: need to remove port, %d\n",
            __func__, cpkt->id));
        vserial_port_remove(fdx, port);
        break;

    case VIRTIO_CONSOLE_CONSOLE_PORT:
        DPRINTK(DPRTL_ON, ("%s: need to init console port, %d with value %x\n",
            __func__, cpkt->id, cpkt->value));
        if (cpkt->value) {
            vserial_port_init_console(port);
        }
        break;

    case VIRTIO_CONSOLE_RESIZE:
        DPRINTK(DPRTL_ON, ("%s: console resize, %d\n", __func__, cpkt->id));
        break;

    case VIRTIO_CONSOLE_PORT_OPEN:
        DPRINTK(DPRTL_ON, ("%s: port open %d, connected %d, HostConnected %d\n",
                __func__, cpkt->id, cpkt->value, port->HostConnected));

        connected = (BOOLEAN)cpkt->value;
        if (port->HostConnected != connected) {
            port->HostConnected = connected;
            vserial_port_pnp_notify(port);
        }

        /* Someone is listening. Trigger a check to see if we have
         * something waiting to be told.
         */
        if (port->HostConnected) {
            InterlockedExchange(&fdx->queue_int, 1);
            KeInsertQueueDpc(&fdx->int_dpc, (void *)1, (void *)0);
        }
        if (connected) {
            DPRINTK(DPRTL_ON, ("%s: setting port open event\n", __func__));
            KeSetEvent(&port->port_opened_event, 0, FALSE);
        }
        break;

    case VIRTIO_CONSOLE_PORT_NAME:
        DPRINTK(DPRTL_ON, ("%s: need to create port name\n", __func__));
        vserial_port_create_name(fdx, port, buf);
        KeSetEvent(&port->name_event, 0, FALSE);
        break;
    default:
        DPRINTK(DPRTL_ON, ("%s: unknown event %d\n", __func__, cpkt->event));
    }
    DPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

void
vserial_ctrl_msg_get(IN PFDO_DEVICE_EXTENSION fdx)
{
    virtio_queue_t *vq;
    port_buffer_t *buf;
    KLOCK_QUEUE_HANDLE lh;
    unsigned int len;
    NTSTATUS  status = STATUS_SUCCESS;

    KeAcquireInStackQueuedSpinLock(&fdx->cvq_lock, &lh);

    DPRINTK(DPRTL_ON, ("--> %s: %x, c_ivq %p\n",
        __func__, fdx->sig, fdx->c_ivq));

    vq = fdx->c_ivq;
    if (vq) {
        while ((buf = vring_get_buf(vq, &len))) {
            KeReleaseInStackQueuedSpinLock(&lh);
            buf->len = len;
            buf->offset = 0;
            DPRINTK(DPRTL_ON, ("%s: found buf %p\n", __func__, buf));
            vserial_ctrl_msg_process(fdx, buf);

            KeAcquireInStackQueuedSpinLock(&fdx->cvq_lock, &lh);
            status = vserial_add_in_buf(vq, buf);
            if (!NT_SUCCESS(status)) {
                DPRINTK(DPRTL_ON, ("%s: can't add buffer %p\n", __func__, buf));
            }
        }
    }

    KeReleaseInStackQueuedSpinLock(&lh);
    DPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

void
vserial_ctrl_msg_send(
    IN PFDO_DEVICE_EXTENSION fdx,
    IN ULONG id,
    IN USHORT event,
    IN USHORT value)
{
    virtio_buffer_descriptor_t sg;
    KLOCK_QUEUE_HANDLE lh;
    unsigned int len;
    VIRTIO_CONSOLE_CONTROL cpkt;
    int cnt = 0;

    DPRINTK(DPRTL_ON, ("--> %s: sig %x event %d\n", __func__, fdx->sig, event));

    if (!fdx->is_host_multiport) {
        return;
    }

    cpkt.id = id;
    cpkt.event = event;
    cpkt.value = value;

    sg.phys_addr = (MmGetPhysicalAddress(&cpkt)).QuadPart;
    sg.len = sizeof(cpkt);

    KeAcquireInStackQueuedSpinLock(&fdx->cvq_lock, &lh);
    if (vring_add_buf(fdx->c_ovq, &sg, 1, 0, &cpkt) >= 0) {
        vring_kick(fdx->c_ovq);
        while (vring_get_buf(fdx->c_ovq, &len) == NULL) {
            KeStallExecutionProcessor(50);
            if (++cnt > RETRY_THRESHOLD) {
                DPRINTK(DPRTL_ON, ("%s: failed to get buf after retries %d\n",
                    __func__, cnt));
                break;
            }
        }
    }
    KeReleaseInStackQueuedSpinLock(&lh);

    DPRINTK(DPRTL_ON, ("<-- %s\n", __func__));
}

NTSTATUS
vserial_queue_passive_level_callback(
    __in PFDO_DEVICE_EXTENSION fdx,
    __in PIO_WORKITEM_ROUTINE callback_function,
    __in_opt PVOID context1,
    __in_opt PVOID context2)
{
    PIO_WORKITEM item = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    PWORKER_ITEM_CONTEXT context;

    context = ExAllocatePoolWithTag(NonPagedPoolNx,
       sizeof(WORKER_ITEM_CONTEXT),
       VSERIAL_POOL_TAG);

    if (NULL == context) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    item = IoAllocateWorkItem(fdx->Self);
    if (item != NULL) {
        context->WorkItem = item;
        context->Argument1 = context1;
        context->Argument2 = context2;

        IoQueueWorkItem(item,
            callback_function,
            DelayedWorkQueue,
            context);
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
        ExFreePoolWithTag(context, VSERIAL_POOL_TAG);
    }

    return status;
}
