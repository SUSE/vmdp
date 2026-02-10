/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2022-2026 SUSE LLC
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

#include "vfs.h"

void
vfs_int_dpc_work(FDO_DEVICE_EXTENSION *fdx, ULONG qidx)
{
    KLOCK_QUEUE_HANDLE lh;
    virtio_fs_request_t *fs_req;
    PSINGLE_LIST_ENTRY iter;
    virtio_fs_request_t *current;
    DRIVER_CANCEL *cancel_routine;
    KIRQL irql;
    void *system_buffer;
    void * out_buf_va;
    unsigned int len;

    DPRINTK(DPRTL_DPC, ("--> %s\n", __func__));

    if (fdx == NULL) {
        RPRINTK(DPRTL_ON, ("<-- %s: fdx == NULL\n", __func__));
        return;
    }
    for (;;) {
        KeAcquireInStackQueuedSpinLock(&fdx->qlock[qidx], &lh);
        fs_req =  (virtio_fs_request_t *)vq_get_buf(fdx->vqs[qidx], &len);
        KeReleaseInStackQueuedSpinLock(&lh);
        if (fs_req == NULL) {
            break;
        }

        KeAcquireInStackQueuedSpinLock(&fdx->req_lock, &lh);
        iter = &fdx->request_list;
        while (iter->Next != NULL) {
            current = CONTAINING_RECORD(iter->Next,
                                        virtio_fs_request_t,
                                        list_entry);
            if (fs_req == current) {
                DPRINTK(DPRTL_DPC, ("Delete %p Request: %p Buffer: %p\n",
                    fs_req, fs_req->irp, fs_req->in_mdl));
                iter->Next = current->list_entry.Next;
                break;
            } else {
                iter = iter->Next;
            }
        }
        KeReleaseInStackQueuedSpinLock(&lh);

        if (fs_req->irp != NULL && !fs_req->irp->Cancel) {
            IoAcquireCancelSpinLock(&irql);
            cancel_routine = IoSetCancelRoutine(fs_req->irp, NULL);
            IoReleaseCancelSpinLock(irql);
            if (cancel_routine != NULL) {
                len = min(len, (unsigned)fs_req->out_len);
                system_buffer = fs_req->irp->AssociatedIrp.SystemBuffer;
                out_buf_va = MmMapLockedPagesSpecifyCache(
                    fs_req->out_mdl, KernelMode, MmNonCached, NULL,
                    FALSE, NormalPagePriority);

                if (out_buf_va != NULL) {
                    RtlCopyMemory(system_buffer, out_buf_va, len);
                    vfs_dump_buf((UCHAR *)system_buffer, len);
                    MmUnmapLockedPages(out_buf_va, fs_req->out_mdl);
                    fs_req->irp->IoStatus.Status = STATUS_SUCCESS;
                }
                else {
                    PRINTK(("%s: MmMapLockedPagesSpecifyCache failed\n",
                            __func__));
                    fs_req->irp->IoStatus.Status =
                        STATUS_INSUFFICIENT_RESOURCES;
                    len = 0;
                }
                fs_req->irp->IoStatus.Information = len;
                DPRINTK(DPRTL_IO, ("  ** dcp complete irp %p\n", fs_req->irp));
                vfs_complete_request(fs_req->irp, IO_NO_INCREMENT);
            }
        }
        vfs_free_request(fs_req);
    }
    DPRINTK(DPRTL_DPC, ("<-- %s\n", __func__));
}
void
vfs_int_dpc(PKDPC dpc, void *context, void *s1, void *s2)
{
    UNREFERENCED_PARAMETER(dpc);
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)context;
    ULONG message_id_start = (ULONG)((ULONG_PTR)s1);
    ULONG message_id_end = (ULONG)((ULONG_PTR)s2);
    ULONG i;

    for (i = message_id_start; i < message_id_end; i++) {
        vfs_int_dpc_work(fdx, i);
    }
}

BOOLEAN
wdm_device_isr(IN PKINTERRUPT InterruptObject, IN PVOID context)
{
    UNREFERENCED_PARAMETER(InterruptObject);
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)context;
    ULONG cc;
    BOOLEAN int_serviced;

    DPRINTK(DPRTL_INT, ("--> %s: (irql %d)\n", __func__, KeGetCurrentIrql()));

    if (fdx == NULL) {
        return FALSE;
    }
    cc = virtio_device_read_isr_status(&fdx->vdev);
    if (cc > 0) {
        DPRINTK(DPRTL_INT, ("  servicing int %x\n", cc));
        int_serviced = TRUE;
        KeInsertQueueDpc(&fdx->int_dpc,
                         (void *)0,
                         (void *)fdx->num_queues);
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
    UNREFERENCED_PARAMETER(Interrupt);
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)context;
    ULONG cc;
    BOOLEAN int_serviced;

    if (fdx == NULL) {
        return FALSE;
    }

    cc = virtio_device_read_isr_status(&fdx->vdev);

    DPRINTK(DPRTL_INT, ("--> %s: irql %d, msg id %x, cc %x\n",
        __func__, KeGetCurrentIrql(), MessageId, cc));

    if ((int)MessageId < VIRTIO_FS_MAX_INTS || cc > 0) {
        int_serviced = TRUE;
        cc = KeInsertQueueDpc(&fdx->int_dpc,
                              (void *)MessageId,
                              (void *)((ULONG_PTR)MessageId + 1));
    } else {
        int_serviced = FALSE;
    }

    DPRINTK(DPRTL_INT, ("<-- %s: serviced interrupt = %d\n",
        __func__, int_serviced));

    return int_serviced;
}
