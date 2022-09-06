/*
 * Copyright (C) 2019 Red Hat, Inc.
 *
 * Written By: Gal Hammer <ghammer@redhat.com>
 *
 * Copyright 2022 SUSE LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "vfs.h"
#include "shared\fuse.h"

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

DRIVER_CANCEL vfs_request_cancel;

static inline int
vfs_get_queue_index(IN BOOLEAN is_high_prio)
{
    int index = is_high_prio ? VQ_TYPE_HIPRIO : VQ_TYPE_REQUEST;

    return index;
}

static SIZE_T
vfs_get_required_sg_size(IN virtio_fs_request_t *fs_req)
{

    return (DIV_ROUND_UP(fs_req->in_len, PAGE_SIZE) +
            DIV_ROUND_UP(fs_req->out_len, PAGE_SIZE));
}

static PMDL
vfs_alloc_pages_mdl(IN SIZE_T total_bytes)
{
    PHYSICAL_ADDRESS low_addr;
    PHYSICAL_ADDRESS high_addr;
    PHYSICAL_ADDRESS skip_bytes;

    low_addr.QuadPart = 0;
    high_addr.QuadPart = -1;
    skip_bytes.QuadPart = 0;

    return MmAllocatePagesForMdlEx(low_addr,
                                   high_addr,
                                   skip_bytes,
                                   total_bytes,
                                   MmNonCached,
                                   MM_DONT_ZERO_ALLOCATION |
                                        MM_ALLOCATE_FULLY_REQUIRED);
}

static int
vfs_fill_sg_from_mdl(OUT virtio_buffer_descriptor_t sg[],
                     IN PMDL mdl,
                     IN size_t length)
{
    PPFN_NUMBER pfn;
    ULONG total_pages;
    ULONG len;
    ULONG j;
    int i = 0;

    while (mdl != NULL)
    {
        total_pages = MmGetMdlByteCount(mdl) / PAGE_SIZE;
        pfn = MmGetMdlPfnArray(mdl);
        for (j = 0; j < total_pages; j++) {
            len = (ULONG)(min(length, PAGE_SIZE));
            length -= len;
            sg[i].phys_addr = (ULONGLONG)pfn[j] << PAGE_SHIFT;
            sg[i].len = len;
            i += 1;
        }
        mdl = mdl->Next;
    }

    return i;
}

static NTSTATUS
vfs_enqueue_request(IN PFDO_DEVICE_EXTENSION fdx,
                     IN virtio_fs_request_t *fs_req,
                     IN BOOLEAN high_prio)
{
    KLOCK_QUEUE_HANDLE qlh;
    KLOCK_QUEUE_HANDLE rlh;
    KSPIN_LOCK *vq_lock;
    virtio_queue_t *vq;
    virtio_buffer_descriptor_t *sg;
    virtio_fs_request_t *removed;
    PSINGLE_LIST_ENTRY iter;
    size_t sg_size;
    NTSTATUS status;
    int vq_index;
    int ret;
    int out_num, in_num;
    KIRQL irql;

    DPRINTK(DPRTL_IO, ("--> %s\n", __func__));

    vq_index = vfs_get_queue_index(high_prio);
    vq = fdx->vqs[vq_index];
    vq_lock = &fdx->qlock[vq_index];

    sg_size = vfs_get_required_sg_size(fs_req);
    sg = (virtio_buffer_descriptor_t *)EX_ALLOC_POOL(
        VPOOL_NON_PAGED,
        sg_size * sizeof(virtio_buffer_descriptor_t),
        VFS_POOL_TAG);

    if (sg == NULL) {
        PRINTK(("Failed to allocate a %Iu items sg list\n", sg_size));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    out_num = vfs_fill_sg_from_mdl(sg,
                                   fs_req->in_mdl,
                                   fs_req->in_len);
    in_num = vfs_fill_sg_from_mdl(sg + out_num,
                                  fs_req->out_mdl,
                                  fs_req->out_len);

    KeAcquireInStackQueuedSpinLock(vq_lock, &qlh);
    IoAcquireCancelSpinLock(&irql);
    if (fs_req->irp->Cancel) {
        status = STATUS_CANCELLED;
        IoReleaseCancelSpinLock(irql);
    } else {
        IoSetCancelRoutine(fs_req->irp, vfs_request_cancel);
        IoReleaseCancelSpinLock(irql);
        fs_req->irp->IoStatus.Information = fs_req->in_len;
        fs_req->irp->IoStatus.Status = STATUS_PENDING;

        KeAcquireInStackQueuedSpinLock(&fdx->req_lock, &rlh);
        PushEntryList(&fdx->request_list, &fs_req->list_entry);
        KeReleaseInStackQueuedSpinLock(&rlh);

        ret = vq_add_buf(vq, sg, out_num, in_num, fs_req);

        if (ret < 0) {
            RPRINTK(DPRTL_UNEXPD,
                    ("%s: Failed to add buffer to virt queue 0x%x\n",
                     __func__, ret));
            KeAcquireInStackQueuedSpinLock(&fdx->req_lock, &rlh);
            iter = &fdx->request_list;
            while (iter->Next != NULL) {
                removed = CONTAINING_RECORD(iter->Next,
                                            virtio_fs_request_t,
                                            list_entry);
                if (fs_req == removed) {
                    DPRINTK(DPRTL_IO, ("Delete %p Request: %p Buffer: %p\n",
                        fs_req, fs_req->irp, fs_req->in_mdl));
                    iter->Next = removed->list_entry.Next;
                    break;
                } else {
                    iter = iter->Next;
                }
            }
            KeReleaseInStackQueuedSpinLock(&rlh);

            IoAcquireCancelSpinLock(&irql);
            IoSetCancelRoutine(fs_req->irp, NULL);
            IoReleaseCancelSpinLock(irql);
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            IoMarkIrpPending(fs_req->irp);
            status = STATUS_PENDING;
            vq_kick(vq);
        }
    }
    KeReleaseInStackQueuedSpinLock(&qlh);
    ExFreePoolWithTag(sg, VFS_POOL_TAG);
    DPRINTK(DPRTL_IO, ("<-- %s: %x\n", __func__, status));
    return status;
}

NTSTATUS
vfs_get_volume_name(IN PFDO_DEVICE_EXTENSION fdx,
    IN PIRP Request,
    IN size_t outbuf_len)
{
    NTSTATUS status;
    WCHAR WideTag[MAX_FILE_SYSTEM_NAME + 1];
    ULONG WideTagActualSize;
    char tag[MAX_FILE_SYSTEM_NAME];
    size_t size;

    DPRINTK(DPRTL_IO, ("--> %s\n", __func__));

    RtlZeroMemory(WideTag, sizeof(WideTag));

    VIRTIO_DEVICE_GET_CONFIG(&fdx->vdev,
        FIELD_OFFSET(virtio_fs_config_t, tag),
        &tag,
        sizeof(tag));

    status = RtlUTF8ToUnicodeN(WideTag,
                               sizeof(WideTag),
                               &WideTagActualSize,
                               tag,
                               sizeof(tag));

    if (!NT_SUCCESS(status)) {
        PRINTK(("%s: Failed to convert config tag: %x\n", status));
    } else {
        RPRINTK(DPRTL_IO, ("Config tag: %s Tag: %S\n", tag, WideTag));
    }

    size = (wcslen(WideTag) + 1) * sizeof(WCHAR);

    if (outbuf_len < size) {
        PRINTK(("%s: output buffer too small (%d < %d)\n",
                __func__, outbuf_len, size));
        return STATUS_BUFFER_TOO_SMALL;
    }
    Request->IoStatus.Information = size;
    RtlCopyMemory(Request->AssociatedIrp.SystemBuffer, WideTag, size);
    DPRINTK(DPRTL_IO, ("<-- %s: %x\n", __func__, status));
    return STATUS_SUCCESS;
}

static inline BOOLEAN
vfs_is_opcode_high_prio(IN UINT32 opcode)
{
    return (opcode == FUSE_FORGET) ||
           (opcode == FUSE_INTERRUPT) ||
           (opcode == FUSE_BATCH_FORGET);
}

NTSTATUS
vfs_fuse_request(PFDO_DEVICE_EXTENSION fdx,
    PIRP Irp,
    ULONG out_len,
    ULONG in_len)
{
    NTSTATUS status;
    virtio_fs_request_t *fs_req;
    PVOID in_buf_va;
    PVOID in_buf;
    BOOLEAN hiprio;

    status = STATUS_INVALID_PARAMETER;
    fs_req = NULL;
    do {
        if (in_len < sizeof(struct fuse_in_header)) {
            PRINTK(("%s: Insufficient in buffer %d\n", __func__,
                    in_len));
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (out_len < sizeof(struct fuse_out_header)) {
            PRINTK(("%s: Insufficient out buffer %d\n", __func__,
                    out_len));
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        fs_req = (virtio_fs_request_t *)EX_ALLOC_POOL(
            VPOOL_NON_PAGED,
            sizeof(virtio_fs_request_t ),
            VFS_POOL_TAG);
        if (fs_req == NULL) {
            PRINTK(("  Failed to alloc fs_req\n"));
            break;
        }

        fs_req->irp = Irp;

        fs_req->in_len = in_len;
        fs_req->in_mdl = vfs_alloc_pages_mdl(in_len);
        if (fs_req->in_mdl == NULL) {
            PRINTK(("  Failed to alloc in_mdl %d\n", in_len));
            break;
        }

        fs_req->out_len = out_len;
        fs_req->out_mdl = vfs_alloc_pages_mdl(out_len);
        if (fs_req->out_mdl == NULL) {
            PRINTK(("  Failed to alloc out_mdl %d\n", out_len));
            break;
        }

        in_buf_va = MmMapLockedPagesSpecifyCache(fs_req->in_mdl,
                                                 KernelMode,
                                                 MmNonCached,
                                                 NULL,
                                                 FALSE,
                                                 NormalPagePriority);

        if (in_buf_va == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            PRINTK(("    MmMapLockedPages failed (in_mdl)\n"));
            break;
        }

        RtlCopyMemory(in_buf_va,
                      Irp->AssociatedIrp.SystemBuffer,
                      in_len);
        vfs_dump_buf(in_buf_va, in_len);
        MmUnmapLockedPages(in_buf_va, fs_req->in_mdl);

        hiprio = vfs_is_opcode_high_prio(
            ((struct fuse_in_header *)Irp->AssociatedIrp.SystemBuffer)->opcode);

        status = vfs_enqueue_request(fdx, fs_req, hiprio);
    } while (0);

    if (status != STATUS_PENDING) {
        vfs_free_request(fs_req);
    }
    return status;
}

static void
vfs_request_cancel(PDEVICE_OBJECT DeviceObject, PIRP request)
{
    PFDO_DEVICE_EXTENSION fdx;
    PSINGLE_LIST_ENTRY iter;
    virtio_fs_request_t *entry;
    KLOCK_QUEUE_HANDLE lh;

    RPRINTK(DPRTL_ON, ("--> %s: called on request 0x%p\n", __func__, request));

    fdx = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    KeAcquireInStackQueuedSpinLock(&fdx->req_lock, &lh);
    iter = &fdx->request_list;
    while (iter->Next != NULL) {
        entry = CONTAINING_RECORD(iter->Next, virtio_fs_request_t, list_entry);

        if (request == entry->irp) {
            RPRINTK(DPRTL_ON, ("Clear entry %p request.\n", entry));

            entry->irp = NULL;
            break;
        } else {
            iter = iter->Next;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lh);

    IoReleaseCancelSpinLock(request->CancelIrql);
    request->IoStatus.Information = 0;
    request->IoStatus.Status = STATUS_CANCELLED;
    vfs_complete_request(request, IO_NO_INCREMENT);

    RPRINTK(DPRTL_ON, ("<-- %s: completed canceled request\n", __func__));
}
