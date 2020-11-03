/*
 * Copyright (c) 2009-2017  Red Hat, Inc.
 *
 * Author(s):
 *  Vadim Rozenfeld <vrozenfe@redhat.com>
 *
 * Copyright 2010-2012 Novell, Inc.
 * Copyright 2012-2020 SUSE LLC
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

#include "virtio_balloon.h"

static void
InsertHeadMdl(virtio_bln_mdl_list_t *mdl_list, PMDL mdl)
{
    mdl->Next = mdl_list->head;
    mdl_list->head = mdl;

    if (mdl_list->tail == NULL) {
        mdl_list->tail = mdl;
    }
}

static void
InsertTailMdl(virtio_bln_mdl_list_t *mdl_list, PMDL mdl)
{
    if (mdl_list->tail) {
        mdl_list->tail->Next = mdl;
    }
    mdl_list->tail = mdl;
    mdl->Next = NULL;

    if (mdl_list->head == NULL) {
        mdl_list->head = mdl;
    }
}

static void
balloon_add_mdl_to_list(vbln_dev_extn_t *fdx,
    PMDL mdl,
    virtio_bln_pfn_t pfn)
{
    /* Lowmem is re-populated first, so highmem pages go at list tail. */
    if (PfnHighMem(pfn)) {
        InsertTailMdl(&fdx->mdl_list, mdl);
        fdx->high_mem_pages++;
    } else {
        InsertHeadMdl(&fdx->mdl_list, mdl);
        fdx->low_mem_pages++;
    }
}

static PMDL
balloon_remove_mdl_from_list(vbln_dev_extn_t *fdx)
{
    PMDL mdl;

    mdl = NULL;
    if (fdx->mdl_list.head) {
        mdl = fdx->mdl_list.head;
        fdx->mdl_list.head = fdx->mdl_list.head->Next;
        mdl->Next = NULL;
        if (fdx->mdl_list.head == NULL) {
            fdx->mdl_list.tail = NULL;
        }
        if (PfnHighMem((MmGetMdlPfnArray(mdl)[0]))) {
            fdx->high_mem_pages--;
        } else {
            fdx->low_mem_pages--;
        }
    }
    return mdl;
}

static void
virtio_bln_free_mdl_list(PMDL mdl_head)
{
    PMDL mdl;

    while (mdl_head) {
        mdl = mdl_head;
        mdl_head = mdl_head->Next;
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
    }
}

static void
virtio_bln_tell_host(vbln_dev_extn_t *fdx,
    virtio_queue_t *q,
    KEVENT *kevent)
{
    virtio_buffer_descriptor_t sg;
    PHYSICAL_ADDRESS phys_addr;
    NTSTATUS            status;
    LARGE_INTEGER       timeout = {0};


    phys_addr = MmGetPhysicalAddress(fdx->pfn_list);
    sg.phys_addr = phys_addr.QuadPart;
    sg.len =  sizeof(fdx->pfn_list[0]) * fdx->num_pfns;

    vring_add_buf(q, &sg, 1, 0, fdx);
    vring_kick(q);

    timeout.QuadPart = Int32x32To64(1000, -10000);
    RPRINTK(DPRTL_INT, ("%s: waiting for event %p\n",
                        VDEV_DRIVER_NAME, kevent));
    status = KeWaitForSingleObject (
        kevent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);
    RPRINTK(DPRTL_INT, ("%s: done waiting for event %p\n",
                        VDEV_DRIVER_NAME, kevent));

    if (STATUS_TIMEOUT == status) {
        PRINTK(("%s: Timed out waiting for balloon update.\n",
                VDEV_DRIVER_NAME));
    }
}

virtio_bln_ulong_t
virtio_bln_free_pages(vbln_dev_extn_t *fdx, virtio_bln_ulong_t target)
{
    KLOCK_QUEUE_HANDLE lh;
    PMDL mdl, head, tail;

    RPRINTK(DPRTL_TRC, ("virtio_bln_free_pages: %d pages\n", target));

    if (target > MAX_PFN_ENTRIES) {
        target = MAX_PFN_ENTRIES;
    }

    KeAcquireInStackQueuedSpinLock(&fdx->balloon_lock, &lh);

    head = NULL;
    tail = NULL;
    for (fdx->num_pfns = 0; fdx->num_pfns < target; fdx->num_pfns++) {
        mdl = balloon_remove_mdl_from_list(fdx);
        if (mdl) {
            fdx->pfn_list[fdx->num_pfns] =
                (virtio_bln_pfn_t)((MmGetMdlPfnArray(mdl)[0]));
            fdx->num_pages--;
            if (head == NULL) {
                head = mdl;
            } else {
                tail->Next = mdl;
            }
            tail = mdl;
        } else {
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lh);

    if (fdx->num_pfns) {
        if (fdx->tell_host_first) {
            virtio_bln_tell_host(fdx, fdx->deflate_q, &fdx->deflate_event);
            virtio_bln_free_mdl_list(head);
        } else {
            virtio_bln_free_mdl_list(head);
            virtio_bln_tell_host(fdx, fdx->deflate_q, &fdx->deflate_event);
        }
    }
    return target;
}

static virtio_bln_ulong_t
virtio_bln_alloc_pages(vbln_dev_extn_t *fdx, virtio_bln_ulong_t target)
{
    PHYSICAL_ADDRESS low, high, skip;
    KLOCK_QUEUE_HANDLE lh;
    PMDL mdl, mdl_list;
    LARGE_INTEGER timeout;
    virtio_bln_ulong_t i;
    virtio_bln_pfn_t pfn;


    RPRINTK(DPRTL_TRC, ("virtio_bln_alloc_pages: %d pages\n", target));

    if (target > MAX_PFN_ENTRIES) {
        target = MAX_PFN_ENTRIES;
    }

    low.QuadPart = 0;
    high.QuadPart = 0xffffffffffffffff;
    skip.QuadPart = 0;

    mdl_list = NULL;
    for (i = 0; i < target; i++) {
        mdl = MmAllocatePagesForMdl(low, high, skip, PAGE_SIZE);
        if (mdl) {
            mdl->Next = mdl_list;
            mdl_list = mdl;
        } else {
            timeout.QuadPart = -10000000; /* 1 second */
            KeDelayExecutionThread(KernelMode, FALSE, &timeout);
            break;
        }
    }

    KeAcquireInStackQueuedSpinLock(&fdx->balloon_lock, &lh);

    for (fdx->num_pfns = 0; mdl_list; fdx->num_pfns++) {
        mdl = mdl_list;
        mdl_list = mdl_list->Next;
        pfn = (virtio_bln_pfn_t)((MmGetMdlPfnArray(mdl)[0]));
        balloon_add_mdl_to_list(fdx, mdl, pfn);
        fdx->pfn_list[fdx->num_pfns] = pfn;
        fdx->num_pages++;
    }

    KeReleaseInStackQueuedSpinLock(&lh);

    if (fdx->num_pfns) {
        virtio_bln_tell_host(fdx, fdx->inflate_q, &fdx->inflate_event);
    }
    return target;
}

static void
virtio_bln_set_pages(vbln_dev_extn_t *fdx, uint32_t num)
{
    VIRTIO_DEVICE_SET_CONFIG(&fdx->vdev,
                             FIELD_OFFSET(virtio_bln_config_t, actual),
                             &num,
                             sizeof(num));
}

static int32_t
virtio_bln_get_pages(vbln_dev_extn_t *fdx)
{
    uint32_t pages;

    VIRTIO_DEVICE_GET_CONFIG(&fdx->vdev,
                             FIELD_OFFSET(virtio_bln_config_t, num_pages),
                             &pages,
                             sizeof(pages));
    return (int32_t)(pages - fdx->num_pages);
}

void
virtio_bln_balloon_pages(vbln_dev_extn_t *fdx)
{
    int32_t target_pages;
    virtio_bln_ulong_t actual_pages;

    do {
        /*
         *Since this is on a work item, DPCs and higer will preempt
         * so no need to yield.
         */
        actual_pages = 0;
        target_pages = virtio_bln_get_pages(fdx);
        if (target_pages > 0) {
            RPRINTK(DPRTL_ON, ("virtio_bln_balloon_pages: alloc %d.\n",
                               target_pages));
            actual_pages = virtio_bln_alloc_pages(fdx, target_pages);
        } else if (target_pages < 0) {
            RPRINTK(DPRTL_ON, ("virtio_bln_balloon_pages: free %d.\n",
                               target_pages));
            target_pages = -target_pages;
            actual_pages = virtio_bln_free_pages(fdx, target_pages);
        }

        RPRINTK(DPRTL_ON, ("virtio_bln_balloon_pages: target %d, actual %d.\n",
                           target_pages, actual_pages));

        virtio_bln_set_pages(fdx, fdx->num_pages);
    } while (target_pages != actual_pages);
    RPRINTK(DPRTL_DPC, ("virtio_bln_balloon_pages: out.\n"));
}

void
virtio_bln_update_stats(vbln_dev_extn_t *fdx)
{
    virtio_buffer_descriptor_t sg;
    LARGE_INTEGER phys_addr;
    int i;

    phys_addr = MmGetPhysicalAddress(fdx->stats);
    sg.phys_addr = phys_addr.QuadPart;
    sg.len =  sizeof(virtio_bln_stat_t) * VIRTIO_BALLOON_S_NR;
    vring_add_buf(fdx->stat_q, &sg, 1, 0, fdx);
    vring_kick(fdx->stat_q);
    fdx->has_new_mem_stats = FALSE;
    fdx->backend_wants_mem_stats = FALSE;
}

void
virtio_bln_worker(PDEVICE_OBJECT fdo, PVOID context)
{
    virtio_bln_work_item_t *vwork_item;
    vbln_dev_extn_t *fdx;
    KLOCK_QUEUE_HANDLE lh;

    RPRINTK(DPRTL_ON, ("virtio_bln_worker: in.\n"));

    if (context == NULL) {
        return;
    }
    vwork_item = (virtio_bln_work_item_t *)context;
    fdx = vwork_item->fdx;

    virtio_bln_balloon_pages(fdx);

    if (vwork_item->work_item) {
        IoFreeWorkItem(vwork_item->work_item);
    }
    ExFreePoolWithTag(vwork_item, VIRTIO_BLN_POOL_TAG);
    KeAcquireInStackQueuedSpinLock(&fdx->balloon_lock, &lh);
    fdx->worker_running = FALSE;
    KeReleaseInStackQueuedSpinLock(&lh);
    RPRINTK(DPRTL_ON, ("virtio_bln_worker: out.\n"));
}


void
virtio_bln_dpc(PKDPC dpc, void *context, void *s1, void *s2)
{
    vbln_dev_extn_t *fdx;
    KLOCK_QUEUE_HANDLE lh;
    virtio_bln_work_item_t *vwork_item;
    unsigned int len;
    BOOLEAN schedule_worker = TRUE;

    if (context == NULL) {
        return;
    }
    fdx = (vbln_dev_extn_t *)context;
    RPRINTK(DPRTL_DPC, ("virtio_bln_dpc: in, power %x, pnp %x.\n",
        fdx->power_state, fdx->pnpstate));

    KeAcquireInStackQueuedSpinLock(&fdx->balloon_lock, &lh);
    if (fdx->inflate_q && fdx->pnpstate == Started) {
        RPRINTK(DPRTL_DPC, ("virtio_bln_dpc: inflate_q.\n"));
        if (vring_get_buf(fdx->inflate_q, &len) != NULL) {
            RPRINTK(DPRTL_ON, ("virtio_bln_dpc: set event inflate_q.\n"));
            KeSetEvent (&fdx->inflate_event, IO_NO_INCREMENT, FALSE);
            schedule_worker = FALSE;
        }
    }
    if (fdx->deflate_q && fdx->pnpstate == Started) {
        RPRINTK(DPRTL_DPC, ("virtio_bln_dpc: deflate_q.\n"));
        if (vring_get_buf(fdx->deflate_q, &len) != NULL) {
            RPRINTK(DPRTL_ON, ("virtio_bln_dpc: set event deflate_q.\n"));
            KeSetEvent (&fdx->deflate_event, IO_NO_INCREMENT, FALSE);
            schedule_worker = FALSE;
        }
    }
    if (!(vbnctrl_flags & PVCTRL_DISABLE_MEM_STATS) && fdx->stat_q
            && fdx->pnpstate == Started) {
        RPRINTK(DPRTL_DPC, ("virtio_bln_dpc: stat_q.\n"));
        if (vring_get_buf(fdx->stat_q, &len) != NULL) {
            RPRINTK(DPRTL_ON, ("virtio_bln_dpc: backend wants mem stats.\n"));
            fdx->backend_wants_mem_stats = TRUE;
            if (fdx->has_new_mem_stats) {
                RPRINTK(DPRTL_ON, ("virtio_bln_dpc: update stats.\n"));
                virtio_bln_update_stats(fdx);
            }
        }
    }
    if (fdx->pnpstate != Started || fdx->power_state == PowerSystemHibernate) {
        RPRINTK(DPRTL_DPC, ("virtio_bln_dpc: out, pnp state %x.\n",
            fdx->pnpstate));
        KeReleaseInStackQueuedSpinLock(&lh);
        return;
    }
    if (!schedule_worker || fdx->worker_running) {
        RPRINTK(DPRTL_DPC,
                ("virtio_bln_dpc: out, worker still running: s %d w %d **\n",
                 schedule_worker, fdx->worker_running));
        KeReleaseInStackQueuedSpinLock(&lh);
        return;
    }

    vwork_item = ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(virtio_bln_work_item_t),
        VIRTIO_BLN_POOL_TAG);

    if (vwork_item) {
        vwork_item->work_item = IoAllocateWorkItem(fdx->Self);
        if (vwork_item->work_item != NULL) {
            vwork_item->fdx = fdx;
            fdx->worker_running = TRUE;
            IoQueueWorkItem(vwork_item->work_item,
                            virtio_bln_worker,
                            DelayedWorkQueue,
                            vwork_item);
            RPRINTK(DPRTL_DPC, ("virtio_bln_dpc: IoQueueWorkItem\n"));
        } else {
            PRINTK(("virtio_bln_dpc: IoAllocateWorkItem failed.\n"));
            ExFreePoolWithTag(vwork_item, VIRTIO_BLN_POOL_TAG);
        }
    }
    KeReleaseInStackQueuedSpinLock(&lh);

    RPRINTK(DPRTL_DPC, ("virtio_bln_dpc: out.\n"));
}

BOOLEAN
wdm_device_interrupt_message_service(
    PKINTERRUPT Interrupt,
    PVOID context,
    ULONG  MessageId)
{
    return wdm_device_isr(Interrupt, context);
}

BOOLEAN
wdm_device_isr(IN PKINTERRUPT InterruptObject, IN PVOID context)
{
    vbln_dev_extn_t *fdx;
    BOOLEAN int_serviced;

    DPRINTK(DPRTL_INT, ("%s %s: (irql %d) in\n",
                        VDEV_DRIVER_NAME, __func__, KeGetCurrentIrql()));

    if (context == NULL) {
        return FALSE;
    }
    fdx = (vbln_dev_extn_t *)context;
    if (virtio_device_read_isr_status(&fdx->vdev) > 0) {
        int_serviced = TRUE;
        KeInsertQueueDpc(&fdx->dpc, NULL, NULL);
    } else {
        int_serviced = FALSE;
    }

    DPRINTK(DPRTL_INT, ("%s %s: serviced interrupt = %d, out\n",
                        VDEV_DRIVER_NAME, __func__, int_serviced));
    return int_serviced;
}

static void
virtio_bln_dev_reset(vbln_dev_extn_t *fdx)
{
    uint8_t status;

    VIRTIO_DEVICE_RESET(&fdx->vdev);
    virtio_device_reset_features(&fdx->vdev);
    status = VIRTIO_DEVICE_GET_STATUS(&fdx->vdev);
    if (status) {
        RPRINTK(DPRTL_ON,
            ("%s Device status is still %02X\n", __func__, (ULONG)status));
        VIRTIO_DEVICE_RESET(&fdx->vdev);
        status = VIRTIO_DEVICE_GET_STATUS(&fdx->vdev);
        RPRINTK(DPRTL_ON,
            ("%s Device status on retry %02X\n", __func__, (ULONG)status));
    }
    virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_ACKNOWLEDGE);
    virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER);
}

static void
virtio_bln_disable_interrupts(vbln_dev_extn_t *fdx)
{
    vring_stop_interrupts(fdx->deflate_q);
    vring_stop_interrupts(fdx->inflate_q);
    vring_stop_interrupts(fdx->stat_q);
}

static void
virtio_bln_enable_interrupts(vbln_dev_extn_t *fdx)
{
    vring_start_interrupts(fdx->deflate_q);
    vring_start_interrupts(fdx->inflate_q);
    vring_start_interrupts(fdx->stat_q);
}

static void
virtio_bln_delete_qs(vbln_dev_extn_t *fdx)
{
    if (fdx->deflate_q)  {
        VIRTIO_DEVICE_QUEUE_DELETE(&fdx->vdev, fdx->deflate_q, TRUE);
        fdx->deflate_q = NULL;
    }
    if (fdx->inflate_q)  {
        VIRTIO_DEVICE_QUEUE_DELETE(&fdx->vdev, fdx->inflate_q, TRUE);
        fdx->inflate_q = NULL;
    }
    if (fdx->stat_q)  {
        VIRTIO_DEVICE_QUEUE_DELETE(&fdx->vdev, fdx->stat_q, TRUE);
        fdx->stat_q = NULL;
        if (fdx->stats) {
            ExFreePoolWithTag(fdx->stats, VIRTIO_BLN_POOL_TAG);
            fdx->stats = NULL;
        }
    }
}

NTSTATUS
wdm_device_virtio_init(PFDO_DEVICE_EXTENSION fdx)
{
    virtio_buffer_descriptor_t sg;
    PHYSICAL_ADDRESS phys_addr;
    uint64_t host_features;
    uint64_t guest_features;
    NTSTATUS status = STATUS_SUCCESS;

    RPRINTK(DPRTL_ON, ("%s %s: in\n", VDEV_DRIVER_NAME, __func__));
    do {
        virtio_bln_dev_reset(fdx);

        guest_features = 0;
        host_features = VIRTIO_DEVICE_GET_FEATURES(&fdx->vdev);
        PRINTK(("%s: host features 0x%llx\n", VDEV_DRIVER_NAME, host_features));
        if (virtio_is_feature_enabled(host_features, VIRTIO_F_VERSION_1)) {
            virtio_feature_enable(guest_features, VIRTIO_F_VERSION_1);
        }
        if (virtio_is_feature_enabled(host_features,
                                      VIRTIO_BALLOON_F_STATS_VQ)) {
            RPRINTK(DPRTL_ON, ("%s %s: enable stats feature\n",
                               VDEV_DRIVER_NAME, __func__));
            virtio_feature_enable(guest_features, VIRTIO_BALLOON_F_STATS_VQ);
        }
        PRINTK(("%s: setting guest features 0x%llx\n",
                VDEV_DRIVER_NAME, guest_features));
        fdx->guest_features = guest_features;
        virtio_device_set_guest_feature_list(&fdx->vdev, guest_features);

        fdx->inflate_q = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                       VIRTIO_QUEUE_BALLOON_INFLATE,
                                       NULL,
                                       NULL,
                                       0,
                                       VIRTIO_MSI_NO_VECTOR,
                                       FALSE);
        if (fdx->inflate_q == NULL) {
            PRINTK(("%s %s: balloon failed to setup inflate q.\n",
                    VDEV_DRIVER_NAME, __func__));
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        fdx->deflate_q = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                       VIRTIO_QUEUE_BALLOON_DEFLATE,
                                       NULL,
                                       NULL,
                                       0,
                                       VIRTIO_MSI_NO_VECTOR,
                                       FALSE);
        if (fdx->deflate_q == NULL) {
            PRINTK(("%s %s: balloon failed to setup deflate q.\n",
                    VDEV_DRIVER_NAME, __func__));
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        if (virtio_is_feature_enabled(host_features,
                                      VIRTIO_BALLOON_F_STATS_VQ)) {
            PRINTK(("%s %s: balloon has stats queue.\n",
                    VDEV_DRIVER_NAME, __func__));
            fdx->stat_q = VIRTIO_DEVICE_QUEUE_SETUP(&fdx->vdev,
                                           VIRTIO_QUEUE_BALLOON_STAT,
                                           NULL,
                                           NULL,
                                           0,
                                           VIRTIO_MSI_NO_VECTOR,
                                           FALSE);
            if (fdx->stat_q == NULL) {
                PRINTK(("%s %s: balloon failed to setup stat q.\n",
                        VDEV_DRIVER_NAME, __func__));
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            fdx->stats = ExAllocatePoolWithTag(
                NonPagedPoolNx,
                sizeof(virtio_bln_stat_t) * VIRTIO_BALLOON_S_NR,
                VIRTIO_BLN_POOL_TAG);
            if (fdx->stats == NULL) {
                PRINTK(("%s %s: balloon failed to alloc stat pool.\n",
                        VDEV_DRIVER_NAME, __func__));
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            RtlFillMemory(fdx->stats,
                sizeof(virtio_bln_stat_t) * VIRTIO_BALLOON_S_NR,
                -1);
            virtio_bln_update_stats(fdx);
        }

        fdx->pfn_list = ExAllocatePoolWithTag(
            NonPagedPoolNx,
            PAGE_SIZE,
            VIRTIO_BLN_POOL_TAG);
        if (fdx->pfn_list == NULL) {
            PRINTK(("%s %s: balloon failed to alloc pfn list.\n",
                    VDEV_DRIVER_NAME, __func__));
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        fdx->tell_host_first = virtio_device_has_host_feature(&fdx->vdev,
            VIRTIO_BALLOON_F_MUST_TELL_HOST);
        mb();

        fdx->low_mem_pages   = 0;
        fdx->high_mem_pages  = 0;

    } while (FALSE);

    if (NT_SUCCESS(status)) {
        virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER_OK);
        PRINTK(("%s %s: balloon initial pages to be ballooned = %d.\n",
                VDEV_DRIVER_NAME, __func__, virtio_bln_get_pages(fdx)));

        virtio_bln_enable_interrupts(fdx);
    } else {
        PRINTK(("%s %s: balloon init failed, %x\n",
                VDEV_DRIVER_NAME, __func__, status));
        virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_FAILED);
        virtio_bln_destroy(fdx);
    }

    RPRINTK(DPRTL_ON, ("%s %s: out.\n", VDEV_DRIVER_NAME, __func__));
    return status;
}

void
virtio_bln_suspend(vbln_dev_extn_t *fdx)
{
    LARGE_INTEGER timeout;
    KLOCK_QUEUE_HANDLE lh;

    PRINTK(("%s %s: pages to be returned %d\n",
            VDEV_DRIVER_NAME, __func__, fdx->num_pages));

    timeout.QuadPart = -10000000; /* 1 second */
    while (fdx->worker_running) {
        PRINTK(("%s %s: waiting for worker to finish.\n",
                VDEV_DRIVER_NAME, __func__));
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    while (fdx->num_pages) {
        RPRINTK(DPRTL_ON, (
            "%s %s: free, pages to be returned %d, freed %d.\n",
            VDEV_DRIVER_NAME, __func__,
            fdx->num_pages, virtio_bln_get_pages(fdx)));
        virtio_bln_free_pages(fdx, fdx->num_pages);
    }

    virtio_bln_set_pages(fdx, fdx->num_pages);
    virtio_bln_disable_interrupts(fdx);

    /* Keep the DPC from functioning after interrupts are disabled. */
    KeAcquireInStackQueuedSpinLock(&fdx->balloon_lock, &lh);
    fdx->power_state = PowerSystemSleeping3;
    KeReleaseInStackQueuedSpinLock(&lh);

    virtio_device_remove_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER_OK);

    virtio_bln_delete_qs(fdx);

    VIRTIO_DEVICE_RESET(&fdx->vdev);
    virtio_device_reset_features(&fdx->vdev);

    RPRINTK(DPRTL_ON, ("%s %s: irql %d, port status %x\n",
            VDEV_DRIVER_NAME, __func__,
            KeGetCurrentIrql(), VIRTIO_DEVICE_GET_STATUS(&fdx->vdev)));

    if (fdx->pfn_list) {
        ExFreePoolWithTag(fdx->pfn_list, VIRTIO_BLN_POOL_TAG);
        fdx->pfn_list = NULL;
        RPRINTK(DPRTL_ON, ("%s %s: fdx->pfn_list = NUL\n",
                           VDEV_DRIVER_NAME, __func__));
    }

    PRINTK(("%s %s: pages to be returned %d, freed %d.\n",
            VDEV_DRIVER_NAME, __func__,
            fdx->num_pages, virtio_bln_get_pages(fdx)));
}

void
virtio_bln_destroy(vbln_dev_extn_t *fdx)
{
    RPRINTK(DPRTL_ON, ("%s %s: in\n", VDEV_DRIVER_NAME, __func__));
    if (fdx && fdx->sig == VIRTIO_BLN_SIG) {
        virtio_bln_suspend(fdx);

        if (DriverInterruptObj) {
            RPRINTK(DPRTL_ON, ("%s %s: IoDisconnectInterrupt\n",
                               VDEV_DRIVER_NAME, __func__));
            IoDisconnectInterrupt(DriverInterruptObj);
            DriverInterruptObj = NULL;
        }

        wdm_unmap_io_space(fdx);
        fdx->sig = 0;
    }
    RPRINTK(DPRTL_ON, ("%s %s: out.\n", VDEV_DRIVER_NAME,  __func__));
}
