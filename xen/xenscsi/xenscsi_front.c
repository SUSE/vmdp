/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2026 SUSE LLC
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

#include <stdio.h>
#include <ntddk.h>
#include <stdlib.h>
#include "xenscsi.h"

#define MAXIMUM_OUTSTANDING_BLOCK_REQS \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST * VSCSI_RING_SIZE)
#define GRANT_INVALID_REF   0

static XenbusState vs_backend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len);
static int vs_talk_to_backend(struct vscsi_front_info *);
static int vs_setup_ring(struct vscsi_front_info *);
static void vs_restart_queue(IN PDEVICE_OBJECT DevObject, IN PVOID Context);
static void vs_free(struct vscsi_front_info *, int);
static void vs_completion(struct vscsi_shadow *s);

static char *
kasprintf(size_t len, const char *fmt, ...)
{
    va_list ap;
    char *p;

    p = EX_ALLOC_POOL(VPOOL_NON_PAGED, len + 1, XENSCSI_TAG_GENERAL);
    if (!p) {
        return NULL;
    }

    va_start(ap, fmt);
    RtlStringCbVPrintfA(p, len + 1, fmt, ap);
    va_end(ap);
    return p;
}

/*
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures and the ring buffer for communication with the backend, and
 * inform the backend of the appropriate details for those.  Switch to
 * Initialised state.
 */
NTSTATUS
vscsi_probe(struct vscsi_front_info *info)
{
    enum xenbus_state backend_state;
    int err, i;

    RPRINTK(DPRTL_INIT, ("vscsi_probe: "));

    info->nodename = xenbus_get_nodename_from_dev(info);
    info->otherend = xenbus_get_otherend_from_dev(info);
    info->otherend_id = (domid_t)cmp_strtou64(
        xenbus_get_backendid_from_dev(info),
            NULL, 10);
    RPRINTK(DPRTL_INIT, ("n %s, o %s, id %d\n", info->nodename,
                         info->otherend, info->otherend_id));

    info->connected = BLKIF_STATE_DISCONNECTED;
    InitializeListHead(&info->sdev_list);
    KeInitializeSpinLock(&info->lock);

    info->shadow_free = 0;
    for (i = 0; i < VSCSI_RING_SIZE; i++) {
        info->shadow[i].req.id = (uint16_t)i + 1;
        info->shadow[i].req.nr_segments = 0;
        info->shadow[i].request = NULL;
    }
    info->shadow[VSCSI_RING_SIZE - 1].req.id = 0x0fff;

    InitializeListHead(&info->watch.list);
    info->watch.callback = vs_backend_changed;
    info->watch.node = info->otherend;
    info->watch.flags = XBWF_new_thread;
    info->watch.context = info;
    info->mm.cons = 0;
    info->mm.prod = 0;

    RPRINTK(DPRTL_FRNT, ("XenScsi:  vscsi_probe - vs_talk_to_backend.\n"));
    err = vs_talk_to_backend(info);
    if (err) {
        return err;
    }

    RPRINTK(DPRTL_FRNT,
            ("      vscsi_probe %s: waiting for connect, irql %x, cpu %x\n",
             info->nodename, KeGetCurrentIrql(),
             KeGetCurrentProcessorNumber()));

    /*
     * We don't actually want to wait any time because we may be
     * at greater than PASSIVE_LEVEL.
     */
    while (1) {
        backend_state = vs_backend_changed(&info->watch, NULL, 0);
        if (backend_state == XenbusStateConnected) {
            break;
        }
        if (backend_state == XenbusStateClosed) {
            return STATUS_NO_SUCH_DEVICE;
        }
    }

    RPRINTK(DPRTL_FRNT, ("      vscsi_probe: register_xenbus_watch.\n"));
    err = register_xenbus_watch(&info->watch);
    if (err) {
        PRINTK(("vscsi_probe: register_xenbus_watch returned 0x%x.\n",
            err));
        if (err != -EEXIST) {
            return err;
        }
    }

    RPRINTK(DPRTL_INIT, ("XenScsi: vscsi_probe finished\n"));
    return STATUS_SUCCESS;
}

static void
vs_free(struct vscsi_front_info *info, int suspend)
{
    XENSCSI_LOCK_HANDLE lh = {0};

    /* Prevent new requests being issued until we fix things up. */
    xenscsi_acquire_spinlock(info->xbdev, &info->lock, InterruptLock,
                             NULL, &lh);
    XENSCSI_SET_FLAG(info->xenscsi_locks, (BLK_FRE_L | BLK_INT_L));
    XENSCSI_SET_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
    info->connected = suspend ?
        BLKIF_STATE_SUSPENDED : BLKIF_STATE_DISCONNECTED;
    XENSCSI_CLEAR_FLAG(info->xenscsi_locks, (BLK_FRE_L | BLK_INT_L));
    XENSCSI_CLEAR_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
    xenscsi_release_spinlock(info->xbdev, &info->lock, lh);

    /* Free resources associated with old device channel. */
    if (info->ring_ref != GRANT_INVALID_REF) {
        gnttab_end_foreign_access(info->ring_ref, 0);
        info->ring_ref = GRANT_INVALID_REF;
        info->ring.sring = NULL;
    }
    if (info->evtchn) {
        RPRINTK(DPRTL_FRNT,
                ("      vs_free:unregister_dpc_from_evtchn %d.\n",
                 info->evtchn));
        unregister_dpc_from_evtchn(info->evtchn);
        xenbus_free_evtchn(info->evtchn);
        info->evtchn = 0;
    }
}

static int
vs_setup_ring(struct vscsi_front_info *info)
{
    vscsiif_sring_t *sring = NULL;
    int err = 0;

    do {
        info->ring_ref = GRANT_INVALID_REF;

        sring = EX_ALLOC_POOL(VPOOL_NON_PAGED,
            PAGE_SIZE, XENSCSI_TAG_GENERAL);
        if (!sring) {
            PRINTK(("vs_setup_ring: failed to allocate sring.\n"));
            xenbus_printf(XBT_NIL, info->nodename, "alloc shared ring", "%x",
                          -ENOMEM);
            err = -ENOMEM;
            break;
        }
        RPRINTK(DPRTL_INIT, ("vs_setup_ring alloc sring **.\n"));
        XENSCSI_INC(info->xbdev->alloc_cnt_s);
        SHARED_RING_INIT(sring);
        WIN_FRONT_RING_INIT(&info->ring, sring, PAGE_SIZE);

        RPRINTK(DPRTL_FRNT,
            ("sring_t %x, req %x, rsp %x, ring %x.\n",
            sizeof(vscsiif_sring_t), sizeof(vscsiif_request_t),
            sizeof(vscsiif_response_t), __WIN_RING_SIZE(sring, PAGE_SIZE)));
        RPRINTK(DPRTL_FRNT,
            ("off ring %x, id %x, seg %x\n",
            offsetof(vscsiif_sring_t, ring),
            offsetof(vscsiif_request_t, id),
            offsetof(vscsiif_request_t, seg)));
        RPRINTK(DPRTL_FRNT,
            ("vs_setup_ring: sring = %x, mfn ring.sring = %x, mfn sring = %x\n",
            sring, virt_to_mfn(info->ring.sring), virt_to_mfn(sring)));

        err = xenbus_grant_ring(info->otherend_id,
                                virt_to_mfn(info->ring.sring));
        if (err < 0) {
            PRINTK(("vs_setup_ring: xenbus_grant_ring failed\n"));
            XENSCSI_DEC(info->xbdev->alloc_cnt_s);
            break;
        }
        info->ring_ref = err;
        RPRINTK(DPRTL_FRNT,
            ("vs_setup_ring: info->ring_ref = %x for id %d\n", info->ring_ref,
            info->otherend_id));

        err = xenbus_alloc_evtchn(info->otherend_id, (int *)&info->evtchn);
        if (err) {
            PRINTK(("vs_setup_ring: xenbus_alloc_evtchn failed\n"));
            break;
        }
        RPRINTK(DPRTL_FRNT,
            ("vs_setup_ring: info->evtchn = %d, %p\n",
            info->evtchn, vscsi_xenbus_int));
        err = register_dpc_to_evtchn(info->evtchn, vscsi_xenbus_int, info,
            &info->has_interrupt);

        if (err < 0) {
            xenbus_printf(XBT_NIL, info->nodename,
                "bind_evtchn_to_irqhandler failed", "%x", err);
            PRINTK(("register_dpc_to_evtchn failed %x\n", err));
            break;
        }

        RPRINTK(DPRTL_INIT, ("setup blkring out: ring_ref %u, evtchn %u\n",
            info->ring_ref, info->evtchn));
        err = 0;
    } while (0);

    if (err) {
        if (sring) {
            ExFreePool(sring);
            info->ring.sring = NULL;
        }
        vs_free(info, 0);
        PRINTK(("setup blkring: failed %x\n", err));
    }
    return err;
}

static int talking_to_backend;

/* Common code used when first setting up, and when resuming. */
static int
vs_talk_to_backend(struct vscsi_front_info *info)
{
    const char *message;
    struct xenbus_transaction xbt = {0};
    int err;


    do {
        message = NULL;

        RPRINTK(DPRTL_INIT, ("vs_talk_to_backend: irql %x, cpu %x\n",
            KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
        DPRINTK(DPRTL_INIT, (" locks %x\n", info->xenscsi_locks));

        /* Create shared ring, alloc event channel. */
        err = vs_setup_ring(info);
        if (err) {
            break;
        }

        RPRINTK(DPRTL_FRNT,
            ("vs_talk_to_backend: ring_ref %u, evtchn %u\n",
            info->ring_ref, info->evtchn));

        err = xenbus_transaction_start(&xbt);
        if (err) {
            PRINTK(("vs_talk_to_backend: xenbus_transaction_start failed\n"));
            xenbus_printf(xbt, info->nodename, "starting transaction", "%d",
                          err);
            break;
        }

        talking_to_backend++;
        RPRINTK(DPRTL_FRNT,
            ("vs_talk_to_backend: ring_ref %u\n", info->ring_ref));
        err = xenbus_printf(xbt, info->nodename, "ring-ref", "%u",
                            info->ring_ref);
        if (err) {
            message = "writing ring-ref";
            break;
        }
        RPRINTK(DPRTL_FRNT,
            ("vs_talk_to_backend: evtchn %u\n", info->evtchn));
        err = xenbus_printf(xbt, info->nodename, "event-channel", "%u",
            info->evtchn);
        if (err) {
            message = "writing event-channel";
            break;
        }
        RPRINTK(DPRTL_FRNT,
            ("vs_talk_to_backend: protocol %s\n", XEN_IO_PROTO_ABI_NATIVE));
        err = xenbus_printf(xbt, info->nodename, "protocol", "%s",
            XEN_IO_PROTO_ABI_NATIVE);
        if (err) {
            message = "writing protocol";
            break;
        }

        err = xenbus_transaction_end(xbt, 0);
        if (err) {
            if (err != -EAGAIN) {
                xenbus_printf(xbt, info->nodename,
                              "completing transaction", "%d",
                              err);
                break;
            }
        }
    } while (err == -EAGAIN);

    if (err == 0) {
        xenbus_switch_state(info->nodename, XenbusStateInitialised);
    } else {
        if (message) {
            xenbus_transaction_end(xbt, 1);
            xenbus_printf(xbt, info->nodename, message, "%s", err);
        }
        vs_free(info, 0);
    }

    talking_to_backend--;
    RPRINTK(DPRTL_INIT, ("vs_talk_to_backend %x: irql %x, cpu %x\n",
        err,  KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    DPRINTK(DPRTL_INIT, (" locks %x\n", info->xenscsi_locks));
    return err;
}

static NTSTATUS
vs_parse_vdev_str(char *str, uint16_t *chn, uint16_t *tid, uint16_t *lun)
{
    char tmp[4];
    int i;
    int j;

    DPRINTK(DPRTL_INIT,  ("vs_parse_vdev_str: %s\n", str));

    /* Parse off the host.  It's not needed. */
    for (i = 0; i < 3 && str[i] != ':' && str[i] != '\0'; i++) {
        ;
    }

    if (str[i] != ':') {
        PRINTK(("vs_parse_vdev_str: failed to find the first :\n"));
        return STATUS_UNSUCCESSFUL;
    }
    DPRINTK(DPRTL_INIT, ("1: str[%d] = %c\n", i - 1, str[i - 1]));

    for (j = 0, i++ ; j < 3 && str[i] != ':' && str[i] != '\0'; i++, j++) {
        tmp[j] = str[i];
    }
    if (str[i] != ':') {
        PRINTK(("vs_parse_vdev_str: failed to find the second :\n"));
        return STATUS_UNSUCCESSFUL;
    }
    DPRINTK(DPRTL_INIT, ("2: str[%d] = %c\n", i - 1, str[i - 1]));
    tmp[j] = '\0';
    *chn = (uint16_t)atoi(tmp);

    for (j = 0, i++ ; j < 3 && str[i] != ':' && str[i] != '\0'; i++, j++) {
        tmp[j] = str[i];
    }
    if (str[i] != ':') {
        PRINTK(("vs_parse_vdev_str: failed to find the third :\n"));
        return STATUS_UNSUCCESSFUL;
    }
    DPRINTK(DPRTL_INIT, ("3: str[%d] = %c\n", i - 1, str[i - 1]));
    tmp[j] = '\0';
    *tid = (uint16_t)atoi(tmp);

    for (j = 0, i++ ; j < 3 && str[i] != ':' && str[i] != '\0'; i++, j++) {
        tmp[j] = str[i];
    }
    if (str[i] != '\0') {
        PRINTK(("vs_parse_vdev_str: failed to find the null\n"));
        return STATUS_UNSUCCESSFUL;
    }
    DPRINTK(DPRTL_INIT, ("4: str[%d] = %c\n", i - 1, str[i - 1]));
    tmp[j] = '\0';
    *lun = (uint16_t)atoi(tmp);

    return STATUS_SUCCESS;
}

vscsi_dev_t *
vs_device_lookup(LIST_ENTRY *sdev_lst, uint16_t chn, uint16_t tid, uint16_t lun)
{
    vscsi_dev_t *sdev;
    PLIST_ENTRY entry;

    for (entry = sdev_lst->Flink;
            entry != sdev_lst;
            entry = entry->Flink) {
        sdev = CONTAINING_RECORD(entry, vscsi_dev_t, sdev_l);

        if (sdev->chn == chn && sdev->tid == tid && sdev->lun == lun) {
            return sdev;
        }
    }
    return NULL;
}

static vscsi_dev_t *
vs_guest_dev_lookup(vscsi_dev_t **sdev_array,
    uint16_t chn, uint16_t tid, uint16_t lun)
{
    int idx;

    idx = VS_GET_LIST_IDX(chn, tid, lun);
    if (idx < VS_MAX_DEVS) {
        return sdev_array[idx];
    }
    return NULL;
}

static vscsi_dev_t *
vs_add_device(vscsi_dev_t **sdev_array, LIST_ENTRY *sdev_lst,
    uint16_t chn, uint16_t tid, uint16_t lun)
{
    vscsi_dev_t *sdev;
    int i;

    for (i = 0; i < VS_MAX_DEVS; i++) {
        if (sdev_array[i] == NULL) {
            break;
        }
    }
    if (i == VS_MAX_DEVS) {
        return NULL;
    }

    sdev = EX_ALLOC_POOL(VPOOL_NON_PAGED, sizeof(vscsi_dev_t),
        XENSCSI_TAG_GENERAL);

    if (sdev) {
        sdev->chn = chn;
        sdev->tid = tid;
        sdev->lun = lun;
        sdev->idx = (uint16_t)i;
        InsertTailList(sdev_lst, &sdev->sdev_l);
        sdev_array[i] = sdev;
    }
    return sdev;
}

static void
vs_remove_device(vscsi_dev_t **sdev_array, vscsi_dev_t *sdev)
{
    int i;

    for (i = 0; i < VS_MAX_DEVS; i++) {
        if (sdev_array[i] == sdev) {
            sdev_array[i] = NULL;
            break;
        }
    }
    RemoveEntryList(&sdev->sdev_l);
    ExFreePool(sdev);
}

static int
vs_disconnect(struct vscsi_front_info *info)
{
    info->connected = BLKIF_STATE_DISCONNECTED;
    xenbus_switch_state(info->nodename, XenbusStateClosed);
    return 0;
}

static void
vs_hotplug(struct vscsi_front_info *info, int op)
{
    vscsi_dev_t *sdev;
    char *str, *state_str;
    char **dir;
    char *buf;
    NTSTATUS status;
    unsigned int i;
    unsigned int dir_n = 0;
    unsigned int device_state;
    uint16_t chn, tid, lun;

    RPRINTK(DPRTL_ON, ("vs_hotplug: start, op %d\n", op));

    dir = xenbus_directory(XBT_NIL, info->otherend, "vscsi-devs", &dir_n);
    if (IS_ERR(dir)) {
        return;
    }

    for (i = 0; i < dir_n; i++) {
        /* read status */
        str = kasprintf(64, "vscsi-devs/%s/state", dir[i]);
        buf = xenbus_read(XBT_NIL, info->otherend, str, NULL);
        xenbus_free_string(str);
        if (buf == NULL) {
            PRINTK(("Failed to read other end vscis-devs %s state\n", dir[i]));
            continue;
        }

        device_state = (enum xenbus_state)cmp_strtou64(buf, NULL, 10);
        RPRINTK(DPRTL_ON, ("vs_hotplug: dev %s = %u\n", dir[i], device_state));
        xenbus_free_string(buf);

        /* virtual SCSI device */
        str = kasprintf(64, "vscsi-devs/%s/v-dev", dir[i]);
        buf = xenbus_read(XBT_NIL, info->otherend, str, NULL);
        xenbus_free_string(str);
        if (buf == NULL) {
            PRINTK(("Failed to read other end v-dev\n"));
            continue;
        }

        /* buf has the host:chn:tgt:lun in it */
        status = vs_parse_vdev_str(buf, &chn, &tid, &lun);
        xenbus_free_string(buf);
        if (status != STATUS_SUCCESS) {
            PRINTK(("Failed to parse_dev_str\n"));
            continue;
        }

        /* front device state path */
        state_str = kasprintf(64, "vscsi-devs/%s/state", dir[i]);

        switch (op) {
        case VSCSIFRONT_OP_ADD_LUN:
            RPRINTK(DPRTL_ON, ("vs_hotplug: op = add.\n"));
            if (device_state == XenbusStateInitialised) {
                sdev = vs_device_lookup(&info->sdev_list, chn, tid, lun);
                if (sdev) {
                    PRINTK(("vs_hotplug: %s/%s in use switch to Closed\n",
                            info->nodename, dir[i]));
                    xenbus_printf(XBT_NIL, info->nodename,
                                  state_str, "%d", XenbusStateClosed);
                } else {
                    sdev = vs_add_device(info->sdev, &info->sdev_list,
                                         chn, tid, lun);
                    if (sdev == NULL) {
                        PRINTK(("vs_hotplug: Failed to add sdev\n"));
                    }
                    #ifdef DBG
                    sdev = vs_device_lookup(&info->sdev_list, chn, tid, lun);
                    if (sdev) {
                        RPRINTK(DPRTL_ON,
                                ("sdev lookup: chn %u , tid %u , lun %u\n",
                                 sdev->chn, sdev->tid, sdev->lun));
                    } else {
                        RPRINTK(DPRTL_ON, ("vs_hotplug: to lookup sdev\n"));
                    }
                    #endif

                    RPRINTK(DPRTL_ON,
                            ("vs_hotplug add dev: %s/%s, switch to Connected\n",
                             info->nodename, state_str));
                    xenbus_printf(XBT_NIL, info->nodename,
                                  state_str, "%d", XenbusStateConnected);
                }
            } else {
                RPRINTK(DPRTL_ON,
                        ("vs_hotplug: ADD_LUN %u != initialised, do nothing\n",
                         device_state));
            }
            break;
        case VSCSIFRONT_OP_DEL_LUN:
            RPRINTK(DPRTL_ON,
                    ("vs_hotplug: %s/%s, op = del.\n", info->nodename, dir[i]));
            if (device_state == XenbusStateClosing) {
                sdev = vs_device_lookup(&info->sdev_list, chn, tid, lun);
                if (sdev) {
                    RPRINTK(DPRTL_ON, ("\tvs_remove_device %s/%s.\n",
                             info->nodename, dir[i]));
                    vs_remove_device(info->sdev, sdev);

                    RPRINTK(DPRTL_ON, ("\tset fe state closed.\n"));
                    xenbus_printf(XBT_NIL, info->nodename,
                                  state_str, "%d", XenbusStateClosed);
                } else {
                    PRINTK(("vs_hotplug: couldn't find sdev %s/%s to del\n",
                            info->nodename, dir[i]));
                }
            } else {
                RPRINTK(DPRTL_ON, ("vs_hotplug: fe ! Closing, do nothing\n"));
            }
            break;
        default:
            break;
        }
        xenbus_free_string(state_str);
    }

    ExFreePool(dir);

    RPRINTK(DPRTL_ON, ("vs_hotplug end\n"));
    return;
}

static XenbusState
vs_backend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    UNREFERENCED_PARAMETER(len);

    struct vscsi_front_info *info = (struct vscsi_front_info *)watch->context;
    char *buf;
    XEN_LOCK_HANDLE lh;
    XenbusState backend_state;
    XenbusState frontend_state;

    if (vec) {
        RPRINTK(DPRTL_INIT, ("vs_backend_changed: %s, ", vec[0]));
    }
    if (talking_to_backend) {
        RPRINTK(DPRTL_FRNT,
            ("vs_backend_changed called while talking to backend.\n"));
    }

    buf = xenbus_read(XBT_NIL, info->otherend, "state", NULL);
    if (buf == NULL) {
        xenbus_printf(XBT_NIL, info->nodename, "reading state", "%x", buf);
        PRINTK(("vs_backend_changed: failed to read state from %s.\n",
            info->otherend));
        if (info->connected != BLKIF_STATE_DISCONNECTED) {
            return XenbusStateUnknown;
        }

        backend_state = XenbusStateClosed;
    } else {
        backend_state = (enum xenbus_state)cmp_strtou64(buf, NULL, 10);
        xenbus_free_string(buf);
        RPRINTK(DPRTL_INIT, ("st %d.\n", backend_state));
    }

    buf = xenbus_read(XBT_NIL, info->nodename, "state", NULL);
    if (buf == NULL) {
        xenbus_printf(XBT_NIL, info->nodename, "reading state", "%x", buf);
        PRINTK(("vs_backend_changed: failed to read state from %s.\n",
            info->nodename));
        if (info->connected != BLKIF_STATE_DISCONNECTED) {
            return XenbusStateUnknown;
        }

        frontend_state = XenbusStateClosed;
    } else {
        frontend_state = (enum xenbus_state)cmp_strtou64(buf, NULL, 10);
        xenbus_free_string(buf);
        RPRINTK(DPRTL_INIT, ("vs_backend_changed: fe st %d.\n",
            frontend_state));
    }

    RPRINTK(DPRTL_ON, ("vs_backend_changed: be state %u, fe state %u\n",
        backend_state, frontend_state));

    switch (backend_state) {
    case XenbusStateUnknown:
    case XenbusStateInitialising:
    case XenbusStateInitWait:
        RPRINTK(DPRTL_ON, ("vs_backend_changed: be state %u break\n",
                           backend_state));
        break;

    case XenbusStateClosed:

        RPRINTK(DPRTL_ON, ("vs_backend_changed: %s changed to closed\n",
                           info->nodename));
        XenAcquireSpinLock(&info->lock, &lh);
        unregister_xenbus_watch(&info->watch);
        if (info->ring_ref) {
            gnttab_end_foreign_access(info->ring_ref, 0);
            info->ring_ref = 0;
        }
        XenScsiFreeResource(info, XENBLK_MAXIMUM_TARGETS, RELEASE_REMOVE);
        XenReleaseSpinLock(&info->lock, lh);
        break;

    case XenbusStateInitialised:
        RPRINTK(DPRTL_ON, ("vs_backend_changed: be changed to %u, break\n",
                           backend_state));
        break;

    case XenbusStateConnected:
        if (frontend_state == XenbusStateInitialised) {
            RPRINTK(DPRTL_ON,
                    ("vs_backend_changed: be is connected, fe initialised\n"));
            RPRINTK(DPRTL_ON, ("  do vs_hotplug add\n"));
            vs_hotplug(info, VSCSIFRONT_OP_ADD_LUN);
            xenscsi_notification(BusChangeDetected, info->xbdev, 0);
        }

        if (frontend_state == XenbusStateConnected) {
            RPRINTK(DPRTL_ON,  ("vs_backend_changed: fe & be connected\n"));
            break;
        }

        RPRINTK(DPRTL_ON,
                ("vs_backend_changed: be connected, set fe to connected\n"));

        xenbus_switch_state(info->nodename, XenbusStateConnected);
        info->connected = BLKIF_STATE_CONNECTED;
        break;

    case XenbusStateClosing:
        RPRINTK(DPRTL_ON,
                ("vs_backend_changed: be closing, vs_disconnect.\n"));
        vs_disconnect(info);
        break;

    case XenbusStateReconfiguring:
        RPRINTK(DPRTL_ON,
                ("vs_backend_changed: be is reconfiguring, vs_hotplug del\n"));
        vs_hotplug(info, VSCSIFRONT_OP_DEL_LUN);
        RPRINTK(DPRTL_ON, ("\tswitching fe to XenbusStateReconfiguring\n"));
        xenbus_switch_state(info->nodename, XenbusStateReconfiguring);
        break;

    case XenbusStateReconfigured:
        RPRINTK(DPRTL_ON,
                ("vs_backend_changed: be is reconfigured, vs_hotplug add.\n"));
        vs_hotplug(info, VSCSIFRONT_OP_ADD_LUN);
        RPRINTK(DPRTL_ON, ("\tswitching fe to XenbusStateConnected.\n"));
        xenbus_switch_state(info->nodename, XenbusStateConnected);
        if (!IsListEmpty(&info->sdev_list)) {
            RPRINTK(DPRTL_ON,
                    ("vs_backend_changed: reconfigured, do rescan.\n"));
            xenscsi_notification(BusChangeDetected, info->xbdev, 0);
        }
        break;
    }
    RPRINTK(DPRTL_ON, ("vs_backend_changed out\n"));
    return backend_state;
}

static uint16_t
vs_get_id_from_freelist(struct vscsi_front_info *info)
{
    uint16_t free;

    CDPRINTK(DPRTL_COND, 0, 1, (info->xenscsi_locks & BLK_ID_L),
        ("%s already set: irql %x, cpu %x, xlocks %x on 0x%x\n",
        __func__, KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
        info->xenscsi_locks, info->cpu_locks));

    XENSCSI_SET_FLAG(info->xenscsi_locks, (BLK_ID_L | BLK_GET_L));
    XENSCSI_SET_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));

    free = info->shadow_free;
    ASSERT(free < VSCSI_RING_SIZE);
    info->shadow_free = info->shadow[free].req.id;
    info->shadow[free].req.id = 0x0fee; /* debug */

    XENSCSI_CLEAR_FLAG(info->xenscsi_locks, (BLK_ID_L | BLK_GET_L));
    XENSCSI_CLEAR_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));

    return free;
}

static void
vs_add_id_to_freelist(struct vscsi_front_info *info, uint16_t id)
{
    CDPRINTK(DPRTL_COND, 0, 1, (info->xenscsi_locks & BLK_ID_L),
        ("%s already set: irql %x, cpu %x, xlocks %x on 0x%x\n",
        __func__, KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
        info->xenscsi_locks, info->cpu_locks));

    XENSCSI_SET_FLAG(info->xenscsi_locks, (BLK_ID_L | BLK_ADD_L));
    XENSCSI_SET_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));

    info->shadow[id].req.id  = info->shadow_free;
    info->shadow[id].request = NULL;
    info->shadow_free = id;

    XENSCSI_CLEAR_FLAG(info->xenscsi_locks, (BLK_ID_L | BLK_ADD_L));
    XENSCSI_CLEAR_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
}

static inline void
vs_flush_requests(struct vscsi_front_info *info)
{
    int notify;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->ring, notify);

    if (notify) {
        notify_remote_via_irq(info->evtchn);
    }
#ifdef DBG
    else {
        DPRINTK(DPRTL_RING, ("vs_flush_requests: don't notify\n"));
    }
#endif
}

static void
vs_restart_queue(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    struct vscsi_front_info *info = (struct vscsi_front_info *)Context;

    if (info->connected == BLKIF_STATE_CONNECTED) {
        vs_flush_requests(info);
    }
}

static void
vs_restart_queue_callback(void *arg)
{
    struct vscsi_front_info *info = (struct vscsi_front_info *)arg;

    xenscsi_request_timer_call(RequestTimerCall, info->xbdev,
        vs_restart_queue, 100);
}

static vscsiif_request_t *
vs_get_request(vscsi_front_info_t *info)
{
    vscsiif_request_t *ring_req;
    XENSCSI_LOCK_HANDLE int_lh = {0};
    uint32_t id;

    ring_req = RING_GET_REQUEST(&(info->ring), info->ring.req_prod_pvt);
    info->ring.req_prod_pvt++;

    storport_acquire_spinlock(info->xbdev, InterruptLock, NULL, &int_lh);
    id = vs_get_id_from_freelist(info);
    storport_release_spinlock(info->xbdev, int_lh);
    vs_completion(&info->shadow[id]);

    ring_req->rqid = (uint16_t)id;

    return ring_req;
}

static void
vs_completion(struct vscsi_shadow *s)
{
    int i;

    if (s->sc_data_direction == DMA_NONE) {
        return;
    }

    for (i = 0; i < s->req.nr_segments; i++) {
        gnttab_end_foreign_access(s->req.seg[i].gref, 0);
    }
    s->req.nr_segments = 0;
}

static int
vs_map_data_for_request(vscsi_front_info_t *info,
    SCSI_REQUEST_BLOCK *srb, vscsiif_request_t *ring_req, uint32_t rqid)
{
    PFN_NUMBER pfn;
    ULONG bytes;
    ULONG i;
    grant_ref_t gref_head;
    int err, ref;
    int write;
    unsigned int nr_pages, ref_cnt, offset;
    STOR_SCATTER_GATHER_LIST *sgl;
    STOR_SCATTER_GATHER_ELEMENT *sg;
    ULONG data_len;
    ULONG len;
    xenscsi_srb_extension *srb_ext;
#ifdef DBG
    uint64_t disk_offset = 0;
#endif

    if (ring_req->sc_data_direction == DMA_NONE) {
        return 0;
    }
    if (srb->DataTransferLength == 0) {
        return 0;
    }

    /*
     * nr_pages may be 1 more that the number of pages needed by
     * DataTransferLength if the first and last element sum to PAGE_SIZE.
     */
    nr_pages = ((srb->DataTransferLength + PAGE_SIZE - 1) >> PAGE_SHIFT) + 1;
    if (nr_pages > VSCSIIF_SG_TABLESIZE) {
        PRINTK(("vs_map_data_for_request: too many pages %u\n", nr_pages));
        return -ERANGE;
    }

    srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;
    if (srb_ext->sgl) {
        sgl = srb_ext->sgl;
    } else {
        sgl = xenscsi_build_sgl(info->xbdev, srb);
    }
    if (sgl == NULL) {
        PRINTK(("vs_map_data_for_request: failed to get sgl\n"));
        return -ENOMEM;
    }

    err = gnttab_alloc_grant_references(VSCSIIF_SG_TABLESIZE, &gref_head);
    if (err) {
        PRINTK(("vs_map_data_for_request: failed to alloc grant refs\n"));
        return -ENOMEM;
    }

#ifdef DBG
    if (srb->Cdb[0] == SCSIOP_READ
            || srb->Cdb[0] == SCSIOP_WRITE
            || srb->Cdb[0] == SCSIOP_READ16
            || srb->Cdb[0] == SCSIOP_WRITE16) {
        if (srb->Cdb[0] < SCSIOP_READ16) {
            disk_offset = ((uint64_t)((uint32_t)(
                ((PCDB)srb->Cdb)->CDB10.LogicalBlockByte3
                | ((PCDB)srb->Cdb)->CDB10.LogicalBlockByte2 << 8
                | ((PCDB)srb->Cdb)->CDB10.LogicalBlockByte1 << 16
                | ((PCDB)srb->Cdb)->CDB10.LogicalBlockByte0 << 24)));
        } else {
            REVERSE_BYTES_QUAD(&disk_offset,
                               ((PCDB)srb->Cdb)->CDB16.LogicalBlock);
            DPRINTK(DPRTL_TRC,
                ("\tREV: %02x%02x%02x%02x%02x%02x%02x%02x, %x%08x.\n",
                ((PCDB)srb->Cdb)->CDB16.LogicalBlock[0],
                ((PCDB)srb->Cdb)->CDB16.LogicalBlock[1],
                ((PCDB)srb->Cdb)->CDB16.LogicalBlock[2],
                ((PCDB)srb->Cdb)->CDB16.LogicalBlock[3],
                ((PCDB)srb->Cdb)->CDB16.LogicalBlock[4],
                ((PCDB)srb->Cdb)->CDB16.LogicalBlock[5],
                ((PCDB)srb->Cdb)->CDB16.LogicalBlock[6],
                ((PCDB)srb->Cdb)->CDB16.LogicalBlock[7],
                (uint32_t)(disk_offset >> 32),
                (uint32_t)disk_offset));
        }
    }
#endif

    write = (ring_req->sc_data_direction == DMA_TO_DEVICE);
    ref_cnt = 0;

    data_len = srb->DataTransferLength;
    for (i = 0; i < sgl->NumberOfElements; i++) {
        sg = &sgl->List[i];
        offset = sg->PhysicalAddress.u.LowPart & (PAGE_SIZE - 1);
        len = sg->Length;

        pfn = (ULONG)(sg->PhysicalAddress.QuadPart >> PAGE_SHIFT);

        while (len > 0 && data_len > 0) {
            /*
             * sg sends a scatterlist that is larger than
             * the data_len it wants transferred for certain
             * IO sizes
             */
            bytes = min(len, PAGE_SIZE - offset);
            bytes = min(bytes, data_len);

            ref = gnttab_claim_grant_reference(&gref_head);
            if (ref == -1) {
                ref_cnt = ref;
                break;
            }
            gnttab_grant_foreign_access_ref(ref, info->otherend_id,
                (ULONG)pfn, write);

            info->shadow[rqid].req.seg[ref_cnt].gref = ref;
            ring_req->seg[ref_cnt].gref   = ref;
            ring_req->seg[ref_cnt].offset = (uint16_t)offset;
            ring_req->seg[ref_cnt].length = (uint16_t)bytes;

            pfn++;
            len -= bytes;
            data_len -= bytes;
            offset = 0;
            ref_cnt++;
        }
    }
#ifdef DBG
    if (ref_cnt > nr_pages) {
        PRINTK(("FN %x: disk_offset 0x%x, ref_cnt %d, pgs %d, len %d\n",
            srb->Cdb[0], (uint32_t)disk_offset, ref_cnt, nr_pages,
            srb->DataTransferLength));
    }
#endif

    gnttab_free_grant_references(gref_head);

    return ref_cnt;
}

UCHAR
vscsi_do_request(vscsi_front_info_t *info, SCSI_REQUEST_BLOCK *srb)
{
    vscsiif_request_t *ring_req;
    xenscsi_srb_extension *srb_ext;
    XEN_LOCK_HANDLE lh;
    int ref_cnt;
    uint16_t rqid;
    vscsi_dev_t *sdev;

    XenAcquireSpinLock(&info->lock, &lh);
    if (RING_FULL(&info->ring)) {
        XenReleaseSpinLock(&info->lock, lh);
        PRINTK(("vscsi_do_request: Ring full\n"));
        return SRB_STATUS_BUSY;
    }

    sdev = vs_guest_dev_lookup(info->sdev, srb->PathId,
                               srb->TargetId, srb->Lun);
    if (sdev == NULL) {
        DPRINTK(DPRTL_ON,
            ("vscsi_do_request: No sdev for chn %u, tid %u, lun %u\n",
            srb->PathId, srb->TargetId, srb->Lun));
        XenReleaseSpinLock(&info->lock, lh);
        return SRB_STATUS_NO_DEVICE;
    }

    srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;

#ifdef DBG
    if (info->ring.sring->rsp_prod != info->ring.rsp_cons) {
        DPRINTK(DPRTL_RING,
                ("info->ring.sring->rsp_prod != info->ring.rsp_cons: %d %d\n",
                 info->ring.sring->rsp_prod, info->ring.rsp_cons));
    }

    if (srb_ext->next) {
        PRINTK(("%s: srb %p ext %p next should be 0, %p\n",
            __func__, srb, srb_ext, srb_ext->next));
    }

    if (srb_ext->use_cnt) {
        PRINTK(("%s: srb %p ext %p use count should be 0 but is %d\n",
                __func__, srb, srb_ext, srb_ext->use_cnt));

        PRINTK(("    uresp %d, prod_pvt %d rsp_prod %d rsp_con %d req_evt %d\n",
                RING_HAS_UNCONSUMED_RESPONSES(&info->ring),
                info->ring.req_prod_pvt,
                info->ring.sring->rsp_prod, info->ring.rsp_cons,
                info->ring.sring->req_event));
        return SRB_STATUS_BUSY;
    }
#endif

    ring_req            = vs_get_request(info);
    rqid                = ring_req->rqid;
    ring_req->act       = VSCSIIF_ACT_SCSI_CDB;
    ring_req->id        = sdev->tid;
    ring_req->lun       = sdev->lun;
    ring_req->channel   = sdev->chn;
    ring_req->cmd_len   = min(srb->CdbLength, VSCSIIF_MAX_COMMAND_SIZE);
    ring_req->timeout_per_command = (USHORT)srb->TimeOutValue;

    if (ring_req->cmd_len) {
        memcpy(ring_req->cmnd, srb->Cdb, ring_req->cmd_len);
    } else {
        memset(ring_req->cmnd, 0, VSCSIIF_MAX_COMMAND_SIZE);
    }

    if (srb->DataTransferLength && (srb->SrbFlags & SRB_FLAGS_DATA_IN)
            && (srb->SrbFlags & SRB_FLAGS_DATA_OUT)) {
        ring_req->sc_data_direction = DMA_BIDIRECTIONAL;
    } else if (srb->DataTransferLength &&
            (srb->SrbFlags & SRB_FLAGS_DATA_IN)) {
        ring_req->sc_data_direction = DMA_FROM_DEVICE;
    } else if (srb->DataTransferLength &&
            (srb->SrbFlags & SRB_FLAGS_DATA_OUT)) {
        ring_req->sc_data_direction = DMA_TO_DEVICE;
    } else {
        ring_req->sc_data_direction = DMA_NONE;
    }

    info->shadow[rqid].request              = srb;
    info->shadow[rqid].sc_data_direction    = ring_req->sc_data_direction;
    info->shadow[rqid].act                  = ring_req->act;

    ref_cnt = vs_map_data_for_request(info, srb, ring_req, rqid);
    if (ref_cnt < 0) {
        vs_add_id_to_freelist(info, rqid);
        XenReleaseSpinLock(&info->lock, lh);
        PRINTK(("vscsi_do_request: vs_map_data_for_request failed\n"));
        return SRB_STATUS_BUSY;
    }

    ring_req->nr_segments          = (uint8_t)ref_cnt;
    info->shadow[rqid].nr_segments = ref_cnt;

    /* Copy the ring_req into the shadow. */
    info->shadow[rqid].req = *ring_req;

    info->shadow[rqid].srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;
    InterlockedIncrement((LONG *)&srb_ext->use_cnt);

#ifdef DBG
    info->shadow[rqid].seq = info->seq;
    InterlockedIncrement((LONG *)&info->seq);

    if (srb_ext->use_cnt != 1) {
        PRINTK(("srb: %p %p use count should be 1, %d\n",
                srb, srb_ext, srb_ext->use_cnt));
    }
    if (srb_ext->next) {
        PRINTK(("srb: %p %p end next should be 0, %p\n",
                srb, srb_ext, srb_ext->next));
    }

    if (info->shadow[rqid].request == NULL) {
        PRINTK(("rqid %d request is null.\n", rqid));
    }
    if (info->shadow[rqid].srb_ext->srb != info->shadow[rqid].request) {
            PRINTK(("rqid %d srb != request. %p %p\n",
                    rqid,
                    info->shadow[rqid].srb_ext->srb,
                    info->shadow[rqid].request));
    }
#endif

    /*
     * Check if there are virtual and system addresses that need to be
     * freed and unmapped now that we are at DPC time.
     */
    xenscsi_unmap_system_addresses(info);

    vs_flush_requests(info);

    XenReleaseSpinLock(&info->lock, lh);

    return SRB_STATUS_PENDING;
}

/* vscsi supports only device_reset, because it is each of LUNs */
UCHAR
vscsi_do_reset(vscsi_front_info_t *info, SCSI_REQUEST_BLOCK *srb)
{
    vscsiif_request_t *ring_req;
    xenscsi_srb_extension *srb_ext;
    XEN_LOCK_HANDLE lh;
    uint16_t rqid;
    vscsi_dev_t *sdev;

    XenAcquireSpinLock(&info->lock, &lh);
    if (RING_FULL(&info->ring)) {
        XenReleaseSpinLock(&info->lock, lh);
        PRINTK(("vscsi_do_request: Ring full\n"));
        return SRB_STATUS_BUSY;
    }

    sdev = vs_guest_dev_lookup(info->sdev, srb->PathId,
                               srb->TargetId, srb->Lun);
    if (sdev == NULL) {
        RPRINTK(DPRTL_ON,
            ("vscsi_do_request: No sdev for chn %u, tid %u, lun %u\n",
            srb->PathId, srb->TargetId, srb->Lun));
        XenReleaseSpinLock(&info->lock, lh);
        return SRB_STATUS_NO_DEVICE;
    }

    KeInitializeEvent(&info->vs_reset_event, SynchronizationEvent, FALSE);

    srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;

    ring_req            = vs_get_request(info);
    rqid                = ring_req->rqid;
    ring_req->act       = VSCSIIF_ACT_SCSI_RESET;
    ring_req->id        = sdev->tid;
    ring_req->lun       = sdev->lun;
    ring_req->channel   = sdev->chn;
    ring_req->cmd_len   = min(srb->CdbLength, VSCSIIF_MAX_COMMAND_SIZE);
    ring_req->timeout_per_command = (USHORT)srb->TimeOutValue;

    InterlockedIncrement((LONG *)&srb_ext->use_cnt);

    if (ring_req->cmd_len) {
        memcpy(ring_req->cmnd, srb->Cdb, ring_req->cmd_len);
    } else {
        memset(ring_req->cmnd, 0, VSCSIIF_MAX_COMMAND_SIZE);
    }


    if (srb->DataTransferLength && (srb->SrbFlags & SRB_FLAGS_DATA_IN) &&
            (srb->SrbFlags & SRB_FLAGS_DATA_OUT)) {
        ring_req->sc_data_direction = DMA_BIDIRECTIONAL;
    } else if (srb->DataTransferLength &&
            (srb->SrbFlags & SRB_FLAGS_DATA_IN)) {
        ring_req->sc_data_direction = DMA_FROM_DEVICE;
    } else if (srb->DataTransferLength &&
            (srb->SrbFlags & SRB_FLAGS_DATA_OUT)) {
        ring_req->sc_data_direction = DMA_TO_DEVICE;
    } else {
        ring_req->sc_data_direction = DMA_NONE;
    }

    info->shadow[rqid].request           = srb;
    info->shadow[rqid].sc_data_direction = ring_req->sc_data_direction;
    info->shadow[rqid].act               = ring_req->act;

    ring_req->nr_segments = 0;

    info->shadow[rqid].req = *ring_req;

    info->shadow[rqid].srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;
    vs_flush_requests(info);
    XenReleaseSpinLock(&info->lock, lh);

    DPRINTK(DPRTL_ON,
        ("do: fn %x id %d req %p srb %p ext %p, t %d p %d c %d\n",
        srb->Cdb[0],
        rqid,
        info->shadow[rqid].request,
        info->shadow[rqid].srb_ext->srb,
        info->shadow[rqid].srb_ext,
        info->ring.req_prod_pvt,
        info->ring.sring->rsp_prod, info->ring.rsp_cons));

    DPRINTK(DPRTL_ON, ("vscsi_do_reset: KeWaitForSingleObject\n"));
    KeWaitForSingleObject(&info->vs_reset_event,
        Executive, KernelMode, FALSE, NULL);
    PRINTK(("vscsi_do_reset: Done waiting for vs reset event\n"));
    return SRB_STATUS_SUCCESS;
}

static void
vs_complete_request(struct vscsi_front_info *info, SCSI_REQUEST_BLOCK *srb,
    unsigned int status)
{
    xenscsi_srb_extension *srb_ext;
#ifdef DBG
    int i, j;
    uint8_t *va;

    va = (uint8_t *)srb->DataBuffer;

    DPRINTK(DPRTL_IO,
        ("vs_complete_request: cmd %x, status %x:\n", srb->Cdb[0], status));
    if (srb->Cdb[0] == 0x12 && srb->Cdb[1] == 0) {
        for (j = 0; j < 16; j++) {
            if (va[j] > 0x20 && va[j] < 0x7f) {
                DPRINTK(DPRTL_IO, ("%c ", va[j]));
            } else {
                DPRINTK(DPRTL_IO, ("%x ", va[j]));
            }
        }
        DPRINTK(DPRTL_IO, ("\n"));
        for (; j < 32; j++) {
            if (va[j] > 0x20 && va[j] < 0x7f) {
                DPRINTK(DPRTL_IO, ("%c ", va[j]));
            } else {
                DPRINTK(DPRTL_IO, ("%x ", va[j]));
            }
        }
        DPRINTK(DPRTL_IO, ("\n"));
    } else if (srb->Cdb[0] == 0x25) {
        for (j = 0; j < 4; j++) {
            DPRINTK(DPRTL_IO, ("%x ", va[j]));
        }
        DPRINTK(DPRTL_IO, ("-- "));
        for (; j < 8; j++) {
            DPRINTK(DPRTL_IO, ("%x ", va[j]));
        }
        DPRINTK(DPRTL_IO, ("\n"));
    } else if (srb->Cdb[0] == 0x9e) {
        for (j = 0; j < 8; j++) {
            DPRINTK(DPRTL_IO, ("%x ", va[j]));
        }
        DPRINTK(DPRTL_IO, ("-- "));
        for (; j < 12; j++) {
            DPRINTK(DPRTL_IO, ("%x ", va[j]));
        }
        DPRINTK(DPRTL_IO, ("\n"));
    } else {
        if (va) {
            DPRINTK(DPRTL_IO, ("%x %x\n", va[0], va[1]));
        }
    }

    if (srb->Function == SRB_FUNCTION_EXECUTE_SCSI
            && srb->Cdb[0] == SCSIOP_INQUIRY
            && srb->Cdb[1] == 0) {
        PINQUIRYDATA inquiryData;

        inquiryData = srb->DataBuffer;
        PRINTK(("Inquery: type %x, qualifier %x, removable %x, queue %d\n",
                inquiryData->DeviceType,
                inquiryData->DeviceTypeQualifier,
                inquiryData->RemovableMedia,
                inquiryData->CommandQueue));
        if (inquiryData->CommandQueue) {
            i = xenscsi_set_queue_depth(info->xbdev, srb,
                                        RING_SIZE(&info->ring) / 2);
            DPRINTK(DPRTL_ON,
                    ("Queue depth set to %d, status %d\n",
                     RING_SIZE(&info->ring) / 2, i));
        }
    }

    if (srb->Function == SRB_FUNCTION_EXECUTE_SCSI) {
        DPRINTK(DPRTL_IO,
            ("%s: srb %p function %x sub %x\n",
            __func__, srb, srb->Function, srb->Cdb[0]));
    } else {
        DPRINTK(DPRTL_IO,
            ("%s: srb %p function %x\n",
            __func__, srb, srb->Function));
    }
#endif

    srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;
    if (srb_ext->va) {
        if (srb->Cdb[0] == SCSIOP_READ || srb->Cdb[0] == SCSIOP_READ16) {
            DPRINTK(DPRTL_MM,
                (" xenblk_cp_to_sa: srb %p, ext %p, va %p, sa %p\n",
                srb, srb_ext, srb_ext->va, srb_ext->sa));
            xenscsi_cp_to_sa(srb_ext->sa, srb_ext->sys_sgl, srb_ext->va);
            DPRINTK(DPRTL_MM, ("\tRtlCopyMemory done.\n"));
        }

        /*
         * Save the virtual and system addresses so that they can be
         * freed and unmapped at DPC time rather than at interrupt time.
         */
        xenscsi_save_system_address(info, srb_ext);
        DPRINTK(DPRTL_MM, ("\tabout to complete %p.\n", srb));
    }

    if (status == 0) {
        srb->SrbStatus = SRB_STATUS_SUCCESS;
    } else {
        DPRINTK(DPRTL_ON, ("%s: FN %x status %x\n",
            __func__, srb->Cdb[0], status));
        srb->SrbStatus = SRB_STATUS_ERROR;
    }

    if (srb->Function == SRB_FUNCTION_RESET_DEVICE
            ||  srb->Function == SRB_FUNCTION_RESET_LOGICAL_UNIT) {
        DPRINTK(DPRTL_ON, ("Set the reset event\n"));
        KeSetEvent((PKEVENT)&info->vs_reset_event, IO_NO_INCREMENT, FALSE);
    } else {
        /* Normal completion. */
        XENSCSI_INC_SRB(srbs_returned);
        XENSCSI_INC_SRB(io_srbs_returned);
        XENSCSI_INC_SRB(sio_srbs_returned);
        xenscsi_next_request(NextRequest, info->xbdev);
        xenscsi_request_complete(RequestComplete, info->xbdev, srb);
    }
}

uint32_t
vscsi_complete_int(struct vscsi_front_info *info)
{
    XEN_LOCK_HANDLE lh;
    SCSI_REQUEST_BLOCK *srb;
    vscsiif_response_t *ring_rsp;
    RING_IDX i, rp;
    uint16_t id;
    uint32_t did_work = 0;
    int more_to_do = 1;
    uint16_t status;
#ifdef DBG
    int outoforder = 0;
#endif

    DPRINTK(DPRTL_TRC,
        ("vscsi_complete_int - IN irql = %d\n", KeGetCurrentIrql()));

    XenAcquireSpinLock(&info->lock, &lh);
    if (info->connected) {
        while (more_to_do) {
            rp = info->ring.sring->rsp_prod;
            rmb(); /* Ensure we see queued responses up to 'rp'. */

            for (i = info->ring.rsp_cons; i != rp; i++) {
                ring_rsp = RING_GET_RESPONSE(&info->ring, i);
                id = ring_rsp->rqid;

                /*
                 * vs_completion(&info->shadow[id]);
                 * is done right after GET_ID_FROM_FREE_LIST
                 */

#ifdef DBG
                if (info->shadow[id].seq > info->cseq) {
                    DPRINTK(DPRTL_RING,
                            ("XENSCSI: sequence, %x - %x: req %p, status %x\n",
                            info->shadow[id].seq, info->cseq,
                            info->shadow[id].request, ring_rsp->rslt));

                }
                InterlockedIncrement((LONG *)&info->cseq);
#endif
                InterlockedDecrement((LONG *)&info->shadow[id].srb_ext->use_cnt);

                if (info->shadow[id].request) {
#ifdef DBG
                    if (info->shadow[id].srb_ext->srb
                            != info->shadow[id].request) {
                        PRINTK(("id %d srb != request. %p %p\n",
                                id,
                                info->shadow[id].srb_ext->srb,
                                info->shadow[id].request));
                    }
                    if (info->shadow[id].srb_ext->use_cnt) {
                        PRINTK(("XENSCSI: srb %p %p use count %x\n",
                                info->shadow[id].request,
                                info->shadow[id].srb_ext,
                                info->shadow[id].srb_ext->use_cnt));
                        outoforder = 1;
                        info->queued_srb_ext++;
                    }
                    InterlockedDecrement((LONG *)&info->req);
#endif
                    srb = info->shadow[id].srb_ext->srb;
                    if (srb->SenseInfoBuffer != NULL) {
                        memset(srb->SenseInfoBuffer, 0,
                               srb->SenseInfoBufferLength);
                        if (ring_rsp->sense_len > 0) {
                            memcpy(srb->SenseInfoBuffer,
                                   ring_rsp->sense_buffer,
                                   min(srb->SenseInfoBufferLength,
                                       ring_rsp->sense_len));
                        }
                    }

                    info->shadow[id].srb_ext->status = (uint16_t)ring_rsp->rslt;
                    xenscsi_add_tail(info, info->shadow[id].srb_ext);
                } else {
                    PRINTK(("info->shadow[%p].request is null\n", id));
                }

                vs_add_id_to_freelist(info, id);
                did_work++;
            }

            info->ring.rsp_cons = i;

            if (i != info->ring.req_prod_pvt) {
                RING_FINAL_CHECK_FOR_RESPONSES(&info->ring, more_to_do);
            } else {
                info->ring.sring->rsp_event = i + 1;
                more_to_do = 0;
            }
        }

        while (info->hsrb_ext) {
            if (info->hsrb_ext->use_cnt == 0) {
#ifdef DBG
                if (outoforder) {
                    DPRINTK(DPRTL_ON, ("XENSCSI: completing sequenced srb %p\n",
                        info->hsrb_ext->srb));
                    info->queued_srb_ext--;
                } else if (info->queued_srb_ext) {
                    DPRINTK(DPRTL_ON, ("XENSCSI: completing queued, srb %p\n",
                        info->hsrb_ext->srb));
                    info->queued_srb_ext--;
                }
#endif
                srb = info->hsrb_ext->srb;
                status = info->hsrb_ext->status;
                info->hsrb_ext = info->hsrb_ext->next;
                vs_complete_request(info, srb, status);
            } else {
                if ((int32_t)info->hsrb_ext->use_cnt) {
                    PRINTK(("* XENSCSI: srb %p, %p status %x, use_count %x.\n",
                        info->hsrb_ext->srb,
                        info->hsrb_ext->srb->SrbExtension,
                        info->hsrb_ext->status,
                        info->hsrb_ext->use_cnt));
                }
                if (info->hsrb_ext->next) {
                    PRINTK(("* XENSCSI: srb %p, %p next %p\n",
                        info->hsrb_ext->srb,
                        info->hsrb_ext->srb->SrbExtension,
                        info->hsrb_ext->next));
                }
                break;
            }
        }
    }

    DPRINTK(DPRTL_TRC, ("  vscsi_complete_int - OUT\n"));
    XenReleaseSpinLock(&info->lock, lh);

    return did_work;
}

void
vscsi_int_dpc(PKDPC dpc, PVOID dcontext, PVOID sa1, PVOID sa2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(dcontext);
    UNREFERENCED_PARAMETER(sa2);

    struct vscsi_front_info *info = (struct vscsi_front_info *)sa1;

    vscsi_complete_int(info);
}

void
vscsi_xenbus_int(PKDPC dpc, PVOID dcontext, PVOID sa1, PVOID sa2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(sa1);
    UNREFERENCED_PARAMETER(sa2);

    struct vscsi_front_info *info = (struct vscsi_front_info *)dcontext;

    if (info == NULL) {
        return;
    }
    StorPortIssueDpc(info->xbdev, &info->vscsi_int_dpc, info, NULL);
}

void
vscsi_quiesce(struct vscsi_front_info *info)
{
    uint32_t j;
    vscsiif_response_t *ring_rsp;
    RING_IDX i, id;

    XENSCSI_ZERO_VALUE(conditional_times_to_print_limit);

    RPRINTK(DPRTL_ON, ("vscsi_quiesce: IN\n"));
    for (j = 0; j < VSCSI_RING_SIZE; j++) {
        if (info->shadow[j].request) {
            PRINTK(("vscsi_quiesce: waiting for %d %p\n",
                    j, info->shadow[j].request));
        }
    }
    info->ring.sring->rsp_prod = info->ring.req_prod_pvt;
    rmb(); /* Ensure we see queued responses up to 'rp'. */
    for (i = info->ring.rsp_cons; i != info->ring.sring->rsp_prod; i++) {
        ring_rsp = RING_GET_RESPONSE(&info->ring, i);
        id = ring_rsp->rqid;
        PRINTK(("vscsi_quiesce: failing request %d %p\n",
                id, info->shadow[id].request));
        ring_rsp->rslt = 2;
        info->shadow[id].srb_ext->status = 2;
    }
    while (info->ring.rsp_cons != info->ring.req_prod_pvt) {
        RPRINTK(DPRTL_FRNT,
            ("vscsi_quiesce outstanding reqs %p: %x %x\n",
            info, info->ring.rsp_cons, info->ring.req_prod_pvt));
        vscsi_complete_int(info);
    }

    /* Clear out any grants that may still be around. */
    RPRINTK(DPRTL_FRNT,
        ("vscsi_quiesce: doing shadow completion\n"));
    for (j = 0; j < VSCSI_RING_SIZE; j++) {
        vs_completion(&info->shadow[j]);
    }
    RPRINTK(DPRTL_ON, ("vscsi_quiesce: OUT\n"));
    DPR_SRB("Q");
}

void
vscsi_disconnect_backend(XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    XEN_LOCK_HANDLE lh;
    char *buf;
    enum xenbus_state backend_state;
    struct vscsi_front_info *info;

    RPRINTK(DPRTL_ON, ("%s: IN\n", __func__));
    info = dev_ext->info;
    XenAcquireSpinLock(&info->lock, &lh);
    if (info->xbdev) {
        /*
         * Since we are doing the disconnect, unregister the watch so
         * we wont get a callback after we have freed resources.
         */
        unregister_xenbus_watch(&info->watch);
        if (info->evtchn) {
            RPRINTK(DPRTL_FRNT,
                ("      disconnect unregister_dpc_from_evtchn %d\n",
                info->evtchn));
            unregister_dpc_from_evtchn(info->evtchn);
            xenbus_free_evtchn(info->evtchn);
            info->evtchn = 0;
        }
        vscsi_quiesce(info);

        RPRINTK(DPRTL_FRNT,
            ("      switching to closeing: %s\n", info->nodename));
        xenbus_switch_state(info->nodename, XenbusStateClosing);
        RPRINTK(DPRTL_ON, ("%s: waiting for XenbusStateClosing\n", __func__));
        do {
            buf = xenbus_read(XBT_NIL, info->otherend, "state", NULL);
            if (buf) {
                backend_state = (enum xenbus_state)
                    cmp_strtou64(buf, NULL, 10);
                xenbus_free_string(buf);
                if (backend_state == XenbusStateClosing) {
                    RPRINTK(DPRTL_FRNT,
                        ("      back end state is closing\n"));
                    break;
                }
            } else {
                PRINTK(("%s: null waiting for XenbusStateClosing\n", __func__));
            }
        } while (buf);

        RPRINTK(DPRTL_FRNT,
            ("      switching to closed: %s\n", info->nodename));
        xenbus_switch_state(info->nodename, XenbusStateClosed);
        RPRINTK(DPRTL_ON,
            ("%s: waiting for XenbusStateClosed\n", __func__));
        do {
            buf = xenbus_read(XBT_NIL, info->otherend, "state", NULL);
            if (buf) {
                backend_state = (enum xenbus_state)
                    cmp_strtou64(buf, NULL, 10);
                xenbus_free_string(buf);
                if (backend_state == XenbusStateClosed) {
                    RPRINTK(DPRTL_FRNT,
                        ("      back end state is closed.\n"));
                    break;
                }
            } else {
                PRINTK(("%s: null waiting for XenbusStateClosed\n", __func__));
            }
        } while (buf);

        RPRINTK(DPRTL_FRNT,
            ("      switching to initializing: %s.\n", info->nodename));
        xenbus_switch_state(info->nodename, XenbusStateInitialising);
        RPRINTK(DPRTL_ON,
            ("%s: waiting for XenbusStateInitWait\n", __func__));
        do {
            buf = xenbus_read(XBT_NIL, info->otherend, "state", NULL);
            if (buf) {
                backend_state = (enum xenbus_state)
                    cmp_strtou64(buf, NULL, 10);
                xenbus_free_string(buf);
                if (backend_state == XenbusStateInitWait) {
                    RPRINTK(DPRTL_FRNT,
                        ("      back end state is init wait.\n"));
                    break;
                }
            } else {
                PRINTK(("%s: null waiting for XenbusStateInitWait\n",
                        __func__));
            }
        } while (buf);
        if (info->ring_ref) {
            gnttab_end_foreign_access(info->ring_ref, 0);
            info->ring_ref = 0;
        }
        XenScsiFreeAllResources(dev_ext, RELEASE_ONLY);
    } else {
        RPRINTK(DPRTL_ON,
            ("%s: info->xbdev already NULL\n", __func__));
    }
    RPRINTK(DPRTL_ON, ("%s: OUT\n", __func__));
    DPRINTK(DPRTL_ON, ("  alloc_cnt i %d, s %d, v %d\n",
            dev_ext->alloc_cnt_i,
            dev_ext->alloc_cnt_s,
            dev_ext->alloc_cnt_v));
    dev_ext->op_mode = OP_MODE_DISCONNECTED;
    XenReleaseSpinLock(&info->lock, lh);
    RPRINTK(DPRTL_ON, ("%s: OUT\n", __func__));
}

void
vscsi_shutdown_backend(char *otherend)
{
    char *state_str;
    char **dir;
    char *buf;
    unsigned int dir_n = 0;
    unsigned int device_state;
    uint32_t i;
    int ret;

    RPRINTK(DPRTL_ON, ("vscsi_shutdown_backend\n"));
    dir = xenbus_directory(XBT_NIL, otherend, "vscsi-devs", &dir_n);
    if (IS_ERR(dir)) {
        RPRINTK(DPRTL_ON,
            ("vscsi_shutdown_backend: failed to read otherend %s\n", otherend));
        return;
    }

    for (i = 0; i < dir_n; i++) {
        state_str = kasprintf(64, "vscsi-devs/%s/state", dir[i]);
        buf = xenbus_read(XBT_NIL, otherend, state_str, NULL);
        if (buf) {
            device_state = (enum xenbus_state)cmp_strtou64(buf, NULL, 10);
            RPRINTK(DPRTL_ON, ("vscsi_shutdown_backend: %s = %d\n",
                state_str, device_state));
            if (device_state != XenbusStateInitialising) {
                ret = xenbus_printf(XBT_NIL, otherend,
                    state_str, "%d", XenbusStateInitialising);
                PRINTK(("shutdown_backend: ret = %d.\n", ret));
            }
            xenbus_free_string(buf);
            device_state = 66;
            buf = xenbus_read(XBT_NIL, otherend, state_str, NULL);
            if (buf) {
                device_state = (enum xenbus_state)cmp_strtou64(buf, NULL, 10);
                RPRINTK(DPRTL_ON, ("vscsi_shutdown_backend is now: %s = %d\n",
                    state_str, device_state));
                xenbus_free_string(buf);
            }
        } else {
            RPRINTK(DPRTL_ON, ("vscsi_shutdown_backend: failed to read %s\n",
                state_str));
        }
        xenbus_free_string(state_str);
    }
    ExFreePool(dir);
}


#ifdef DBG
static int dumpit;
static void
DumpPacket(uint64_t disk_offset, PUCHAR currentAddress, uint32_t len)
{
    uint32_t i;
    int j;

    if (!currentAddress) {
        return;
    }
    len = len > 512 ? 512 : len;

    DPRINTK(DPRTL_ON, ("Dumpping packe for disk_offset %x, address %x\n",
        (uint32_t)disk_offset, currentAddress));
    for (i = 0; i < len;) {
        DPRINTK(DPRTL_ON, ("%3x: ", i));
        for (j = 0; i < len && j < 16; j++, i++) {
            DPRINTK(DPRTL_ON, ("%2x ", currentAddress[i]));
        }
        DPRINTK(DPRTL_ON, ("\n"));
    }
}
#endif
