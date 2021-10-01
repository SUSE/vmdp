/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2020 SUSE LLC
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
#include "xenblk.h"

#define MAXIMUM_OUTSTANDING_BLOCK_REQS \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST * BLK_RING_SIZE)
#define GRANT_INVALID_REF   0

static int talking_to_backend;

static XenbusState backend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len);
static void connect(struct blkfront_info *);
static void blkfront_closing(struct blkfront_info *info);
static int blkfront_remove(XENBLK_DEVICE_EXTENSION *);
static int talk_to_backend(struct blkfront_info *);
static int setup_blkring(struct blkfront_info *info,
                         unsigned int old_ring_size);

static void kick_pending_request_queues(struct blkfront_info *);
static void blkif_restart_queue(IN PDEVICE_OBJECT DevObject, IN PVOID Context);
static void blkif_completion(struct blkfront_info *info, unsigned long id);

/*
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures and the ring buffer for communication with the backend, and
 * inform the backend of the appropriate details for those.  Switch to
 * Initialised state.
 */
NTSTATUS
blkfront_probe(struct blkfront_info *info)
{
    char *buf;
    enum xenbus_state backend_state;
    int err, i;

    RPRINTK(DPRTL_INIT, ("blkfront_probe: "));

    info->nodename = xenbus_get_nodename_from_dev(info);
    info->otherend = xenbus_get_otherend_from_dev(info);
    info->otherend_id = (domid_t)cmp_strtou64(
        xenbus_get_backendid_from_dev(info),
            NULL, 10);
    RPRINTK(DPRTL_INIT, ("n %s, o %s, id %d\n",
                         info->nodename, info->otherend, info->otherend_id));

    info->connected = BLKIF_STATE_DISCONNECTED;
    info->sector_size = 0;
    info->sectors = 0;
    InitializeListHead(&info->rq);
    KeInitializeSpinLock(&info->lock);


    info->handle = (uint16_t)cmp_strtou64(
        strrchr(info->nodename, '/') + 1, NULL, 10);

    InitializeListHead(&info->watch.list);
    info->watch.callback = backend_changed;
    info->watch.node = info->otherend;
    info->watch.flags = XBWF_new_thread;
    info->watch.context = info;
    info->mm.cons = 0;
    info->mm.prod = 0;

    RPRINTK(DPRTL_FRNT, ("XenBlk:    blkfront_probe - talk_to_backend.\n"));
    err = talk_to_backend(info);
    if (err) {
        return err;
    }

    RPRINTK(DPRTL_FRNT, ("Alloc %d * %d * %d + %d * %d = %d\n",
                         BLK_RING_SIZE,
                         sizeof(void *), info->max_segs_per_req,
                         sizeof(unsigned long),
                         info->max_segs_per_req,
                         BLK_RING_SIZE * ((sizeof(void *)
                             * info->max_segs_per_req) +
                             (sizeof(unsigned long)
                             * info->max_segs_per_req))));
    buf = EX_ALLOC_POOL(VPOOL_NON_PAGED,
        BLK_RING_SIZE * ((sizeof(void *) * info->max_segs_per_req) +
            (sizeof(unsigned long) * info->max_segs_per_req)),
        XENBLK_TAG_GENERAL);
    if (buf == NULL) {
        PRINTK(("blkfront_probe failed to alloc memory.\n"));
        blkif_free(info, 0);
        return  STATUS_NO_MEMORY;
    }
    for (i = 0; i < BLK_RING_SIZE; i++) {
        info->mm.ring[i].mapped_addr = (void **)buf;
        buf += sizeof(void *) * info->max_segs_per_req;
        info->mm.ring[i].mapped_len = (unsigned long *)buf;
        buf += sizeof(unsigned long) * info->max_segs_per_req;
    }

    RPRINTK(DPRTL_FRNT,
            ("      blkfront_probe %s: waiting for connect, irql %x, cpu %x\n",
             info->nodename, KeGetCurrentIrql(),
             KeGetCurrentProcessorNumber()));

    /*
     * We don't actually want to wait any time because we may be
     * at greater than PASSIVE_LEVEL.
     */
    while (1) {
        backend_state = backend_changed(&info->watch, NULL, 0);
        if (backend_state == XenbusStateConnected) {
            break;
        }
        if (backend_state == XenbusStateClosed) {
            return STATUS_NO_SUCH_DEVICE;
        }
    }

    RPRINTK(DPRTL_FRNT, ("      blkfront_probe: register_xenbus_watch.\n"));
    err = register_xenbus_watch(&info->watch);
    if (err) {
        PRINTK(("blkfront_probe: register_xenbus_watch returned 0x%x.\n",
            err));
        if (err != -EEXIST) {
            return err;
        }
    }

    RPRINTK(DPRTL_INIT, ("XenBlk: blkfront_probe finished\n"));
    return STATUS_SUCCESS;
}

static unsigned int
ilog2(unsigned int x)
{
    unsigned int res = -1;

    while (x) {
        res++;
        x = x >> 1;
    }
    return res;
}

static void
xenblk_get_ring_details(struct blkfront_info *info, unsigned int *ring_order)
{
    char *buf;
    unsigned int ring_size;

    RPRINTK(DPRTL_ON, ("Per controller: max segs per request %d\n",
                       XENBLK_MAX_SGL_ELEMENTS));
    buf = xenbus_read(XBT_NIL, info->otherend, "max-ring-pages", NULL);
    if (buf == NULL) {
        ring_size = 0;
        RPRINTK(DPRTL_ON, ("blkfront: %s: err max-ring-pages, ring_size zero\n",
                           info->nodename));
    } else {
        ring_size = (unsigned int)cmp_strtou64(buf, NULL, 10);
        RPRINTK(DPRTL_ON, ("blkfront: %s: max-ring-pages, ring_size %u\n",
                           info->nodename, ring_size));
        xenbus_free_string(buf);
    }

    buf = xenbus_read(XBT_NIL, info->otherend, "max-ring-page-order", NULL);
    if (buf == NULL) {
        *ring_order = ring_size ? ilog2(ring_size) : 0;
        RPRINTK(DPRTL_ON, ("blkfront: %s: missing max-ring-page-order\n",
                           info->nodename));
        RPRINTK(DPRTL_ON, ("  use ilog2(%u) to get ring_order %u\n",
                           info->nodename, ring_size, *ring_order));
    } else {
        *ring_order = (unsigned int)cmp_strtou64(buf, NULL, 10);
        xenbus_free_string(buf);
        if (ring_size != 0) {
            if ((ring_size - 1) >> *ring_order) {
                RPRINTK(DPRTL_ON,
                        ("blkfront: %s: max-ring-pages (%u) inconsistent with"
                         " max-ring-page-order (%u)\n",
                         info->nodename, ring_size, *ring_order));
            } else {
                *ring_order = ilog2(ring_size);
                RPRINTK(DPRTL_ON,
                        ("blkfront: %s: using ilog2(%u) ring_order %u\n",
                         info->nodename, ring_size, *ring_order));
            }
        }
    }
    if (*ring_order > BLK_MAX_RING_PAGE_ORDER) {
        *ring_order = BLK_MAX_RING_PAGE_ORDER;
    }
    /*
     * While for larger rings not all pages are actually used, be on the
     * safe side and set up a full power of two to please as many backends
     * as possible.
     */
    info->ring_size = 1U << *ring_order;
    RPRINTK(DPRTL_ON, ("blkfront: %s: finalized ring_order %u, ring_size %u\n",
                       info->nodename, *ring_order, info->ring_size));
}

static void
xenblk_get_xenstore_max_segs(struct blkfront_info *info)
{
    char *buf;
    unsigned int max_segs;

    max_segs = 0;
    buf = xenbus_read(XBT_NIL, info->otherend,
                      "feature-max-indirect-segments", NULL);
    if (buf == NULL) {
        max_segs = XENBLK_MAX_SGL_ELEMENTS;
        RPRINTK(DPRTL_ON, ("  missing max_ind_segs, use default %u\n",
                           max_segs));
    } else {
        max_segs = (unsigned int)cmp_strtou64(buf, NULL, 10);
        xenbus_free_string(buf);
        if (max_segs < BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            max_segs = BLKIF_MAX_SEGMENTS_PER_REQUEST;
            RPRINTK(DPRTL_ON, ("  max_ind_segs < default, use default %u\n",
                               max_segs));
        } else {
            if (max_segs > g_max_segs_per_req) {
                RPRINTK(DPRTL_ON,
                        ("  maxsegs %u > max_segs_per_req %u, use %u\n",
                         max_segs, g_max_segs_per_req, g_max_segs_per_req));
                max_segs = g_max_segs_per_req;
            }
            if (BLKIF_INDIRECT_PAGES(max_segs)
                 > BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST) {
                max_segs = BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST
                       * BLKIF_SEGS_PER_INDIRECT_FRAME;
                RPRINTK(DPRTL_ON, ("  rather use calculated max_segs: %u\n",
                                   max_segs));
            }
        }
    }
    info->max_segs_per_req = max_segs;

    RPRINTK(DPRTL_ON, ("blkfront: %s: finalized max_sgs_per_req %u\n",
                       info->nodename, info->max_segs_per_req));
    RPRINTK(DPRTL_ON, ("  BLKIF_MAX_SEGMENTS_PER_REQUEST %u\n",
                       BLKIF_MAX_SEGMENTS_PER_REQUEST));
    RPRINTK(DPRTL_ON, ("  BLKIF_SEGS_PER_INDIRECT_FRAME %u\n",
                       (unsigned int)BLKIF_SEGS_PER_INDIRECT_FRAME));
    RPRINTK(DPRTL_ON, ("  BLKIF_INDIRECT_PAGES: %u + %u - 1/ %u = %u\n",
                       max_segs, BLKIF_SEGS_PER_INDIRECT_FRAME,
                       BLKIF_SEGS_PER_INDIRECT_FRAME,
                       (unsigned int)BLKIF_INDIRECT_PAGES(max_segs)));
    RPRINTK(DPRTL_ON, ("  BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST %u\n",
                       BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST));
    RPRINTK(DPRTL_ON, ("  BLK_MAX_RING_PAGE_ORDER %u\n",
                       BLK_MAX_RING_PAGE_ORDER));
    RPRINTK(DPRTL_ON, ("  BLK_MAX_RING_PAGES %u\n",
                       BLK_MAX_RING_PAGES));
    RPRINTK(DPRTL_ON, ("  BLK_MAX_RING_SIZE %u\n",
                       (unsigned int)BLK_MAX_RING_SIZE));
}

/* Common code used when first setting up, and when resuming. */
static int
talk_to_backend(struct blkfront_info *info)
{
    const char *message = NULL;
    struct xenbus_transaction xbt;
    char tbuf[12];
    int err;
    unsigned int ring_order;
    unsigned int i;
    unsigned int old_ring_size = RING_SIZE(&info->ring);

    if (info->xbdev->pvctrl_flags & XENBUS_PVCTRL_USE_JUST_ONE_CONTROLLER) {
        RPRINTK(DPRTL_ON, ("talk_to_backend %s: "
                           " One controller, max segs per request %d\n",
                           info->nodename, XENBLK_MAX_SGL_ELEMENTS));
        info->ring_size = 1;
        info->max_segs_per_req = XENBLK_MAX_SGL_ELEMENTS;
    } else {
        xenblk_get_ring_details(info, &ring_order);
        xenblk_get_xenstore_max_segs(info);
    }

    /* Create shared ring, alloc event channel. */
    RPRINTK(DPRTL_ON, ("talk_to_backend: irql %x, cpu %x\n",
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    DPRINTK(DPRTL_INIT, ("  locks %x\n", info->xenblk_locks));
    err = setup_blkring(info, old_ring_size);
    if (err) {
        goto out;
    }

again:
    err = xenbus_transaction_start(&xbt);
    if (err) {
        PRINTK(("talk_to_backend %s: xenbus_transaction_start failed\n",
                info->nodename));
        xenbus_printf(xbt, info->nodename, "starting transaction", "%d", err);
        goto destroy_blkring;
    }

    talking_to_backend++;

    if (info->ring_size == 1) {
        RPRINTK(DPRTL_ON, ("talk_to_backend %s: ring-ref %u\n",
                           info->nodename, info->ring_refs[0]));
        err = xenbus_printf(xbt, info->nodename, "ring-ref", "%u",
                            info->ring_refs[0]);
        if (err) {
            message = "writing ring-ref";
            goto abort_transaction;
        }
    } else {
        RPRINTK(DPRTL_ON, ("talk_to_backend %s: ring-page-order %u\n",
                           info->nodename, ring_order));
        err = xenbus_printf(xbt, info->nodename, "ring-page-order", "%u",
                            ring_order);
        if (err) {
            message = "writing ring-page-order";
            goto abort_transaction;
        }

        RPRINTK(DPRTL_ON, ("talk_to_backend %s: num-ring-pages %u\n",
                           info->nodename, info->ring_size));
        err = xenbus_printf(xbt, info->nodename, "num-ring-pages", "%u",
                            info->ring_size);
        if (err) {
            message = "writing num-ring-pages";
            goto abort_transaction;
        }

        for (i = 0; i < info->ring_size; i++) {
            if (RtlStringCbPrintfA(tbuf, sizeof(tbuf), "ring-ref%u", i)
                    != STATUS_SUCCESS) {
                message = "formatting ring-ref";
                goto abort_transaction;
            }
            RPRINTK(DPRTL_ON, ("talk_to_backend %s: %s %u\n",
                               info->nodename, tbuf, info->ring_refs[i]));
            err = xenbus_printf(xbt, info->nodename, tbuf, "%u",
                                info->ring_refs[i]);
            if (err) {
                message = "writing ring-ref";
                goto abort_transaction;
            }
        }
    }

    RPRINTK(DPRTL_ON, ("talk_to_backend %s: evtchn %u\n",
                       info->nodename, info->evtchn));
    err = xenbus_printf(xbt, info->nodename, "event-channel", "%u",
        info->evtchn);
    if (err) {
        message = "writing event-channel";
        goto abort_transaction;
    }
    RPRINTK(DPRTL_ON, ("talk_to_backend %s: protocol %u\n",
                       info->nodename, XEN_IO_PROTO_ABI_NATIVE));
    err = xenbus_printf(xbt, info->nodename, "protocol", "%s",
        XEN_IO_PROTO_ABI_NATIVE);
    if (err) {
        message = "writing protocol";
        goto abort_transaction;
    }

    err = xenbus_transaction_end(xbt, 0);
    if (err) {
        if (err == -EAGAIN) {
            goto again;
        }
        xenbus_printf(xbt, info->nodename, "completing transaction", "%d", err);
        goto destroy_blkring;
    }

    xenbus_switch_state(info->nodename, XenbusStateInitialised);

    RPRINTK(DPRTL_INIT, ("talk_to_backend finished: irql %x, cpu %x\n",
             KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    DPRINTK(DPRTL_INIT, ("  locks %x\n", info->xenblk_locks));
    talking_to_backend--;
    return 0;

 abort_transaction:
    xenbus_transaction_end(xbt, 1);
    if (message) {
        xenbus_printf(xbt, info->nodename, message, "%s", err);
    }
 destroy_blkring:
    blkif_free(info, 0);
 out:
    talking_to_backend--;
    RPRINTK(DPRTL_INIT, ("talk_to_backend error: irql %x, cpu %x\n",
                         KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    DPRINTK(DPRTL_INIT, ("  locks %x\n", info->xenblk_locks));
    return err;
}

#ifdef DBG
static void
xenblk_dump_ring_info(struct blkfront_info *info)
{
    PRINTK(("  sizeof(blkif_request_t) %u\n", (unsigned int)
            sizeof(blkif_request_t)));
    PRINTK(("  BLK_MAX_RING_SIZE %u\n", (unsigned int)BLK_MAX_RING_SIZE));
    PRINTK(("  BLK_RING_SIZE %u\n", (unsigned int)BLK_RING_SIZE));
    PRINTK(("  __RING_SIZE %u\n",
            (unsigned int)__WIN_RING_SIZE(info->ring.sring, PAGE_SIZE)));
    PRINTK(("  __RING_SIZE * 4 %u\n",
            (unsigned int)__WIN_RING_SIZE(info->ring.sring, 4 * PAGE_SIZE)));
    PRINTK(("  __RD32(%x) / %u\n", (4096 -
          (ULONG_PTR)&(info->ring.sring)->ring + (ULONG_PTR)(info->ring.sring)),
            sizeof((info->ring.sring)->ring[0])));

    RPRINTK(DPRTL_ON, ("sring_t %x, req %x, rsp %x, ring %x.\n",
        sizeof(blkif_sring_t), sizeof(blkif_request_t),
        sizeof(blkif_response_t), __WIN_RING_SIZE(info->ring.sring,
        PAGE_SIZE)));
    RPRINTK(DPRTL_FRNT, ("off ring %x, h %x, id %x, s %x, seg %x\n",
        offsetof(blkif_sring_t, ring),
        offsetof(blkif_request_t, handle),
        offsetof(blkif_request_t, id),
        offsetof(blkif_request_t, sector_number),
        offsetof(blkif_request_t, seg)));
    RPRINTK(DPRTL_FRNT, ("setup_blkring: sring = %x, mfn ring.sring = %x\n",
        info->ring.sring, virt_to_mfn(info->ring.sring)));
}
#else
#define xenblk_dump_ring_info(info)
#endif

static int
xenblk_setup_sring(struct blkfront_info *info)
{
    blkif_sring_t *sring;
    unsigned int nr;
    int err = 0;

    sring = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                          (size_t)info->ring_size * PAGE_SIZE,
                          XENBLK_TAG_GENERAL);
    if (!sring) {
        xenbus_printf(XBT_NIL, info->nodename, "allocating shared ring", "%x",
            -ENOMEM);
        return -ENOMEM;
    }

    RPRINTK(DPRTL_ON, ("sring = %p\n", sring));
    XENBLK_INC(info->xbdev->alloc_cnt_s);

    for (nr = 0; nr < info->ring_size; nr++) {
        info->ring_refs[nr] = GRANT_INVALID_REF;
        info->ring_pages[nr] = (char *)sring + ((size_t)nr * PAGE_SIZE);
        RPRINTK(DPRTL_ON, ("ring_pages[%d] = %p\n",
                           nr, info->ring_pages[nr]));

        err = xenbus_grant_ring(info->otherend_id,
                                virt_to_mfn(info->ring_pages[nr]));
        if (err < 0) {
            PRINTK(("setup_blkring: xenbus_grant_ring failed for page[%d] %p\n",
                    nr, info->ring_pages[nr]));
            return err;
        }
        info->ring_refs[nr] = err;
        RPRINTK(DPRTL_FRNT,
                ("setup_blkring: info->ring_refs[%u] = %x for id %d, err %u\n",
                 nr, info->ring_refs[nr], info->otherend_id, err));
    }
    SHARED_RING_INIT(sring);
    WIN_FRONT_RING_INIT(&info->ring, sring, (size_t)nr * PAGE_SIZE);
    return err;
}

static NTSTATUS
xenblk_setup_indirect_refs(struct blkfront_info *info,
                           unsigned int old_ring_size)
{
    struct blkif_request_segment **segs;
    unsigned int i, ring_size;

    ring_size = RING_SIZE(&info->ring);
    if (info->max_segs_per_req > XENBLK_MAX_SGL_ELEMENTS) {
        if (info->indirect_segs == NULL) {
            old_ring_size = 0;
        }
        if (old_ring_size < ring_size) {
            segs = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                 ring_size * sizeof(*segs),
                                 XENBLK_TAG_GENERAL);
            RPRINTK(DPRTL_ON, ("  ring_size %u, sizeof(*segs) %u: %p\n",
                               ring_size, (unsigned int)sizeof(*segs), segs));
            if (segs == NULL) {
                return STATUS_UNSUCCESSFUL;
            }
            info->indirect_segs = segs;
            for (i = old_ring_size; i < ring_size; ++i) {
                info->indirect_segs[i] = NULL;
            }
        }
        for (i = old_ring_size; i < ring_size; ++i) {
            info->indirect_segs[i] =
                EX_ALLOC_POOL(VPOOL_NON_PAGED,
                              BLKIF_INDIRECT_PAGES(
                                  info->max_segs_per_req) * PAGE_SIZE,
                              XENBLK_TAG_GENERAL);
            if (info->indirect_segs[i] == NULL) {
                return STATUS_UNSUCCESSFUL;
            }
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS xenblk_setup_shadow(struct blkfront_info *info)
{
    struct blk_shadow *shadow;
    unsigned long *frame;
    unsigned int i, ring_size, shadow_frames;

    ring_size = RING_SIZE(&info->ring);
    info->shadow_free = 0;
    info->shadow = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                 ring_size * sizeof(struct blk_shadow),
                                 XENBLK_TAG_GENERAL);
    if (info->shadow == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    memset(info->shadow, 0, ring_size * sizeof(struct blk_shadow));
    if (info->max_segs_per_req > XENBLK_MAX_SGL_ELEMENTS) {
        shadow_frames = info->max_segs_per_req;
    } else {
        shadow_frames = BLKIF_MAX_SEGMENTS_PER_REQUEST;
    }
    shadow = info->shadow;
    for (i = 0; i < ring_size; i++) {
        shadow->frame = EX_ALLOC_POOL(VPOOL_NON_PAGED,
            (size_t)shadow_frames * sizeof(*frame),
            XENBLK_TAG_GENERAL);
        if (shadow->frame == NULL) {
            return STATUS_UNSUCCESSFUL;
        }
        shadow->req.id = (uint64_t)i + 1;
        shadow->req.nr_segments = 0;
        shadow->request = NULL;
        memset(shadow->frame, ~0, shadow_frames * sizeof(*frame));
        shadow++;
    }
    shadow--;
    shadow->req.id = 0x0fffffff;
    return STATUS_SUCCESS;
}

static int
setup_blkring(struct blkfront_info *info, unsigned int old_ring_size)
{
    NTSTATUS status;
    int err;

    err = xenblk_setup_sring(info);
    if (err < 0) {
        goto fail;
    }
    xenblk_dump_ring_info(info);

    status = xenblk_setup_indirect_refs(info, old_ring_size);
    if (status != STATUS_SUCCESS) {
        goto fail;
    }

    status = xenblk_setup_shadow(info);
    if (status != STATUS_SUCCESS) {
        goto fail;
    }

    err = xenbus_alloc_evtchn(info->otherend_id, &info->evtchn);
    if (err) {
        PRINTK(("setup_blkring: xenbus_alloc_evtchn failed\n"));
        goto fail;
    }
#ifdef XENBLK_STORPORT
    RPRINTK(DPRTL_FRNT, ("setup_blkring: info->evtchn = %d, %p\n",
                         info->evtchn, blkif_int));
    err = register_dpc_to_evtchn(info->evtchn, blkif_int, info,
        &info->has_interrupt);
#else
    RPRINTK(DPRTL_FRNT, ("setup_blkring: info->evtchn = %d\n", info->evtchn));
    err = register_dpc_to_evtchn(info->evtchn, NULL, NULL,
        &info->has_interrupt);
#endif

    if (err < 0) {
        xenbus_printf(XBT_NIL, info->nodename,
            "bind_evtchn_to_irqhandler failed", "%x", err);
        PRINTK(("register_dpc_to_evtchn failed %x\n", err));
        goto fail;
    }

    RPRINTK(DPRTL_INIT,
            ("returning from setup blkring: ring_refs[0] %u, evtchn %u\n",
             info->ring_refs[0], info->evtchn));
    return 0;
fail:
    blkif_free(info, 0);
    PRINTK(("setup blkring: failed %x\n", err));
    return err;
}


/* Callback received when the backend's state changes. */
static XenbusState
backend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    struct blkfront_info *info = (struct blkfront_info *)watch->context;
    char *buf;
    XENBLK_LOCK_HANDLE io_lh = {0};
    XenbusState backend_state;
    xenbus_release_device_t release_data;
    uint32_t i;
    uint32_t found;

    if (vec) {
        RPRINTK(DPRTL_ON, ("blkfront:backend_changed: %s, ", vec[0]));
    }
    if (talking_to_backend) {
        RPRINTK(DPRTL_FRNT,
                ("backend_changed called while talking to backend.\n"));
    }

    buf = xenbus_read(XBT_NIL, info->otherend, "state", NULL);
    if (buf == NULL) {
        xenbus_printf(XBT_NIL, info->nodename, "reading state", "%x", buf);
        PRINTK(("blkfront:backend_changed failed to read state from\n"));
        PRINTK(("         %s.\n", info->otherend));
        if (info->connected != BLKIF_STATE_DISCONNECTED) {
            return XenbusStateUnknown;
        }

        backend_state = XenbusStateClosed;
    } else {
        backend_state = (enum xenbus_state)cmp_strtou64(buf, NULL, 10);
        xenbus_free_string(buf);
        RPRINTK(DPRTL_ON, ("st %d.\n", backend_state));
    }

    switch (backend_state) {
    case XenbusStateInitialising:
    case XenbusStateInitWait:
    case XenbusStateInitialised:
    case XenbusStateUnknown:
        break;
    case XenbusStateClosed:
        if (info && info->nodename) {
            PRINTK(("blkfront: %s backend_changed to closed\n",
                    info->nodename));
        } else {
            PRINTK(("blkfront: backend_changed to closed\n"));
        }
        break;

    case XenbusStateConnected:
        RPRINTK(DPRTL_FRNT,
                ("backend_changed %p: connect irql = %d, cpu = %d\n",
                 backend_changed, KeGetCurrentIrql(),
                 KeGetCurrentProcessorNumber()));

        XENBLK_SET_FLAG(info->xenblk_locks, (BLK_CON_L | BLK_INT_L));
        XENBLK_SET_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));

        connect(info);

        XENBLK_CLEAR_FLAG(info->xenblk_locks, (BLK_CON_L | BLK_INT_L));
        XENBLK_CLEAR_FLAG(info->cpu_locks,
                          (1 << KeGetCurrentProcessorNumber()));
        break;

    case XenbusStateClosing:
        storport_acquire_spinlock(info->xbdev, StartIoLock, NULL, &io_lh);
        PRINTK(("blkfront: %s backend_changed to closing\n", info->nodename));
        XENBLK_SET_FLAG(info->xenblk_locks, (BLK_INT_L));
        RPRINTK(DPRTL_FRNT,
                ("blkfront:backend_changed is closing - blkif_quiesce.\n"));

        blkif_quiesce(info);

        if (info->evtchn) {
            RPRINTK(DPRTL_FRNT,
                    ("      backend_changed:unregister_dpc_from_evtchn %d.\n",
                     info->evtchn));
            unregister_dpc_from_evtchn(info->evtchn);
            xenbus_free_evtchn(info->evtchn);
            info->evtchn = 0;
        }

        info->connected = BLKIF_STATE_DISCONNECTED;
        storport_release_spinlock(info->xbdev, io_lh);
        XENBLK_CLEAR_FLAG(info->xenblk_locks, (BLK_INT_L));

        /* Un-register the watch before switching to closed.*/
        unregister_xenbus_watch(&info->watch);

        RPRINTK(DPRTL_FRNT,
                ("blkfront:backend_changed is closing - switch to closed.\n"));
        xenbus_switch_state(info->nodename, XenbusStateClosed);

        /*
         * Since we unregistered the watch and switched the state to closed,
         * do any cleanup up work here.
         */
        found = 0;
        for (i = 0; i < info->ring_size; i++) {
            if (info->ring_refs[i] != GRANT_INVALID_REF) {
                gnttab_end_foreign_access(info->ring_refs[i], 0);
                info->ring_refs[i] = GRANT_INVALID_REF;
            }
        }
        for (i = 0; i < info->xbdev->max_targets; i++) {
            if (info->xbdev->info[i] == info) {
                found = 1;
                PRINTK(("blkfront: XenBlkFreeResource[%u]\n", i));
                XenBlkFreeResource(info, i, RELEASE_REMOVE);
                break;
            }
        }
        /* info may not be in the info array yet. */
        if (!found) {
            PRINTK(("blkfront: XenBlkFreeResource[%u]\n", i));
            XenBlkFreeResource(info, XENBLK_MAXIMUM_TARGETS, RELEASE_REMOVE);
        }
        break;
    }
    RPRINTK(DPRTL_ON, ("backend_changed %p: OUT irql = %d, cpu = %d\n",
                       backend_changed, KeGetCurrentIrql(),
                       KeGetCurrentProcessorNumber()));
    return backend_state;
}


/*
 * Invoked when the backend is finally 'ready' (and has told produced
 * the details about the physical device - #sectors, size, etc).
 */
static void
connect(struct blkfront_info *info)
{
    uint64_t sectors;
    char *buf;
    int err;

    RPRINTK(DPRTL_FRNT, ("blkfront %s: %s IN\n", __func__, info->otherend));
    RPRINTK(DPRTL_FRNT, ("  info %p, connected %d, irql %x, cpu %x\n",
                         info, info->connected,
                         KeGetCurrentIrql(),
                         KeGetCurrentProcessorNumber()));

    if (info->connected == BLKIF_STATE_SUSPENDED) {
        return;
    }

    buf = xenbus_read(XBT_NIL, info->otherend, "sectors", NULL);
    if (buf == NULL) {
        xenbus_printf(XBT_NIL, info->nodename, "reading sectors", "%x", buf);
        PRINTK(("blkfront %s: failed to read sectors\n", __func__));
        return;
    } else {
        sectors = cmp_strtou64(buf, NULL, 10);
        xenbus_free_string(buf);
    }

    /* If already connected, check for a capacity change. */
    if (info->connected == BLKIF_STATE_CONNECTED) {
        if (sectors != info->sectors) {
            RPRINTK(DPRTL_FRNT, ("  updating sectors from %lld to %lld\n",
                     info->sectors, sectors));
            info->sectors = sectors;
            /*
             * A BusChangeDetected notification doesn't trigger a
             * SCSIOP_READ_CAPACITY to let the upper layers know
             * of the change.  We will leave that to diskpart or
             * Disk Management to do a rescan to reflect the change.
             */
        }
        return;
    }

    info->sectors = sectors;

    buf = xenbus_read(XBT_NIL, info->otherend, "sector-size", NULL);
    if (buf == NULL) {
        xenbus_printf(XBT_NIL, info->nodename, "reading sector-size",
            "%x", buf);
        PRINTK(("blkfront %s: failed to read sector-size\n", __func__));
    } else {
        info->sector_size = (unsigned long)cmp_strtou64(buf, NULL, 10);
        xenbus_free_string(buf);
    }

    buf = xenbus_read(XBT_NIL, info->otherend, "mode", NULL);
    if (buf == NULL) {
        xenbus_printf(XBT_NIL, info->nodename, "reading mode", "%x", buf);
        PRINTK(("blkfront %s: failed to read mode\n", __func__));
    } else {
        if (buf[0] == 'r') {
            info->flags |= BLKIF_READ_ONLY_F;
        }
        xenbus_free_string(buf);
    }

    RPRINTK(DPRTL_FRNT,
            ("  sectors 0x%llx sector-sz 0x%x last sector 0x%x flags %x\n",
             info->sectors,
             info->sector_size,
             (uint32_t)(info->sectors) - 1,
             info->flags));

    (void)xenbus_switch_state(info->nodename, XenbusStateConnected);

    info->connected = BLKIF_STATE_CONNECTED;

    /* Kick pending requests. */
    kick_pending_request_queues(info);
    RPRINTK(DPRTL_FRNT, ("blkfront %s: OUT\n", __func__));
}

static inline int
GET_ID_FROM_FREELIST(struct blkfront_info *info)
{
    unsigned long free;

    CDPRINTK(DPRTL_COND, 0, 1, (info->xenblk_locks & BLK_ID_L),
        ("GET_ID_FROM_FREELIST already set: irql %x, cpu %x, xlocks %x on %x\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
        info->xenblk_locks, info->cpu_locks));

    XENBLK_SET_FLAG(info->xenblk_locks, (BLK_ID_L | BLK_GET_L));
    XENBLK_SET_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));

    free = info->shadow_free;
    ASSERT(free < BLK_RING_SIZE);
    info->shadow_free = (unsigned long)info->shadow[free].req.id;
    info->shadow[free].req.id = 0x0fffffee; /* debug */

    XENBLK_CLEAR_FLAG(info->xenblk_locks, (BLK_ID_L | BLK_GET_L));
    XENBLK_CLEAR_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));

    return free;
}

static inline void
ADD_ID_TO_FREELIST(struct blkfront_info *info, unsigned long id)
{
    CDPRINTK(DPRTL_COND, 0, 1, (info->xenblk_locks & BLK_ID_L),
        ("ADD_ID_TO_FREELIST already set: irql %x, cpu %x, xlocks %x on %x\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
        info->xenblk_locks, info->cpu_locks));

    XENBLK_SET_FLAG(info->xenblk_locks, (BLK_ID_L | BLK_ADD_L));
    XENBLK_SET_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));

    info->shadow[id].req.id  = info->shadow_free;
    info->shadow[id].request = NULL;
    info->shadow_free = id;

    XENBLK_CLEAR_FLAG(info->xenblk_locks, (BLK_ID_L | BLK_ADD_L));
    XENBLK_CLEAR_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
}


static void
flush_enabled(struct blkfront_info *info)
{
    RPRINTK(DPRTL_TRC, ("flush_enabled - IN irql = %d\n", KeGetCurrentIrql()));
    notify_remote_via_irq(info->evtchn);
    RPRINTK(DPRTL_TRC, ("flush_enabled - OUT irql = %d\n", KeGetCurrentIrql()));
}

static inline void
flush_requests(struct blkfront_info *info)
{
    int notify;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->ring, notify);

    if (notify) {
        notify_remote_via_irq(info->evtchn);
    }
}

static void
kick_pending_request_queues(struct blkfront_info *info)
{
    if (!RING_FULL(&info->ring)) {
        /* Re-enable calldowns. */
    }
}

static void
blkif_restart_queue(IN PDEVICE_OBJECT DeviceObject, IN PVOID Context)
{
    struct blkfront_info *info = (struct blkfront_info *)Context;

    if (info->connected == BLKIF_STATE_CONNECTED) {
        kick_pending_request_queues(info);
    }
}

static void
blkif_restart_queue_callback(void *arg)
{
    struct blkfront_info *info = (struct blkfront_info *)arg;

    xenblk_request_timer_call(RequestTimerCall, info->xbdev,
        blkif_restart_queue, 100);
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

    PRINTK(("Dumpping packe for disk_offset %x, address %x\n",
        (uint32_t)disk_offset, currentAddress));
    for (i = 0; i < len;) {
        PRINTK(("%3x: ", i));
        for (j = 0; i < len && j < 16; j++, i++) {
            PRINTK(("%2x ", currentAddress[i]));
        }
        PRINTK(("\n"));
    }
}
#endif

static NTSTATUS
do_blkif_ind_request(struct blkfront_info *info, SCSI_REQUEST_BLOCK *srb,
                     int num_pages)
{
    uint64_t disk_offset;
    xenblk_addr_t addr;
    xenblk_srb_extension *srb_ext;
    blkif_request_t *ring_req;
    STOR_SCATTER_GATHER_LIST *sgl;
    struct blkif_request_segment *segs;
    struct blkif_request_indirect *ind;
    XENBLK_LOCK_HANDLE int_lh = {0};
    XEN_LOCK_HANDLE lh;
    grant_ref_t gref_head;
    ULONG i;
    ULONG j;
    ULONG sidx;
    unsigned long buffer_mfn;
    unsigned long id;
    unsigned long len;
    unsigned long page_offset;
    unsigned int fsect;
    unsigned int lsect;
    int ref;
    int notify;

    srb_ext = (xenblk_srb_extension *)srb->SrbExtension;
    srb_ext->next = NULL;
    srb_ext->srb = srb;
    srb_ext->use_cnt = 0;
    DPRINTK(DPRTL_TRC,
            ("      %s - IN srb %p, srb_ext %p, va %p\n",
             __func__, srb, srb_ext, srb_ext->va));

    srb_req_offset(srb, disk_offset);

    XenAcquireSpinLock(&info->lock, &lh);

#ifdef DBG
    InterlockedIncrement(&info->depth);
    if (info->depth > info->max_depth) {
        info->max_depth = info->depth;
        PRINTK(("Max queue depth %d\n", info->max_depth));
    }
#endif
    if (gnttab_alloc_grant_references(
            (uint16_t)(num_pages +
                       BLKIF_INDIRECT_PAGES(info->max_segs_per_req)),
            &gref_head) < 0) {
        RPRINTK(DPRTL_UNEXPD,
                ("XenBlk %x: ind req failed to allocate %d grant references\n",
                 srb->TargetId,
                 num_pages + BLKIF_INDIRECT_PAGES(info->max_segs_per_req)));
        XenReleaseSpinLock(&info->lock, lh);
        return STATUS_UNSUCCESSFUL;
    }

    /* Fill out a communications ring structure. */
    ring_req = RING_GET_REQUEST(&info->ring, info->ring.req_prod_pvt);

    /* scsi already has a spinlock.  Just do it for storport. */
    storport_acquire_spinlock(info->xbdev, InterruptLock, NULL, &int_lh);
    id = GET_ID_FROM_FREELIST(info);
    storport_release_spinlock(info->xbdev, int_lh);


    ring_req->id = id;
    ring_req->sector_number = disk_offset;
    ring_req->handle = info->handle;

    ring_req->operation =
        (srb->Cdb[0] == SCSIOP_WRITE || srb->Cdb[0] == SCSIOP_WRITE16) ?
        BLKIF_OP_WRITE : BLKIF_OP_READ;

    ind = (void *)ring_req;
    ind->indirect_op = ring_req->operation;
    ind->operation = BLKIF_OP_INDIRECT;
    ind->nr_segments = (uint16_t)num_pages;
    ind->handle = info->handle;
    segs = info->indirect_segs[id];



#ifdef DBG
    DPRINTK(DPRTL_IO, ("Do indirect: srb %p len %d, elmnts %d, pgs %d, id %d\n",
                       srb, srb->DataTransferLength,
                       srb_ext->sgl->NumberOfElements,
                       num_pages, id));
    if ((ULONG)num_pages > srb_ext->sgl->NumberOfElements) {
        DPRINTK(DPRTL_IO, ("Do indirect: srb %p len %d, elmnts %d, id %d\n",
                           srb, srb->DataTransferLength,
                           srb_ext->sgl->NumberOfElements, id));
    }
#endif
    /* Grant the pages of the indirect segnemt. */
    for (i = 0; i < BLKIF_INDIRECT_PAGES(num_pages); i++) {
        ref = gnttab_claim_grant_reference(&gref_head);
        if (ref == -1) {
            PRINTK(("do_blkif_ind_request: failed seg claim grant ref\n"));
        }
        ASSERT(ref != -1);
        gnttab_grant_foreign_access_ref(
            ref,
            info->otherend_id,
            virt_to_mfn((char *)segs + ((size_t)i * PAGE_SIZE)),
            GTF_readonly);
        ind->indirect_grefs[i] = ref;
#ifdef DBG
        if ((ULONG)num_pages > srb_ext->sgl->NumberOfElements) {
            DPRINTK(DPRTL_IO, ("  indirect_gref[%d] %d\n", i, ref));
        }
#endif
    }

    /* Grant each page making up the sgl. */
    sidx = 0;
    sgl = srb_ext->sgl;
    for (i = 0; i < sgl->NumberOfElements; i++) {
        addr = (xenblk_addr_t)sgl->List[i].PhysicalAddress.QuadPart;
        len = sgl->List[i].Length;
        while ((int)len > 0) {
            ref = gnttab_claim_grant_reference(&gref_head);
            if (ref == -1) {
                PRINTK(("do_blkif_ind_request: failed page claim grant ref\n"));
            }
            ASSERT(ref != -1);
            buffer_mfn = xenblk_buffer_mfn(info->xbdev, srb, srb_ext, addr);
            gnttab_grant_foreign_access_ref(
                ref,
                info->otherend_id,
                buffer_mfn,
                ring_req->operation & 1);

            /* Check for page/sector alignment. */
            page_offset = (unsigned long)addr & (PAGE_SIZE - 1);
#ifdef DBG
            if ((ULONG)num_pages > srb_ext->sgl->NumberOfElements) {
                DPRINTK(DPRTL_IO,
                        ("    segs[%d] %d: len %d -> %d addr %p off %d\n",
                         sidx, ref, len, len - PAGE_SIZE - page_offset,
                         addr, page_offset));
            }
#endif
            fsect = page_offset >> 9;
            lsect = page_offset + len >= PAGE_SIZE ? 7 :
                (uint8_t)(((page_offset + len) >> 9) - 1);
            addr += PAGE_SIZE - page_offset;
            len -= PAGE_SIZE - page_offset;

            info->shadow[id].frame[i] = mfn_to_pfn(buffer_mfn);
            segs[sidx].gref = ref;
            segs[sidx].first_sect = (uint8_t)fsect;
            segs[sidx].last_sect = (uint8_t)lsect;
            sidx++;
        }
    }
    info->ring.req_prod_pvt++;

    /* Keep a private copy so we can reissue requests when recovering. */
    info->shadow[id].ind = *ind;
    info->shadow[id].num_ind = sidx;
    gnttab_free_grant_references(gref_head);

#ifdef DBG
    if (sidx != num_pages) {
        DPRINTK(DPRTL_IO, ("** sidx %d != num_pages %d\n", sidx, num_pages));
    }
    info->shadow[id].seq = info->seq;
    InterlockedIncrement(&info->seq);
#endif
    info->shadow[id].srb_ext = srb_ext;
    InterlockedIncrement(&srb_ext->use_cnt);

    info->shadow[id].request = srb;
#ifdef DBG
    if (srb->Cdb[0] >= SCSIOP_READ16) {
        DPRINTK(DPRTL_TRC, ("Submitting the SCSIOP 16 request %x.\n",
                            srb->Cdb[0]));
    }
    InterlockedIncrement(&info->req);
#endif

    /*
     * Check if there are virtual and system addresses that need to be
     * freed and unmapped now that we are at DPC time.
     */
    xenblk_unmap_system_addresses(info);

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->ring, notify);

    XenReleaseSpinLock(&info->lock, lh);

    if (notify) {
        notify_remote_via_irq(info->evtchn);
    }

    DPRINTK(DPRTL_TRC,
            ("      blkif_queue_request - OUT srb %p, srb_ext %p, va %p\n",
             srb, srb_ext, srb_ext->va));
    XENBLK_INC_SRB(io_srbs_seen);
    return STATUS_SUCCESS;
}

NTSTATUS
do_blkif_request(struct blkfront_info *info, SCSI_REQUEST_BLOCK *srb)
{
    uint64_t disk_offset;
    xenblk_addr_t addr;
    xenblk_srb_extension *srb_ext;
    blkif_request_t *ring_req;
    STOR_SCATTER_GATHER_LIST *sgl;
    uint32_t *ids;
    ULONG sidx;
    ULONG i;
    unsigned long buffer_mfn;
    unsigned long len;
    unsigned long id;
    unsigned long page_offset;
    unsigned long remaining_bytes;
    unsigned int starting_req_prod_pvt;
    unsigned int fsect;
    unsigned int lsect;
    XEN_LOCK_HANDLE lh;
    XENBLK_LOCK_HANDLE int_lh = {0};
    grant_ref_t gref_head;
    int idx;
    int ref;
    int num_pages;
    int num_segs;
    int num_ring_req;
    int notify;

    srb_ext = (xenblk_srb_extension *)srb->SrbExtension;
    if (info->connected != BLKIF_STATE_CONNECTED) {
        PRINTK(("\tblkif_queue_request - OUT, not connected\n"));
        return STATUS_UNSUCCESSFUL;
    }

    /* Figure out how many pages this request will take. */
    srb_pages_in_req(srb_ext, num_pages);
    if (num_pages > XENBLK_MAX_SGL_ELEMENTS) {
        return do_blkif_ind_request(info, srb, num_pages);
    }

    XenAcquireSpinLock(&info->lock, &lh);

    /* The total num_segs needed is equal to num_pages. */
    if (gnttab_alloc_grant_references((uint16_t)num_pages, &gref_head) < 0) {
        RPRINTK(DPRTL_UNEXPD,
                ("XenBlk %x: do req failed to allocate %d grant references\n",
                srb->TargetId, num_pages));
        XenReleaseSpinLock(&info->lock, lh);
        return STATUS_UNSUCCESSFUL;
    }

    srb_ext->next = NULL;
    srb_ext->srb = srb;
    srb_ext->use_cnt = 0;
    DPRINTK(DPRTL_TRC,
            ("      blkif_queue_request - IN srb %p, srb_ext %p, va %p\n",
             srb, srb_ext, srb_ext->va));

    srb_req_offset(srb, disk_offset);

    /* Figure out how many pages this request will take. */
    num_ring_req = ((num_pages - 1) / BLKIF_MAX_SEGMENTS_PER_REQUEST) + 1;

    idx = 0;

#ifdef DBG
    InterlockedIncrement(&info->depth);
    if (info->depth > info->max_depth) {
        info->max_depth = info->depth;
        PRINTK(("Max queue depth %d\n", info->max_depth));
    }
#endif
    starting_req_prod_pvt = info->ring.req_prod_pvt;
    ids = info->id;

    if ((int)(RING_FREE_REQUESTS(&info->ring)) < num_ring_req) {
        PRINTK(("blkif_queue_request - OUT, free %x, required %x, pages %d\n",
            (int)(RING_FREE_REQUESTS(&info->ring)), num_ring_req, num_pages));
        XenReleaseSpinLock(&info->lock, lh);
        return STATUS_UNSUCCESSFUL;
    }

    sgl = srb_ext->sgl;
    len = sgl->List[0].Length;
    addr = xenblk_get_buffer_addr(srb, srb_ext);
    sidx = 1;

    for (; num_ring_req; num_ring_req--) {
        if (num_pages <= BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            num_segs = num_pages;
            num_pages = 0;
        } else {
            num_segs = BLKIF_MAX_SEGMENTS_PER_REQUEST;
            num_pages -= BLKIF_MAX_SEGMENTS_PER_REQUEST;
        }

        /* Fill out a communications ring structure. */
        ring_req = RING_GET_REQUEST(&info->ring, info->ring.req_prod_pvt);

        /* scsi already has a spinlock.  Just do it for storport. */
        storport_acquire_spinlock(info->xbdev, InterruptLock, NULL, &int_lh);
        id = GET_ID_FROM_FREELIST(info);
        storport_release_spinlock(info->xbdev, int_lh);

        ids[idx++] = id;
        ring_req->id = id;
        ring_req->operation =
            (srb->Cdb[0] == SCSIOP_WRITE || srb->Cdb[0] == SCSIOP_WRITE16) ?
            BLKIF_OP_WRITE : BLKIF_OP_READ;
        ring_req->sector_number = disk_offset;
        ring_req->handle = info->handle;

        for (ring_req->nr_segments = 0; num_segs; num_segs--) {
            ref = gnttab_claim_grant_reference(&gref_head);
            ASSERT(ref != -1);

            buffer_mfn = xenblk_buffer_mfn(info->xbdev, srb, srb_ext, addr);
            ring_req->seg[ring_req->nr_segments].gref = ref;

            /* Check for page/sector alignment. */
            page_offset = (unsigned long)addr & (PAGE_SIZE - 1);
            fsect = page_offset >> 9;
            lsect = page_offset + len >= PAGE_SIZE ? 7 :
                (uint8_t)(((page_offset + len) >> 9) - 1);
            addr += PAGE_SIZE - page_offset;
#ifdef DBG
            if ((int)(len - PAGE_SIZE - page_offset) < 0) {
                DPRINTK(DPRTL_TRC,
                        ("Do regular: len %d, segs %d, id %d\n",
                         srb->DataTransferLength,
                         srb_ext->sgl->NumberOfElements, id));
                DPRINTK(DPRTL_TRC,
                        ("    segs[%d] %d: len %d -> %d addr %p off %d\n",
                         sidx, ref, len, len - PAGE_SIZE - page_offset,
                         addr, page_offset));
            }
#endif
            len -= PAGE_SIZE - page_offset;
            if ((int)len <= 0 && sidx < sgl->NumberOfElements) {
                len = sgl->List[sidx].Length;
                addr = (xenblk_addr_t)
                sgl->List[sidx].PhysicalAddress.QuadPart;
                sidx++;
            }


            ring_req->seg[ring_req->nr_segments].first_sect = (uint8_t)fsect;
            ring_req->seg[ring_req->nr_segments].last_sect = (uint8_t)lsect;
            disk_offset += (((uint64_t)lsect - (uint64_t)fsect) + 1);

            gnttab_grant_foreign_access_ref(
                ref,
                info->otherend_id,
                buffer_mfn,
                ring_req->operation & 1);

            info->shadow[id].frame[ring_req->nr_segments] =
                mfn_to_pfn(buffer_mfn);

            ring_req->nr_segments++;
        }

        info->ring.req_prod_pvt++;

        /* Keep a private copy so we can reissue requests when recovering. */
        info->shadow[id].req = *ring_req;

#ifdef DBG
        info->shadow[id].seq = info->seq;
        InterlockedIncrement(&info->seq);
#endif
        info->shadow[id].srb_ext = srb_ext;
        InterlockedIncrement(&srb_ext->use_cnt);
    }
    gnttab_free_grant_references(gref_head);

    info->shadow[id].request = srb;
#ifdef DBG
    if (srb->Cdb[0] >= SCSIOP_READ16) {
        DPRINTK(DPRTL_TRC, ("Submitting the SCSIOP 16 request %x.\n",
                            srb->Cdb[0]));
    }
    InterlockedIncrement(&info->req);
#endif

    /*
     * Check if there are virtual and system addresses that need to be
     * freed and unmapped now that we are at DPC time.
     */
    xenblk_unmap_system_addresses(info);

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->ring, notify);

    XenReleaseSpinLock(&info->lock, lh);

    if (notify) {
        notify_remote_via_irq(info->evtchn);
    }

    DPRINTK(DPRTL_TRC,
            ("      blkif_queue_request - OUT srb %p, srb_ext %p, va %p\n",
             srb, srb_ext, srb_ext->va));
    XENBLK_INC_SRB(io_srbs_seen);
    return STATUS_SUCCESS;
}

static void
XenBlkCompleteRequest(struct blkfront_info *info, SCSI_REQUEST_BLOCK *srb,
    unsigned int status)
{
    xenblk_srb_extension *srb_ext;
    unsigned int len;
#ifdef XENBLK_REQUEST_VERIFIER
    uint32_t *pu32;
#endif

    DPRINTK(DPRTL_TRC, ("    XenBlkCompleteRequest - in\n"));
    srb_ext = (xenblk_srb_extension *)srb->SrbExtension;

#ifdef DBG
    if (srb->Cdb[0] >= SCSIOP_READ16) {
        DPRINTK(DPRTL_TRC, ("Start completing the SCSIOP 16 request %x.\n",
                            srb->Cdb[0]));
    }
#endif
    if (srb_ext->va) {
        if (srb->Cdb[0] == SCSIOP_READ || srb->Cdb[0] == SCSIOP_READ16) {
            DPRINTK(DPRTL_MM,
                    (" xenblk_cp_to_sa: srb %p, ext %p, va %p, sa %p\n",
                     srb, srb_ext, srb_ext->va, srb_ext->sa));
            xenblk_cp_to_sa(srb_ext->sa, srb_ext->sys_sgl, srb_ext->va);
            DPRINTK(DPRTL_MM, ("\tRtlCopyMemory done.\n"));
#ifdef XENBLK_REQUEST_VERIFIER
            pu32 = (uint32_t *)(srb_ext->va + srb->DataTransferLength);
            for (len = 0; len < PAGE_SIZE; len += 4) {
                if (*pu32 != 0xabababab) {
                    PRINTK(("** Overwrite at %x: %x.\n", len, *pu32));
                }
            }
#endif
        }

        /*
         * Save the virtual and system addresses so that they can be
         * freed and unmapped at DPC time rather than at interrupt time.
         */
        xenblk_save_system_address(info, srb_ext);
        DPRINTK(DPRTL_MM, ("\tabout to complete %p.\n", srb));
    }
#ifdef XENBLK_DBG_MAP_SGL_ONLY
    else {
        if (srb->Cdb[0] == SCSIOP_READ || srb->Cdb[0] == SCSIOP_READ16) {
            xenblk_save_system_address(info, srb_ext);
        }
    }
#endif
    xenblk_save_req(info, srb, srb_ext);

    if (status == BLKIF_RSP_OKAY) {
        srb->SrbStatus = SRB_STATUS_SUCCESS;
    } else {
        uint64_t disk_offset;

        srb->SrbStatus = SRB_STATUS_ERROR;
        srb_req_offset(srb, disk_offset);

        PRINTK(("\tXenBlkCompleteRequest: error status %x\n", status));
        PRINTK(("\tsrb %p op %x, I/O len 0x%x, disk offset 0x%x%08x %llx\n",
            srb,
            srb->Cdb[0],
            srb->DataTransferLength,
            (uint32_t)(disk_offset >> 32),
            (uint32_t)disk_offset,
            disk_offset));
    }

    xenblk_next_request(NextRequest, info->xbdev);
    XENBLK_INC_SRB(srbs_returned);
    XENBLK_INC_SRB(io_srbs_returned);
    XENBLK_INC_SRB(sio_srbs_returned);
    xenblk_request_complete(RequestComplete, info->xbdev, srb);
    DPRINTK(DPRTL_TRC, ("    XenBlkCompleteRequest - out\n"));
}

uint32_t
blkif_complete_int(struct blkfront_info *info)
{
    XEN_LOCK_HANDLE lh;
    SCSI_REQUEST_BLOCK *srb;
    blkif_response_t *bret;
    RING_IDX i, rp;
    unsigned long id;
    uint32_t did_work = 0;
    int more_to_do = 1;
    uint16_t status;
#ifdef DBG
    int outoforder = 0;
    int o = 0;
#endif

    DPRINTK(DPRTL_FRNT, ("  blkif_complete_int - IN irql = %d\n",
                         KeGetCurrentIrql()));

    XenAcquireSpinLock(&info->lock, &lh);
    if (info->connected) {
        while (more_to_do) {
            rp = info->ring.sring->rsp_prod;
            rmb(); /* Ensure we see queued responses up to 'rp'. */

            for (i = info->ring.rsp_cons; i != rp; i++) {
                bret = RING_GET_RESPONSE(&info->ring, i);
                id = (unsigned long)bret->id;

                blkif_completion(info, id);
                /*
                 * blkif_completion(&info->shadow[id]);
                 * is done right after GET_ID_FROM_FREE_LIST
                 */

#ifdef DBG
                if (info->shadow[id].seq > info->cseq) {
                    DPRINTK(DPRTL_FRNT,
                            ("XENBLK: sequence, %x - %x: req %p, status %x\n",
                             info->shadow[id].seq, info->cseq,
                             info->shadow[id].request, bret->status));
                    xenblk_print_cur_req(info,
                        (SCSI_REQUEST_BLOCK *)info->shadow[id].request);
                    o++;

                } else if (o) {
                    DPRINTK(DPRTL_FRNT,
                        ("XENBLK: sequence, %x - %x: req %p, status %x, o %d\n",
                        info->shadow[id].seq, info->cseq,
                        info->shadow[id].request, bret->status, o));
                    o = 0;

                }
                InterlockedIncrement(&info->cseq);
#endif
                InterlockedDecrement(&info->shadow[id].srb_ext->use_cnt);

                if (info->shadow[id].request) {
#ifdef DBG
                    if (info->shadow[id].srb_ext->use_cnt) {
                        DPRINTK(DPRTL_FRNT,
                                ("XENBLK: srb %p  use count %x\n",
                                 info->shadow[id].request,
                                 info->shadow[id].srb_ext->use_cnt));
                        outoforder = 1;
                        info->queued_srb_ext++;
                    }
                    InterlockedDecrement(&info->req);
#endif
                    info->shadow[id].srb_ext->status = bret->status;
                    xenblk_add_tail(info, info->shadow[id].srb_ext);
                    if (info->shadow[id].srb_ext->next != NULL) {
                        PRINTK(("XENBLK: srb_ext->next sn %p tn %p x %p\n",
                                info->shadow[id].srb_ext->next,
                                info->tsrb_ext->next,
                                info->shadow[id].srb_ext));
                    }
                }

                ADD_ID_TO_FREELIST(info, id);
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
                    DPRINTK(DPRTL_FRNT,
                            ("XENBLK: completing sequenced srb %p\n",
                             info->hsrb_ext->srb));
                    info->queued_srb_ext--;
                } else if (info->queued_srb_ext) {
                    DPRINTK(DPRTL_FRNT,
                            ("XENBLK: completing queued, srb %p\n",
                             info->hsrb_ext->srb));
                    info->queued_srb_ext--;
                }
                InterlockedDecrement(&info->depth);
#endif
                srb = info->hsrb_ext->srb;
                status = info->hsrb_ext->status;
                info->hsrb_ext = info->hsrb_ext->next;
                XenBlkCompleteRequest(info, srb, status);
            } else {
                if ((int32_t)info->hsrb_ext->use_cnt < 0) {
                    PRINTK(("** XENBLK: srb %p, status %x, use_count = %x.\n",
                        info->hsrb_ext->srb,
                        info->hsrb_ext->status,
                        info->hsrb_ext->use_cnt));
                }
                break;
            }
        }
    }

    DPRINTK(DPRTL_FRNT, ("  blkif_complete_int - OUT\n"));

    XenReleaseSpinLock(&info->lock, lh);
    return did_work;
}

#ifdef XENBLK_STORPORT
void
blkif_int_dpc(PKDPC dpc, PVOID dcontext, PVOID sa1, PVOID sa2)
{
    struct blkfront_info *info = (struct blkfront_info *)sa1;

    if (info == NULL) {
        return;
    }
    blkif_complete_int(info);
}

void
blkif_int(KDPC *dpc, void *context, void *s1, void *s2)
{
    struct blkfront_info *info = (struct blkfront_info *)context;

    if (info == NULL) {
        return;
    }
    StorPortIssueDpc(info->xbdev, &info->dpc, info, NULL);
}
#endif

void
blkif_quiesce(struct blkfront_info *info)
{
    LARGE_INTEGER timeout;
    uint32_t j;

    XENBLK_ZERO_VALUE(conditional_times_to_print_limit);

    DPRINTK(DPRTL_ON, ("blkif_quiesce: IN\n"));
    for (j = 0; j < BLK_RING_SIZE; j++) {
        if (info->shadow[j].request) {
            PRINTK(("blkif-quiesce: %d, waiting for %p\n",
                    j, info->shadow[j].request));
        }
    }
    if (info->ring.rsp_cons != info->ring.req_prod_pvt) {
        PRINTK(("blkif-quiesce: outstanding reqs %x, pvt %x, cons %x\n",
                info->ring.req_prod_pvt - info->ring.rsp_cons,
                info->ring.req_prod_pvt, info->ring.rsp_cons));
        timeout.QuadPart = -1000000; /* .1 second */
        for (j = 0;
                j < 100 && info->ring.rsp_cons != info->ring.req_prod_pvt;
                j++) {
            DPRINTK(DPRTL_FRNT, ("blkif_quiesce outstanding reqs %p: %x %x\n",
                info, info->ring.rsp_cons, info->ring.req_prod_pvt));
            KeDelayExecutionThread(KernelMode, FALSE, &timeout);
            blkif_complete_int(info);
        }
        PRINTK(("%s: waited %d time(s) - remaining reqs %x, pvt %x, cons %x\n",
                __func__, j,
                info->ring.req_prod_pvt - info->ring.rsp_cons,
                info->ring.req_prod_pvt, info->ring.rsp_cons));
    }

    /* Clear out any grants that may still be around. */
    DPRINTK(DPRTL_ON, ("blkif_quiesce: doing shadow completion\n"));
    for (j = 0; j < BLK_RING_SIZE; j++) {
        blkif_completion(info, j);
    }
    DPRINTK(DPRTL_ON, ("blkif_quiesce: OUT\n"));
    DPR_SRB("Q");
}

void
blkif_disconnect_backend(XENBLK_DEVICE_EXTENSION *dev_ext)
{
    uint32_t i;
    uint32_t j;
    char *buf;
    enum xenbus_state backend_state;
    struct blkfront_info *info;
    unsigned int nr;

    RPRINTK(DPRTL_ON, ("blkif_disconnect_backend: IN.\n"));
    for (i = 0; i < dev_ext->max_targets; i++) {
        info = dev_ext->info[i];
        if (info) {
            /*
             * Since we are doing the disconnect, unregister the watch so
             * we wont get a callback after we have freed resources.
             */
            unregister_xenbus_watch(&info->watch);
            if (info->evtchn) {
                RPRINTK(DPRTL_FRNT,
                        ("      disconnect unregister_dpc_from_evtchn %d.\n",
                         info->evtchn));
                unregister_dpc_from_evtchn(info->evtchn);
                xenbus_free_evtchn(info->evtchn);
                info->evtchn = 0;
            }
            blkif_quiesce(info);

            RPRINTK(DPRTL_FRNT,
                    ("      switching to closeing: %s.\n",
                     info->nodename));
            xenbus_switch_state(info->nodename, XenbusStateClosing);
            while (1) {
                buf = xenbus_read(XBT_NIL, info->otherend, "state", NULL);
                if (buf) {
                    backend_state = (enum xenbus_state)
                        cmp_strtou64(buf, NULL, 10);
                    xenbus_free_string(buf);
                    if (backend_state == XenbusStateClosing) {
                        RPRINTK(DPRTL_FRNT,
                                ("      back end state is closing.\n"));
                        break;
                    }
                }
            }

            RPRINTK(DPRTL_FRNT, ("      switching to closed: %s.\n",
                                 info->nodename));
            xenbus_switch_state(info->nodename, XenbusStateClosed);
            while (1) {
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
                }
            }

            RPRINTK(DPRTL_FRNT,
                    ("      switching to initializing: %s.\n", info->nodename));
            xenbus_switch_state(info->nodename, XenbusStateInitialising);
            while (1) {
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
                }
            }
            for (nr = 0; nr < info->ring_size; nr++) {
                if (info->ring_refs[nr] != GRANT_INVALID_REF) {
                    gnttab_end_foreign_access(info->ring_refs[nr], 0);
                    info->ring_refs[nr] = GRANT_INVALID_REF;
                }
            }
        }
    }
    XenBlkFreeAllResources(dev_ext, RELEASE_ONLY);
    RPRINTK(DPRTL_ON, ("blkif_disconnect_backend: OUT.\n"));
    DPRINTK(DPRTL_ON,
            ("  alloc_cnt i %d, s %d, v %d\n",
             dev_ext->alloc_cnt_i,
             dev_ext->alloc_cnt_s,
             dev_ext->alloc_cnt_v));
    dev_ext->op_mode = OP_MODE_DISCONNECTED;
}

void
blkif_free(struct blkfront_info *info, int suspend)
{
    XENBLK_LOCK_HANDLE lh = {0};
    void *mem_to_free;
    unsigned int i, ring_size;

    /* Prevent new requests being issued until we fix things up. */
    xenblk_acquire_spinlock(info->xbdev, &info->lock, InterruptLock, NULL, &lh);
    XENBLK_SET_FLAG(info->xenblk_locks, (BLK_FRE_L | BLK_INT_L));
    XENBLK_SET_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
    info->connected = suspend ?
        BLKIF_STATE_SUSPENDED : BLKIF_STATE_DISCONNECTED;
    XENBLK_CLEAR_FLAG(info->xenblk_locks, (BLK_FRE_L | BLK_INT_L));
    XENBLK_CLEAR_FLAG(info->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
    xenblk_release_spinlock(info->xbdev, &info->lock, lh);

    gnttab_cancel_free_callback(&info->callback);

    /* Free resources associated with old device channel. */
    for (i = 0; i < info->ring_size; i++) {
        if (info->ring_refs[i] != GRANT_INVALID_REF) {
            if (!(info->xbdev->state & RESUMING)) {
                RPRINTK(DPRTL_ON,
                        ("      blkif_free: end grant access %d\n",
                         (info->ring_refs[i])));
                gnttab_end_foreign_access(info->ring_refs[i], 0);
            }
            info->ring_refs[i] = GRANT_INVALID_REF;
        }
    }

    if (info->evtchn) {
        if (!(info->xbdev->state & RESUMING)) {
            RPRINTK(DPRTL_ON,
                    ("      blkif_free:unregister_dpc_from_evtchn %d.\n",
                     info->evtchn));
            unregister_dpc_from_evtchn(info->evtchn);
            xenbus_free_evtchn(info->evtchn);
        }
        info->evtchn = 0;
    }

    if (info->ring.sring) {
        RPRINTK(DPRTL_ON, ("      blkif_free: free sring\n"));
        ExFreePool(info->ring.sring);
        info->ring.sring = NULL;
        XENBLK_DEC(info->xbdev->alloc_cnt_s);
    }

    ring_size = RING_SIZE(&info->ring);
    if (info->indirect_segs != NULL) {
        RPRINTK(DPRTL_ON, ("      blkif_free: free indirect_segs\n"));
        for (i = 0; i < ring_size; i++) {
            /* Use mem_to_free to fix DVL error. */
            mem_to_free = info->indirect_segs[i];
            if (mem_to_free != NULL) {
                ExFreePool(mem_to_free);
            }
        }
        ExFreePool(info->indirect_segs);
        info->indirect_segs = NULL;
    }

    info->shadow_free = 0;
    if (info->shadow != NULL) {
        RPRINTK(DPRTL_ON, ("      blkif_free: free shadow\n"));
        for (i = 0; i < ring_size; i++) {
            /* Use mem_to_free to fix DVL error. */
            mem_to_free = info->shadow[i].frame;
            if (mem_to_free != NULL) {
                ExFreePool(mem_to_free);
            }
        }
        ExFreePool(info->shadow);
        info->shadow = NULL;
    }

    if (info->mm.ring[0].mapped_addr) {
        /* This was all allocated in one chunck so just free the first one. */
        RPRINTK(DPRTL_ON, ("      blkif_free: mapped_addr %p\n",
                           info->mm.ring[0].mapped_addr));
        ExFreePool(info->mm.ring[0].mapped_addr);
        info->mm.ring[0].mapped_addr = NULL;
    }
}

#ifdef DBG
static void
blkif_completion_checks(struct blk_shadow *s,
                        struct blkif_request_segment *ind_segs,
                        uint32_t nr_segs)
{
    uint32_t i;

    if (s->num_ind == 0) {
        return;
    }
    if (s->num_ind > s->srb_ext->sgl->NumberOfElements) {
        DPRINTK(DPRTL_IO, ("    blkif_completion srb %p %d\n",
                           s->request, s->num_ind));
    }
    for (i = 0; i < s->num_ind; i++) {
        if (s->num_ind > s->srb_ext->sgl->NumberOfElements) {
            DPRINTK(DPRTL_IO, ("    segs[%d] %d\n",
                               i, ind_segs[i].gref));
        }
    }
    for (i = 0; i < nr_segs; i++) {
        if (s->num_ind > s->srb_ext->sgl->NumberOfElements) {
            DPRINTK(DPRTL_IO, ("  indirect_gref[%d] %d\n",
                               i, s->ind.indirect_grefs[i]));
        }
    }
}
#else
#define blkif_completion_checks(s, segs, nr)
#endif

static void
blkif_completion(struct blkfront_info *info, unsigned long id)
{
    struct blk_shadow *s;
    struct blkif_request_segment *ind_segs;
    uint32_t i;
    uint32_t nr_segs;

    s = &info->shadow[id];
    switch (s->req.operation) {
    case BLKIF_OP_DISCARD:
        break;

    case BLKIF_OP_INDIRECT: {
        nr_segs = BLKIF_INDIRECT_PAGES(s->ind.nr_segments);
        ind_segs = info->indirect_segs[id];
        blkif_completion_checks(s, ind_segs, nr_segs);
        for (i = 0; i < s->num_ind; i++) {
            gnttab_end_foreign_access(ind_segs[i].gref, 0UL);
        }

        for (i = 0; i < nr_segs; i++) {
            gnttab_end_foreign_access(s->ind.indirect_grefs[i], 0UL);
        }
        s->num_ind = 0;
        s->ind.nr_segments = 0;
        break;
    }
    default:
        for (i = 0; i < s->req.nr_segments; i++) {
            gnttab_end_foreign_access(s->req.seg[i].gref, 0);
            CDPRINTK(DPRTL_COND, 0, 0, 1,
                ("blkif_completion: end_foreign_access i = %d, gref = %x.\n",
                i, s->req.seg[i].gref));
        }
        s->req.nr_segments = 0;
        break;
    }
}
