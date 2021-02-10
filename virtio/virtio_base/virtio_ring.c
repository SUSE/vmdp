/*
 * Copyright 2017 Red Hat, Inc.
 *
 * Authors:
 *  Ladi Prosek <lprosek@redhat.com>
 *
 * Copyright 2011-2012 Novell, Inc.
 * Copyright 2012-2021 SUSE LLC
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

#include <ntddk.h>
#include <win_stdint.h>
#include <win_mmio_map.h>
#include <win_mem_barrier.h>
#include <virtio_dbg_print.h>
#include <virtio_config.h>
#include <virtio_ring.h>
#include <virtio_pci.h>
#include <virtio_queue_ops.h>

static int
vring_add_buf(virtio_queue_t *vq_common,
    virtio_buffer_descriptor_t *sg,
    unsigned int out,
    unsigned int in,
    void *data)
{
    unsigned int i, avail, head, prev;
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;
    DPRINTK(DPRTL_RING, ("%s: vq %p, data %p\n", __func__, vq, data));
    if (data == NULL) {
        PRINTK(("%s: data is NULL!\n",  __func__));
        return -1;
    }

    if (out + in > vq->vring.num) {
        PRINTK(("%s: out %d + in %d > vq->vring.num %d!\n",  __func__,
                out, in, vq->vring.num));
        return -1;
    }

    if (out + in == 0) {
        PRINTK(("%s: out + in == 0!\n",  __func__));
        return -1;
    }

    if (vq->num_free < out + in) {
        DPRINTK(DPRTL_UNEXPD, ("Can't add buf len %i - avail = %i\n",
            out + in, vq->num_free));
        /*
         * notify the host immediately if we are out of
         * descriptors in tx ring
         */
        if (out) {
            vq_notify(vq_common);
        }
        return -1;
    }

    /* We're about to use some buffers from the free list. */
    vq->num_free -= out + in;

    prev = 0;
    head = vq->free_head;
    for (i = vq->free_head; out; i = vq->vring.desc[i].next, out--) {
        vq->vring.desc[i].addr = sg->phys_addr;
        vq->vring.desc[i].len = sg->len;
        vq->vring.desc[i].flags = VRING_DESC_F_NEXT;
        prev = i;
        sg++;
    }
    for (; in; i = vq->vring.desc[i].next, in--) {
        vq->vring.desc[i].addr = sg->phys_addr;
        vq->vring.desc[i].len = sg->len;
        vq->vring.desc[i].flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
        DPRINTK(DPRTL_TRC, ("%s >>> sg phys %x, size %d\n",
            __func__,  (uint32_t)vq->vring.desc[i].addr,
            vq->vring.desc[i].len));
        prev = i;
        sg++;
    }
    /* Last one doesn't continue. */
    vq->vring.desc[prev].flags &= ~VRING_DESC_F_NEXT;

    /* Update free pointer */
    vq->free_head = i;

    /* Set token. */
    vq->data[head] = data;

    /*
     * Put entry in available array (but don't update avail->idx until they
     * do sync).  FIXME: avoid modulus here?
     */
    avail = vq->vring.avail->idx & (vq->vring.num - 1);
    vq->vring.avail->ring[avail] = (uint16_t)head;

    DPRINTK(DPRTL_RING, ("%s >>> avail %d vq->vring.avail->idx = %d,\n",
        __func__, avail, vq->vring.avail->idx));
    DPRINTK(DPRTL_RING, ("\tvq->num_added = %d vq->vring.num = %d\n",
        vq->num_added, vq->vring.num));
    DPRINTK(DPRTL_RING, ("%s>>> ring %d, head %d, last_used %d, used %d\n",
                         __func__, vq_common->qidx, head, vq->last_used_idx,
                         vq->vring.used->idx));

    mb();
    vq->vring.avail->idx++;
    vq->num_added++;
    return vq->num_free;
}

static int
vring_add_buf_indirect(virtio_queue_t *vq_common,
    virtio_buffer_descriptor_t *sg,
    unsigned int out,
    unsigned int in,
    void *data,
    struct vring_desc *vr_desc,
    uint64_t pa)
{
    unsigned head;
    unsigned int i;
    unsigned int avail;
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;

    if (!pa) {
        return -1;
    }
    /* Transfer entries from the sg list into the indirect page */
    for (i = 0; i < out; i++) {
        vr_desc[i].addr = sg->phys_addr;
        vr_desc[i].len = sg->len;
        vr_desc[i].next = i + 1;
        vr_desc[i].flags = VRING_DESC_F_NEXT;
        sg++;
    }
    for (; i < (out + in); i++) {
        vr_desc[i].addr = sg->phys_addr;
        vr_desc[i].len = sg->len;
        vr_desc[i].next = i + 1;
        vr_desc[i].flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
        sg++;
    }

    /* Last one doesn't continue. */
    vr_desc[i - 1].flags &= ~VRING_DESC_F_NEXT;
    vr_desc[i - 1].next = 0;

    /* We're about to use a buffer */
    vq->num_free--;

    /* Use a single buffer which doesn't continue */
    head = vq->free_head;
    vq->vring.desc[head].flags = VRING_DESC_F_INDIRECT;
    vq->vring.desc[head].addr = pa;
    vq->vring.desc[head].len = i * sizeof(struct vring_desc);

    /* Update free pointer */
    vq->free_head = vq->vring.desc[head].next;


    /* Set token. */
    vq->data[head] = data;

    /*
     * Put entry in available array (but don't update avail->idx until they
     * do sync).  FIXME: avoid modulus here?
     */
    avail = vq->vring.avail->idx & (vq->vring.num - 1);
    vq->vring.avail->ring[avail] = (uint16_t)head;

    DPRINTK(DPRTL_RING, ("%s >>> avail %d vq->vring.avail->idx = %d,\n",
        __func__, avail, vq->vring.avail->idx));
    DPRINTK(DPRTL_RING, ("\tvq->num_added = %d vq->vring.num = %d\n",
        vq->num_added, vq->vring.num));
    DPRINTK(DPRTL_RING, ("%s>>> ring %d, head %d, last_used %d, used %d\n",
                         __func__, vq_common->qidx, head, vq->last_used_idx,
                         vq->vring.used->idx));

    mb();
    vq->vring.avail->idx++;
    vq->num_added++;
    return vq->num_free;
}

static void
detach_buf(virtio_queue_t *vq_common, unsigned int head)
{
    unsigned int i;
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;

    /* Clear data ptr. */
    vq->data[head] = NULL;

    /* Put back on free list: find end */
    i = head;
    while (vq->vring.desc[i].flags & VRING_DESC_F_NEXT) {
        i = vq->vring.desc[i].next;
        vq->num_free++;
    }

    vq->vring.desc[i].next = (uint16_t) vq->free_head;
    vq->free_head = head;
    /* Plus final descriptor */
    vq->num_free++;
}

static void *
vring_get_buf(virtio_queue_t *vq_common, unsigned int *len)
{
    virtio_queue_split_t *vq;
    void *buf;
    unsigned int i;
    unsigned int avail;

    vq = (virtio_queue_split_t *)vq_common;

    if (!VRING_HAS_UNCONSUMED_RESPONSES(vq)) {
        return NULL;
    }

    /* Only get used array entries after they have been exposed by host. */
    rmb();

    avail = vq->last_used_idx & (vq->vring.num - 1);
    i = vq->vring.used->ring[avail].id;
    *len = vq->vring.used->ring[avail].len;

    DPRINTK(DPRTL_RING,
            ("%s>>> ring %d, id %d, len %d, last_used %d, used %d\n",
             __func__, vq_common->qidx, i, *len, vq->last_used_idx,
             vq->vring.used->idx));

    if (i >= vq->vring.num) {
        PRINTK(("id %u out of range\n", i));
        return NULL;
    }
    if (!vq->data[i]) {
        PRINTK(("id %u is not a head!\n", i));
        return NULL;
    }

    /* detach_buf clears data, so grab it now. */
    buf = vq->data[i];
    detach_buf(vq_common, i);
    vq->last_used_idx++;

    /*
     * If we expect an interrupt for the next entry, tell host
     * by writing event index and flush out the write before
     * the read in the next get_buf call.
     */
    if (vq_common->use_event_idx
            && !(vq->flags & VRING_AVAIL_F_NO_INTERRUPT)) {
        vring_used_event(&vq->vring) = vq->last_used_idx;
        mb();
    }

    return buf;
}

static void *
vring_detach_unused_buf(virtio_queue_t *vq_common)
{
    unsigned int i;
    void *buf;
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;

    for (i = 0; i < vq->vring.num; i++) {
        if (!vq->data[i]) {
            continue;
        }
        buf = vq->data[i];
        detach_buf(vq_common, i);
        vq->vring.avail->idx--;
        return buf;
    }
    return NULL;
}

static __inline BOOLEAN
vring_need_event(u16 event_idx, u16 new_idx, u16 old)
{
    return (u16)(new_idx - event_idx - 1) < (u16)(new_idx - old);
}

static BOOLEAN
vring_kick_prepare(virtio_queue_t *vq_common)
{
    uint16_t new, old;
    BOOLEAN needs_kick;
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;

    /*We need to expose available array entries before checking avail event. */
    mb();

    old = (uint16_t)(vq->vring.avail->idx - vq->num_added);
    new = vq->vring.avail->idx;
    vq->num_added = 0;

    if (vq_common->use_event_idx) {
        needs_kick = vring_need_event(vring_avail_event(&vq->vring), new, old);
    } else {
        needs_kick = !(vq->vring.used->flags & VRING_USED_F_NO_NOTIFY);
    }
    return needs_kick;
}

static void
vring_kick_always(virtio_queue_t *vq_common)
{
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;

    /*
     * Descriptors and available array need to be set before we expose the
     * new available array entries.
     */
    wmb();

    DPRINTK(DPRTL_RING, ("%s>>> vq->vring.avail->idx %d\n",
        __func__, vq->vring.avail->idx));
    vq->num_added = 0;

    /* Need to update avail index before checking if we should notify */
    mb();

    vq_notify(vq_common);
}

void
static vring_kick(virtio_queue_t *vq_common)
{
    if (vring_kick_prepare(vq_common)) {
        vq_notify(vq_common);
    }
}

static void
vring_disable_interrupt(virtio_queue_t *vq_common)
{
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;

    if (!(vq->flags & VRING_AVAIL_F_NO_INTERRUPT)) {
        vq->flags |= VRING_AVAIL_F_NO_INTERRUPT;
        if (vq_common->use_event_idx == FALSE) {
            vq->vring.avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
            mb();
        }
    }
}

static BOOLEAN
vring_enable_interrupt(virtio_queue_t *vq_common)
{
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;

    /*
     * We optimistically turn back on interrupts, then check if there was
     * more to do.
     */
    if (vq->flags & VRING_AVAIL_F_NO_INTERRUPT) {
        vq->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
        if (vq_common->use_event_idx == FALSE) {
            vq->vring.avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
        }
    }

    vring_used_event(&vq->vring) = vq->last_used_idx;
    mb();

    return TRUE;
}

static void
vring_start_interrupts(virtio_queue_t *vq_common)
{
    if (vq_common)  {
        vring_enable_interrupt(vq_common);
        vring_kick(vq_common);
    }
}

static void
vring_stop_interrupts(virtio_queue_t *vq_common)
{
    if (vq_common)  {
        vring_disable_interrupt(vq_common);
    }
}

static void
vring_get_ring_mem_desc(virtio_queue_t *vq_common,
                        void **ring,
                        void **avail,
                        void **used)
{
    virtio_queue_split_t *vq;

    vq = (virtio_queue_split_t *)vq_common;
    if (ring != NULL) {
        *ring = vq->vring.desc;
    }
    if (avail != NULL) {
        *avail = (void *)vq->vring.avail;
    }
    if (used != NULL) {
        *used = (void *)vq->vring.used;
    }
}

/* ********************** Non vring common vq functions ******************* */

/* Negotiates virtio transport features */
void
vring_transport_features(uint64_t *features)
{
    unsigned int i;

    for (i = VIRTIO_TRANSPORT_F_START; i < VIRTIO_TRANSPORT_F_END; i++) {
        if (i != VIRTIO_RING_F_INDIRECT_DESC &&
            i != VIRTIO_RING_F_EVENT_IDX &&
            i != VIRTIO_F_VERSION_1) {
            virtio_feature_disable(*features, i);
        }
    }
}

static __inline
void vring_init_split(struct vring *vr, unsigned int num, void *p,
                  unsigned long align)
{
    vr->num = num;
    vr->desc = p;
    vr->avail = (void *)((uint8_t *)p + num * sizeof(struct vring_desc));
    vr->used = (void *)(((ULONG_PTR)&vr->avail->ring[num] + align - 1)
                & ~((ULONG_PTR)align - 1));
}

void
vring_vq_setup_split(virtio_device_t *vdev,
                     virtio_queue_t *vq_common,
                     void *vring_mem,
                     unsigned long align,
                     uint16_t num,
                     uint16_t qidx,
                     BOOLEAN use_event_idx)
{
    virtio_queue_split_t *vq;
    uint16_t i;

    vq = (virtio_queue_split_t *)vq_common;

    vq->num_free = num;
    vq->free_head = 0;

    if ((num & (num - 1)) != 0) {
        PRINTK(("%s: virtio queue length %u is not a power of 2\n", num));
    }

    RPRINTK(DPRTL_PCI, ("%s: vring_init num %d\n",  __func__, num));
    vring_init_split(&vq->vring, num, vring_mem, align);

    RPRINTK(DPRTL_PCI, ("%s: init descriptors\n", __func__));
    for (i = 0; i < num - 1; i++) {
        vq->vring.desc[i].next = i + 1;
    }

    vq_common->vdev = vdev;
    vq_common->vq_type = split_vq;
    vq_common->num = num;
    vq_common->qidx = qidx;
    vq_common->use_event_idx = use_event_idx;
    RPRINTK(DPRTL_PCI, ("%s: use_event_idx %d\n",
                        __func__, vq_common->use_event_idx));

    vq_common->vring_add_buf = vring_add_buf;
    vq_common->vring_add_buf_indirect = vring_add_buf_indirect;
    vq_common->vring_get_buf = vring_get_buf;
    vq_common->vring_detach_unused_buf = vring_detach_unused_buf;
    vq_common->vring_kick_always = vring_kick_always;
    vq_common->vring_kick = vring_kick;
    vq_common->vring_disable_interrupt = vring_disable_interrupt;
    vq_common->vring_enable_interrupt = vring_enable_interrupt;
    vq_common->vring_start_interrupts = vring_start_interrupts;
    vq_common->vring_stop_interrupts = vring_stop_interrupts;
    vq_common->vring_get_ring_mem_desc = vring_get_ring_mem_desc;
}
