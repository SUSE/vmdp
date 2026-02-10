/*
 * Packed virtio ring manipulation routines
 *
 * Copyright 2019 Red Hat, Inc.
 * Copyright 2021-2026 SUSE LLC
 *
 * Authors:
 *  Yuri Benditovich <ybendito@redhat.com>
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
#include <virtio_ring_packed.h>
#include <virtio_pci.h>
#include <virtio_queue_ops.h>

/* The following is used with USED_EVENT_IDX and AVAIL_EVENT_IDX */
/* Assuming a given event_idx value from the other side, if
 * we have just incremented index from old to new_idx,
 * should we trigger an event?
 */
static __inline BOOLEAN
vring_need_event(u16 event_idx, u16 new_idx, u16 old)
{
    /* Note: Xen has similar logic for notification hold-off
    * in include/xen/interface/io/ring.h with req_event and req_prod
    * corresponding to event_idx + 1 and new_idx respectively.
    * Note also that req_event and req_prod in Xen start at 1,
    * event indexes in virtio start at 0. */
    return (u16)(new_idx - event_idx - 1) < (u16)(new_idx - old);
}

static int
vring_add_buf_packed(
    virtio_queue_t *vq_common, /* the queue */
    virtio_buffer_descriptor_t *sg, /* sg array of length out + in */
    unsigned int out,        /* num of drv->device buffer descriptors in sg */
    unsigned int in,         /* num of device->drv buffer descriptors in sg */
    void *opaque)            /* later returned from vring_get_buf */
{
    virtio_queue_packed_t *vq;
    vring_packed_desc_t *desc;
    unsigned int descs_used;
    unsigned int n;
    u16 head, id, i;
    u16 curr, prev, head_flags;
    u16 flags;

    vq = (virtio_queue_packed_t *)vq_common;
    prev = 0;
    head_flags = 0;

    DPRINTK(DPRTL_RING, ("%s: vq %p, opaque %p\n", __func__, vq, opaque));
    if (opaque == NULL) {
        PRINTK(("%s: opaque is NULL!\n",  __func__));
        return -1;
    }

    if (out + in == 0) {
        PRINTK(("%s: out + in == 0!\n",  __func__));
        return -1;
    }
    descs_used = out + in;

    head = vq->packed.next_avail_idx;
    id = (u16)vq->free_head;

    if (id >= vq->packed.vring.num) {
        PRINTK(("%s: id %d > vring.num %d\n",
                 __func__, id, vq->packed.vring.num));
        return -1;
    }

    if (vq->num_free < descs_used) {
        DPRINTK(DPRTL_UNEXPD, ("Can't add buf len %i - avail = %i\n",
            out + in, vq->num_free));
        return -1;
    }

    desc = vq->packed.vring.desc;
    i = head;
    curr = id;
    for (n = 0; n < descs_used; n++) {
        flags = vq->avail_used_flags;
        flags |= n < out ? 0 : VRING_DESC_F_WRITE;
        if (n != descs_used - 1) {
            flags |= VRING_DESC_F_NEXT;
        }
        desc[i].id = id;
        desc[i].addr = sg->phys_addr;
        desc[i].len = sg->len;
        sg++;
        if (n == 0) {
            head_flags = flags;
        }
        else {
            desc[i].flags = flags;
        }

        prev = curr;
        curr = vq->packed.desc_state[curr].next;

        if (++i >= vq->packed.vring.num) {
            i = 0;
            vq->avail_used_flags ^=
                1 << VRING_PACKED_DESC_F_AVAIL |
                1 << VRING_PACKED_DESC_F_USED;
        }
    }

    if (i < head) {
        vq->packed.avail_wrap_counter ^= 1;
    }

    /* We're using some buffers from the free list. */
    vq->num_free -= descs_used;

    /* Update free pointer */
    vq->packed.next_avail_idx = i;
    vq->free_head = curr;

    /* Store token. */
    vq->packed.desc_state[id].num = (u16)descs_used;
    vq->packed.desc_state[id].data = opaque;
    vq->packed.desc_state[id].last = prev;

    /*
     * A driver MUST NOT make the first descriptor in the list
     * available before all subsequent descriptors comprising
     * the list are made available.
     */
    mb();
    vq->packed.vring.desc[head].flags = head_flags;
    vq->num_added += descs_used;

    DPRINTK(DPRTL_RING, ("Added buffer head @%i+%d to Q%d\n",
            head, descs_used, vq_common->qidx));

    return 0;
}

static int
vring_add_buf_indirect_packed(
    virtio_queue_t *vq_common, /* the queue */
    virtio_buffer_descriptor_t *sg, /* sg array of length out + in */
    unsigned int out,        /* num of drv->device buffer descriptors in sg */
    unsigned int in,         /* num of device->drv buffer descriptors in sg */
    void *opaque,            /* later returned from vring_get_buf */
    void *va_indirect,       /* VA of the indirect page or NULL */
    uint64_t phys_indirect) /* PA of the indirect page or 0 */
{
    virtio_queue_packed_t *vq;
    unsigned int descs_used;
    struct vring_packed_desc *desc;
    u16 head, id, i;

    vq = (virtio_queue_packed_t *)vq_common;

    if (out + in == 0) {
        PRINTK(("%s: out + in == 0!\n",  __func__));
        return -1;
    }
    if (va_indirect == 0 || phys_indirect == 0 || vq->num_free == 0) {
        PRINTK(("%s: indirect addresses not given va %p pa %lld free %d\n",
                 __func__, va_indirect, phys_indirect, vq->num_free));
        return -1;
    }

    descs_used = out + in;
    head = vq->packed.next_avail_idx;
    id = (u16)vq->free_head;

    if (id >= vq->packed.vring.num) {
        PRINTK(("%s: id %d > vring.num %d\n",
                 __func__, id, vq->packed.vring.num));
        return -1;
    }

    desc = va_indirect;
    for (i = 0; i < descs_used; i++) {
        desc[i].flags = i < out ? 0 : VRING_DESC_F_WRITE;
        desc[i].addr = sg->phys_addr;
        desc[i].len = sg->len;
        sg++;
    }
    vq->packed.vring.desc[head].addr = phys_indirect;
    vq->packed.vring.desc[head].len = descs_used * sizeof(vring_packed_desc_t);
    vq->packed.vring.desc[head].id = id;

    mb();
    vq->packed.vring.desc[head].flags =
        VRING_DESC_F_INDIRECT | vq->avail_used_flags;

    DPRINTK(DPRTL_RING, ("Added buffer head %i to Q%d\n",
                         head, vq_common->qidx));
    head++;
    if (head >= vq->packed.vring.num) {
        head = 0;
        vq->packed.avail_wrap_counter ^= 1;
        vq->avail_used_flags ^=
            1 << VRING_PACKED_DESC_F_AVAIL |
            1 << VRING_PACKED_DESC_F_USED;
    }
    vq->packed.next_avail_idx = head;
    /* We're using some buffers from the free list. */
    vq->num_free--;
    vq->num_added++;

    vq->free_head = vq->packed.desc_state[id].next;

    /* Store token and indirect buffer state. */
    vq->packed.desc_state[id].num = 1;
    vq->packed.desc_state[id].data = opaque;
    vq->packed.desc_state[id].last = id;

    return 0;
}

static void
detach_buf_packed(virtio_queue_packed_t *vq, unsigned int id)
{
    vring_desc_state_packed_t *state;

    state = &vq->packed.desc_state[id];

    /* Clear data ptr. */
    state->data = NULL;

    vq->packed.desc_state[state->last].next = (u16)vq->free_head;
    vq->free_head = id;
    vq->num_free += state->num;
}

static void *
vring_detach_unused_buf_packed(virtio_queue_t *vq_common)
{
    virtio_queue_packed_t *vq;
    unsigned int i;
    void *buf;

    vq = (virtio_queue_packed_t *)vq_common;
    for (i = 0; i < vq->packed.vring.num; i++) {
        if (!vq->packed.desc_state[i].data)
            continue;
        /* detach_buf clears data, so grab it now. */
        buf = vq->packed.desc_state[i].data;
        detach_buf_packed(vq, i);
        return buf;
    }
    /* That should have freed everything. */
    if (vq->num_free != vq->packed.vring.num) {
        PRINTK(("%s: num_free %d != vring.num %d\n",
                __func__, vq->num_free, vq->packed.vring));
    }

    return NULL;
}

static void
vring_disable_cb_packed(virtio_queue_t *vq_common)
{
    virtio_queue_packed_t *vq;

    vq = (virtio_queue_packed_t *)vq_common;

    if (vq->packed.event_flags_shadow != VRING_PACKED_EVENT_FLAG_DISABLE) {
        vq->packed.event_flags_shadow = VRING_PACKED_EVENT_FLAG_DISABLE;
        vq->packed.vring.driver->flags = vq->packed.event_flags_shadow;
    }
}

static __inline BOOLEAN
vring_poll_packed(virtio_queue_packed_t *vq, u16 off_wrap)
{
    BOOLEAN wrap_counter;
    u16 used_idx;

    mb();

    wrap_counter = off_wrap >> VRING_PACKED_EVENT_F_WRAP_CTR;
    used_idx = off_wrap & ~(1 << VRING_PACKED_EVENT_F_WRAP_CTR);

    return vring_has_unconsumed_responses_packed(vq, used_idx, wrap_counter);

}

static __inline unsigned
vring_enable_cb_prepare_packed(virtio_queue_packed_t *vq)
{
    BOOLEAN event_suppression_enabled;

    event_suppression_enabled = vq->vq_common.use_event_idx;

    /*
     * We optimistically turn back on interrupts, then check if there was
     * more to do.
     */

    if (event_suppression_enabled) {
        vq->packed.vring.driver->off_wrap =
            vq->last_used_idx |
            (vq->packed.used_wrap_counter <<
                VRING_PACKED_EVENT_F_WRAP_CTR);
        /*
         * We need to update event offset and event wrap
         * counter first before updating event flags.
         */
        mb();
    }

    if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DISABLE) {
        vq->packed.event_flags_shadow = event_suppression_enabled ?
            VRING_PACKED_EVENT_FLAG_DESC :
            VRING_PACKED_EVENT_FLAG_ENABLE;
        vq->packed.vring.driver->flags = vq->packed.event_flags_shadow;
    }

    return vq->last_used_idx | ((u16)vq->packed.used_wrap_counter <<
        VRING_PACKED_EVENT_F_WRAP_CTR);
}

static BOOLEAN
vring_enable_cb_packed(virtio_queue_t *vq_common)
{
    virtio_queue_packed_t *vq;
    unsigned last_used_idx;

    vq = (virtio_queue_packed_t *)vq_common;
    last_used_idx = vring_enable_cb_prepare_packed(vq);
    return !vring_poll_packed(vq, (u16)last_used_idx);
}

static BOOLEAN
vring_enable_cb_delayed_packed(virtio_queue_t *vq_common)
{
    virtio_queue_packed_t *vq;
    BOOLEAN event_suppression_enabled;
    u16 used_idx, wrap_counter;
    u16 bufs;

    vq = (virtio_queue_packed_t *)vq_common;
    event_suppression_enabled = vq->vq_common.use_event_idx;

    /*
     * We optimistically turn back on interrupts, then check if there was
     * more to do.
     */

    if (event_suppression_enabled) {
        /* TODO: tune this threshold */
        bufs = ((u16)(vq->packed.vring.num - vq->num_free)) * 3 / 4;
        wrap_counter = vq->packed.used_wrap_counter;

        used_idx = vq->last_used_idx + bufs;
        if (used_idx >= vq->packed.vring.num) {
            used_idx -= (u16)vq->packed.vring.num;
            wrap_counter ^= 1;
        }

        vq->packed.vring.driver->off_wrap = used_idx |
            (wrap_counter << VRING_PACKED_EVENT_F_WRAP_CTR);

        /*
         * We need to update event offset and event wrap
         * counter first before updating event flags.
         */
        mb();
    }

    if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DISABLE) {
        vq->packed.event_flags_shadow = event_suppression_enabled ?
            VRING_PACKED_EVENT_FLAG_DESC :
            VRING_PACKED_EVENT_FLAG_ENABLE;
        vq->packed.vring.driver->flags = vq->packed.event_flags_shadow;
    }

    /*
     * We need to update event suppression structure first
     * before re-checking for more used buffers.
     */
    mb();

    if (vring_has_unconsumed_responses_packed(vq,
                                              vq->last_used_idx,
                                              vq->packed.used_wrap_counter)) {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
vring_is_interrupt_enabled_packed(virtio_queue_t *vq_common)
{
    virtio_queue_packed_t *vq;

    vq = (virtio_queue_packed_t *)vq_common;
    return vq->packed.event_flags_shadow & VRING_PACKED_EVENT_FLAG_DISABLE;
}

static void
vring_shutdown_packed(virtio_queue_t *vq_common)
{
    virtio_queue_packed_t *vq;
    unsigned int num;
    void *vring_men;
    unsigned int vring_align;

    vq = (virtio_queue_packed_t *)vq_common;
    num = vq->packed.vring.num;
    vring_men = vq->packed.vring.desc;
    vring_align = vq_common->vdev->addr ? PAGE_SIZE : SMP_CACHE_BYTES;

    RtlZeroMemory(vring_men, vring_size_packed(num, vring_align));
    vring_vq_setup_packed(vq_common->vdev,
                          vq_common,
                          vring_men,
                          SMP_CACHE_BYTES,
                          (uint16_t)num,
                          vq_common->qidx,
                          vq_common->use_event_idx);
}

static void *
vring_get_buf_packed(virtio_queue_t *vq_common,
                     unsigned int *len)
{
    virtio_queue_packed_t *vq;
    void *ret;
    u16 last_used, id;

    vq = (virtio_queue_packed_t *)vq_common;

    if (!vring_has_unconsumed_responses_packed(vq,
                                               vq->last_used_idx,
                                               vq->packed.used_wrap_counter)) {
        DPRINTK(DPRTL_RING, ("%s: No more buffers in queue\n", __func__));
        return NULL;
    }

    /* Only get used elements after they have been exposed by host. */
    mb();

    last_used = vq->last_used_idx;
    id = vq->packed.vring.desc[last_used].id;
    *len = vq->packed.vring.desc[last_used].len;

    if (id >= vq->packed.vring.num) {
        PRINTK(("%s: id %u out of range\n", __func__, id));
        return NULL;
    }
    if (!vq->packed.desc_state[id].data) {
        PRINTK(("%s: id %u is not a head!\n", __func__, id));
        return NULL;
    }

    /* detach_buf_packed clears data, so grab it now. */
    ret = vq->packed.desc_state[id].data;
    detach_buf_packed(vq, id);

    vq->last_used_idx += vq->packed.desc_state[id].num;
    if (vq->last_used_idx >= vq->packed.vring.num) {
        vq->last_used_idx -= (u16)vq->packed.vring.num;
        vq->packed.used_wrap_counter ^= 1;
    }

    /*
     * If we expect an interrupt for the next entry, tell host
     * by writing event index and flush out the write before
     * the read in the next get_buf call.
     */
    if (vq->packed.event_flags_shadow == VRING_PACKED_EVENT_FLAG_DESC) {
        vq->packed.vring.driver->off_wrap = vq->last_used_idx |
            ((u16)vq->packed.used_wrap_counter <<
                VRING_PACKED_EVENT_F_WRAP_CTR);
        mb();
    }

    return ret;
}

static BOOLEAN
vring_kick_prepare_packed(virtio_queue_t *vq_common)
{
    virtio_queue_packed_t *vq;
    u16 off_wrap, flags, wrap_counter, event_idx, new, old;
    BOOLEAN needs_kick;
    union {
        struct {
            u16 off_wrap;
            u16 flags;
        } s;
        u32 value32;
    } snapshot;

    vq = (virtio_queue_packed_t *)vq_common;
    /*
     * We need to expose the new flags value before checking notification
     * suppressions.
     */
    mb();

    old = vq->packed.next_avail_idx - (u16)vq->num_added;
    new = vq->packed.next_avail_idx;
    vq->num_added = 0;

    snapshot.value32 = *(u32 *)vq->packed.vring.device;
    flags = snapshot.s.flags;

    if (flags != VRING_PACKED_EVENT_FLAG_DESC) {
        needs_kick = (flags != VRING_PACKED_EVENT_FLAG_DISABLE);
        goto out;
    }

    off_wrap = snapshot.s.off_wrap;

    wrap_counter = off_wrap >> VRING_PACKED_EVENT_F_WRAP_CTR;
    event_idx = off_wrap & ~(1 << VRING_PACKED_EVENT_F_WRAP_CTR);
    if (wrap_counter != vq->packed.avail_wrap_counter)
        event_idx -= (u16)vq->packed.vring.num;

    needs_kick = vring_need_event(event_idx, new, old);
out:
    return needs_kick;
}

static void
vring_kick_always_packed(virtio_queue_t *vq_common)
{
    virtio_queue_packed_t *vq;

    vq = (virtio_queue_packed_t *)vq_common;
    mb();
    vq->num_added = 0;
    vq_notify(vq_common);
}

void
static vring_kick_packed(virtio_queue_t *vq_common)
{
    if (vring_kick_prepare_packed(vq_common)) {
        vq_notify(vq_common);
    }
}

static void
vring_start_interrupts_packed(virtio_queue_t *vq_common)
{
    if (vq_common)  {
        vring_enable_cb_packed(vq_common);
        vring_kick_packed(vq_common);
    }
}

static void
vring_stop_interrupts_packed(virtio_queue_t *vq_common)
{
    if (vq_common)  {
        vring_disable_cb_packed(vq_common);
    }
}


static void
vring_get_ring_mem_desc_packed(virtio_queue_t *vq_common,
                               void **ring,
                               void **avail,
                               void **used)
{
    virtio_queue_packed_t *vq;

    vq = (virtio_queue_packed_t *)vq_common;
    if (ring != NULL) {
        *ring = vq->packed.vring.desc;
    }
    if (avail != NULL) {
        *avail = (void *)vq->packed.vring.driver;
    }
    if (used != NULL) {
        *used = (void *)vq->packed.vring.device;
    }
}

/* Initializes a new virtqueue using already allocated memory */
void
vring_vq_setup_packed(virtio_device_t *vdev,
                     virtio_queue_t *vq_common,
                     void *vring_mem,
                     unsigned long align,
                     uint16_t num,
                     uint16_t qidx,
                     BOOLEAN use_event_idx)
{
    UNREFERENCED_PARAMETER(align);

    virtio_queue_packed_t *vq;
    uint16_t i;

    vq = (virtio_queue_packed_t *)vq_common;

    /* initialize the ring */
    vq->packed.vring.num = num;
    vq->packed.vring.desc = vring_mem;

    vq->packed.vring.driver = (vring_packed_desc_event_t *)
        ((uint8_t *)vring_mem + num * sizeof(vring_packed_desc_t));

    vq->packed.vring.device = (vring_packed_desc_event_t *)
        ((uint8_t *)vq->packed.vring.driver
            + sizeof(vring_packed_desc_event_t));

    vq->num_free = num;
    vq->free_head = 0;
    vq->num_added = 0;
    vq->packed.avail_wrap_counter = 1;
    vq->packed.used_wrap_counter = 1;
    vq->last_used_idx = 0;
    vq->avail_used_flags = 1 << VRING_PACKED_DESC_F_AVAIL;
    vq->packed.next_avail_idx = 0;
    vq->packed.event_flags_shadow = 0;
    vq->packed.desc_state = vq->desc_states;

    RtlZeroMemory(vq->packed.desc_state, num * sizeof(*vq->packed.desc_state));
    for (i = 0; i < num - 1; i++) {
        vq->packed.desc_state[i].next = i + 1;
    }

    vq_common->vdev = vdev;
    vq_common->vq_type = packed_vq;
    vq_common->num = num;
    vq_common->qidx = qidx;
    vq_common->use_event_idx = use_event_idx;
    RPRINTK(DPRTL_PCI, ("%s: use_event_idx %d\n",
                        __func__, vq_common->use_event_idx));

    vq_common->vring_add_buf = vring_add_buf_packed;
    vq_common->vring_add_buf_indirect = vring_add_buf_indirect_packed;
    vq_common->vring_get_buf = vring_get_buf_packed;
    vq_common->vring_detach_unused_buf = vring_detach_unused_buf_packed;
    vq_common->vring_kick_always = vring_kick_always_packed;
    vq_common->vring_kick = vring_kick_packed;
    vq_common->vring_disable_interrupt = vring_disable_cb_packed;
    vq_common->vring_enable_interrupt = vring_enable_cb_packed;
    vq_common->vring_start_interrupts = vring_start_interrupts_packed;
    vq_common->vring_stop_interrupts = vring_stop_interrupts_packed;
    vq_common->vring_get_ring_mem_desc = vring_get_ring_mem_desc_packed;
}
