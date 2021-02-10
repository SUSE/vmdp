#ifndef _VIRTIO_QUEUE_OPS_H
#define _VIRTIO_QUEUE_OPS_H

/*
 * An interface for efficient virtio implementation, currently for use by KVM
 * and lguest, but hopefully others soon.  Do NOT change this since it will
 * break existing servers and clients.
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2021 SUSE LLC
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
 *
 */

#include <virtio_utils.h>
#include <virtio_queue.h>
#include <virtio_ring.h>
#include <virtio_ring_packed.h>

static __inline int
vq_add_buf(virtio_queue_t *vq,
           virtio_buffer_descriptor_t *sg,
           unsigned int out,
           unsigned int in,
           void *data)
{
    return vq->vring_add_buf(vq, sg, out, in, data);
}

static __inline int
vq_add_buf_indirect(virtio_queue_t *vq,
                    virtio_buffer_descriptor_t *sg,
                    unsigned int out,
                    unsigned int in,
                    void *data,
                    struct vring_desc *vr_desc,
                    uint64_t pa)
{
    return vq->vring_add_buf_indirect(vq, sg, out, in, data, vr_desc, pa);
}

static __inline void *
vq_get_buf(virtio_queue_t *vq, unsigned int *len)
{
    return vq->vring_get_buf(vq, len);
}

static __inline void *
vq_detach_unused_buf(virtio_queue_t *vq)
{
    return vq->vring_detach_unused_buf(vq);
}

static __inline void
vq_kick_always(virtio_queue_t *vq)
{
    vq->vring_kick_always(vq);
}

static __inline void
vq_kick(virtio_queue_t *vq)
{
    vq->vring_kick(vq);
}

static __inline void
vq_disable_interrupt(virtio_queue_t *vq)
{
    vq->vring_disable_interrupt(vq);
}

static __inline BOOLEAN
vq_enable_interrupt(virtio_queue_t *vq)
{
    return vq->vring_enable_interrupt(vq);
}

static __inline void
vq_start_interrupts(virtio_queue_t *vq)
{
    vq->vring_start_interrupts(vq);
}

static __inline void
vq_stop_interrupts(virtio_queue_t *vq)
{
    vq->vring_stop_interrupts(vq);
}

static __inline unsigned int
vq_has_unconsumed_responses(virtio_queue_t *vq_common)
{
    if (vq_common->vq_type == split_vq) {
        return VRING_HAS_UNCONSUMED_RESPONSES(
            (virtio_queue_split_t *)vq_common);

    } else {
        virtio_queue_packed_t *vq;

        vq = (virtio_queue_packed_t *)vq_common;
        return vring_has_unconsumed_responses_packed(
            vq,
            vq->last_used_idx,
            vq->packed.used_wrap_counter);
    }
}

static __inline void
vq_final_check_for_responses(virtio_queue_t *vq_common, int *more_to_do)
{
    if (vq_common->vq_type == split_vq) {
        VRING_FINAL_CHECK_FOR_RESPONSES((virtio_queue_split_t *)vq_common,
                                        more_to_do);
    } else {
        virtio_queue_packed_t *vq;

        vq = (virtio_queue_packed_t *)vq_common;
        *more_to_do = vring_has_unconsumed_responses_packed(
            vq,
            vq->last_used_idx,
            vq->packed.used_wrap_counter);
    }
}

static __inline unsigned int
vq_full(virtio_queue_t *vq)
{
    if (vq->vq_type == split_vq) {
        return ((virtio_queue_split_t *)vq)->num_free == 0;
    } else {
        return ((virtio_queue_packed_t *)vq)->num_free == 0;
    }
}

static __inline unsigned int
vq_empty(virtio_queue_t *vq)
{
    if (vq->vq_type == split_vq) {
        return ((virtio_queue_split_t *)vq)->num_free ==
                   ((virtio_queue_split_t *)vq)->vring.num;
    } else {
        return ((virtio_queue_packed_t *)vq)->num_free ==
                   ((virtio_queue_packed_t *)vq)->packed.vring.num;
    }
}

static __inline unsigned int
vq_free_requests(virtio_queue_t *vq)
{
    if (vq->vq_type == split_vq) {
        return ((virtio_queue_split_t *)vq)->num_free;
    } else {
        return ((virtio_queue_packed_t *)vq)->num_free;
    }
}

static __inline void
vq_get_ring_mem_desc(virtio_queue_t *vq,
                     void **ring,
                     void **avail,
                     void **used)
{
    vq->vring_get_ring_mem_desc(vq, ring, avail, used);
}

static __inline void
vq_notify(virtio_queue_t *vq)
{
    /*
     * we write the queue's selector into the notification register to
     * signal the other end
     */
    RPRINTK(DPRTL_RING, ("[%s] write port %x, idx %x\n",
                         __func__, vq->notification_addr, vq->qidx));
    virtio_iowrite16((ULONG_PTR)(vq->notification_addr), (uint16_t)vq->qidx);
}

#endif /* _VIRTIO_QUEUE_OPS_H */
