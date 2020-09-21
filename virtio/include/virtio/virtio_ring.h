#ifndef _LINUX_VIRTIO_RING_H
#define _LINUX_VIRTIO_RING_H

#include <virtio_utils.h>

/* An interface for efficient virtio implementation, currently for use by KVM
 * and lguest, but hopefully others soon.  Do NOT change this since it will
 * break existing servers and clients.
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright Rusty Russell IBM Corporation 2007.
 * Copyright 2020 SUSE LLC
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

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT   1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE  2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT   4

/* The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY  1
/* The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT  1

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC 28

/* The Guest publishes the used index for which it expects an interrupt
* at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
* at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX     29

#define SIZE_OF_SINGLE_INDIRECT_DESC 16

#pragma pack(push)
#pragma pack(1)

/* Virtio ring descriptors: 16 bytes.  These can chain together via "next". */
struct vring_desc {
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;
    /* The flags as indicated above. */
    uint16_t flags;
    /* We chain unused descriptors via this, too */
    uint16_t next;
};

struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
    /* Index of start of used descriptor chain. */
    uint32_t id;
    /* Total length of the descriptor chain which was used (written to) */
    uint32_t len;
};

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[];
};

typedef struct vring {
    unsigned int num;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
} vring_t;
#pragma pack(pop)


typedef struct virtio_queue_s {
    vring_t vring;
    uint32_t port;
    struct virtio_device_s *vdev;
    void *notification_addr;
    uint32_t num_free;          /* Number of free buffers */
    uint32_t free_head;         /* Head of free buffer list. */
    uint32_t num_added;         /* Number we've added since last sync. */
    uint16_t qidx;
    uint16_t last_used_idx;     /* Last used index we've seen. */
    uint16_t broken;
    BOOLEAN use_event_idx;
    void *data[];
} virtio_queue_t;


/* The standard layout for the ring is a continuous chunk of memory which looks
 * like this.  We assume num is a power of 2.
 *
 * struct vring
 * {
 *  // The actual descriptors (16 bytes each)
 *  struct vring_desc desc[num];
 *
 *  // A ring of available descriptor heads with free-running index.
 *  __u16 avail_flags;
 *  __u16 avail_idx;
 *  __u16 available[num];
 *
 *  // Padding to the next align boundary.
 *  char pad[];
 *
 *  // A ring of used descriptor heads with free-running index.
 *  __u16 used_flags;
 *  __u16 used_idx;
 *  struct vring_used_elem used[num];
 * };
 */

/* We publish the used event index at the end of the available ring, and vice
 * versa. They are at the end for backwards compatibility.
 */
#define vring_used_event(vr) ((vr)->avail->ring[(vr)->num])
#define vring_avail_event(vr) (*(uint16_t *)&(vr)->used->ring[(vr)->num])

static __inline void vring_init(struct vring *vr, unsigned int num, void *p,
                  unsigned long align)
{
    vr->num = num;
    vr->desc = p;
    vr->avail = (void *)((uint8_t *)p + num*sizeof(struct vring_desc));
    vr->used = (void *)(((ULONG_PTR)&vr->avail->ring[num] + align-1)
                & ~((ULONG_PTR)align - 1));
}

static __inline unsigned vring_size(unsigned int num, unsigned long align)
{
    return (((unsigned)sizeof(struct vring_desc) * num
                    + (unsigned)sizeof(uint16_t) * (3 + num)
                    + align - 1)
                & ~(align - 1))
            + (unsigned)sizeof(uint16_t) * 3
                + (unsigned)sizeof(struct vring_used_elem) * num;
}

static __inline BOOLEAN vring_need_event(u16 event_idx, u16 new_idx, u16 old)
{
    return (u16)(new_idx - event_idx - 1) < (u16)(new_idx - old);
}

#define VRING_HAS_UNCONSUMED_RESPONSES(_vq)                             \
    ((_vq)->last_used_idx != (_vq)->vring.used->idx)

#define VRING_FINAL_CHECK_FOR_RESPONSES(_vq, _more_to_do)               \
    (_more_to_do) = ((_vq)->last_used_idx != (_vq)->vring.used->idx)

int vring_add_buf(virtio_queue_t *vq,
    virtio_buffer_descriptor_t *sg,
    unsigned int out,
    unsigned int in,
    void *data);
int vring_add_buf_indirect(virtio_queue_t *vq,
    virtio_buffer_descriptor_t *sg,
    unsigned int out,
    unsigned int in,
    void *data,
    struct vring_desc *vr_desc,
    uint64_t pa);
void *vring_get_buf(virtio_queue_t *vq, unsigned int *len);
void *vring_detach_unused_buf(virtio_queue_t *vq);
void vring_kick_always(virtio_queue_t *vq);
void vring_kick(virtio_queue_t *vq);
void vring_disable_interrupt(virtio_queue_t *vq);
BOOLEAN vring_enable_interrupt(virtio_queue_t *vq);
void vring_start_interrupts(virtio_queue_t *vq);
void vring_stop_interrupts(virtio_queue_t *vq);
void vring_transport_features(uint64_t *features);

#endif /* _LINUX_VIRTIO_RING_H */
