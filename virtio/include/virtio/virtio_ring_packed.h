#ifndef _VIRTIO_RING_PACKED_H
#define _VIRTIO_RING_PACKED_H

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

#include <virtio_utils.h>
#include <virtio_queue.h>

#include <pshpack1.h>

typedef struct vring_packed_desc_event {
    uint16_t off_wrap;  /* Descriptor Ring Change Event Offset/Wrap Counter. */
    uint16_t flags;     /* Descriptor Ring Change Event Flags. */
} vring_packed_desc_event_t;

typedef struct vring_packed_desc {
    uint64_t addr;  /* Buffer Address. */
    uint32_t len;   /* Buffer Length. */
    uint16_t id;    /* Buffer ID. */
    uint16_t flags; /* The flags depending on descriptor type. */
} vring_packed_desc_t;

#include <poppack.h>

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT   1

/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE  2

/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT   4

/*
 * Mark a descriptor as available or used in packed ring.
 * Notice: they are defined as shifts instead of shifted values.
 */
#define VRING_PACKED_DESC_F_AVAIL   7
#define VRING_PACKED_DESC_F_USED    15

/* Enable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_ENABLE  0x0

/* Disable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_DISABLE 0x1

/*
 * Enable events for a specific descriptor in packed ring.
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if VIRTIO_RING_F_EVENT_IDX has been negotiated.
 */
#define VRING_PACKED_EVENT_FLAG_DESC    0x2

 /*
  * Wrap counter bit shift in event suppression structure
  * of packed ring.
  */
#define VRING_PACKED_EVENT_F_WRAP_CTR   15

typedef struct vring_desc_state_packed {
    void *data;         /* Data for callback. */
    u16 num;            /* Descriptor list length. */
    u16 next;           /* The next desc state in a list. */
    u16 last;           /* The last desc state in a list. */
} vring_desc_state_packed_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4200)
#endif

typedef struct virtio_queue_packed {
    virtio_queue_t vq_common;
    unsigned int num_added; /* Number we've added since last sync. */
    unsigned int free_head; /* Head of free buffer list. */
    unsigned int num_free;  /* Number of free descriptors */
    u16 last_used_idx;      /* Last used index we've seen. */
    u16 avail_used_flags;   /* Avail used flags. */
    struct
    {
        BOOLEAN avail_wrap_counter;    /* Driver ring wrap counter. */
        BOOLEAN used_wrap_counter;     /* Device ring wrap counter. */
        u16 next_avail_idx;         /* Index of the next avail descriptor. */
        /*
         * Last written value to driver->flags in
         * guest byte order.
         */
        u16 event_flags_shadow;
        struct {
            unsigned int num;
            struct vring_packed_desc *desc;
            struct vring_packed_desc_event *driver;
            struct vring_packed_desc_event *device;
        } vring;
        struct vring_desc_state_packed *desc_state; /* Per-descriptor state. */
    } packed;
    struct vring_desc_state_packed desc_states[];
} virtio_queue_packed_t;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

static __inline BOOLEAN
vring_has_unconsumed_responses_packed(const virtio_queue_packed_t *vq,
                                      u16 idx,
                                      BOOLEAN used_wrap_counter)
{
    BOOLEAN avail, used;
    u16 flags;

    flags = vq->packed.vring.desc[idx].flags;
    avail = !!(flags & (1 << VRING_PACKED_DESC_F_AVAIL));
    used = !!(flags & (1 << VRING_PACKED_DESC_F_USED));

    return avail == used && used == used_wrap_counter;
}

static __inline unsigned long
vring_size_packed(unsigned int num, unsigned long align)
{
    UNREFERENCED_PARAMETER(align);

    /* array of descriptors */
    unsigned long res = num * sizeof(vring_packed_desc_t);

    /* driver and device event */
    res += 2 * sizeof(vring_packed_desc_event_t);
    return res;
}

static __inline unsigned long
vring_control_block_size_packed(unsigned int num)
{
    return sizeof(virtio_queue_packed_t)
           + sizeof(vring_desc_state_packed_t) * num;
}

void
vring_vq_setup_packed(struct virtio_device_s *vdev,
                     virtio_queue_t *vq_common,
                     void *vring_mem,
                     unsigned long align,
                     uint16_t num,
                     uint16_t qidx,
                     BOOLEAN use_event_idx);

#endif /* _VIRTIO_RING_PACKED_H  */
