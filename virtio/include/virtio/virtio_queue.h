#ifndef _VIRTIO_QUEUE_H
#define _VIRTIO_QUEUE_H

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
 * Copyright 2021-2026 SUSE LLC
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

typedef enum _virtio_queue_type {
    split_vq,
    packed_vq,
} virtio_queue_type;

struct vring_desc;

typedef struct virtio_queue_s {
    struct virtio_device_s *vdev;
    void *notification_addr;
    virtio_queue_type vq_type;
    unsigned int num;
    unsigned short qidx;
    BOOLEAN use_event_idx;

    int (*vring_add_buf)(struct virtio_queue_s *vq_common,
                         virtio_buffer_descriptor_t *sg,
                         unsigned int out,
                         unsigned int in,
                         void *data);
    int (*vring_add_buf_indirect)(struct virtio_queue_s *vq_common,
                                  virtio_buffer_descriptor_t *sg,
                                  unsigned int out,
                                  unsigned int in,
                                  void *data,
                                  struct vring_desc *vr_desc,
                                  uint64_t pa);
    void * (*vring_get_buf)(struct virtio_queue_s *vq_common,
                            unsigned int *len);
    void * (*vring_detach_unused_buf)(struct virtio_queue_s *vq_common);
    void (*vring_kick_always)(struct virtio_queue_s *vq_common);
    void (*vring_kick)(struct virtio_queue_s *vq_common);
    void (*vring_disable_interrupt)(struct virtio_queue_s *vq_common);
    BOOLEAN (*vring_enable_interrupt)(struct virtio_queue_s *vq_common);
    void (*vring_start_interrupts)(struct virtio_queue_s *vq_common);
    void (*vring_stop_interrupts)(struct virtio_queue_s *vq_common);
    void (*vring_get_ring_mem_desc)(struct virtio_queue_s *vq_common,
                                    void **ring,
                                    void **avail,
                                    void **used);

} virtio_queue_t;

#endif /* _VIRTIO_QUEUE_H */
