/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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
 */

#ifndef _VIRTIO_UTILS_H
#define _VIRTIO_UTILS_H

#include <win_stdint.h>
#include <win_mmio_map.h>

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define VIRTIO_POOL_TAG         ((ULONG)'OI_V')

#define VIRTIO_ALLOC(_len)                                              \
    ExAllocatePoolWithTagPriority(                                      \
        NonPagedPoolNx,                                                 \
        (_len),                                                         \
        VIRTIO_POOL_TAG,                                                \
        NormalPoolPriority);

#define VIRTIO_FREE(_addr) ExFreePoolWithTag((_addr), VIRTIO_POOL_TAG)

#if WINVER >= 0x602
#define VIRTIO_ALLOC_CONTIGUOUS(_va, _len)                              \
{                                                                       \
    PHYSICAL_ADDRESS max_phys_addr;                                     \
    PHYSICAL_ADDRESS zero_phys_addr;                                    \
                                                                        \
    max_phys_addr.QuadPart = (uint64_t)-1;                              \
    zero_phys_addr.QuadPart = 0;                                        \
    (_va) = MmAllocateContiguousNodeMemory((_len),                      \
                                           zero_phys_addr,              \
                                           max_phys_addr,               \
                                           zero_phys_addr,              \
                                           PAGE_READWRITE,              \
                                           MM_ANY_NODE_OK);             \
}
#else
#define VIRTIO_ALLOC_CONTIGUOUS(_va, _len)                              \
{                                                                       \
    PHYSICAL_ADDRESS max_phys_addr;                                     \
                                                                        \
    max_phys_addr.QuadPart = (uint64_t)-1;                              \
    (_va) = MmAllocateContiguousMemory((_len), max_phys_addr);          \
}
#endif

#define VIRTIO_FREE_CONTIGUOUS(_va) MmFreeContiguousMemory((_va))

typedef struct virtio_buffer_descriptor_s {
    uint64_t phys_addr;
    unsigned long len;
} virtio_buffer_descriptor_t;

#endif
