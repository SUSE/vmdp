/*-
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

#ifndef _GNTTAB_H
#define _GNTTAB_H

#include <xen/public/grant_table.h>
#include <win_features.h>
#include <asm/win_hypervisor.h>

#define MIN_NR_GRANT_ENTRIES    \
    (MIN_NR_GRANT_FRAMES * PAGE_SIZE / sizeof(struct grant_entry))

#define MAX_NR_GRANT_ENTRIES    \
    (MAX_NR_GRANT_FRAMES * PAGE_SIZE / sizeof(struct grant_entry))

struct gnttab_free_callback {
    struct gnttab_free_callback *next;
    void (*fn)(void *);
    void *arg;
    u16 count;
};

#ifndef USE_INDIRECT_XENBUS_APIS
DLLEXPORT int
gnttab_grant_foreign_access(domid_t domid, unsigned long frame,
                                int readonly);

/*
 * End access through the given grant reference, iff the grant entry is no
 * longer in use.  Return 1 if the grant entry was freed, 0 if it is still in
 * use.
 */
DLLEXPORT int
gnttab_end_foreign_access_ref(grant_ref_t ref, int readonly);

DLLEXPORT void
gnttab_end_foreign_access(grant_ref_t ref, int readonly);

DLLEXPORT int
gnttab_grant_foreign_transfer(domid_t domid, unsigned long pfn);

DLLEXPORT unsigned long
gnttab_end_foreign_transfer_ref(grant_ref_t ref);
DLLEXPORT unsigned long
gnttab_end_foreign_transfer(grant_ref_t ref);

DLLEXPORT int
gnttab_query_foreign_access(grant_ref_t ref);

DLLEXPORT uint16_t
gnttab_query_foreign_access_flags(grant_ref_t ref);

/*
 * operations on reserved batches of grant references
 */
DLLEXPORT int
gnttab_alloc_grant_references(u16 count, grant_ref_t *pprivate_head);

DLLEXPORT void
gnttab_free_grant_reference(grant_ref_t ref);

DLLEXPORT void
gnttab_free_grant_references(grant_ref_t head);

DLLEXPORT int
gnttab_empty_grant_references(const grant_ref_t *pprivate_head);

DLLEXPORT int
gnttab_claim_grant_reference(grant_ref_t *pprivate_head);

DLLEXPORT void
gnttab_release_grant_reference(grant_ref_t *private_head,
                                    grant_ref_t release);

DLLEXPORT void
gnttab_request_free_callback(struct gnttab_free_callback *callback,
                                  void (*fn)(void *), void *arg, u16 count);
DLLEXPORT void
gnttab_cancel_free_callback(struct gnttab_free_callback *callback);

DLLEXPORT void
gnttab_grant_foreign_access_ref(grant_ref_t ref, domid_t domid,
                                     unsigned long frame, int readonly);

DLLEXPORT void
gnttab_grant_foreign_transfer_ref(grant_ref_t, domid_t domid,
                                       unsigned long pfn);
#endif

#define gnttab_map_vaddr(map) ((void *)(map.host_virt_addr))


static __inline void
gnttab_set_map_op(struct gnttab_map_grant_ref *map, unsigned long addr,
                  uint32_t flags, grant_ref_t ref, domid_t domid)
{
    PHYSICAL_ADDRESS physaddr;

    if (flags & GNTMAP_contains_pte) {
        map->host_addr = addr;
    } else if (xen_feature(XENFEAT_auto_translated_physmap)) {
        physaddr = MmGetPhysicalAddress((void *)((ULONG_PTR)addr));
        map->host_addr = physaddr.QuadPart;
    } else {
        map->host_addr = addr;
    }

    map->flags = flags;
    map->ref = ref;
    map->dom = domid;
}

static __inline void
gnttab_set_unmap_op(struct gnttab_unmap_grant_ref *unmap, unsigned long addr,
                    uint32_t flags, grant_handle_t handle)
{
    PHYSICAL_ADDRESS physaddr;

    if (flags & GNTMAP_contains_pte) {
        unmap->host_addr = addr;
    } else if (xen_feature(XENFEAT_auto_translated_physmap)) {
        physaddr = MmGetPhysicalAddress((void *)((ULONG_PTR)addr));
        unmap->host_addr = physaddr.QuadPart;
    } else {
        unmap->host_addr = addr;
    }

    unmap->handle = handle;
    unmap->dev_bus_addr = 0;
}

#endif
