/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2010-2012 Novell, Inc.
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

#include "xenbus.h"
#include <win_maddr.h>
#include <win_rtlq_flags.h>

#if defined TARGET_OS_WinNET || \
    defined TARGET_OS_WinLH  || \
    defined TARGET_OS_Win7
#define XEN4_VM_PAGE_ADJUSTMENT_FROM_OS 99
#else
#define XEN4_VM_PAGE_ADJUSTMENT_FROM_OS 100
#endif

#define XEN_VERSION_3    0x30000
#define XEN_VERSION_4    0x40000
#define XEN_VERSION_4_02 0x40002
#define XEN_VERSION_4_12 0x4000c
#define XEN3_VM_PAGE_ADJUSTMENT_FROM_OS 105

#define XEN4_PAGE_ADJUSTMENT 1024
#define XEN3_PAGE_ADJUSTMENT 33
#define XEN_PAGE_ADJUSTMENT 2048
#define XEN_OVMF_BIOS_PAGE_ADJUSTMENT 1240

#define PHYS_MEM_REG_FULL_WSTR \
L"\\Registry\\Machine\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory"

#define PAGES2KB(_p) ((_p) << (PAGE_SHIFT - 10))
#define MB2PAGES(mb) ((mb) << (20 - PAGE_SHIFT))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define PfnHighMem(_pfn) ((_pfn) > (0xffffffff >> PAGE_SHIFT)) ? 1 : 0

#define MAX_MEM_RES_DESCRIPTORS 16 /* gives 256 byts */

struct balloon_stats {
    /* We aim for 'current allocation' == 'target allocation'. */
    xen_ulong_t current_pages;
    xen_ulong_t target_pages;

    /*
     * Drivers may alter the memory reservation independently, but they
     * must inform the balloon driver so we avoid hitting the hard limit.
     */
    xen_ulong_t driver_pages;
    /* Number of pages in high- and low-memory balloons. */
    xen_ulong_t balloon_low;
    xen_ulong_t balloon_high;
};

typedef struct reg_res_list_s {
    ULONG len;
    ULONG value_type;
    CM_RESOURCE_LIST rlist;
} reg_res_list_t;

static struct balloon_stats bs;
static struct xenbus_watch balloon_watch = {0};
static xen_ulong_t totalram_bias;
static xen_ulong_t totalram_pages;
static xen_ulong_t num_physpages;
static KSPIN_LOCK balloon_lock = 0xbad;
static PMDL mdl_head;
static PMDL mdl_tail;
DWORD derive_os_mem;

/* We increase/decrease in batches which fit in a page */
static xen_ulong_t frame_list[PAGE_SIZE / sizeof(xen_ulong_t)];

IO_WORKITEM_ROUTINE balloon_worker;

static void
InsertHeadMdl(PMDL mdl)
{
    mdl->Next = mdl_head;
    mdl_head = mdl;

    if (mdl_tail == NULL) {
        mdl_tail = mdl;
    }
}

static void
InsertTailMdl(PMDL mdl)
{
    if (mdl_tail) {
        mdl_tail->Next = mdl;
    }
    mdl_tail = mdl;
    mdl->Next = NULL;

    if (mdl_head == NULL) {
        mdl_head = mdl;
    }
}

static void
balloon_add_mdl_to_list(PMDL mdl, xen_ulong_t pfn)
{
    /* Lowmem is re-populated first, so highmem pages go at list tail. */
    if (PfnHighMem(pfn)) {
        InsertTailMdl(mdl);
        bs.balloon_high++;
    } else {
        InsertHeadMdl(mdl);
        bs.balloon_low++;
    }
}

static PMDL
balloon_remove_mdl_from_list(void)
{
    PMDL mdl;

    mdl = NULL;
    if (mdl_head) {
        mdl = mdl_head;
        mdl_head = mdl_head->Next;
        mdl->Next = NULL;
        if (mdl_head == NULL) {
            mdl_tail = NULL;
        }
        if (PfnHighMem((MmGetMdlPfnArray(mdl)[0]))) {
            bs.balloon_high--;
        } else {
            bs.balloon_low--;
        }
    }
    return mdl;
}

static xen_ulong_t
current_target(void)
{
    xen_ulong_t target = bs.target_pages;

    if (target > (bs.current_pages + bs.balloon_low + bs.balloon_high)) {
        target = bs.current_pages + bs.balloon_low + bs.balloon_high;
        PRINTK(("balloon: requested target is too large %lld, use %lld\n",
                (uint64_t)bs.target_pages, target));
    }
    return target;
}

static xen_ulong_t
balloon_minimum_target(void)
{
    xen_ulong_t min_pages, curr_pages = current_target();

    /*
     * Simple continuous piecewiese linear function:
     *  max MiB -> min MiB  gradient
     *       0     0
     *      16    16
     *      32    24
     *     128    72    (1/2)
     *     512   168    (1/4)
     *    2048   360    (1/8)
     *    8192   552    (1/32)
     *   32768  1320
     *  131072  4392
     */
    if (num_physpages < MB2PAGES(128)) {
        min_pages = MB2PAGES(8) + (num_physpages >> 1);
    } else if (num_physpages < MB2PAGES(512)) {
        min_pages = MB2PAGES(40) + (num_physpages >> 2);
    } else if (num_physpages < MB2PAGES(2048)) {
        min_pages = MB2PAGES(104) + (num_physpages >> 3);
    } else {
        min_pages = MB2PAGES(296) + (num_physpages >> 5);
    }

    /* Don't enforce growth */
    return min(min_pages, curr_pages);
}

static int
increase_reservation(xen_ulong_t nr_pages)
{
    struct xen_memory_reservation reservation;
    XEN_LOCK_HANDLE lh;
    xen_ulong_t i;
    PMDL mdl, head, tail;
    xen_long_t rc;

    if (nr_pages > ARRAY_SIZE(frame_list)) {
        nr_pages = ARRAY_SIZE(frame_list);
    }

    XenAcquireSpinLock(&balloon_lock, &lh);

    mdl = mdl_head;
    for (i = 0; i < nr_pages && mdl; i++) {
        frame_list[i] = (MmGetMdlPfnArray(mdl)[0]);
        mdl = mdl->Next;
    }

    reservation.address_bits = 0;
    reservation.extent_order = 0,
    reservation.domid = DOMID_SELF;
    set_xen_guest_handle(reservation.extent_start, frame_list);
    reservation.nr_extents = nr_pages;

    RPRINTK(DPRTL_ON, ("%s: %d pages\n", __func__, nr_pages));
    rc = HYPERVISOR_memory_op(XENMEM_populate_physmap, &reservation);

    RPRINTK(DPRTL_ON, ("%s: pages %d, rc %d.\n",
                       __func__, (int)nr_pages, (int)rc));

    if (rc < 0) {
        PRINTK(("%s: pages %d, rc %d.\n",
                __func__, (int)nr_pages, (int)rc));
        XenReleaseSpinLock(&balloon_lock, lh);
    } else {
        head = NULL;
        tail = NULL;
        if (rc == 0) {
            PRINTK(("%s: pages %d, rc %d.\n",
                    __func__, (int)nr_pages, (int)rc));
        }
        for (i = 0; i < (xen_ulong_t)rc; i++) {
            mdl = balloon_remove_mdl_from_list();
            if (mdl == NULL) {
                PRINTK(("%s: balloon_remove_mdl_from_list returned NULL.\n",
                        __func__));
                PRINTK(("  head %p, tail %p, high %lld, low %lld.\n",
                        mdl_head, mdl_tail,
                        (uint64_t)bs.balloon_high, (uint64_t)bs.balloon_low));
                break;
            }
            if (head == NULL) {
                head = mdl;
            } else {
                tail->Next = mdl;
            }
            tail = mdl;
        }

        XenReleaseSpinLock(&balloon_lock, lh);

        for (i = 0; head; i++) {
            mdl = head;
            head = head->Next;
            MmFreePagesFromMdl(mdl);
            ExFreePool(mdl);
        }

        bs.current_pages += i;
        totalram_pages = bs.current_pages - totalram_bias;
    }

    return (int)(rc < 0 ? rc : rc != (xen_long_t)nr_pages);
}

static int
decrease_reservation(xen_ulong_t nr_pages)
{
    PHYSICAL_ADDRESS low, high, skip;
    struct xen_memory_reservation reservation;
    XEN_LOCK_HANDLE lh;
    PMDL mdl, mdl_list;
    xen_ulong_t i;
    xen_ulong_t pfn;
    int need_sleep;
    int ret;

    RPRINTK(DPRTL_ON, ("%s: %d pages\n", __func__, nr_pages));

    if (nr_pages > ARRAY_SIZE(frame_list)) {
        nr_pages = ARRAY_SIZE(frame_list);
    }

    low.QuadPart = 0;
    high.QuadPart = 0xffffffffffffffff;
    skip.QuadPart = 0;
    need_sleep = 0;

    mdl_list = NULL;
    for (i = 0; i < nr_pages; i++) {
        mdl = MmAllocatePagesForMdl(low, high, skip, PAGE_SIZE);
        if (mdl) {
            mdl->Next = mdl_list;
            mdl_list = mdl;
        } else {
            nr_pages = i;
            need_sleep = 1;
            break;
        }
    }

    XenAcquireSpinLock(&balloon_lock, &lh);

    for (i = 0; mdl_list; i++) {
        mdl = mdl_list;
        mdl_list = mdl_list->Next;
        pfn = (MmGetMdlPfnArray(mdl)[0]);
        balloon_add_mdl_to_list(mdl, pfn);
        frame_list[i] = pfn;
    }

    reservation.address_bits = 0;
    reservation.extent_order = 0,
    reservation.domid = DOMID_SELF;
    set_xen_guest_handle(reservation.extent_start, frame_list);
    reservation.nr_extents = nr_pages;

    ret = (int)HYPERVISOR_memory_op(XENMEM_decrease_reservation, &reservation);

    if (ret != nr_pages) {
        PRINTK(("%s: pages %d, rc %d.\n",
                __func__, (int)nr_pages, (int)ret));
    }

    bs.current_pages -= nr_pages;
    totalram_pages = bs.current_pages - totalram_bias;

    XenReleaseSpinLock(&balloon_lock, lh);

    return need_sleep;
}

static void
balloon_handler(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    UNREFERENCED_PARAMETER(watch);
    UNREFERENCED_PARAMETER(vec);
    UNREFERENCED_PARAMETER(len);

    uint64_t new_target;
    char *str;
    struct xenbus_transaction xbt;
    int err;

again:
    err = xenbus_transaction_start(&xbt);
    if (err) {
        PRINTK(("%s: xenbus_transaction_start failed %x\n", __func__, err));
        return;
    }

    str = (char *)xenbus_read(xbt, "memory", "target", NULL);
    /* Ignore read errors and empty reads. */
    if (IS_ERR(str) || str == NULL) {
        xenbus_transaction_end(xbt, 1);
        RPRINTK(DPRTL_ON, ("%s %p: empty or NULL irql %d, cpu %d.\n",
                           __func__, balloon_watch, KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber()));
        return;
    }

    err = xenbus_transaction_end(xbt, 0);
    if (err == -EAGAIN) {
        xenbus_free_string(str);
        goto again;
    }
    new_target =  cmp_strtou64(str, NULL, 10);
    xenbus_free_string(str);
    balloon_do_reservation(new_target);
}

void
balloon_do_reservation(uint64_t new_target)
{
    LARGE_INTEGER timeout;
    xen_long_t credit;
    int need_sleep;
    int i;

    if (new_target == BALLOON_MAX_RESERVATION) {
        new_target = num_physpages << (PAGE_SHIFT - 10);
    }

    /* new_target is in KiB, convert to pages. */
    bs.target_pages = (xen_ulong_t)max((new_target >> (PAGE_SHIFT - 10)),
        balloon_minimum_target());

    PRINTK(("%s: new target = %lld, current pages = %lld\n",
            __func__, (uint64_t)new_target, (uint64_t)bs.target_pages));
    PRINTK(("  pages to be ballooned = %lld.\n", (int64_t)
            ((uint64_t)current_target() - (uint64_t)bs.current_pages)));

    timeout.QuadPart = -10000000; /* 1 second */
    need_sleep = 0;
    i = 0;
    do {
        credit = current_target() - bs.current_pages;
        i++;
        RPRINTK(DPRTL_ON, ("%s %d: cp %d, ct %d, credit = %d.\n",
                           __func__, i, bs.current_pages,
                           current_target(), credit));
        if (credit > 0) {
            need_sleep = (increase_reservation(credit) != 0);
        }
        if (credit < 0) {
            need_sleep = (decrease_reservation(-credit) != 0);
        }
        if (need_sleep) {
            KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        }
    } while (credit != 0 && !need_sleep);
    PRINTK(("%s: high %lld, low %lld, not ballooned %lld.\n",
            __func__, (uint64_t)bs.balloon_high,
            (uint64_t)bs.balloon_low, (uint64_t)credit));
}

static DWORD
balloon_default_os_page_adj(xen_ulong_t version)
{
    DWORD vm_page_adjustment;
    char *str;

    if (version > XEN_VERSION_4_02) {
        vm_page_adjustment = XEN4_VM_PAGE_ADJUSTMENT_FROM_OS;
        RPRINTK(DPRTL_ON, ("%s: use > %x, %d\n",
                           __func__, XEN_VERSION_4_02, vm_page_adjustment));
    } else if (version >= XEN_VERSION_4) {
        vm_page_adjustment = XEN4_VM_PAGE_ADJUSTMENT_FROM_OS;
        RPRINTK(DPRTL_ON, ("%s: use >= %x, %d\n",
                           __func__, XEN_VERSION_4, vm_page_adjustment));
    } else {
        vm_page_adjustment = XEN3_VM_PAGE_ADJUSTMENT_FROM_OS;
        RPRINTK(DPRTL_ON, ("%s: use < %x, %d\n",
                           __func__, XEN_VERSION_4, vm_page_adjustment));
    }
    str = (char *)xenbus_read(XBT_NIL, "hvmloader", "bios", NULL);
    if (!IS_ERR(str) && str != NULL) {
        if (strcmp(str, "ovmf") == 0) {
            PRINTK(("%s:\n\tbios is %s, increase vm_page_adjustment %d by %d\n",
                    __func__, str, vm_page_adjustment,
                    XEN_OVMF_BIOS_PAGE_ADJUSTMENT));
            vm_page_adjustment += XEN_OVMF_BIOS_PAGE_ADJUSTMENT;
        } else {
            PRINTK(("%s:\n\tbios is %s, keep vm_page_adjustment at %d\n",
                    __func__, str, vm_page_adjustment));
        }
        xenbus_free_string(str);
    } else {
        PRINTK(("%s: couldn't read xenstore hvmloader bios.\n", __func__));
    }
    return vm_page_adjustment;
}

static DWORD
balloon_default_xenstore_page_adj(xen_ulong_t version)
{
    DWORD vm_page_adjustment;

    if (version > XEN_VERSION_4_02) {
        vm_page_adjustment = 0;
        RPRINTK(DPRTL_ON, ("%s: use > %x, %d\n",
                           __func__, XEN_VERSION_4_02, vm_page_adjustment));
    } else if (version >= XEN_VERSION_4) {
        vm_page_adjustment = XEN_PAGE_ADJUSTMENT - XEN4_PAGE_ADJUSTMENT;
        RPRINTK(DPRTL_ON, ("%s: use >= %x, %d\n",
                           __func__, XEN_VERSION_4, vm_page_adjustment));
    } else {
        vm_page_adjustment = XEN_PAGE_ADJUSTMENT - XEN3_PAGE_ADJUSTMENT;
        RPRINTK(DPRTL_ON, ("%s: use < %x, %d\n",
                           __func__, XEN_VERSION_4, vm_page_adjustment));
    }
    return vm_page_adjustment;
}

static void
balloon_get_os_vm_page_adjustment(xen_ulong_t version, DWORD *vm_page_adj)
{
    NTSTATUS status;

    /* Get the registry page adjustment if there. */
    status = xenbus_get_reg_value(XENBUS_FULL_DEVICE_KEY_WSTR,
                                  XENBUS_PVCTRL_VM_PAGE_ADJUST_WSTR,
                                  vm_page_adj);
    if (status == STATUS_SUCCESS) {
        PRINTK(("%s:\n\tUsing regitry override for vm_page_adjustment %d\n",
                __func__, *vm_page_adj));
    } else {
        /* The value wasn't there.  Get the default. */
        *vm_page_adj = balloon_default_os_page_adj(version);

        PRINTK(("%s:\n\tUsing default vm_page_adjustment %d\n",
                __func__, *vm_page_adj));
    }
}

static void
balloon_get_derive_os_mem_method(xen_ulong_t version,
                                 DWORD *derive_os_mem_from)
{
    NTSTATUS status;

    if (version >= XEN_VERSION_4_12) {
        /* Default is to use Xenstore devrived total memory. */
        *derive_os_mem_from = XENBUS_DERIVE_OS_MEM_FROM_XENSTORE;
    } else {
        /* Default is to use OS devrived total memory. */
        *derive_os_mem_from = XENBUS_DERIVE_OS_MEM_FROM_OS;
    }

    /* Check for derive_os_memory registry override. */
    status = xenbus_get_reg_value(XENBUS_FULL_DEVICE_KEY_WSTR,
                                  XENBUS_PVCTRL_DERIVE_OS_MEM_WSTR,
                                  derive_os_mem_from);
    if (status == STATUS_SUCCESS) {
        PRINTK(("%s:\n\tUsing regitry override for derive_os_memory %d\n",
                __func__, *derive_os_mem_from));
    } else {
        PRINTK(("%s:\n\tUsing default derive_os_memory %d\n",
                __func__, *derive_os_mem_from));
    }
}

static NTSTATUS
balloon_get_max_phys_pages_from_os(xen_ulong_t *max_pages)
{
    RTL_QUERY_REGISTRY_TABLE paramTable[2] = {0};
    uint8_t buf[sizeof(reg_res_list_t)
        + (sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR)
           * MAX_MEM_RES_DESCRIPTORS)] = {0};
    CM_RESOURCE_LIST *res;
    reg_res_list_t *reg_res_list;
    uint64_t mem_bytes;
    uint64_t tmem;
    NTSTATUS status;
    uint32_t i;
    USHORT flags;
    UCHAR rtype;

    *max_pages = 0;
    reg_res_list = (reg_res_list_t *)buf;
    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = L".Translated";
    paramTable[0].EntryContext = reg_res_list;
    paramTable[0].DefaultType =
        (REG_RESOURCE_LIST<< RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = NULL;
    paramTable[0].DefaultLength = sizeof(buf);

    reg_res_list->len = sizeof(buf);
    reg_res_list->value_type = REG_RESOURCE_LIST;

    RPRINTK(DPRTL_ON, ("%s: size of buf %d, partial %d\n",
                       __func__, sizeof(buf),
                       sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR)));

    status = RtlQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        PHYS_MEM_REG_FULL_WSTR,
        &paramTable[0],
        NULL,
        NULL);
    if (status != STATUS_SUCCESS) {
        PRINTK(("%s: Failed to read registry physical memory: 0x%x.\n",
                __func__, status));
        return status;
    }

    RPRINTK(DPRTL_ON, ("%s: PHYS_MEM len %ld, data len %ld\n",
                       __func__, reg_res_list->len,
                       paramTable[0].DefaultLength));

    if (!reg_res_list) {
        PRINTK(("%s: resource list is null.\n", __func__));
        return STATUS_UNSUCCESSFUL;
    }

    res = &reg_res_list->rlist;
    RPRINTK(DPRTL_ON,
            ("%s: PHYS_MEM len %ld, type %ld, res type %d\n",
             __func__, reg_res_list->len,
             reg_res_list->value_type,
             res->List->PartialResourceList.PartialDescriptors[0].Type));

    for (i = 0, mem_bytes = 0; i < res->List->PartialResourceList.Count; i++) {
        RPRINTK(DPRTL_ON,
                ("%s: PHYS_MEM res type %d, flags 0x%x\n",
                 __func__,
                 res->List->PartialResourceList.PartialDescriptors[i].Type,
                 res->List->PartialResourceList.PartialDescriptors[i].Flags));

        rtype = res->List->PartialResourceList.PartialDescriptors[i].Type;
        flags = res->List->PartialResourceList.PartialDescriptors[i].Flags;

        if (rtype == CmResourceTypeMemory
                || rtype == CmResourceTypeMemoryLarge) {

            tmem = res->List->PartialResourceList.
                PartialDescriptors[i].u.Memory.Length;

            if (rtype == CmResourceTypeMemoryLarge) {
                switch (flags) {
                case CM_RESOURCE_MEMORY_LARGE_40:
                    tmem <<= 8;
                    break;
                case CM_RESOURCE_MEMORY_LARGE_48:
                    tmem <<= 16;
                    break;
                case CM_RESOURCE_MEMORY_LARGE_64:
                    tmem <<= 32;
                    break;
                default:
                    break;
                }
            }
            RPRINTK(DPRTL_ON, ("%s: PHYS_MEM mem[%d] %lld\n",
                              __func__, i, tmem));
            mem_bytes += tmem;
        }
    }
    *max_pages = (xen_ulong_t)(mem_bytes >> PAGE_SHIFT);
    RPRINTK(DPRTL_ON, ("%s: PHYS_MEM total bytes %p %lld pages %lld\n",
                       __func__, (void *)mem_bytes, mem_bytes, *max_pages));
    return STATUS_SUCCESS;
}

static NTSTATUS
balloon_get_max_phys_pages_from_xenstore(xen_ulong_t *max_pages)
{
    uint64_t static_max;
    uint64_t videoram;
    char *str;

    *max_pages = 0;
    str = (char *)xenbus_read(XBT_NIL, "memory", "static-max", NULL);
    if (IS_ERR(str) || str == NULL) {
        PRINTK(("%s: failed to read static-max memory value\n", __func__));
        return STATUS_UNSUCCESSFUL;
    }
    static_max =  cmp_strtou64(str, NULL, 10);
    xenbus_free_string(str);

    str = (char *)xenbus_read(XBT_NIL, "memory", "videoram", NULL);
    if (IS_ERR(str) || str == NULL) {
        PRINTK(("%s: failed to read videoram memory value\n", __func__));
        return STATUS_UNSUCCESSFUL;
    }
    videoram =  cmp_strtou64(str, NULL, 10);
    xenbus_free_string(str);

    *max_pages = (xen_ulong_t)((static_max >> (PAGE_SHIFT - 10))
        - (videoram >> (PAGE_SHIFT - 10)));

    return STATUS_SUCCESS;
}

NTSTATUS
balloon_init(void)
{
    xen_pod_target_t pod_target;
    xen_ulong_t version;
    NTSTATUS status;
    DWORD vm_page_adjustment;
    DWORD attempts;

    RPRINTK(DPRTL_ON, ("%s: derive os mem from %d IN\n",
                       __func__, derive_os_mem));

    /*
     * Only need to get the derive_os_mem if it
     * hasn't been derived yet.  It will already be set when coming
     * back up from a migrate, so no need to get it again.
     */
    vm_page_adjustment = 0;
    if (derive_os_mem == 0) {

        version = (xen_ulong_t)HYPERVISOR_xen_version(0, NULL);
        PRINTK(("%s: HYPERVERSIOR version %x\n", __func__, version));

        status = STATUS_SUCCESS;

        /*
         * The goal here is to get num_physpages equal to the amount RAM
         * reported as installed in the VM.
         */

        balloon_get_derive_os_mem_method(version, &derive_os_mem);


        num_physpages = 0;
        for (attempts = 0;
              num_physpages == 0
                && attempts < XENBUS_DERIVE_OS_MEM_FROM_XENSTORE;
              attempts++) {
            switch (derive_os_mem) {
            case XENBUS_DERIVE_OS_MEM_FROM_OS:
                balloon_get_os_vm_page_adjustment(version, &vm_page_adjustment);
                status = balloon_get_max_phys_pages_from_os(&totalram_pages);
                if (status == STATUS_SUCCESS) {
                    num_physpages = totalram_pages + vm_page_adjustment;
                } else {
                    PRINTK(("%s: Failed to get total RAM pages from OS.\n",
                            __func__));
                    PRINTK(("\tTry xenstore method.\n"));
                    derive_os_mem = XENBUS_DERIVE_OS_MEM_FROM_XENSTORE;
                }
                break;
            case XENBUS_DERIVE_OS_MEM_FROM_XENSTORE:
                if (version > XEN_VERSION_4_02) {
                    status = balloon_get_max_phys_pages_from_xenstore(
                        &totalram_pages);
                    if (status == STATUS_SUCCESS) {
                        num_physpages = totalram_pages;
                    } else {
                        PRINTK(("%s: Failed to get total RAM pages from Xen.\n",
                                __func__));
                        PRINTK(("\tTry OS method.\n"));
                        derive_os_mem = XENBUS_DERIVE_OS_MEM_FROM_OS;
                    }
                } else {
                    pod_target.domid = DOMID_SELF;
                    vm_page_adjustment = balloon_default_xenstore_page_adj(
                        version);
                    if (version >= XEN_VERSION_4) {
                        totalram_pages = HYPERVISOR_memory_op(
                            XENMEM_maximum_reservation,
                            &pod_target.domid);
                    } else {
                        totalram_pages = HYPERVISOR_memory_op(
                            XENMEM_current_reservation,
                            &pod_target.domid);
                    }
                    num_physpages = totalram_pages - vm_page_adjustment;
                }
                break;
            default:
                PRINTK(("%s: Unknown derive_os_mem type %d.\n",
                        __func__, derive_os_mem));
                break;

            }
        }

        if (num_physpages == 0) {
            PRINTK(("%s: failed to get ram pages\n", __func__));
            return STATUS_UNSUCCESSFUL;
        }

        totalram_bias = 0;

        bs.current_pages = num_physpages;
        bs.target_pages  = bs.current_pages;
        bs.balloon_low   = 0;
        bs.balloon_high  = 0;
        bs.driver_pages  = 0UL;

        mdl_head = NULL;
        mdl_tail = NULL;
        KeInitializeSpinLock(&balloon_lock);
    }

    PRINTK(("%s: derive os memeroy method %d\n", __func__, derive_os_mem));
    PRINTK(("\tvm_page_adjustment %d\n", vm_page_adjustment));
    PRINTK(("\ttotalram_pages %d\n", totalram_pages));
    PRINTK(("\tnum_physpages %d\n", num_physpages));

    return STATUS_SUCCESS;
}

void
balloon_worker(PDEVICE_OBJECT fdo, PVOID context)
{
    UNREFERENCED_PARAMETER(fdo);

    RPRINTK(DPRTL_ON, ("balloon_worker: in.\n"));

    if (context != NULL) {
        IoFreeWorkItem((PIO_WORKITEM)context);
    }

    if (pvctrl_flags & XENBUS_PVCTRL_USE_BALLOONING) {
        if (balloon_init() != STATUS_SUCCESS) {
            pvctrl_flags &= ~XENBUS_PVCTRL_USE_BALLOONING;
        }
    }

    if (!(pvctrl_flags & XENBUS_PVCTRL_USE_BALLOONING)) {
        return;
    }

    balloon_watch.callback = balloon_handler;
    balloon_watch.node = "memory/target";
    balloon_watch.flags = XBWF_new_thread;
    balloon_watch.context = NULL;

    register_xenbus_watch(&balloon_watch);
    RPRINTK(DPRTL_ON, ("balloon_worker: out.\n"));
}

void
balloon_start(PFDO_DEVICE_EXTENSION fdx, uint32_t reason)
{
    PIO_WORKITEM work_item;

    if (fdx == NULL || reason != OP_MODE_NORMAL) {
        return;
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        balloon_worker((PDEVICE_OBJECT)fdx, NULL);
        return;
    }

    work_item = IoAllocateWorkItem(fdx->Self);
    if (work_item != NULL) {
        RPRINTK(DPRTL_ON, ("balloon_start: IoQueueWorkItem\n"));
        IoQueueWorkItem(work_item,
                        balloon_worker,
                        DelayedWorkQueue,
                        work_item);
    } else {
        PRINTK(("balloon_start: IoAllocateWorkItem failed.\n"));
    }
}
