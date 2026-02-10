/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
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
#include "xen_support.h"

shared_info_t *shared_info_area;

u8 xen_features[XENFEAT_NR_SUBMAPS * 32];

#define HYPERCALL_PAGE_MEM_SIZE (PAGE_SIZE * 2)
#ifdef ARCH_x86
#if WINVER >= 0xA00
extern uint8_t hypercall_page_mem[];
/* The hypercall_page_mem is in the asm file. */
#else
UCHAR hypercall_page_mem[HYPERCALL_PAGE_MEM_SIZE];
#endif
#endif

static uint64_t xen_mmio;
static unsigned long xen_mmio_alloc;
static uint32_t xen_mmiolen;
static uint8_t *xen_shared_mem;
static uint32_t xen_shared_len;
static uint32_t xen_shared_alloc;

static NTSTATUS
set_hvm_val(uint64_t val, uint32_t idx)
{
    struct xen_hvm_param a;

    RPRINTK(DPRTL_ON, ("set_hvm_val: IN %d\n", idx));
    a.domid = DOMID_SELF;
    a.index = idx;
    a.value = val;
    if (HYPERVISOR_hvm_op(HVMOP_set_param, &a) != 0) {
        PRINTK(("XENBUS: set hvm val failed.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    RPRINTK(DPRTL_ON, ("set_hvm_val: OUT\n"));

    return STATUS_SUCCESS;
}

static void
xenbus_mmio_init(void)
{
    xen_mmio = 0;
    xen_mmio_alloc = 0;
    xen_mmiolen = 0;
    xen_shared_mem = NULL;
    xen_shared_alloc = 0;
    xen_shared_len = 0;
    shared_info_area = NULL;
}

static NTSTATUS
xenbus_set_io_resources(uint64_t mmio, uint8_t *mem, uint32_t mmio_len,
    uint32_t vector, uint32_t reason)
{
    UNREFERENCED_PARAMETER(vector);

    FDO_DEVICE_EXTENSION *fdx;

    RPRINTK(DPRTL_ON,
            ("xenbus_set_io_resources: mmio %llx mem %p mmio_len %x\n",
             mmio, mem, mmio_len));
    RPRINTK(DPRTL_ON,
            ("xenbus_set_io_resources: xen_mmmio %x xen_shared_mem %p\n",
             (uint32_t)xen_mmio, xen_shared_mem));

    if (gfdo && mmio) {
        /* Normal boot up init */
        RPRINTK(DPRTL_ON,
                ("xenbus_set_io_resources: normal init, gfdo %p %p\n",
                 gfdo, *(PDEVICE_OBJECT *)(((shared_info_t *)mem) + 1)));
        fdx = (FDO_DEVICE_EXTENSION *) gfdo->DeviceExtension;
        fdx->mem = mem;
        fdx->mmio = mmio;
        fdx->mmiolen = mmio_len;
    } else {
        RPRINTK(DPRTL_ON,
                ("xenbus_set_io_resources: non-normal init, gfdo %p\n", gfdo));
        if (gfdo == NULL) {
            /* Init due to hibernate or crash dump. */
            if (mem) {
                gfdo = *(PDEVICE_OBJECT *)(((shared_info_t *)mem) + 1);
            }
            if (gfdo == NULL) {
                PRINTK(("xenbus_set_io_resources: failed to get gfdo.\n"));
                return STATUS_UNSUCCESSFUL;
            }
        }
        RPRINTK(DPRTL_ON,
                ("xenbus_set_io_resources: retrieved gfdo %p, reason %x\n",
                 gfdo, reason));
        fdx = (FDO_DEVICE_EXTENSION *) gfdo->DeviceExtension;
        RPRINTK(DPRTL_ON,
                ("xenbus_set_io_resources: mmio %llx, mmiolen %x, mem %p\n",
                 fdx->mmio, fdx->mmiolen, fdx->mem));
    }

    xen_shared_mem = fdx->mem;
    xen_mmio = fdx->mmio;
    xen_mmiolen = fdx->mmiolen;
    xen_shared_len = fdx->mmiolen;

    xen_mmio_alloc = 0;
    xen_shared_alloc = 0;
    shared_info_area = NULL;
    dbg_print_mask = fdx->dbg_print_mask;
    RPRINTK(DPRTL_ON,
            ("xenbus_set_io_resources out: xen_mmio of %x is %p.\n",
             (uint32_t)xen_mmio, xen_shared_mem));
    return STATUS_SUCCESS;
}

NTSTATUS
alloc_xen_mmio(unsigned long len, uint64_t *phys_addr)
{
    if (xen_mmio_alloc + len <= xen_mmiolen) {
        *phys_addr = xen_mmio + xen_mmio_alloc;
        xen_mmio_alloc += len;
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
alloc_xen_shared_mem(uint32_t len, void **addr)
{
    if (xen_shared_alloc + len <= xen_shared_len) {
        *addr = xen_shared_mem + xen_shared_alloc;
        xen_shared_alloc += len;
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

static void
setup_xen_features(void)
{
    xen_feature_info_t fi;
    int i, j;

    for (i = 0; i < XENFEAT_NR_SUBMAPS; i++) {
        fi.submap_idx = i;
        RPRINTK(DPRTL_ON, ("XENBUS: call HYPERVISOR_xen_version.\n"));
        if (HYPERVISOR_xen_version(XENVER_get_features, &fi) < 0) {
            PRINTK(("XENBUS: error setting up xen features.\n"));
            break;
        }
        RPRINTK(DPRTL_ON, ("XENBUS: back from HYPERVISOR_xen_version.\n"));
        for (j = 0; j < 32; j++) {
            xen_features[i * 32 + j] = !!(fi.submap & 1 << j);
        }
    }
}

static NTSTATUS
xen_info_init(uint32_t reason)
{
    unsigned long shared_info_frame;
    struct xen_add_to_physmap_compat xatp;
    PHYSICAL_ADDRESS addr;
    xen_long_t status;

    RPRINTK(DPRTL_ON, ("xen_info_init: calling setup_xen_features.\n"));
    setup_xen_features();

    if (reason == OP_MODE_HIBERNATE || reason == OP_MODE_CRASHDUMP)  {
        return STATUS_SUCCESS;
    }

    RPRINTK(DPRTL_ON,
            ("xen_info_init: IN, sizeof(shared_info_t) = %d.\n",
             sizeof(shared_info_t)));

    RPRINTK(DPRTL_ON, ("xen_info_init: calling alloc_xen_mmio.\n"));
    if (alloc_xen_mmio(PAGE_SIZE,
                       (uint64_t *)&addr.QuadPart) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    shared_info_frame = (ULONG) (addr.QuadPart >> PAGE_SHIFT);

    if (shared_info_frame == 0) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    xatp.domid = DOMID_SELF;
    xatp.idx = 0;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.gpfn = shared_info_frame;

    RPRINTK(DPRTL_ON, ("xen_info_init: calling HYPERVISOR_memory_op.\n"));
    status = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
    if (status != 0) {
        PRINTK(("XENBUS: shared_info hypercall failed.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    RPRINTK(DPRTL_ON, ("xen_info_init: OUT.\n"));
    return STATUS_SUCCESS;
}

VOID
xen_info_cleanup(void)
{
    xenbus_mmio_init();
    shared_info_area = NULL;
}

NTSTATUS
GetXenVersion(uint32_t *ver, uint32_t *offset)
{
    UINT32 eax, ebx, ecx, edx;
    char signature[13];

    GetCPUID(0x40000000, &eax, &ebx, &ecx, &edx);

    signature[12] = 0;
    *(UINT32 *)(signature + 0) = ebx;
    *(UINT32 *)(signature + 4) = ecx;
    *(UINT32 *)(signature + 8) = edx;

    if (eax < 0x40000002) {
        PRINTK(("XENBUS: not on Xen VMM. (sig %s, eax %x)\n",
            signature, eax));
        return STATUS_UNSUCCESSFUL;
    }
    if (strcmp("XenVMMXenVMM", signature) == 0) {
        *offset = 0;
    } else if (strcmp("NovellShimHv", signature) == 0) {
        *offset = 0x1000;
    } else if (strcmp("Microsoft Hv", signature) == 0) {
        *offset = 0x100;
    } else {
        PRINTK(("XENBUS: not on Xen VMM. (sig %s, eax %x)\n",
            signature, eax));
        return STATUS_UNSUCCESSFUL;
    }

    GetCPUID(0x40000001 + *offset, &eax, &ebx, &ecx, &edx);
    *ver = eax;
    return STATUS_SUCCESS;
}

NTSTATUS
InitializeHypercallPage(VOID)
{
    PHYSICAL_ADDRESS addr;
    uint32_t ecx, edx, pages, msr, i;
    uint32_t version, index_offset;

    if (GetXenVersion(&version, &index_offset) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    PRINTK(("Xen version: %d.%d, 0x%x.\n",
        version >> 16, version & 0xffff, version));

    GetCPUID(0x40000002 + index_offset, &pages, &msr, &ecx, &edx);
    RPRINTK(DPRTL_ON, ("XENBUS: hypercall msr 0x%x, pages %d.\n", msr, pages));

    if (pages == 0) {
        PRINTK(("XENBUS: error: hypercall page count == 0?"));
        return STATUS_UNSUCCESSFUL;
    }

    hypercall_page = (PUCHAR)(((uintptr_t)hypercall_page_mem
        & ~(PAGE_SIZE - 1)) + PAGE_SIZE);

    if (hypercall_page + ((uintptr_t)pages * PAGE_SIZE) >
        hypercall_page_mem + HYPERCALL_PAGE_MEM_SIZE) {
        PRINTK(("InitializeHypercallPage: not enough space for %d pages\n",
            pages));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    addr = MmGetPhysicalAddress(hypercall_page);

    RPRINTK(DPRTL_ON,
            ("XENBUS: init hypercall_page %p at va 0x%p pa 0x%08x:%08x\n",
             hypercall_page_mem,
             hypercall_page,
             ((ULONG)(addr.QuadPart >> 32)),
             (ULONG)(addr.QuadPart)));

    RPRINTK(DPRTL_ON,
            ("%02x %02x %02x %02x %02x %02x %02x %02x",
             hypercall_page[0],
             hypercall_page[1],
             hypercall_page[2],
             hypercall_page[3],
             hypercall_page[4],
             hypercall_page[5],
             hypercall_page[6],
             hypercall_page[7]));
    RPRINTK(DPRTL_ON,
            (" %02x %02x %02x %02x %02x %02x %02x %02x\n",
             hypercall_page[8],
             hypercall_page[9],
             hypercall_page[10],
             hypercall_page[11],
             hypercall_page[12],
             hypercall_page[13],
             hypercall_page[14],
             hypercall_page[15]));




    for (i = 0; i < pages; i++) {
        WriteMSR(msr, (UINT64) addr.QuadPart + ((uintptr_t)i * PAGE_SIZE));
    }

    RPRINTK(DPRTL_ON,
            ("%02x %02x %02x %02x %02x %02x %02x %02x",
             hypercall_page[0],
             hypercall_page[1],
             hypercall_page[2],
             hypercall_page[3],
             hypercall_page[4],
             hypercall_page[5],
             hypercall_page[6],
             hypercall_page[7]));
    RPRINTK(DPRTL_ON,
            (" %02x %02x %02x %02x %02x %02x %02x %02x\n",
             hypercall_page[8],
             hypercall_page[9],
             hypercall_page[10],
             hypercall_page[11],
             hypercall_page[12],
             hypercall_page[13],
             hypercall_page[14],
             hypercall_page[15]));

    RPRINTK(DPRTL_ON, ("XENBUS: hypercall_page[0] %x\n",
                       *(uint32_t *)hypercall_page));
    if (*(uint32_t *)hypercall_page == 0) {
        PRINTK(("XENBUS: Xen failed to setup hypercall_page\n"));
        PRINTK(("XENBUS: PV drivers will not be used.\n"));
        PRINTK(("XENBUS: hypercall_page: va 0x%p, pa 0x%08x:%08x\n",
                 hypercall_page,
                 ((ULONG)(addr.QuadPart >> 32)),
                 (ULONG)(addr.QuadPart)));
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

void
xenbus_prepare_shared_for_init(FDO_DEVICE_EXTENSION *fdx,
                               uint32_t shared_info_state)
{
    fdx->initialized = shared_info_state;
}

static void
xenbus_clear_pdx(FDO_DEVICE_EXTENSION *fdx)
{
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;
    uint32_t i;
    uint32_t found;

    for (entry = fdx->ListOfPDOs.Flink;
        entry != &fdx->ListOfPDOs;
        entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if ((pdx->Type == vbd || pdx->Type == vscsi)
                && pdx->frontend_dev != NULL) {
            found = 0;
            if (pdx->Type == vbd) {
                for (i = 0; i < fdx->max_info_entries; i++) {
                    if (fdx->info[i] == pdx->frontend_dev) {
                        RPRINTK(DPRTL_ON,
                                ("xenbus_clear_pdx: found pdx info %p.\n",
                                 pdx->frontend_dev));
                        found = 1;
                        break;
                    }
                }
            } else {
                for (i = 0; i < fdx->max_info_entries; i++) {
                    if (fdx->sinfo[i] == pdx->frontend_dev) {
                        RPRINTK(DPRTL_ON,
                                ("xenbus_clear_pdx: found pdx sinfo %p.\n",
                                 pdx->frontend_dev));
                        found = 1;
                        break;
                    }
                }
            }
            if (!found) {
                RPRINTK(DPRTL_ON,
                        ("xenbus_clear_pdx: not found, pdx info %p.\n",
                         pdx->frontend_dev));
                pdx->frontend_dev = NULL;
                pdx->controller = NULL;
            }
        }
    }
}

NTSTATUS
xenbus_xen_shared_init(uint64_t mmio, uint8_t *mem, uint32_t mmio_len,
    uint32_t vector, uint32_t reason)
{
    FDO_DEVICE_EXTENSION *fdx;
    xenbus_shared_info_t *xenbus_shared_info;
    NTSTATUS status;

    RPRINTK(DPRTL_ON,
            ("xenbus_xen_shared_init: IN gfdo %p, mem %p xsm %p, irql %d.\n",
             gfdo, mem, xen_shared_mem, KeGetCurrentIrql()));

    if (gfdo) {
        fdx = (FDO_DEVICE_EXTENSION *) gfdo->DeviceExtension;
        if (fdx->initialized == SHARED_INFO_INITIALIZED) {
            RPRINTK(DPRTL_ON,
                    ("xenbus_xen_shared_init: OUT, already initialized.\n"));
            return STATUS_SUCCESS;
        }
    }

    do {
        /* initialize hypercall_page */
        RPRINTK(DPRTL_ON,
                ("xenbus_xen_shared_init: call InitializeHypercallPage.\n"));
        status = InitializeHypercallPage();
        if (!NT_SUCCESS(status)) {
            PRINTK(("xenbus_xen_shared_init: init hypercall_page fail.\n"));
            break;
        }
        XENBUS_SET_FLAG(rtrace, INITIALIZE_HYPERCALL_PAGE_F);

        RPRINTK(DPRTL_ON,
                ("xenbus_xen_shared_init: call xenbus_set_io_resources.\n"));
        status = xenbus_set_io_resources(mmio, mem, mmio_len, vector, reason);
        if (!NT_SUCCESS(status)) {
            break;
        }
        if (gfdo == NULL) {
            status = STATUS_UNSUCCESSFUL;
            break;
        }
        fdx = (FDO_DEVICE_EXTENSION *) gfdo->DeviceExtension;

        RPRINTK(DPRTL_ON, ("xenbus_xen_shared_init: call xs_init.\n"));
        status = xs_init(fdx, reason);
        if (!NT_SUCCESS(status)) {
            PRINTK(("xenbus_xen_shared_init: xs_init failed.\n"));
            return status;
        }
        XENBUS_SET_FLAG(rtrace, XS_INIT_F);

        RPRINTK(DPRTL_ON, ("xenbus_xen_shared_init: call xen_info_init.\n"));
        status = xen_info_init(reason);
        if (!NT_SUCCESS(status)) {
            PRINTK(("xenbus_xen_shared_init: xen_info_init fail.\n"));
            break;
        }
        XENBUS_SET_FLAG(rtrace, XEN_INFO_INIT_F);

        RPRINTK(DPRTL_ON, ("xenbus_xen_shared_init: call gnttab_init.\n"));
        gNR_GRANT_FRAMES = fdx->num_grant_frames;
        gNR_GRANT_ENTRIES =
            ((uintptr_t)gNR_GRANT_FRAMES * PAGE_SIZE
                / sizeof(struct grant_entry));
        gGNTTAB_LIST_END = (gNR_GRANT_ENTRIES + 1);
        status = gnttab_init(reason);
        if (!NT_SUCCESS(status)) {
            PRINTK(("xenbus_xen_shared_init: gnttab_init fail.\n"));
            break;
        }
        XENBUS_SET_FLAG(rtrace, GNTTAB_INIT_F);

        RPRINTK(DPRTL_ON, ("xenbus_xen_shared_init: call evtchn_init.\n"));
        evtchn_init(reason);
        XENBUS_SET_FLAG(rtrace, EVTCHN_INIT_F);

        /* Can't write to shared memory until after xen_info init(). */
        RPRINTK(DPRTL_ON,
                ("xenbus_xen_shared_init: calling alloc_xen_shared_mem.\n"));
        status = alloc_xen_shared_mem(PAGE_SIZE, &shared_info_area);
        if (!NT_SUCCESS(status)) {
            PRINTK(("xenbus_xen_shared_init: alloc_xen_shared_mem fail.\n"));
            break;
        }
        RPRINTK(DPRTL_ON, ("xenbus_xen_shared_init: shared_info_area = %p.\n",
                           shared_info_area));
        shared_info_area->vcpu_info[0].evtchn_upcall_mask = 0;

        /*
         * Save off gfdo at the end of share_info_area.  We can then
         * retrieve it during a hibernate or crashdump.
         */
        xenbus_shared_info = (xenbus_shared_info_t *)(shared_info_area + 1);
        xenbus_shared_info->gfdo = gfdo;
        RPRINTK(DPRTL_ON, ("\tVerify gfdo set in shared_info_area:\n"));
        RPRINTK(DPRTL_ON, ("\t  %p %p, len %d.\n",
                           gfdo, *(PDEVICE_OBJECT *)(shared_info_area + 1),
                           sizeof(shared_info_t)));
#ifdef PVVXBN
        xenbus_shared_info->xenbus_set_apis = xenbus_set_apis;

        RPRINTK(DPRTL_ON, ("\txenbus_set_apis %p, xenbus_printk %p\n",
                           xenbus_set_apis, xenbus_printk));
#endif

        status = gnttab_finish_init(gfdo, reason);
        if (!NT_SUCCESS(status)) {
            PRINTK(("xenbus_xen_shared_init: gnttab_init fail.\n"));
            break;
        }
        XENBUS_SET_FLAG(rtrace, GNTTAB_FINISH_INIT_F);

        status = xs_finish_init(gfdo, reason);
        if (!NT_SUCCESS(status)) {
            PRINTK(("xenbus_xen_shared_init: xs_finish_init failed.\n"));
            break;
        }

        status = xenbus_probe_init(gfdo, reason);
        if (!NT_SUCCESS(status)) {
            PRINTK(("xenbus_xen_shared_init: xenbus_probe_init failed.\n"));
            break;
        }

#ifdef DBG
        cpu_ints = 0;
        cpu_ints_claimed = 0;
#endif
        if (reason == OP_MODE_NORMAL) {
            /* If coming up from hibernate, clear out any left over pdx info. */
            xenbus_clear_pdx(fdx);
            xenbus_control_pv_devices(fdx->PortBase, NULL);
            if (fdx->initialized == SHARED_INFO_NOT_INITIALIZED) {
                RPRINTK(DPRTL_ON,
                    ("xenbus_xen_shared_init: IoInvalidateDeviceRelations.\n"));
                IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);
            }
        }

        RPRINTK(DPRTL_ON, ("xenbus_xen_shared_init: balloon_start.\n"));
        balloon_start(fdx, reason);

        fdx->initialized = SHARED_INFO_INITIALIZED;

        /* set_callback_irq() needs to be called elsewhere. */
    } while (FALSE);


    if (status != STATUS_SUCCESS) {
        RPRINTK(DPRTL_ON, ("xenbus_xen_shared_init: xenbus_mmio_init.\n"));
        xenbus_mmio_init();
    }

    RPRINTK(DPRTL_ON, ("xenbus_xen_shared_init: return status %x.\n", status));
    return status;
}
