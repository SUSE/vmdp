/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
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

#ifndef _XENSCSI_H_
#define _XENSCSI_H_

#include <ntddk.h>
#include <ntdddisk.h>
#include <storport.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#include <win_version.h>

#define __XEN_INTERFACE_VERSION__ 0x00030202
#include <asm/win_compat.h>
#include <xen/public/win_xen.h>
#include <xen/public/grant_table.h>
#ifdef ARCH_x86_64
#pragma pack(8)
#else
#pragma pack(4)
#endif
#include <xen/public/io/vscsiif.h>
#pragma pack()
#include <xen/public/io/protocols.h>
#include <win_gnttab.h>
#include <win_xenbus.h>
#include <win_evtchn.h>
#include <win_maddr.h>
#include <win_exalloc.h>
#include <win_cmp_strtol.h>
#include <storport_reg.h>
#include <sp_io_control.h>
#include <vxscsi.h>
#include <win_vxprintk.h>

#define NT_DEVICE_NAME              L"\\Device\\XenScsi"
#define DOS_DEVICE_NAME             L"\\DosDevices\\"
#define XENSCSI_DESIGNATOR_STR      "Xen Virtual Scsi Device"

#define XENSCSI_TAG_GENERAL         'GneX'  /* "XenG" - generic tag */

#define XENSCSI_MEDIA_TYPE          FixedMedia /* 0xF8 */

#define FLAG_LINK_CREATED           0x00000001

#define REQUEST_ALLOCED             0x1
#define VIRTUAL_ADDR_ALLOCED        0x2
#define XENSCSI_MAX_SGL_ELEMENTS    32

#define VSCSI_RING_SIZE __WIN_RING_SIZE((vscsiif_sring_t *)0, PAGE_SIZE)

#define VSCSIFRONT_OP_ADD_LUN   1
#define VSCSIFRONT_OP_DEL_LUN   2

#ifndef unlikely
#define unlikely
#endif

#define CRASHDUMP_LEVEL         IPI_LEVEL

#define BLKIF_STATE_DISCONNECTED 0
#define BLKIF_STATE_CONNECTED    1
#define BLKIF_STATE_SUSPENDED    2


#define WORKING                 0x001
#define PENDINGSTOP             0x002
#define PENDINGREMOVE           0x004
#define SURPRISEREMOVED         0x008
#define REMOVED                 0x010
#define REMOVING                0x020
#define RESTARTING              0x040
#define RESTARTED               0x080
#define INITIALIZING            0x100
#define STOPPED                 0x200
#define UNLOADING               0x400
#define REGISTERING             0x800

#define VS_MAX_LUNS             SCSI_MAXIMUM_LOGICAL_UNITS
#define VS_MAX_TIDS             8
#define VS_MAX_CHNS             4
#define VS_MAX_DEVS             (VS_MAX_LUNS * VS_MAX_TIDS * VS_MAX_CHNS)
#define VS_BUS_SHIFT            6 /* 1 << 6 == (VS_MAX_LUNS * VS_MAX_TIDS)) */
#define VS_TID_SHIFT            3 /* 1 << 3 == (VS_MAX_TIDS)) */

#define VS_GET_LIST_IDX(_chn, _tid, _lun)                                   \
    (((_chn) * VS_MAX_TIDS * VS_MAX_LUNS) + ((_tid) * VS_MAX_LUNS) + (_lun))

#ifdef XENSCSI_REQUEST_VERIFIER
#define PAGE_ROUND_UP           2
#else
#define PAGE_ROUND_UP           1
#endif

#define XENSCSI_LOCK_HANDLE     STOR_LOCK_HANDLE

#ifdef DBG
#define BLK_SIO_L               1
#define BLK_INT_L               2
#define BLK_BLK_L               4
#define BLK_ID_L                8
#define BLK_GET_L               0x10
#define BLK_ADD_L               0x20
#define BLK_CON_L               0x40
#define BLK_FRE_L               0x80
#define BLK_IZE_L               0x100
#define BLK_STI_L               0x200
#define BLK_RBUS_L              0x400
#define BLK_ISR_L               0x800
#define BLK_RDPC_L              0x1000
#define BLK_ACTR_L              0x2000
#define BLK_RSU_L               0x4000

#define XENSCSI_SET_FLAG(_F, _V)        InterlockedOr((LONG *)&(_F), (_V))
#define XENSCSI_CLEAR_FLAG(_F, _V)      InterlockedAnd((LONG *)&(_F), ~(_V))
#define XENSCSI_ZERO_VALUE(_V)          _V = 0
#define XENSCSI_SET_VALUE(_V, _S)       _V = _S
#define XENSCSI_INC(_V)                 InterlockedIncrement((LONG *)&(_V))
#define XENSCSI_DEC(_V)                 InterlockedDecrement((LONG *)&(_V))
#else
#define XENSCSI_SET_FLAG(_F, _V)
#define XENSCSI_CLEAR_FLAG(_F, _V)
#define XENSCSI_SET_VALUE(_V, _S)
#define XENSCSI_ZERO_VALUE(_V)
#define XENSCSI_INC(_V)
#define XENSCSI_DEC(_V)
#endif

#define XENSCSI_DBG_TRACK_SRBS 1
#ifdef XENSCSI_DBG_TRACK_SRBS
extern uint32_t srbs_seen;
extern uint32_t srbs_returned;
extern uint32_t io_srbs_seen;
extern uint32_t io_srbs_returned;
extern uint32_t sio_srbs_seen;
extern uint32_t sio_srbs_returned;
#define XENSCSI_INC_SRB(_V)             InterlockedIncrement((LONG *)&(_V))
#define XENSCSI_DEC_SRB(_V)             InterlockedDecrement((LONG *)&(_V))
#ifdef VBIF_DBG_TRACK_AND_REPORT_SRBS
static inline void
DPR_SRB(char *where)
{
    if (srbs_seen != srbs_returned) {
        PRINTK(("%s: srbs_seen = %x, srbs_returned = %x, diff %d.\n",
            where, srbs_seen, srbs_returned,
            srbs_seen - srbs_returned));
    }
    if (sio_srbs_seen != sio_srbs_returned) {
        PRINTK(("%s: sio_srbs_seen = %x, sio_srbs_returned = %x, diff %d.\n",
            where, sio_srbs_seen, sio_srbs_returned,
            sio_srbs_seen - sio_srbs_returned));
    }
    if (io_srbs_seen != io_srbs_returned) {
        PRINTK(("%s: io_srbs_seen = %x, io_srbs_returned = %x, diff %d.\n",
            where, io_srbs_seen, io_srbs_returned,
            io_srbs_seen - io_srbs_returned));
    }
}
#else
#define DPR_SRB(_where)
#endif

#else
#define XENSCSI_INC_SRB(_V)
#define XENSCSI_DEC_SRB(_V)
#define DPR_SRB(_where)
#endif

typedef struct _xenscsi_srb_extension {
    uint8_t *va;
    STOR_SCATTER_GATHER_LIST *sgl;
    STOR_SCATTER_GATHER_LIST *sys_sgl;
    uint8_t working_sgl_buf[sizeof(STOR_SCATTER_GATHER_LIST) +
        (sizeof(STOR_SCATTER_GATHER_ELEMENT) * XENSCSI_MAX_SGL_ELEMENTS)];
    STOR_SCATTER_GATHER_LIST *working_sgl;
    void *sa[XENSCSI_MAX_SGL_ELEMENTS];
    struct _xenscsi_srb_extension *next;
    SCSI_REQUEST_BLOCK *srb;
    uint32_t use_cnt;
    uint16_t status;
#ifdef DBG
    void *dev_ext;
#endif
} xenscsi_srb_extension;

typedef struct vscsi_shadow {
    vscsiif_request_t req;
    void *request;
    unsigned long frame[VSCSIIF_SG_TABLESIZE];
    xenscsi_srb_extension *srb_ext;
    unsigned int nr_segments;
    grant_ref_t gref;
    uint8_t sc_data_direction;
    uint8_t act;
#ifdef DBG
    uint32_t seq;
#endif
} vscsi_shadow_t;

#ifdef XENSCSI_DBG_SRB_REQ
struct blk_req_ring_el {
    uint64_t addr[XENSCSI_MAX_SGL_ELEMENTS];
    uint32_t len[XENSCSI_MAX_SGL_ELEMENTS];
    uint32_t tlen;
    uint16_t rw;
    uint16_t num_el;
    uint16_t disk;
    uint16_t alloced;
};

struct blk_req_ring {
    struct blk_req_ring_el ring[VSCSI_RING_SIZE];
    uint32_t prod;
};
#endif

struct blk_mm_ring_el {
    void *vaddr;
    uint32_t mapped_elements;
    void *mapped_addr[XENSCSI_MAX_SGL_ELEMENTS];
    unsigned long mapped_len[XENSCSI_MAX_SGL_ELEMENTS];
};

struct blk_mm_ring {
    struct blk_mm_ring_el ring[VSCSI_RING_SIZE];
    unsigned long cons;
    unsigned long prod;
};

enum dma_data_direction {
        DMA_BIDIRECTIONAL = 0,
        DMA_TO_DEVICE = 1,
        DMA_FROM_DEVICE = 2,
        DMA_NONE = 3,
};

typedef struct vscsi_dev {
    LIST_ENTRY sdev_l;
    uint16_t chn;
    uint16_t tid;
    uint16_t lun;
    uint16_t idx;
} vscsi_dev_t;

/*
 * We have one of these per vbd, whether ide, scsi or 'other'.  They
 * hang in private_data off the gendisk structure. We may end up
 * putting all kinds of interesting stuff here :-)
 */
typedef struct vscsi_front_info {
    struct _XENSCSI_DEVICE_EXTENSION *xbdev;
    LIST_ENTRY sdev_list;
    int connected;
    int ring_ref;
    vscsiif_front_ring_t ring;
    unsigned int evtchn;
    KSPIN_LOCK lock;
    STOR_DPC vscsi_int_dpc;
    struct xenbus_watch watch;
    vscsi_shadow_t shadow[VSCSI_RING_SIZE];
    uint16_t id[VSCSI_RING_SIZE];
    uint16_t shadow_free;
    char *nodename;
    char *otherend;
    domid_t otherend_id;
    uint32_t has_interrupt;
    struct blk_mm_ring mm;
    xenscsi_srb_extension *hsrb_ext;
    xenscsi_srb_extension *tsrb_ext;
    vscsi_dev_t *sdev[VS_MAX_DEVS]; /* same as XENBLK_MAXIMUM_TARGETS */
    KEVENT vs_reset_event;

#ifdef DBG
    uint32_t queued_srb_ext;
    uint32_t xenscsi_locks;
    uint32_t cpu_locks;
    uint32_t req;
    uint32_t seq;
    uint32_t cseq;
#endif
} vscsi_front_info_t;

typedef struct _XENSCSI_DEVICE_EXTENSION {
    vscsi_front_info_t *info;
    struct vscsi_front_info **pinfo;
    vscsi_front_info_t info_buffer;
    uint64_t        mmio;
    uint32_t        mmio_len;
    void            *mem;
    void            *port;
    uint32_t        state;
    uint32_t        op_mode;
    ULONG           vector;
    KIRQL           irql;
    XENSCSI_LOCK_HANDLE lh;
    KDPC            restart_dpc;
    uint32_t        max_targets;
    uint32_t        pvctrl_flags;

#ifdef DBG
    uint32_t        xenscsi_locks;
    uint32_t        cpu_locks;
    uint32_t        alloc_cnt_i;
    uint32_t        alloc_cnt_s;
    uint32_t        alloc_cnt_v;
#endif
#ifdef XENSCSI_DBG_SRB_REQ
    struct blk_req_ring req;
#endif
} XENSCSI_DEVICE_EXTENSION, *PXENSCSI_DEVICE_EXTENSION;

ULONG XenDriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath);


static inline void
xenscsi_add_tail(struct vscsi_front_info *info, xenscsi_srb_extension *srb_ext)
{
    if (info->hsrb_ext == NULL) {
        info->hsrb_ext = srb_ext;
        info->tsrb_ext = srb_ext;
    } else {
        info->tsrb_ext->next = srb_ext;
        info->tsrb_ext = srb_ext;
    }
}

static inline void
xenscsi_build_alloced_sgl(uint8_t *va, ULONG tlen,
    STOR_SCATTER_GATHER_LIST *sgl)
{
    STOR_PHYSICAL_ADDRESS pa;
    STOR_PHYSICAL_ADDRESS spa;
    ULONG len;
    uint32_t i;

    DPRINTK(DPRTL_MM, ("xenscsi_build_alloced_sgl of len %d\n", tlen));
    i = 0;
    while (tlen) {
        spa.QuadPart = __pa(va);
        sgl->List[i].PhysicalAddress.QuadPart = spa.QuadPart;
        len =  PAGE_SIZE < tlen ? PAGE_SIZE : tlen;
        while (len < tlen) {
            pa.QuadPart = __pa(va + len);
            if (spa.QuadPart + len != pa.QuadPart) {
                break;
            }
            len += len + PAGE_SIZE < tlen ? PAGE_SIZE : tlen - len;
        }
        DPRINTK(DPRTL_MM,
            ("xenscsi_build_alloced_sgl [%d] len %d\n", i, len));
        sgl->List[i].Length = len;
        va += len;
        tlen -= len;
        i++;
    }
    DPRINTK(DPRTL_MM,
        ("xenscsi_build_alloced_sgl num elements %d\n", i));
    sgl->NumberOfElements = i;
}

#ifdef XENSCSI_DBG_SRB_REQ
static inline void
xenscsi_print_save_req(struct blk_req_ring *req)
{
    uint32_t i;
    uint32_t j;
    uint32_t k;

    PRINTK(("\nVSCSI_RING_SIZE is %d\n", VSCSI_RING_SIZE));
    i = req->prod & (VSCSI_RING_SIZE - 1);
    for (j = 0; j < VSCSI_RING_SIZE; j++) {
        PRINTK(("%3d Disk %d, op %x, total len %d, elements %d, alloced %d\n",
            i,
            req->ring[i].disk,
            req->ring[i].rw,
            req->ring[i].tlen,
            req->ring[i].num_el,
            req->ring[i].alloced));
        for (k = 0; k < req->ring[i].num_el; k++) {
            PRINTK(("\telemet %d, addr %x, len 0x%x\n", k,
                (uint32_t)req->ring[i].addr[k],
                req->ring[i].len[k]));
        }
        i = (i + 1) & (VSCSI_RING_SIZE - 1);
    }
    PRINTK(("End Disk request dump.\n"));
}

static inline void
xenscsi_save_req(struct vscsi_front_info *info,
    SCSI_REQUEST_BLOCK *srb,
    xenscsi_srb_extension *srb_ext)
{
    struct blk_req_ring *req;
    unsigned long idx;
    uint32_t i;

    req = &info->xbdev->req;
    idx = req->prod & (VSCSI_RING_SIZE - 1);

    req->ring[idx].rw = srb->Cdb[0];
    req->ring[idx].num_el = (uint16_t)srb_ext->sys_sgl->NumberOfElements;
    req->ring[idx].tlen = srb->DataTransferLength;
    req->ring[idx].disk = srb->TargetId;
    req->ring[idx].alloced = srb_ext->va ? 1 : 0;
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        req->ring[idx].len[i] = srb_ext->sys_sgl->List[i].Length;
        req->ring[idx].addr[i] =
            srb_ext->sys_sgl->List[i].PhysicalAddress.QuadPart;
    }
    req->prod++;
}

static inline void
xenscsi_print_cur_req(struct vscsi_front_info *info, SCSI_REQUEST_BLOCK *srb)
{
    xenscsi_srb_extension *srb_ext;
    struct blk_req_ring *req;
    unsigned long idx;
    uint32_t i;

    if (!srb) {
        return;
    }

    srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;
    PRINTK(("rDisk %d, op %x, total len %d, elements %d, alloced %d\n",
        srb->TargetId,
        srb->Cdb[0],
        srb->DataTransferLength,
        srb_ext->sys_sgl->NumberOfElements,
        srb_ext->va ? 1 : 0));
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        PRINTK(("\telemet %d, addr %x, len 0x%x\n", i,
            (uint32_t)srb_ext->sys_sgl->List[i].PhysicalAddress.QuadPart,
            srb_ext->sys_sgl->List[i].Length));
    }
}
#else
#define xenscsi_print_save_req(_req)
#define xenscsi_save_req(_info, _srb, _srb_ext)
#define xenscsi_print_cur_req(_info, _srb)
#endif

/***************************** STOR PORT *******************************/
typedef uint64_t xenscsi_addr_t;
#define xenscsi_pause StorPortPause
#define xenscsi_resume StorPortResume

#ifdef DBG
static inline void
xenscsi_request_complete(SCSI_NOTIFICATION_TYPE nt,
    XENSCSI_DEVICE_EXTENSION *dev_ext, SCSI_REQUEST_BLOCK *srb)
{
    UNREFERENCED_PARAMETER(nt);

    xenscsi_srb_extension *srb_ext;

    srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;
    if (srb_ext->dev_ext != (void *)dev_ext) {
        PRINTK(("** srb completion dev_ext don't match %p, %p\n",
            srb_ext->dev_ext, dev_ext));
    }
    StorPortNotification(RequestComplete, dev_ext, srb);
}
#else
#define xenscsi_request_complete StorPortNotification
#endif
#define xenscsi_complete_request StorPortCompleteRequest
#define xenscsi_notification StorPortNotification
#define xenscsi_next_request(_next, _dev_ext)
#define xenscsi_request_timer_call StorPortNotification
#define xenscsi_complete_all_requests StorPortCompleteRequest
#define xenscsi_get_physical_address StorPortGetPhysicalAddress
#define xenscsi_get_device_base StorPortGetDeviceBase
#define xenscsi_build_sgl StorPortGetScatterGatherList
#define xenscsi_set_queue_depth(_dev, _srb, _ring_size)                     \
    StorPortSetDeviceQueueDepth((_dev),                                     \
        (_srb)->PathId,                                                     \
        (_srb)->TargetId,                                                   \
        (_srb)->Lun,                                                        \
        (_ring_size))

#define xenscsi_write_port_ulong(_dev, _port, _val)                         \
    StorPortWritePortUlong((_dev), (PULONG)(_port), (_val))
#define xenscsi_write_port_ushort(_dev, _port, _val)                        \
    StorPortWritePortUshort((_dev), (PUSHORT)(_port), (_val))
#define xenscsi_write_port_uchar(_dev, _port, _val)                         \
    StorPortWritePortUchar((_dev), (PUCHAR)(_port), (_val))

#define xenscsi_read_port_ulong(_dev, _port)                                \
    StorPortReadPortUlong((_dev), (PULONG)(_port))
#define xenscsi_read_port_ushort(_dev, _port)                               \
    StorPortReadPortUshort((_dev), (PUSHORT)(_port))
#define xenscsi_read_port_uchar(_dev, _port)                                \
    StorPortReadPortUchar((_dev), (PUCHAR)(_port))

#define xenscsi_acquire_spinlock(_dext, _plock, _ltype, _lctx, _plhndl)     \
    StorPortAcquireSpinLock((_dext), (_ltype), (_lctx), (_plhndl))
#define xenscsi_release_spinlock(_dext, _plock, _lhndl)                     \
    StorPortReleaseSpinLock((_dext), &(_lhndl))
#define storport_acquire_spinlock(_dext, _ltype, _lctx, _plhndl)            \
    StorPortAcquireSpinLock((_dext), (_ltype), (_lctx), (_plhndl))
#define storport_release_spinlock(_dext, _lhndl)                            \
    StorPortReleaseSpinLock((_dext), &(_lhndl))

#define scsiport_acquire_spinlock(_plock, _plhndl)
#define scsiport_release_spinlock(_plock, _lhndl)

static inline void
xenscsi_map_system_sgl(SCSI_REQUEST_BLOCK *srb, MEMORY_CACHING_TYPE cache_type)
{
    xenscsi_srb_extension *srb_ext;
    uint32_t i;
#ifdef DBG
    KIRQL irql;

    irql = KeGetCurrentIrql();

    if (irql > DISPATCH_LEVEL && irql < HIGH_LEVEL) {
        DPRINTK(DPRTL_ON, ("** xenscsi_map_system_sgl at irql %d **\n", irql));
    }
#endif
    srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;
    ASSERT(srb_ext->sys_sgl->NumberOfElements <= XENSCSI_MAX_SGL_ELEMENTS);
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        srb_ext->sa[i] = mm_map_io_space(
            srb_ext->sys_sgl->List[i].PhysicalAddress,
            srb_ext->sys_sgl->List[i].Length,
            cache_type);
        if (srb_ext->sa[i] == NULL) {
            PRINTK(("xenscsi_map_system_sgl: MmMapIoSpace failed.\n"));
        }
        DPRINTK(DPRTL_MM,
            ("\t\tMmMapIoSpace i %d: sa %p len %x op %x\n", i,
            srb_ext->sa[i],
            srb_ext->sys_sgl->List[i].Length,
            srb->Cdb[0]));
    }

    srb_ext->working_sgl = (STOR_SCATTER_GATHER_LIST *)
        srb_ext->working_sgl_buf;

    xenscsi_build_alloced_sgl(srb_ext->va, srb->DataTransferLength,
        srb_ext->working_sgl);

    srb_ext->sgl = srb_ext->working_sgl;
}

static inline void
xenscsi_unmap_system_address(void *sa[], STOR_SCATTER_GATHER_LIST *sys_sgl)
{
    uint32_t i;

#ifdef DBG
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > DISPATCH_LEVEL && irql < HIGH_LEVEL) {
        DPRINTK(DPRTL_ON, ("** xenscsi_unmap_system_address at irql %d **\n",
                           irql));
    }
#endif
    for (i = 0; i < sys_sgl->NumberOfElements; i++) {
        MmUnmapIoSpace(sa[i], sys_sgl->List[i].Length);
        sa[i] = NULL;
    }
}

static inline void
xenscsi_unmap_system_addresses(struct vscsi_front_info *info)
{
    struct blk_mm_ring *mm;
    unsigned long idx;
    uint32_t i;

#ifdef DBG
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > DISPATCH_LEVEL && irql < HIGH_LEVEL) {
        DPRINTK(DPRTL_ON, ("** xenscsi_unmap_system_addresses at irql %d **\n",
                           irql));
    }
#endif
    mm = &info->mm;
    while (mm->cons != mm->prod) {
        idx = mm->cons & (VSCSI_RING_SIZE - 1);
        for (i = 0; i < mm->ring[idx].mapped_elements; i++) {
            if (mm->ring[idx].mapped_addr[i]) {
                DPRINTK(DPRTL_MM,
                    ("\t\tUnMapIoSpace idx %d i %d: sa %p len %x\n",
                    idx, i,
                    mm->ring[idx].mapped_addr[i],
                    mm->ring[idx].mapped_len[i]));
                MmUnmapIoSpace(mm->ring[idx].mapped_addr[i],
                    mm->ring[idx].mapped_len[i]);
                mm->ring[idx].mapped_addr[i] = NULL;
            }
        }
        if (mm->ring[idx].vaddr) {
            DPRINTK(DPRTL_MM,
                ("mm ExFreePool addr %p\n", mm->ring[idx].vaddr));
            ExFreePool(mm->ring[idx].vaddr);
            XENSCSI_DEC(info->xbdev->alloc_cnt_v);
            mm->ring[idx].vaddr = NULL;
        }
        mm->cons++;
    }
}

static inline void
xenscsi_save_system_address(struct vscsi_front_info *info,
    xenscsi_srb_extension *srb_ext)
{
    struct blk_mm_ring *mm;
    unsigned long idx;
    uint32_t i;

    mm = &info->mm;
    idx = mm->prod & (VSCSI_RING_SIZE - 1);
#ifdef DBG
    if (mm->ring[idx].vaddr != NULL) {
        PRINTK(("xenscsi_save_system_address: vaddr is null %p\n",
            mm->ring[idx].vaddr));
    }
#endif
    mm->ring[idx].vaddr = srb_ext->va;
    DPRINTK(DPRTL_MM,
        ("\tSave sysadd vaddr i %d va %p\n", idx, mm->ring[idx].vaddr));
    mm->ring[idx].mapped_elements = srb_ext->sys_sgl->NumberOfElements;
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        mm->ring[idx].mapped_addr[i] = srb_ext->sa[i];
        mm->ring[idx].mapped_len[i] = srb_ext->sys_sgl->List[i].Length;

        DPRINTK(DPRTL_MM,
            ("\t\tSave sysaddr idx %d i %d: sa %p len %x\n",
            idx, i,
            mm->ring[idx].mapped_addr[i],
            mm->ring[idx].mapped_len[i]));
    }
    mm->prod++;
}

void XenScsiFreeResource(struct vscsi_front_info *info, uint32_t info_idx,
    XENBUS_RELEASE_ACTION action);
void XenScsiFreeAllResources(XENSCSI_DEVICE_EXTENSION *dev_ext,
    XENBUS_RELEASE_ACTION action);
NTSTATUS vscsi_probe(struct vscsi_front_info *info);
vscsi_dev_t *vs_device_lookup(LIST_ENTRY *list,
    uint16_t chn, uint16_t tid, uint16_t lun);
UCHAR vscsi_do_request(struct vscsi_front_info *info, SCSI_REQUEST_BLOCK *srb);
UCHAR vscsi_do_reset(vscsi_front_info_t *info, SCSI_REQUEST_BLOCK *srb);
uint32_t vscsi_complete_int(struct vscsi_front_info *info);
KDEFERRED_ROUTINE vscsi_int_dpc;
KDEFERRED_ROUTINE vscsi_xenbus_int;
void vscsi_quiesce(struct vscsi_front_info *info);
void vscsi_disconnect_backend(XENSCSI_DEVICE_EXTENSION *dev_ext);
void vscsi_shutdown_backend(char *otherend);
void XenScsiDebugDump(XENSCSI_DEVICE_EXTENSION *dev_ext);

static inline void
xenscsi_cp_from_sa(void *sa[], STOR_SCATTER_GATHER_LIST *sys_sgl, uint8_t *va)
{
    uint32_t i;

    for (i = 0; i < sys_sgl->NumberOfElements; i++) {
        RtlCopyMemory(va, sa[i], sys_sgl->List[i].Length);
        va += sys_sgl->List[i].Length;
    }
}

static inline void
xenscsi_cp_to_sa(void *sa[], STOR_SCATTER_GATHER_LIST *sys_sgl, uint8_t *va)
{
    uint32_t i;

    for (i = 0; i < sys_sgl->NumberOfElements; i++) {
        DPRINTK(DPRTL_MM,
            ("   xenscsi_cp_to_sa: sa[%d] %p, va %p, len %d\n",
            i, sa[i], va, sys_sgl->List[i].Length));
        RtlCopyMemory(sa[i], va, sys_sgl->List[i].Length);
        va += sys_sgl->List[i].Length;
    }
}

#endif  /* _XENSCSI_H_ */
