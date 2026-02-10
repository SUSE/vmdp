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

#ifndef _XENBLK_H_
#define _XENBLK_H_

#include <ntddk.h>
#include <ntdddisk.h>
#ifdef XENBLK_STORPORT
#include <storport.h>
#else
#include <scsi.h>
#endif

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
#include <xen/public/io/blkif.h>
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
#include <vxblk.h>
#include <win_vxprintk.h>

#define NT_DEVICE_NAME              L"\\Device\\XenBlk"
#define DOS_DEVICE_NAME             L"\\DosDevices\\"
#define XENBLK_DESIGNATOR_STR       "Xen Virtual Block Device"

#define XENBLK_TAG_GENERAL          'GneX'  /* "XenG" - generic tag */

#define XENBLK_MEDIA_TYPE           FixedMedia /* 0xF8 */

#define FLAG_LINK_CREATED           0x00000001

#define REQUEST_ALLOCED             0x1
#define VIRTUAL_ADDR_ALLOCED        0x2
#define XENBLK_MAX_SGL_ELEMENTS     32

#define BLK_RING_SIZE __WIN_RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

#ifndef unlikely
#define unlikely
#endif

#define CRASHDUMP_LEVEL         IPI_LEVEL

#define BLKIF_STATE_DISCONNECTED 0
#define BLKIF_STATE_CONNECTED    1
#define BLKIF_STATE_SUSPENDED    2

/* BLKIF flags */
#define BLKIF_READ_ONLY_F       0x01

#define WORKING                 0x0001
#define PENDINGSTOP             0x0002
#define PENDINGREMOVE           0x0004
#define SURPRISEREMOVED         0x0008
#define REMOVED                 0x0010
#define REMOVING                0x0020
#define RESTARTING              0x0040
#define RESTARTED               0x0080
#define INITIALIZING            0x0100
#define STOPPED                 0x0200
#define UNLOADING               0x0400
#define REGISTERING             0x0800
#define RESUMING                0x1000

#ifdef XENBLK_REQUEST_VERIFIER
#define PAGE_ROUND_UP           2
#else
#define PAGE_ROUND_UP           1
#endif

#ifdef XENBLK_STORPORT
#define XENBLK_LOCK_HANDLE STOR_LOCK_HANDLE
#else
#define XENBLK_LOCK_HANDLE XEN_LOCK_HANDLE
#endif

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

#define XENBLK_SET_FLAG(_F, _V)         InterlockedOr((LONG *)&(_F), (_V))
#define XENBLK_CLEAR_FLAG(_F, _V)       InterlockedAnd((LONG *)&(_F), ~(_V))
#define XENBLK_ZERO_VALUE(_V)           _V = 0
#define XENBLK_SET_VALUE(_V, _S)        _V = _S
#define XENBLK_INC(_V)                  InterlockedIncrement((LONG *)&(_V))
#define XENBLK_DEC(_V)                  InterlockedDecrement((LONG *)&(_V))
#else
#define XENBLK_SET_FLAG(_F, _V)
#define XENBLK_CLEAR_FLAG(_F, _V)
#define XENBLK_SET_VALUE(_V, _S)
#define XENBLK_ZERO_VALUE(_V)
#define XENBLK_INC(_V)
#define XENBLK_DEC(_V)
#endif

#define XENBLK_DBG_TRACK_SRBS 1
#ifdef XENBLK_DBG_TRACK_SRBS
extern uint32_t srbs_seen;
extern uint32_t srbs_returned;
extern uint32_t io_srbs_seen;
extern uint32_t io_srbs_returned;
extern uint32_t sio_srbs_seen;
extern uint32_t sio_srbs_returned;
#define XENBLK_INC_SRB(_V)              InterlockedIncrement((LONG *)&(_V))
#define XENBLK_DEC_SRB(_V)              InterlockedDecrement((LONG *)&(_V))
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
#define XENBLK_INC_SRB(_V)
#define XENBLK_DEC_SRB(_V)
#define DPR_SRB(_where)
#endif

#define BLK_MAX_RING_PAGE_ORDER 4U
#define BLK_MAX_RING_PAGES (1U << BLK_MAX_RING_PAGE_ORDER)
#define BLK_MAX_RING_SIZE __CONST_RING_SIZE(blkif, \
                                            BLK_MAX_RING_PAGES * PAGE_SIZE)

#define BLKIF_SEGS_PER_INDIRECT_FRAME \
    (PAGE_SIZE / sizeof(struct blkif_request_segment))
#define BLKIF_INDIRECT_PAGES(segs) \
    (((segs) + BLKIF_SEGS_PER_INDIRECT_FRAME - 1) \
     / BLKIF_SEGS_PER_INDIRECT_FRAME)

extern uint32_t g_max_segs_per_req;

#ifndef XENBLK_STORPORT
typedef PHYSICAL_ADDRESS STOR_PHYSICAL_ADDRESS;
typedef struct _STOR_SCATTER_GATHER_ELEMENT {
    STOR_PHYSICAL_ADDRESS PhysicalAddress;
    ULONG Length;
    ULONG_PTR Reserved;
} STOR_SCATTER_GATHER_ELEMENT;

typedef struct _STOR_SCATTER_GATHER_LIST {
    ULONG NumberOfElements;
    ULONG_PTR Reserved;
    STOR_SCATTER_GATHER_ELEMENT List[1];
} STOR_SCATTER_GATHER_LIST;
#endif

typedef struct _xenblk_srb_extension {
    uint8_t *va;
    STOR_PHYSICAL_ADDRESS pa;
    STOR_SCATTER_GATHER_LIST *sgl;
    STOR_SCATTER_GATHER_LIST *sys_sgl;
    uint8_t *working_sgl_buf;
    STOR_SCATTER_GATHER_LIST *working_sgl;
#ifdef XENBLK_STORPORT
    void **sa;
#else
    void *sa[1];
    STOR_SCATTER_GATHER_LIST scsi_sgl;
#endif
    struct _xenblk_srb_extension *next;
    SCSI_REQUEST_BLOCK *srb;
    uint32_t use_cnt;
    uint16_t status;
#ifdef DBG
    void *dev_ext;
#endif
} xenblk_srb_extension;

typedef struct blk_shadow {
    union {
        blkif_request_t req;
        blkif_request_indirect_t ind;
    } u;
    void *request;
    unsigned long *frame;
    uint32_t num_ind;
    xenblk_srb_extension *srb_ext;
#ifdef DBG
    uint32_t seq;
#endif
} blk_shadow_t;

#ifdef XENBLK_DBG_SRB_REQ
struct blk_req_ring_el {
    uint64_t addr[XENBLK_MAX_SGL_ELEMENTS];
    uint32_t len[XENBLK_MAX_SGL_ELEMENTS];
    uint32_t tlen;
    uint16_t rw;
    uint16_t num_el;
    uint16_t disk;
    uint16_t alloced;
};

struct blk_req_ring {
    struct blk_req_ring_el ring[BLK_RING_SIZE];
    uint32_t prod;
};
#endif

struct blk_mm_ring_el {
    void *vaddr;
#ifdef XENBLK_STORPORT
    uint32_t mapped_elements;
    void **mapped_addr;
    unsigned long *mapped_len;
#endif
};

struct blk_mm_ring {
    struct blk_mm_ring_el ring[BLK_RING_SIZE];
    unsigned long cons;
    unsigned long prod;
};

typedef struct _XENBLK_DEVICE_EXTENSION {
    struct blkfront_info **info;        /* xenbus has the array */
    uint64_t        mmio;
    uint32_t        mmio_len;
    void            *mem;
    uint32_t        state;
    uint32_t        op_mode;
    ULONG           vector;
    KIRQL           irql;
    XENBLK_LOCK_HANDLE lh;
    KDPC            restart_dpc;
    uint32_t        max_targets;
    uint32_t        pvctrl_flags;
    uint32_t        qdepth;
#ifndef XENBLK_STORPORT
    KSPIN_LOCK      dev_lock;
    KDPC            rwdpc;
#endif
#ifdef DBG
    uint32_t        xenblk_locks;
    uint32_t        cpu_locks;
    uint32_t        alloc_cnt_i;
    uint32_t        alloc_cnt_s;
    uint32_t        alloc_cnt_v;
#endif
#ifdef XENBLK_DBG_SRB_REQ
    struct blk_req_ring req;
#endif
} XENBLK_DEVICE_EXTENSION, *PXENBLK_DEVICE_EXTENSION;

/*
 * We have one of these per vbd, whether ide, scsi or 'other'.  They
 * hang in private_data off the gendisk structure. We may end up
 * putting all kinds of interesting stuff here :-)
 */
struct blkfront_info {
    XENBLK_DEVICE_EXTENSION *xbdev;
    blkif_vdev_t handle;
    int connected;
    unsigned int ring_size;
    blkif_front_ring_t ring;
    struct blkif_request_segment **indirect_segs;
    unsigned int max_segs_per_req;
    unsigned int evtchn;
    LIST_ENTRY rq;
    KSPIN_LOCK lock;
#if defined XENBLK_STORPORT
    STOR_DPC dpc;
#endif
    struct xenbus_watch watch;
    struct gnttab_free_callback callback;
    blk_shadow_t *shadow;
    grant_ref_t ring_refs[BLK_MAX_RING_PAGES];
    void *ring_pages[BLK_MAX_RING_PAGES];
    uint32_t id[BLK_RING_SIZE];
    unsigned long shadow_free;
    unsigned long sector_size;
    uint64_t sectors;
    char *nodename;
    char *otherend;
    domid_t otherend_id;
    uint32_t has_interrupt;
    struct blk_mm_ring mm;
    xenblk_srb_extension *hsrb_ext;
    xenblk_srb_extension *tsrb_ext;
    uint32_t flags;

#ifdef DBG
    uint32_t depth;
    uint32_t max_depth;
    uint32_t queued_srb_ext;
    uint32_t xenblk_locks;
    uint32_t cpu_locks;
    uint32_t req;
    uint32_t seq;
    uint32_t cseq;
#endif
};

ULONG XenDriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath);

#define srb_pages_in_req(_srb_ext, _np)                                     \
{                                                                           \
    ULONG i;                                                                \
    ULONG sgl_len;                                                          \
    ULONG remaining_bytes;                                                  \
    ULONG pg_offset;                                                        \
                                                                            \
    (_np) = 0;                                                              \
    pg_offset = 0;                                                          \
    for (i = 0; i < (_srb_ext)->sgl->NumberOfElements; i++) {               \
        if (((uint32_t)(_srb_ext)->sgl->List[i].PhysicalAddress.QuadPart &  \
                (PAGE_SIZE - 1)) == 0) {                                    \
            (_np) += (((_srb_ext)->sgl->List[i].Length - 1) >>              \
                (PAGE_SHIFT)) + 1;                                          \
        } else {                                                            \
            (_np)++; /* we have at least one page */                        \
            pg_offset = (unsigned long)                                     \
                (_srb_ext)->sgl->List[i].PhysicalAddress.QuadPart &         \
                    (PAGE_SIZE - 1);                                        \
            sgl_len = (_srb_ext)->sgl->List[i].Length;                      \
            remaining_bytes = sgl_len > PAGE_SIZE - pg_offset ?             \
                sgl_len - (PAGE_SIZE - pg_offset) : 0;                      \
            if (remaining_bytes) {                                          \
                (_np) += ((remaining_bytes - 1) >> (PAGE_SHIFT)) + 1;       \
            }                                                               \
        }                                                                   \
    }                                                                       \
}


#define srb_req_offset(_srb, _req_off)                                      \
{                                                                           \
    if ((_srb)->Cdb[0] < SCSIOP_READ16) {                                   \
        (_req_off) = ((uint64_t)((uint32_t)(                                \
            ((PCDB)(_srb)->Cdb)->CDB10.LogicalBlockByte3                    \
            | ((PCDB)(_srb)->Cdb)->CDB10.LogicalBlockByte2 << 8             \
            | ((PCDB)(_srb)->Cdb)->CDB10.LogicalBlockByte1 << 16            \
            | ((PCDB)(_srb)->Cdb)->CDB10.LogicalBlockByte0 << 24)));        \
    } else {                                                                \
        REVERSE_BYTES_QUAD(&(_req_off),                                     \
                           ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock);        \
        DPRINTK(DPRTL_TRC,                                                  \
            ("\tREV: %02x%02x%02x%02x%02x%02x%02x%02x, %x%08x.\n",          \
            ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock[0],                     \
            ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock[1],                     \
            ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock[2],                     \
            ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock[3],                     \
            ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock[4],                     \
            ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock[5],                     \
            ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock[6],                     \
            ((PCDB)(_srb)->Cdb)->CDB16.LogicalBlock[7],                     \
            (uint32_t)((_req_off) >> 32),                                   \
            (uint32_t)(_req_off)));                                         \
    }                                                                       \
}
static inline void
xenblk_add_tail(struct blkfront_info *info, xenblk_srb_extension *srb_ext)
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
xenblk_build_alloced_sgl(uint8_t *va, ULONG tlen,
    STOR_SCATTER_GATHER_LIST *sgl)
{
    STOR_PHYSICAL_ADDRESS pa;
    STOR_PHYSICAL_ADDRESS spa;
    ULONG len;
    uint32_t i;

    DPRINTK(DPRTL_MM, ("xenblk_build_alloced_sgl of len %d\n", tlen));
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
        DPRINTK(DPRTL_MM, ("xenblk_build_alloced_sgl [%d] len %d\n", i, len));
        sgl->List[i].Length = len;
        va += len;
        tlen -= len;
        i++;
    }
    DPRINTK(DPRTL_MM, ("xenblk_build_alloced_sgl num elements %d\n", i));
    sgl->NumberOfElements = i;
}

#ifdef XENBLK_DBG_SRB_REQ
static inline void
xenblk_print_save_req(struct blk_req_ring *req)
{
    uint32_t i;
    uint32_t j;
    uint32_t k;

    PRINTK(("\nBLK_RING_SIZE is %d\n", BLK_RING_SIZE));
    i = req->prod & (BLK_RING_SIZE - 1);
    for (j = 0; j < BLK_RING_SIZE; j++) {
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
        i = (i + 1) & (BLK_RING_SIZE - 1);
    }
    PRINTK(("End Disk request dump.\n"));
}

static inline void
xenblk_save_req(struct blkfront_info *info,
    SCSI_REQUEST_BLOCK *srb,
    xenblk_srb_extension *srb_ext)
{
    struct blk_req_ring *req;
    unsigned long idx;
    uint32_t i;

    req = &info->xbdev->req;
    idx = req->prod & (BLK_RING_SIZE - 1);

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
xenblk_print_cur_req(struct blkfront_info *info, SCSI_REQUEST_BLOCK *srb)
{
    xenblk_srb_extension *srb_ext;
    struct blk_req_ring *req;
    unsigned long idx;
    uint32_t i;

    if (!srb) {
        return;
    }

    srb_ext = (xenblk_srb_extension *)srb->SrbExtension;
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
#define xenblk_print_save_req(_req)
#define xenblk_save_req(_info, _srb, _srb_ext)
#define xenblk_print_cur_req(_info, _srb)
#endif

#ifdef XENBLK_STORPORT
/***************************** STOR PORT *******************************/
typedef uint64_t xenblk_addr_t;
#define xenblk_pause StorPortPause
#define xenblk_resume StorPortResume

#ifdef DBG
static inline void
xenblk_request_complete(SCSI_NOTIFICATION_TYPE nt,
    XENBLK_DEVICE_EXTENSION *dev_ext, SCSI_REQUEST_BLOCK *srb)
{
    UNREFERENCED_PARAMETER(nt);

    xenblk_srb_extension *srb_ext;

    srb_ext = (xenblk_srb_extension *)srb->SrbExtension;
    if (srb_ext->dev_ext != (void *)dev_ext) {
        PRINTK(("** srb completion dev_ext don't match %p, %p\n",
            srb_ext->dev_ext, dev_ext));
    }
    StorPortNotification(RequestComplete, dev_ext, srb);
}
#else
#define xenblk_request_complete StorPortNotification
#endif
#define xenblk_complete_request StorPortCompleteRequest
#define xenblk_notification StorPortNotification
#define xenblk_next_request(_next, _dev_ext)
#define xenblk_request_timer_call StorPortNotification
#define xenblk_complete_all_requests StorPortCompleteRequest
#define xenblk_get_physical_address StorPortGetPhysicalAddress
#define xenblk_get_device_base StorPortGetDeviceBase
#define xenblk_build_sgl StorPortGetScatterGatherList
#define xenblk_set_queue_depth(_dev, _srb, _ring_size)                      \
    StorPortSetDeviceQueueDepth((_dev),                                     \
        (_srb)->PathId,                                                     \
        (_srb)->TargetId,                                                   \
        (_srb)->Lun,                                                        \
        (_ring_size))

#define xenblk_write_port_ulong(_dev, _port, _val)                      \
    StorPortWritePortUlong((_dev), (PULONG)(_port), (_val))
#define xenblk_write_port_ushort(_dev, _port, _val)                     \
    StorPortWritePortUshort((_dev), (PUSHORT)(_port), (_val))
#define xenblk_write_port_uchar(_dev, _port, _val)                      \
    StorPortWritePortUchar((_dev), (PUCHAR)(_port), (_val))

#define xenblk_read_port_ulong(_dev, _port)                             \
    StorPortReadPortUlong((_dev), (PULONG)(_port))
#define xenblk_read_port_ushort(_dev, _port)                            \
    StorPortReadPortUshort((_dev), (PUSHORT)(_port))
#define xenblk_read_port_uchar(_dev, _port)                             \
    StorPortReadPortUchar((_dev), (PUCHAR)(_port))

#define xenblk_acquire_spinlock(_dext, _plock, _ltype, _lctx, _plhndl)  \
    StorPortAcquireSpinLock((_dext), (_ltype), (_lctx), (_plhndl))
#define xenblk_release_spinlock(_dext, _plock, _lhndl)  \
    StorPortReleaseSpinLock((_dext), &(_lhndl))
#define storport_acquire_spinlock(_dext, _ltype, _lctx, _plhndl)    \
    StorPortAcquireSpinLock((_dext), (_ltype), (_lctx), (_plhndl))
#define storport_release_spinlock(_dext, _lhndl)    \
    StorPortReleaseSpinLock((_dext), &(_lhndl))

#define scsiport_acquire_spinlock(_plock, _plhndl)
#define scsiport_release_spinlock(_plock, _lhndl)

static inline void
xenblk_map_system_sgl(SCSI_REQUEST_BLOCK *srb, MEMORY_CACHING_TYPE cache_type)
{
    xenblk_srb_extension *srb_ext;
    uint32_t i;

#ifdef DBG
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > DISPATCH_LEVEL && irql < HIGH_LEVEL) {
        DPRINTK(DPRTL_ON, ("*** xenblk_map_system_sgl at irql %d ***\n", irql));
    }
#endif
    srb_ext = (xenblk_srb_extension *)srb->SrbExtension;
    ASSERT(srb_ext->sys_sgl->NumberOfElements <= XENBLK_MAX_SGL_ELEMENTS);
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        srb_ext->sa[i] = mm_map_io_space(
            srb_ext->sys_sgl->List[i].PhysicalAddress,
            srb_ext->sys_sgl->List[i].Length,
            cache_type);
        if (srb_ext->sa[i] == NULL) {
            PRINTK(("xenblk_map_system_sgl: MmMapIoSpace failed.\n"));
        }
        DPRINTK(DPRTL_MM,
                ("\tMmMapIoSpace addr = %p, paddr = %lx, len = %d\n",
                 srb_ext->sa[i],
                 (uint32_t)srb_ext->sys_sgl->List[i].PhysicalAddress.QuadPart,
                 srb_ext->sys_sgl->List[i].Length));
        }

    srb_ext->working_sgl = (STOR_SCATTER_GATHER_LIST *)
        srb_ext->working_sgl_buf;

    xenblk_build_alloced_sgl(srb_ext->va, srb->DataTransferLength,
        srb_ext->working_sgl);

    srb_ext->sgl = srb_ext->working_sgl;
}

static inline void
xenblk_unmap_system_address(void *sa[], STOR_SCATTER_GATHER_LIST *sys_sgl)
{
    uint32_t i;

#ifdef DBG
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > DISPATCH_LEVEL && irql < HIGH_LEVEL) {
        DPRINTK(DPRTL_ON,
                ("*** xenblk_unmap_system_address at irql %d ***\n", irql));
    }
#endif
    for (i = 0; i < sys_sgl->NumberOfElements; i++) {
        MmUnmapIoSpace(sa[i], sys_sgl->List[i].Length);
        sa[i] = NULL;
    }
}

static inline void
xenblk_unmap_system_addresses(struct blkfront_info *info)
{
    struct blk_mm_ring *mm;
    unsigned long idx;
    uint32_t i;

#ifdef DBG
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > DISPATCH_LEVEL && irql < HIGH_LEVEL) {
        DPRINTK(DPRTL_ON,
                ("*** xenblk_unmap_system_addresses at irql %d ***\n", irql));
    }
#endif
    mm = &info->mm;
    while (mm->cons != mm->prod) {
        idx = mm->cons & (BLK_RING_SIZE - 1);
        DPRINTK(DPRTL_MM, ("mm umap: va %p irql %d\n",
                           mm->ring[idx].vaddr, KeGetCurrentIrql()));
        for (i = 0; i < mm->ring[idx].mapped_elements; i++) {
            if (mm->ring[idx].mapped_addr[i]) {
                DPRINTK(DPRTL_MM,
                    ("mm umap: sa %p idx %d, i %d, len %d\n",
                     mm->ring[idx].mapped_addr[i],
                     idx, i, mm->ring[idx].mapped_len[i]));
                MmUnmapIoSpace(mm->ring[idx].mapped_addr[i],
                    mm->ring[idx].mapped_len[i]);
                mm->ring[idx].mapped_addr[i] = NULL;
            }
        }
        DPRINTK(DPRTL_MM, ("mm ExFreePool addr %p\n", mm->ring[idx].vaddr));
        if (mm->ring[idx].vaddr) {
            ExFreePool(mm->ring[idx].vaddr);
            XENBLK_DEC(info->xbdev->alloc_cnt_v);
            mm->ring[idx].vaddr = NULL;
        }
        mm->cons++;
    }
}

static inline void
xenblk_save_system_address(struct blkfront_info *info,
    xenblk_srb_extension *srb_ext)
{
    struct blk_mm_ring *mm;
    unsigned long idx;
    uint32_t i;

    mm = &info->mm;
    idx = mm->prod & (BLK_RING_SIZE - 1);
#ifdef DBG
    if (mm->ring[idx].vaddr != NULL) {
        PRINTK(("xenblk_save_system_address: vaddr is null %p\n",
            mm->ring[idx].vaddr));
    }
#endif
    mm->ring[idx].vaddr = srb_ext->va;
    mm->ring[idx].mapped_elements = srb_ext->sys_sgl->NumberOfElements;
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        mm->ring[idx].mapped_addr[i] = srb_ext->sa[i];
        mm->ring[idx].mapped_len[i] = srb_ext->sys_sgl->List[i].Length;
        DPRINTK(DPRTL_MM,
                ("mm save: idx %d, i %d, irql %d, len %lx, va %p, sa %p\n",
                idx, i, KeGetCurrentIrql(), mm->ring[idx].mapped_len[i],
                mm->ring[idx].vaddr,
                mm->ring[idx].mapped_addr[i]));
    }
    mm->prod++;
}

static inline unsigned long
xenblk_get_system_address(XENBLK_DEVICE_EXTENSION *dev_ext,
    SCSI_REQUEST_BLOCK *srb,
    void **sa)
{
    STOR_PHYSICAL_ADDRESS paddr;
    ULONG len;

    paddr = StorPortGetPhysicalAddress(dev_ext, srb, srb->DataBuffer, &len);
    *sa = StorPortGetVirtualAddress(dev_ext, paddr);
    DPRINTK(DPRTL_MM, ("\tsa = %p, PA = %x %x, DLen = %lx len = %lx.\n",
                       *sa,
                       (uint32_t)(paddr.QuadPart >> 32),
                       (uint32_t)paddr.QuadPart,
                       srb->DataTransferLength, len));
    return *sa ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static inline void *
xenblk_get_virtual_address(XENBLK_DEVICE_EXTENSION *dev_ext,
    SCSI_REQUEST_BLOCK *Srb,
    STOR_PHYSICAL_ADDRESS paddr)
{
    UNREFERENCED_PARAMETER(Srb);
    return StorPortGetVirtualAddress(dev_ext, paddr);
}

static inline xenblk_addr_t
xenblk_get_buffer_addr(SCSI_REQUEST_BLOCK *srb, xenblk_srb_extension *srb_ext)
{
    UNREFERENCED_PARAMETER(srb);
    UNREFERENCED_PARAMETER(srb_ext);

    return srb_ext->sgl->List[0].PhysicalAddress.QuadPart;
}

static inline unsigned long
xenblk_buffer_mfn(XENBLK_DEVICE_EXTENSION *dev_ext, SCSI_REQUEST_BLOCK *srb,
    xenblk_srb_extension *srb_ext, xenblk_addr_t addr)
{
    UNREFERENCED_PARAMETER(dev_ext);
    UNREFERENCED_PARAMETER(srb);
    UNREFERENCED_PARAMETER(srb_ext);
    return pfn_to_mfn((unsigned long)(addr >> PAGE_SHIFT));
}

#else
/***************************** SCSI MINIPORT *******************************/
typedef uintptr_t xenblk_addr_t;
#define xenblk_pause(_dev_ext, _pause_val)
#define xenblk_resume(dev_ext)
#define xenblk_request_complete ScsiPortNotification
#define xenblk_complete_request ScsiPortCompleteRequest
#define xenblk_notification ScsiPortNotification
#define xenblk_next_request ScsiPortNotification
#define xenblk_request_timer_call ScsiPortNotification
#define xenblk_complete_all_requests ScsiPortCompleteRequest
#define xenblk_get_physical_address ScsiPortGetPhysicalAddress
#define xenblk_get_device_base ScsiPortGetDeviceBase
#define xenblk_write_port_ulong(_dext, _port, _val)                     \
        ScsiPortWritePortUlong((PULONG)(_port), (_val))
#define xenblk_write_port_ushort(_dext, _port, _val)                    \
        ScsiPortWritePortUshort((PUSHORT)(_port), (_val))
#define xenblk_write_port_uchar(_dext, _port, _val)                     \
        ScsiPortWritePortUchar((PUCHAR)(_port), (_val))
#define xenblk_read_port_ulong(_dext, _port)                            \
        ScsiPortReadPortUlong((PULONG)(_port))
#define xenblk_read_port_ushort(_dext, _port)                           \
        ScsiPortReadPortUshort((PUSHORT)(_port))
#define xenblk_read_port_uchar(_dext, _port)                            \
        ScsiPortReadPortUchar((PUCHAR)(_port))



#define xenblk_acquire_spinlock(_dext, _plock, _ltype, _lctx, _plhndl)  \
    XenAcquireSpinLock((_plock), (_plhndl))
#define xenblk_release_spinlock(_dext, _plock, _lhndl)  \
    XenReleaseSpinLock((_plock), (_lhndl));

#define scsiport_acquire_spinlock(_plock, _plhndl)  \
    XenAcquireSpinLock((_plock), (_plhndl))
#define scsiport_release_spinlock(_plock, _lhndl)       \
    XenReleaseSpinLock((_plock), (_lhndl))

#define xenblk_unmap_system_address(_addr, _len)
#define StorPortEnablePassiveInitialization(_dev, _foo)
#define storport_acquire_spinlock(_dext, _ltype, _lctx, _plhndl)
#define storport_release_spinlock(_dext, _lhndl)

static inline void
xenblk_unmap_system_addresses(struct blkfront_info *info)
{
    struct blk_mm_ring *mm;

    mm = &info->mm;
    while (mm->cons != mm->prod) {
        ExFreePool(mm->ring[mm->cons & (BLK_RING_SIZE - 1)].vaddr);
        XENBLK_DEC(info->xbdev->alloc_cnt_v);
        mm->cons++;
    }
}

static inline void
xenblk_save_system_address(struct blkfront_info *info,
    xenblk_srb_extension *srb_ext)
{
    struct blk_mm_ring *mm;

    mm = &info->mm;
    mm->ring[mm->prod & (BLK_RING_SIZE - 1)].vaddr = srb_ext->va;
    mm->prod++;
}

static inline void
xenblk_map_system_sgl(SCSI_REQUEST_BLOCK *srb, MEMORY_CACHING_TYPE cache_type)
{
    xenblk_srb_extension *srb_ext;

    srb_ext = (xenblk_srb_extension *)srb->SrbExtension;
    srb_ext->sa[0] = srb->DataBuffer;

    srb_ext->working_sgl = (STOR_SCATTER_GATHER_LIST *)
        srb_ext->working_sgl_buf;

    xenblk_build_alloced_sgl(srb_ext->va, srb->DataTransferLength,
        srb_ext->working_sgl);

    srb_ext->sgl = srb_ext->working_sgl;
}

static inline void *
xenblk_get_virtual_address(XENBLK_DEVICE_EXTENSION *dev_ext,
    SCSI_REQUEST_BLOCK *Srb,
    STOR_PHYSICAL_ADDRESS paddr)
{
    return Srb->DataBuffer;
}

static inline STOR_SCATTER_GATHER_LIST *
xenblk_build_sgl(XENBLK_DEVICE_EXTENSION *dev_ext,
    SCSI_REQUEST_BLOCK *Srb)
{
    xenblk_srb_extension *srb_ext;
    ULONG len;

    srb_ext = (xenblk_srb_extension *)Srb->SrbExtension;
    srb_ext->scsi_sgl.NumberOfElements = 1;
    srb_ext->scsi_sgl.List[0].Length = Srb->DataTransferLength;
    srb_ext->scsi_sgl.List[0].PhysicalAddress =
        xenblk_get_physical_address(dev_ext, Srb, Srb->DataBuffer, &len);
    return &srb_ext->scsi_sgl;
}

static inline xenblk_addr_t
xenblk_get_buffer_addr(SCSI_REQUEST_BLOCK *srb, xenblk_srb_extension *srb_ext)
{
    if (srb_ext->va == NULL) {
        return (xenblk_addr_t)srb->DataBuffer;
    }
    return (xenblk_addr_t)srb_ext->va;
}

static inline unsigned long
scsi_virt_to_mfn(XENBLK_DEVICE_EXTENSION *dev_ext, SCSI_REQUEST_BLOCK *srb,
    void *vaddr, unsigned long *len)
{
    PHYSICAL_ADDRESS paddr;

    paddr = xenblk_get_physical_address(dev_ext, srb, vaddr, len);
    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("\tscsi_virt_to_mfn = %x\n", (uint32_t)paddr.QuadPart));
    return pfn_to_mfn((unsigned long)(paddr.QuadPart >> PAGE_SHIFT));
}

static inline unsigned long
xenblk_buffer_mfn(XENBLK_DEVICE_EXTENSION *dev_ext, SCSI_REQUEST_BLOCK *srb,
    xenblk_srb_extension *srb_ext, xenblk_addr_t addr)
{
    unsigned long buffer_mfn;
    unsigned long phys_len;

    if (srb_ext->va == NULL) {
        buffer_mfn = scsi_virt_to_mfn(
            dev_ext, srb, (void *)addr, &phys_len);
        if (buffer_mfn == 0) {
            CDPRINTK(DPRTL_COND, 0, 0, 1,
                ("\tscsi_virt_to_mfn returned 0\n"));
            buffer_mfn = virt_to_mfn(addr);
        }
    } else {
        buffer_mfn = virt_to_mfn(addr);
        if (buffer_mfn == 0) {
            CDPRINTK(DPRTL_COND, 0, 0, 1,
                ("\tvirt_to_mfn returned 0\n"));
            buffer_mfn = scsi_virt_to_mfn(
                dev_ext, NULL, (void *)addr, &phys_len);
        }
    }
    return buffer_mfn;
}


#endif


void XenBlkFreeResource(struct blkfront_info *info, uint32_t info_idx,
    XENBUS_RELEASE_ACTION action);
void XenBlkFreeAllResources(XENBLK_DEVICE_EXTENSION *dev_ext,
    XENBUS_RELEASE_ACTION action);
NTSTATUS blkfront_probe(struct blkfront_info *info);
NTSTATUS do_blkif_request(struct blkfront_info *info, SCSI_REQUEST_BLOCK *srb);
uint32_t blkif_complete_int(struct blkfront_info *info);
#ifdef XENBLK_STORPORT
KDEFERRED_ROUTINE blkif_int_dpc;
KDEFERRED_ROUTINE blkif_int;
#endif
void blkif_quiesce(struct blkfront_info *info);
void blkif_disconnect_backend(XENBLK_DEVICE_EXTENSION *dev_ext);
void blkif_free(struct blkfront_info *, int);
void XenBlkDebugDump(XENBLK_DEVICE_EXTENSION *dev_ext);

static inline void
xenblk_cp_from_sa(void *sa[], STOR_SCATTER_GATHER_LIST *sys_sgl, uint8_t *va)
{
    uint32_t i;

    for (i = 0; i < sys_sgl->NumberOfElements; i++) {
        RtlCopyMemory(va, sa[i], sys_sgl->List[i].Length);
        va += sys_sgl->List[i].Length;
    }
}

static inline void
xenblk_cp_to_sa(void *sa[], STOR_SCATTER_GATHER_LIST *sys_sgl, uint8_t *va)
{
    uint32_t i;

    for (i = 0; i < sys_sgl->NumberOfElements; i++) {
        DPRINTK(DPRTL_MM, ("   xenblk_cp_to_sa: sa[%d] %p, va %p, len %d\n",
                           i, sa[i], va, sys_sgl->List[i].Length));
        RtlCopyMemory(sa[i], va, sys_sgl->List[i].Length);
        va += sys_sgl->List[i].Length;
    }
}

#endif  /* _XENBLK_H_ */
