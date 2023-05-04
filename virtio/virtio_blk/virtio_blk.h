/*
 * Copyright (c) 2008-2017 Red Hat, Inc.
 * Copyright 2011-2012 Novell, Inc.
 * Copyright 2012-2023 SUSE LLC
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

#ifndef _VIRTIO_BLK_H_
#define _VIRTIO_BLK_H_

#include <ntddk.h>
#include <ntdddisk.h>
#include <limits.h>
#ifdef IS_STORPORT
#include <storport.h>
#else
#include <scsi.h>
#endif

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <win_version.h>
#include <win_stdint.h>
#include <win_mmio_map.h>
#include <virtio_dbg_print.h>
#include <virtio_pci.h>
#include <virtio_queue_ops.h>
#include <storport_reg.h>
#include <sp_io_control.h>
#define VBIF_DESIGNATOR_STR "Virtio Block Device"
#define VIRTIO_SP_DRIVER_NAME "VBLK"
#define VIRTIO_SP_POOL_TAG         ((ULONG)'KLBV')

#define VIRTIO_SCSI_QUEUE_REQUEST 0
#define VIRTIO_SP_MSI_NUM_QUEUE_ADJUST 1

/* Feature bits */
#define VIRTIO_BLK_F_BARRIER    0       /* Does host support barriers? */
#define VIRTIO_BLK_F_SIZE_MAX   1       /* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX    2       /* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY   4       /* Legacy geometry available  */
#define VIRTIO_BLK_F_RO         5       /* Disk is read-only */
#define VIRTIO_BLK_F_BLK_SIZE   6       /* Block size of disk is available*/
#define VIRTIO_BLK_F_SCSI       7       /* Supports scsi command passthru */
#define VIRTIO_BLK_F_FLUSH      9       /* Flush command supported */
#define VIRTIO_BLK_F_TOPOLOGY   10      /* Topology information is available */
#define VIRTIO_BLK_F_CONFIG_WCE 11      /* Writeback mode available in config */
#define VIRTIO_BLK_F_MQ         12      /* support more than one vq */
#define VIRTIO_BLK_F_DISCARD    13      /* DISCARD is supported */
#define VIRTIO_BLK_F_WRITE_ZEROES 14    /* WRITE ZEROES is supported */

#define VIRTIO_BLK_MAX_DISCARD  16
#define VIRTIO_BLK_SERIAL_STRLEN 20

/* These two define direction. */
#define VIRTIO_BLK_T_IN         0
#define VIRTIO_BLK_T_OUT        1

#define VIRTIO_BLK_T_SCSI_CMD   2
#define VIRTIO_BLK_T_FLUSH      4
#define VIRTIO_BLK_T_GET_ID     8
#define VIRTIO_BLK_T_DISCARD    11
#define VIRTIO_BLK_T_WRITE_ZEROES   13

#define VIRTIO_BLK_S_OK         0
#define VIRTIO_BLK_S_IOERR      1
#define VIRTIO_BLK_S_UNSUPP     2

#define SECTOR_SIZE             512
#define SECTOR_SHIFT            9
#define MAX_DISCARD_SEGMENTS    256u

#ifdef IS_STORPORT
#define MAX_PHYS_SEGMENTS       254
#else
#define MAX_PHYS_SEGMENTS       64
#endif
#define DEFAULT_MAX_PHYS_SEGS   64
#define VIRTIO_MAX_SG           (3 + MAX_PHYS_SEGMENTS)

#define MIN_DISCARD_SECTOR_ALIGNMENT    8

#include <sp_defs.h>

#define VBIF_IN_FLY_THRESHOLD   3

#define IO_PORT_LENGTH          0x40

#define OP_MODE_NORMAL          0x01
#define OP_MODE_HIBERNATE       0x02
#define OP_MODE_CRASHDUMP       0x04
#define OP_MODE_SHUTTING_DOWN   0x08
#define OP_MODE_DISCONNECTED    0x10
#define OP_MODE_RESTARTING      0x20
#define OP_MODE_FLUSH           0x40
#define OP_MODE_RESET           0x80
#define OP_MODE_POLLING         0x100

#define CRASHDUMP_LEVEL         IPI_LEVEL

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

#define VBIF_SET_FLAG(_F, _V)       InterlockedOr(&(_F), (_V))
#define VBIF_CLEAR_FLAG(_F, _V)     InterlockedAnd(&(_F), ~(_V))
#define VBIF_ZERO_VALUE(_V)         _V = 0
#define VBIF_SET_VALUE(_V, _S)      _V = _S
#define VBIF_INC(_V)                InterlockedIncrement(&(_V))
#define VBIF_DEC(_V)                InterlockedDecrement(&(_V))

#define VBIF_DBG_TRACK_SRBS 1

#else
#define VBIF_SET_FLAG(_F, _V)
#define VBIF_CLEAR_FLAG(_F, _V)
#define VBIF_SET_VALUE(_V, _S)
#define VBIF_ZERO_VALUE(_V)
#define VBIF_INC(_V)
#define VBIF_DEC(_V)
#endif


#pragma pack(1)
typedef struct virtio_blk_geometry_s {
        uint16_t cylinders;
        uint8_t heads;
        uint8_t sectors;
} virtio_blk_geometry_t;

typedef struct vbif_info_s {
    uint64_t capacity;              /* capacity (in 512-byte sectors). */
    uint32_t size_max;              /* max seg sz (if VIRTIO_BLK_F_SIZE_MAX) */
    uint32_t seg_max;               /* max segs (if VIRTIO_BLK_F_SEG_MAX) */
    virtio_blk_geometry_t geometry; /* (if VIRTIO_BLK_F_GEOMETRY) */
    uint32_t blk_size;              /* (if VIRTIO_BLK_F_BLK_SIZE) */
    uint8_t  physical_block_exp;
    uint8_t  alignment_offset;
    uint16_t min_io_size;
    uint32_t opt_io_size;
    uint8_t wce;
    uint8_t unused;
    uint16_t num_queues;            /* Available when VIRTIO_BLK_F_MQ is set */

    /* The next 3 entries are guarded by VIRTIO_BLK_F_DISCARD */
    uint32_t max_discard_sectors;       /* Max discard sectors (in 512-byte */
                                        /* sectors) for one segment. */
    uint32_t max_discard_seg;           /* Max segs in a discard command */
    uint32_t discard_sector_alignment;  /* Discard commands must be aligned */
                                        /* to this number of sectors. */

    /* The next 3 entries are guarded by VIRTIO_BLK_F_WRITE_ZEROES */
    uint32_t max_write_zeroes_sectors;  /* Max write zero sectors (in 512 */
                                        /* byte sectors) in one segment. */
    uint32_t max_write_zeroes_seg;  /* Max segs in a write zeroes command */
    uint8_t write_zeroes_may_unmap; /* Set if a VIRTIO_BLK_T_WRITE_ZEROES */
                                    /* request may result in the deallocation */
                                    /* of one or more of the sectors. */

    uint8_t unused1[3];
} vbif_info_t;
#pragma pack()

typedef struct virtio_blk_outhdr_s {
    uint32_t type;      /* VIRTIO_BLK_T IN or OUT */
    uint32_t ioprio;    /* io priority. */
    uint64_t sector;    /* sector offset of request */
} virtio_blk_outhdr_t;

#if (NTDDI_VERSION >= NTDDI_WIN8)
/* Discard/write zeroes range for each request. */
typedef struct virtio_blk_discard_write_zeroes_s {
    uint64_t sector;        /* discard/write zeroes start sector */
    uint32_t num_sectors;   /* number of discard/write zeroes sectors */
    uint32_t flags;         /* flags for this range */
} virtio_blk_discard_write_zeroes_t;
#endif

typedef struct virtio_blk_req_s {
    LIST_ENTRY list_entry;
    virtio_blk_outhdr_t out_hdr;
    void *req;
    uint8_t status;
} virtio_blk_req_t;

typedef struct _vbif_srb_extension {
    virtio_blk_req_t vbr;
    ULONG            out;
    ULONG            in;
    virtio_buffer_descriptor_t sg[VIRTIO_MAX_SG];
    struct vring_desc vr_desc[VIRTIO_MAX_SG];
    BOOLEAN         force_unit_access;
#ifndef IS_STORPORT
    BOOLEAN         notify_next;
#endif
} vbif_srb_ext_t, virtio_sp_srb_ext_t;

typedef struct _virtio_sp_dev_ext {
    virtio_device_t vdev;
    ULONG_PTR       ring_va;
    ULONG_PTR       queue_va;

    /* Target specific */
    virtio_queue_t  **vq;
    void            **vr;
    uint64_t        features;
    ULONG           num_queues;
    uint32_t        queue_depth;
    ULONG           msi_vectors;

    UCHAR           pci_cfg_buf[sizeof(PCI_COMMON_CONFIG)];
    virtio_bar_t    bar[PCI_TYPE0_ADDRESSES];

    /* Common to the adapter */
    uint32_t        state;              /* Current device state */
    uint32_t        op_mode;            /* operation mode e.g. OP_MODE_NORMAL */
#ifdef USE_STORPORT_DPC
    STOR_DPC        *srb_complete_dpc;
    PGROUP_AFFINITY pmsg_affinity;
    ULONG           perf_flags;
#else
    sp_sgl_t        scsi_sgl;
#endif
    ULONG           num_affinity;
    KSPIN_LOCK      *requestq_lock;
    BOOLEAN         msi_enabled;
    BOOLEAN         msix_uses_one_vector;
    BOOLEAN         indirect;
    BOOLEAN         b_use_packed_rings;

    vbif_info_t     info;
    uint32_t        num_phys_breaks;
    uint32_t        max_xfer_len;
    CHAR            sn[VIRTIO_BLK_SERIAL_STRLEN];
#if (NTDDI_VERSION >= NTDDI_WIN8)
    virtio_blk_discard_write_zeroes_t blk_discard[VIRTIO_BLK_MAX_DISCARD];
#endif
#ifdef DBG
    uint32_t        sp_locks;
    uint32_t        cpu_locks;
    uint32_t        alloc_cnt_i;
    uint32_t        alloc_cnt_s;
    uint32_t        alloc_cnt_v;
#endif
} virtio_sp_dev_ext_t;

#include <virtio_sp_common.h>

BOOLEAN virtio_blk_do_poll(virtio_sp_dev_ext_t *dev_ext, void *no_used);
void virtio_blk_get_blk_config(virtio_sp_dev_ext_t *dev_ext);
void virtio_blk_dump_config_info(virtio_sp_dev_ext_t *dev_ext,
    PPORT_CONFIGURATION_INFORMATION config_info);
void virtio_blk_inquery_data(virtio_sp_dev_ext_t *dev_ext,
    PSCSI_REQUEST_BLOCK srb);
UCHAR virtio_blk_mode_sense(virtio_sp_dev_ext_t *dev_ext,
    PSCSI_REQUEST_BLOCK srb);
uint64_t virtio_blk_get_lba(virtio_sp_dev_ext_t *dev_ext,
    PSCSI_REQUEST_BLOCK srb);
BOOLEAN virtio_blk_do_flush(virtio_sp_dev_ext_t *dev_ext,
    SCSI_REQUEST_BLOCK *srb);
BOOLEAN virtio_blk_do_sn(virtio_sp_dev_ext_t *dev_ext,
    SCSI_REQUEST_BLOCK *srb);
void virtio_blk_fill_sn(virtio_sp_dev_ext_t *dev_ext,
    SCSI_REQUEST_BLOCK *srb);
#if (NTDDI_VERSION >= NTDDI_WIN8)
BOOLEAN virtio_blk_do_unmap(virtio_sp_dev_ext_t *dev_ext,
    SCSI_REQUEST_BLOCK *srb);
#endif

#endif  /* _VIRTIO_BLK_H_ */
