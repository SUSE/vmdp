/*
 * Copyright (c) 2012-2017 Red Hat, Inc.
 * Copyright 2012-2021 SUSE LLC
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

#ifndef _VIRTIO_SCSI_H_
#define _VIRTIO_SCSI_H_

#include <ntddk.h>
#include <ntdddisk.h>
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
#include <virtio_dbg_print.h>
#include <virtio_pci.h>
#include <virtio_queue_ops.h>
#include <storport_reg.h>
#include <sp_defs.h>
#include "virtio_scsix.h"

#define VBIF_DESIGNATOR_STR "Virtio Block Device"
#define VIRTIO_SP_DRIVER_NAME "VSCSI"

#define VIRTIO_SCSI_QUEUE_CONTROL       0
#define VIRTIO_SCSI_QUEUE_EVENT         1
#define VIRTIO_SCSI_QUEUE_REQUEST       2
#define VIRTIO_SCSI_QUEUE_NUM_QUEUES    3
#define VIRTIO_SP_MSI_NUM_QUEUE_ADJUST  3
#define VIRTIO_SCSI_OFFSET_SRB_EXT    VIRTIO_SCSI_QUEUE_NUM_QUEUES
#define VIRTIO_SCSI_OFFSET_EVENT_NODE (VIRTIO_SCSI_OFFSET_SRB_EXT + 1)
#define VIRTIO_SCSI_OFFSET_VQ (VIRTIO_SCSI_OFFSET_EVENT_NODE + 1)
#ifdef NEED_VDEV
#define VIRTIO_SCSI_OFFSET_VDEV (VIRTIO_SCSI_OFFSET_VQ + 1)
#define VIRTIO_SCSI_OFFSET_MAX (VIRTIO_SCSI_OFFSET_VDEV + 1)
#else
#define VIRTIO_SCSI_OFFSET_MAX (VIRTIO_SCSI_OFFSET_VQ + 1)
#endif

#define VIRTIO_SCSI_DEFAULT_QUEU_NUM    128

#define VIRTIO_SCSI_MAX_Q_DEPTH 32

#define SECTOR_SIZE             512
#define MAX_PHYS_SEGMENTS       64
#ifdef IS_STORPORT
#define VIRTIO_MAX_SG           (3 + MAX_PHYS_SEGMENTS)
#else
#define MAX_PHYS_SEGMENTS_SCSI  64
#define VIRTIO_MAX_SG           (3 + MAX_PHYS_SEGMENTS_SCSI)
#endif
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

/* Feature Bits */
#define VIRTIO_SCSI_F_INOUT                    0
#define VIRTIO_SCSI_F_HOTPLUG                  1
#define VIRTIO_SCSI_F_CHANGE                   2

/* Response codes */
#define VIRTIO_SCSI_S_OK                       0
#define VIRTIO_SCSI_S_UNDERRUN                 1
#define VIRTIO_SCSI_S_ABORTED                  2
#define VIRTIO_SCSI_S_BAD_TARGET               3
#define VIRTIO_SCSI_S_RESET                    4
#define VIRTIO_SCSI_S_BUSY                     5
#define VIRTIO_SCSI_S_TRANSPORT_FAILURE        6
#define VIRTIO_SCSI_S_TARGET_FAILURE           7
#define VIRTIO_SCSI_S_NEXUS_FAILURE            8
#define VIRTIO_SCSI_S_FAILURE                  9
#define VIRTIO_SCSI_S_FUNCTION_SUCCEEDED       10
#define VIRTIO_SCSI_S_FUNCTION_REJECTED        11
#define VIRTIO_SCSI_S_INCORRECT_LUN            12

/* Controlq type codes.  */
#define VIRTIO_SCSI_T_TMF                      0
#define VIRTIO_SCSI_T_AN_QUERY                 1
#define VIRTIO_SCSI_T_AN_SUBSCRIBE             2

/* Valid TMF subtypes.  */
#define VIRTIO_SCSI_T_TMF_ABORT_TASK           0
#define VIRTIO_SCSI_T_TMF_ABORT_TASK_SET       1
#define VIRTIO_SCSI_T_TMF_CLEAR_ACA            2
#define VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET       3
#define VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET      4
#define VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET   5
#define VIRTIO_SCSI_T_TMF_QUERY_TASK           6
#define VIRTIO_SCSI_T_TMF_QUERY_TASK_SET       7

/* Events.  */
#define VIRTIO_SCSI_T_EVENTS_IN_QUEUE          8
#define VIRTIO_SCSI_T_EVENTS_MISSED            0x80000000
#define VIRTIO_SCSI_T_NO_EVENT                 0
#define VIRTIO_SCSI_T_TRANSPORT_RESET          1
#define VIRTIO_SCSI_T_ASYNC_NOTIFY             2
#define VIRTIO_SCSI_T_PARAM_CHANGE             3

/* Reasons of transport reset event */
#define VIRTIO_SCSI_EVT_RESET_HARD             0
#define VIRTIO_SCSI_EVT_RESET_RESCAN           1
#define VIRTIO_SCSI_EVT_RESET_REMOVED          2

#define VIRTIO_SCSI_S_SIMPLE                   0
#define VIRTIO_SCSI_S_ORDERED                  1
#define VIRTIO_SCSI_S_HEAD                     2
#define VIRTIO_SCSI_S_ACA                      3

#define SPC3_SCSI_SENSEQ_PARAMETERS_CHANGED         0x0
#define SPC3_SCSI_SENSEQ_MODE_PARAMETERS_CHANGED    0x01
#define SPC3_SCSI_SENSEQ_CAPACITY_DATA_HAS_CHANGED  0x09

#define VIRTIO_SCSI_UNDERRUN_MOD                100

#ifdef DBG
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

#define VIRTIO_SCSI_CDB_SIZE   32
#define VIRTIO_SCSI_SENSE_SIZE 96

#pragma pack(1)
typedef struct virtio_scsi_geometry_s {
        uint16_t cylinders;
        uint8_t heads;
        uint8_t sectors;
} virtio_scsi_geometry_t;

typedef struct virtio_scsi_config_s {
    uint32_t num_queues;
    uint32_t seg_max;
    uint32_t max_sectors;
    uint32_t cmd_per_lun;
    uint32_t event_info_size;
    uint32_t sense_size;
    uint32_t cdb_size;
    uint16_t max_channel;
    uint16_t max_target;
    uint32_t max_lun;
} virtio_scsi_config_t;

/* SCSI command request, followed by data-out */
typedef struct virtio_scsi_cmd_req_s {
    uint8_t lun[8];     /* Logical Unit Number */
    uint64_t tag;       /* Command identifier */
    uint8_t task_attr;  /* Task attribute */
    uint8_t prio;
    uint8_t crn;
    uint8_t cdb[VIRTIO_SCSI_CDB_SIZE];
} virtio_scsi_cmd_req_t;

/* Response, followed by sense data and data-in */
typedef struct virtio_scsi_cmd_resp_s {
    uint32_t sense_len;         /* Sense data length */
    uint32_t resid;             /* Residual bytes in data buffer */
    uint16_t status_qualifier;  /* Status qualifier */
    uint8_t status;             /* Command completion status */
    uint8_t response;           /* Response values */
    uint8_t sense[VIRTIO_SCSI_SENSE_SIZE];
} virtio_scsi_cmd_resp_t;

/* Task Management Request */
typedef struct virtio_scsi_ctrl_tmf_req_s {
    uint32_t type;
    uint32_t subtype;
    uint8_t lun[8];
    uint64_t tag;
} virtio_scsi_ctrl_tmf_req_t;

typedef struct virtio_scsi_ctrl_tmf_resp_s {
    uint8_t response;
} virtio_scsi_ctrl_tmf_resp_t;

/* Asynchronous notification query/subscription */
typedef struct virtio_scsi_ctrl_an_req_s {
    uint32_t type;
    uint8_t lun[8];
    uint32_t event_requested;
} virtio_scsi_ctrl_an_req_t;

typedef struct virtio_scsi_ctrl_an_resp_s {
    uint32_t event_actual;
    uint8_t response;
} virtio_scsi_ctrl_an_resp_t;

typedef struct virtio_scsi_event_s {
    uint32_t event;
    uint8_t lun[8];
    uint32_t reason;
} virtio_scsi_event_t;

/* Command queue element */
typedef struct virtio_scsi_cmd_s {
    void *sc;
    void *comp;
    union {
        virtio_scsi_cmd_req_t       cmd;
        virtio_scsi_ctrl_tmf_req_t  tmf;
        virtio_scsi_ctrl_an_req_t   an;
    } req;
    union {
        virtio_scsi_cmd_resp_t      cmd;
        virtio_scsi_ctrl_tmf_resp_t tmf;
        virtio_scsi_ctrl_an_resp_t  an;
        virtio_scsi_event_t         evt;
    } resp;
} virtio_scsi_cmd_t;

typedef struct virtio_scsi_event_node_s {
    PVOID                           adapter;
    virtio_scsi_event_t             event;
    virtio_buffer_descriptor_t      sg;
} virtio_scsi_event_node_t;
#pragma pack()

typedef struct _vscsi_srb_extension {
    virtio_scsi_cmd_t   vbr;
    ULONG               out;
    ULONG               in;
    ULONG               Xfer;
    ULONG               q_idx;
    virtio_buffer_descriptor_t sg[VIRTIO_MAX_SG];
    struct vring_desc vr_desc[VIRTIO_MAX_SG];
    LIST_ENTRY          list_entry;
#ifndef IS_STORPORT
    BOOLEAN             notify_next;
#endif
} vscsi_srb_ext_t, virtio_sp_srb_ext_t;

typedef struct {
    SCSI_REQUEST_BLOCK  Srb;
    vscsi_srb_ext_t     *SrbExtension;
} TMF_COMMAND, *PTMF_COMMAND;

typedef struct _vscsi_dev_ext {
    virtio_device_t vdev;
    ULONG_PTR       ring_va;
    ULONG_PTR       queue_va;

    /* Target specific */
    virtio_queue_t  **vq;
    void            **vr;
    uint64_t        features;
    ULONG           num_queues;
    ULONG           queue_depth;
    ULONG           msi_vectors;

    /* Common to the adapter */
    uint32_t        state;              /* Current device state */
    uint32_t        op_mode;            /* operation mode e.g. OP_MODE_NORMAL */
#ifdef USE_STORPORT_DPC
    KSPIN_LOCK      dev_lock;
    STOR_DPC        srb_complete_dpc;
#endif
#ifndef IS_STORPORT
    sp_sgl_t        scsi_sgl;
#endif
#ifdef DBG
    uint32_t        sp_locks;
    uint32_t        cpu_locks;
    uint32_t        alloc_cnt_i;
    uint32_t        alloc_cnt_s;
    uint32_t        alloc_cnt_v;
#endif
    BOOLEAN         msi_enabled;
    BOOLEAN         msix_uses_one_vector;
    BOOLEAN         indirect;
    BOOLEAN         b_use_packed_rings;


    virtio_scsi_event_node_t *event_node;
    virtio_scsi_config_t scsi_config;
    SCSI_REQUEST_BLOCK  tmf_cmd_srb;
    uint32_t        underruns;
    BOOLEAN         tmf_infly;
    BOOLEAN         inquiry_supported;
} virtio_sp_dev_ext_t;

#include <virtio_sp_common.h>

#ifdef IS_STORPORT
/***************************** STOR PORT *******************************/
#ifdef USE_STORPORT_DPC
#define virtio_sp_int_complete_cmd(_dev_ext, _reason, _msg_id, _cc)         \
{                                                                           \
    if ((_dev_ext)->op_mode == OP_MODE_NORMAL) {                            \
        StorPortIssueDpc((_dev_ext), &(_dev_ext)->srb_complete_dpc,         \
           (void *)(_reason), (void *)(_msg_id));                           \
        (_cc) = TRUE;                                                       \
    }                                                                       \
    else                                                                    \
        (_cc) = virtio_sp_complete_cmd((_dev_ext), (_reason), (_msg_id));   \
}
#else
#define virtio_sp_int_complete_cmd(_dev_ext, _reason, _msg_id, _cc)         \
    (_cc) = virtio_sp_complete_cmd((_dev_ext), (_reason), (_msg_id))
#endif

#else
/***************************** SCSI MINIPORT *******************************/
#define virtio_sp_int_complete_cmd(_dev_ext, _reason, _msg_id, _cc)         \
    (_cc) = virtio_sp_complete_cmd((_dev_ext), (_reason), (_msg_id))


#endif

void virtio_scsi_get_scsi_config(virtio_sp_dev_ext_t *dev_ext);
void virtio_scsi_dump_config_info(virtio_sp_dev_ext_t *dev_ext,
    PPORT_CONFIGURATION_INFORMATION config_info);
void virtio_scsi_inquery_data(PSCSI_REQUEST_BLOCK srb);
UCHAR virtio_scsi_mode_sense(virtio_sp_dev_ext_t *dev_ext,
    PSCSI_REQUEST_BLOCK srb);
uint64_t virtio_scsi_get_lba(virtio_sp_dev_ext_t *dev_ext,
    PSCSI_REQUEST_BLOCK srb);

BOOLEAN virtio_scsi_add_event(virtio_sp_dev_ext_t *dev_ext,
    virtio_scsi_event_node_t *event_node);
BOOLEAN virtio_scsi_prime_event_queue(virtio_sp_dev_ext_t *dev_ext,
    virtio_scsi_event_node_t *event_node);
void virtio_scsi_transport_reset(virtio_sp_dev_ext_t *dev_ext,
    virtio_scsi_event_t *evt);
void virtio_scsi_param_change(virtio_sp_dev_ext_t *dev_ext,
    virtio_scsi_event_t *evt);

#endif  /* _VIRTIO_SCSI_H_ */
