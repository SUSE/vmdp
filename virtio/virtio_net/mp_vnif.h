/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2019-2021 SUSE LLC
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

#ifndef _MP_VNIF_H
#define _MP_VNIF_H

#define VIRTIO_NET_CTRL_MQ 4
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET 0
#define VNIF_CTRL_BUF_SIZE 512
#define VNIF_CTRL_SG_ELEMENTS 4
#define VNIF_NET_OK     0
#define VNIF_NET_ERR    1

#define VNIF_RX_INT         0x01
#define VNIF_TX_INT         0x02
#define VNIF_CTRL_INT       0x04
#define VNIF_UNKNOWN_INT    0x08
#define VNIF_DISABLE_INT    0x80
#define VNIF_INVALID_INT    0xff
#define VNIF_VALID_INT      \
    (VNIF_RX_INT | VNIF_TX_INT | VNIF_CTRL_INT | VNIF_UNKNOWN_INT)

typedef struct _virtio_net_ctrl_hdr_s {
    uint8_t class_of_command;
    uint8_t cmd;
} virtio_net_ctrl_hdr_t __attribute__((packed));

typedef uint8_t virtio_net_ctrl_ack_t;

typedef struct _vnif_vq_path_s {
    virtio_queue_t      *rx;
    virtio_queue_t      *tx;
    LONG                interrupt_status;
    UINT                vq_idx;
    uint16_t            rx_msg;
    uint16_t            tx_msg;
} vnif_vq_path_t;

typedef struct _vnif_vq_common_path_s {
    virtio_queue_t      *q;
    LONG                interrupt_status;
    UINT                vq_idx;
    uint16_t            msg;
} vnif_vq_common_path_t;

typedef struct _vnif_virtio_s {
    virtio_device_t     vdev;
    virtio_bar_t        vbar[PCI_TYPE0_ADDRESSES];
    uint64_t            features;

#ifdef NDIS60_MINIPORT
    PIO_INTERRUPT_MESSAGE_INFO  msi_info_tbl;
    NDIS_HANDLE         interrupt_handle;
#else
    NDIS_MINIPORT_INTERRUPT interrupt;
#endif

    ULONG               interrupt_level;
    ULONG               interrupt_vector;
    KAFFINITY           interruopt_affinity;
    uint32_t            interrupt_flags;
    virtio_queue_t      *ctrl_q;
    PHYSICAL_ADDRESS    ctrl_buf_pa;
    PUCHAR              ctrl_buf;
    NDIS_SPIN_LOCK      ctrl_lock;
    uint16_t            ctrl_msg;
    BOOLEAN             b_control_queue;
    BOOLEAN             cached;             /* are alloc bufferes cached */
} vnif_virtio_t;


typedef struct _sync_ctx {
    struct _VNIF_ADAPTER *adapter;
    ULONG path_id;
    LONG int_status;
} sync_ctx_t;

/* *************** mp_vnic5/6.c ************ */
#ifndef NDIS60_MINIPORT
void MPV_DriverEntryEx(NDIS_MINIPORT_CHARACTERISTICS *mp_char);
NDIS_STATUS VNIFV_GetHWResources(struct _VNIF_ADAPTER *adapter);
#define vnifv_msi_config(_adapter) NDIS_STATUS_SUCCESS
#else
NDIS_STATUS vnifv_msi_config(struct _VNIF_ADAPTER *adapter);
#endif
NDIS_STATUS VNIFV_RegisterNdisInterrupt(struct _VNIF_ADAPTER *adapter);
void VNIFV_DeregisterHardwareResources(struct _VNIF_ADAPTER *adapter);
UINT vnifv_get_num_paths(struct _VNIF_ADAPTER *adapter);
NDIS_STATUS vnifv_setup_path_info_ex(struct _VNIF_ADAPTER *adapter);

/* *************** mp_vinterface.c ************ */
void VNIFV_ALLOCATE_SHARED_MEMORY(struct _VNIF_ADAPTER *adapter,
    void **va, PHYSICAL_ADDRESS *pa, uint32_t len, NDIS_HANDLE hndl);
void vnifv_restart_interface(struct _VNIF_ADAPTER *adapter);
void VNIFV_FreeAdapterInterface(struct _VNIF_ADAPTER *adapter);
void VNIFV_CleanupInterface(struct _VNIF_ADAPTER *adapter, NDIS_STATUS status);
NDIS_STATUS VNIFV_FindAdapter(struct _VNIF_ADAPTER *adapter);
BOOLEAN vnif_send_control_msg(struct _VNIF_ADAPTER *adapter,
                              UCHAR cls,
                              UCHAR cmd,
                              PVOID buffer1,
                              ULONG size1,
                              PVOID buffer2,
                              ULONG size2);
NDIS_STATUS VNIFV_SetupAdapterInterface(struct _VNIF_ADAPTER *adapter);
NDIS_STATUS VNIFV_QueryHWResources(struct _VNIF_ADAPTER *adapter,
    PNDIS_RESOURCE_LIST res_list);
uint32_t VNIFV_Quiesce(struct _VNIF_ADAPTER *adapter);
void VNIFV_CleanupRings(struct _VNIF_ADAPTER *adapter);
uint32_t VNIFV_DisconnectBackend(struct _VNIF_ADAPTER *adapter);
void vnifv_send_packet_filter(struct _VNIF_ADAPTER *adapter);
void vnifv_send_multicast_list(struct _VNIF_ADAPTER *adapter);

/* *************** mp_vutils.c ************ */
#ifdef NDIS60_MINIPORT
MINIPORT_DISABLE_INTERRUPT MPDisableInterrupt;
MINIPORT_ENABLE_INTERRUPT MPEnableInterrupt;
#else
void MPDisableInterrupt(IN PVOID MiniportInterruptContext);
void MPEnableInterrupt(IN PVOID MiniportInterruptContext);
#endif

void vnifv_notify_always_tx(struct _VNIF_ADAPTER *adapter, UINT path_id);
void vnifv_add_tx(struct _VNIF_ADAPTER *adapter, UINT path_id, struct _TCB *tcb,
    UINT send_len, UINT pkt_len, uint16_t flags, UINT *i);
void *vnifv_get_tx(struct _VNIF_ADAPTER *adapter, UINT path_id,
                   UINT *cons, UINT prod,
                   UINT cnt, UINT *len, UINT *status);
struct _RCB *vnifv_get_rx(struct _VNIF_ADAPTER *adapter, UINT path_id,
    UINT rp, UINT *i, INT *len);
void vnifv_ndis_queue_dpc(struct _VNIF_ADAPTER *adapter,
                          UINT rcv_qidx,
                          UINT max_nbls_to_indicate);
void vnif_virtio_dev_reset(struct _VNIF_ADAPTER *adapter);
void vnif_report_link_status(struct _VNIF_ADAPTER *adapter);

#ifdef DBG
void VNIFV_DUMP(struct _VNIF_ADAPTER *adapter, UINT path_id, PUCHAR str,
                uint32_t rxtx, uint32_t force);
void vnifv_rcv_stats_dump(struct _VNIF_ADAPTER *adapter, UINT path_id);
#endif

void VNIFV_FREE_SHARED_MEMORY(struct _VNIF_ADAPTER *adapter, void *va,
    PHYSICAL_ADDRESS pa, uint32_t len, NDIS_HANDLE hndl);

void VNIFV_ADD_RCB_TO_RING(struct _VNIF_ADAPTER *adapter, struct _RCB *rcb);
ULONG VNIFV_RX_RING_SIZE(struct _VNIF_ADAPTER *adapter);
ULONG VNIFV_TX_RING_SIZE(struct _VNIF_ADAPTER *adapter);
void VNIFV_GET_TX_REQ_PROD_PVT(struct _VNIF_ADAPTER *adapter, UINT path_id,
                               UINT *i);
void VNIFV_GET_RX_REQ_PROD(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *i);
void VNIFV_SET_TX_REQ_PROD_PVT(struct _VNIF_ADAPTER *adapter, UINT path_id,
                               UINT i);
void VNIFV_GET_TX_RSP_PROD(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *prod);
void VNIFV_GET_RX_RSP_PROD(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *prod);
void VNIFV_GET_TX_RSP_CONS(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *cons);
void VNIFV_GET_RX_RSP_CONS(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *cons);
void VNIFV_SET_TX_RSP_CONS(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT cons);
void VNIFV_SET_RX_RSP_CONS(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT cons);
void VNIFV_SET_TX_EVENT(struct _VNIF_ADAPTER *adapter, UINT path_id, UINT prod);
void VNIFV_SET_RX_EVENT(struct _VNIF_ADAPTER *adapter, UINT path_id, UINT prod);
void VNIFV_RX_RING_KICK_ALWAYS(void *path);
void VNIFV_RX_NOTIFY(struct _VNIF_ADAPTER *adapter, UINT path_id,
                     UINT rcb_added_to_ring, UINT old);
UINT VRINGV_CAN_ADD_TX(struct _VNIF_ADAPTER *adapter, UINT path_id, UINT num);
UINT VNIFV_RING_FREE_REQUESTS(struct _VNIF_ADAPTER *adapter, UINT path_id);
UINT VNIFV_HAS_UNCONSUMED_RESPONSES(void *vq, UINT cons, UINT prod);
UINT VNIFV_IS_VALID_RCB(struct _RCB *rcb);
UINT VNIFV_DATA_VALID_CHECKSUM_VALID(struct _RCB *rcb);
UINT VNIFV_CHECKSUM_SUCCEEDED(struct _RCB *rcb);
UINT VNIFV_IS_PACKET_DATA_VALID(struct _RCB *rcb);
UINT VNIFV_PACKET_NEEDS_CHECKSUM(struct _RCB *rcb);
UINT MPV_RING_FULL(void *vq);
UINT MPV_RING_EMPTY(void *vq);
UINT VNIFV_RING_HAS_UNCONSUMED_RESPONSES(void *vq);
void VNIFV_RING_FINAL_CHECK_FOR_RESPONSES(void *vq, int *more_to_do);
#endif
