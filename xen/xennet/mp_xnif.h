/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2019-2020 SUSE LLC
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

#ifndef _MP_XNIF_H
#define _MP_XNIF_H

#define GRANT_INVALID_REF 0

#define RX_MIN_TARGET 8
#define RX_DFL_MIN_TARGET 64
#define RX_MAX_TARGET min(NET_RX_RING_SIZE, 256)
#define TX_MAX_TARGET min(NET_TX_RING_SIZE, 256)

#define TX_MAX_GRANT_REFS   TX_MAX_TARGET

typedef struct _vnif_xq_path_s {
    struct _VNIF_ADAPTER *adapter;
    struct netif_tx_front_ring tx_front_ring;
    struct netif_rx_front_ring rx_front_ring;
    grant_ref_t         gref_tx_head;
    grant_ref_t         gref_rx_head;
    UINT                tx_evtchn;
    UINT                rx_evtchn;
    UINT                path_id;
    KDPC                path_dpc;
    int                 tx_ring_ref;
    int                 rx_ring_ref;
    void                *tx_packets[NET_TX_RING_SIZE];
    xen_ulong_t         tx_id_alloc_head;
    grant_ref_t         grant_tx_ref[NET_TX_RING_SIZE];
} vnif_xq_path_t;

typedef struct _vnif_xen_s {
    struct xenbus_watch watch;
    struct xenbus_watch backend_watch;
    PUCHAR              otherend;
    UINT                copyall;
    domid_t             backend_id;
    UCHAR               feature_split_evtchn;
} vnif_xen_t;

#define VNIF_UNMASK unmask_evtchn

/* *************** mp_xutils.c ************ */
KDEFERRED_ROUTINE vnifx_interrupt_dpc;
KDEFERRED_ROUTINE vnifx_tx_interrupt_dpc;
KDEFERRED_ROUTINE vnifx_rx_interrupt_dpc;
void vnifx_notify_always_tx(struct _VNIF_ADAPTER *adapter, UINT path_id);
void vnifx_add_tx(struct _VNIF_ADAPTER *adapter, UINT path_id, struct _TCB *tcb,
    UINT send_len, UINT pkt_len, uint16_t flags, UINT *i);
void *vnifx_get_tx(struct _VNIF_ADAPTER *adapter, UINT path_id,
                   UINT *cons, UINT prod,
                   UINT cnt, UINT *len, UINT *status);
struct _RCB *vnifx_get_rx(struct _VNIF_ADAPTER *adapter, UINT path_id, UINT rp,
    UINT *i, INT *len);
void vnifx_ndis_queue_dpc(struct _VNIF_ADAPTER *adapter,
                          UINT rcv_qidx,
                          UINT max_nbls_to_indicate);

void VNIFX_FREE_SHARED_MEMORY(struct _VNIF_ADAPTER *adapter, void *va,
    PHYSICAL_ADDRESS pa, uint32_t len, NDIS_HANDLE hndl);
void VNIFX_ADD_RCB_TO_RING(struct _VNIF_ADAPTER *adapter, struct _RCB *rcb);
ULONG VNIFX_RX_RING_SIZE(struct _VNIF_ADAPTER *adapter);
ULONG VNIFX_TX_RING_SIZE(struct _VNIF_ADAPTER *adapter);
void VNIFX_GET_TX_REQ_PROD_PVT(struct _VNIF_ADAPTER *adapter, UINT path_id,
                               UINT *i);
void VNIFX_GET_RX_REQ_PROD(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *i);
void VNIFX_SET_TX_REQ_PROD_PVT(struct _VNIF_ADAPTER *adapter, UINT path_id,
                               UINT i);
void VNIFX_GET_TX_RSP_PROD(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *prod);
void VNIFX_GET_RX_RSP_PROD(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *prod);
void VNIFX_GET_TX_RSP_CONS(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *cons);
void VNIFX_GET_RX_RSP_CONS(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT *cons);
void VNIFX_SET_TX_RSP_CONS(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT cons);
void VNIFX_SET_RX_RSP_CONS(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           UINT cons);
void VNIFX_SET_TX_EVENT(struct _VNIF_ADAPTER *adapter, UINT path_id,
                        UINT prod);
void VNIFX_SET_RX_EVENT(struct _VNIF_ADAPTER *adapter, UINT path_id, UINT prod);
void VNIFX_RX_RING_KICK_ALWAYS(void *path);
void VNIFX_RX_NOTIFY(struct _VNIF_ADAPTER *adapter, UINT path_id,
                     UINT rcb_added_to_ring, UINT old);
UINT VRINGX_CAN_ADD_TX(struct _VNIF_ADAPTER *adapter, UINT path_id, UINT num);
UINT VNIFX_RING_FREE_REQUESTS(struct _VNIF_ADAPTER *adapter, UINT path_id);
UINT VNIFX_HAS_UNCONSUMED_RESPONSES(void *vq, UINT cons, UINT prod);
UINT VNIFX_IS_VALID_RCB(struct _RCB *rcb);
UINT VNIFX_DATA_VALID_CHECKSUM_VALID(struct _RCB *rcb);
UINT VNIFX_CHECKSUM_SUCCEEDED(struct _RCB *rcb);
UINT VNIFX_IS_PACKET_DATA_VALID(struct _RCB *rcb);
UINT VNIFX_PACKET_NEEDS_CHECKSUM(struct _RCB *rcb);
UINT MPX_RING_FULL(void *r);
UINT MPX_RING_EMPTY(void *r);
UINT VNIFX_RING_HAS_UNCONSUMED_RESPONSES(void *vq);
void VNIFX_RING_FINAL_CHECK_FOR_RESPONSES(void *vq, int *more_to_do);

NDIS_STATUS VNIFX_GetHWResources(struct _VNIF_ADAPTER *adapter);
NDIS_STATUS VNIFX_RegisterNdisInterrupt(struct _VNIF_ADAPTER *adapter);
void VNIFX_DeregisterHardwareResources(struct _VNIF_ADAPTER *adapter);

#ifdef NDIS60_MINIPORT
#else
void MPX_DriverEntryEx(NDIS_MINIPORT_CHARACTERISTICS *mp_char);
#endif



#ifdef DBG
void VNIFX_DUMP(struct _VNIF_ADAPTER *adapter, UINT path_id,
                PUCHAR str, uint32_t rxtx, uint32_t force);
void vnifx_rcv_stats_dump(struct _VNIF_ADAPTER *adapter, UINT path_id);
#endif

/* *************** mp_xinterface.c ************ */
void VNIFX_ALLOCATE_SHARED_MEMORY(struct _VNIF_ADAPTER *adapter, void **va,
    PHYSICAL_ADDRESS *pa, uint32_t len, NDIS_HANDLE hndl);
void vnifx_restart_interface(struct _VNIF_ADAPTER *adapter);
void VNIFX_FreeAdapterInterface(struct _VNIF_ADAPTER *adapter);
void VNIFX_CleanupInterface(struct _VNIF_ADAPTER *adapter, NDIS_STATUS status);
NDIS_STATUS VNIFX_FindAdapter(struct _VNIF_ADAPTER *adapter);
NDIS_STATUS VNIFX_SetupAdapterInterface(struct _VNIF_ADAPTER *adapter);
NDIS_STATUS VNIFX_QueryHWResources(struct _VNIF_ADAPTER *adapter,
    PNDIS_RESOURCE_LIST res_list);
uint32_t VNIFX_Quiesce(struct _VNIF_ADAPTER *adapter);
void VNIFX_CleanupRings(struct _VNIF_ADAPTER *adapter);
uint32_t VNIFX_DisconnectBackend(struct _VNIF_ADAPTER *adapter);
UINT vnifx_get_num_paths(struct _VNIF_ADAPTER *adapter);
NDIS_STATUS vnifx_setup_path_info_ex(struct _VNIF_ADAPTER *adapter);


#ifdef VNIF_TRACK_TX
void xennet_print_req(struct txlist_s *txlist);
void xennet_save_req(struct txlist_s *txlist, struct _TCB *tcb, uint32_t ridx);
void xennet_clear_req(struct txlist_s *txlist, TCB *tcb);
#else
#define xennet_print_req(_txlist)
#define xennet_save_req(_txlist, _tcb, _ridx)
#define xennet_clear_req(_txlist, _tcb)
#endif

#endif
