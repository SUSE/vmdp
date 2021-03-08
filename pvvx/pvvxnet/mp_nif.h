/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2010-2012 Novell, Inc.
 * Copyright 2012-2021 SUSE LLC
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

#ifndef _MP_NIF_H
#define _MP_NIF_H

#define __XEN_INTERFACE_VERSION__ 0x00030202
#include <asm/win_compat.h>
#include <xen/public/win_xen.h>
#include <xen/public/grant_table.h>
#include <xen/public/io/netif.h>
#include <win_maddr.h>
#include <win_gnttab.h>
#include <win_xenbus.h>
#include <win_evtchn.h>
#include <virtio_dbg_print.h>
#include <virtio_pci.h>
#include <virtio_net.h>
#include <win_xenbus_apis.h>
#include <win_pvvx.h>
#include <mp_xnif.h>
#include <mp_vnif.h>
#include "pvvxnet_ver.h"

extern NDIS_INTERFACE_TYPE VNIF_INTERFACE_TYPE;
extern char VNIF_DRIVER_NAME[12];
extern char VNIF_VENDOR_DESC[4];
extern ULONG VNIF_VENDOR_ID;

/* Indirect function pointers from mp_vutils and mp_xutils. */
extern void (*vnif_notify_always_tx)(struct _VNIF_ADAPTER *adapter,
                                     UINT path_id);
extern void (*vnif_add_tx)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                           struct _TCB *tcb, UINT send_len,
                           UINT pkt_len, uint16_t flags, UINT *prod);
extern void *(*vnif_get_tx)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                            UINT *cons, UINT prod,
                            UINT cnt, UINT *len, UINT *status);
extern struct _RCB *(*vnif_get_rx)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                   UINT prod, UINT *_cons, INT *len);

/* Indirect function pointers from mp_vinterface and mp_xinterface. */
extern void (*VNIFFreeAdapterInterface)(struct _VNIF_ADAPTER *adapter);
extern void (*VNIFCleanupInterface)(struct _VNIF_ADAPTER *adapter,
                                    NDIS_STATUS status);
extern NDIS_STATUS (*VNIFFindAdapter)(struct _VNIF_ADAPTER *adapter);
extern NDIS_STATUS (*VNIFSetupAdapterInterface)(struct _VNIF_ADAPTER *adapter);
extern NDIS_STATUS (*VNIFQueryHWResources)(struct _VNIF_ADAPTER *adapter,
    PNDIS_RESOURCE_LIST res_list);
extern uint32_t (*VNIFQuiesce)(struct _VNIF_ADAPTER *adapter);
extern void (*VNIFCleanupRings)(struct _VNIF_ADAPTER *adapter);
extern uint32_t (*VNIFDisconnectBackend)(struct _VNIF_ADAPTER *adapter);
extern void (*vnif_restart_interface)(struct _VNIF_ADAPTER *adapter);

/* Indirect function pointers from mp_vnif and mp_xnif */
extern void (*VNIF_FREE_SHARED_MEMORY)(struct _VNIF_ADAPTER *adapter, void *va,
    PHYSICAL_ADDRESS pa, uint32_t len, NDIS_HANDLE _hndl);
extern void (*VNIF_ADD_RCB_TO_RING) (struct _VNIF_ADAPTER *adapter,
    struct _RCB *rcb);
extern ULONG (*VNIF_RX_RING_SIZE)(struct _VNIF_ADAPTER *adapter);
extern ULONG (*VNIF_TX_RING_SIZE)(struct _VNIF_ADAPTER *adapter);
extern void (*VNIF_GET_TX_REQ_PROD_PVT)(struct _VNIF_ADAPTER *adapter,
                                        UINT path_id, UINT *i);
extern void (*VNIF_GET_RX_REQ_PROD)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                    UINT *i);

/* Indirect function pointers from mp_nif */
extern void (*VNIF_SET_TX_REQ_PROD_PVT)(struct _VNIF_ADAPTER *adapter,
                                        UINT path_id, UINT i);
extern void (*VNIF_GET_TX_RSP_PROD)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                    UINT *prod);
extern void (*VNIF_GET_RX_RSP_PROD)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                    UINT *prod);
extern void (*VNIF_GET_TX_RSP_CONS)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                    UINT *cons);
extern void (*VNIF_GET_RX_RSP_CONS)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                    UINT *cons);
extern void (*VNIF_SET_TX_RSP_CONS)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                    UINT cons);
extern void (*VNIF_SET_RX_RSP_CONS)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                    UINT cons);
extern void (*VNIF_SET_TX_EVENT)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                 UINT prod);
extern void (*VNIF_SET_RX_EVENT)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                 UINT prod);
extern void (*VNIF_RX_RING_KICK_ALWAYS)(void *vq);
extern void (*VNIF_RX_NOTIFY)(struct _VNIF_ADAPTER *adapter, UINT path_id,
    UINT rcb_added_to_ring, UINT old);
extern UINT (*VRING_CAN_ADD_TX)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                                UINT num);
extern UINT (*VNIF_RING_FREE_REQUESTS)(struct _VNIF_ADAPTER *adapter,
                                       UINT path_id);
extern UINT (*VNIF_HAS_UNCONSUMED_RESPONSES)(void *vq, UINT cons, UINT prod);
extern UINT (*VNIF_IS_VALID_RCB)(struct _RCB *rcb);
extern UINT (*VNIF_DATA_VALID_CHECKSUM_VALID)(struct _RCB *rcb);
extern UINT (*VNIF_CHECKSUM_SUCCEEDED)(struct _RCB *rcb);
extern UINT (*VNIF_IS_PACKET_DATA_VALID)(struct _RCB *rcb);
extern UINT (*VNIF_PACKET_NEEDS_CHECKSUM)(struct _RCB *rcb);
extern UINT (*MP_RING_FULL)(void *r);
extern UINT (*MP_RING_EMPTY)(void *r);
extern UINT (*VNIF_RING_HAS_UNCONSUMED_RESPONSES)(void *vq);
extern void (*VNIF_RING_FINAL_CHECK_FOR_RESPONSES)(void *vq, int *more_to_do);
extern void (*vnif_ndis_queue_dpc)(struct _VNIF_ADAPTER *adapter,
                                   UINT rcv_qidx,
                                   UINT max_nbls_to_indicate);
extern void (*vnif_send_packet_filter)(struct _VNIF_ADAPTER *adapter);
extern void (*vnif_send_multicast_list )(struct _VNIF_ADAPTER *adapter);

#ifdef NDIS60_MINIPORT
#else
extern void (*DriverEntryEx)(NDIS_MINIPORT_CHARACTERISTICS *mp_char);
extern NDIS_STATUS (*VNIFGetHWResources)(struct _VNIF_ADAPTER *adapter);
#endif

extern NDIS_STATUS (*VNIFQueryHWResources)(struct _VNIF_ADAPTER *adapter,
    PNDIS_RESOURCE_LIST res_list);
extern NDIS_STATUS (*VNIFRegisterNdisInterrupt)(struct _VNIF_ADAPTER *adapter);
extern void (*VNIFDeregisterHardwareResources)(struct _VNIF_ADAPTER *adapter);
extern UINT (*VNIF_GET_NUM_PATHS)(struct _VNIF_ADAPTER *adapter);
extern NDIS_STATUS (*VNIF_SETUP_PATH_INFO_EX)(struct _VNIF_ADAPTER *adapter);
#ifdef DBG
extern void (*VNIF_DUMP)(struct _VNIF_ADAPTER *adapter, UINT path_id,
                         PUCHAR str, uint32_t rxtx, uint32_t force);
extern void (*vnif_rcv_stats_dump)(struct _VNIF_ADAPTER *adapter, UINT path_id);
#else
#define VNIF_DUMP(adapter, path_id, str, rxtx, force)
#define vnif_rcv_stats_dump(_adapter, _path_id)
#endif

#endif
