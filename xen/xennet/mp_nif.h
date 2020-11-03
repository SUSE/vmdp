/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2010-2012 Novell, Inc.
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
#include "xennet_ver.h"
#include <win_vxprintk.h>
#include <mp_xnif.h>

#define XENNET_MINIPORT 1

#define VNIF_INTERFACE_TYPE     NdisInterfaceInternal
#define VNIF_DRIVER_NAME        "New Xennet"
#define VNIF_VENDOR_DESC        "Xen"
#define VNIF_VENDOR_ID          0x0000163E

typedef struct _vnif_virtio_s {
    UINT                reserved;
} vnif_virtio_t, vnif_vq_path_t;

#define VNIF_FREE_SHARED_MEMORY VNIFX_FREE_SHARED_MEMORY

#define VNIF_ADD_RCB_TO_RING VNIFX_ADD_RCB_TO_RING

#define VNIF_NOTIFY_REMOTE VNIFX_NOTIFY_REMOTE

#define VNIFRegisterNdisInterrupt VNIFX_RegisterNdisInterrupt

#define VNIFDeregisterHardwareResources VNIFX_DeregisterHardwareResources

#define MP_RING_FULL MPX_RING_FULL

#define MP_RING_EMPTY MPX_RING_EMPTY

#define VNIF_RX_RING_SIZE VNIFX_RX_RING_SIZE

#define VNIF_TX_RING_SIZE VNIFX_TX_RING_SIZE

#define VNIF_GET_TX_REQ_PROD_PVT VNIFX_GET_TX_REQ_PROD_PVT

#define VNIF_GET_RX_REQ_PROD VNIFX_GET_RX_REQ_PROD

#define VNIF_SET_TX_REQ_PROD_PVT VNIFX_SET_TX_REQ_PROD_PVT

#define VNIF_GET_TX_RSP_PROD VNIFX_GET_TX_RSP_PROD

#define VNIF_GET_RX_RSP_PROD VNIFX_GET_RX_RSP_PROD

#define VNIF_GET_TX_RSP_CONS VNIFX_GET_TX_RSP_CONS

#define VNIF_GET_RX_RSP_CONS VNIFX_GET_RX_RSP_CONS

#define VNIF_SET_TX_RSP_CONS VNIFX_SET_TX_RSP_CONS

#define VNIF_SET_RX_RSP_CONS VNIFX_SET_RX_RSP_CONS

#define VNIF_SET_TX_EVENT VNIFX_SET_TX_EVENT

#define VNIF_SET_RX_EVENT VNIFX_SET_RX_EVENT

#define VNIF_RX_NOTIFY VNIFX_RX_NOTIFY

#define VNIF_RING_FINAL_CHECK_FOR_RESPONSES VNIFX_RING_FINAL_CHECK_FOR_RESPONSES

#define VNIF_RING_HAS_UNCONSUMED_RESPONSES VNIFX_RING_HAS_UNCONSUMED_RESPONSES

#define VNIF_RX_RING_KICK_ALWAYS VNIFX_RX_RING_KICK_ALWAYS

#define VNIF_IS_VALID_RCB VNIFX_IS_VALID_RCB

#define VNIF_HAS_UNCONSUMED_RESPONSES VNIFX_HAS_UNCONSUMED_RESPONSES

#define VNIF_DATA_VALID_CHECKSUM_VALID VNIFX_DATA_VALID_CHECKSUM_VALID

#define VNIF_CHECKSUM_SUCCEEDED VNIFX_CHECKSUM_SUCCEEDED

#define VNIF_IS_PACKET_DATA_VALID VNIFX_IS_PACKET_DATA_VALID

#define VNIF_PACKET_NEEDS_CHECKSUM VNIFX_PACKET_NEEDS_CHECKSUM

#define VRING_CAN_ADD_TX VRINGX_CAN_ADD_TX

#define VNIF_RING_FREE_REQUESTS VNIFX_RING_FREE_REQUESTS

#define vnif_notify_always_tx vnifx_notify_always_tx

#define vnif_add_tx vnifx_add_tx

#define vnif_get_tx vnifx_get_tx

#define vnif_get_rx vnifx_get_rx

#define vnif_ndis_queue_dpc vnifx_ndis_queue_dpc

#define vnif_restart_interface vnifx_restart_interface

#define VNIFFreeAdapterInterface VNIFX_FreeAdapterInterface

#define VNIFCleanupInterface VNIFX_CleanupInterface

#define VNIFFindAdapter VNIFX_FindAdapter

#define VNIFSetupAdapterInterface VNIFX_SetupAdapterInterface

#define VNIFQueryHWResources VNIFX_QueryHWResources

#define VNIFQuiesce VNIFX_Quiesce

#define VNIFCleanupRings VNIFX_CleanupRings

#define VNIFDisconnectBackend VNIFX_DisconnectBackend

#define VNIF_GET_NUM_PATHS vnifx_get_num_paths

#define VNIF_SETUP_PATH_INFO_EX vnifx_setup_path_info_ex

#ifndef NDIS60_MINIPORT
#define DriverEntryEx MPX_DriverEntryEx
#endif

#define VNIFGetHWResources VNIFX_GetHWResources

#ifdef DBG
#define vnif_rcv_stats_dump vnifx_rcv_stats_dump
#define VNIF_DUMP VNIFX_DUMP
#else
#define VNIF_DUMP(adapter, path_id, str, rxtx, force)
#define vnif_rcv_stats_dump(_adapter, _path_id)
#endif


#endif
