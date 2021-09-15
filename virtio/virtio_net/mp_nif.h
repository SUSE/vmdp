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

#include <virtio_dbg_print.h>
#include <win_maddr.h>
#include <virtio_pci.h>
#include <virtio_net.h>
#include <virtio_utils.h>
#include <mp_vnif.h>
#include "virtio_net_ver.h"

#define VNIF_INTERFACE_TYPE     NdisInterfacePci
#define VNIF_DRIVER_NAME        "Virtio_net"
#define VNIF_VENDOR_DESC        "KVM"
#define VNIF_VENDOR_ID          0x00525400

typedef struct _vnif_xen_s {
    UINT                reserved;
} vnif_xen_t, vnif_xq_path_t;

#define NETIF_RSP_DROPPED         -2
#define NETIF_RSP_ERROR           -1
#define NETIF_RSP_OKAY             0
/* No response: used for auxiliary requests (e.g., netif_tx_extra). */
#define NETIF_RSP_NULL             1

/* Protocol checksum field is blank in the packet (hardware offload)? */
#define _NETTXF_csum_blank     (0)
#define  NETTXF_csum_blank     (1U << _NETTXF_csum_blank)

/* Packet data has been validated against protocol checksum. */
#define _NETTXF_data_validated (1)
#define  NETTXF_data_validated (1U << _NETTXF_data_validated)

#define VNIF_FREE_SHARED_MEMORY VNIFV_FREE_SHARED_MEMORY

#define VNIF_RX_RING_SIZE VNIFV_RX_RING_SIZE

#define VNIF_TX_RING_SIZE VNIFV_TX_RING_SIZE

#define VNIF_GET_TX_REQ_PROD_PVT VNIFV_GET_TX_REQ_PROD_PVT

#define VNIF_GET_RX_REQ_PROD VNIFV_GET_RX_REQ_PROD

#define VNIF_SET_TX_REQ_PROD_PVT VNIFV_SET_TX_REQ_PROD_PVT

#define VNIF_GET_TX_RSP_PROD VNIFV_GET_TX_RSP_PROD

#define VNIF_GET_RX_RSP_PROD VNIFV_GET_RX_RSP_PROD

#define VNIF_GET_TX_RSP_CONS VNIFV_GET_TX_RSP_CONS

#define VNIF_GET_RX_RSP_CONS VNIFV_GET_RX_RSP_CONS

#define VNIF_SET_TX_RSP_CONS VNIFV_SET_TX_RSP_CONS

#define VNIF_SET_RX_RSP_CONS VNIFV_SET_RX_RSP_CONS

#define VNIF_SET_TX_EVENT VNIFV_SET_TX_EVENT

#define VNIF_SET_RX_EVENT VNIFV_SET_RX_EVENT

#define VNIF_RX_RING_KICK_ALWAYS VNIFV_RX_RING_KICK_ALWAYS

#define VNIF_RX_NOTIFY VNIFV_RX_NOTIFY

#define VRING_CAN_ADD_TX VRINGV_CAN_ADD_TX

#define VNIF_RING_FREE_REQUESTS VNIFV_RING_FREE_REQUESTS

#define VNIF_HAS_UNCONSUMED_RESPONSES VNIFV_HAS_UNCONSUMED_RESPONSES

#define VNIF_IS_VALID_RCB VNIFV_IS_VALID_RCB

#define VNIF_DATA_VALID_CHECKSUM_VALID VNIFV_DATA_VALID_CHECKSUM_VALID

#define VNIF_CHECKSUM_SUCCEEDED VNIFV_CHECKSUM_SUCCEEDED

#define VNIF_IS_PACKET_DATA_VALID VNIFV_IS_PACKET_DATA_VALID

#define VNIF_PACKET_NEEDS_CHECKSUM VNIFV_PACKET_NEEDS_CHECKSUM

#define VNIF_ADD_RCB_TO_RING VNIFV_ADD_RCB_TO_RING

#define MP_RING_FULL MPV_RING_FULL

#define MP_RING_EMPTY MPV_RING_EMPTY

#define VNIF_RING_HAS_UNCONSUMED_RESPONSES VNIFV_RING_HAS_UNCONSUMED_RESPONSES

#define VNIF_RING_FINAL_CHECK_FOR_RESPONSES VNIFV_RING_FINAL_CHECK_FOR_RESPONSES

#define vnif_notify_always_tx vnifv_notify_always_tx

#define vnif_add_tx vnifv_add_tx

#define vnif_get_tx vnifv_get_tx

#define vnif_get_rx vnifv_get_rx

#define vnif_ndis_queue_dpc vnifv_ndis_queue_dpc

#define vnif_send_packet_filter vnifv_send_packet_filter

#define vnif_send_multicast_list vnifv_send_multicast_list

#define vnif_send_vlan_filter vnifv_send_vlan_filter

#define vnif_restart_interface vnifv_restart_interface

#define VNIFFreeAdapterInterface VNIFV_FreeAdapterInterface

#define VNIFCleanupInterface VNIFV_CleanupInterface

#define VNIFFindAdapter VNIFV_FindAdapter

#define VNIFSetupAdapterInterface VNIFV_SetupAdapterInterface

#define VNIFQueryHWResources VNIFV_QueryHWResources

#define VNIFQuiesce VNIFV_Quiesce

#define VNIFCleanupRings VNIFV_CleanupRings

#define VNIFDisconnectBackend VNIFV_DisconnectBackend

#define VNIFRegisterNdisInterrupt VNIFV_RegisterNdisInterrupt

#define VNIFDeregisterHardwareResources VNIFV_DeregisterHardwareResources

#define VNIF_GET_NUM_PATHS vnifv_get_num_paths

#define VNIF_SETUP_PATH_INFO_EX vnifv_setup_path_info_ex

#ifdef DBG
#define VNIF_DUMP VNIFV_DUMP
#define vnif_rcv_stats_dump vnifv_rcv_stats_dump
#else
#define VNIF_DUMP(adapter, path_id, str, rxtx, force)
#define vnif_rcv_stats_dump(_adapter, _path_id)
#endif

#ifdef NDIS_SUPPORT_NDIS6
#else
#define DriverEntryEx MPV_DriverEntryEx

#define VNIFGetHWResources VNIFV_GetHWResources
#endif

#endif
