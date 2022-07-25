/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2019-2022 SUSE LLC
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

#ifndef _MP_PACKET_H
#define _MP_PACKET_H

#define __XEN_INTERFACE_VERSION__ 0x00030202
#include <asm/win_compat.h>

#if defined XENNET || defined PVVXNET
#include <xen/public/win_xen.h>
#include <xen/public/grant_table.h>
#endif

#define NET_TX_RING_SIZE 256
#define NET_RX_RING_SIZE 256

#define VNIF_DEFAULT_BUSY_RECVS     64

#define VNIF_MAX_TX_SG_ELEMENTS 36

#if NDIS_SUPPORT_NDIS6 == 0
typedef enum _NET_IF_MEDIA_DUPLEX_STATE {
    MediaDuplexStateUnknown,
    MediaDuplexStateHalf,
    MediaDuplexStateFull
} NET_IF_MEDIA_DUPLEX_STATE;
typedef NET_IF_MEDIA_DUPLEX_STATE NDIS_MEDIA_DUPLEX_STATE;
#endif

typedef struct vnif_buffer_descriptor_s {
    uint64_t phys_addr;
    ULONG len;
    ULONG pfn;
    ULONG offset;
} vnif_buffer_descriptor_t;

/* TCB (Transmit Control Block) */
typedef struct _TCB {
    LIST_ENTRY              list;
    struct _TCB             *next;
    struct _TCB             *next_free;
#if NDIS_SUPPORT_NDIS6
    PNET_BUFFER             nb;
    PNET_BUFFER_LIST        nb_list;
    struct _VNIF_ADAPTER    *adapter;
#else
    PNDIS_PACKET            orig_send_packet;
#endif
    vnif_buffer_descriptor_t sg[VNIF_MAX_TX_SG_ELEMENTS];
    UINT                    sg_cnt;
    PHYSICAL_ADDRESS        data_pa;
    UCHAR                   *data;
#ifndef XENNET
    PHYSICAL_ADDRESS        vr_desc_pa;
    uint8_t                 *vr_desc;
#endif

    /* give us a relation between grant_ref and TCB */
    UINT                    index;
#if defined XENNET || defined PVVXNET
    grant_ref_t             grant_tx_ref;
#endif
    uint16_t                ip_hdr_len;
    uint16_t                tcp_hdr_len;
    uint16_t                flags;
    uint8_t                 ip_version;
    uint8_t                 priority_vlan_adjust;
#ifdef VNIF_TRACK_TX
    UINT                    granted;
    UINT                    ringidx;
    UINT                    len;
#endif
} TCB, *PTCB;

typedef struct _rcb_pkt_info {
#if NDIS_SUPPORT_NDIS620
    ULONG hash_type;
    ULONG hash_value;
    ULONG hash_function;
#endif
    UINT ip_ver;
    uint16_t ip_hdr_len;
    uint8_t protocol;
} rcb_pkt_info_t;

/* RCB (Receive Control Block) */
typedef struct _RCB {
    LIST_ENTRY              list;
    struct _RCB             *next;
#if NDIS_SUPPORT_NDIS6
    PMDL                    mdl;
    void                    *mdl_start_va;
    PNET_BUFFER             nb;
    PNET_BUFFER_LIST        nbl;
#else
    PNDIS_PACKET            packet;
    PNDIS_BUFFER            buffer;
#endif
    PHYSICAL_ADDRESS        page_pa;
    PUCHAR                  page;
    UINT                    index;
#if defined XENNET || defined PVVXNET
    grant_ref_t             grant_rx_ref;
#endif
    INT                     total_len;
    uint32_t                len;
    uint32_t                flags;
    uint64_t                st;
    UINT                    path_id;
    UINT                    rcv_qidx;
    rcb_pkt_info_t          pkt_info;
#ifdef DBG
    LONG                    cnt;
    uint32_t                seq;
#endif
#ifdef RSS_DEBUG
    LONG                    rss_seq;
#endif
} RCB, *PRCB;

typedef struct _rcb_ring_pool {
    LIST_ENTRY          rcb_free_list;
    RCB                 **rcb_array;
    RCB                 *rcb_ring[NET_RX_RING_SIZE];
#if NDIS_SUPPORT_NDIS6
    PNET_BUFFER_LIST    rcb_nbl;
#endif
} rcb_ring_pool_t;

typedef struct _rcv_to_process_q {
    LIST_ENTRY          rcv_to_process;
    NDIS_SPIN_LOCK      rcv_to_process_lock;
    KDPC                rcv_q_dpc;
    LONG                n_busy_rcv;
    PROCESSOR_NUMBER    rcv_processor;
    UINT                path_id;
    BOOLEAN             rcv_should_queue_dpc;
#ifdef RSS_DEBUG
    LONG               seq;
#endif
} rcv_to_process_q_t;

#endif

