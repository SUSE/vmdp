/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2024 SUSE LLC
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

#include "miniport.h"


#if NDIS_SUPPORT_NDIS685

static VOID
vnif_unmask_evtchn_from_status(PVNIF_ADAPTER adapter,
                               UINT path_id,
                               LONG poll_requested)
{
    if (poll_requested & VNIF_TX_INT) {
        /* If TX and RX are combined, just enable the TX evtchn. */
        DPRINTK(DPRTL_TXDPC, ("VNIF: %s enable tx[%d].\n", __func__, path_id));
        VNIF_UNMASK(adapter->path[path_id].u.xq.tx_evtchn);
    }  else {
        DPRINTK(DPRTL_RXDPC, ("VNIF: %s enable rx[%d].\n", __func__, path_id));
        VNIF_UNMASK(adapter->path[path_id].u.xq.rx_evtchn);
    }
}

void
vnifx_disable_adapter_notifications(PVNIF_ADAPTER adapter,
                                    UINT path_id,
                                    LONG poll_requested)
{
}

void
vnifx_enable_adapter_notifications(PVNIF_ADAPTER adapter,
                                   UINT path_id,
                                   LONG poll_requested)
{
    vnif_unmask_evtchn_from_status(adapter, path_id, poll_requested);
    vnif_continue_ndis_request_poll(adapter, path_id, poll_requested);
}

#endif

VOID
vnifx_interrupt_dpc(
  IN PKDPC Dpc,
  IN PVOID DeferredContext,
  IN PVOID SystemArgument1,
  IN PVOID SystemArgument2)
{
    vnif_xq_path_t *path = (vnif_xq_path_t *) DeferredContext;
    PVNIF_ADAPTER adapter;
    UINT path_id;

    if (path == NULL) {
        DPRINTK(DPRTL_ON, ("VNIF: %s path == NULL.\n", __func__));
        return;
    }
    if (path->adapter == NULL) {
        DPRINTK(DPRTL_ON, ("VNIF: %s adapter == NULL.\n", __func__));
        return;
    }

    adapter = path->adapter;
    path_id = path->path_id;

    DPRINTK(DPRTL_DPC, ("VNIF: %s - IN.\n", __func__));

#if NDIS_SUPPORT_NDIS685
    if (adapter->b_use_ndis_poll == TRUE) {
        NdisRequestPoll(adapter->path[path_id].rx_poll_context.nph, NULL);
    } else {
#endif
        vnif_txrx_interrupt_dpc(adapter,
                                VNIF_TX_INT,
                                path_id,
                                NDIS_INDICATE_ALL_NBLS);
        vnif_txrx_interrupt_dpc(adapter,
                                VNIF_RX_INT,
                                path_id,
                                NDIS_INDICATE_ALL_NBLS);

        /*
         * Xenbus will mask the evtchn before scheduling the DPC.
         * Unmask here to allow xen to inject more interrupts.
         */
        VNIF_UNMASK(path->tx_evtchn);
#if NDIS_SUPPORT_NDIS685
    }
#endif

    DPRINTK(DPRTL_DPC, ("VNIF: %s - OUT.\n", __func__));
}

static __inline VOID
vnifx_split_interrupt_dpc(vnif_xq_path_t *path, ULONG txrx_ind)
{
    vnif_txrx_interrupt_dpc(path->adapter,
                            txrx_ind,
                            path->path_id,
                            NDIS_INDICATE_ALL_NBLS);

    /*
     * Xenbus will mask the evtchn before scheduling the DPC.
     * Unmask here to allow xen to inject more interrupts.
     */
    if (txrx_ind == VNIF_RX_INT) {
        DPRINTK(DPRTL_RXDPC, ("VNIF: %s rx path_id %d cpu %d.\n",
                              __func__,
                              path->path_id,
                              vnif_get_current_processor(NULL)));
        VNIF_UNMASK(path->rx_evtchn);
    } else {
        VNIF_UNMASK(path->tx_evtchn);
    }
}

VOID
vnifx_tx_interrupt_dpc(
  IN PKDPC Dpc,
  IN PVOID DeferredContext,
  IN PVOID SystemArgument1,
  IN PVOID SystemArgument2)
{
    vnif_xq_path_t *path = (vnif_xq_path_t *)DeferredContext;
    PVNIF_ADAPTER adapter;
    UINT path_id;

    if (path == NULL) {
        RPRINTK(DPRTL_UNEXPD, ("VNIF: %s path == NULL.\n", __func__));
        return;
    }
    if (path->adapter == NULL) {
        RPRINTK(DPRTL_UNEXPD, ("VNIF: %s adapter == NULL.\n", __func__));
        return;
    }

    adapter = path->adapter;
    path_id = path->path_id;

    DPRINTK(DPRTL_TXDPC, ("VNIF: %s - In.\n", __func__));
#if NDIS_SUPPORT_NDIS685

    if (adapter->b_use_ndis_poll == TRUE) {
        DPRINTK(DPRTL_TXDPC,
                ("    %s: request poll - path_id %d/%d irql %d cpu %d\n",
                 __func__, path_id,
                 adapter->path[path_id].tx_poll_context.path_rcv_q_id,
                 KeGetCurrentIrql(),
                 KeGetCurrentProcessorNumber()));

        NdisRequestPoll(adapter->path[path_id].tx_poll_context.nph, NULL);
    } else {
#endif
        vnifx_split_interrupt_dpc(path, VNIF_TX_INT);
#if NDIS_SUPPORT_NDIS685
    }
#endif

    DPRINTK(DPRTL_TXDPC, ("VNIF: %s - Out.\n", __func__));
}

VOID
vnifx_rx_interrupt_dpc(
  IN PKDPC Dpc,
  IN PVOID DeferredContext,
  IN PVOID SystemArgument1,
  IN PVOID SystemArgument2)
{
    vnif_xq_path_t *path = (vnif_xq_path_t *) DeferredContext;
    PVNIF_ADAPTER adapter;
    UINT path_id;

    if (path == NULL) {
        RPRINTK(DPRTL_UNEXPD, ("VNIF: %s path == NULL.\n", __func__));
        return;
    }
    if (path->adapter == NULL) {
        RPRINTK(DPRTL_UNEXPD, ("VNIF: %s adapter == NULL.\n", __func__));
        return;
    }

    adapter = path->adapter;
    path_id = path->path_id;

    DPRINTK(DPRTL_RXDPC, ("VNIF: %s - In.\n", __func__));

#if NDIS_SUPPORT_NDIS685

    if (adapter->b_use_ndis_poll == TRUE) {
        DPRINTK(DPRTL_RXDPC,
           ("    %s: request poll - path_id %d irql %d cpu %d\n",
            __func__,
            path_id,
            KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber()));

        NdisRequestPoll(adapter->path[path_id].rx_poll_context.nph, NULL);
    } else {
#endif
        vnifx_split_interrupt_dpc(path, VNIF_RX_INT);
#if NDIS_SUPPORT_NDIS685
    }
#endif

    DPRINTK(DPRTL_RXDPC, ("VNIF: %s - Out.\n", __func__));
}

void
vnifx_ndis_queue_dpc(PVNIF_ADAPTER adapter,
                     UINT rcv_qidx,
                     UINT max_nbls_to_indicate)
{
    NDIS_STATUS status = 0xbad;

    DPRINTK(DPRTL_RSS, ("VNIF: %s path_id %d evtchn %d cur_proc %d In\n",
            __func__,
            adapter->rcv_q[rcv_qidx].path_id,
            adapter->path[adapter->rcv_q[rcv_qidx].path_id].u.xq.rx_evtchn,
            vnif_get_current_processor(NULL)));
    DPRINTK(DPRTL_RSS, ("      rcv_q[%d] pn %d g %d\n",
            rcv_qidx,
            adapter->rcv_q[rcv_qidx].rcv_processor.Number,
            adapter->rcv_q[rcv_qidx].rcv_processor.Group));

    status = KeInsertQueueDpc(&adapter->rcv_q[rcv_qidx].rcv_q_dpc,
                              (void *)adapter->rcv_q[rcv_qidx].path_id,
                              (void *)max_nbls_to_indicate);

    DPRINTK(DPRTL_RSS, ("VNIF: %s - 0x%x Out.\n", __func__, status));
}

void
vnifx_notify_always_tx(PVNIF_ADAPTER adapter, UINT path_id)
{
    int notify;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(
        &adapter->path[path_id].u.xq.tx_front_ring, notify);
    if (notify) {
        notify_remote_via_evtchn(adapter->path[path_id].u.xq.tx_evtchn);
    }
}

void
vnifx_add_tx(PVNIF_ADAPTER adapter, UINT path_id, TCB *tcb,
             UINT send_len, UINT pkt_len,
             uint16_t flags, UINT *prod)
{
    VNIF_GSO_INFO gso_info;
    struct netif_tx_request *tx;
    struct netif_extra_info *gso;
    uint8_t *ip_hdr;
    xen_ulong_t id;
    ULONG gso_mss;
    UINT i;
    uint16_t ip_hdr_len;

    if (tcb == NULL) {
        return;
    }
    VNIF_GET_GOS_INFO(tcb, gso_info);
    gso_mss = VNIF_GET_GSO_MSS(gso_info);

    tx = NULL;
    if (tcb->sg_cnt == 0) {
        id = adapter->path[path_id].u.xq.tx_id_alloc_head;
        adapter->path[path_id].u.xq.tx_id_alloc_head = (xen_ulong_t)
            (adapter->path[path_id].u.xq.tx_packets[id]);
        adapter->path[path_id].u.xq.tx_packets[id] = tcb;
        tx = RING_GET_REQUEST(&adapter->path[path_id].u.xq.tx_front_ring,
                              *prod);
        tx->id = (uint16_t)id;
        gnttab_grant_foreign_access_ref(
            adapter->path[path_id].u.xq.grant_tx_ref[id],
            adapter->u.x.backend_id, phys_to_mfn(tcb->data_pa.QuadPart),
            GNTMAP_readonly);
        tx->gref = adapter->path[path_id].u.xq.grant_tx_ref[id];
        tx->offset = (uint16_t) BYTE_OFFSET(tcb->data);
        tx->size = (uint16_t)send_len;
        tx->flags = flags;
        (*prod)++;
        DPRINTK(DPRTL_TRC, ("%s: path %d id %d gref %d txref %d prod %d\n",
                           __func__,
                           path_id,
                           id,
                           tx->gref,
                           adapter->path[path_id].u.xq.grant_tx_ref[id],
                           *prod));

        if (gso_mss) {
            /*
             * When copying the packet buffers to one buffer, need to
             * get the ip header len, tcp header len, and do the checksums.
             * These are already done if a sg list is obtained for the packet.
             */
            ip_hdr = tcb->data + tcb->priority_vlan_adjust + ETH_HEADER_SIZE;
            ip_hdr_len = get_ip_hdr_len(ip_hdr,
                send_len - (adapter->buffer_offset + ETH_HEADER_SIZE));
            vnif_gos_hdr_update(tcb,
                                ip_hdr,
                                ip_hdr + ip_hdr_len,
                                ip_hdr_len,
                                send_len);

            tx->flags |= NETTXF_data_validated
                | NETTXF_csum_blank
                | NETTXF_extra_info;

            gso = (struct netif_extra_info *)
                RING_GET_REQUEST(&adapter->path[path_id].u.xq.tx_front_ring,
                                 *prod);
            gso->u.gso.size = (uint16_t)gso_mss;
            gso->u.gso.type = tcb->ip_version == IPV4 ?
                XEN_NETIF_GSO_TYPE_TCPV4 :
                XEN_NETIF_GSO_TYPE_TCPV6;
            gso->u.gso.pad = 0;
            gso->u.gso.features = 0;

            gso->type = XEN_NETIF_EXTRA_TYPE_GSO;
            gso->flags = 0;

            VNIF_SET_GSO_PAYLOAD(tcb, gso_info, pkt_len -
                (ETH_HEADER_SIZE + tcb->ip_hdr_len + tcb->tcp_hdr_len));

            (*prod)++;
        }
    } else {
        for (i = 0; i < tcb->sg_cnt; i++) {
            id = adapter->path[path_id].u.xq.tx_id_alloc_head;
            adapter->path[path_id].u.xq.tx_id_alloc_head = (xen_ulong_t)
                (adapter->path[path_id].u.xq.tx_packets[id]);
            adapter->path[path_id].u.xq.tx_packets[id] = NULL;
            tx = RING_GET_REQUEST(&adapter->path[path_id].u.xq.tx_front_ring,
                                  *prod);
            tx->id = (uint16_t)id;
            gnttab_grant_foreign_access_ref(
                adapter->path[path_id].u.xq.grant_tx_ref[id],
                adapter->u.x.backend_id, tcb->sg[i].pfn,
                GNTMAP_readonly);
            tx->gref = adapter->path[path_id].u.xq.grant_tx_ref[id];
            tx->offset = (uint16_t)tcb->sg[i].offset;
            tx->size = (uint16_t)tcb->sg[i].len;
            tx->flags = flags | NETTXF_more_data;
            flags = 0;
            (*prod)++;
            DPRINTK(DPRTL_TRC, ("adding pfn %x, offset %d, len %d.\n",
                tcb->sg[i].pfn,
                tcb->sg[i].offset,
                tcb->sg[i].len));

            if (i == 0) {
                tx->size = (uint16_t)send_len;

                if (gso_mss) {
                    DPRINTK(DPRTL_TRC, ("** Setting up gso.\n"));
                    tx->flags |= NETTXF_data_validated
                        | NETTXF_csum_blank
                        | NETTXF_extra_info;

                    gso = (struct netif_extra_info *)
                        RING_GET_REQUEST(
                            &adapter->path[path_id].u.xq.tx_front_ring,
                            *prod);
                    gso->u.gso.size = (uint16_t)gso_mss;
                    gso->u.gso.type = tcb->ip_version == IPV4 ?
                        XEN_NETIF_GSO_TYPE_TCPV4 :
                        XEN_NETIF_GSO_TYPE_TCPV6;
                    gso->u.gso.pad = 0;
                    gso->u.gso.features = 0;

                    gso->type = XEN_NETIF_EXTRA_TYPE_GSO;
                    gso->flags = 0;
                    VNIF_SET_GSO_PAYLOAD(tcb, gso_info, pkt_len -
                        (ETH_HEADER_SIZE + tcb->ip_hdr_len + tcb->tcp_hdr_len));

                    (*prod)++;
                }
            }
        }
        adapter->path[path_id].u.xq.tx_packets[id] = tcb;
        if (tx != NULL) {
            tx->flags &= ~NETTXF_more_data;
        }
    }
}

void *
vnifx_get_tx(PVNIF_ADAPTER adapter, UINT path_id, UINT *_cons, UINT prod,
    UINT cnt, UINT *len, UINT *status)
{
    void *pkt;
    struct netif_tx_response *txrsp;
    UINT id;
    UINT cons;

    do {
        if (*_cons != prod && cnt < NET_TX_RING_SIZE) {
            cons = *_cons;
            txrsp = RING_GET_RESPONSE(
                &adapter->path[path_id].u.xq.tx_front_ring,
                cons);
            (*_cons)++;
            if (txrsp->status == NETIF_RSP_NULL) {
                DPRINTK(DPRTL_TX,
                    ("VNIFCheckSendCompletion: tx NETIF_RSP_NULL %x\n",
                    txrsp->id));
                continue;
            }

            id = txrsp->id;

            pkt = adapter->path[path_id].u.xq.tx_packets[id];
            DPRINTK(DPRTL_TRC, ("txr packet = %p, id = %d.\n", pkt, id));

            adapter->path[path_id].u.xq.tx_packets[id] =
                (void *)adapter->path[path_id].u.xq.tx_id_alloc_head;
            adapter->path[path_id].u.xq.tx_id_alloc_head = id;

            if (gnttab_end_foreign_access_ref(
                    adapter->path[path_id].u.xq.grant_tx_ref[id],
                        GNTMAP_readonly) == 0) {
                PRINTK(("VNIFCheckSendCompletion: grant %d in use!\n",
                        adapter->path[path_id].u.xq.grant_tx_ref[id]));
            }
            if (pkt == NULL) {
                continue;
            }

            *status = txrsp->status;
            return pkt;
        } else {
            return NULL;
        }
    } while (TRUE);
    return NULL;
}

RCB *
vnifx_get_rx(PVNIF_ADAPTER adapter, UINT path_id,
             UINT prod, UINT *_cons, INT *len)
{
    struct netif_rx_response *rx;
    struct netif_extra_info *extra;
    RCB *rcb;
    RCB *head;
    RCB *tail;
    RCB *extra_rcb;
    UINT cons;
    UINT exflags;

    cons = *_cons;
    head = NULL;
    *len = 0;
    if (cons < prod) {
        do {
            rx = RING_GET_RESPONSE(&adapter->path[path_id].u.xq.rx_front_ring,
                                   cons);
            cons++;
            if (rx->status <= NETIF_RSP_NULL) {
                PRINTK(("vnif_get_rx: bad status %x, id %x, cons %x prod %x\n",
                    rx->status, rx->id, cons - 1, prod));
                VNIF_DUMP(adapter, path_id, "get_rx", 1, 1);
            }

            rcb = adapter->path[path_id].rcb_rp.rcb_array[rx->id];
            head = rcb;
            tail = rcb;
            rcb->next = NULL;
            rcb->len = rx->status;
            (*len) += rx->status;
            rcb->flags = rx->flags;
            exflags = rx->flags;

            DPRINTK(DPRTL_TRC,
                ("Doing rx: %p frag len is %d %d, id %x, rid %x, cons %x, %p\n",
                rcb, rcb->len, *len,  rx->id, (cons - 1) & 255, cons - 1,
                adapter->path[path_id].rcb_rp.rcb_ring[(cons - 1)
                    & (NET_RX_RING_SIZE - 1)]));

            if (exflags & NETRXF_extra_info) {
                if (cons < prod) {
                    extra = (struct netif_extra_info *)RING_GET_RESPONSE(
                        &adapter->path[path_id].u.xq.rx_front_ring, cons);
                    extra_rcb = adapter->path[path_id].rcb_rp.rcb_ring[cons
                        & (NET_RX_RING_SIZE - 1)];
                    cons++;
#ifdef DBG
                    if (extra->type == XEN_NETIF_EXTRA_TYPE_GSO &&
                        extra->u.gso.type == XEN_NETIF_EXTRA_TYPE_GSO) {
                        DPRINTK(DPRTL_TRC,
                            ("Doing rx: %p extra info with mss %d, flags %x\n",
                            extra_rcb, extra->u.gso.size, exflags));
                    } else {
                        PRINTK(("vnif_get_rx: %s, invalid extra type: %x\n",
                                adapter->node_name, extra->type));
                        PRINTK((" flg %x cons %x cons %x prod %x rsp_prod %x\n",
                         exflags, *_cons, cons, prod,
                         adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_prod));
                    }
#endif
                    vnif_return_rcb(adapter, extra_rcb);
                } else {
                    PRINTK(("vnif_get_rx: extra flags (%x) but no data\n",
                            exflags));
                    PRINTK(("  starting cons %x currnet cons %x prod %x\n",
                            *_cons, cons, prod));
                }
            }

            while (exflags & NETRXF_more_data) {
                if (cons >= prod) {
                    PRINTK(("vnif_get_rx: doing more but no more on ring\n"));
                    PRINTK(("  flags %x cons %x local prod %x, rsp_prod %x\n",
                    exflags, cons, prod,
                    adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_prod));
                    break;
                }
                rx = RING_GET_RESPONSE(
                    &adapter->path[path_id].u.xq.rx_front_ring,
                    cons);
                cons++;
                rcb = adapter->path[path_id].rcb_rp.rcb_array[rx->id];
                rcb->next = NULL;
                tail->next = rcb;
                tail = rcb;
                rcb->len = rx->status;
                (*len) += rx->status;
                exflags = rx->flags;
#ifdef DBG
                if (rx->status <= NETIF_RSP_NULL) {
                    PRINTK(("vnif_get_rx: status %x <= NETIF_RSP_NULL id %x\n",
                        rx->status, rx->id));
                }
                DPRINTK(DPRTL_ON,
                    ("Doing rx: %p rlen is %d %d, id %x, rid %x, cons %x, %p\n",
                    rcb, rcb->len, *len, rx->id,
                    (cons - 1) & (NET_RX_RING_SIZE - 1), cons - 1,
                    adapter->path[path_id].rcb_rp.rcb_ring[(cons - 1)
                        & (NET_RX_RING_SIZE - 1)]));
                if (!(rx->flags & NETTXF_more_data)) {
                    DPRINTK(DPRTL_TRC, (" total len is %d\n", *len));
                }
#endif
            }
        } while (FALSE);
        if ((int)head->len > NETIF_RSP_NULL) {
            head->total_len = *len;
        } else {
            head->total_len = head->len;
        }
        *_cons = cons;
    }
    return head;
}




void
VNIFX_FREE_SHARED_MEMORY(VNIF_ADAPTER *adapter, void *va,
    PHYSICAL_ADDRESS pa, uint32_t len, NDIS_HANDLE hndl)
{
    NdisFreeMemory(va, len, 0);
}

void
VNIFX_ADD_RCB_TO_RING(VNIF_ADAPTER *adapter, RCB *rcb)
{
    RING_IDX req_prod;
    netif_rx_request_t *req;
    UINT ridx;
    UINT path_id;

    path_id = rcb->path_id;
    req_prod = adapter->path[path_id].u.xq.rx_front_ring.req_prod_pvt;
    ridx = (req_prod
            & (RING_SIZE(&adapter->path[path_id].u.xq.rx_front_ring) - 1));
    adapter->path[path_id].rcb_rp.rcb_ring[ridx] = rcb;
    req = RING_GET_REQUEST(&adapter->path[path_id].u.xq.rx_front_ring,
                           req_prod);
    req->gref = rcb->grant_rx_ref;
    req->id = (UINT16) rcb->index;
    KeMemoryBarrier();

    DPRINTK(DPRTL_TRC, ("Put rcb:  %p, idx %x back on the ring at %x.\n",
        rcb, rcb->index, req_prod));
    adapter->path[path_id].u.xq.rx_front_ring.req_prod_pvt = req_prod + 1;
    RING_PUSH_REQUESTS(&adapter->path[path_id].u.xq.rx_front_ring);
}

ULONG
VNIFX_RX_RING_SIZE(VNIF_ADAPTER *adapter)
{
    return NET_RX_RING_SIZE;
}

ULONG
VNIFX_TX_RING_SIZE(VNIF_ADAPTER *adapter)
{
    return NET_TX_RING_SIZE;
}

void
VNIFX_GET_TX_REQ_PROD_PVT(VNIF_ADAPTER *adapter, UINT path_id, UINT *i)
{
    *i = adapter->path[path_id].u.xq.tx_front_ring.req_prod_pvt;
}

void
VNIFX_GET_RX_REQ_PROD(VNIF_ADAPTER *adapter, UINT path_id, UINT *i)
{
    *i = adapter->path[path_id].u.xq.rx_front_ring.sring->req_prod;
}

void
VNIFX_SET_TX_REQ_PROD_PVT(VNIF_ADAPTER *adapter, UINT path_id, UINT i)
{
    adapter->path[path_id].u.xq.tx_front_ring.req_prod_pvt = i;
}

void
VNIFX_GET_TX_RSP_PROD(VNIF_ADAPTER *adapter, UINT path_id, UINT *prod)
{
    *prod = adapter->path[path_id].u.xq.tx_front_ring.sring->rsp_prod;
}

void
VNIFX_GET_RX_RSP_PROD(VNIF_ADAPTER *adapter, UINT path_id, UINT *prod)
{
    *prod = adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_prod;
}

void
VNIFX_GET_TX_RSP_CONS(VNIF_ADAPTER *adapter, UINT path_id, UINT *cons)
{
    *cons = adapter->path[path_id].u.xq.tx_front_ring.rsp_cons;
}

void
VNIFX_GET_RX_RSP_CONS(VNIF_ADAPTER *adapter, UINT path_id, UINT *cons)
{
    *cons = adapter->path[path_id].u.xq.rx_front_ring.rsp_cons;
}

void
VNIFX_SET_TX_RSP_CONS(VNIF_ADAPTER *adapter, UINT path_id, UINT cons)
{
    adapter->path[path_id].u.xq.tx_front_ring.rsp_cons = cons;
}

void
VNIFX_SET_RX_RSP_CONS(VNIF_ADAPTER *adapter, UINT path_id, UINT cons)
{
    adapter->path[path_id].u.xq.rx_front_ring.rsp_cons = cons;
}

void
VNIFX_SET_TX_EVENT(VNIF_ADAPTER *adapter, UINT path_id, UINT prod)
{
    adapter->path[path_id].u.xq.tx_front_ring.sring->rsp_event =
        prod + ((adapter->path[path_id].u.xq.tx_front_ring.sring->req_prod
                    - prod) >> 1) + 1;
}

void
VNIFX_SET_RX_EVENT(VNIF_ADAPTER *adapter, UINT path_id, UINT prod)
{
    adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_event =
        prod + ((adapter->path[path_id].u.xq.rx_front_ring.sring->req_prod
                    - prod) >> 1) + 1;
}

void
VNIFX_RX_RING_KICK_ALWAYS(void *path)
{
    vnif_path_t *rx_path;

    rx_path = (vnif_path_t *)path;
    notify_remote_via_evtchn(rx_path->u.xq.rx_evtchn);
}

void
VNIFX_RX_NOTIFY(VNIF_ADAPTER *adapter, UINT path_id,
                UINT rcb_added_to_ring, UINT old)
{
    if (adapter->path[path_id].u.xq.rx_front_ring.sring->req_event > old) {
        notify_remote_via_evtchn(adapter->path[path_id].u.xq.rx_evtchn);
    }
}

UINT
VRINGX_CAN_ADD_TX(VNIF_ADAPTER *adapter, UINT path_id, UINT num)
{
    return RING_FREE_REQUESTS(&adapter->path[path_id].u.xq.tx_front_ring) > num;
}

UINT
VNIFX_RING_FREE_REQUESTS(VNIF_ADAPTER *adapter, UINT path_id)
{
    return RING_FREE_REQUESTS(&adapter->path[path_id].u.xq.tx_front_ring);
}

UINT
VNIFX_HAS_UNCONSUMED_RESPONSES(void *vq, UINT cons, UINT prod)
{
    UINT ret;

    ret = (cons == prod) &&
            (prod != ((struct netif_tx_front_ring *)vq)->sring->rsp_prod);
    return ret;
}

UINT
VNIFX_IS_VALID_RCB(RCB *rcb)
{
    return rcb->grant_rx_ref != GRANT_INVALID_REF;
}

UINT
VNIFX_DATA_VALID_CHECKSUM_VALID(struct _RCB *rcb)
{
    return ((rcb->flags & (NETRXF_data_validated | NETRXF_csum_blank))
            == NETRXF_data_validated);
}

UINT
VNIFX_CHECKSUM_SUCCEEDED(struct _RCB *rcb)
{
    return rcb->flags & (NETRXF_data_validated | NETRXF_csum_blank);
}

UINT
VNIFX_IS_PACKET_DATA_VALID(RCB *rcb)
{
    return rcb->flags & NETRXF_data_validated;
}

UINT
VNIFX_PACKET_NEEDS_CHECKSUM(RCB *rcb)
{
    return rcb->flags & NETRXF_csum_blank;
}

UINT
MPX_RING_FULL(void *r)
{
    return RING_FULL((struct netif_rx_front_ring *)r);
}

UINT
MPX_RING_EMPTY(void *r)
{
    UINT ret;

    ret = ((((struct netif_rx_front_ring *)r)->req_prod_pvt -
            ((struct netif_rx_front_ring *)r)->rsp_cons) == 0);
    return ret;
}

UINT
VNIFX_RING_HAS_UNCONSUMED_RESPONSES(void *vq)
{
    return RING_HAS_UNCONSUMED_RESPONSES((struct netif_rx_front_ring *)vq);
}

void
VNIFX_RING_FINAL_CHECK_FOR_RESPONSES(void *vq, int *more_to_do)
{
    int mtd;

    RING_FINAL_CHECK_FOR_RESPONSES(((struct netif_rx_front_ring *)vq), mtd);
    *more_to_do = mtd;
}

#if NDIS_SUPPORT_NDIS6 == 0
void
MPX_DriverEntryEx(NDIS_MINIPORT_CHARACTERISTICS *mp_char)
{
}
#endif

NDIS_STATUS
VNIFX_GetHWResources(VNIF_ADAPTER *adapter)
{
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
VNIFX_RegisterNdisInterrupt(VNIF_ADAPTER *adapter)
{
    return NDIS_STATUS_SUCCESS;
}

void
VNIFX_DeregisterHardwareResources(VNIF_ADAPTER *adapter)
{
}

NDIS_STATUS
vnifx_setup_path_info_ex(VNIF_ADAPTER *adapter)
{
    UINT i;

    for (i = 0; i < adapter->num_paths; i++) {
        adapter->path[i].u.xq.gref_tx_head = GRANT_INVALID_REF;
        adapter->path[i].u.xq.gref_rx_head = GRANT_INVALID_REF;
    }

    vnif_setup_rx_path_dpc(adapter);

    return NDIS_STATUS_SUCCESS;
}

UINT
vnifx_get_num_paths(struct _VNIF_ADAPTER *adapter)
{
    return adapter->num_hw_queues;
}


#ifdef DBG
static uint32_t vnif_dump_print_cnt = VNIF_DUMP_PRINT_CNT;

void
VNIFX_DUMP(PVNIF_ADAPTER adapter, UINT path_id, PUCHAR str,
           uint32_t rxtx, uint32_t force)
{
    if (KeGetCurrentIrql() > 2) {
        DPRINTK(DPRTL_ON, ("%s irql = %d\n", str, KeGetCurrentIrql()));
    }
    if (dbg_print_mask == DPRTL_OFF) {
        return;
    }
    if (adapter->dbg_print_cnt < vnif_dump_print_cnt || force) {
        if (adapter->node_name
                && adapter->path[path_id].u.xq.rx_front_ring.sring
                && adapter->path[path_id].u.xq.tx_front_ring.sring) {
            DPRINTK(DPRTL_ON, ("%s: %p, %s %d, has %d recv, fltr %x\n",
                str, adapter, adapter->node_name, adapter->dbg_print_cnt,
                VNIF_RING_HAS_UNCONSUMED_RESPONSES(adapter->path[path_id].rx),
                adapter->PacketFilter));
            if (rxtx & 1) {
                PRINTK(("%s: nBusyRecv %d, receives to process %d\n",
                    str, adapter->nBusyRecv,
                    adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_prod -
                        adapter->path[path_id].u.xq.rx_front_ring.rsp_cons));
                PRINTK(("%s: req_prod_pvt 0x%x, rsp_cons 0x%x\n",
                    str, adapter->path[path_id].u.xq.rx_front_ring.req_prod_pvt,
                    adapter->path[path_id].u.xq.rx_front_ring.rsp_cons));
                PRINTK(("%s: sring: req_prod 0x%x, rsp_prod 0x%x.\n",
                    str,
                    adapter->path[path_id].u.xq.rx_front_ring.sring->req_prod,
                    adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_prod));
                PRINTK(("%s: sring: req_event 0x%x, rsp_event 0x%x.\n\n",
                   str,
                   adapter->path[path_id].u.xq.rx_front_ring.sring->req_event,
                   adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_event));
            }

            if (rxtx & 2) {
                PRINTK(("%s: nBusySends %d, flags 0x%x\n",
                    str, adapter->nBusySend, adapter->adapter_flags));
                PRINTK(("%s: req_prod_pvt 0x%x, rsp_cons 0x%x\n",
                    str, adapter->path[path_id].u.xq.tx_front_ring.req_prod_pvt,
                    adapter->path[path_id].u.xq.tx_front_ring.rsp_cons));
                PRINTK(("%s: sring: req_prod 0x%x, rsp_prod 0x%x.\n",
                    str,
                    adapter->path[path_id].u.xq.tx_front_ring.sring->req_prod,
                    adapter->path[path_id].u.xq.tx_front_ring.sring->rsp_prod));
                PRINTK(("%s: sring: req_event 0x%x, rsp_event 0x%x.\n",
                   str,
                   adapter->path[path_id].u.xq.tx_front_ring.sring->req_event,
                   adapter->path[path_id].u.xq.tx_front_ring.sring->rsp_event));
            }
            adapter->dbg_print_cnt++;
        } else {
            PRINTK(("%s, name %p, rring %p, tring %p.\n",
                    str, adapter->node_name,
                    adapter->path[path_id].u.xq.rx_front_ring.sring,
                    adapter->path[path_id].u.xq.tx_front_ring.sring));
        }
    }
}

void
vnifx_rcv_stats_dump(PVNIF_ADAPTER adapter, UINT path_id)
{
    if ((adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_prod -
            adapter->path[path_id].u.xq.rx_front_ring.rsp_cons) >=
                (NET_RX_RING_SIZE - 5) ||
        (adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_prod ==
            adapter->path[path_id].u.xq.rx_front_ring.sring->req_prod) ||
        ((adapter->path[path_id].u.xq.rx_front_ring.sring->rsp_prod -
            adapter->path[path_id].u.xq.rx_front_ring.rsp_cons)
            + adapter->nBusyRecv) >= (NET_RX_RING_SIZE - 5)) {
        VNIF_DUMP(adapter, path_id, "VNIFReceivePackets", 1, 1);
    }
}
#endif

#ifdef VNIF_TRACK_TX
void
xennet_print_req(txlist_t *txlist)
{
    uint32_t i, j;
    uint32_t idx;

    PRINTK(("txlist cons %x, prod %x\n", txlist->cons, txlist->prod));
    for (j = 0, i = txlist->prod; j < NET_TX_RING_SIZE; j++, i++) {
        idx = i & (NET_TX_RING_SIZE - 1);
        if (txlist->list[idx].state) {
            PRINTK(("txlist %d: tcb %x, ref %x, rid %x, state %x\n",
                idx,
                txlist->list[idx].id,
                txlist->list[idx].ref,
                txlist->list[idx].rid,
                txlist->list[idx].state));
            PRINTK(("           sflags %x, eflags %x foreign flags %x.\n",
                txlist->list[idx].sflags,
                txlist->list[idx].eflags,
                gnttab_query_foreign_access_flags(txlist->list[idx].ref)));
        }
    }
}

void
xennet_save_req(txlist_t *txlist, struct _TCB *tcb, uint32_t ridx)
{
    uint32_t idx;

    if (tcb->granted) {
        PRINTK(("Reusing TCB before cleared: %p ref %x, id %x, granted %d.\n",
            tcb, tcb->grant_tx_ref, tcb->index, tcb->granted));
    }
    tcb->granted++;
    tcb->ringidx = ridx;
    idx = txlist->prod & (NET_TX_RING_SIZE - 1);
    if (txlist->list[idx].state == 1) {
        PRINTK(("txlist wrapped %d: tcb %x, ref %x, rid %x, state %x\n",
            idx,
            txlist->list[idx].id,
            txlist->list[idx].ref,
            txlist->list[idx].rid,
            txlist->list[idx].state));
        PRINTK(("                   sflags %x, eflags %x foreign flags %x.\n",
            txlist->list[idx].sflags,
            txlist->list[idx].eflags,
            gnttab_query_foreign_access_flags(txlist->list[idx].ref)));
    }
    txlist->list[idx].ref = tcb->grant_tx_ref;
    txlist->list[idx].id = tcb->index;
    txlist->list[idx].rid = tcb->ringidx;
    txlist->list[idx].state = 1;
    txlist->list[idx].sflags =
        gnttab_query_foreign_access_flags(tcb->grant_tx_ref);
    txlist->list[idx].eflags = 0;
    txlist->prod++;
}

void
xennet_clear_req(txlist_t *txlist, TCB *tcb)
{
    uint32_t idx;
    uint32_t i;
    uint32_t j;

    tcb->granted-- ;
    tcb->ringidx = 0;
    for (i = txlist->cons; i < txlist->prod; i++) {
        idx = i & (NET_TX_RING_SIZE - 1);
        if (txlist->list[idx].ref == tcb->grant_tx_ref) {
            if (i == txlist->cons) {
                txlist->list[idx].state = 0;
            } else {
                txlist->list[idx].state = 2;
            }
            txlist->list[idx].eflags =
                gnttab_query_foreign_access_flags(tcb->grant_tx_ref);
            txlist->cons = i + 1;
            return;
        }
    }

    j = NET_TX_RING_SIZE - (txlist->prod - txlist->cons);
    for (i = txlist->cons - 1; j; i--, j--) {
        idx = i & (NET_TX_RING_SIZE - 1);
        if (txlist->list[idx].ref == tcb->grant_tx_ref) {
            txlist->list[idx].state = 3;
            txlist->list[idx].eflags =
                gnttab_query_foreign_access_flags(tcb->grant_tx_ref);
            return;
    }
    }
    PRINTK(("\ntxlist req couldn't find it: ref %x, c %x, p %x\n",
               tcb->grant_tx_ref, txlist->cons, txlist->prod));
}
#endif
