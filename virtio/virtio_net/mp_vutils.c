/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2011-2017 Novell, Inc.
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

#include <ndis.h>
#include "miniport.h"
#include <virtio_config.h>
#include <virtio_utils.h>
#include <virtio_pci.h>
#include <virtio_queue_ops.h>
#include <virtio_net.h>

void
MPDisableInterrupt(IN PVOID MiniportInterruptContext)
{
    UINT i;
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)MiniportInterruptContext;

    for (i = 0; i < adapter->num_paths; i++) {
        vq_disable_interrupt(adapter->path[i].rx);
        vq_disable_interrupt(adapter->path[i].tx);
    }
}

void
MPEnableInterrupt(IN PVOID MiniportInterruptContext)
{
    UINT i;
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)MiniportInterruptContext;

    for (i = 0; i < adapter->num_paths; i++) {
        vq_enable_interrupt(adapter->path[i].rx);
        vq_enable_interrupt(adapter->path[i].tx);
    }
}

void
vnif_virtio_dev_reset(PVNIF_ADAPTER adapter)
{
    uint8_t status;

    VIRTIO_DEVICE_RESET(&adapter->u.v.vdev);
    virtio_device_reset_features(&adapter->u.v.vdev);
    status = VIRTIO_DEVICE_GET_STATUS(&adapter->u.v.vdev);
    if (status) {
        RPRINTK(DPRTL_ON,
            ("%s Device status is still %02X", __func__, (ULONG)status));
        VIRTIO_DEVICE_RESET(&adapter->u.v.vdev);
        status = VIRTIO_DEVICE_GET_STATUS(&adapter->u.v.vdev);
        RPRINTK(DPRTL_ON,
            ("%s Device status on retry %02X", __func__, (ULONG)status));
    }
    virtio_device_add_status(&adapter->u.v.vdev,
                             VIRTIO_CONFIG_S_ACKNOWLEDGE);
    virtio_device_add_status(&adapter->u.v.vdev, VIRTIO_CONFIG_S_DRIVER);
}

void
vnif_report_link_status(PVNIF_ADAPTER adapter)
{
    uint16_t link_status;
    BOOLEAN link_up;
    BOOLEAN link_anounce;

    VIRTIO_DEVICE_GET_CONFIG(&adapter->u.v.vdev,
        ETH_LENGTH_OF_ADDRESS,
        &link_status,
        sizeof(link_status));

    DPRINTK(DPRTL_ON, ("%s: link status %x.\n", __func__, link_status));

    link_up = !!(link_status & VIRTIO_NET_S_LINK_UP);
    if (link_up != !VNIF_TEST_FLAG(adapter, VNF_ADAPTER_NO_LINK)) {
        if (link_up) {
            VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_NO_LINK);
        } else {
            VNIF_SET_FLAG(adapter, VNF_ADAPTER_NO_LINK);
        }

        DPRINTK(DPRTL_ON, ("%s: indicate status %x.\n", __func__, link_up));
        VNIFIndicateLinkStatus(adapter, link_up);
    }
    if (virtio_is_feature_enabled(adapter->u.v.features,
                                  VIRTIO_NET_F_GUEST_ANNOUNCE)
            && link_up
            && !!(link_status & VIRTIO_NET_S_ANNOUNCE)) {

        DPRINTK(DPRTL_ON, ("%s: send arp.\n", __func__));
        vnif_send_arp(adapter);

        DPRINTK(DPRTL_ON, ("%s: send anounce ctrl msg.\n", __func__));
        vnif_send_control_msg(adapter,
                      VIRTIO_NET_CTRL_ANNOUNCE,
                      VIRTIO_NET_CTRL_ANNOUNCE_ACK,
                      NULL,
                      0,
                      NULL,
                      0);
    }
}

#ifdef DBG
virtio_net_hdr_t ghdr;
#endif

void
vnifv_add_tx(PVNIF_ADAPTER adapter, UINT path_id, TCB *tcb,
             UINT send_len, UINT pkt_len,
             uint16_t flags, UINT *i)
{
    VNIF_GSO_INFO gso_info;
    virtio_buffer_descriptor_t sg[VNIF_MAX_TX_SG_ELEMENTS];
    virtio_net_hdr_t *hdr;
    uint8_t *ip_hdr;
    ULONG gso_mss;
    UINT sg_cnt;
    uint16_t ip_hdr_len;
    uint8_t protocol;
    uint8_t ip_version;
#ifdef DBG
    uint8_t *pDest;
    uint32_t k, j;

    hdr = NULL;
#endif

    if (tcb == NULL) {
        return;
    }

    NdisZeroMemory(tcb->data, adapter->buffer_offset);
    sg[0].phys_addr = tcb->data_pa.QuadPart;
    sg[0].len = adapter->buffer_offset;

    VNIF_GET_GOS_INFO(tcb, gso_info);
    gso_mss = VNIF_GET_GSO_MSS(gso_info);

    if (tcb->sg_cnt == 0) {
        sg[1].phys_addr = tcb->data_pa.QuadPart + adapter->buffer_offset;
        sg[1].len = send_len;
        sg_cnt = 2;

        ip_hdr = tcb->data
                    + adapter->buffer_offset
                    + tcb->priority_vlan_adjust
                    + ETH_HEADER_SIZE;

#ifdef DBG
        pDest = tcb->data + adapter->buffer_offset;
        if (pDest[12] == 0x81) {
            DPRINTK(DPRTL_PRI, ("%s: TX [12] %x [13] %x [14] %x [15] %x\n",
                                __func__,
                                pDest[12], pDest[13], pDest[14], pDest[15]));
        }
        if (pDest[12] == 0x81 && tcb->priority_vlan_adjust == 0) {
            DPRINTK(DPRTL_PRI, ("%s: priority but adjust == 0\n", __func__));
        }
#endif
        ip_version = IP_INPLACE_HEADER_VERSION(ip_hdr);
        if (ip_version == IPV4 || ip_version == IPV6) {
            if (ip_version == IPV4) {
                ip_hdr_len = IP_INPLACE_HEADER_SIZE(ip_hdr);
                protocol = ip_hdr[IP_HDR_TCP_UDP_OFFSET];
                DPRINTK(DPRTL_PRI, ("%s: ipv4\n", __func__));
            } else {
                DPRINTK(DPRTL_PRI, ("%s: ipv6\n", __func__));
                get_ipv6_hdr_len_and_protocol((ipv6_header_t *)ip_hdr,
                                              send_len - ETH_HEADER_SIZE,
                                              &ip_hdr_len,
                                              &protocol);
            }

            if (flags & NETTXF_csum_blank) {
                DPRINTK(DPRTL_PRI, ("%s: flags and checksum\n", __func__));
                hdr = (virtio_net_hdr_t *)tcb->data;
                hdr->flags |= VIRTIO_NET_HDR_F_NEEDS_CSUM;
                hdr->csum_start = ip_hdr_len + ETH_HEADER_SIZE;
                hdr->csum_offset = protocol == VNIF_PACKET_TYPE_TCP ?
                    VNIF_PACKET_BYTE_OFFSET_TCP_CHKSUM :
                    VNIF_PACKET_BYTE_OFFSET_UDP_CHKSUM;

                DPRINTK(DPRTL_CHKSUM, ("%s: v%d - f %x st %x off %x\n",
                        __func__,
                        IP_INPLACE_HEADER_VERSION(ip_hdr),
                        hdr->flags,
                        hdr->csum_start,
                        hdr->csum_offset));
            }
            if (gso_mss) {
                /*
                 * When copying the packet buffers to one buffer, need to
                 * get the ip header len, tcp header len, and do the checksums.
                 * These are already done if a sg list is obtained for the
                 * packet.
                 */
                DPRINTK(DPRTL_PRI, ("%s: gso_mss\n", __func__));
                vnif_gos_hdr_update(tcb,
                                    ip_hdr,
                                    ip_hdr + ip_hdr_len,
                                    ip_hdr_len,
                                    send_len);
            }
        }
    } else {
        for (sg_cnt = 0; sg_cnt < tcb->sg_cnt; sg_cnt++) {
            sg[sg_cnt + 1].phys_addr = tcb->sg[sg_cnt].phys_addr;
            sg[sg_cnt + 1].len = tcb->sg[sg_cnt].len;
        }
        sg_cnt++; /* Add one for the header. */
    }

    if (gso_mss) {
        hdr = (virtio_net_hdr_t *)tcb->data;
        hdr->flags |= VIRTIO_NET_HDR_F_NEEDS_CSUM;
        hdr->gso_type = tcb->ip_version == IPV4 ?
            VIRTIO_NET_HDR_GSO_TCPV4 : VIRTIO_NET_HDR_GSO_TCPV6;
        hdr->hdr_len  = ETH_HEADER_SIZE
            + tcb->ip_hdr_len
            + tcb->tcp_hdr_len;
        hdr->gso_size = (uint16_t)gso_mss;
        hdr->csum_start =  ETH_HEADER_SIZE + tcb->ip_hdr_len;
        hdr->csum_offset = VNIF_PACKET_BYTE_OFFSET_TCP_CHKSUM;

        VNIF_SET_GSO_PAYLOAD(tcb, gso_info, pkt_len -
            (ETH_HEADER_SIZE + tcb->ip_hdr_len + tcb->tcp_hdr_len));

        DPRINTK(DPRTL_CHKSUM, ("%s: v%d - f %x st %x off %x hln %x t %d s %d\n",
                __func__,
                tcb->ip_version,
                hdr->flags,
                hdr->csum_start,
                hdr->csum_offset,
                hdr->hdr_len,
                hdr->gso_type,
                hdr->gso_size));
    }

    DPRINTK(DPRTL_IO,
        ("vnif_add_tx: vring_add_buf tcb = %p, pa %x, sz %x\n",
        tcb, (uint32_t)sg[0].phys_addr, sg[0].len));

#ifdef DBG
    if (gso_mss && hdr != NULL &&
            (ghdr.flags != hdr->flags ||
            ghdr.gso_type != hdr->gso_type ||
            ghdr.hdr_len != hdr->hdr_len ||
            ghdr.gso_size != hdr->gso_size ||
            ghdr.csum_start != hdr->csum_start ||
            ghdr.csum_offset != hdr->csum_offset)) {
        ghdr.flags = hdr->flags;
        ghdr.gso_type = hdr->gso_type;
        ghdr.hdr_len = hdr->hdr_len;
        ghdr.gso_size = hdr->gso_size;
        ghdr.csum_start = hdr->csum_start;
        ghdr.csum_offset = hdr->csum_offset;
        PRINTK(("LSO: f %x t %x hl %d gs %d cs %d co %d\n",
            hdr->flags,
            hdr->gso_type,
            hdr->hdr_len,
            hdr->gso_size,
            hdr->csum_start,
            hdr->csum_offset));
        PRINTK(("     pl %d ip %d tl %d sgc %d sg0 %d sg1 %d\n",
            gso_info.LsoV1TransmitComplete.TcpPayload,
            tcb->ip_hdr_len,
            tcb->tcp_hdr_len,
            sg_cnt,
            sg[0].len,
            sg[1].len));
        if (sg_cnt == 2 && (dbg_print_mask & DPRTL_LSO)) {
            PRINTK(("%p: ", tcb->data));
            for (k = 0; k < adapter->buffer_offset; k++) {
                PRINTK(("%02x ", tcb->data[k]));
            }
            PRINTK(("\n%p %d", tcb->data + adapter->buffer_offset, sg[1].len));
            for (j = 0; j < sg[1].len && j < hdr->hdr_len; j++) {
                if ((j % 16) == 0) {
                    PRINTK(("\n"));
                }
                PRINTK(("%02x ", tcb->data[k + j]));
            }
            PRINTK(("\n"));
        }
    }
#endif

    if (adapter->b_indirect) {
        vq_add_buf_indirect(adapter->path[path_id].tx,
                               sg,
                               sg_cnt,
                               0,
                               tcb,
                               (struct vring_desc *)tcb->vr_desc,
                               tcb->vr_desc_pa.QuadPart);
    } else {
        vq_add_buf(adapter->path[path_id].tx, sg, sg_cnt, 0, tcb);
    }
}

void
vnifv_notify_always_tx(PVNIF_ADAPTER adapter, UINT path_id)
{
    vq_kick_always(adapter->path[path_id].tx);
}

void *
vnifv_get_tx(PVNIF_ADAPTER adapter, UINT path_id, UINT *cons, UINT prod,
    UINT cnt, UINT *len, UINT *status)
{
    *status = NETIF_RSP_OKAY;
    return vq_get_buf(adapter->path[path_id].tx, len);
}

RCB *
vnifv_get_rx(PVNIF_ADAPTER adapter, UINT path_id, UINT rp, UINT *i, INT *len)
{
    RCB *rcb;

    rcb = vq_get_buf(adapter->path[path_id].u.vq.rx, len);
    if (rcb) {
        rcb->len = *len - adapter->buffer_offset;
        rcb->total_len = rcb->len;
        rcb->next = NULL;
    }
    return rcb;
}

#ifdef NDIS60_MINIPORT
void
vnifv_ndis_queue_dpc(PVNIF_ADAPTER adapter,
                     UINT rcv_qidx,
                     UINT max_nbls_to_indicate)
{
#if NDIS620_MINIPORT_SUPPORT
    GROUP_AFFINITY target_affinity;
#endif
    UINT path_id;

    path_id = adapter->rcv_q[rcv_qidx].path_id;

    if (path_id < adapter->num_paths) {
#if NDIS620_MINIPORT_SUPPORT
        target_affinity.Group = adapter->rcv_q[rcv_qidx].rcv_processor.Group;
        target_affinity.Mask = 1;
        target_affinity.Mask <<= adapter->rcv_q[rcv_qidx].rcv_processor.Number;

        DPRINTK(DPRTL_RX,
                ("%s: NDPC rqidx %d pathid %d\n", __func__, rcv_qidx, path_id));
        NdisMQueueDpcEx(adapter->u.v.interrupt_handle,
                        adapter->path[path_id].u.vq.rx_msg,
                        &target_affinity,
                        (void *)VNIF_RX_INT);
#else
        NdisMQueueDpc(adapter->u.v.interrupt_handle,
                      adapter->path[path_id].u.vq.rx_msg,
                      1 << adapter->rcv_q[rcv_qidx].rcv_processor.Number,
                      (void *)VNIF_RX_INT);
#endif
    } else {
        DPRINTK(DPRTL_RSS,
               ("%s: KeDPC rqidx %d pathid %d\n", __func__, rcv_qidx, path_id));
        KeInsertQueueDpc(&adapter->rcv_q[rcv_qidx].rcv_q_dpc,
                         (void *)path_id,
                         (void *)max_nbls_to_indicate);
    }
}
#endif

void
VNIFV_FREE_SHARED_MEMORY(VNIF_ADAPTER *adapter, void *va,
    PHYSICAL_ADDRESS pa, uint32_t len, NDIS_HANDLE hndl)
{
    NdisMFreeSharedMemory(
        adapter->AdapterHandle,
        len,
        adapter->u.v.cached,
        va,
        pa);
}

void
VNIFV_ADD_RCB_TO_RING(VNIF_ADAPTER *adapter, RCB *rcb)
{
    virtio_buffer_descriptor_t sg;

    sg.phys_addr = rcb->page_pa.QuadPart;
    sg.len = adapter->rx_alloc_buffer_size;
    vq_add_buf(adapter->path[rcb->path_id].u.vq.rx, &sg, 0, 1, rcb);
}

ULONG
VNIFV_RX_RING_SIZE(VNIF_ADAPTER *adapter)
{
    if (adapter->path != NULL) {
        return adapter->path[0].u.vq.rx->num;
    }
    return 0;
}

ULONG
VNIFV_TX_RING_SIZE(VNIF_ADAPTER *adapter)
{
    if (adapter->path != NULL) {
        return adapter->path[0].u.vq.tx->num;
    }
    return 0;
}

void
VNIFV_GET_TX_REQ_PROD_PVT(VNIF_ADAPTER *adapter, UINT path_id, UINT *i)
{
}

void
VNIFV_GET_RX_REQ_PROD(VNIF_ADAPTER *adapter, UINT path_id, UINT *i)
{
}

void
VNIFV_SET_TX_REQ_PROD_PVT(VNIF_ADAPTER *adapter, UINT path_id, UINT i)
{
}

void
VNIFV_GET_TX_RSP_PROD(VNIF_ADAPTER *adapter, UINT path_id, UINT *prod)
{
    *prod = 0;
}
void
VNIFV_GET_RX_RSP_PROD(VNIF_ADAPTER *adapter, UINT path_id, UINT *prod)
{
    *prod = 0;
}

void
VNIFV_GET_TX_RSP_CONS(VNIF_ADAPTER *adapter, UINT path_id, UINT *prod)
{
}

void
VNIFV_GET_RX_RSP_CONS(VNIF_ADAPTER *adapter, UINT path_id, UINT *prod)
{
}

void
VNIFV_SET_TX_RSP_CONS(VNIF_ADAPTER *adapter, UINT path_id, UINT cons)
{
}

void
VNIFV_SET_RX_RSP_CONS(VNIF_ADAPTER *adapter, UINT path_id, UINT cons)
{
}

void
VNIFV_SET_TX_EVENT(VNIF_ADAPTER *adapter, UINT path_id, UINT prod)
{
}

void
VNIFV_SET_RX_EVENT(VNIF_ADAPTER *adapter, UINT path_id, UINT prod)
{
}

void
VNIFV_RX_RING_KICK_ALWAYS(void *path)
{
    vq_kick_always(((vnif_path_t *)path)->rx);
}

void
VNIFV_RX_NOTIFY(VNIF_ADAPTER *adapter, UINT path_id,
                UINT rcb_added_to_ring, UINT old)
{
    if (rcb_added_to_ring) {
        vq_kick_always(adapter->path[path_id].rx);
    }
}

UINT
VRINGV_CAN_ADD_TX(VNIF_ADAPTER *adapter, UINT path_id, UINT num)
{
    return vq_free_requests(adapter->path[path_id].u.vq.tx) >= num;
}

UINT
VNIFV_RING_FREE_REQUESTS(VNIF_ADAPTER *adapter, UINT path_id)
{
    return vq_free_requests(adapter->path[path_id].u.vq.tx);
}

UINT
VNIFV_HAS_UNCONSUMED_RESPONSES(void *vq, UINT cons, UINT prod)
{
    return vq_has_unconsumed_responses((virtio_queue_t *)vq);
}

UINT
VNIFV_IS_VALID_RCB(RCB *rcb)
{
    return 1;
}

UINT
VNIFV_DATA_VALID_CHECKSUM_VALID(struct _RCB *rcb)
{
    return ((((virtio_net_hdr_t *)(rcb->page))->flags
        & (VIRTIO_NET_HDR_F_DATA_VALID | VIRTIO_NET_HDR_F_NEEDS_CSUM))
            == VIRTIO_NET_HDR_F_DATA_VALID);
}

UINT
VNIFV_CHECKSUM_SUCCEEDED(struct _RCB *rcb)
{
    return ((virtio_net_hdr_t *)(rcb->page))->flags
        & (VIRTIO_NET_HDR_F_DATA_VALID | VIRTIO_NET_HDR_F_NEEDS_CSUM);
}

UINT
VNIFV_IS_PACKET_DATA_VALID(RCB *rcb)
{
    return ((virtio_net_hdr_t *)(rcb->page))->flags
        & VIRTIO_NET_HDR_F_DATA_VALID;
}

UINT
VNIFV_PACKET_NEEDS_CHECKSUM(RCB *rcb)
{
    return ((virtio_net_hdr_t *)(rcb->page))->flags
        & VIRTIO_NET_HDR_F_NEEDS_CSUM;
}

UINT
MPV_RING_FULL(void *vq)
{
    return vq_full((virtio_queue_t *)vq);
}

UINT
MPV_RING_EMPTY(void *vq)
{
    return vq_empty((virtio_queue_t *)vq);
}

UINT
VNIFV_RING_HAS_UNCONSUMED_RESPONSES(void *vq)
{
    return vq_has_unconsumed_responses((virtio_queue_t *)vq);
}

void
VNIFV_RING_FINAL_CHECK_FOR_RESPONSES(void *vq, int *more_to_do)
{
    vq_final_check_for_responses((virtio_queue_t *)vq, more_to_do);
}

#ifdef DBG
static uint32_t vnif_dump_print_cnt = VNIF_DUMP_PRINT_CNT;

void
VNIFV_DUMP(PVNIF_ADAPTER adapter,
           UINT path_id,
           PUCHAR str,
           uint32_t rxtx,
           uint32_t force)
{
}

void vnifv_rcv_stats_dump(PVNIF_ADAPTER adapter, UINT path_id)
{
}
#endif
