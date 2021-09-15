/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
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

#include "miniport.h"

#ifdef DBG
static uint32_t vnif_send_print_cnt = VNIF_SEND_PRINT_CNT;
static uint32_t max_data_len;
static uint32_t max_loop_cnt;
static uint32_t max_sg_cnt;
static uint32_t max_pkt_len;
#endif

static NDIS_STATUS
should_checksum_tx(PVNIF_ADAPTER adapter, PNET_BUFFER_LIST nb_list,
    uint16_t *flags)
{
    PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO info;
    NDIS_STATUS status;

    info =
        (PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO) (
            &(NET_BUFFER_LIST_INFO(
            nb_list,
            TcpIpChecksumNetBufferListInfo)));
#ifdef DBG
    if (info->Transmit.TcpChecksum || info->Transmit.UdpChecksum ||
        info->Transmit.IpHeaderChecksum) {
        DPRINTK(DPRTL_CHKSUM,
            ("Rqst TX Checksum: v4 %x, v6 %x, tcp %x, udp %x, ip %x.\n",
            info->Transmit.IsIPv4,
            info->Transmit.IsIPv6,
            info->Transmit.TcpChecksum,
            info->Transmit.UdpChecksum,
            info->Transmit.IpHeaderChecksum));

    }
#endif

    if ((*(uintptr_t *)&info->Value) & VNIF_CHECKSUM_OFFLOAD_INFO_BITS) {
        DPRINTK(DPRTL_CHKSUM,
            ("TX cinfo: v4 %x, v6 %x, tcp %x, udp %x, ip %x.\n",
            info->Transmit.IsIPv4,
            info->Transmit.IsIPv6,
            info->Transmit.TcpChecksum,
            info->Transmit.UdpChecksum,
            info->Transmit.IpHeaderChecksum));
        if (info->Transmit.IsIPv4) {
            if (info->Transmit.TcpChecksum) {
                if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_TCP)) {
                    PRINTK(("tcp: mark checksum as failure\n"));
                    return NDIS_STATUS_FAILURE;
                }
            }
            if (info->Transmit.UdpChecksum) {
                if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_UDP)) {
                    PRINTK(("udp: mark checksum as failure\n"));
                    return NDIS_STATUS_FAILURE;
                }
            }
            if (info->Transmit.IpHeaderChecksum) {
                if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_IP)) {
                    PRINTK(("ip: mark checksum as failure\n"));
                    return NDIS_STATUS_FAILURE;
                }
            }
        } else if (info->Transmit.IsIPv6) {
            if (info->Transmit.TcpChecksum) {
                if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                    PRINTK(("tcp6: mark checksum as failure\n"));
                    return NDIS_STATUS_FAILURE;
                }
            }
            if (info->Transmit.UdpChecksum) {
                if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_UDP)) {
                    PRINTK(("udp6: mark checksum as failure\n"));
                    return NDIS_STATUS_FAILURE;
                }
            }
        } else {
            /* Packet wants checksum, but it's not supported. */
            PRINTK(("Unknow packet type, mark checksum as failure\n"));
            return NDIS_STATUS_FAILURE;
        }
        *flags |= NETTXF_data_validated | NETTXF_csum_blank;
    }
    return NDIS_STATUS_SUCCESS;
}

static __inline uint16_t
vnif_get_8021q_info(NET_BUFFER_LIST *nbl, uint32_t supported)
{
    PNDIS_NET_BUFFER_LIST_8021Q_INFO p8021;
    uint16_t    priority_vlan;

    priority_vlan = 0;
    if (supported) {
        p8021 = (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(&(NET_BUFFER_LIST_INFO(
                                                  nbl,
                                                  Ieee8021QNetBufferListInfo)));
        if (p8021->Value != NULL) {
            if (supported & P8021_PRIORITY_TAG) {
                priority_vlan =
                    p8021->TagHeader.UserPriority << P8021_PRIORITY_WORD_SHIFT;
            }
            if (supported & P8021_VLAN_TAG) {
                priority_vlan |= p8021->TagHeader.VlanId;
            }
            priority_vlan = RtlUshortByteSwap(priority_vlan);

            DPRINTK(DPRTL_PRI, ("TX 8021 priority %x vlan %x swapped %x.\n",
                                p8021->TagHeader.UserPriority,
                                p8021->TagHeader.VlanId,
                                priority_vlan));
        }
    }
    return priority_vlan;
}

static uint32_t
VNIFCopyNetBuffer(PVNIF_ADAPTER adapter,
                  TCB *tcb,
                  PNET_BUFFER nb)
{
    ULONG       cur_len;
    PUCHAR      pSrc;
    PUCHAR      pDest;
    ULONG       bytes_copied = 0;
    ULONG       offset;
    PMDL        cur_mdl;
    ULONG       data_len;
    uint32_t    adjust;
    uint32_t    loop_cnt;
    uint32_t    mac_len;
    uint16_t    priority_vlan;

    DPRINTK(DPRTL_TRC, ("--> VNIFCopyNetBuffer\n"));

    adjust = adapter->buffer_offset;

    pDest = tcb->data + adjust;
    cur_mdl = NET_BUFFER_FIRST_MDL(nb);
    offset = NET_BUFFER_DATA_OFFSET(nb);
    data_len = NET_BUFFER_DATA_LENGTH(nb);
    DPRINTK(DPRTL_TRC, ("Copy: data len %d.\n", data_len));

    priority_vlan = vnif_get_8021q_info(tcb->nb_list,
                                        adapter->priority_vlan_support);

    mac_len = P8021_TPID_BYTE;
    loop_cnt = 0;
    cur_len = 0;
#ifdef DBG
    if (data_len > max_data_len) {
        PRINTK(("new max_data_len is %d.\n", data_len));
        max_data_len = data_len;
    }
#endif
    while (cur_mdl && data_len > 0) {
        DPRINTK(DPRTL_TRC,
            ("NdisQueryMdl: cnt %d, mdl %p, cl %x, dl %x, off %x, dest %p\n",
            loop_cnt, cur_mdl, cur_len, data_len, offset, pDest));
        NdisQueryMdl(cur_mdl, &pSrc, &cur_len, NormalPagePriority);
        DPRINTK(DPRTL_TRC, ("Copy: mdl len %d.\n", cur_len - offset));
        DPRINTK(DPRTL_TRC, ("              src %p, cl %x\n", pSrc, cur_len));
        if (pSrc == NULL) {
            bytes_copied = 0;
            break;
        }
        /*  Current buffer length is greater than the offset to the buffer. */
        if (cur_len > offset) {
            pSrc += offset;
            cur_len -= offset;

            if (cur_len > data_len) {
                cur_len = data_len;
            }
            data_len -= cur_len;
            DPRINTK(DPRTL_TRC, ("              src %p, dest %p cl %x\n",
                    pSrc, pDest, cur_len));
            /* Check if the priority Vlan info has been handled. */
            if (priority_vlan != 0) {
                DPRINTK(DPRTL_PRI, ("%s: Priority 0x%x\n",
                                    __func__, priority_vlan));
                if (cur_len >= mac_len) {
                    NdisMoveMemory(pDest, pSrc, mac_len);
                    pDest += mac_len;
                    pSrc += mac_len;
                    *(uint16_t *)pDest = P8021_TPID_TYPE;
                    pDest += sizeof(uint16_t);
                    *(uint16_t *)pDest = priority_vlan;
                    pDest += sizeof(uint16_t);
                    bytes_copied += P8021_BYTE_LEN + mac_len;
                    cur_len -= mac_len;
                    mac_len = 0;
                    priority_vlan = 0;
                } else {
                    mac_len -= cur_len;
                }
            }
            NdisMoveMemory(pDest, pSrc, cur_len);
            bytes_copied += cur_len;

            pDest += cur_len;
            offset = 0;
        } else {
            DPRINTK(DPRTL_TRC, ("VNIFCopyNetBuffer: CurrLenght <= offset\n"));
            offset -= cur_len;
        }
        DPRINTK(DPRTL_TRC, ("              NdisGetNextMdl\n"));
        NdisGetNextMdl(cur_mdl, &cur_mdl);
        loop_cnt++;

    }
    DPRINTK(DPRTL_TRC, ("              Done copy\n"));
    if ((bytes_copied != 0) && (bytes_copied < ETH_MIN_PACKET_SIZE)) {
        NdisZeroMemory(pDest, ETH_MIN_PACKET_SIZE - bytes_copied);
        bytes_copied = ETH_MIN_PACKET_SIZE;
    }

    if (*(uint16_t *)(tcb->data + adjust + P8021_TPID_BYTE)
            == P8021_TPID_TYPE) {
        tcb->priority_vlan_adjust = P8021_BYTE_LEN;
#ifdef DBG
        pDest = tcb->data + adjust;
        DPRINTK(DPRTL_PRI, ("CTX [12] %x [13] %x [14] %x [15] %x\n",
                pDest[12], pDest[13], pDest[14], pDest[15]));
#endif
    }

    DPRINTK(DPRTL_TRC, ("<-- VNIFCopyNetBuffer\n"));
#ifdef DBG
    if (data_len != 0) {
        PRINTK(("data_len not 0: %d.\n", data_len));
    }
    if (loop_cnt > max_loop_cnt) {
        PRINTK(("new max loop_cnt is %d.\n", loop_cnt));
        max_loop_cnt = loop_cnt;
    }
#endif
    tcb->sg_cnt = 0;
    return bytes_copied;
}

static __inline UINT
vnif_num_in_list(LIST_ENTRY *list_head, UINT needed)
{
    LIST_ENTRY *list;
    UINT n;

    n = 0;
    list = list_head->Flink;
    while (list != list_head && n < needed) {
        n++;
        list = list->Flink;
    }
    return n;
}

static __inline UINT
vnif_get_mdl_sg_cnt(PMDL mdl)
{

    UINT  array_size;
    UINT sg_cnt;

    sg_cnt = 0;
    array_size = 0;
    while (mdl != NULL) {
        NdisGetMdlPhysicalArraySize(mdl, &array_size);
        sg_cnt += array_size;
        mdl = mdl->Next;
    }
    return sg_cnt;
}

static UINT
vnif_collapse_tx(PVNIF_ADAPTER adapter,
                 TCB *tcb,
                 PMDL mdl,
                 ULONG mdl_offset,
                 ULONG data_len,
                 UINT path_id,
                 uint16_t priority_vlan)
{
    PPFN_NUMBER pfn_list;
    PUCHAR      pSrc;
    PUCHAR      pDest;
    TCB         *cur_tcb;
    TCB         *tail_tcb;
    PFN_NUMBER  pfn;
    ULONG       page_offset;
    ULONG       mdl_len;
    ULONG       bytes_in_page;
    ULONG       dest_len;
    ULONG       cp_len;
    ULONG       len;
    ULONG       adv_len;
    UINT        sg_idx;
    UINT        i;
    BOOLEAN     check_for_vlan;
#ifdef DBG
    UINT        avail_tcbs;

    avail_tcbs = vnif_num_in_list(&adapter->path[path_id].tcb_free_list,
                                  adapter->max_sg_el);
#endif
    NdisQueryMdl(mdl, &pSrc, &mdl_len, NormalPagePriority);
    if (pSrc == NULL) {
        return 0;
    }
    if (mdl_len > mdl_offset) {
        mdl_len -= mdl_offset;
        pSrc += mdl_offset;
    }

    check_for_vlan = adapter->priority_vlan_support ? TRUE : FALSE;
    sg_idx = 0;
    cur_tcb = tcb;
    tail_tcb = tcb;
    pDest = tcb->data + adapter->buffer_offset;
    bytes_in_page = PAGE_SIZE - (adapter->buffer_offset +
                                (priority_vlan ? P8021_BYTE_LEN : 0));
    adv_len = 0;
    dest_len = 0;
    len = 0;

    while (mdl) {
        DPRINTK(DPRTL_LSO,
            ("  Mdl: mdl %p, ml %d, dl %d, off %d\n",
            mdl, mdl_len, data_len, mdl_offset));

        if (mdl_len > data_len) {
            mdl_len = data_len;
        }

        page_offset = (ULONG_PTR)pSrc & (PAGE_SIZE - 1);
        if (priority_vlan == 0
                && ((mdl_len & (PAGE_SIZE - 1)) == 0)
                && dest_len == 0 && page_offset == 0) {
            DPRINTK(DPRTL_LSO, ("  everything aligns.\n"));
            if (check_for_vlan == TRUE) {
                if (*(uint16_t *)(pSrc + P8021_TPID_BYTE) == P8021_TPID_TYPE) {
                    tcb->priority_vlan_adjust = P8021_BYTE_LEN;
                    DPRINTK(DPRTL_PRI,
                            ("%s: vlan embedded in packet page aligned\n",
                             __func__));
                }
                check_for_vlan = FALSE;
            }
            pfn_list = MmGetMdlPfnArray(mdl);
            for (i = 0; len < mdl_len; i++) {
                pfn = pfn_list[i];
                tcb->sg[sg_idx].phys_addr = ((uint64_t)pfn << PAGE_SHIFT);
                tcb->sg[sg_idx].len = PAGE_SIZE;
                tcb->sg[sg_idx].offset = 0;
                tcb->sg[sg_idx].pfn = (ULONG)pfn;
                sg_idx++;
                len += PAGE_SIZE;
            }
        } else {
            while (mdl_len > 0) {
                if (mdl_len > bytes_in_page) {
                    cp_len = bytes_in_page - dest_len;
                } else if (mdl_len < bytes_in_page - dest_len) {
                    cp_len = mdl_len;
                } else {
                    cp_len = bytes_in_page - dest_len;
                }
                DPRINTK(DPRTL_LSO, ("    copy d %p s %p len %d\n",
                                         pDest, pSrc, cp_len));

                if (priority_vlan != 0) {
                    if (dest_len == 0) {
                        if (cp_len >= P8021_TPID_BYTE) {
                            adv_len = P8021_TPID_BYTE;
                            NdisMoveMemory(pDest, pSrc, adv_len);
                        }
                    } else if (dest_len <= ETH_ADDRESS_SIZE) {
                        if (cp_len >= P8021_TPID_BYTE - dest_len) {
                            adv_len = P8021_TPID_BYTE - dest_len;
                            NdisMoveMemory(pDest, pSrc, adv_len);
                        }
                    }
                    if (adv_len != 0) {
                        DPRINTK(DPRTL_PRI,
                            ("mdl_len %d dest_len %d cp_len %d adv_len %d\n",
                            mdl_len, dest_len, cp_len, adv_len));
                        dest_len += adv_len + P8021_BYTE_LEN;
                        len += adv_len + P8021_BYTE_LEN;
                        cp_len -= adv_len;
                        mdl_len -= adv_len;
                        pSrc += adv_len;
                        pDest += adv_len;
                        *(uint16_t *)pDest = P8021_TPID_TYPE;
                        pDest += sizeof(uint16_t);
                        *(uint16_t *)pDest = priority_vlan;
                        pDest += sizeof(uint16_t);
                        priority_vlan = 0;

                        /* Add back the P8021_BYTE_LEN to the page now that
                         * the priority/vlan info has been copyied to the
                         * page and dest_len has included it as well. */
                        bytes_in_page += P8021_BYTE_LEN;
                    }
                }

                if (cp_len != 0) {
                    NdisMoveMemory(pDest, pSrc, cp_len);
                    mdl_len -= cp_len;
                    pDest += cp_len;
                    pSrc += cp_len;
                    dest_len += cp_len;
                    len += cp_len;
                }

                DPRINTK(DPRTL_LSO,
                    ("    cp %p, len %d, dlen %d, tlen %d.\n",
                    cur_tcb->data, cp_len, dest_len, len));

                /* Have we have filled up the current page? */
                if (dest_len == bytes_in_page) {
                    tcb->sg[sg_idx].phys_addr = bytes_in_page == PAGE_SIZE ?
                        cur_tcb->data_pa.QuadPart :
                        cur_tcb->data_pa.QuadPart + adapter->buffer_offset;

                    tcb->sg[sg_idx].len = bytes_in_page;
                    tcb->sg[sg_idx].offset = 0;
                    tcb->sg[sg_idx].pfn =
                        phys_to_mfn(cur_tcb->data_pa.QuadPart);
                    sg_idx++;

                    if (mdl_len) {
                        if (!IsListEmpty(
                                &adapter->path[path_id].tcb_free_list)) {
                            cur_tcb = (TCB *)RemoveHeadList(
                                &adapter->path[path_id].tcb_free_list);
                            cur_tcb->next = NULL;
                            pDest = cur_tcb->data;
                            bytes_in_page = PAGE_SIZE;
                            dest_len = 0;
                            tail_tcb->next = cur_tcb;
                            tail_tcb = cur_tcb;
                        } else {
                            DPRINTK(DPRTL_ON,
                                    ("%s: available tcbs at start %d\n",
                                    __func__, avail_tcbs));
                            return 0;
                        }
                    }
                }
            }
        }
        NdisGetNextMdl(mdl, &mdl);
        if (mdl) {
            NdisQueryMdl(mdl, &pSrc, &mdl_len, NormalPagePriority);
            if (pSrc == NULL) {
                PRINTK(("%s: failed to get src from mdl\n", __func__));
                return 0;
            }
            DPRINTK(DPRTL_PRI,
                    ("Gertting next mld of length %d cur dest_len %d\n",
                    mdl_len, dest_len));
        }
    }

    if (dest_len) {
        DPRINTK(DPRTL_LSO,
            ("vnif_collapse_tx out: dlen %d, tlen %d sg_idx %d.\n",
            dest_len, len, sg_idx));
        if (sg_idx == 0) {
            tcb->sg[sg_idx].phys_addr =
                cur_tcb->data_pa.QuadPart + adapter->buffer_offset;
            tcb->sg[sg_idx].offset = adapter->buffer_offset;
        } else {
            tcb->sg[sg_idx].phys_addr = cur_tcb->data_pa.QuadPart;
            tcb->sg[sg_idx].offset = 0;
        }
        tcb->sg[sg_idx].len = dest_len;
        tcb->sg[sg_idx].pfn = phys_to_mfn(cur_tcb->data_pa.QuadPart);
        sg_idx++;
    }

    if (check_for_vlan == TRUE) {
        if (*(uint16_t *)(tcb->data + adapter->buffer_offset + P8021_TPID_BYTE)
                == P8021_TPID_TYPE) {
            DPRINTK(DPRTL_PRI, ("collapse setting tcb vlan adjust\n"));
            tcb->priority_vlan_adjust = P8021_BYTE_LEN;
        }
    }

#ifdef DBG
    if (data_len + (adv_len ? P8021_BYTE_LEN : 0) != len) {
        dest_len = 0;
        PRINTK(("vnif_collapse_tx: len != data_len, %d %d\n", len, data_len));
        for (i = 0; i < sg_idx; i++) {
            dest_len += tcb->sg[i].len;
            PRINTK(("  sg[%d].len = %d, dest_len %d\n",
                i, tcb->sg[i].len, dest_len));
        }
    }
    DPRINTK(DPRTL_LSO, ("vnif_collapse_tx: len %d\n", len));
    dest_len = 0;
    for (i = 0; i < sg_idx; i++) {
        dest_len += tcb->sg[i].len;
        DPRINTK(DPRTL_LSO, ("  sg[%d].len = %d, dest_len %d\n",
            i, tcb->sg[i].len, dest_len));
    }
#endif

    tcb->sg_cnt = sg_idx;
    return len;
}

static void
vnif_gso_chksum(TCB *tcb, PMDL mdl, ULONG mdl_offset, ULONG data_len)
{
    PUCHAR      pSrc;
    PUCHAR      tcp_hdr;
    PUCHAR      ip_hdr;
    ULONG       mdl_len;
    UINT        loop_cnt;
    UINT        vlan_adjust;
    uint16_t    ip_hdr_len;

    tcb->ip_hdr_len = IP_HEADER_SIZE_VAL;
    tcb->tcp_hdr_len = 0;
    tcp_hdr = NULL;
    ip_hdr = NULL;
    ip_hdr_len = IP_HEADER_SIZE_VAL;
    vlan_adjust = 0;
    loop_cnt = 0;
    while (mdl && data_len > 0 && loop_cnt <= 2 && tcp_hdr == NULL) {
        pSrc = MmGetMdlVirtualAddress(mdl);
        mdl_len = MmGetMdlByteCount(mdl);
        if (mdl_len > mdl_offset) {
            mdl_len -= mdl_offset;
            pSrc += mdl_offset;
        }

        DPRINTK(DPRTL_TRC,
            ("Mdl: cnt %d, mdl %p, cl %d, dl %d, off %d\n",
            loop_cnt, mdl, mdl_len, data_len, mdl_offset));

        if (mdl_len > data_len) {
            mdl_len = data_len;
        }

        if (loop_cnt == 0) {
            if (mdl_len >= P8021_TPID_BYTE + P8021_BYTE_LEN) {
                if (*(uint16_t *)(pSrc + P8021_TPID_BYTE) == P8021_TPID_TYPE) {
                    vlan_adjust = P8021_BYTE_LEN;
                }
                if (mdl_len >= ETH_HEADER_SIZE + IP_HEADER_SIZE_VAL) {
                    ip_hdr = pSrc + vlan_adjust + ETH_HEADER_SIZE;
                    ip_hdr_len = get_ip_hdr_len(ip_hdr,
                        mdl_len - (vlan_adjust + ETH_HEADER_SIZE));
                }
                if (mdl_len >= (ULONG)(ETH_HEADER_SIZE
                                       + ip_hdr_len
                                       + TCP_HEADER_SIZE)) {
                    tcp_hdr = pSrc + ETH_HEADER_SIZE + vlan_adjust + ip_hdr_len;
                }
            }
        } else if (loop_cnt == 1) {
            if (ip_hdr == NULL) {
                if (vlan_adjust == 0 && *(uint16_t *)pSrc == P8021_TPID_TYPE) {
                    vlan_adjust = P8021_BYTE_LEN;
                }
                ip_hdr = pSrc + vlan_adjust;
                ip_hdr_len = get_ip_hdr_len(ip_hdr,
                    mdl_len - (vlan_adjust + ETH_HEADER_SIZE));
            }
            if (mdl_len >= (ULONG)(ip_hdr_len + TCP_HEADER_SIZE)) {
                tcp_hdr = pSrc + vlan_adjust + ip_hdr_len;
            }
        } else {
            tcp_hdr = pSrc;
        }

        if (tcp_hdr != NULL && ip_hdr != NULL) {
            vnif_gos_hdr_update(tcb, ip_hdr, tcp_hdr, ip_hdr_len, data_len);
            break;
        } else {
            NdisGetNextMdl(mdl, &mdl);
            if (mdl) {
                mdl_offset = MmGetMdlByteOffset(mdl);
            }
        }
        loop_cnt++;
    }

#ifdef DBG
    if (ip_hdr == NULL) {
        PRINTK(("vnif_gso_chksum: failed to find IP header.\n"));
    }
#endif
}

static UINT
vnif_build_sg(PVNIF_ADAPTER adapter, UINT path_id, TCB *tcb, UINT sg_cnt)
{
    VNIF_GSO_INFO gso_info;
    PPFN_NUMBER pfn_list;
    PUCHAR      pSrc;
    PUCHAR      pDest;
    PFN_NUMBER  pfn;
    PMDL        mdl;
    ULONG       mdl_offset;
    ULONG       data_len;
    ULONG       mdl_len;
    ULONG       len_inc;
    ULONG       len;
    ULONG       cur_pos;
    ULONG       bytes_copied;
    ULONG       page_offset;
    UINT        sg_idx;
    UINT        adv_len;
    UINT        i;
    UINT        cp_len;
    uint16_t priority_vlan;
#ifdef DBG
    PMDL        org_mdl;
    ULONG       org_mdl_offset;
    ULONG       org_data_len;
#endif

    mdl = NET_BUFFER_FIRST_MDL(tcb->nb);
    mdl_offset = NET_BUFFER_DATA_OFFSET(tcb->nb);
    data_len = NET_BUFFER_DATA_LENGTH(tcb->nb);

    priority_vlan = vnif_get_8021q_info(tcb->nb_list,
                                        adapter->priority_vlan_support);
    if (priority_vlan) {
        sg_cnt++;   /* one for the vlan info */
    }

    VNIF_GET_GOS_INFO(tcb, gso_info);

    DPRINTK(DPRTL_TRC, ("--> vnif_build_sg, offset %d, len %d, gos %p\n",
        mdl_offset, data_len, gso_info.Value));

    if (gso_info.Value) {
        vnif_gso_chksum(tcb, mdl, mdl_offset, data_len);
    }

    if (sg_cnt >= adapter->max_sg_el) {
        DPRINTK(DPRTL_UNEXPDTX,
            ("%s: need to do vnif_collapse_tx: len %d sg_cnt = %d needed %d.\n",
             __func__,
             data_len,
             sg_cnt,
             vnif_num_in_list(&adapter->path[path_id].tcb_free_list, sg_cnt)));
        bytes_copied = vnif_collapse_tx(adapter, tcb, mdl, mdl_offset,
                                        data_len, path_id, priority_vlan);
        return bytes_copied;
    }

#ifdef DBG
    org_mdl = mdl;
    org_mdl_offset = mdl_offset;
    org_data_len = data_len;
#endif
    pSrc = NULL;
    bytes_copied = 0;
    sg_idx = 0;

    if (mdl) {
        pSrc = MmGetMdlVirtualAddress(mdl);
        mdl_len = MmGetMdlByteCount(mdl);
        if (mdl_len > mdl_offset) {
            mdl_len -= mdl_offset;
            pSrc += mdl_offset;
        }
    }

    if (priority_vlan != 0) {
        pDest = tcb->data + adapter->buffer_offset;
        tcb->sg[0].phys_addr = tcb->data_pa.QuadPart + adapter->buffer_offset;
        tcb->sg[0].len = P8021_TPID_BYTE + P8021_BYTE_LEN;
        tcb->sg[0].offset = adapter->buffer_offset;
        tcb->sg[0].pfn = phys_to_mfn(tcb->data_pa.QuadPart);
        cp_len = 0;
        adv_len = 0;
        do {
            if (cp_len == 0) {
                if (mdl_len >= P8021_TPID_BYTE) {
                    cp_len = P8021_TPID_BYTE;
                } else {
                    cp_len = mdl_len;
                }
                adv_len = cp_len;
            } else {
                adv_len = P8021_TPID_BYTE - cp_len;
                cp_len += adv_len;
            }
            NdisMoveMemory(pDest, pSrc, adv_len);
            pSrc += adv_len;
            pDest += adv_len;
            mdl_offset += adv_len;
            mdl_len -= adv_len;

            if (cp_len == P8021_TPID_BYTE ) {
                *(uint16_t *)pDest = P8021_TPID_TYPE;
                pDest += sizeof(uint16_t);
                *(uint16_t *)pDest = priority_vlan;
                pDest += sizeof(uint16_t);
                priority_vlan = 0;
            }

            if (mdl_len == 0) {
                NdisGetNextMdl(mdl, &mdl);
                if (mdl) {
                    mdl_offset = MmGetMdlByteOffset(mdl);
                    pSrc = MmGetMdlVirtualAddress(mdl);
                    mdl_len = MmGetMdlByteCount(mdl);
                    DPRINTK(DPRTL_TRC,
                        ("Next: src %x, off %d, pg off %d, pp_ff %d, len %d.\n",
                        pSrc, mdl_offset, (ULONG_PTR)pSrc & (PAGE_SIZE - 1),
                        (ULONG_PTR)(pSrc + mdl_offset) & (PAGE_SIZE - 1),
                        mdl_len));
                }
            }
        } while (priority_vlan != 0);
        sg_idx++;
        data_len -= P8021_TPID_BYTE + P8021_BYTE_LEN;
        bytes_copied += P8021_TPID_BYTE + P8021_BYTE_LEN;
    }

    while (mdl && data_len > 0 && sg_idx < adapter->max_sg_el) {
        DPRINTK(DPRTL_TRC,
            ("Mdl: sg_idx %d, mdl %p, cl %d, dl %d, off %d\n",
            sg_idx, mdl, mdl_len, data_len, mdl_offset));

        if (mdl_len > data_len) {
            mdl_len = data_len;
        }

        pfn_list = MmGetMdlPfnArray(mdl);
        page_offset = (ULONG_PTR)pSrc & (PAGE_SIZE - 1);
        cur_pos = mdl_offset;
        len = 0;
        for (i = 0; len < mdl_len && sg_idx < adapter->max_sg_el; i++) {
            if (len + PAGE_SIZE - page_offset < mdl_len) {
                len_inc = PAGE_SIZE - page_offset;
            } else {
                len_inc = mdl_len - len;
            }

            pfn = pfn_list[i];
            tcb->sg[sg_idx].phys_addr =
                ((uint64_t)pfn << PAGE_SHIFT) + page_offset;
            tcb->sg[sg_idx].len = len_inc;
            tcb->sg[sg_idx].offset = page_offset;
            tcb->sg[sg_idx].pfn = (ULONG)pfn;

            DPRINTK(DPRTL_TRC,
                ("%x: i %d sg %d pfn[%d] %x addr %x off %d len %d\n",
                adapter->CurrentAddress[MAC_LAST_DIGIT],
                i,
                sg_idx,
                cur_pos >> PAGE_SHIFT,
                tcb->sg[sg_idx].pfn,
                (uint32_t)tcb->sg[sg_idx].phys_addr,
                tcb->sg[sg_idx].offset,
                tcb->sg[sg_idx].len));

            sg_idx++;
            len += len_inc;
            cur_pos += len_inc;
            pSrc += len_inc;
            page_offset = (ULONG_PTR)pSrc & (PAGE_SIZE - 1);
        }

        if (sg_idx <= adapter->max_sg_el) {
            data_len -= mdl_len;
            bytes_copied += mdl_len;

            NdisGetNextMdl(mdl, &mdl);
            if (mdl) {
                mdl_offset = MmGetMdlByteOffset(mdl);
                pSrc = MmGetMdlVirtualAddress(mdl);
                mdl_len = MmGetMdlByteCount(mdl);
                DPRINTK(DPRTL_TRC,
                    ("Next: psrc %x, offset %d, pg off %d, pp_ff %d, len %d.\n",
                    pSrc, mdl_offset, (ULONG_PTR)pSrc & (PAGE_SIZE - 1),
                    (ULONG_PTR)(pSrc + mdl_offset) & (PAGE_SIZE - 1),
                    mdl_len));
            }
        }
    }
    tcb->sg_cnt = sg_idx;

#ifdef DBG
    if (sg_idx < adapter->max_sg_el) {
        if (data_len != 0) {
            PRINTK(("data_len not 0: %d.\n", data_len));
        }
    } else {
        PRINTK(("******** sg_idx %d sg_cnt %d data_len %d %d **************\n",
                sg_idx, vnif_get_mdl_sg_cnt(org_mdl), org_data_len, data_len));
        PRINTK(
            ("Need to do vnif_collapse_tx: len %d sg_idx = %d needed %d.\n",
             org_data_len,
             sg_idx,
             vnif_num_in_list(&adapter->path[path_id].tcb_free_list, sg_idx)));
    }
#endif

    DPRINTK(DPRTL_TRC, ("<-- vnif_build_sg\n"));
    return bytes_copied;
}

NDIS_STATUS
VNIFSendNetBufferList(PVNIF_ADAPTER adapter,
    PNET_BUFFER_LIST nb_list,
    UINT path_id,
    BOOLEAN bFromQueue,
    BOOLEAN dispatch_level)
{
    NDIS_STATUS     status;
    NDIS_STATUS     send_status;
    TCB             *tcb;
    TCB             *ftcb;
    ULONG           bytes_copied;
    PNET_BUFFER     nb_to_send;
    PNET_BUFFER     nb;
    uint32_t        len;
    int             notify;
    UINT            i;
    UINT            sg_cnt;
    UINT            avail_tcbs;
    UINT            needed_tcbs;
    UINT            nb_len;
    uint16_t        flags;

    status = NDIS_STATUS_PENDING;
    send_status = NDIS_STATUS_SUCCESS;

    if (bFromQueue) {
        DPRINTK(DPRTL_TX, ("** Processing from Queue.\n"));
        nb_to_send = VNIF_GET_NET_BUFFER_LIST_NEXT_SEND(nb_list);
        VNIF_GET_NET_BUFFER_LIST_NEXT_SEND(nb_list) = NULL;
    } else {
        nb_to_send = NET_BUFFER_LIST_FIRST_NB(nb_list);
    }

    flags = 0;
    if (adapter->cur_tx_tasks) {
        send_status = should_checksum_tx(adapter, nb_list, &flags);
    }

    tcb = NULL;
    for (;
          nb_to_send != NULL && send_status == NDIS_STATUS_SUCCESS;
          nb_to_send = NET_BUFFER_NEXT_NB(nb_to_send)) {

        nb_len = NET_BUFFER_DATA_LENGTH(nb_to_send);

        if (VRING_CAN_ADD_TX(
                adapter,
                path_id,
                ((adapter->b_indirect || nb_len <= ETH_MAX_PACKET_SIZE) ?
                    MIN_FREE_CP_TX_SLOTS : adapter->max_sg_el)) == 0) {
            DPRINTK(DPRTL_UNEXPDTX,
                ("%s[%d]: not enough slots %d, pkt len %d\n",
                 __func__, path_id,
                 VNIF_RING_FREE_REQUESTS(adapter, path_id),
                 NET_BUFFER_DATA_LENGTH(nb_to_send)));
            status = NDIS_STATUS_RESOURCES;
            break;
        }

        sg_cnt = vnif_get_mdl_sg_cnt(NET_BUFFER_FIRST_MDL(nb_to_send));
        if (nb_len > (PAGE_SIZE
                      - P8021_BYTE_LEN  /* Potential vlan info */
                      - adapter->buffer_offset)) {
            if (sg_cnt > adapter->max_sg_el) {
                needed_tcbs = (nb_len / (PAGE_SIZE - adapter->buffer_offset))
                              + 1;
                avail_tcbs =
                    vnif_num_in_list(&adapter->path[path_id].tcb_free_list,
                                     needed_tcbs);
                if (needed_tcbs > avail_tcbs) {
                    DPRINTK(DPRTL_UNEXPD, ("%s: nl_len %d sg_cnt %d ",
                            __func__, nb_len, sg_cnt));
                    DPRINTK(DPRTL_UNEXPD, ("avail tcbs %d needed tcbs %d\n",
                            avail_tcbs, needed_tcbs));
                    status = NDIS_STATUS_RESOURCES;
                    break;
                }
            }
        }

        if (!IsListEmpty(&adapter->path[path_id].tcb_free_list)) {
            tcb = (TCB *)RemoveHeadList(&adapter->path[path_id].tcb_free_list);
        }

        if (tcb == NULL) {
            DPRINTK(DPRTL_UNEXPD, ("** Ran out of tcbs.\n"));
            status = NDIS_STATUS_RESOURCES;
            break;
        }

        tcb->next = NULL;
        tcb->adapter = adapter;
        tcb->nb = nb_to_send;
        tcb->nb_list = nb_list;
        tcb->priority_vlan_adjust = 0;

        VNIFInterlockedIncrement(adapter->nBusySend);
        VNIFIncStat(adapter->pv_stats->tx_pkt_cnt);

        if (nb_len <= ETH_MAX_PACKET_SIZE
                || (sg_cnt > adapter->max_sg_el
                    && nb_len < (PAGE_SIZE
                                 - P8021_BYTE_LEN  /* potential vlan space */
                                 - adapter->buffer_offset))) {
            len = VNIFCopyNetBuffer(adapter, tcb, nb_to_send);
        } else {
            len = vnif_build_sg(adapter, path_id, tcb, sg_cnt);

            if (adapter->cur_tx_tasks & (VNIF_CHKSUM_IPV4_TCP
                                         | VNIF_CHKSUM_IPV6_TCP)) {
                flags |= NETTXF_data_validated | NETTXF_csum_blank;
            }
        }

#ifdef DBG
        if (sg_cnt > max_sg_cnt) {
            PRINTK(("max_sg_cnt %d\n", sg_cnt));
            max_sg_cnt = sg_cnt;
        }
        if (len > max_pkt_len) {
            PRINTK(("max_pkt_len %d\n", len));
            max_pkt_len = len;
        }
#endif

        if (len) {
            VNIF_TRACK_TX_SET(tcb->len, len);

            DPRINTK(DPRTL_TX, ("%s[%d]: add tcb %p\n",
                                __func__, path_id, tcb));

            /* Send the packet. */
            VNIF_GET_TX_REQ_PROD_PVT(adapter, path_id, &i);
            vnif_add_tx(adapter,
                        path_id,
                        tcb,
                        len,
                        NET_BUFFER_DATA_LENGTH(nb_to_send),
                        flags,
                        &i);
            VNIF_SET_TX_REQ_PROD_PVT(adapter, path_id, i);

            tcb = NULL;
        } else {
            PRINTK(("%s: NetBuffer %p failed data prep for length %d.\n",
                __func__, nb_to_send, NET_BUFFER_DATA_LENGTH(nb_to_send)));
            send_status = NDIS_STATUS_INVALID_LENGTH;
            break;
        }
    } /* for */

    /* tcb is non-null if there was an error and couldn't send it. */
    while (tcb != NULL) {
        tcb->nb = NULL;
        tcb->nb_list = NULL;
        ftcb = tcb;
        tcb = tcb->next;
        ftcb->next = NULL;
        InsertHeadList(&adapter->path[path_id].tcb_free_list, &ftcb->list);
        VNIFInterlockedDecrement(adapter->nBusySend);
    }

    if (status == NDIS_STATUS_RESOURCES) {
        /* Save off the buffer we are currently trying to send. */
        VNIF_GET_NET_BUFFER_LIST_NEXT_SEND(nb_list) = nb_to_send;

        if (!bFromQueue) {
            /* We didn't process nb_list form the queue, so put it on. */
            DPRINTK(DPRTL_UNEXPD,
                ("VNIFSendNetBufferList: InsHeadQueue SendWait nbl %p\n",
                VNIF_GET_NET_BUFFER_LIST_LINK(nb_list)));
            InsertHeadQueue(&adapter->path[path_id].send_wait_queue,
                VNIF_GET_NET_BUFFER_LIST_LINK(nb_list));
            adapter->nWaitSend++;
        }
        adapter->path[path_id].sending_nbl = NULL;
    }

    /*
     * All the NetBuffers in the NetBufferList has been processed,
     * If the NetBufferList is in queue now, dequeue it.
     */
    if (nb_to_send == NULL) {
        if (bFromQueue) {
            DPRINTK(DPRTL_TX,
                ("** VNIFSendNetBufferList: RemoveHeadQueue SendWait nbl %p\n",
                GetHeadQueue(&adapter->path[path_id].send_wait_queue)));
            RemoveHeadQueue(&adapter->path[path_id].send_wait_queue);
            adapter->nWaitSend--;
        }
        adapter->path[path_id].sending_nbl = NULL;
    } else {
        DPRINTK(DPRTL_UNEXPDTX, ("** Didn't finish sending the nb_to_send.\n"));
    }

    /*
     * As far as the miniport knows, the NetBufferList has been sent out.
     * Complete the NetBufferList now.  Error case.
     *
     * This only happens if the first net buffer fials.
     */
    if (send_status != NDIS_STATUS_SUCCESS) {
        for (; nb_to_send != NULL;
            nb_to_send = NET_BUFFER_NEXT_NB(nb_to_send)) {
            VNIF_GET_NET_BUFFER_LIST_REF_COUNT(nb_list)--;
        }
        PRINTK(("VNIFSendNetBufferList: failed, should complete, cnt %x.\n",
            VNIF_GET_NET_BUFFER_LIST_REF_COUNT(nb_list)));

        NET_BUFFER_LIST_STATUS(nb_list) = send_status;
        if (VNIF_GET_NET_BUFFER_LIST_REF_COUNT(nb_list) == 0) {
            VNIF_RELEASE_SPIN_LOCK(&adapter->path[path_id].tx_path_lock,
                                   dispatch_level);
            NET_BUFFER_LIST_NEXT_NBL(nb_list) = NULL;
            PRINTK(("VNIFSendNetBufferList: failed, now completing.\n"));
            NdisMSendNetBufferListsComplete(
                adapter->AdapterHandle,
                nb_list,
                NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
            VNIF_ACQUIRE_SPIN_LOCK(&adapter->path[path_id].tx_path_lock,
                                   dispatch_level);
        } else {
            PRINTK(("VNIFSendNetBufferList: failed, not completing %x.\n",
                VNIF_GET_NET_BUFFER_LIST_REF_COUNT(nb_list)));
        }
    }

    vnif_notify_always_tx(adapter, path_id);

    DPRINTK(DPRTL_TX,  ("<-- VNIFSendNetBufferList\n"));
    return status;

}

static PNET_BUFFER_LIST
vnif_free_send_net_buffer(PVNIF_ADAPTER adapter, TCB *tcb)
{

    PNET_BUFFER         nb;
    PNET_BUFFER_LIST    nb_list;
    TCB                 *return_tcb;

    nb = tcb->nb;
    nb_list = tcb->nb_list;
    tcb->nb = NULL;
    tcb->nb_list = NULL;

    VNIFInterlockedDecrement(adapter->nBusySend);
    ASSERT(adapter->nBusySend >= 0);

    if (nb_list) {
        VNIF_GET_NET_BUFFER_LIST_REF_COUNT(nb_list)--;
        if (VNIF_GET_NET_BUFFER_LIST_REF_COUNT(nb_list) == 0) {
            DPRINTK(DPRTL_TX, ("Completing NetBufferList= %p\n", nb_list));
            NET_BUFFER_LIST_NEXT_NBL(nb_list) = NULL;
            return nb_list;
        }
        DPRINTK(DPRTL_TX,
            ("** MP_FREE_SEND_NET_BUFFER: nb_list not done %p\n", nb_list));
    }

    return NULL;
}

/* SendLock is held */
static void
vnif_free_send_tcbs(PVNIF_ADAPTER adapter, TCB *tcb, UINT path_id)
{
    TCB *ftcb;
    TCB *tcb_list;
    TCB *return_tcb;

    tcb_list = tcb;
    while (tcb_list != NULL) {
        ftcb = tcb_list;
        tcb_list = tcb_list->next_free;
        while (ftcb) {
            return_tcb = ftcb;
            ftcb = ftcb->next;
            return_tcb->next = NULL;
            InsertHeadList(&adapter->path[path_id].tcb_free_list,
                           &return_tcb->list);
        }
    }
}

static void
vnif_send_status(PVNIF_ADAPTER adapter, PNET_BUFFER NetBuffer, int16_t status)
{
    PUCHAR  EthHeader;
    ULONG   Length;
    PMDL    Mdl = NET_BUFFER_CURRENT_MDL(NetBuffer);

    NdisQueryMdl(Mdl, &EthHeader, &Length, NormalPagePriority);
    if (EthHeader != NULL) {
        EthHeader += NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);
        if (ETH_IS_BROADCAST(EthHeader)) {
            adapter->ifHCOutBroadcastPkts++;
            adapter->ifHCOutBroadcastOctets +=
                NET_BUFFER_DATA_LENGTH(NetBuffer);
        } else if (ETH_IS_MULTICAST(EthHeader)) {
            adapter->ifHCOutMulticastPkts++;
            adapter->ifHCOutMulticastOctets +=
                NET_BUFFER_DATA_LENGTH(NetBuffer);
        } else {
            adapter->ifHCOutUcastPkts++;
            adapter->ifHCOutUcastOctets += NET_BUFFER_DATA_LENGTH(NetBuffer);
        }
    }
    if (status != NETIF_RSP_OKAY) {
        if (status == NETIF_RSP_ERROR) {
            adapter->ifOutErrors++;
        }
        if (status == NETIF_RSP_DROPPED) {
            adapter->ifOutDiscards++;
        }
        PRINTK(("VNIF: status %d, send errors %d, dropped %d.\n",
            status, adapter->ifOutErrors, adapter->ifOutDiscards));
    }
}

int
VNIFCheckSendCompletion(PVNIF_ADAPTER adapter, UINT path_id)
{
    NDIS_STATUS         status = NDIS_STATUS_SUCCESS;
    PNET_BUFFER_LIST    nb_list;
    PNET_BUFFER_LIST    last_nb_list = NULL;
    PNET_BUFFER_LIST    complete_nb_lists = NULL;
    PQUEUE_ENTRY pEntry;
    TCB *tcb;
    TCB *tcb_to_free;
    UINT cons, prod;
    UINT i;
    UINT len;
    UINT cnt;
    UINT txstatus;

    DPRINTK(DPRTL_TX, ("---> VNIFCheckSendCompletion\n"));
    NdisDprAcquireSpinLock(&adapter->path[path_id].tx_path_lock);

    cnt = 0;
    prod = 0;
    tcb_to_free = NULL;

    /* Any packets being sent? Any packet waiting in the send queue? */
    if (adapter->nBusySend == 0 &&
        IsQueueEmpty(&adapter->path[path_id].send_wait_queue)) {
        DPRINTK(DPRTL_TX, ("<--- VNIFCheckSendCompletion: nothing to chk\n"));
        NdisDprReleaseSpinLock(&adapter->path[path_id].tx_path_lock);
        return 0;
    }

    /* Check the first TCB on the send list */
    do {
        VNIF_GET_TX_RSP_PROD(adapter, path_id, &prod);
        KeMemoryBarrier();

        VNIF_GET_TX_RSP_CONS(adapter, path_id, &cons);
        while ((tcb = vnif_get_tx(adapter, path_id, &cons, prod, cnt,
                                  &len, &txstatus)) != NULL) {
#ifdef DBG
            if (!VNIF_IS_READY(adapter)) {
                DPRINTK(DPRTL_ON,
                    ("VNIFCheckSendCompletion: not ready %p\n", tcb));
            }
#endif
            cnt++;

            /* nb and nb_list will be NULL for a gratuitous ARP packet. */
            if (tcb->nb) {
                vnif_send_status(adapter, tcb->nb, (int16_t)txstatus);
            }

            if (tcb_to_free == NULL) {
                tcb->next_free = NULL;
            } else {
                tcb->next_free = tcb_to_free;
            }
            tcb_to_free = tcb;
            nb_list = vnif_free_send_net_buffer(adapter, tcb);

            DPRINTK(DPRTL_TX, ("%s[%d]: tcb %p, nbl %p, cnt %d.\n",
                __func__, path_id, tcb, nb_list, cnt));

            if (nb_list != NULL) {
                NET_BUFFER_LIST_STATUS(nb_list) = NDIS_STATUS_SUCCESS;
                if (complete_nb_lists == NULL) {
                    complete_nb_lists = nb_list;
                } else {
                    NET_BUFFER_LIST_NEXT_NBL(last_nb_list) = nb_list;
                }
                NET_BUFFER_LIST_NEXT_NBL(nb_list) = NULL;
                last_nb_list = nb_list;
            }
        }
        VNIF_SET_TX_RSP_CONS(adapter, path_id, prod);

        /*
         * Set a new event, then check for race with update of tx_cons.
         * Note that it is essential to schedule a callback, no matter
         * how few buffers are pending. Even if there is space in the
         * transmit ring, higher layers may be blocked because too much
         * data is outstanding: in such cases notification from Xen is
         * likely to be the only kick that we'll get.
         */
        VNIF_SET_TX_EVENT(adapter, path_id, prod);
        KeMemoryBarrier();
    } while (VNIF_HAS_UNCONSUMED_RESPONSES(adapter->path[path_id].tx,
                                           cons,
                                           prod));

    vnif_free_send_tcbs(adapter, tcb_to_free, path_id);

    /* If we queued any transmits because we didn't have any TCBs earlier,
     * dequeue and send those packets now, as long as we have free TCBs.
     */
    if (VNIF_IS_READY(adapter)) {
        while (adapter->path[path_id].sending_nbl == NULL
               && !IsListEmpty(&adapter->path[path_id].tcb_free_list)
               && !IsQueueEmpty(&adapter->path[path_id].send_wait_queue)) {

            /* We cannot remove it now, we just need to get the head */
            pEntry = GetHeadQueue(&adapter->path[path_id].send_wait_queue);
            ASSERT(pEntry);
            DPRINTK(DPRTL_TX,
                ("VNIFCheckSendCompletion: GetHeadQueue SendWait %p\n",
                pEntry));
            DPRINTK(DPRTL_TX,
                (":\t SendWait empty %d, SendFree empty %d, Sending %p\n",
                IsQueueEmpty(&adapter->path[path_id].send_wait_queue),
                IsListEmpty(&adapter->path[path_id].tcb_free_list),
                adapter->path[path_id].sending_nbl));
            nb_list = VNIF_GET_NET_BUFFER_LIST_FROM_QUEUE_LINK(pEntry);
            adapter->path[path_id].sending_nbl = nb_list;

            status = VNIFSendNetBufferList(adapter,
                                           nb_list,
                                           path_id,
                                           TRUE,
                                           TRUE);
            if (status != NDIS_STATUS_SUCCESS &&
                status != NDIS_STATUS_PENDING) {
                break;
            }
        }
    }
    NdisDprReleaseSpinLock(&adapter->path[path_id].tx_path_lock);

    /* Complete the NET_BUFFER_LISTs */
    if (complete_nb_lists != NULL) {
        NdisMSendNetBufferListsComplete(
                adapter->AdapterHandle,
                complete_nb_lists,
                NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);

    }
    DPRINTK(DPRTL_TX, ("<--- VNIFCheckSendCompletion\n"));
    return (int)cnt;
}

VOID
MpProcessSGList(
    IN  PDEVICE_OBJECT          pDO,
    IN  PVOID                   pIrp,
    IN  PSCATTER_GATHER_LIST    pSGList,
    IN  PVOID                   tcb)
{
}

void
MPSendNetBufferLists(
    NDIS_HANDLE adptr_ctx,
    PNET_BUFFER_LIST nb_list,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags)
{

    PVNIF_ADAPTER adapter;
    NDIS_STATUS status = NDIS_STATUS_PENDING;
    UINT nb_cnt = 0;
    UINT path_id;
    UINT old_path_id;
    PNET_BUFFER nb;
    PNET_BUFFER_LIST cur_nb_list;
    PNET_BUFFER_LIST next_nb_list;
    BOOLEAN dispatch_level;

    DPRINTK(DPRTL_TX, ("MPSendNetBufferLists IN.\n"));
    adapter = (PVNIF_ADAPTER)adptr_ctx;
#ifdef DBG
    if (adapter == NULL) {
        PRINTK(("MPSendNetBufferLists: received null adapter\n"));
        return;
    }
    if (adapter->dbg_print_cnt < vnif_send_print_cnt) {
        DPRINTK(DPRTL_ON,
            ("MPSendNetBufferLists: starting send, dbg prnt %p, %s %d\n",
            adapter, adapter->node_name, adapter->dbg_print_cnt));
        adapter->dbg_print_cnt++;
    }
#endif

    dispatch_level = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags);
    do {
        if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_PAUSING | VNF_ADAPTER_PAUSED)) {
            status =  NDIS_STATUS_PAUSED;
            PRINTK(("MPSendNetBufferLists: adapter paused %x.\n",
                    adapter->adapter_flags));
            break;
        }

        /* Is this adapter ready for sending? */
        if (VNIF_IS_NOT_READY(adapter)) {
            status = VNIF_GET_STATUS_FROM_FLAGS(adapter);

            DPRINTK(DPRTL_ON,
                    ("MPSendNetBufferLists: not ready, f = %x, s = %x.\n",
                     adapter->adapter_flags, status));
            break;
        }

        /*
         * Adapter is ready, send this net buffer list, in this case,
         * we always return pending
         */
        old_path_id = (UINT)-1;
        for (cur_nb_list = nb_list;
                cur_nb_list != NULL;
                cur_nb_list = next_nb_list) {

            VNIF_RSS_2_QUEUE_MAP(adapter, cur_nb_list, path_id);

            if (old_path_id != path_id) {
                if (old_path_id != (UINT)-1) {
                    VNIF_RELEASE_SPIN_LOCK(
                        &adapter->path[old_path_id].tx_path_lock,
                        dispatch_level);
                }
                old_path_id = path_id;
                VNIF_ACQUIRE_SPIN_LOCK(&adapter->path[path_id].tx_path_lock,
                                       dispatch_level);
            }

            next_nb_list = NET_BUFFER_LIST_NEXT_NBL(cur_nb_list);
            NET_BUFFER_LIST_NEXT_NBL(cur_nb_list) = NULL;
            nb_cnt = 0;
            for (nb = NET_BUFFER_LIST_FIRST_NB(cur_nb_list);
                    nb != NULL;
                    nb = NET_BUFFER_NEXT_NB(nb)) {
                nb_cnt++;
            }
            ASSERT(nb_cnt > 0);
            VNIF_GET_NET_BUFFER_LIST_REF_COUNT(cur_nb_list) = nb_cnt;
            /*
             * Queue is not empty or tcb is not available, or another
             * thread is sending a NetBufferList.
             */
            if (!IsQueueEmpty(&adapter->path[path_id].send_wait_queue) ||
                IsListEmpty(&adapter->path[path_id].tcb_free_list) ||
                adapter->path[path_id].sending_nbl != NULL) {
                /* The first net buffer is the buffer to send */
                VNIF_GET_NET_BUFFER_LIST_NEXT_SEND(cur_nb_list) =
                    NET_BUFFER_LIST_FIRST_NB(cur_nb_list);
                NET_BUFFER_LIST_STATUS(cur_nb_list) = NDIS_STATUS_SUCCESS;
                DPRINTK(DPRTL_TX,
                    ("** MPSendNetBufferLists: InsertTailQueue SendWait %p\n",
                    VNIF_GET_NET_BUFFER_LIST_LINK(cur_nb_list)));
                DPRINTK(DPRTL_TX,
                    ("\t SndWait empty %d, SndFree empty %d, Sending %p\n",
                    IsQueueEmpty(&adapter->path[path_id].send_wait_queue),
                    IsListEmpty(&adapter->path[path_id].tcb_free_list),
                    adapter->path[path_id].sending_nbl));
                InsertTailQueue(&adapter->path[path_id].send_wait_queue,
                    VNIF_GET_NET_BUFFER_LIST_LINK(cur_nb_list));
                adapter->nWaitSend++;
            } else {
                /* Do the actual work of sending. */
                adapter->path[path_id].sending_nbl = cur_nb_list;
                NET_BUFFER_LIST_STATUS(cur_nb_list) = NDIS_STATUS_SUCCESS;
                VNIFSendNetBufferList(adapter,
                                      cur_nb_list,
                                      path_id,
                                      FALSE,
                                      dispatch_level);
            }
        }
        if (old_path_id != (UINT)-1) {
            VNIF_RELEASE_SPIN_LOCK(&adapter->path[path_id].tx_path_lock,
                                   dispatch_level);
        }
    } while (FALSE);

    if (status != NDIS_STATUS_PENDING) {
        ULONG SendCompleteFlags = 0;

        for (cur_nb_list = nb_list;
            cur_nb_list != NULL;
            cur_nb_list = next_nb_list) {
            next_nb_list = NET_BUFFER_LIST_NEXT_NBL(cur_nb_list);
            NET_BUFFER_LIST_STATUS(cur_nb_list) = status;
        }

        if (NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags)) {
            NDIS_SET_SEND_COMPLETE_FLAG(SendCompleteFlags,
                NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        }

        DPRINTK(DPRTL_ON,
            ("MPSendNetBufferLists: error, complete nb_list %x.\n",
            SendCompleteFlags));
        if (nb_list) {
            NdisMSendNetBufferListsComplete(adapter->AdapterHandle,
                                            nb_list,
                                            SendCompleteFlags);
        }
    }
    DPRINTK(DPRTL_TX,  ("<==== MPSendNetBufferLists\n"));
}

static UINT
vnif_complete_priority_vlan_pkt(PVNIF_ADAPTER adapter, RCB *rcb)
{
    PNDIS_NET_BUFFER_LIST_8021Q_INFO p8021;
    uint8_t *data_buf;
    int j, k;

    data_buf = rcb->page + adapter->buffer_offset;
    if (*(uint16_t *)&data_buf[P8021_TPID_BYTE] == P8021_TPID_TYPE) {

        p8021 = (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(&(NET_BUFFER_LIST_INFO(
                                                  rcb->nbl,
                                                  Ieee8021QNetBufferListInfo)));

        p8021->Value = NULL;
        p8021->TagHeader.UserPriority =
            data_buf[P8021_TCI_BYTE] >> P8021_PRIORITY_SHIFT;
        p8021->TagHeader.VlanId =
            (uint16_t)(data_buf[P8021_TCI_BYTE] & 0x0f) << 8
                | (uint16_t)(data_buf[P8021_VLAN_BYTE]);


        DPRINTK(DPRTL_PRI, ("RX 8021 [14] %x [15] %x priority %x vlan %x %x.\n",
                            data_buf[14],
                            data_buf[15],
                            p8021->TagHeader.UserPriority,
                            p8021->TagHeader.VlanId,
                            adapter->vlan_id));

        /* If the packet has a vlan_id, should match the one that is set. */
        if (adapter->vlan_id
                && adapter->vlan_id != p8021->TagHeader.VlanId) {
            adapter->in_discards++;
            PRINTK(("  vlan tags do not match\n"));
            return VNIF_RECEIVE_DISCARD;
        }

        /*
         * Copy the MAC header to fill in the space
         * occupied by the priority bytes.
         */
        for (k = P8021_VLAN_BYTE, j = SRC_ADDR_END_BYTE;
            j >= 0; k--, j--) {
            data_buf[k] = data_buf[j];
        }
        /*
         * Don't worry about the offset, just adjust the
         * mdl start address.  Fix the address when the
         * packet is returned.
         */
        rcb->total_len -= P8021_BYTE_LEN;
        rcb->len -= P8021_BYTE_LEN;
        (uint8_t *)rcb->mdl->MappedSystemVa += P8021_BYTE_LEN;
        (uint8_t *)rcb->mdl->StartVa += P8021_BYTE_LEN;

        DPRINTK(DPRTL_PRI, ("  %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                  data_buf[0],
                  data_buf[1],
                  data_buf[2],
                  data_buf[3],
                  data_buf[4],
                  data_buf[5],
                  data_buf[6],
                  data_buf[7],
                  data_buf[8]));
        DPRINTK(DPRTL_PRI, (" %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                  data_buf[9],
                  data_buf[10],
                  data_buf[11],
                  data_buf[12],
                  data_buf[13],
                  data_buf[14],
                  data_buf[15],
                  data_buf[16],
                  data_buf[17]));

    }
    return VNIF_RECEIVE_COMPLETE;
}

static void
vnif_rx_checksum(PVNIF_ADAPTER adapter, PNET_BUFFER_LIST nbl,
    RCB *rcb, UINT total_len)
{
    PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO info;
    uint8_t *data_buf;
    NDIS_STATUS status;
    BOOLEAN valid_chksum;

    data_buf = rcb->page + adapter->buffer_offset;

    if (rcb->pkt_info.protocol != VNIF_PACKET_TYPE_TCP
            && rcb->pkt_info.protocol != VNIF_PACKET_TYPE_UDP) {
        return;
    }

    info = (PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO) (
            &(NET_BUFFER_LIST_INFO(
            nbl,
            TcpIpChecksumNetBufferListInfo)));
    info->Value = 0;

    if (rcb->pkt_info.ip_ver == IPV4) {
        if ((data_buf[VNIF_IP_FLAGS_BYTE] & VNIF_IP_FLAGS_MF_BIT)
            || (data_buf[VNIF_IP_FLAGS_BYTE] & VNIF_IP_FLAGS_MF_OFFSET_BIT)
            || data_buf[VNIF_IP_FRAG_OFFSET_BYTE]) {
            /* Can't be fragmented or have a fragment offset */
            return;
        }
        if (rcb->pkt_info.protocol == VNIF_PACKET_TYPE_TCP) {
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_TCP)) {
                return;
            }
        } else if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_UDP)) {
                return;
        }
    } else {
        if (rcb->pkt_info.protocol == VNIF_PACKET_TYPE_TCP) {
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                return;
            }
        } else if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_UDP)) {
                return;
        }
    }

    /* From here down we know that we need to fill out the checksum info. */
    if (VNIF_DATA_VALID_CHECKSUM_VALID(rcb)) {
        valid_chksum = 1;
    } else {
        valid_chksum = calculate_rx_checksum(rcb,
            data_buf,
            total_len,
            rcb->pkt_info.ip_ver,
            rcb->pkt_info.ip_hdr_len,
            rcb->pkt_info.protocol,
            (BOOLEAN)!!VNIF_PACKET_NEEDS_CHECKSUM(rcb));
    }

    if (rcb->pkt_info.protocol == VNIF_PACKET_TYPE_TCP) {
        info->Receive.TcpChecksumSucceeded = valid_chksum;
        info->Receive.TcpChecksumFailed = !valid_chksum;
    } else {
        info->Receive.UdpChecksumSucceeded = valid_chksum;
        info->Receive.UdpChecksumFailed = !valid_chksum;
    }

    DPRINTK(DPRTL_CHKSUM,
            ("Checksum: %s: ip flags %x ip frag offset %x\n",
             adapter->node_name,
             data_buf[VNIF_IP_FLAGS_BYTE],
             data_buf[VNIF_IP_FRAG_OFFSET_BYTE]));
    DPRINTK(DPRTL_CHKSUM,
            (" cinfo%x rx %x %d fl %x: ipf %d ips %d tf %d ts %d uf %d us %d\n",
             rcb->pkt_info.ip_ver,
             adapter->cur_rx_tasks,
             total_len,
             VNIF_IS_PACKET_DATA_VALID(rcb) | VNIF_PACKET_NEEDS_CHECKSUM(rcb),
             info->Receive.IpChecksumFailed,
             info->Receive.IpChecksumSucceeded,
             info->Receive.TcpChecksumFailed,
             info->Receive.TcpChecksumSucceeded,
             info->Receive.UdpChecksumFailed,
             info->Receive.UdpChecksumSucceeded));
}

static void
vnif_build_nb(PVNIF_ADAPTER adapter, RCB *rcb, PNET_BUFFER_LIST nbl)
{
    PNET_BUFFER nb;
    PMDL tail_mdl;
    UINT len;

    nb = rcb->nb;
    NET_BUFFER_LIST_FIRST_NB(nbl) = nb;
    NET_BUFFER_CURRENT_MDL_OFFSET(nb) = 0;
    NET_BUFFER_FIRST_MDL(nb) = rcb->mdl;
    NET_BUFFER_CURRENT_MDL(nb) = rcb->mdl;
    NET_BUFFER_DATA_OFFSET(nb) = 0;
    NET_BUFFER_DATA_LENGTH(nb) = rcb->total_len;
    (RCB *)NET_BUFFER_MINIPORT_RESERVED(nb)[0] = rcb;
    tail_mdl = NULL;
    while (rcb) {
        NdisAdjustMdlLength(rcb->mdl, rcb->len);
        if (tail_mdl != NULL) {
            NDIS_MDL_LINKAGE(tail_mdl) = rcb->mdl;
        }
        tail_mdl = rcb->mdl;
        DPRINTK(DPRTL_TRC, ("Build sg: rcb %p, len %d.\n", rcb, rcb->len));
        rcb = rcb->next;
    }
    if (tail_mdl != NULL) {
        NDIS_MDL_LINKAGE(tail_mdl) = NULL;
    }
}

static __inline BOOLEAN
vnif_continue_proccessing_rcb(PVNIF_ADAPTER adapter,
                              RCB *rcb,
                              UINT len,
                              UINT path_id)
{
    vnif_rcb_verify(adapter, rcb, path_id);
    if (len <= NETIF_RSP_NULL) {
        PRINTK(("Dropping for len %d\n", len));
        vnif_drop_rcb(adapter, rcb, rcb->len);
        return FALSE;
    }
    if (!VNIF_IS_VALID_RCB(rcb)) {
        /*
         * This definitely indicates a bug, either in this driver
         * or in the backend driver. In future this should flag the
         * bad situation to the system controller to reboot the
         * backed.
         */
        PRINTK(("VNIF: GRANT_INVALID_REF for rcb %d.\n", rcb->index));
        vnif_return_rcb(adapter, rcb);
        return FALSE;
    }

    DPRINTK(DPRTL_RX, ("%s: rcb (%p) %d %d\n\n",
        __func__, rcb, rcb->index, rcb->path_id));
    vnif_dump_buf(DPRTL_RX, rcb->page + adapter->buffer_offset, 16);

    if (vnif_should_complete_packet(adapter,
                                    rcb->page + adapter->buffer_offset,
                                    len) == VNIF_RECEIVE_DISCARD) {
        vnif_return_rcb(adapter, rcb);
        return FALSE;
    }

    VNIF_POP_PCB(adapter->path[rcb->path_id].rcb_rp.rcb_nbl, rcb->nbl);
    if (rcb->nbl == NULL) {
        /* Should never happen. */
        PRINTK(("Drop for nbl, len %d, p_id %d, rcb %d:%d\n",
                rcb->len,
                path_id,
                rcb->path_id,
                rcb->rcv_qidx));
        vnif_drop_rcb(adapter, rcb, rcb->len);
        return FALSE;
    }

    if (vnif_complete_priority_vlan_pkt(adapter,
                                        rcb) == VNIF_RECEIVE_DISCARD) {
        vnif_return_rcb(adapter, rcb);
        return FALSE;
    }

#ifdef DBG
    if (NET_BUFFER_LIST_GET_HASH_TYPE(rcb->nbl) != 0) {
        PRINTK(("** nbl hash type not 0 - %d\n",
                NET_BUFFER_LIST_GET_HASH_TYPE(rcb->nbl)));
    }
    if (NET_BUFFER_LIST_GET_HASH_FUNCTION(rcb->nbl) != 0) {
        PRINTK(("** nbl hash function not 0 - %d\n",
                NET_BUFFER_LIST_GET_HASH_FUNCTION(rcb->nbl)));
    }
#endif
    return TRUE;
}

static __inline void
vnif_get_rcb_pkt_info(PVNIF_ADAPTER adapter,
                      RCB *rcb,
                      PROCESSOR_NUMBER *target_processor,
                      UINT *rcv_target_qidx,
                      UINT len)
{
    NDIS_STATUS status;

    if (VNIF_GET_RSS_MODE(adapter) == VNIF_RSS_FULL
            || adapter->cur_rx_tasks) {
        status = get_ip_pkt_info(rcb, adapter->buffer_offset, len);
        if (VNIF_GET_RSS_MODE(adapter) == VNIF_RSS_FULL
                && status == NDIS_STATUS_SUCCESS) {
            vnif_rss_get_rcb_target_info(adapter,
                                         rcb,
                                         rcv_target_qidx,
                                         target_processor);
            DPRINTK(DPRTL_RSS,
                    ("RSS rcv path_id %d t_id %x cpu %d tcpu %x\n",
                     rcb->path_id,
                     *rcv_target_qidx,
                     vnif_get_current_processor(NULL),
                     target_processor->Number));
        }
    }
}

static __inline void
vnif_queue_rcv_dpc_if_needed(PVNIF_ADAPTER adapter,
                             UINT max_nbls_to_indicate,
                             BOOLEAN needs_dpc)
{
    UINT i;

    if (needs_dpc) {
        for (i = 0; i < adapter->num_rcv_queues; i++) {
            if (adapter->rcv_q[i].rcv_should_queue_dpc == TRUE) {
                vnif_ndis_queue_dpc(adapter,
                                    i,
                                    max_nbls_to_indicate);
                adapter->rcv_q[i].rcv_should_queue_dpc = FALSE;
            }
        }
    }
}

/*
 * VNIFReceivePackets does the following:
 * 1. update rx_ring consumer pointer.
 * 2. remove the corresponding RCB out of free list
 * 3. indicate all these packets.
 *
 * Later when returning the packets:
 * 1. reinit the packets, reinsert into free list.
 * 2. put the grant_ref back into rx_ring.req
 */
VOID
VNIFReceivePackets(PVNIF_ADAPTER adapter,
                   UINT path_id,
                   UINT max_nbls_to_indicate)
{
    PROCESSOR_NUMBER target_processor = {0};
    PNET_BUFFER nb;
    PNET_BUFFER_LIST nb_list;
    PNET_BUFFER_LIST cur_nbl;
    PNET_BUFFER_LIST prev_nb_list;
    rcv_to_process_q_t *rcv_q;
    uint32_t rcv_flags;
    UINT nb_list_cnt;
    UINT rp;
    UINT old;
    RCB *rcb;
    UINT len;
    UINT rcb_added_to_ring;
    UINT rcv_qidx;
    UINT rcv_target_qidx;
    int more_to_do;
    uint32_t ring_size;
    uint32_t i;
    uint64_t st;
    BOOLEAN needs_dpc;
#ifdef RSS_DEBUG
    LONG seq = 0;
#endif

    rcv_qidx = vnif_rss_get_rcv_qidx_for_cur_cpu(adapter);

#ifdef DBG
    if (path_id >= adapter->num_paths && path_id >= adapter->num_rcv_queues) {
        DPRINTK(DPRTL_RSS,
                ("%s: path_id %d > num_rcv_queues %d. Use rcv_qidx %d\n",
                __func__, path_id, adapter->num_rcv_queues, rcv_qidx));
    }
#endif

    if (rcv_qidx == VNIF_NO_RECEIVE_QUEUE) {
#ifdef DBG
        if (adapter->num_rcv_queues > 1) {
            DPRINTK(DPRTL_RSS,
                ("%s: no queue mapping for path_id %d, use default\n",
                 __func__, path_id));
        }
#endif
        rcv_qidx = adapter->num_rcv_queues - 1;
    }

    DPRINTK(DPRTL_RX, ("---> %s path_id %d cpu %d rcvq_idx %d\n",
                       __func__,
                       path_id,
                       vnif_get_current_processor(NULL),
                       rcv_qidx));

    ring_size = min(max_nbls_to_indicate, VNIF_RX_RING_SIZE(adapter));
    rcv_q = &adapter->rcv_q[rcv_qidx];
    rcv_q->rcv_should_queue_dpc = FALSE;
    rp = 0;
    nb_list = NULL;
    prev_nb_list = NULL;
    nb_list_cnt = 0;
    rcb_added_to_ring = 0;
    more_to_do = 0;
    needs_dpc = FALSE;

    if (path_id < adapter->num_paths) {
        NdisDprAcquireSpinLock(&adapter->path[path_id].rx_path_lock);
        VNIF_GET_RX_REQ_PROD(adapter, path_id, &old);
    }

    NdisDprAcquireSpinLock(&rcv_q->rcv_to_process_lock);

    VNIF_INC_REF(adapter);
    if (path_id < adapter->num_paths) {
        VNIFReceivePacketsStats(adapter, path_id, ring_size);
    }
    DPRINTK(DPRTL_RX, ("VNIFReceivePackets: start rcv_qidx %d path_id %d %d.\n",
                       rcv_qidx, path_id, ring_size));
    do {
        /*
         * Pull rx packtes off the ring and place them in them correct rcv q.
         */
        if (path_id < adapter->num_paths) {
            VNIF_GET_RX_RSP_PROD(adapter, path_id, &rp);
            KeMemoryBarrier();

            VNIF_GET_RX_RSP_CONS(adapter, path_id, &i);
            while ((rcb = vnif_get_rx(adapter, path_id, rp, &i, &len))
                   != NULL) {

                len = (UINT)rcb->total_len;
                if (vnif_continue_proccessing_rcb(adapter, rcb, len, path_id)
                        == FALSE) {
                    rcb_added_to_ring++;
                    continue;
                }

                if (rcb->len < VNIF_TCPIP_HEADER_LEN) {
                    rcb_added_to_ring += vnif_collapse_rx(adapter, rcb);
                }

                if (len < ETH_MIN_PACKET_SIZE) {
                    NdisZeroMemory(
                        rcb->page +
                            (uintptr_t)adapter->buffer_offset + (uintptr_t)len,
                        ETH_MIN_PACKET_SIZE - (uintptr_t)len);
                }

                rcv_target_qidx = rcv_qidx;
                vnif_get_rcb_pkt_info(adapter,
                                      rcb,
                                      &target_processor,
                                      &rcv_target_qidx,
                                      len);
                if (rcv_target_qidx != rcv_qidx) {
                    NdisDprReleaseSpinLock(&rcv_q->rcv_to_process_lock);
                    NdisDprAcquireSpinLock(
                        &adapter->rcv_q[rcv_target_qidx].rcv_to_process_lock);
                    InsertTailList(
                        &adapter->rcv_q[rcv_target_qidx].rcv_to_process,
                        &rcb->list);

#ifdef DBG
                    if (adapter->rcv_q[rcv_target_qidx].rcv_processor.Number
                        != target_processor.Number) {
                        PRINTK(("%s: rcv_processor %d != target_processor %d\n",
                           __func__,
                           adapter->rcv_q[rcv_target_qidx].rcv_processor.Number,
                           target_processor.Number));
                        adapter->rcv_q[rcv_target_qidx].rcv_processor =
                            target_processor;
                    }
#endif
                    adapter->rcv_q[rcv_target_qidx].rcv_should_queue_dpc = TRUE;
                    NdisDprReleaseSpinLock(
                        &adapter->rcv_q[rcv_target_qidx].rcv_to_process_lock);
                    NdisDprAcquireSpinLock(&rcv_q->rcv_to_process_lock);

                    /* Setup DPC */
                    DPRINTK(DPRTL_RSS,
                            ("%s: pid %d rpid %d, tpid %d rqidx %d trqidx %d\n",
                             __func__,
                             path_id,
                             rcv_q->path_id,
                             adapter->rcv_q[rcv_target_qidx].path_id,
                             rcv_qidx,
                             rcv_target_qidx));
                    needs_dpc = TRUE;

                    vnif_rss_dbg_seq(adapter,
                                     rcb,
                                     path_id,
                                     rcv_target_qidx,
                                     target_processor.Number,
                                     rcv_qidx);
                } else {
                    DPRINTK(DPRTL_RX,
                            ("  InsertTailList rcb_idx %d rcb_pathid %d c %d\n",
                            rcb->index, rcb->path_id,
                            vnif_get_current_processor(NULL)));

                    InsertTailList(&rcv_q->rcv_to_process, &rcb->list);

                    vnif_rss_dbg_seq(adapter,
                                     rcb,
                                     path_id,
                                     rcv_qidx,
                                     target_processor.Number,
                                     rcv_qidx);
                }

                if (adapter->num_rcb > NET_RX_RING_SIZE) {
                    rcb_added_to_ring += vnif_add_rcb_to_ring_from_list(
                        adapter,
                        path_id);
                }
                VNIFInterlockedIncrementStat(
                    adapter->pv_stats->rx_to_process_cnt);
            }

            VNIF_SET_RX_RSP_CONS(adapter, path_id, rp);
        } /* Pull packets off the ring. */


        VNIFStatQueryInterruptTime(st);

        /*
         * Build net buffer list from rx packets on the current rcv q.
         */
        while (nb_list_cnt < ring_size
               && !IsListEmpty(&rcv_q->rcv_to_process)) {
            rcb = (RCB *) RemoveHeadList(&rcv_q->rcv_to_process);
            len = (UINT)rcb->total_len;

            vnif_rss_test_seq(__func__, rcb, path_id, rcv_qidx, &seq);

            DPRINTK(DPRTL_RX,
                ("  Receiving rcb %d %d.\n", rcb->index, rcb->path_id));

            VNIFInterlockedDecrementStat(adapter->pv_stats->rx_to_process_cnt);

            cur_nbl = rcb->nbl;
            if (cur_nbl == NULL) {
                /* Should never happen. */
                PRINTK(("2 Drop for nbl, len %d r_qidx %d p_id %d, rcb %d:%d\n",
                        rcb->len,
                        rcv_qidx,
                        path_id,
                        rcb->path_id,
                        rcb->rcv_qidx));
                vnif_drop_rcb(adapter, rcb, rcb->len);
                continue;
            }
            rcb->rcv_qidx = rcv_qidx;
            vnif_build_nb(adapter, rcb, cur_nbl);

            nb_list_cnt++;
            if (nb_list == NULL) {
                nb_list = cur_nbl;
            } else {
                NET_BUFFER_LIST_NEXT_NBL(prev_nb_list) = cur_nbl;
            }
            VNIF_CLEAR_NB_FLAG(cur_nbl, (NET_BUFFER_LIST_FLAGS(cur_nbl)
                                       & NBL_FLAGS_MINIPORT_RESERVED));
            prev_nb_list = cur_nbl;

            if (adapter->cur_rx_tasks) {
                vnif_rx_checksum(adapter, cur_nbl, rcb, len);
            }

            vnif_rss_set_nbl_info(adapter, cur_nbl, rcb);

            VNIFInterlockedIncrement(adapter->nBusyRecv);
            VNIFInterlockedIncrement(rcv_q->n_busy_rcv);

            rcb->st = st;
#ifdef DBG
            if (adapter->pv_stats) {
                rcb->seq = adapter->pv_stats->rcb_seq;
            }
            VNIFInterlockedIncrementStat(adapter->pv_stats->rcb_seq);
#endif
        } /* Build net buffer list. */

        if (path_id < adapter->num_paths) {
            VNIF_RING_FINAL_CHECK_FOR_RESPONSES(adapter->path[path_id].rx,
                                                &more_to_do);
        }
    } while (more_to_do && nb_list_cnt < ring_size);

    rcv_flags = NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL |
        NDIS_RECEIVE_FLAGS_PERFECT_FILTERED;

    if (rcv_q->n_busy_rcv < adapter->rcv_limit) {
        VNIFIncrementStat(adapter->pv_stats->spkt_cnt, nb_list_cnt);
    } else {
        VNIFIncrementStat(adapter->pv_stats->rpkt_cnt, nb_list_cnt);
        rcv_flags |= NDIS_RECEIVE_FLAGS_RESOURCES;
    }

    if (!IsListEmpty(&rcv_q->rcv_to_process)) {
        DPRINTK(DPRTL_DPC,
            ("%s: RecvToProcess not empty, schedule dpc, nbls %d ind %d\n",
            __func__,
            nb_list_cnt,
            max_nbls_to_indicate));
        rcv_q->rcv_should_queue_dpc = TRUE;
        needs_dpc = TRUE;
    }

    vnif_queue_rcv_dpc_if_needed(adapter, max_nbls_to_indicate, needs_dpc);

    NdisDprReleaseSpinLock(&rcv_q->rcv_to_process_lock);

    if (path_id < adapter->num_paths) {
        if (nb_list_cnt == 0) {
            VNIF_RX_NOTIFY(adapter, path_id, rcb_added_to_ring, old);
        }
        NdisDprReleaseSpinLock(&adapter->path[path_id].rx_path_lock);
    }

    if (nb_list_cnt) {
        if (path_id < adapter->num_paths) {
            VNIFReceivePacketsPostStats(adapter, path_id,
                                        ring_size, nb_list_cnt);
        }

        DPRINTK(DPRTL_RX, ("  IndicateRcv of %d on ridx %d path_id %d\n",
                            nb_list_cnt, rcv_qidx, path_id));
        NdisMIndicateReceiveNetBufferLists(adapter->AdapterHandle,
                                           nb_list,
                                           NDIS_DEFAULT_PORT_NUMBER,
                                           nb_list_cnt,
                                           rcv_flags);

        if (rcv_flags & NDIS_RECEIVE_FLAGS_RESOURCES) {
            MPReturnNetBufferLists(adapter,
                                   nb_list,
                                   NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
        }
    }

    VNIF_DEC_REF(adapter);
    DPRINTK(DPRTL_RX, ("<--- %s: end rcv_qidx %d path_id %d.\n",
                       __func__, rcv_qidx, path_id));
}

VOID
MPReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext,
    PNET_BUFFER_LIST    NetBufferLists,
    ULONG               ReturnFlags)
{
    PVNIF_ADAPTER adapter;
    PNDIS_NET_BUFFER_LIST_8021Q_INFO p8021;
    RCB *rcb;
    PNET_BUFFER_LIST nb_list;
    PNET_BUFFER_LIST next_nb_list;
    PNET_BUFFER nb;
    UINT old_path_id;
    UINT cur_path_id;
    UINT cur_rcv_qidx;
#ifdef DBG
    UINT acq = 0;
#endif
#ifdef RSS_DEBUG
    LONG seq = 0;
#endif
    BOOLEAN dispatch_level;

    adapter = (PVNIF_ADAPTER)MiniportAdapterContext;
    DPRINTK(DPRTL_RX, ("==> MPReturnNetBufferLists\n"));

    dispatch_level = NDIS_TEST_RETURN_AT_DISPATCH_LEVEL(ReturnFlags);

    old_path_id = (UINT)-1;
    for (nb_list = NetBufferLists; nb_list != NULL; nb_list = next_nb_list) {
        next_nb_list = NET_BUFFER_LIST_NEXT_NBL(nb_list);
        NET_BUFFER_LIST_NEXT_NBL(nb_list) = NULL;
        nb = NET_BUFFER_LIST_FIRST_NB(nb_list);
        rcb = (RCB *)NET_BUFFER_MINIPORT_RESERVED(nb)[0];

        vnif_rss_test_seq(__func__, rcb, rcb->path_id, rcb->rcv_qidx, &seq);
        DPRINTK(DPRTL_RX, ("  Return rcb (%p) %d %d: nbl %p, nb %p\n\n",
            rcb, rcb->index, rcb->path_id, nb_list, nb));
        vnif_dump_buf(DPRTL_RX, rcb->page + adapter->buffer_offset, 16);

        cur_path_id = rcb->path_id;
        cur_rcv_qidx = rcb->rcv_qidx;

        if (old_path_id != cur_path_id) {
            if (old_path_id != (UINT)-1) {
                VNIF_RELEASE_SPIN_LOCK(&adapter->path[old_path_id].rx_path_lock,
                                       dispatch_level);
            }
            old_path_id = cur_path_id;
            VNIF_ACQUIRE_SPIN_LOCK(&adapter->path[cur_path_id].rx_path_lock,
                                   dispatch_level);
            adapter->path[cur_path_id].rx_should_notify++;
#ifdef DBG
            acq++;
#endif
        }

        p8021 = (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(
                &(NET_BUFFER_LIST_INFO(nb_list, Ieee8021QNetBufferListInfo)));
        p8021->Value = 0;

        VNIF_PUSH_PCB(adapter->path[cur_path_id].rcb_rp.rcb_nbl, nb_list);

        VNIFReturnRcbStats(adapter, rcb);
        vnif_return_rcb(adapter, rcb);

        VNIFInterlockedDecrement(adapter->nBusyRecv);
        VNIFInterlockedDecrement(adapter->rcv_q[cur_rcv_qidx].n_busy_rcv);
    }
    if (old_path_id != (UINT)-1) {
        VNIF_RELEASE_SPIN_LOCK(&adapter->path[old_path_id].rx_path_lock,
                               dispatch_level);
    }

    for (cur_path_id = 0; cur_path_id < adapter->num_paths; cur_path_id++) {
        if (adapter->path[cur_path_id].rx_should_notify != 0) {
            VNIF_RX_RING_KICK_ALWAYS(&adapter->path[cur_path_id]);
            adapter->path[cur_path_id].rx_should_notify = 0;
        }
    }
#ifdef DBG
    if (acq != 1) {
        PRINTK(("** acq = %d\n", acq));
    }
#endif

    DPRINTK(DPRTL_RX, ("<== MPReturnNetBufferLists\n"));
}

VOID
VNIFFreeQueuedSendPackets(PVNIF_ADAPTER adapter, NDIS_STATUS status)
{
    PQUEUE_ENTRY entry;
    PNET_BUFFER_LIST nb_list;
    PNET_BUFFER_LIST nb_list_to_complete = NULL;
    PNET_BUFFER_LIST last_nb_list = NULL;
    PNET_BUFFER nb;
    UINT i;

    DPRINTK(DPRTL_TRC, ("--> VNIFFreeQueuedSendPackets\n"));

    for (i = 0; i < adapter->num_paths; i++) {
        NdisAcquireSpinLock(&adapter->path[i].tx_path_lock);
        while (!IsQueueEmpty(&adapter->path[i].send_wait_queue)) {
            entry = RemoveHeadQueue(&adapter->path[i].send_wait_queue);
            ASSERT(entry);

            adapter->nWaitSend--;

            nb_list = VNIF_GET_NET_BUFFER_LIST_FROM_QUEUE_LINK(entry);

            NET_BUFFER_LIST_STATUS(nb_list) = status;

            /* The sendLock is held */
            nb = VNIF_GET_NET_BUFFER_LIST_NEXT_SEND(nb_list);

            for (; nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
                VNIF_GET_NET_BUFFER_LIST_REF_COUNT(nb_list)--;
            }
            /*
             * If Ref count goes to 0, then complete it.
             * Otherwise, Send interrupt DPC would complete it later
             */
            if (VNIF_GET_NET_BUFFER_LIST_REF_COUNT(nb_list) == 0) {
                if (nb_list_to_complete == NULL) {
                    nb_list_to_complete = nb_list;
                } else {
                    NET_BUFFER_LIST_NEXT_NBL(last_nb_list) = nb_list;
                }
                NET_BUFFER_LIST_NEXT_NBL(nb_list) = NULL;
                last_nb_list = nb_list;

            }
        }

        NdisReleaseSpinLock(&adapter->path[i].tx_path_lock);
        if (nb_list_to_complete != NULL) {
            NdisMSendNetBufferListsComplete(
                adapter->AdapterHandle,
                nb_list_to_complete,
                NDIS_STATUS_SEND_ABORTED);
        }
    }

    DPRINTK(DPRTL_TRC, ("<-- VNIFFreeQueuedSendPackets\n"));

}

void
VNIFIndicateLinkStatus(PVNIF_ADAPTER adapter, uint32_t status)
{

    NDIS_LINK_STATE                LinkState;
    NDIS_STATUS_INDICATION         StatusIndication;

    RPRINTK(DPRTL_INIT, ("--> VNIFIndicateLinkStatus: %x\n", status));
    NdisZeroMemory(&LinkState, sizeof(NDIS_LINK_STATE));
    NdisZeroMemory(&StatusIndication, sizeof(NDIS_STATUS_INDICATION));

    LinkState.Header.Revision = NDIS_LINK_STATE_REVISION_1;
    LinkState.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    LinkState.Header.Size = sizeof(NDIS_LINK_STATE);

    if (status) {
        LinkState.MediaConnectState = MediaConnectStateConnected;
        LinkState.MediaDuplexState = adapter->duplex_state;
        LinkState.XmitLinkSpeed = adapter->ul64LinkSpeed;
        LinkState.RcvLinkSpeed = adapter->ul64LinkSpeed;
    } else {
        LinkState.MediaConnectState = MediaConnectStateDisconnected;
        LinkState.MediaDuplexState = MediaDuplexStateUnknown;
        LinkState.XmitLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
        LinkState.RcvLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
    }

    StatusIndication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    StatusIndication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    StatusIndication.Header.Size = sizeof(NDIS_STATUS_INDICATION);
    StatusIndication.SourceHandle = adapter->AdapterHandle;
    StatusIndication.StatusCode = NDIS_STATUS_LINK_STATE;
    StatusIndication.StatusBuffer = &LinkState;
    StatusIndication.StatusBufferSize = sizeof(LinkState);

    NdisMIndicateStatusEx(adapter->AdapterHandle, &StatusIndication);
    RPRINTK(DPRTL_INIT, ("<-- VNIFIndicateLinkStatus\n"));
}

void
vnif_complete_lost_sends(VNIF_ADAPTER *adapter)
{
    TCB *tcb;
    NDIS_STATUS         status = NDIS_STATUS_SUCCESS;
    PNET_BUFFER_LIST    nb_list;
    PNET_BUFFER_LIST    last_nb_list = NULL;
    PNET_BUFFER_LIST    complete_nb_lists = NULL;
    ULONG num_ring_desc;
    UINT i;
    UINT p;

    num_ring_desc = VNIF_TX_RING_SIZE(adapter);
    for (p = 0; p < adapter->num_paths; p++) {
        NdisAcquireSpinLock(&adapter->path[p].tx_path_lock);
        for (i = 0; i < num_ring_desc; i++) {
            tcb = adapter->TCBArray[(p * num_ring_desc) + i];
            if (!tcb) {
                continue;
            }
            if (!tcb->nb) {
                continue;
            }
            nb_list = vnif_free_send_net_buffer(adapter, tcb);
            if (nb_list != NULL) {
                NET_BUFFER_LIST_STATUS(nb_list) = NDIS_STATUS_RESET_IN_PROGRESS;
                if (complete_nb_lists == NULL) {
                    complete_nb_lists = nb_list;
                } else {
                    NET_BUFFER_LIST_NEXT_NBL(last_nb_list) = nb_list;
                }
                NET_BUFFER_LIST_NEXT_NBL(nb_list) = NULL;
                last_nb_list = nb_list;
            }
            vnif_free_send_tcbs(adapter, tcb, p);
        }
        NdisReleaseSpinLock(&adapter->path[p].tx_path_lock);
    }

    if (complete_nb_lists != NULL) {
        NdisMSendNetBufferListsComplete(
            adapter->AdapterHandle,
            complete_nb_lists,
            NDIS_STATUS_SEND_ABORTED);
    }
}

void
VNIFPollTimerDpc(void *s1, void *context, void *s2, void *s3)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)context;
    UINT i;

    DPRINTK(DPRTL_ON, ("%s: in, flags %x\n", __func__, adapter->adapter_flags));

    if (adapter) {
        NdisAcquireSpinLock(&adapter->adapter_flag_lock);
        if (adapter->adapter_flags & VNF_ADAPTER_POLLING) {
            NdisReleaseSpinLock(&adapter->adapter_flag_lock);
            vnif_call_txrx_interrupt_dpc(adapter);
            NdisAcquireSpinLock(&adapter->adapter_flag_lock);
        }

        if (adapter->adapter_flags & VNF_ADAPTER_POLLING) {
            VNIF_SET_TIMER(adapter->poll_timer, 1);
        }
        NdisReleaseSpinLock(&adapter->adapter_flag_lock);
    }
    DPRINTK(DPRTL_ON, ("%s: out\n", __func__));
}

void
vnif_poll_dpc(PKDPC dpc, void *ctx, void *s1, void *s2)
{
    PVNIF_ADAPTER adapter;
    UINT i;

    adapter = (PVNIF_ADAPTER)ctx;
    DPRINTK(DPRTL_ON, ("%s: in, flags %x\n", __func__,
                        adapter->adapter_flags));
    if (adapter) {
        NdisAcquireSpinLock(&adapter->adapter_flag_lock);
        if (adapter->adapter_flags & VNF_ADAPTER_POLLING) {
            NdisReleaseSpinLock(&adapter->adapter_flag_lock);
            vnif_call_txrx_interrupt_dpc(adapter);
        } else {
            NdisReleaseSpinLock(&adapter->adapter_flag_lock);
        }
    }
    DPRINTK(DPRTL_ON, ("%s: out\n", __func__));
}
