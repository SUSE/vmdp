/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2022 SUSE LLC
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

static void vnif_check_tx_throttle(PVNIF_ADAPTER adapter);
static void MPReturnPacketWithLock(PVNIF_ADAPTER adapter, PNDIS_PACKET packet);

static int
should_checksum_tx(PVNIF_ADAPTER adapter, NDIS_PACKET *packet, uint16_t *flags)
{
    PNDIS_TCP_IP_CHECKSUM_PACKET_INFO packetinfo;

    packetinfo = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)(
        &(NDIS_PER_PACKET_INFO_FROM_PACKET(
            packet, TcpIpChecksumPacketInfo)));
#ifdef DBG
    if (packetinfo->Value & 0xfffe) {
        DPRINTK(DPRTL_CHKSUM, ("TX check value %p.\n", packetinfo->Value));
    }
#endif
    if ((*(uintptr_t *)&packetinfo->Value) & 0x1c) {
        if (packetinfo->Transmit.NdisPacketChecksumV4) {
            if (packetinfo->Transmit.NdisPacketTcpChecksum) {
                if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_TCP)) {
                    DPRINTK(DPRTL_ON,
                        ("chksum bad request tcp: tx task %x v %x\n",
                        adapter->cur_tx_tasks, packetinfo->Value));
                    return 0;
                }
            }
            if (packetinfo->Transmit.NdisPacketUdpChecksum) {
                if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_UDP)) {
                    DPRINTK(DPRTL_ON,
                        ("chksum bad request udp: tx task %x v %x\n",
                        adapter->cur_tx_tasks, packetinfo->Value));
                    return 0;
                }
            }
            if (packetinfo->Transmit.NdisPacketIpChecksum) {
                if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_IP)) {
                    DPRINTK(DPRTL_ON,
                        ("chksum bad ip udp: tx task %x v %x\n",
                        adapter->cur_tx_tasks, packetinfo->Value));
                    return 0;
                }
            }
        } else {
            /* IPV6 packet */
            DPRINTK(DPRTL_ON, ("discard ipv6: c %x i %p\n",
                adapter->cur_tx_tasks, packetinfo->Value));
            return 0;
        }
        *flags |= NETTXF_data_validated | NETTXF_csum_blank;
    }

    return 1;
}

static UINT
VNIFCopyPacket(TCB *tcb, PNDIS_BUFFER CurrentBuffer,
    UINT PacketLength, UINT data_offset)
{
    PVOID          VirtualAddress;
    UINT           CurrentLength;
    UINT           BytesToCopy;
    UINT           BytesCopied = 0;
    UINT           BufferCount;
    UINT           DestBufferSize;
    PUCHAR         pDest;

    NdisZeroMemory(tcb->data, data_offset);
    pDest = tcb->data + data_offset;
    DestBufferSize = PacketLength;

    while (CurrentBuffer && DestBufferSize) {
        NdisQueryBufferSafe(
            CurrentBuffer,
            &VirtualAddress,
            &CurrentLength,
            NormalPagePriority);

        if (VirtualAddress == NULL) {
            return 0;
        }

        CurrentLength = min(CurrentLength, DestBufferSize);

        if (CurrentLength) {
            NdisMoveMemory(pDest, VirtualAddress, CurrentLength);
            BytesCopied += CurrentLength;
            DestBufferSize -= CurrentLength;
            pDest += CurrentLength;
        }

        NdisGetNextBuffer(
            CurrentBuffer,
            &CurrentBuffer);
    }

    if (BytesCopied < ETH_MIN_PACKET_SIZE) {
        /*
         * This would be the case if the packet size is less than
         * ETH_MIN_PACKET_SIZE
         */
        NdisZeroMemory(pDest, ETH_MIN_PACKET_SIZE - BytesCopied);
        BytesCopied = ETH_MIN_PACKET_SIZE;
    }

    tcb->sg_cnt = 0;
    return BytesCopied;
}

static void
vnif_build_ip_chksum_hdr(TCB *tcb, PUCHAR virtual_addr, UINT cur_len, UINT i,
    UINT *ip_chksum_completed)
{
    PUCHAR hdr;
    PUCHAR ip_hdr;

    if (cur_len >= IP_HEADER_SIZE_VAL) {
        hdr = virtual_addr;
        if (!(*ip_chksum_completed)) {
            ip_hdr = hdr + (i ? 0 : ETH_HEADER_SIZE);
            tcb->ip_hdr_len = (ip_hdr[0] & 0xf) << 2;
            calculate_ip_checksum(ip_hdr);
            *ip_chksum_completed = 1;
            DPRINTK(DPRTL_TRC,
                ("vnif_build_ip_chksum_hdr: calculate_ip_checksum in el %d\n",
                i));
        }
        if (!tcb->tcp_hdr_len) {
            if (i == 0) {
                if (cur_len >= ETH_HEADER_SIZE
                        + IP_HEADER_SIZE_VAL
                        + TCP_HEADER_SIZE) {
                    tcb->tcp_hdr_len =
                        virtual_addr[ETH_HEADER_SIZE +
                            tcb->ip_hdr_len
                            + TCP_DATA_OFFSET] >> 2;
                    DPRINTK(DPRTL_CHKSUM,
                        ("hdr: len %d, val %x, len %d, loop %d.\n",
                        cur_len,
                        hdr[ETH_HEADER_SIZE +
                            tcb->ip_hdr_len
                            + TCP_DATA_OFFSET],
                        tcb->tcp_hdr_len,
                        i));
                }
            } else if (i == 1) {
                if (cur_len >= IP_HEADER_SIZE_VAL + TCP_HEADER_SIZE) {
                    tcb->tcp_hdr_len = virtual_addr[tcb->ip_hdr_len
                        + TCP_DATA_OFFSET] >> 2;
                    DPRINTK(DPRTL_CHKSUM,
                        ("hdr: len %d, val %x, len %d, loop %d.\n",
                        cur_len,
                        hdr[tcb->ip_hdr_len + TCP_DATA_OFFSET],
                        tcb->tcp_hdr_len,
                        i));
                }
            } else {
                if (cur_len >= TCP_HEADER_SIZE) {
                    tcb->tcp_hdr_len =
                        virtual_addr[TCP_DATA_OFFSET] >> 2;
                    DPRINTK(DPRTL_CHKSUM,
                        ("hdr: len %d, val %x, len %d, loop %d.\n",
                        cur_len,
                        hdr[TCP_DATA_OFFSET],
                        tcb->tcp_hdr_len,
                        i));
                }
            }
        }
    }
}

static UINT
vnif_build_sg_ex(PVNIF_ADAPTER adapter, TCB *tcb, PNDIS_BUFFER current_buffer,
    UINT data_len)
{
    PHYSICAL_ADDRESS addr;
    PUCHAR      virtual_addr;
    PUCHAR      pDest;
    TCB         *cur_tcb;
    TCB         *tail_tcb;
    ULONG       page_offset;
    ULONG       cur_len;
    ULONG       dest_len;
    ULONG       cp_len;
    ULONG       len;
    UINT        sg_idx;
    UINT        built;
    UINT        i;

    sg_idx = 0;
    cur_tcb = tcb;
    tail_tcb = tcb;
    pDest = tcb->data + adapter->buffer_offset;
    dest_len = adapter->buffer_offset;
    len = 0;

    built = 0;
    tcb->tcp_hdr_len = 0;
    for (i = 0; current_buffer; i++) {
        NdisQueryBufferSafe(
            current_buffer,
            &virtual_addr,
            &cur_len,
            NormalPagePriority);
        if (i <= 2 && !tcb->tcp_hdr_len) {
            vnif_build_ip_chksum_hdr(tcb, virtual_addr, cur_len, i, &built);
        }

        if (cur_len > data_len) {
            cur_len = data_len;
        }

        page_offset = (ULONG_PTR)virtual_addr & (PAGE_SIZE - 1);

        if (((cur_len & (PAGE_SIZE - 1)) == 0) && page_offset == 0) {
            addr = MmGetPhysicalAddress(virtual_addr);
            tcb->sg[sg_idx].phys_addr = addr.QuadPart;
            tcb->sg[sg_idx].len = cur_len;
            tcb->sg[sg_idx].offset = 0;
            tcb->sg[sg_idx].pfn = phys_to_mfn(addr.QuadPart);
            sg_idx++;
            len += cur_len;
            cur_len = 0;
            dest_len = 0;
        } else {
            while (cur_len > 0) {
                if (cur_len > PAGE_SIZE) {
                    cp_len = PAGE_SIZE - dest_len;
                } else if (cur_len < PAGE_SIZE - dest_len) {
                    cp_len = cur_len;
                } else {
                    cp_len = PAGE_SIZE - dest_len;
                }
                NdisMoveMemory(pDest, virtual_addr, cp_len);
                cur_len -= cp_len;
                pDest += cp_len;
                virtual_addr += cp_len;
                dest_len += cp_len;
                len += cp_len;
                DPRINTK(DPRTL_LSO,
                    ("vnif_build_sg_ex: cp %p, len %d, dlen %d, tlen %d.\n",
                    cur_tcb->data, cp_len, dest_len, len));
                if (dest_len == PAGE_SIZE) {
                    tcb->sg[sg_idx].phys_addr = cur_tcb->data_pa.QuadPart;
                    tcb->sg[sg_idx].len = PAGE_SIZE;
                    tcb->sg[sg_idx].offset = 0;
                    tcb->sg[sg_idx].pfn =
                        phys_to_mfn(cur_tcb->data_pa.QuadPart),
                    sg_idx++;

                    if (cur_len) {
                        cur_tcb = (TCB *)
                            RemoveHeadList(&adapter->path[0].tcb_free_list);
                        cur_tcb->next = NULL;
                        pDest = cur_tcb->data;
                        dest_len = 0;
                        tail_tcb->next = cur_tcb;
                        tail_tcb = cur_tcb;
                    }
                }
            }
        }

        NdisGetNextBuffer(
            current_buffer,
            &current_buffer);
    }

    if (dest_len) {
        tcb->sg[sg_idx].phys_addr = cur_tcb->data_pa.QuadPart;
        tcb->sg[sg_idx].len = dest_len;
        tcb->sg[sg_idx].offset = 0;
        tcb->sg[sg_idx].pfn =
            phys_to_mfn(cur_tcb->data_pa.QuadPart),
        sg_idx++;
    }

#ifdef DBG
    if (data_len != len) {
        dest_len = 0;
        PRINTK(("vnif_build_sg_ex: len != data_len, %d %d\n", len, data_len));
        for (i = 0; i < sg_idx; i++) {
            dest_len += tcb->sg[i].len;
            PRINTK(("  sg[%d].len = %d, dest_len %d\n",
                i, tcb->sg[i].len, dest_len));
        }
    }
    DPRINTK(DPRTL_LSO, ("vnif_build_sg_ex: len %d\n", len));
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

static UINT
vnif_build_sg(PVNIF_ADAPTER adapter, TCB *tcb, PNDIS_BUFFER current_buffer,
    UINT packet_len)
{
    PHYSICAL_ADDRESS    addr;
    PNDIS_BUFFER        orig_buf;
    PUCHAR              virtual_addr;
    ULONG               page_offset;
    ULONG               len_inc;
    UINT                orig_len;
    UINT                sg_idx;
    UINT                built;
    UINT                cur_len;
    UINT                len;
    UINT                i;

    orig_buf = current_buffer;
    orig_len = packet_len;
    sg_idx = 0;
    built = 0;
    tcb->tcp_hdr_len = 0;
    for (i = 0; current_buffer; i++) {
        NdisQueryBufferSafe(
            current_buffer,
            &virtual_addr,
            &cur_len,
            NormalPagePriority);

        if (i <= 2 && !tcb->tcp_hdr_len) {
            vnif_build_ip_chksum_hdr(tcb, virtual_addr, cur_len, i, &built);
        }

        len = 0;
        while (len < cur_len && sg_idx < adapter->max_sg_el) {
            addr = MmGetPhysicalAddress(virtual_addr);
            page_offset = addr.u.LowPart & (PAGE_SIZE - 1);
            if (len + PAGE_SIZE - page_offset < cur_len) {
                len_inc = PAGE_SIZE - page_offset;
            } else{
                len_inc = cur_len - len;
            }

            tcb->sg[sg_idx].phys_addr = addr.QuadPart;
            tcb->sg[sg_idx].len = len_inc;
            tcb->sg[sg_idx].offset = page_offset;
            tcb->sg[sg_idx].pfn = phys_to_mfn(addr.QuadPart);

            DPRINTK(DPRTL_LSO,
                ("  idx %d, pfn %x, addr %x, offset %x, len %d.\n",
                sg_idx,
                tcb->sg[sg_idx].pfn,
                (uint32_t)tcb->sg[sg_idx].phys_addr,
                tcb->sg[sg_idx].offset,
                tcb->sg[sg_idx].len));

            sg_idx++;
            len += len_inc;
            virtual_addr += len_inc;
        }

        if (sg_idx < adapter->max_sg_el) {
            NdisGetNextBuffer(
                current_buffer,
                &current_buffer);
        } else {
            current_buffer = NULL;
        }
    }

    if (sg_idx < adapter->max_sg_el) {
        tcb->sg_cnt = sg_idx;
        return packet_len;
    }

    DPRINTK(DPRTL_LSO, ("vnif_build_sg: calling vnif_build_sg_ex\n"));
    return vnif_build_sg_ex(adapter, tcb, orig_buf, orig_len);
}

void
MPSendPackets(
  PVNIF_ADAPTER adapter,
  PPNDIS_PACKET PacketArray,
  UINT NumberOfPackets)

/* We failed the whole list, make sure we don't advance pvt. */
{
    LIST_ENTRY discard_list;
    LIST_ENTRY *list_packet;
    NDIS_PACKET *packet;
    TCB *tcb;
    PNDIS_BUFFER nbuf;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    uint32_t packet_len;
    UINT buffer_cnt;
    UINT len;
    unsigned int i;
    uint16_t flags;

    DPRINTK(DPRTL_IO, ("VNIF: VNIFSendPackets IN.\n"));
    if (adapter == NULL) {
        PRINTK(("VNIFSendPackets: received null adapter\n"));
        return;
    }
    VNIF_DUMP(adapter, 0, "VNIFSendPackets", 2, 0);

    /* send the packets */
    NdisAcquireSpinLock(&adapter->path[0].tx_path_lock);

    if (VNIF_IS_READY(adapter)) {
        NdisInitializeListHead(&discard_list);
        for (i = 0; i < NumberOfPackets; i++) {
            NdisQueryPacketLength(PacketArray[i], &packet_len);
            InsertTailList(&adapter->SendWaitList,
                (PLIST_ENTRY)PacketArray[i]->MiniportReserved);
        }
        if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_SEND_IN_PROGRESS)) {
            NdisReleaseSpinLock(&adapter->path[0].tx_path_lock);
            DPRINTK(DPRTL_ON,
                ("MPSendPackets: VNF_ADAPTER_SEND_IN_PROGRESS\n"));
            return;
        }
        if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_SEND_SLOWDOWN)) {
            DPRINTK(DPRTL_ON,
                ("Too many receives outstanding %x, queuing sends.\n",
                adapter->nBusyRecv));
            NdisReleaseSpinLock(&adapter->path[0].tx_path_lock);
            return;
        }

        VNIF_SET_FLAG(adapter, VNF_ADAPTER_SEND_IN_PROGRESS);

        while (VRING_CAN_ADD_TX(adapter, 0, VNIF_MAX_TX_SG_ELEMENTS)
                && !IsListEmpty(&adapter->path[0].tcb_free_list)) {
            list_packet = RemoveHeadList(&adapter->SendWaitList);
            if (list_packet != &adapter->SendWaitList) {
                packet = (NDIS_PACKET *)CONTAINING_RECORD(list_packet,
                    NDIS_PACKET, MiniportReserved);
            } else {
                /* No more packets on the WaitList or in PacketArray. */
                DPRINTK(DPRTL_TRC, ("MPSendPackets: no buffers in queues\n"));
                break;
            }

            flags = 0;
            if (adapter->cur_tx_tasks) {
                if (!should_checksum_tx(adapter, packet, &flags)) {
                    InsertTailList(&discard_list,
                       (PLIST_ENTRY)packet->MiniportReserved);
                    continue;
                }
            }

            tcb = (TCB *) RemoveHeadList(&adapter->path[0].tcb_free_list);
            tcb->orig_send_packet = packet;

            NdisQueryPacketLength(packet, &packet_len);
            NdisQueryPacket(packet, &buffer_cnt, NULL, &nbuf, &len);
            if (packet_len <= ETH_MAX_PACKET_SIZE) {
                len = VNIFCopyPacket(tcb, nbuf, len, adapter->buffer_offset);
            } else {
                DPRINTK(DPRTL_TRC, ("** Starting to do a large send.\n"));
                DPRINTK(DPRTL_ON, ("vnif_build_sg: len %d, physfrags %d.\n",
                    len, buffer_cnt));
                if (buffer_cnt < adapter->max_sg_el) {
                    vnif_build_sg(adapter, tcb, nbuf, len);
                } else if (len < PAGE_SIZE - adapter->buffer_offset) {
                    len = VNIFCopyPacket(tcb, nbuf, len,
                                         adapter->buffer_offset);
                } else{
                    vnif_build_sg_ex(adapter, tcb, nbuf, len);
                }

                if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_TCP) {
                    flags |= NETTXF_data_validated | NETTXF_csum_blank;
                }
            }

            if (len) {
                VNIF_TRACK_TX_SET(tcb->len, len);
                VNIF_GET_TX_REQ_PROD_PVT(adapter, 0, &i);
                vnif_add_tx(adapter, 0, tcb, len, packet_len, flags, &i);
                VNIF_SET_TX_REQ_PROD_PVT(adapter, 0, i);
            } else {
                PRINTK(("MPSendPackets: data prep failed on length %d.\n",
                    packet_len));
                if (tcb->sg_cnt < adapter->max_sg_el) {
                    NdisMSendComplete(adapter->AdapterHandle,
                        packet,
                        NDIS_STATUS_RESOURCES);
                } else{
                    NdisMSendComplete(adapter->AdapterHandle,
                        packet,
                        NDIS_STATUS_BUFFER_OVERFLOW);
                }
                InsertHeadList(&adapter->path[0].tcb_free_list, &tcb->list);
                continue;
            }

            VNIFInterlockedIncrement(adapter->nBusySend);
            VNIFIncStat(adapter->pv_stats->tx_pkt_cnt);
        }

        vnif_notify_always_tx(adapter, 0);

        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SEND_IN_PROGRESS);
        NdisReleaseSpinLock(&adapter->path[0].tx_path_lock);

        while (!IsListEmpty(&discard_list)) {
            list_packet = RemoveHeadList(&discard_list);
            packet = (NDIS_PACKET *)CONTAINING_RECORD(list_packet,
                NDIS_PACKET, MiniportReserved);
            DPRINTK(DPRTL_IO,
                ("VNIFSendPackets discarding packet %p.\n", packet));
            NdisMSendComplete(
                adapter->AdapterHandle,
                packet,
                NDIS_STATUS_FAILURE);
        }
    } else {
        DPRINTK(DPRTL_ON, ("VNIFSendPackets not ready %x.\n",
                           adapter->adapter_flags));
        NdisReleaseSpinLock(&adapter->path[0].tx_path_lock);
        status = VNIF_GET_STATUS_FROM_FLAGS(adapter);
        for (i = 0; i < NumberOfPackets; i++) {
            DPRINTK(DPRTL_IO, ("VNIFSendPackets completing packet %p.\n",
                PacketArray[i]));
            NdisMSendComplete(
                adapter->AdapterHandle,
                PacketArray[i],
                status);
        }
    }

    DPRINTK(DPRTL_TRC, ("VNIF: VNIFSendPackets OUT.\n"));
}


int
VNIFCheckSendCompletion(PVNIF_ADAPTER adapter, UINT path_id)
{
    /*
     * This function is to be called within the dpc
     * to free those completed send packets.
     */
    PNDIS_PACKET TxPacketArray[NET_TX_RING_SIZE];
    TCB *tcb;
    TCB *return_tcb;
    UINT cons, prod;
    uint32_t cnt;
    UINT len;
    UINT i;
    UINT txstatus;
    int did_work = 0;

    DPRINTK(DPRTL_TRC, ("VNIF: VNIFCheckSendCompletion IN.\n"));
#ifdef DBG
    if (KeGetCurrentIrql() > 2) {
        KdPrint(("VNIFCheckSendCompletion irql = %d\n", KeGetCurrentIrql()));
    }
#endif

    DPRINTK(DPRTL_TRC, ("VNIF: VNIF Check Send Completion.\n"));
    NdisDprAcquireSpinLock(&adapter->path[0].tx_path_lock);
    prod = 0;
    cnt = 0;
    do {
        VNIF_GET_TX_RSP_PROD(adapter, path_id, &prod);
        KeMemoryBarrier();

        VNIF_GET_TX_RSP_CONS(adapter, path_id, &cons);
        while ((tcb = vnif_get_tx(adapter, path_id, &cons, prod,
                                  cnt, &len, &txstatus))
                != NULL) {
            if (tcb->orig_send_packet) {
                /* orig_send_packet will be null for gratuitous arp. */
                TxPacketArray[cnt] = tcb->orig_send_packet;
                tcb->orig_send_packet = NULL;
                cnt++;
            }
            if (txstatus == NETIF_RSP_OKAY) {
                adapter->GoodTransmits++;
            } else{
                if (txstatus == NETIF_RSP_ERROR) {
                    adapter->ifOutErrors++;
                }
                if (txstatus == NETIF_RSP_DROPPED) {
                    adapter->ifOutDiscards++;
                }
                PRINTK(("VNIF: status %x, send errs %lld, drped %lld, tcb %p\n",
                    txstatus, adapter->ifOutErrors,
                    adapter->ifOutDiscards, tcb));
                PRINTK(("  sg_cnt %d, cons %d, prod %d\n",
                    tcb->sg_cnt, cons, prod));
            }

            VNIFInterlockedDecrement(adapter->nBusySend);

            /* we don't release grant_ref until the device unload. */

#ifdef DBG
            if (!VNIF_IS_READY(adapter)) {
                DPRINTK(DPRTL_ON,
                    ("VNIFCheckSendCompletion: not ready %p\n", tcb));
            }
#endif
            while (tcb) {
                return_tcb = tcb;
                tcb = tcb->next;
                return_tcb->next = NULL;
                InsertHeadList(&adapter->path[0].tcb_free_list,
                               &return_tcb->list);
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
        did_work++;
    } while (VNIF_HAS_UNCONSUMED_RESPONSES(adapter->path[0].tx, cons, prod));

    NdisDprReleaseSpinLock(&adapter->path[0].tx_path_lock);

    /* Now that we've released the spinlock, complete all the sends. */
    for (i = 0; i < cnt; i++) {
        NdisMSendComplete(
            adapter->AdapterHandle,
            TxPacketArray[i],
            NDIS_STATUS_SUCCESS);
    }

    if (VNIF_IS_READY(adapter)) {
        /* See if we can send any packets that we may have queued. */
        if (!IsListEmpty(&adapter->SendWaitList)) {
            MPSendPackets(adapter, NULL, 0);
        }
    }
#ifdef DBG
    else {
        DPRINTK(DPRTL_ON,
            ("VNIFCheckSendCompletion: adptr not ready, reset, halt, etc. %p\n",
             adapter));
    }
#endif
    DPRINTK(DPRTL_TRC, ("VNIF: VNIFCheckSendCompletion OUT.\n"));
    return did_work;

    /* TODO: should try to wake up WaitList */
}

static void
vnif_rx_checksum(PVNIF_ADAPTER adapter, RCB *rcb, UINT total_len)
{
    PNDIS_TCP_IP_CHECKSUM_PACKET_INFO info;
    uint8_t *data_buf;
    NDIS_STATUS status;
    BOOLEAN valid_chksum;

    data_buf = rcb->page + adapter->buffer_offset;

    status = get_ip_pkt_info(rcb, adapter->buffer_offset, total_len);
    if (status != NDIS_STATUS_SUCCESS) {
        return;
    }
    if (rcb->pkt_info.protocol != VNIF_PACKET_TYPE_TCP
            && rcb->pkt_info.protocol != VNIF_PACKET_TYPE_UDP) {
        return;
    }

    info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO) (
            &(NDIS_PER_PACKET_INFO_FROM_PACKET(
            rcb->packet,
            TcpIpChecksumPacketInfo)));
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
            (BOOLEAN)VNIF_PACKET_NEEDS_CHECKSUM(rcb));
    }

    if (rcb->pkt_info.protocol == VNIF_PACKET_TYPE_TCP) {
        info->Receive.NdisPacketTcpChecksumSucceeded = valid_chksum;
        info->Receive.NdisPacketTcpChecksumFailed = !valid_chksum;
    } else {
        info->Receive.NdisPacketUdpChecksumSucceeded = valid_chksum;
        info->Receive.NdisPacketUdpChecksumFailed = !valid_chksum;
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
         info->Receive.NdisPacketIpChecksumFailed,
         info->Receive.NdisPacketIpChecksumSucceeded,
         info->Receive.NdisPacketTcpChecksumFailed,
         info->Receive.NdisPacketTcpChecksumSucceeded,
         info->Receive.NdisPacketUdpChecksumFailed,
         info->Receive.NdisPacketUdpChecksumSucceeded));
}

static void
vnif_build_nb(PVNIF_ADAPTER adapter, RCB *rcb)
{
    PNDIS_PACKET packet;
    PNDIS_BUFFER tail_mdl;

    packet = rcb->packet;
    packet->Private.Head = rcb->buffer;
    packet->Private.TotalLength  = rcb->total_len;
    *((RCB **)packet->MiniportReserved) = rcb;

    tail_mdl = NULL;
    while (rcb) {
        if (tail_mdl != NULL) {
            tail_mdl->Next = rcb->buffer;
        }
        tail_mdl = rcb->buffer;
        NdisAdjustBufferLength(rcb->buffer, rcb->len);
        rcb = rcb->next;
    }
    tail_mdl->Next = NULL;
    packet->Private.Tail = tail_mdl;
    packet->Private.ValidCounts = FALSE;
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
VNIFReceivePackets(IN PVNIF_ADAPTER adapter, UINT path_id, UINT nbls)
{
    PNDIS_PACKET RecvPacketArray[NET_RX_RING_SIZE];
    PNDIS_PACKET free_now_packet_array[NET_RX_RING_SIZE];
    rcv_to_process_q_t *rcv_q;
    uint32_t cnt;
    uint32_t free_now_cnt;
    UINT rp;
    UINT i;
    UINT old;
    RCB *rcb;
    UINT len;
    UINT rcb_added_to_ring;
    PNDIS_PACKET packet;
    int more_to_do;
    uint32_t j;
    uint32_t ring_size;
    uint64_t st;

    DPRINTK(DPRTL_TRC, ("VNIFReceivePackets: start.\n"));

    VNIF_INC_REF(adapter);

    ring_size = VNIF_RX_RING_SIZE(adapter);
    VNIFReceivePacketsStats(adapter, 0, ring_size);

    rp = 0;
    cnt = 0;
    free_now_cnt = 0;
    rcb_added_to_ring = 0;
    VNIF_GET_RX_REQ_PROD(adapter, path_id, &old);
    rcv_q = &adapter->rcv_q[path_id];
    NdisDprAcquireSpinLock(&adapter->path[path_id].rx_path_lock);
    NdisDprAcquireSpinLock(&rcv_q->rcv_to_process_lock);
    do {
        VNIF_GET_RX_RSP_PROD(adapter, path_id, &rp);
        KeMemoryBarrier();

        VNIF_GET_RX_RSP_CONS(adapter, path_id, &i);
        while ((rcb = vnif_get_rx(adapter, path_id, rp, &i, &len)) != NULL) {
            InsertTailList(&rcv_q->rcv_to_process, &rcb->list);
            VNIFInterlockedIncrementStat(adapter->pv_stats->rx_to_process_cnt);
            vnif_rcb_verify(adapter, rcb, path_id);
        }

        VNIF_SET_RX_RSP_CONS(adapter, path_id, rp);

        VNIFStatQueryInterruptTime(st);

        while (cnt < ring_size
               && !IsListEmpty(&rcv_q->rcv_to_process)) {
            rcb = (RCB *)RemoveHeadList(&rcv_q->rcv_to_process);
            len = rcb->total_len;
            VNIFInterlockedDecrementStat(adapter->pv_stats->rx_to_process_cnt);
            if (len > NETIF_RSP_NULL) {
                if (VNIF_IS_VALID_RCB(rcb)) {
                    if (vnif_should_complete_packet(adapter,
                            rcb->page + adapter->buffer_offset, len)) {
                        if (rcb->len < VNIF_TCPIP_HEADER_LEN) {
                            rcb_added_to_ring += vnif_collapse_rx(adapter, rcb);
                        }
                        if (len < ETH_MIN_PACKET_SIZE) {
                            NdisZeroMemory(
                                rcb->page + adapter->buffer_offset + len,
                                ETH_MIN_PACKET_SIZE - len);
                        }

                        vnif_build_nb(adapter, rcb);

                        if (adapter->cur_rx_tasks) {
                            vnif_rx_checksum(adapter, rcb, len);
                        }

                        rcb->st = st;
#ifdef DBG
                        if (adapter->pv_stats) {
                            rcb->seq = adapter->pv_stats->rcb_seq;
                        }
                        VNIFInterlockedIncrementStat(
                            adapter->pv_stats->rcb_seq);
#endif
                        packet = rcb->packet;
                        RecvPacketArray[cnt] = packet;
                        cnt++;
                        adapter->GoodReceives++;
                        VNIFInterlockedIncrement(adapter->nBusyRecv);
                        if (adapter->nBusyRecv < adapter->rcv_limit) {
                            NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
                            VNIFIncStat(adapter->pv_stats->spkt_cnt);
                        } else {
                            NDIS_SET_PACKET_STATUS(packet,
                                NDIS_STATUS_RESOURCES);
                            free_now_packet_array[free_now_cnt] = packet;
                            free_now_cnt++;
                            VNIFIncStat(adapter->pv_stats->rpkt_cnt);
                        }
                        DPRINTK(DPRTL_TRC,
                            ("Receiveing rcb %x.\n", rcb->index));
                        if (adapter->num_rcb > NET_RX_RING_SIZE) {
                            DPRINTK(DPRTL_TRC,
                                ("%s: vnif_add_rcb_to_ring_from_list.\n",
                                 __func__));
                            rcb_added_to_ring +=
                                vnif_add_rcb_to_ring_from_list(adapter,
                                                               path_id);
                        }
                    } else {
                        vnif_return_rcb(adapter, rcb);
                        rcb_added_to_ring++;
                    }
                } else {
                    /*
                     * This definitely indicates a bug, either in this driver
                     * or in the backend driver. In future this should flag the
                     * bad situation to the system controller to reboot the
                     * backed.
                     */
                    PRINTK(("VNIF: GRANT_INVALID_REF for rcb %d.\n",
                        rcb->index));
                    vnif_return_rcb(adapter, rcb);
                    continue;
                }
            } else {
                vnif_drop_rcb(adapter, rcb, rcb->len);
                continue;
            }
        }
        DPRINTK(DPRTL_TRC, ("VNIF: VNIF Received Packets = %d.\n", cnt));
        VNIF_RING_FINAL_CHECK_FOR_RESPONSES(adapter->path[0].rx, &more_to_do);
    } while (more_to_do && cnt < ring_size);

    if ((uint32_t)adapter->nBusyRecv > adapter->tx_throttle_start) {
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_SEND_SLOWDOWN);
        DPRINTK(DPRTL_ON,
            ("VNIFReceivePackets: nBusyRecv %d, slowing down sends\n",
            adapter->nBusyRecv));
    }

    if (!IsListEmpty(&rcv_q->rcv_to_process)) {
        VNIF_SET_TIMER(adapter->rcv_timer, 500);
    }

#ifdef VNIF_RCV_DELAY
    if (adapter->rcv_delay) {
        NdisStallExecution(adapter->rcv_delay);
    }
#endif

    VNIF_RX_NOTIFY(adapter, path_id, rcb_added_to_ring, old);

    /*
     * Holding the lock over the call hangs the machine.
     */
    NdisDprReleaseSpinLock(&rcv_q->rcv_to_process_lock);
    NdisDprReleaseSpinLock(&adapter->path[path_id].rx_path_lock);
    if (cnt != 0) {
        VNIFReceivePacketsPostStats(adapter, 0, ring_size, cnt);

        NdisMIndicateReceivePacket(
          adapter->AdapterHandle,
          RecvPacketArray,
          cnt);

        if (free_now_cnt) {
            NdisDprAcquireSpinLock(&adapter->path[path_id].rx_path_lock);
            for (j = 0; j < free_now_cnt; j++) {
                MPReturnPacketWithLock(adapter, free_now_packet_array[j]);
            }
            vnif_check_tx_throttle(adapter);
            NdisDprReleaseSpinLock(&adapter->path[path_id].rx_path_lock);
        }
    }

    VNIF_DEC_REF(adapter);
    DPRINTK(DPRTL_TRC, ("VNIFReceivePackets: end.\n"));
}

static void
vnif_check_tx_throttle(PVNIF_ADAPTER adapter)
{
    DPRINTK(DPRTL_TRC, ("  %s: in\n", __func__));
    if ((uint32_t)adapter->nBusyRecv <= adapter->tx_throttle_stop) {
        if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_SEND_SLOWDOWN)) {
            VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SEND_SLOWDOWN);
            DPRINTK(DPRTL_ON,
                    ("  %s: nBusyRecv %d, clearing send slowdown\n",
                     __func__, adapter->nBusyRecv));
            if (VNIF_IS_READY(adapter)) {
                /* See if we can send any packets that we may have queued. */
                if (!IsListEmpty(&adapter->SendWaitList)) {
                    DPRINTK(DPRTL_TRC, ("    MPSendPackets.\n"));
                    MPSendPackets(adapter, NULL, 0);
                }
            }
        }
    }
    DPRINTK(DPRTL_TRC, ("  %s: out\n", __func__));
}

static void
MPReturnPacketWithLock(PVNIF_ADAPTER adapter, PNDIS_PACKET packet)
{
    RCB *rcb;

    DPRINTK(DPRTL_TRC, ("  %s: in\n", __func__));

    rcb = *((PRCB *)packet->MiniportReserved);
    VNIFReturnRcbStats(adapter, rcb);
    vnif_return_rcb(adapter, rcb);
    VNIFInterlockedDecrement(adapter->nBusyRecv);

    DPRINTK(DPRTL_TRC, ("  %s: out\n", __func__));
}

VOID
MPReturnPacket(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PNDIS_PACKET packet)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)MiniportAdapterContext;

    DPRINTK(DPRTL_IO, ("%s: in\n", __func__));
    NdisDprAcquireSpinLock(&adapter->path[0].rx_path_lock);

    MPReturnPacketWithLock(adapter, packet);
    vnif_check_tx_throttle(adapter);

    VNIF_RX_RING_KICK_ALWAYS(&adapter->path[0]);
    NdisDprReleaseSpinLock(&adapter->path[0].rx_path_lock);
    DPRINTK(DPRTL_IO, ("%s: out\n", __func__));
}

VOID
VNIFFreeQueuedSendPackets(PVNIF_ADAPTER adapter, NDIS_STATUS status)
{
    PLIST_ENTRY     pEntry;
    PNDIS_PACKET    Packet;

#ifdef DBG
    if (KeGetCurrentIrql() > 2) {
        KdPrint(("VNIFFreeQueuedSendPackets irql = %d\n", KeGetCurrentIrql()));
    }
#endif

    while (TRUE) {
        pEntry = (PLIST_ENTRY) NdisInterlockedRemoveHeadList(
            &adapter->SendWaitList,
            &adapter->path[0].tx_path_lock);
        if (!pEntry) {
            break;
        }

        Packet = CONTAINING_RECORD(pEntry, NDIS_PACKET, MiniportReserved);
        DPRINTK(DPRTL_ON, ("VNIFFreeQueuedSendPackets %p\n", Packet));
        NdisMSendComplete(adapter->AdapterHandle, Packet, status);

    }
}


void
VNIFIndicateLinkStatus(PVNIF_ADAPTER adapter, uint32_t status)
{
    DPRINTK(DPRTL_INIT, ("VNIFIndicateLinkStatus: %x\n", status));
    NdisMIndicateStatus(adapter->AdapterHandle,
        (status ?
            NDIS_STATUS_MEDIA_CONNECT : NDIS_STATUS_MEDIA_DISCONNECT),
        (PVOID)0, 0);

    NdisMIndicateStatusComplete(adapter->AdapterHandle);
}

void
vnif_complete_lost_sends(VNIF_ADAPTER *adapter)
{
    PNDIS_PACKET TxPacketArray[NET_TX_RING_SIZE];
    TCB *tcb;
    NDIS_PACKET *pkt;
    uint32_t cnt;

    for (cnt = 0; cnt < NET_TX_RING_SIZE; cnt++) {
        tcb = adapter->TCBArray[cnt];
        if (!tcb) {
            continue;
        }
        if (!tcb->orig_send_packet) {
            continue;
        }

        pkt = tcb->orig_send_packet;
        tcb->orig_send_packet = NULL;

        PRINTK(("%s: packet %p.\n", __func__, pkt));
        NdisMSendComplete(
            adapter->AdapterHandle,
            pkt,
            NDIS_STATUS_RESET_IN_PROGRESS);
    }
}
