/*
 * Copyright (c) 2008-2017 Red Hat, Inc.
 * Copyright 2011-2012 Novell, Inc.
 * Copyright 2012-2025 SUSE LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "miniport.h"
#include <win_rtlq_flags.h>

BOOLEAN
vnif_should_exit_txrx_dpc(PVNIF_ADAPTER adapter, ULONG txrx_ind, UINT path_id)
{
    NdisAcquireSpinLock(&adapter->adapter_flag_lock);
    /*
     * Don't do VNIF_SET_FLAG(adapter, VNF_ADAPTER_DPC_IN_PROGRESS);
     * because we want the test and set of the flags to be under
     * the same spinlock.
     */
    if (VNIF_SHOULD_EXIT_TXRX_DPC(adapter, txrx_ind, path_id)) {
        DPRINTK(DPRTL_UNEXPD,
            ("%s %x: cpu %d path_id %d, txrx %x exiting flags 0x%x adptr_f %x.\n",
             __func__, adapter->CurrentAddress[MAC_LAST_DIGIT],
             KeGetCurrentProcessorNumber(), path_id, txrx_ind,
             adapter->path[path_id].path_id_flags,
             adapter->adapter_flags));
        NdisReleaseSpinLock(&adapter->adapter_flag_lock);
        return TRUE;
    }

    adapter->path[path_id].path_id_flags |= txrx_ind;

    NdisReleaseSpinLock(&adapter->adapter_flag_lock);

    return FALSE;
}

void
vnif_txrx_interrupt_dpc(PVNIF_ADAPTER adapter,
                        ULONG txrx_ind,
                        UINT path_id,
                        UINT max_nbls_to_indicate)
{
    UINT did_work;
    UINT more_to_do;

    did_work = 0;

    DPRINTK(DPRTL_DPC, ("%s: IN txrx_ind 0x%x path_id %d\n",
                        __func__, txrx_ind, path_id));

    if (adapter == NULL) {
        PRINTK(("%s: adapter is null.\n", __func__));
        return;
    }

    VNIFIncStat(adapter->pv_stats->ints);
    VNIF_INC_REF(adapter);

    vnif_rss_test_dpc(__func__, adapter);

    do {
        more_to_do = 0;

        if (path_id >= adapter->num_paths) {
            DPRINTK(DPRTL_UNEXPD,
                    ("%s: %d >= %d\n", __func__, path_id, adapter->num_paths));
            VNIFReceivePackets(adapter, path_id, max_nbls_to_indicate);
            break;
        }

        if (vnif_should_exit_txrx_dpc(adapter, txrx_ind, path_id) == TRUE) {
            break;
        }

        VNIF_DUMP(adapter, path_id, "vnif_txrx_interrupt_dpc in", 3, 0);

        if (txrx_ind == VNIF_TX_INT) {
            did_work += VNIFCheckSendCompletion(adapter, path_id);
            more_to_do = VNIF_RING_HAS_UNCONSUMED_RESPONSES(
                adapter->path[path_id].tx);
        } else {
            VNIFReceivePackets(adapter, path_id, max_nbls_to_indicate);

            if (g_running_hypervisor == HYPERVISOR_XEN) {
                more_to_do = VNIF_RING_HAS_UNCONSUMED_RESPONSES(
                    adapter->path[path_id].rx);
            }
            did_work++;
        }

        VNIF_DUMP(adapter, path_id, "vnif_txrx_interrupt_dpc out", 3, 0);

        NdisAcquireSpinLock(&adapter->adapter_flag_lock);
        adapter->path[path_id].path_id_flags &= ~(txrx_ind);
        NdisReleaseSpinLock(&adapter->adapter_flag_lock);

    } while (more_to_do);

#if NDIS_SUPPORT_NDIS6
    if (g_running_hypervisor == HYPERVISOR_KVM) {
        if (did_work) {
            NdisAcquireSpinLock(&adapter->adapter_flag_lock);
            if (adapter->adapter_flags & VNF_ADAPTER_POLLING) {
                KeInsertQueueDpc(&adapter->poll_dpc, NULL, NULL);
            }
            NdisReleaseSpinLock(&adapter->adapter_flag_lock);
        }
    }
#endif

    VNIF_DEC_REF(adapter);

    DPRINTK(DPRTL_DPC, ("%s: OUT txrx_ind 0x%x path_id %d\n",
                          __func__, txrx_ind, path_id));
}

void
vnif_call_txrx_interrupt_dpc(PVNIF_ADAPTER adapter)
{
    UINT loop_cnt;
    UINT i;

    loop_cnt = max(adapter->num_paths, adapter->num_rcv_queues);
    for (i = 0; i < loop_cnt; i++) {
        vnif_txrx_interrupt_dpc(adapter,
                                VNIF_TX_INT,
                                i,
                                NDIS_INDICATE_ALL_NBLS);
        vnif_txrx_interrupt_dpc(adapter,
                                VNIF_RX_INT,
                                i,
                                NDIS_INDICATE_ALL_NBLS);
    }
}

VOID
vnif_rx_path_dpc(
  IN PKDPC Dpc,
  IN PVOID DeferredContext,
  IN PVOID SystemArgument1,
  IN PVOID SystemArgument2)
{
    PVNIF_ADAPTER adapter;
    UINT path_id;
    UINT max_nbls_to_indicate;
#ifdef DBG
    PROCESSOR_NUMBER processor;
    UINT rcv_qidx;
    UINT cur_cpu;
#endif

    adapter = (PVNIF_ADAPTER)DeferredContext;
    if (adapter == NULL) {
        RPRINTK(DPRTL_UNEXPD, ("VNIF: %s adapter == NULL.\n", __func__));
        return;
    }

    path_id = (UINT)((ULONG_PTR)SystemArgument1);
    max_nbls_to_indicate = (UINT)((ULONG_PTR)SystemArgument2);

    DPRINTK(DPRTL_RSS,
            ("%s: rxDPC path_id %d max_nbls_to_indicate %d\n",
             __func__, path_id, max_nbls_to_indicate));

#if NDIS_SUPPORT_NDIS620
#ifdef DBG
    cur_cpu = vnif_get_current_processor(NULL);
    if (cur_cpu != path_id) {
        PRINTK(("%s: rxDPC cur_cpu %d path_id %d max_nbls_to_indicate %d\n",
                __func__, cur_cpu, path_id, max_nbls_to_indicate));
    }

    KeGetProcessorNumberFromIndex(path_id, &processor);

    DPRINTK(DPRTL_RSS, ("VNIF: %s - cpu_idx %d pn %d g %d In.\n",
                        __func__,
                        path_id,
                        processor.Number,
                        processor.Group));
    if (path_id < adapter->rss.cpu_idx_mapping_sz) {
        rcv_qidx = adapter->rss.cpu_idx_mapping[path_id];
        if (rcv_qidx != VNIF_NO_RECEIVE_QUEUE) {
            if (adapter->rcv_q[rcv_qidx].rcv_processor.Group
                    != processor.Group
                || adapter->rcv_q[rcv_qidx].rcv_processor.Number
                    != processor.Number) {
                PRINTK(("** pn %d g %d does not match rcv_q[%d] pn %d g %d\n",
                        processor.Number,
                        processor.Group,
                        rcv_qidx,
                        adapter->rcv_q[rcv_qidx].rcv_processor.Number,
                        adapter->rcv_q[rcv_qidx].rcv_processor.Group));
            }
        } else {
            PRINTK(("** rcvqidx == VNIF_NO_RECEIVE_QUEUE (%d)\n",
                    VNIF_NO_RECEIVE_QUEUE));
        }
    }
#endif
#else
    DPRINTK(DPRTL_RSS, ("VNIF: %s - cpu_idx %d In.\n", __func__, path_id));
#endif

    vnif_rss_test_dpc(__func__, adapter);

    vnif_txrx_interrupt_dpc(adapter,
                            VNIF_RX_INT,
                            path_id,
                            max_nbls_to_indicate);

    DPRINTK(DPRTL_RSS, ("VNIF: %s - Out.\n", __func__));
}

NDIS_STATUS
vnif_setup_rx_path_dpc(VNIF_ADAPTER *adapter)
{
    NDIS_STATUS status;
    UINT i;

    for (i = 0; i < adapter->num_rcv_queues; i++) {
        KeInitializeDpc(&adapter->rcv_q[i].rcv_q_dpc,
                        vnif_rx_path_dpc,
                        adapter);
        KeSetImportanceDpc(&adapter->rcv_q[i].rcv_q_dpc, HighImportance);
    }
    vnif_rss_set_rcv_q_targets(adapter);

    return NDIS_STATUS_SUCCESS;
}

BOOLEAN
calculate_rx_checksum(RCB *rcb,
                      uint8_t *pkt_buf,
                      uint32_t pkt_len,
                      UINT ip_ver,
                      uint16_t ip_hdr_len,
                      uint8_t protocol,
                      BOOLEAN update_chksum)
{
    uint8_t *ip_hdr;
    uint16_t *buff;
    uint16_t *src_addr;
    uint16_t *dest_addr;
    uint16_t *w;
    uint32_t len;
    uint32_t cur_len;
    uint32_t sum;
    uint32_t chksum_offset;
    uint16_t odd;
    uint16_t orig_chksum;
    BOOLEAN chksum_valid;

    chksum_valid = TRUE;
    ip_hdr = pkt_buf + ETH_HEADER_SIZE;
    if (ip_ver == IPV4) {
        len = RtlUshortByteSwap(((ipv4_header_t *)ip_hdr)->ip_total_length)
            - ip_hdr_len;
        src_addr = (uint16_t *)(ip_hdr + IP_HDR_SRC_ADDR_OFFSET);
        dest_addr = (uint16_t *)(ip_hdr + IP_HDR_DEST_ADDR_OFFSET);

        /* Calculate the pseudo header. */
        sum = 0;
        sum += src_addr[0];
        sum += src_addr[1];
        sum += dest_addr[0];
        sum += dest_addr[1];
        sum += RtlUshortByteSwap(len);
        sum += RtlUshortByteSwap(protocol);
    } else {
        len = pkt_len - (ETH_HEADER_SIZE + ip_hdr_len);
        sum = calculate_pseudo_ipv6_header_checksum(ip_hdr,
                                                    ip_hdr_len,
                                                    protocol);
    }

    if (protocol == VNIF_PACKET_TYPE_TCP) {
        chksum_offset = VNIF_PACKET_WORD_OFFSET_TCP_CHKSUM;
    } else {
        chksum_offset = VNIF_PACKET_WORD_OFFSET_UDP_CHKSUM;
    }

    buff = (uint16_t *)(ip_hdr + ip_hdr_len);

    orig_chksum = buff[chksum_offset];
    DPRINTK(DPRTL_CHKSUM, ("Protocol %x, bad checksum = %x, ",
        protocol, buff[chksum_offset]));

    buff[chksum_offset] = 0;
    w = buff;

    /* Calculate the checksum for the header and payload. */
    cur_len = rcb->len - (ETH_HEADER_SIZE + ip_hdr_len);
    if (cur_len > len) {
        cur_len = len;
    }
    while (len > 1 && rcb) {
        while (cur_len > 1) {
            cur_len -= 2;
            sum += *w++;
            len -= 2;
        }
        rcb = rcb->next;
        if (rcb) {
            if (cur_len == 0) {
                cur_len = rcb->len;
                w = (uint16_t *)rcb->page;
            } else {
                /*
                 * We have one byte left in the current page and more data
                 * in another fragment. Take the current byte and one from
                 * the next fragment. Due to the byte swapping, put the last
                 * byte in the lower portion on the uint16 and the first byte
                 * of the next fragment in the upper portion of the uint16.
                 */
                odd = *w & 0xFF;
                odd |= ((uint16_t)(rcb->page[0]) << 8);
                sum += odd;
                len -= 2;
                cur_len = rcb->len - 1;
                w = (uint16_t *)(rcb->page + 1);
            }

        }
    }

    /*
     * If len is 1 there ist still on byte left. We add a padding
     * byte (0xFF) to build a 16 bit word.
     */
    if (len > 0) {
        sum += *w & 0xFF;
    }

    /*
     * Keep only the last 16 bits of the 32 bit calculated sum and
     * add the carries.
     */
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    /* Take the one's complement of sum. */
    sum = ~sum;

    if (update_chksum == TRUE) {
        buff[chksum_offset] = (uint16_t)sum;
        DPRINTK(DPRTL_CHKSUM, ("orig new checksum = %x %x\n",
                               orig_chksum, buff[chksum_offset]));
    } else {
        if (orig_chksum != (uint16_t)sum) {
            DPRINTK(DPRTL_CHKSUM,
                ("%x Found bad checksum ptk_len %x len %x: bad %x good %x\n",
                 protocol, pkt_len, len, orig_chksum, (uint16_t)sum));
            chksum_valid = FALSE;
        }
        buff[chksum_offset] = orig_chksum;
    }

    return chksum_valid;
}

static UINT32
raw_checksum_calculator(PVOID buffer, ULONG len)
{
    uint32_t val = 0;
    PUSHORT pus = (PUSHORT)buffer;
    ULONG count = len >> 1;

    while (count--) {
        val += *pus++;
    }
    if (len & 1) {
        val += (USHORT)*(PUCHAR)pus;
    }
    return val;
}

static __inline USHORT
raw_checksum_finalize(UINT32 val)
{
    val = (((val >> 16) | (val << 16)) + val) >> 16;
    return (USHORT)~val;
}

static __inline USHORT
checksum_calculator_flat(PVOID buffer, ULONG len)
{
    return raw_checksum_finalize(raw_checksum_calculator(buffer, len));
}

uint16_t
calculate_pseudo_ipv4_header_checksum(void *hdr)
{
    ipv4_header_t *ip_hdr;
    ipv4_pseudo_header_t pseudo_hdr;
    uint16_t header_len;
    uint16_t len;
    uint16_t checksum;

    ip_hdr = (ipv4_header_t *)hdr;
    header_len = IP_HEADER_LENGTH(ip_hdr);
    len = RtlUshortByteSwap(ip_hdr->ip_total_length) - header_len;

    pseudo_hdr.ipph_src  = ip_hdr->ip_src;
    pseudo_hdr.ipph_dest = ip_hdr->ip_dest;
    pseudo_hdr.ipph_zero = 0;
    pseudo_hdr.ipph_protocol = ip_hdr->ip_protocol;
    pseudo_hdr.ipph_length = RtlUshortByteSwap(len);
    checksum = checksum_calculator_flat(&pseudo_hdr, sizeof(pseudo_hdr));
    return ~checksum;
}

#ifdef DBG
typedef struct giph_s {
    USHORT iplen;
    USHORT payload;
    USHORT spayload;
    USHORT flen;
    ULONG ipph_length;
    USHORT chksum;
} giph_t;

giph_t giph;
#endif

uint16_t
calculate_pseudo_ipv6_header_checksum(void *hdr,
                                      uint16_t ip_hdr_len,
                                      uint8_t protocol)
{
    ipv6_header_t *ip_hdr;
    ipv6_pseudo_header_t pseudo_hdr;
    uint16_t len;
    uint16_t checksum;

    ip_hdr = (ipv6_header_t *)hdr;

    len = RtlUshortByteSwap(ip_hdr->ip6_payload_len)
                            + sizeof(ipv6_header_t) - ip_hdr_len;
    pseudo_hdr.ipph_src[0]  = ip_hdr->ip6_src_address[0];
    pseudo_hdr.ipph_src[1]  = ip_hdr->ip6_src_address[1];
    pseudo_hdr.ipph_src[2]  = ip_hdr->ip6_src_address[2];
    pseudo_hdr.ipph_src[3]  = ip_hdr->ip6_src_address[3];
    pseudo_hdr.ipph_dest[0] = ip_hdr->ip6_dst_address[0];
    pseudo_hdr.ipph_dest[1] = ip_hdr->ip6_dst_address[1];
    pseudo_hdr.ipph_dest[2] = ip_hdr->ip6_dst_address[2];
    pseudo_hdr.ipph_dest[3] = ip_hdr->ip6_dst_address[3];
    pseudo_hdr.ipph_length = RtlUshortByteSwap(len);
    pseudo_hdr.z1 = 0;
    pseudo_hdr.z2 = 0;
    pseudo_hdr.z3 = 0;
    pseudo_hdr.ipph_protocol = protocol;
    checksum = checksum_calculator_flat(&pseudo_hdr, sizeof(pseudo_hdr));

#ifdef DBG
    giph.iplen = ip_hdr_len;
    giph.payload = ip_hdr->ip6_payload_len;
    giph.spayload = RtlUshortByteSwap(ip_hdr->ip6_payload_len);
    giph.flen = len;

    if (giph.ipph_length != pseudo_hdr.ipph_length ||
        giph.chksum != checksum)
    {
        giph.ipph_length = pseudo_hdr.ipph_length;
        giph.chksum = checksum;
        if (giph.payload != giph.ipph_length || giph.spayload != giph.flen) {
            RPRINTK(DPRTL_LSO,
                    ("ipv%d: iplen %d load %d %d ipph_length %d %d chksum %x\n",
                pseudo_hdr.ipph_protocol,
                giph.iplen,
                giph.payload,
                giph.spayload,
                giph.flen,
                giph.ipph_length,
                (USHORT)~checksum));
        } else {
            RPRINTK(DPRTL_LSO, ("ipv%d: iplen %d ipph_length %d %d chksum %x\n",
                pseudo_hdr.ipph_protocol,
                giph.iplen,
                giph.ipph_length,
                giph.flen,
                (USHORT)~checksum));
        }
    }
#endif
    return ~checksum;
}

void
vnif_gos_hdr_update(TCB *tcb,
                    uint8_t *ip_hdr,
                    uint8_t *tcp_hdr,
                    uint16_t ip_hdr_len,
                    UINT nb_len)
{
    ipv4_header_t *ipv4_hdr;
    ipv6_header_t *ipv6_hdr;
#ifdef DBG
    uint16_t before_ip;
    uint16_t before_tcp;
    uint16_t after_ip;
    uint16_t after_tcp;

    before_ip = 0;
    before_tcp = 0;
#endif

    tcb->ip_hdr_len = ip_hdr_len;
    tcb->tcp_hdr_len = tcp_hdr[TCP_DATA_OFFSET] >> 2;
    tcb->ip_version = IP_INPLACE_HEADER_VERSION(ip_hdr);


    if (tcb->ip_version == IPV4) {
#ifdef DBG
        before_ip = *(uint16_t *)&ip_hdr[10];
        before_tcp = *(uint16_t *)&ip_hdr[ip_hdr_len
            + VNIF_PACKET_BYTE_OFFSET_TCP_CHKSUM];
#endif
        ipv4_hdr = (ipv4_header_t *)ip_hdr;
        if (ipv4_hdr->ip_total_length == 0) {
            ipv4_hdr->ip_total_length = RtlUshortByteSwap(
                nb_len - ETH_HEADER_SIZE);
            vnif_dump_buf(DPRTL_CHKSUM, ip_hdr + 2, 16);
        }

        calculate_ip_checksum(ip_hdr);
        ((tcp_hdr_t *)tcp_hdr)->tcp_chksum =
            calculate_pseudo_ipv4_header_checksum(ip_hdr);
#ifdef DBG
        after_ip = *(uint16_t *)&ip_hdr[10];
        after_tcp = *(uint16_t *)&ip_hdr[ip_hdr_len
            + VNIF_PACKET_BYTE_OFFSET_TCP_CHKSUM];
        DPRINTK(DPRTL_CHKSUM, ("     bip %x btcp %x aip %x atcp %x\n",
            before_ip, before_tcp, after_ip, after_tcp));
#endif
    } else {
        ipv6_hdr = (ipv6_header_t *)ip_hdr;
        if (ipv6_hdr->ip6_payload_len == 0) {
            ipv6_hdr->ip6_payload_len = RtlUshortByteSwap(
                nb_len - ETH_HEADER_SIZE - ip_hdr_len);

            DPRINTK(DPRTL_CHKSUM,
                ("%s: missing IPv6 payload, calculate to 0x%x %d\n",
                 __func__,
                 RtlUshortByteSwap(ipv6_hdr->ip6_payload_len),
                 RtlUshortByteSwap(ipv6_hdr->ip6_payload_len)));
        }

        ((tcp_hdr_t *)tcp_hdr)->tcp_chksum =
            calculate_pseudo_ipv6_header_checksum(ip_hdr,
                                                  ip_hdr_len,
                                                  VNIF_PACKET_TYPE_TCP);
        DPRINTK(DPRTL_CHKSUM,
            ("after %x\n", ((tcp_hdr_t *)tcp_hdr)->tcp_chksum));
    }
}

uint16_t
calculate_ip_checksum(uint8_t *pkt_buf)
{
    uint16_t *buff;
    uint16_t *w;
    uint32_t ip_hdr_sz;
    uint32_t i;
    uint32_t sum;

    ip_hdr_sz = IP_INPLACE_HEADER_SIZE(pkt_buf);
    buff = (uint16_t *)pkt_buf;
    w = buff;
    buff[5] = 0;

    /*
     * Make 16 bit words out of every two adjacent 8 bit words in the packet
     * and add them up
     */
    sum = 0;
    while (ip_hdr_sz > 1) {
        sum += *w++;
        ip_hdr_sz -= 2;
    }
    /*
     * If len is 1 there ist still on byte left. We add a padding
     * byte (0xFF) to build a 16 bit word.
     */
    if (ip_hdr_sz > 0) {
        sum += *w & 0xFF;
    }

    /*
     * Keep only the last 16 bits of the 32 bit calculated sum and
     * add the carries.
     */
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    /* Take the one's complement of sum. */
    sum = ~sum;
    buff[5] = (uint16_t)sum;

    DPRINTK(DPRTL_CHKSUM,
        ("calculate_ip_checksum: b[5] %x, pkt_buf[0] %x, sum %x\n",
        buff[5], pkt_buf[0], sum));
    return (uint16_t) sum;
}

void
get_ipv6_hdr_len_and_protocol(ipv6_header_t *ipv6_hdr,
                              UINT pkt_len,
                              uint16_t *pip_hdr_len,
                              uint8_t *pprotocol)
{
    ipv6_common_ext_header_t *ext_hdr;
    uint16_t ip_hdr_len;
    uint8_t protocol;
    uint8_t next_hdr;

    protocol = IPV6_EXT_HDR_NO_NEXT;
    ip_hdr_len = (uint16_t)sizeof(ipv6_header_t);
    next_hdr = ipv6_hdr->ip6_next_header;
    while (next_hdr != IPV6_EXT_HDR_NO_NEXT) {
        switch (next_hdr) {
        case IPV6_EXT_HDR_HOP_BY_HOP:
        case IPV6_EXT_HDR_DESTINATION:
        case IPV6_EXT_HDR_ROUTING:
            DPRINTK(DPRTL_UNEXPD, ("IPv6 EXT Header %d\n", next_hdr));
            ext_hdr = (ipv6_common_ext_header_t *)
                ((uint8_t *)ipv6_hdr + ip_hdr_len);

            next_hdr = ext_hdr->ip6ext_next_header;

            /*
             * Extinsion header lengths do not include the first 8 octets
             * (bytes). Header length is the number of octet (byte) units.
             */
            ip_hdr_len += IPV6_EXT_HDR_FIXED_LEN
                + (ext_hdr->ip6ext_hdr_len * OCTET_BITS);
            break;
        case IPV6_EXT_HDR_FRAGMENT:
            DPRINTK(DPRTL_UNEXPD, ("IPv6 EXT Header FRAGMENT\n"));
            ext_hdr = (ipv6_common_ext_header_t *)
                ((uint8_t *)ipv6_hdr + ip_hdr_len);

            next_hdr = ext_hdr->ip6ext_next_header;
            ip_hdr_len += sizeof(ipv6_fragment_ext_header_t);
            break;
        case IPV6_EXT_HDR_AUTHENTICATION:
            DPRINTK(DPRTL_UNEXPD, ("IPv6 EXT Header AUTHENTICATION\n"));
            ext_hdr = (ipv6_common_ext_header_t *)
                ((uint8_t *)ipv6_hdr + ip_hdr_len);

            next_hdr = ext_hdr->ip6ext_next_header;
            ip_hdr_len += (uint16_t)(ext_hdr->ip6ext_hdr_len + 2)
                * (uint16_t)sizeof(uint32_t);
            break;
        case IPV6_EXT_HDR_ENCAPSULATION_SECURITY_PAYLOAD:
        case IPV6_EXT_HDR_MOBILITY:
        case IPV6_EXT_HDR_HOST_IDENTITY:
        case IPV6_EXT_HDR_SHIM6:
        case IPV6_EXT_HDR_RESERVED1:
        case IPV6_EXT_HDR_RESERVED2:
            RPRINTK(DPRTL_UNEXPD, ("IPv6 EXT Header unknown %x\n", next_hdr));
            next_hdr = IPV6_EXT_HDR_NO_NEXT;
            break;
        default:
            protocol = next_hdr;
            next_hdr = IPV6_EXT_HDR_NO_NEXT;
            break;
        }
        if (ip_hdr_len > pkt_len) {
            next_hdr = IPV6_EXT_HDR_NO_NEXT;
        }
    }
    if (pip_hdr_len != NULL) {
        *pip_hdr_len = ip_hdr_len;
    }
    if (pprotocol != NULL) {
        *pprotocol = protocol;
    }
}

UINT
vnif_collapse_rx(PVNIF_ADAPTER adapter, RCB *rcb)
{
    RCB *cur_rcb;
    RCB *discard_rcb;
    PUCHAR dest;
    UINT rcb_added_to_ring;
    UINT target_len;

    dest = rcb->page + rcb->len + adapter->buffer_offset;
    cur_rcb = rcb->next;
    rcb_added_to_ring = 0;
    if (rcb->total_len > ETH_MIN_PACKET_SIZE) {
        target_len = VNIF_TCPIP_HEADER_LEN;
    } else {
        target_len = ETH_MIN_PACKET_SIZE;
    }
    while (cur_rcb && rcb->len <= target_len) {
        NdisMoveMemory(dest, cur_rcb->page, cur_rcb->len);
        dest += cur_rcb->len;
        rcb->len += cur_rcb->len;
#if NDIS_SUPPORT_NDIS6
        NDIS_MDL_LINKAGE(rcb->mdl) = NDIS_MDL_LINKAGE(cur_rcb->mdl);
#else
        rcb->buffer->Next = cur_rcb->buffer->Next;
#endif
        DPRINTK(DPRTL_TRC,
            ("Collapsing: %p len is %d of %d\n", rcb, cur_rcb->len, rcb->len));
        discard_rcb = cur_rcb;
        cur_rcb = cur_rcb->next;
        discard_rcb->next = NULL;
        vnif_return_rcb(adapter, discard_rcb);
        rcb_added_to_ring++;
    }
#if NDIS_SUPPORT_NDIS6
    NdisAdjustMdlLength(rcb->mdl, rcb->len);
#else
    NdisAdjustBufferLength(rcb->buffer, rcb->len);
#endif
    rcb->next = cur_rcb;
    return rcb_added_to_ring;
}

void
vnif_validate_rcb(char *func, RCB *rcb)
{
    UINT tlen;
    UINT len;
    RCB  *trcb;

    len = 0;
    trcb = rcb;
    tlen = rcb->total_len;
    while (trcb) {
        if (trcb->len == 0) {
            PRINTK(("%s: %p has fragment of len of 0\n", func, trcb));
        }
        len += trcb->len;
        trcb = trcb->next;
    }
    if (len != tlen) {
        trcb = rcb;
        PRINTK(("%s: len %d, tlen %d\n", func, len, tlen));
        while (trcb) {
            PRINTK(("  %p: len %d\n", trcb, trcb->len));
            trcb = trcb->next;
        }
    }
}

uint32_t
vnif_should_complete_packet(PVNIF_ADAPTER adapter, PUCHAR dest, UINT len)
{
    PUCHAR mac;
    uint32_t i, j;

    if (!VNIF_IS_READY(adapter)) {
        adapter->in_discards++;
        return VNIF_RECEIVE_DISCARD;
    }

    DPRINTK(DPRTL_TRC, ("%s IN\n", __func__));

    /* Is this a directed packet? */
    if ((dest[0] & 0x01) == 0) {
#if NDIS_SUPPORT_NDIS6
        adapter->ifHCInUcastPkts++;
        adapter->ifHCInUcastOctets += len;
#endif
        if (adapter->PacketFilter & NDIS_PACKET_TYPE_PROMISCUOUS) {
            DPRINTK(DPRTL_TRC, ("%s directed promiscuous OUT\n", __func__));
            return VNIF_RECEIVE_COMPLETE;
        }
        if (adapter->PacketFilter & NDIS_PACKET_TYPE_DIRECTED) {
            mac = adapter->CurrentAddress;
            for (i = 0; i < ETH_LENGTH_OF_ADDRESS; i++) {
                if (mac[i] != dest[i]) {
                    adapter->in_discards++;
                    DPRINTK(DPRTL_TRC, ("%s filer directed discard OUT\n",
                                        __func__));
                    return VNIF_RECEIVE_DISCARD;
                }
            }
            DPRINTK(DPRTL_TRC, ("%s directed complete OUT\n", __func__));
            return VNIF_RECEIVE_COMPLETE;
        }
        adapter->in_discards++;
        DPRINTK(DPRTL_TRC, ("%s directed discard OUT\n", __func__));
        return VNIF_RECEIVE_DISCARD;
    }

    /* Must be a broadcast or multicast. */
    if (ETH_IS_BROADCAST(dest)) {
#if NDIS_SUPPORT_NDIS6
        adapter->ifHCInBroadcastPkts++;
        adapter->ifHCInBroadcastOctets += len;
#endif
        if (adapter->PacketFilter & NDIS_PACKET_TYPE_PROMISCUOUS) {
            DPRINTK(DPRTL_TRC, ("%s Broadcast promiscuous OUT\n", __func__));
            return VNIF_RECEIVE_COMPLETE;
        }
        if (adapter->PacketFilter & NDIS_PACKET_TYPE_BROADCAST) {
            DPRINTK(DPRTL_TRC, ("%s Broadcast filter completeOUT\n", __func__));
            return VNIF_RECEIVE_COMPLETE;
        }
        adapter->in_discards++;
        DPRINTK(DPRTL_TRC, ("%s Broadcast discard OUT\n", __func__));
        return VNIF_RECEIVE_DISCARD;
    }

    /* Must be a multicast */
#if NDIS_SUPPORT_NDIS6
    adapter->ifHCInMulticastPkts++;
    adapter->ifHCInMulticastOctets += len;
#endif
    if (adapter->PacketFilter & NDIS_PACKET_TYPE_PROMISCUOUS) {
        DPRINTK(DPRTL_TRC, ("%s Multicast promiscuous OUT\n", __func__));
        return VNIF_RECEIVE_COMPLETE;
    }
    if (adapter->PacketFilter & NDIS_PACKET_TYPE_ALL_MULTICAST) {
        DPRINTK(DPRTL_TRC, ("%s Multicast complete OUT\n", __func__));
        return VNIF_RECEIVE_COMPLETE;
    }
    if ((adapter->PacketFilter & NDIS_PACKET_TYPE_MULTICAST) == 0) {
        adapter->in_discards++;
        DPRINTK(DPRTL_TRC, ("%s Multicast discard OUT\n", __func__));
        return VNIF_RECEIVE_DISCARD;
    }

    /* Now we have to search the multicast list to see if there is a match. */
    for (i = 0; i < adapter->ulMCListSize; i++) {
        mac = &adapter->MCList[i][0];
        for (j = 0; j < ETH_LENGTH_OF_ADDRESS; j++) {
            if (mac[j] != dest[j]) {
                break;
            }
        }
        if (j == ETH_LENGTH_OF_ADDRESS) {
            DPRINTK(DPRTL_TRC, ("%s Multicast list complete OUT\n", __func__));
            return VNIF_RECEIVE_COMPLETE;
        }
    }
    adapter->in_discards++;
    DPRINTK(DPRTL_TRC, ("%s discard OUT\n", __func__));
    return VNIF_RECEIVE_DISCARD;
}

/* Assumes Adapter->RecvLock is held. */
/* Assumes Adapter->vq[rcb->path_id].rx_path_lock is held. */
static void
vnif_add_rcb_to_ring(PVNIF_ADAPTER adapter, RCB *rcb)
{
    RCB *cur_rcb;

    while (rcb) {
        cur_rcb = rcb;
        rcb = rcb->next;
        cur_rcb->next = NULL;
        cur_rcb->len = 0;
        cur_rcb->total_len = 0;

        /* In case of priority packet, put things back the way it was.*/
#if NDIS_SUPPORT_NDIS6
        cur_rcb->nbl = NULL;

        cur_rcb->mdl->MappedSystemVa =
            cur_rcb->page + adapter->buffer_offset;
        cur_rcb->mdl->StartVa = cur_rcb->mdl_start_va;
#endif
        VNIF_ADD_RCB_TO_RING(adapter, cur_rcb);
    }
}

/* Assumes Adapter->RecvLock is held. */
/* Assumes Adapter->vq[rcb->path_id].rx_path_lock is held. */
UINT
vnif_add_rcb_to_ring_from_list(PVNIF_ADAPTER adapter, UINT path_id)
{
    RCB *rcb;

    DPRINTK(DPRTL_TRC, ("%s IN\n", __func__));

    if (MP_RING_FULL(adapter->path[path_id].rx)) {
        DPRINTK(DPRTL_RING, ("%s: ring is already full.\n", __func__));
        return 0;
    }
    rcb = (RCB *) RemoveHeadList(
        &adapter->path[path_id].rcb_rp.rcb_free_list);
    if (rcb == (RCB *)&adapter->path[path_id].rcb_rp.rcb_free_list) {
        VNIF_DUMP(adapter, path_id, "vnif_add_rcb_to_ring_from_list", 1, 1);
        return 0;
    }

    vnif_add_rcb_to_ring(adapter, rcb);

    DPRINTK(DPRTL_TRC, ("%s OUT\n", __func__));
    return 1;
}

/* Assumes Adapter->RecvLock is held. */
/* Assumes Adapter->vq[rcb->path_id].rx_path_lock is held. */
void
vnif_return_rcb(PVNIF_ADAPTER adapter, RCB *rcb)
{
    UINT path_id;

    path_id = rcb->path_id;
    DPRINTK(DPRTL_TRC, ("%s: index %x path_id %d.\n",
                        __func__, rcb->index, path_id));
    if (adapter->num_rcb <= NET_RX_RING_SIZE) {
        vnif_add_rcb_to_ring(adapter, rcb);
    } else {
        DPRINTK(DPRTL_TRC, ("%s: vnif_add_rcb_to_ring.\n", __func__));
        InsertTailList(&adapter->path[path_id].rcb_rp.rcb_free_list,
                       &rcb->list);
        vnif_add_rcb_to_ring_from_list(adapter, path_id);
    }
    vnif_return_rcb_verify(adapter, rcb);
}

void
vnif_drop_rcb(PVNIF_ADAPTER adapter, RCB *rcb, int status)
{
    if (status == NETIF_RSP_NULL) {
        PRINTK(("%s: receive null status.\n", __func__));
    } else if (status == NETIF_RSP_ERROR) {
        adapter->ifInErrors++;
    } else if (status == NETIF_RSP_DROPPED) {
        adapter->in_no_buffers++;
    }

    PRINTK(("%s: receive errors = %d, dropped = %d, status = %x, idx %x.\n",
            __func__,
            adapter->ifInErrors, adapter->in_no_buffers, status,
            rcb->index));
    vnif_return_rcb(adapter, rcb);
}

VOID
VNIFFreeQueuedRecvPackets(PVNIF_ADAPTER Adapter)
{
}

VOID
VNIFReceiveTimerDpc(
    IN PVOID SystemSpecific1,
    IN PVOID FunctionContext,
    IN PVOID SystemSpecific2,
    IN PVOID SystemSpecific3)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) FunctionContext;
    UINT i;

    DPRINTK(DPRTL_DPC, ("%s IN\n", __func__));

    NdisAcquireSpinLock(&adapter->adapter_flag_lock);
    if (VNIF_IS_NOT_READY(adapter)) {
        RPRINTK(DPRTL_ON,
            ("%s %x: %d, exiting 0x%x.\n",
             __func__, adapter->CurrentAddress[MAC_LAST_DIGIT],
             KeGetCurrentProcessorNumber(), adapter->adapter_flags));
        NdisReleaseSpinLock(&adapter->adapter_flag_lock);
        return;
    }
    NdisReleaseSpinLock(&adapter->adapter_flag_lock);

    for (i = 0; i < adapter->num_rcv_queues; ++i) {
        if (!IsListEmpty(&adapter->rcv_q[i].rcv_to_process)) {
            if (adapter->pv_stats) {
                RPRINTK(DPRTL_ON,
                   ("%s: %s rx_cnt %d nBusyRecvs %d, irql %d cpu %d.\n",
                   __func__, adapter->node_name,
                   adapter->pv_stats->rx_to_process_cnt, adapter->nBusyRecv,
                   KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
            } else {
                RPRINTK(DPRTL_ON,
                   ("%s: %s nBusyRecvs %d, irql %d cpu %d.\n",
                   __func__, adapter->node_name,
                   adapter->nBusyRecv,
                   KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
            }
            VNIFReceivePackets(adapter, i, NDIS_INDICATE_ALL_NBLS);
        }
    }
    DPRINTK(DPRTL_DPC, ("%s OUT\n", __func__));
}

static void
vnif_build_arp_packet(uint8_t *mac, uint8_t *ip, char *p)
{
    /* Destination mac: broadcast */
    p[0]  = 0xff;
    p[1]  = 0xff;
    p[2]  = 0xff;
    p[3]  = 0xff;
    p[4]  = 0xff;
    p[5]  = 0xff;

    /* Source mac */
    p[6]  = mac[0];
    p[7]  = mac[1];
    p[8]  = mac[2];
    p[9]  = mac[3];
    p[10] = mac[4];
    p[11] = mac[5];

    /* Arp protocol stuff */
    p[12] = 0x08;
    p[13] = 0x06;
    p[14] = 0x00;
    p[15] = 0x01;
    p[16] = 0x08;
    p[17] = 0x00;
    p[18] = 0x06;
    p[19] = 0x04;
    p[20] = 0x00;
    p[21] = 0x01; /* 2 is response. 01 is reply */

    /* Source mac */
    p[22] = mac[0];
    p[23] = mac[1];
    p[24] = mac[2];
    p[25] = mac[3];
    p[26] = mac[4];
    p[27] = mac[5];

    /* Source ip */
    p[28] = ip[0];
    p[29] = ip[1];
    p[30] = ip[2];
    p[31] = ip[3];

    /* Source mac */
    p[32] = 0x00;
    p[33] = 0x00;
    p[34] = 0x00;
    p[35] = 0x00;
    p[36] = 0x00;
    p[37] = 0x00;

    p[38] = ip[0];
    p[39] = ip[1];
    p[40] = ip[2];
    p[41] = ip[3];

    /* Trailer */
    NdisZeroMemory(&p[42], 18);
}

static uint16_t
vnif_wstr_to_str(WCHAR *wstr, char *str)
{
    UNICODE_STRING ustr;
    ANSI_STRING astr;
    uint16_t i;

    for (i = 0; wstr[i] != 0; i++) {
        ;
    }

    ustr.Length = i * sizeof(WCHAR);
    ustr.MaximumLength = PAGE_SIZE;
    ustr.Buffer = wstr;

    astr.Length = 0;
    astr.MaximumLength = 16;
    astr.Buffer = str;

    RtlUnicodeStringToAnsiString(&astr, &ustr, FALSE);
    return i + 1;
}

static void
vnif_ip_str_to_ip(char *ip_str, uint8_t *ip_addr)
{
    int i;
    char *str, *cur;
    char ch;

    str = ip_str;
    cur = ip_str;

    for (i = 0; i < 4; i++) {
        cur = str;
        while (*str != '.' && *str != '\0') {
            str++;
        }
        ch = *str;
        *str = '\0';
        ip_addr[i] = (uint8_t)cmp_strtoul(cur, NULL, 10);
        *str = ch;
        str++;
    }
}

static NDIS_STATUS
vnif_get_ip_address_from_reg(PVNIF_ADAPTER adapter, WCHAR *ip_addr_buf)
{
    RTL_QUERY_REGISTRY_TABLE paramTable[2] = {0};
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    WCHAR ip_reg_buf[128] = {0};
    UNICODE_STRING ip_reg_ustr;
    UNICODE_STRING net_cfg_ustr;

    net_cfg_ustr.Length = GUID_LENGTH * sizeof(WCHAR);
    net_cfg_ustr.MaximumLength = GUID_LENGTH * sizeof(WCHAR);
    net_cfg_ustr.Buffer = adapter->net_cfg_guid;

    ip_reg_ustr.Length = 0;
    ip_reg_ustr.MaximumLength = sizeof(ip_reg_buf);
    ip_reg_ustr.Buffer = ip_reg_buf;
    DPRINTK(DPRTL_ON, ("%s: buffer len = %d.\n", __func__, ip_reg_ustr.Length));
    DPRINTK(DPRTL_ON, ("%s: %ws.\n", __func__, ip_reg_buf));

    /* Create the string to the where the IP addresses are located. */
    RtlUnicodeStringCatString(&ip_reg_ustr,
                              L"\\Tcpip\\Parameters\\Interfaces\\");
    DPRINTK(DPRTL_ON, ("%s: buffer len = %d.\n", __func__, ip_reg_ustr.Length));
    DPRINTK(DPRTL_ON, ("%s: %ws.\n", __func__, ip_reg_buf));

    RtlUnicodeStringCatString(&ip_reg_ustr, adapter->net_cfg_guid);
    DPRINTK(DPRTL_ON, ("%s: buffer len = %d.\n", __func__, ip_reg_ustr.Length));
    DPRINTK(DPRTL_ON, ("%s: %ws.\n", __func__, ip_reg_buf));

    /* Prepare to the receive buffere for the IP addresses. */
    ip_reg_ustr.Length = 0;
    ip_reg_ustr.MaximumLength = PAGE_SIZE;
    ip_reg_ustr.Buffer = ip_addr_buf;
    paramTable[0].Flags = RTL_QUERY_REGISTRY_NOEXPAND
                        | RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = L"DhcpIPAddress";
    paramTable[0].EntryContext = &ip_reg_ustr;
    paramTable[0].DefaultType =
        (REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = L"";
    paramTable[0].DefaultLength = 0;

    /* Get the IP addresses out of the registr. */
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
        ip_reg_buf,
        &paramTable[0],
        NULL,
        NULL);
    if (status != STATUS_SUCCESS) {
        PRINTK(("%s: reg query failed, %x.\n", __func__, status));
        return STATUS_UNSUCCESSFUL;
    }
    DPRINTK(DPRTL_ON, ("%s: dhcp %d = %ws.\n", __func__,
        ip_reg_ustr.Length, ip_addr_buf));

    ip_addr_buf[ip_reg_ustr.Length] = 0;

    if (ip_reg_ustr.Length > 0) {
        /* Move past the DHCP IP address. */
        ip_reg_ustr.Buffer =
            &ip_addr_buf[ip_reg_ustr.Length / sizeof(WCHAR)] + 1;
    }
    ip_reg_ustr.MaximumLength = PAGE_SIZE - ip_reg_ustr.Length;
    ip_reg_ustr.Length = 0;
    paramTable[0].Flags = RTL_QUERY_REGISTRY_NOEXPAND
                        | RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_TYPECHECK;
    paramTable[0].Name = L"IPAddress";
    paramTable[0].EntryContext = &ip_reg_ustr;
    paramTable[0].DefaultType =
        (REG_MULTI_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;
    paramTable[0].DefaultData = L"";
    paramTable[0].DefaultLength = 0;

    /* Get the IP addresses out of the registr. */
    status = RtlQueryRegistryValues(
        RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL,
        ip_reg_buf,
        &paramTable[0],
        NULL,
        NULL);
    if (status != STATUS_SUCCESS) {
        PRINTK(("%s: reg query failed, %x.\n", __func__, status));
    }
    DPRINTK(DPRTL_ON, ("%s: ip %d = %ws.\n", __func__,
                       ip_reg_ustr.Length, ip_addr_buf));
    return status;
}

static void
vnif_send_private_buffer(
  PVNIF_ADAPTER adapter,
  char *buffer,
  uint32_t len)
{
    TCB *tcb;
    UINT i;

    DPRINTK(DPRTL_TRC, ("%s IN\n", __func__));
    if (adapter == NULL || len > adapter->max_frame_sz) {
        PRINTK(("%s: null adapter or buf too large\n", __func__));
        return;
    }

    NdisAcquireSpinLock(&adapter->path[0].tx_path_lock);

    do {
        if (!VNIF_IS_READY(adapter) ||
                VNIF_TEST_FLAG(adapter, VNF_ADAPTER_SEND_IN_PROGRESS)) {
            PRINTK(("%s: send not allowed, f=%x.\n",
                    __func__, adapter->adapter_flags));
            break;
        }

        VNIF_GET_TX_REQ_PROD_PVT(adapter, 0, &i);

        tcb = (TCB *) RemoveHeadList(&adapter->path[0].tcb_free_list);

        if (tcb == NULL) {
            PRINTK(("%s: no tcbs available.\n", __func__));
            break;
        }

        VNIF_SET_FLAG(adapter, VNF_ADAPTER_SEND_IN_PROGRESS);
        VNIF_CLEAR_NDIS_TCB(tcb);
        NdisMoveMemory(tcb->data + adapter->buffer_offset, buffer, len);

        adapter->nBusySend++;

        tcb->sg_cnt = 0;
        vnif_add_tx(adapter, 0, tcb, len, len, NETTXF_data_validated, &i);
        VNIF_SET_TX_REQ_PROD_PVT(adapter, 0, i);

        vnif_notify_always_tx(adapter, 0);
        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SEND_IN_PROGRESS);
    } while (0);

    NdisReleaseSpinLock(&adapter->path[0].tx_path_lock);

    DPRINTK(DPRTL_TRC, ("%s: OUT\n", __func__));
}

void
vnif_send_arp(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    char ip_str[16];
    WCHAR *ip_addr_buf;
    WCHAR *w;
    uint8_t ip_addr[4];
    uint8_t buf[ETH_MIN_PACKET_SIZE];

    /* Allocate memory to hold all possible IP addresses. */
    VNIF_ALLOCATE_MEMORY(
        ip_addr_buf,
        PAGE_SIZE,
        VNIF_POOL_TAG,
        NdisMiniportDriverHandle,
        NormalPoolPriority);
    if (ip_addr_buf == NULL) {
        PRINTK(("%s: failed page allocation.\n", __func__));
        return;
    }
    memset(ip_addr_buf, 0, PAGE_SIZE);

    status = vnif_get_ip_address_from_reg(adapter, ip_addr_buf);

    if (status == STATUS_SUCCESS) {
        DPRINTK(DPRTL_ON, ("%s: ip wstr = %ws.\n", __func__, ip_addr_buf));
        w = ip_addr_buf;
        while (*w != 0 && *(w + 1) != 0) {
            w += vnif_wstr_to_str(w, ip_str);
            DPRINTK(DPRTL_ON, ("%s: ip astr = %s.\n", __func__, ip_str));
            vnif_ip_str_to_ip(ip_str, ip_addr);
            PRINTK(("%s: ip = %d.%d.%d.%d\n",
                __func__, ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]));
            vnif_build_arp_packet(adapter->CurrentAddress, ip_addr, buf);
            vnif_send_private_buffer(adapter,   buf, sizeof(buf));
        }
    }

    NdisFreeMemory(ip_addr_buf, PAGE_SIZE, 0);
}

static void
fill_cnt(PVNIF_ADAPTER adapter, uint64_t *cnt_array, uint32_t cnt, uint32_t max)
{
    if (adapter->pv_stats == NULL) {
        return;
    }

    if (cnt == max) {
        cnt_array[7]++;
    } else if (cnt > 200) {
        cnt_array[6]++;
    } else if (cnt > 100) {
        cnt_array[5]++;
    } else if (cnt > 50) {
        cnt_array[4]++;
    } else if (cnt > 10) {
        cnt_array[3]++;
    } else if (cnt > 5) {
        cnt_array[2]++;
    } else if (cnt > 1) {
        cnt_array[1]++;
    } else {
        cnt_array[0]++;
    }
}

static void
fill_delays(PVNIF_ADAPTER adapter, uint64_t *delay, uint64_t delta)
{
    if (adapter->pv_stats == NULL) {
        return;
    }

    if (delta > 3000000000) {
        delay[7]++;
    } else if (delta > 1000000000) {
        delay[6]++;
    } else if (delta > 500000000) {
        delay[5]++;
    } else if (delta > 100000000) {
        delay[4]++;
    } else if (delta > 50000000) {
        delay[3]++;
    } else if (delta > 5000000) {
        delay[2]++;
    } else if (delta > 1000000) {
        delay[1]++;
    } else {
        delay[0]++;
    }
}

void
VNIFReceivePacketsStats(PVNIF_ADAPTER adapter, UINT path_id, uint32_t ring_size)
{
    if (adapter->pv_stats == NULL) {
        return;
    }

    NdisDprAcquireSpinLock(&adapter->stats_lock);
    fill_cnt(adapter, adapter->pv_stats->rx_max_nbusy,
        adapter->nBusyRecv, ring_size);

#ifdef DBG
    if (KeGetCurrentIrql() > 2) {
        DPRINTK(DPRTL_ON,
            ("%s irql = %d\n", __func__, KeGetCurrentIrql()));
    }

    vnif_rcv_stats_dump(adapter, path_id);

    if (adapter->pv_stats->rx_max_busy < adapter->nBusyRecv) {
        adapter->pv_stats->rx_max_busy = adapter->nBusyRecv;
        DPRINTK(DPRTL_ON,
            ("%s: %s entered with max_busy_recvs %d\n",
            __func__, adapter->node_name, adapter->pv_stats->rx_max_busy));
    }
    if (adapter->pv_stats->rx_max_busy >= (NET_RX_RING_SIZE - 5)
        && adapter->nBusyRecv == 0) {
        PRINTK(("%s: %s nbusyRecv has come back down to 0\n",
                __func__, adapter->node_name));
    }
    if (adapter->pv_stats->rx_max_busy >= (NET_RX_RING_SIZE - 5)
        && adapter->nBusyRecv < (NET_RX_RING_SIZE) / 2) {
        PRINTK(("%s: %s resetting max_busy_recvs to %d\n",
                __func__, adapter->node_name, adapter->nBusyRecv));
        adapter->pv_stats->rx_max_busy = adapter->nBusyRecv;
    }
#endif
    NdisDprReleaseSpinLock(&adapter->stats_lock);
}

void
VNIFReceivePacketsPostStats(PVNIF_ADAPTER adapter, UINT path_id,
                            uint32_t ring_size,
                            uint32_t cnt)
{
    if (adapter->pv_stats == NULL) {
        return;
    }

    NdisDprAcquireSpinLock(&adapter->stats_lock);
    VNIF_ADD(adapter->pv_stats->rx_path_cnt[path_id], cnt);
    fill_cnt(adapter, adapter->pv_stats->rx_max_passed_up, cnt, ring_size);

    if (adapter->nBusyRecv == ring_size) {
        adapter->pv_stats->rx_ring_empty_nbusy++;
    }

    if (path_id < adapter->num_paths
            && MP_RING_EMPTY(adapter->path[path_id].rx)) {
        adapter->pv_stats->rx_ring_empty_calc++;
        VNIFStatQueryInterruptTime(adapter->pv_stats->rx_ring_empty_calc_st);
    }

    if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_HALT_IN_PROGRESS)) {
        DPRINTK(DPRTL_ON,
            ("%s: halting, indicating %d packets.\n", __func__, cnt));
    }
    NdisDprReleaseSpinLock(&adapter->stats_lock);
}

void
VNIFReturnRcbStats(PVNIF_ADAPTER adapter, RCB *rcb)
{
    uint64_t cur;
    uint64_t et;
    uint64_t delta;

    if (adapter->pv_stats == NULL) {
        return;
    }

    NdisAcquireSpinLock(&adapter->stats_lock);
    if (KeGetCurrentIrql() > 2) {
        PRINTK(("%s: irql = %d\n", __func__, KeGetCurrentIrql()));
    }
    if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_HALT_IN_PROGRESS)) {
        PRINTK(("%s: halting, waiting for %d packets.\n",
            __func__, adapter->nBusyRecv));
    }

    VNIFStatQueryInterruptTime(et);
    delta = et - rcb->st;
    fill_delays(adapter, adapter->pv_stats->rx_return_delay, delta);

    if (adapter->pv_stats->rx_ring_empty_calc_st) {
        adapter->pv_stats->rx_ring_empty_calc_st = 0;
        fill_delays(adapter, adapter->pv_stats->rx_ring_empty_delay, delta);
    }

    if (rcb->st == 0) {
        PRINTK(("%s: %s, rcb st is 0!\n",
                __func__, adapter->node_name));
    }
    rcb->st = 0;

#ifdef DBG
    if (rcb->seq == adapter->pv_stats->rcb_ret_seq) {
        VNIFInterlockedIncrement(adapter->pv_stats->rcb_ret_seq);
    } else {
        if (rcb->seq > adapter->pv_stats->rcb_ret_seq) {
            adapter->pv_stats->rcb_ret_seq = rcb->seq + 1;
        }
    }
#endif
    NdisReleaseSpinLock(&adapter->stats_lock);
}

VOID
VNIFPvStatTimerDpc(
    IN PVOID SystemSpecific1,
    IN PVOID FunctionContext,
    IN PVOID SystemSpecific2,
    IN PVOID SystemSpecific3)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) FunctionContext;
    uint64_t et;
    uint64_t delta;
    uint32_t i;
    uint32_t r;
    uint32_t rcb_outstanding_cnt;

    if (adapter == NULL) {
        return;
    }
    if (adapter->pv_stats == NULL) {
        return;
    }

#ifdef RSS_DEBUG
    vnif_rss_dbg_dump_map(adapter);
    if (adapter->pv_stats->interval) {
        if (!VNIF_TEST_FLAG(adapter, VNF_ADAPTER_HALT_IN_PROGRESS)) {
            VNIF_SET_TIMER(adapter->pv_stats->stat_timer,
                adapter->pv_stats->interval);
        }
    }
    return;
#endif

    et = KeQueryInterruptTime();
    NdisDprAcquireSpinLock(&adapter->stats_lock);
    VNIF_DUMP(adapter, 0, "STATS", 1, 1);
    adapter->pv_stats->stat_timer_st = KeQueryInterruptTime();

    delta = et - adapter->pv_stats->stat_timer_st;
    PRINTK(("StatTimer %s: interval %lld, interrupts %lld.\n",
        adapter->node_name,
        delta,
        adapter->pv_stats->ints));

#if NDIS_SUPPORT_NDIS6
    RPRINTK(DPRTL_ON,
           ("    Tx: Sent %lld, Completed %lld, Busy %d, Errors %lld\n",
        adapter->pv_stats->tx_pkt_cnt,
        adapter->ifHCOutUcastPkts
            + adapter->ifHCOutMulticastPkts
            + adapter->ifHCOutBroadcastPkts,
        adapter->nBusySend,
        adapter->ifOutErrors + adapter->ifOutDiscards));
#else
    RPRINTK(DPRTL_ON,
           ("    Tx: Sent %lld, Completed %lld, Busy %d, Errors %lld\n",
        adapter->pv_stats->tx_pkt_cnt,
        adapter->GoodTransmits,
        adapter->nBusySend,
        adapter->ifOutErrors + adapter->ifOutDiscards));
#endif

    RPRINTK(DPRTL_ON,
           ("    Rx: Good %lld, Normal %lld, Resource %lld, Discarded %lld\n",
        adapter->pv_stats->rx_pkt_cnt,
        adapter->pv_stats->spkt_cnt,
        adapter->pv_stats->rpkt_cnt,
        adapter->in_discards));
    RPRINTK(DPRTL_ON,
           ("    Rx return delay: < 1ms %lld, < 5ms %lld, < 50ms %lld\n",
        adapter->pv_stats->rx_return_delay[0],
        adapter->pv_stats->rx_return_delay[1],
        adapter->pv_stats->rx_return_delay[2]));
    RPRINTK(DPRTL_ON,
           ("    < 100ms %lld, < 500ms %lld, < 1s %lld, < 3s %lld, > 3s %lld\n",
        adapter->pv_stats->rx_return_delay[3],
        adapter->pv_stats->rx_return_delay[4],
        adapter->pv_stats->rx_return_delay[5],
        adapter->pv_stats->rx_return_delay[6],
        adapter->pv_stats->rx_return_delay[7]));

    RPRINTK(DPRTL_ON,
           ("    Rx Ring empty %d, %d: < 1ms %lld, < 5ms %lld, < 50ms %lld\n",
        adapter->pv_stats->rx_ring_empty_nbusy,
        adapter->pv_stats->rx_ring_empty_calc,
        adapter->pv_stats->rx_ring_empty_delay[0],
        adapter->pv_stats->rx_ring_empty_delay[1],
        adapter->pv_stats->rx_ring_empty_delay[2]));
    RPRINTK(DPRTL_ON,
           ("    < 100ms %lld, < 500ms %lld, < 1s %lld, < 3s %lld, > 3s %lld\n",
        adapter->pv_stats->rx_ring_empty_delay[3],
        adapter->pv_stats->rx_ring_empty_delay[4],
        adapter->pv_stats->rx_ring_empty_delay[5],
        adapter->pv_stats->rx_ring_empty_delay[6],
        adapter->pv_stats->rx_ring_empty_delay[7]));

    RPRINTK(DPRTL_ON,
           ("    nBusyRcvs: 1 %lld, < 5 %lld, < 10 %lld\n",
        adapter->pv_stats->rx_max_nbusy[0],
        adapter->pv_stats->rx_max_nbusy[1],
        adapter->pv_stats->rx_max_nbusy[2]));
    RPRINTK(DPRTL_ON,
           ("    > 10 %lld, > 50 %lld, > 100 %lld, > 200 %lld, max %lld\n",
        adapter->pv_stats->rx_max_nbusy[3],
        adapter->pv_stats->rx_max_nbusy[4],
        adapter->pv_stats->rx_max_nbusy[5],
        adapter->pv_stats->rx_max_nbusy[6],
        adapter->pv_stats->rx_max_nbusy[7]));

    RPRINTK(DPRTL_ON,
           ("    Rx passed up at once: 1 %lld, > 1 %lld, > 5 %lld\n",
        adapter->pv_stats->rx_max_passed_up[0],
        adapter->pv_stats->rx_max_passed_up[1],
        adapter->pv_stats->rx_max_passed_up[2]));
    RPRINTK(DPRTL_ON,
           ("    > 10 %lld, > 50 %lld, > 100 %lld, > 200 %lld, max %lld\n",
        adapter->pv_stats->rx_max_passed_up[3],
        adapter->pv_stats->rx_max_passed_up[4],
        adapter->pv_stats->rx_max_passed_up[5],
        adapter->pv_stats->rx_max_passed_up[6],
        adapter->pv_stats->rx_max_passed_up[7]));

    rcb_outstanding_cnt = 0;
    if (adapter->path != NULL) {
        for (i = 0; i < adapter->num_paths; ++i) {
            for (r = 0; r < adapter->num_rcb; r++) {
                if (adapter->path[i].rcb_rp.rcb_array[r]->st) {
                    rcb_outstanding_cnt++;
                }
            }
        }
    }
    if (adapter->nBusyRecv || rcb_outstanding_cnt) {
        PRINTK(("    cur nBusyRcv %d, rcbs outstanding %d.\n",
            adapter->nBusyRecv, rcb_outstanding_cnt));
    }

    for (i = 0; i < adapter->num_rcv_queues; ++i) {
        if (!IsListEmpty(&adapter->rcv_q[i].rcv_to_process)) {
            PRINTK(("    [%d] rcv_to_process not empty: cnt %d nBusyRecvs %d\n",
                  i, adapter->pv_stats->rx_to_process_cnt, adapter->nBusyRecv));
#ifdef DBG
            dbg_print_mask |= (DPRTL_DPC);
#endif
        }
    }
    if (adapter->path != NULL) {
        for (i = 0; i < adapter->num_paths; ++i) {
            if (VNIF_RING_HAS_UNCONSUMED_RESPONSES(adapter->path[i].rx)) {
                PRINTK(("    [%d] HAS_UNCONSUMED_RESPONSES\n", i));
#ifdef DBG
                dbg_print_mask |= (DPRTL_DPC);
#endif
            }
#ifndef XENNET
            if (g_running_hypervisor == HYPERVISOR_KVM) {
                if (adapter->path[i].u.vq.rx->vq_type == split_vq) {
                    PRINTK(
                    ("    RX [%d] lst_usd_idx %d usd->idx %d free %d head %d\n",
                        i,
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.rx)->last_used_idx,
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.rx)->vring.used->idx,
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.rx)->num_free,
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.rx)->free_head));
                    if (((virtio_queue_split_t *)
                        adapter->path[i].u.vq.rx)->vring.used->idx >
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.rx)->last_used_idx) {
                        PRINTK(
                         ("    RX to be processed %d: f %x af %x\n",
                         ((virtio_queue_split_t *)
                             adapter->path[i].u.vq.rx)->vring.used->idx -
                         ((virtio_queue_split_t *)
                             adapter->path[i].u.vq.rx)->last_used_idx,
                         ((virtio_queue_split_t *)
                             adapter->path[i].u.vq.tx)->flags,
                         ((virtio_queue_split_t *)
                             adapter->path[i].u.vq.tx)->vring.avail->flags));
                    }

                    PRINTK(
                    ("    TX [%d] lst_usd_idx %d usd->idx %d free %d head %d\n",
                        i,
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.tx)->last_used_idx,
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.tx)->vring.used->idx,
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.tx)->num_free,
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.tx)->free_head));

                    if (((virtio_queue_split_t *)
                        adapter->path[i].u.vq.tx)->vring.used->idx >
                        ((virtio_queue_split_t *)
                            adapter->path[i].u.vq.tx)->last_used_idx) {
                        PRINTK(
                        ("    should call VNIFCheckSendCompletion f %x af %x\n",
                         ((virtio_queue_split_t *)
                             adapter->path[i].u.vq.tx)->flags,
                         ((virtio_queue_split_t *)
                             adapter->path[i].u.vq.tx)->vring.avail->flags));
                    }
                } else {
                }
            }
#endif
        }
    }

    adapter->pv_stats->stat_timer_st = KeQueryInterruptTime();

    if (adapter->pv_stats->interval) {
        if (!VNIF_TEST_FLAG(adapter, VNF_ADAPTER_HALT_IN_PROGRESS)) {
            VNIF_SET_TIMER(adapter->pv_stats->stat_timer,
                adapter->pv_stats->interval);
        }
    }
    NdisDprReleaseSpinLock(&adapter->stats_lock);
}

#if VNIF_DBG_DUMP_CHKSUM
static uint32_t CHKSUM_WRAP;

DEBUG_DUMP_CHKSUM(
    char type, uint16_t f, uint8_t *pkt, uint32_t len)
{
    if (len > 0x33) {
        if (pkt[0xc] == 8 && pkt[0xd] == 0 && pkt[0x17] == 6) {
            KdPrint(("%x%ci%02x%02xt%02x%02x ", f, type,
                pkt[0x18], pkt[0x19], pkt[0x32], pkt[0x33]));
            CHKSUM_WRAP++;
            if (!(CHKSUM_WRAP % 6)) {
                KdPrint(("\n"));
            }
            if (type == 'X') {
                /* pkt[0x32] = 0; */
                /* pkt[0x33] = 0; */
                pkt[0x33]++;
            }
        }
    }
}
#endif

#ifdef DBG
void
vnif_dump_buf(UINT level, uint8_t *buf, UINT len)
{
    DWORD c;
    DWORD i;
    DWORD l;
    DWORD line;
    DWORD lines;
    DWORD line_len;

    if (!(level & dbg_print_mask)) {
        return;
    }

    i = 0;
    line = 0;
    line_len = 16;
    lines = (len / line_len) + 1;
    for (l = 0; l < lines && i < len; l++, line++) {
        PRINTK(("%5d: ", line));
        for (c = 0; c < line_len && i < len; c++, i++) {
            if (c == line_len / 2) {
                PRINTK((" - "));
            }
            PRINTK(("%02x ", buf[i]));
        }
        PRINTK(("\n"));
    }
}
#endif
