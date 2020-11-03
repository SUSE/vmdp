/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
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

#include <ndis.h>
#include "miniport.h"

#ifndef NDIS60_MINIPORT
static NDIS_TASK_OFFLOAD OffloadTasks[] = {
    {
        NDIS_TASK_OFFLOAD_VERSION,
        sizeof(NDIS_TASK_OFFLOAD),
        TcpIpChecksumNdisTask,
        0,
        sizeof(NDIS_TASK_TCP_IP_CHECKSUM)
    },
    {
        NDIS_TASK_OFFLOAD_VERSION,
        sizeof(NDIS_TASK_OFFLOAD),
        TcpLargeSendNdisTask,
        0,
        sizeof(NDIS_TASK_TCP_LARGE_SEND)
    }
};

static ULONG OffloadTasksCount = sizeof(OffloadTasks) / sizeof(OffloadTasks[0]);
#endif


NDIS_OID VNIFSupportedOids[] = {
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_LINK_SPEED,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_VENDOR_ID,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_GEN_XMIT_ERROR,
    OID_GEN_RCV_ERROR,
    OID_GEN_RCV_NO_BUFFER,
    OID_GEN_RCV_CRC_ERROR,
    OID_GEN_TRANSMIT_QUEUE_LENGTH,
#ifdef NDIS60_MINIPORT
    OID_GEN_STATISTICS,
    OID_GEN_INTERRUPT_MODERATION,
#else
    OID_802_3_MAC_OPTIONS,
#endif
#ifdef NDIS620_MINIPORT
    OID_GEN_RECEIVE_SCALE_CAPABILITIES,
    OID_GEN_RECEIVE_SCALE_PARAMETERS,
    OID_GEN_RECEIVE_HASH,
#endif
    OID_802_3_PERMANENT_ADDRESS,
    OID_802_3_CURRENT_ADDRESS,
    OID_802_3_MULTICAST_LIST,
    OID_802_3_MAXIMUM_LIST_SIZE,
    OID_802_3_RCV_ERROR_ALIGNMENT,
    OID_802_3_XMIT_ONE_COLLISION,
    OID_802_3_XMIT_MORE_COLLISIONS,
    OID_802_3_XMIT_DEFERRED,
    OID_802_3_XMIT_MAX_COLLISIONS,
    OID_802_3_RCV_OVERRUN,
    OID_802_3_XMIT_UNDERRUN,
    OID_802_3_XMIT_HEARTBEAT_FAILURE,
    OID_802_3_XMIT_TIMES_CRS_LOST,
    OID_802_3_XMIT_LATE_COLLISIONS,
    OID_PNP_QUERY_POWER,
    OID_PNP_SET_POWER,

#ifdef NDIS60_MINIPORT
    OID_PNP_CAPABILITIES,
    OID_OFFLOAD_ENCAPSULATION,
    OID_TCP_OFFLOAD_PARAMETERS,
#else
    OID_TCP_TASK_OFFLOAD
#endif
};

#ifdef NDIS60_MINIPORT
uint32_t SupportedOidListLength = sizeof(VNIFSupportedOids);
#endif

static NDIS_STATUS
NICGetStatsCounters(PVNIF_ADAPTER adapter, NDIS_OID Oid, PULONG64 info64)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
#ifdef NDIS60_MINIPORT
    PNDIS_STATISTICS_INFO stats;
#endif

    switch (Oid) {
    case OID_GEN_XMIT_ERROR:
        *info64 = adapter->ifOutErrors + adapter->ifOutDiscards;
        break;

    case OID_GEN_RCV_ERROR:
        *info64 = adapter->ifInErrors + adapter->in_no_buffers;
        break;

    case OID_GEN_RCV_NO_BUFFER:
        *info64 = adapter->in_no_buffers;
        break;

    case OID_GEN_RCV_CRC_ERROR:
        *info64 = 0;
        break;

    case OID_GEN_TRANSMIT_QUEUE_LENGTH:
        *info64 = adapter->RegNumTcb;
        break;

    case OID_802_3_RCV_ERROR_ALIGNMENT:
        *info64 = 0;
        break;

    case OID_802_3_XMIT_ONE_COLLISION:
        *info64 = 0;
        break;

    case OID_802_3_XMIT_MORE_COLLISIONS:
        *info64 = 0;
        break;

    case OID_802_3_XMIT_DEFERRED:
        *info64 = 0;
        break;

    case OID_802_3_XMIT_MAX_COLLISIONS:
        *info64 = 0;
        break;

    case OID_802_3_RCV_OVERRUN:
        *info64 = 0;
        break;

    case OID_802_3_XMIT_UNDERRUN:
        *info64 = 0;
        break;

    case OID_802_3_XMIT_HEARTBEAT_FAILURE:
        *info64 = 0;
        break;

    case OID_802_3_XMIT_TIMES_CRS_LOST:
        *info64 = 0;
        break;

    case OID_802_3_XMIT_LATE_COLLISIONS:
        *info64 = 0;
        break;
#ifdef NDIS60_MINIPORT
    case OID_GEN_XMIT_OK:
        *info64 = adapter->ifHCOutUcastPkts +
            adapter->ifHCOutMulticastPkts +
            adapter->ifHCOutBroadcastPkts;
        break;

    case OID_GEN_RCV_OK:
        *info64 = adapter->ifHCInUcastPkts +
            adapter->ifHCInMulticastPkts +
            adapter->ifHCInBroadcastPkts;
        break;

    case OID_GEN_STATISTICS:
        stats = (PNDIS_STATISTICS_INFO)info64;
        NdisZeroMemory(stats, sizeof(NDIS_STATISTICS_INFO));
        stats->Header.Revision = NDIS_OBJECT_REVISION_1;
        stats->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        stats->Header.Size = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
        stats->SupportedStatistics =
            NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS |
            NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
            NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR |
            NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS |
            NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV |
            NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT |
            NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;

        stats->ifInDiscards =
            adapter->ifInErrors +
            adapter->in_discards +
            adapter->in_no_buffers;
        stats->ifInErrors = adapter->ifInErrors;

        stats->ifHCInOctets =
            adapter->ifHCInBroadcastOctets +
            adapter->ifHCInMulticastOctets +
            adapter->ifHCInUcastOctets;

        stats->ifHCInUcastPkts = adapter->ifHCInUcastPkts;
        stats->ifHCInMulticastPkts = adapter->ifHCInMulticastPkts;
        stats->ifHCInBroadcastPkts = adapter->ifHCInBroadcastPkts;

        stats->ifHCOutOctets =
            adapter->ifHCOutMulticastOctets +
            adapter->ifHCOutBroadcastOctets +
            adapter->ifHCOutUcastOctets;

        stats->ifHCOutUcastPkts = adapter->ifHCOutUcastPkts;
        stats->ifHCOutMulticastPkts = adapter->ifHCOutMulticastPkts;
        stats->ifHCOutBroadcastPkts = adapter->ifHCOutBroadcastPkts;

        stats->ifOutErrors = adapter->ifOutErrors + adapter->ifOutDiscards;
        stats->ifOutDiscards = adapter->ifOutErrors;

        stats->ifHCInUcastOctets = adapter->ifHCInUcastOctets;
        stats->ifHCInMulticastOctets = adapter->ifHCInMulticastOctets;
        stats->ifHCInBroadcastOctets = adapter->ifHCInBroadcastOctets;

        stats->ifHCOutUcastOctets = adapter->ifHCOutUcastOctets;
        stats->ifHCOutMulticastOctets = adapter->ifHCOutMulticastOctets;
        stats->ifHCOutBroadcastOctets = adapter->ifHCOutBroadcastOctets;
        break;
#else
    case OID_GEN_XMIT_OK:
        *info64 = adapter->GoodTransmits;
        break;

    case OID_GEN_RCV_OK:
        *info64 = adapter->GoodReceives;
        break;
#endif


    default:
        status = NDIS_STATUS_NOT_SUPPORTED;
    }
    return status;
}

NDIS_STATUS
MPQueryInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesWritten,
  OUT PULONG BytesNeeded)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PVNIF_ADAPTER adapter;

    NDIS_HARDWARE_STATUS hardwareStatus = NdisHardwareStatusReady;
    NDIS_MEDIUM medium = NdisMedium802_3;

    ULONG info = 0;
    USHORT info16;
    UINT64 info64;
    PVOID infoptr = (PVOID) &info;
    ULONG infolen = sizeof(info);
    ULONG ulBytesAvailable = infolen;

#ifdef NDIS60_MINIPORT
    NDIS_INTERRUPT_MODERATION_PARAMETERS int_mod;
#else
    PNDIS_TASK_OFFLOAD_HEADER pNdisTaskOffloadHdr;
    PNDIS_TASK_OFFLOAD pTaskOffload;
    PNDIS_TASK_TCP_IP_CHECKSUM pTcpIpChecksumTask;
    PNDIS_TASK_TCP_LARGE_SEND tcp_large_send;
#endif
    UINT i;
    BOOLEAN do_copy = TRUE;

    if (Oid < 0x20101 || Oid > 0x202ff) {
        RPRINTK(DPRTL_CONFIG, ("Query oid %x.\n", Oid));
    }
    adapter = (PVNIF_ADAPTER) MiniportAdapterContext;

    if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_SURPRISE_REMOVED)) {
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    *BytesWritten = 0;
    *BytesNeeded = 0;

    switch (Oid) {
    case OID_GEN_SUPPORTED_LIST:
        infoptr = (PVOID) VNIFSupportedOids;
        ulBytesAvailable = infolen = sizeof(VNIFSupportedOids);
        break;

    case OID_GEN_HARDWARE_STATUS:
        infoptr = (PVOID) &hardwareStatus;
        ulBytesAvailable = infolen = sizeof(NDIS_HARDWARE_STATUS);
        break;

    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE:
        infoptr = (PVOID) &medium;
        ulBytesAvailable = infolen = sizeof(NDIS_MEDIUM);
        break;

    case OID_GEN_CURRENT_LOOKAHEAD:
    case OID_GEN_MAXIMUM_LOOKAHEAD:
        if (adapter->ulLookAhead == 0) {
            if (adapter->hw_tasks & VNIF_RX_SG_LARGE) {
                adapter->ulLookAhead = VNIF_MAX_RCV_SIZE - ETH_HEADER_SIZE;
            } else {
                adapter->ulLookAhead = adapter->mtu;
            }
        }
        info = adapter->ulLookAhead;
        break;

    case OID_GEN_MAXIMUM_FRAME_SIZE:
        info = adapter->mtu;
        break;

    case OID_GEN_MAXIMUM_TOTAL_SIZE:
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        if (adapter->hw_tasks & VNIF_RX_SG_LARGE) {
            info = (ULONG) VNIF_MAX_RCV_SIZE;
        } else {
            info = (ULONG) adapter->max_frame_sz;
        }
        break;

    case OID_GEN_MAC_OPTIONS:
        info = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
            NDIS_MAC_OPTION_TRANSFERS_NOT_PEND     |
            NDIS_MAC_OPTION_NO_LOOPBACK;
        break;

    case OID_GEN_LINK_SPEED:
        ulBytesAvailable = infolen = sizeof(info64);
        info64 = adapter->ul64LinkSpeed / 100;    /* units are 100 bps */
        infoptr = &info64;
        break;

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
        info = adapter->max_frame_sz * VNIF_TX_RING_SIZE(adapter);
        break;

    case OID_GEN_RECEIVE_BUFFER_SPACE:
        if (adapter->hw_tasks & VNIF_RX_SG_LARGE) {
            info = VNIF_MAX_RCV_SIZE * NET_RX_RING_SIZE;
        } else {
            info = adapter->max_frame_sz * NET_RX_RING_SIZE;
        }
        break;

    case OID_GEN_VENDOR_ID:
        info = VNIF_VENDOR_ID;
        break;

    case OID_GEN_VENDOR_DESCRIPTION:
        infoptr = VNIF_VENDOR_DESC;
        ulBytesAvailable = infolen = strlen(infoptr) + 1;
        break;

    /* driver version */
    case OID_GEN_VENDOR_DRIVER_VERSION:
        info = VNIF_VENDOR_DRIVER_VERSION;
        RPRINTK(DPRTL_INIT, ("OID_GEN_VENDOR_DRIVER_VERSION: %d\n", info));
        break;

    /* NDIS version  */
    case OID_GEN_DRIVER_VERSION:
        info16 = (USHORT) (VNIF_NDIS_MAJOR_VERSION << 8)
            + VNIF_NDIS_MINOR_VERSION;
        infoptr = (PVOID) &info16;
        ulBytesAvailable = infolen = sizeof(USHORT);
        RPRINTK(DPRTL_INIT, ("OID_GEN_DRIVER_VERSION: %d\n", info16));
        PRINTK(("OID_GEN_DRIVER_VERSION: %d\n", info16));
        break;

    case OID_GEN_MAXIMUM_SEND_PACKETS:
        info = VNIF_MAX_SEND_PKTS;
        break;

    case OID_GEN_MEDIA_CONNECT_STATUS:
        info = VNIFGetMediaConnectStatus(adapter);
        break;

    /* allows upper driver to choose which type of packet it can see */
    case OID_GEN_CURRENT_PACKET_FILTER:
        info = adapter->PacketFilter;
        break;

    case OID_PNP_CAPABILITIES:
        RPRINTK(DPRTL_CONFIG, ("OID_PNP_CAPABILITIES: %s not supported.\n",
                               adapter->node_name));
        status = NDIS_STATUS_NOT_SUPPORTED;
        break;

    case OID_802_3_PERMANENT_ADDRESS:
        if (VNIF_TEST_FLAG(adapter, VNF_DISCONNECTED)) {
            if (ETH_LENGTH_OF_ADDRESS <= InformationBufferLength) {
                adapter->oid = Oid;
                adapter->oid_buffer = InformationBuffer;
                *BytesWritten = ETH_LENGTH_OF_ADDRESS;
                return NDIS_STATUS_PENDING;
            }
        }
        infoptr = adapter->PermanentAddress;
        ulBytesAvailable = infolen = ETH_LENGTH_OF_ADDRESS;
        break;

    case OID_802_3_CURRENT_ADDRESS:
        if (VNIF_TEST_FLAG(adapter, VNF_DISCONNECTED)) {
            if (ETH_LENGTH_OF_ADDRESS <= InformationBufferLength) {
                adapter->oid = Oid;
                adapter->oid_buffer = InformationBuffer;
                *BytesWritten = ETH_LENGTH_OF_ADDRESS;
                return NDIS_STATUS_PENDING;
            }
        }
        infoptr = adapter->CurrentAddress;
        ulBytesAvailable = infolen = ETH_LENGTH_OF_ADDRESS;
        break;

    case OID_802_3_MAXIMUM_LIST_SIZE:
        info = VNIF_MAX_MCAST_LIST;
        break;

#ifdef NDIS60_MINIPORT
    case OID_GEN_STATISTICS:
        /* we are going to directly fill the information buffer */
        do_copy = FALSE;

        ulBytesAvailable = infolen = sizeof(NDIS_STATISTICS_INFO);
        if (InformationBufferLength < infolen) {
            break;
        }
        status = NICGetStatsCounters(adapter, Oid,
                                     (PULONG64)InformationBuffer);
        break;

    case OID_GEN_INTERRUPT_MODERATION:
        /* This driver does not support interrupt moderation at this time */
        int_mod.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        int_mod.Header.Revision =
            NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
        int_mod.Header.Size =
            NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
        int_mod.Flags = 0;
        int_mod.InterruptModeration = NdisInterruptModerationNotSupported;
        ulBytesAvailable = infolen =
            sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS);
        infoptr = (PVOID) &int_mod;
        break;
#else
    case OID_802_3_MAC_OPTIONS:
        info = 0;
        break;
#endif
    case OID_GEN_XMIT_OK:
    case OID_GEN_RCV_OK:
    case OID_GEN_XMIT_ERROR:
    case OID_GEN_RCV_ERROR:
    case OID_GEN_RCV_NO_BUFFER:
    case OID_GEN_RCV_CRC_ERROR:
    case OID_GEN_TRANSMIT_QUEUE_LENGTH:
    case OID_802_3_RCV_ERROR_ALIGNMENT:
    case OID_802_3_XMIT_ONE_COLLISION:
    case OID_802_3_XMIT_MORE_COLLISIONS:
    case OID_802_3_XMIT_DEFERRED:
    case OID_802_3_XMIT_MAX_COLLISIONS:
    case OID_802_3_RCV_OVERRUN:
    case OID_802_3_XMIT_UNDERRUN:
    case OID_802_3_XMIT_HEARTBEAT_FAILURE:
    case OID_802_3_XMIT_TIMES_CRS_LOST:
    case OID_802_3_XMIT_LATE_COLLISIONS:
        status = NICGetStatsCounters(adapter, Oid, &info64);
        ulBytesAvailable = infolen = sizeof(info64);
        if (status == NDIS_STATUS_SUCCESS) {
            if (InformationBufferLength < sizeof(ULONG)) {
                status = NDIS_STATUS_BUFFER_TOO_SHORT;
                *BytesNeeded = ulBytesAvailable;
                break;
            }

            infolen = min(InformationBufferLength, ulBytesAvailable);
            infoptr = &info64;
        }

        break;

    case OID_TCP_TASK_OFFLOAD:
        RPRINTK(DPRTL_CONFIG, ("OID_TCP_TASK_OFFLOAD query: %s rx %x tx %x\n",
                               adapter->node_name, adapter->cur_rx_tasks,
                               adapter->cur_tx_tasks));
#ifdef NDIS60_MINIPORT
        status = NDIS_STATUS_SUCCESS;
        break;
#else
        pNdisTaskOffloadHdr = (PNDIS_TASK_OFFLOAD_HEADER) InformationBuffer;

        if (adapter->hw_tasks & VNIF_LSO_V1_SUPPORTED) {
            infolen = sizeof(NDIS_TASK_OFFLOAD_HEADER) +
                FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer) +
                sizeof(NDIS_TASK_TCP_IP_CHECKSUM) +
                FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer) +
                sizeof(NDIS_TASK_TCP_LARGE_SEND);
        } else {
            infolen = sizeof(NDIS_TASK_OFFLOAD_HEADER) +
                FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer) +
                sizeof(NDIS_TASK_TCP_IP_CHECKSUM);
        }

        if (infolen > InformationBufferLength) {
            *BytesNeeded = infolen;
            break;
        }
        RPRINTK(DPRTL_CONFIG, ("OID_TCP_TASK_OFFLOAD: %s query, infolen %d\n",
                               adapter->node_name,  infolen));

        /* the vnif miniport only support 802.3 encapsulation for now */
        if (pNdisTaskOffloadHdr->EncapsulationFormat.Encapsulation
                    != IEEE_802_3_Encapsulation &&
                pNdisTaskOffloadHdr->EncapsulationFormat.Encapsulation
                    != UNSPECIFIED_Encapsulation) {
            PRINTK(("VNIF: %s Encapsulation type is not supported, %d.\n",
                    adapter->node_name,
                    pNdisTaskOffloadHdr->EncapsulationFormat.Encapsulation));
            pNdisTaskOffloadHdr->OffsetFirstTask = 0;
            status = NDIS_STATUS_NOT_SUPPORTED;
            break;
        }

        if (pNdisTaskOffloadHdr->Size != sizeof(NDIS_TASK_OFFLOAD_HEADER) ||
            pNdisTaskOffloadHdr->Version != NDIS_TASK_OFFLOAD_VERSION) {
            PRINTK(("VNIF: %s bad Size or Version of offload header.\n",
                    adapter->node_name));
            pNdisTaskOffloadHdr->OffsetFirstTask = 0;
            status = NDIS_STATUS_NOT_SUPPORTED;
            break;
        }

        pNdisTaskOffloadHdr->OffsetFirstTask = pNdisTaskOffloadHdr->Size;
        pTaskOffload = (PNDIS_TASK_OFFLOAD)(
                       (PUCHAR)(InformationBuffer) + pNdisTaskOffloadHdr->Size);

        if (adapter->hw_tasks & VNIF_LSO_SUPPORTED) {
            OffloadTasksCount = 2;
        } else {
            OffloadTasksCount = 1;
        }

        for (i = 0; i < OffloadTasksCount; i++) {
            pTaskOffload->Size = OffloadTasks[i].Size;
            pTaskOffload->Version = OffloadTasks[i].Version;
            pTaskOffload->Task = OffloadTasks[i].Task;
            pTaskOffload->TaskBufferLength =
                OffloadTasks[i].TaskBufferLength;

            /*
             * There is a description mismatch between DDK and DDK sample
             * code * on OffsetNextTask member of NDIS_TASK_OFFLOAD. We
             * are referring to the sample code.
             */
            if (i != OffloadTasksCount - 1) {
                pTaskOffload->OffsetNextTask =
                    FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
                    + pTaskOffload->TaskBufferLength;
            } else {
                pTaskOffload->OffsetNextTask = 0;
            }

            switch (OffloadTasks[i].Task) {
            case TcpIpChecksumNdisTask:
                pTcpIpChecksumTask = (PNDIS_TASK_TCP_IP_CHECKSUM)
                    pTaskOffload->TaskBuffer;

                RPRINTK(DPRTL_CONFIG, ("\ttx op %x, tx tcp %x tx udp %x\n",
                        adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported,
                        adapter->hw_chksum_task.V4Transmit.TcpChecksum,
                        adapter->hw_chksum_task.V4Transmit.UdpChecksum));
                RPRINTK(DPRTL_CONFIG, ("\trx op %x rx tcp %x rx udp %x\n",
                        adapter->hw_chksum_task.V4Receive.TcpOptionsSupported,
                        adapter->hw_chksum_task.V4Receive.TcpChecksum,
                        adapter->hw_chksum_task.V4Receive.UdpChecksum));
                NdisMoveMemory(pTcpIpChecksumTask,
                               &adapter->hw_chksum_task,
                               sizeof(adapter->hw_chksum_task));
                break;
            case TcpLargeSendNdisTask:
                RPRINTK(DPRTL_CONFIG,
                        ("MPQueryInformation: TcpLargeSendNdisTask\n"));
                tcp_large_send = (PNDIS_TASK_TCP_LARGE_SEND)
                    pTaskOffload->TaskBuffer;
                if (adapter->hw_tasks & VNIF_LSO_V1_SUPPORTED) {
                    tcp_large_send->Version =
                        NDIS_TASK_TCP_LARGE_SEND_V0;
                    tcp_large_send->MaxOffLoadSize =
                        adapter->lso_data_size;
                    tcp_large_send->MinSegmentCount =
                        VNIF_MIN_SEGMENT_COUNT;
                    tcp_large_send->TcpOptions = 1;
                    tcp_large_send->IpOptions = 1;
                }
                break;
            }
            if (i != OffloadTasksCount) {
                pTaskOffload = (PNDIS_TASK_OFFLOAD)
                    ((PUCHAR)pTaskOffload + pTaskOffload->OffsetNextTask);
            }
        }

        /* set InformationBuffer directly, override the default handling */
        *BytesWritten = infolen;
        return NDIS_STATUS_SUCCESS;
#endif

#ifdef NDIS620_MINIPORT
    case OID_GEN_RECEIVE_SCALE_CAPABILITIES:
        RPRINTK(DPRTL_RSS,
                ("%s: OID_GEN_RECEIVE_SCALE_CAPABILITIES\n", __func__));
        do_copy = FALSE;
        ulBytesAvailable = infolen = sizeof(NDIS_RECEIVE_SCALE_CAPABILITIES);

        if (InformationBufferLength < sizeof(NDIS_RECEIVE_SCALE_CAPABILITIES)) {
            *BytesNeeded = sizeof(NDIS_RECEIVE_SCALE_CAPABILITIES);
            status = NDIS_STATUS_BUFFER_TOO_SHORT;
            break;
        }

        infoptr = vnif_rss_set_generall_attributes(
                adapter,
                (NDIS_RECEIVE_SCALE_CAPABILITIES *)InformationBuffer);

        if (infoptr == NULL) {
            status = NDIS_STATUS_NOT_SUPPORTED;
            break;
        }

        break;

    case OID_GEN_RECEIVE_HASH:
        RPRINTK(DPRTL_RSS,
                ("%s: OID_GEN_RECEIVE_HASH\n", __func__));
        /*
         * pInfo = &u.RSSHashKeyParameters;
         * ulSize = ParaNdis6_QueryReceiveHash(&pContext->RSSParameters,
         *                                     &u.RSSHashKeyParameters);
         */
        break;
#endif

    case OID_PNP_QUERY_POWER:
        RPRINTK(DPRTL_CONFIG,
                ("OID_PNP_QUERY_POWER: %s\n", adapter->node_name));
        status = NDIS_STATUS_SUCCESS;
        break;

    case OID_GEN_INIT_TIME_MS:       /* 0x00020213 */
    case OID_GEN_RESET_COUNTS:       /* 0x00020214 */
    case OID_GEN_MEDIA_SENSE_COUNTS: /* 0x00020215 */
    case OID_IP4_OFFLOAD_STATS:      /* 0xFC010209 */
    case OID_IP6_OFFLOAD_STATS:      /* 0xFC01020A */
        status = NDIS_STATUS_NOT_SUPPORTED;
        break;
    default:
        RPRINTK(DPRTL_CONFIG, ("Unknown OID %x\n", Oid));
        status = NDIS_STATUS_NOT_SUPPORTED;
        break;
    }

    if (status == NDIS_STATUS_SUCCESS) {
        *BytesNeeded = ulBytesAvailable;
        if (infolen <= InformationBufferLength) {
            /* Copy result into InformationBuffer */
            *BytesWritten = infolen;
            if (infolen && do_copy) {
                NdisMoveMemory(InformationBuffer, infoptr, infolen);
            }
        } else {
            /* too short */
            *BytesNeeded = infolen;
            status = NDIS_STATUS_BUFFER_TOO_SHORT;
        }
    }
    return status;
}

NDIS_STATUS
MPSetInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesRead,
  OUT PULONG BytesNeeded)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;

#ifdef NDIS60_MINIPORT
    PNDIS_OFFLOAD_ENCAPSULATION encapsulation;
    PNDIS_OFFLOAD_PARAMETERS offload_parms;
    uint32_t offload_changed;
    uint32_t lso_enabled;
    USHORT offload_params_size;
#else
    PNDIS_TASK_OFFLOAD_HEADER pNdisTaskOffloadHdr;
    PNDIS_TASK_OFFLOAD pTaskOffload;
    PNDIS_TASK_TCP_IP_CHECKSUM pTcpIpChecksumTask;
    PNDIS_TASK_TCP_LARGE_SEND tcp_large_send;
#endif
    uint32_t new_rx_chksum_tasks;
    uint32_t new_tx_chksum_tasks;
    NDIS_DEVICE_POWER_STATE NewPowerState;
    UINT i;

    if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_SURPRISE_REMOVED)) {
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    *BytesRead = 0;
    *BytesNeeded = 0;

    RPRINTK(DPRTL_CONFIG, ("Set oid %x.\n", Oid));
    switch (Oid) {
    case OID_802_3_MULTICAST_LIST:
        status = VNIFSetMulticastList(
            adapter,
            InformationBuffer,
            InformationBufferLength,
            BytesRead,
            BytesNeeded);
        break;

    case OID_GEN_CURRENT_PACKET_FILTER:
        if (InformationBufferLength != sizeof(ULONG)) {
            *BytesNeeded = sizeof(ULONG);
            status = NDIS_STATUS_INVALID_LENGTH;
            break;
        }

        *BytesRead = InformationBufferLength;

        status = VNIFSetPacketFilter(adapter, *((PULONG)InformationBuffer));
        break;

    case OID_GEN_CURRENT_LOOKAHEAD:
        if (InformationBufferLength < sizeof(ULONG)) {
            *BytesNeeded = sizeof(ULONG);
            status = NDIS_STATUS_INVALID_LENGTH;
            break;
        }

        if (adapter->hw_tasks & VNIF_RX_SG_LARGE) {
            if (*(UNALIGNED PULONG)InformationBuffer
                    > VNIF_MAX_RCV_SIZE - ETH_HEADER_SIZE) {
                status = NDIS_STATUS_INVALID_DATA;
                break;
            }
        } else {
            if (*(UNALIGNED PULONG)InformationBuffer > adapter->mtu) {
                status = NDIS_STATUS_INVALID_DATA;
                break;
            }
        }

        NdisMoveMemory(&adapter->ulLookAhead, InformationBuffer, sizeof(ULONG));

        *BytesRead = sizeof(ULONG);
        status = NDIS_STATUS_SUCCESS;
        break;

#ifdef NDIS60_MINIPORT
    case OID_GEN_INTERRUPT_MODERATION:
        /* This driver does not support interrupt moderation at this time */
        status = NDIS_STATUS_INVALID_DATA;
        break;

    case OID_OFFLOAD_ENCAPSULATION:
        RPRINTK(DPRTL_CONFIG,
                ("OID_OFFLOAD_ENCAPSULATION %s.\n", adapter->node_name));
        if (InformationBufferLength < sizeof(NDIS_OFFLOAD_ENCAPSULATION)) {
            *BytesNeeded = sizeof(NDIS_OFFLOAD_ENCAPSULATION);
            status = NDIS_STATUS_INVALID_LENGTH;
            PRINTK(("OID_OFFLOAD_ENCAPSULATION: %s, too small %x.\n",
                    adapter->node_name, InformationBufferLength));
            break;
        }
        encapsulation = (PNDIS_OFFLOAD_ENCAPSULATION) InformationBuffer;
        if (encapsulation->Header.Type
                    != NDIS_OBJECT_TYPE_OFFLOAD_ENCAPSULATION
                && encapsulation->Header.Revision
                    != NDIS_OFFLOAD_ENCAPSULATION_REVISION_1
                && encapsulation->Header.Size
                    != NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1
                && encapsulation->IPv4.EncapsulationType
                    != NDIS_ENCAPSULATION_IEEE_802_3
                && encapsulation->IPv6.EncapsulationType
                    != NDIS_ENCAPSULATION_IEEE_802_3) {
            status = NDIS_STATUS_INVALID_DATA;
            PRINTK(("OID_OFFLOAD_ENCAPSULATION: %s, bad data.\n",
                    adapter->node_name));
            break;
        }
        *BytesRead = sizeof(NDIS_OFFLOAD_ENCAPSULATION);
        VNIFIndicateOffload(adapter);
        RPRINTK(DPRTL_CONFIG, ("\tBytesRead %x, 4e %x, 4t %x 6e %x 6t %x.\n",
                               *BytesRead,
                               encapsulation->IPv4.Enabled,
                               encapsulation->IPv4.EncapsulationType,
                               encapsulation->IPv6.Enabled,
                               encapsulation->IPv6.EncapsulationType));
        status = NDIS_STATUS_SUCCESS;
        break;

    case OID_TCP_OFFLOAD_PARAMETERS:
        RPRINTK(DPRTL_CONFIG,
                ("OID_TCP_OFFLOAD_PARAMETERS %s\n", adapter->node_name));
#ifdef NDIS620_MINIPORT
        offload_params_size = NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_2;
#else
        offload_params_size = NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_1;
#endif
        if (InformationBufferLength < offload_params_size) {
            *BytesNeeded = offload_params_size;
            status = NDIS_STATUS_INVALID_LENGTH;
            PRINTK(("OID_TCP_OFFLOAD_PARAMETERS too small %d < %d.\n",
                    InformationBufferLength,
                    offload_params_size));
            break;
        }

        offload_parms = (PNDIS_OFFLOAD_PARAMETERS)InformationBuffer;

        if (offload_parms->Header.Type != NDIS_OBJECT_TYPE_DEFAULT) {
            status = NDIS_STATUS_INVALID_DATA;
            PRINTK(("OID_TCP_OFFLOAD_PARAMETERS: %s, bad default type 0x%x.\n",
                    adapter->node_name,
                    offload_parms->Header.Type));
            break;
        }

        if (offload_parms->Header.Size < offload_params_size) {
            status = NDIS_STATUS_INVALID_DATA;
            PRINTK(("OID_TCP_OFFLOAD_PARAMETERS: %s, bad hdr size %d %d.\n",
                    adapter->node_name,
                    offload_parms->Header.Size,
                    offload_params_size));
            break;
        }

        if (offload_parms->IPsecV1
                || offload_parms->TcpConnectionIPv4
                || offload_parms->TcpConnectionIPv6) {
            status = NDIS_STATUS_NOT_SUPPORTED;
            PRINTK(("OID_TCP_OFFLOAD_PARAMETERS: %s, not supported.\n",
                    adapter->node_name));
            break;
        }

        offload_changed = 0;
        new_rx_chksum_tasks = 0;
        new_tx_chksum_tasks = 0;

        RPRINTK(DPRTL_CHKSUM,
                ("Offload hw %x ctx %x crx %x t4 %x u4 %x t6 %x u6 %x.\n",
                adapter->hw_tasks,
                adapter->cur_tx_tasks,
                adapter->cur_rx_tasks,
                offload_parms->TCPIPv4Checksum,
                offload_parms->UDPIPv4Checksum,
                offload_parms->TCPIPv6Checksum,
                offload_parms->UDPIPv6Checksum
                ));

        if (adapter->hw_tasks & VNIF_CHKSUM_TXRX_SUPPORTED) {
            /* Check for RX enable checksum changes. */
            switch (offload_parms->TCPIPv4Checksum) {
            case NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED:
                new_tx_chksum_tasks |= VNIF_CHKSUM_IPV4_TCP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED:
                new_rx_chksum_tasks |= VNIF_CHKSUM_IPV4_TCP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED:
                new_tx_chksum_tasks |= VNIF_CHKSUM_IPV4_TCP;
                new_rx_chksum_tasks |= VNIF_CHKSUM_IPV4_TCP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED:
            default:
                break;
            }
            switch (offload_parms->UDPIPv4Checksum) {
            case NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED:
                new_tx_chksum_tasks |= VNIF_CHKSUM_IPV4_UDP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED:
                new_rx_chksum_tasks |= VNIF_CHKSUM_IPV4_UDP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED:
                new_tx_chksum_tasks |= VNIF_CHKSUM_IPV4_UDP;
                new_rx_chksum_tasks |= VNIF_CHKSUM_IPV4_UDP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED:
            default:
                break;
            }
        }
        if (adapter->hw_tasks & VNIF_CHKSUM_TXRX_IPV6_SUPPORTED) {
            /* Check for RX enable checksum changes. */
            switch (offload_parms->TCPIPv6Checksum) {
            case NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED:
                new_tx_chksum_tasks |= VNIF_CHKSUM_IPV6_TCP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED:
                new_rx_chksum_tasks |= VNIF_CHKSUM_IPV6_TCP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED:
                new_tx_chksum_tasks |= VNIF_CHKSUM_IPV6_TCP;
                new_rx_chksum_tasks |= VNIF_CHKSUM_IPV6_TCP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED:
            default:
                break;
            }
            switch (offload_parms->UDPIPv6Checksum) {
            case NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED:
                new_tx_chksum_tasks |= VNIF_CHKSUM_IPV6_UDP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED:
                new_rx_chksum_tasks |= VNIF_CHKSUM_IPV6_UDP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED:
                new_tx_chksum_tasks |= VNIF_CHKSUM_IPV6_UDP;
                new_rx_chksum_tasks |= VNIF_CHKSUM_IPV6_UDP;
                break;
            case NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED:
            default:
                break;
            }
        }
        if (adapter->cur_rx_tasks != new_rx_chksum_tasks) {
            adapter->cur_rx_tasks = new_rx_chksum_tasks;
            offload_changed = 1;
        }
        if (adapter->cur_tx_tasks != new_tx_chksum_tasks) {
            adapter->cur_tx_tasks = new_tx_chksum_tasks;
            offload_changed = 1;
        }

        /* Check for LSO enables.  Only enable if hardware supports it. */
        lso_enabled = 0;
        if (offload_parms->LsoV1 == NDIS_OFFLOAD_PARAMETERS_LSOV1_ENABLED
                && adapter->hw_tasks & VNIF_LSO_V1_SUPPORTED) {
            lso_enabled |= VNIF_LSOV1_ENABLED;
        }
        if (offload_parms->LsoV2IPv4 == NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED
                && adapter->hw_tasks & VNIF_LSO_V2_SUPPORTED) {
            lso_enabled |= VNIF_LSOV2_ENABLED;
        }
        if (offload_parms->LsoV2IPv6 == NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED
                && adapter->hw_tasks & VNIF_LSO_V2_IPV6_SUPPORTED) {
            lso_enabled |= VNIF_LSOV2_IPV6_ENABLED;
        }
        if (adapter->lso_enabled != lso_enabled) {
            adapter->lso_enabled = lso_enabled;
            offload_changed = 1;
        }

        if (offload_changed) {
            RPRINTK(DPRTL_CHKSUM,
                    ("Offload txchk %x rxchk %x lso %x v1 %d v2 %d v2_6 %d.\n",
                    adapter->cur_tx_tasks,
                    adapter->cur_rx_tasks,
                    adapter->lso_enabled,
                    offload_parms->LsoV1,
                    offload_parms->LsoV2IPv4,
                    offload_parms->LsoV2IPv6));
            VNIFIndicateOffload(adapter);
        }

        *BytesRead = sizeof(NDIS_OFFLOAD_PARAMETERS);
        RPRINTK(DPRTL_CONFIG, ("\tBytesRead %x.\n", *BytesRead));
        break;

#ifdef NDIS620_MINIPORT
    case OID_GEN_RECEIVE_SCALE_PARAMETERS:
        status = vnif_rss_oid_gen_receive_scale_params(
            adapter,
            (NDIS_RECEIVE_SCALE_PARAMETERS *)InformationBuffer,
            InformationBufferLength,
            BytesRead,
            BytesNeeded);
        break;
#endif
#else
    case OID_TCP_TASK_OFFLOAD:
        RPRINTK(DPRTL_CONFIG, ("OID_TCP_TASK_OFFLOAD: %s\n",
                               adapter->node_name));

        if (InformationBufferLength < sizeof(NDIS_TASK_OFFLOAD_HEADER)) {
            status = NDIS_STATUS_INVALID_LENGTH;
            break;
        }

        *BytesRead = sizeof(NDIS_TASK_OFFLOAD_HEADER);

        pNdisTaskOffloadHdr = (PNDIS_TASK_OFFLOAD_HEADER) InformationBuffer;
        if (pNdisTaskOffloadHdr->EncapsulationFormat.Encapsulation
                    != IEEE_802_3_Encapsulation &&
                pNdisTaskOffloadHdr->EncapsulationFormat.Encapsulation
                    != UNSPECIFIED_Encapsulation) {
            pNdisTaskOffloadHdr->OffsetFirstTask = 0;
            status = NDIS_STATUS_INVALID_DATA;
            break;
        }

        if (pNdisTaskOffloadHdr->OffsetFirstTask == 0) {
            RPRINTK(DPRTL_CONFIG, ("\tOffsetFistTask==0, clear\n"));
            adapter->cur_rx_tasks = 0;
            adapter->cur_tx_tasks = 0;
            status = NDIS_STATUS_SUCCESS;
            break;
        }

            /* sanity checks */
        if (pNdisTaskOffloadHdr->OffsetFirstTask < pNdisTaskOffloadHdr->Size) {
            pNdisTaskOffloadHdr->OffsetFirstTask = 0;
            status = NDIS_STATUS_FAILURE;
            break;
        }

        RPRINTK(DPRTL_CONFIG, ("\tInfoBufferLength %x, %x, %x.\n",
                               InformationBufferLength,
                               pNdisTaskOffloadHdr->OffsetFirstTask,
                               sizeof(NDIS_TASK_OFFLOAD)));
        if (InformationBufferLength < (pNdisTaskOffloadHdr->OffsetFirstTask
                                       + sizeof(NDIS_TASK_OFFLOAD))) {
            RPRINTK(DPRTL_CONFIG, ("\tInfoBufLength too small rx %x tx %x.\n",
                    adapter->cur_rx_tasks, adapter->cur_tx_tasks));
            status = NDIS_STATUS_INVALID_LENGTH;
            break;
        }

        NdisMoveMemory(&adapter->EncapsulationFormat,
                       &pNdisTaskOffloadHdr->EncapsulationFormat,
                       sizeof(NDIS_ENCAPSULATION_FORMAT));

        ASSERT(pNdisTaskOffloadHdr->EncapsulationFormat.Flags.FixedHeaderSize
               == 1);

        pTaskOffload = (PNDIS_TASK_OFFLOAD)((PUCHAR)pNdisTaskOffloadHdr
                        + pNdisTaskOffloadHdr->OffsetFirstTask);

        new_tx_chksum_tasks = 0;
        new_rx_chksum_tasks = 0;
        RPRINTK(DPRTL_CONFIG, ("\tcurrent tasks: rx %x tx %x\n",
                               adapter->cur_rx_tasks, adapter->cur_tx_tasks));

        if (adapter->hw_tasks & VNIF_LSO_SUPPORTED) {
            OffloadTasksCount = 2;
        } else {
            OffloadTasksCount = 1;
        }

        while (pTaskOffload) {
            *BytesRead += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer);

            switch (pTaskOffload->Task) {
            case TcpIpChecksumNdisTask:
                if (InformationBufferLength < *BytesRead
                        + sizeof(NDIS_TASK_TCP_IP_CHECKSUM)) {
                    *BytesNeeded = *BytesRead
                        + sizeof(NDIS_TASK_TCP_IP_CHECKSUM);
                    status = NDIS_STATUS_INVALID_LENGTH;
                    break;
                }

                for (i = 0; i < OffloadTasksCount; i++) {
                    if (OffloadTasks[i].Task == pTaskOffload->Task &&
                        OffloadTasks[i].Version == pTaskOffload->Version) {
                        break;
                    }
                }

                if (i == OffloadTasksCount) {
                    RPRINTK(DPRTL_CONFIG, ("\ti not supported.\n"));
                    status = NDIS_STATUS_NOT_SUPPORTED;
                    break;
                }

                pTcpIpChecksumTask = (PNDIS_TASK_TCP_IP_CHECKSUM)
                    pTaskOffload->TaskBuffer;

                if (pTcpIpChecksumTask->V4Transmit.IpOptionsSupported) {
                    if (adapter->hw_chksum_task.V4Transmit.IpOptionsSupported
                            == 0) {
                        RPRINTK(DPRTL_CONFIG, ("\ttx op IP NS.\n"));
                        return NDIS_STATUS_NOT_SUPPORTED;
                    }
                }

                if (pTcpIpChecksumTask->V4Transmit.TcpOptionsSupported) {
                    if (adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported
                            == 0) {
                        RPRINTK(DPRTL_CONFIG, ("\ttx op TCP NS.\n"));
                        return NDIS_STATUS_NOT_SUPPORTED;
                    }
                }

                /* IPV4 Transmit */
                if (pTcpIpChecksumTask->V4Transmit.TcpChecksum) {
                    if (adapter->hw_chksum_task.V4Transmit.TcpChecksum == 0) {
                        RPRINTK(DPRTL_CONFIG, ("\ttx TCP NS %x.\n",
                                           adapter->cur_tx_tasks));
                        return NDIS_STATUS_NOT_SUPPORTED;
                    }
                    RPRINTK(DPRTL_CONFIG, ("\tsetting tx tcp.\n"));
                    new_tx_chksum_tasks |= VNIF_CHKSUM_IPV4_TCP;
                }

                if (pTcpIpChecksumTask->V4Transmit.IpChecksum) {
                    if (adapter->hw_chksum_task.V4Transmit.IpChecksum == 0) {
                        RPRINTK(DPRTL_CONFIG, ("\ttx ip NS.\n"));
                        return NDIS_STATUS_NOT_SUPPORTED;
                    }
                    RPRINTK(DPRTL_CONFIG, ("\tsetting tx ip.\n"));
                    new_tx_chksum_tasks |= VNIF_CHKSUM_IPV4_IP;
                }

                if (pTcpIpChecksumTask->V4Transmit.UdpChecksum) {
                    if (adapter->hw_chksum_task.V4Transmit.UdpChecksum == 0) {
                        RPRINTK(DPRTL_CONFIG, ("\ttx UDP NS.\n"));
                        return NDIS_STATUS_NOT_SUPPORTED;
                    }
                    RPRINTK(DPRTL_CONFIG, ("\tsetting tx udp.\n"));
                    new_tx_chksum_tasks |= VNIF_CHKSUM_IPV4_UDP;
                }

                /* IPV4 Receive */
                if (pTcpIpChecksumTask->V4Receive.TcpChecksum) {
                    if (adapter->hw_chksum_task.V4Receive.TcpChecksum == 0) {
                        RPRINTK(DPRTL_CONFIG, ("\trx TCP NS %x.\n",
                                               adapter->cur_rx_tasks));
                        return NDIS_STATUS_NOT_SUPPORTED;
                    }
                    RPRINTK(DPRTL_CONFIG, ("\tsetting rx TCP %x.\n",
                            adapter->hw_chksum_task.V4Receive.TcpChecksum));
                    new_rx_chksum_tasks |= VNIF_CHKSUM_IPV4_TCP;
                }

                if (pTcpIpChecksumTask->V4Receive.IpChecksum) {
                    if (adapter->hw_chksum_task.V4Receive.IpChecksum == 0) {
                        RPRINTK(DPRTL_CONFIG, ("\trx IP NS.\n"));
                        return NDIS_STATUS_NOT_SUPPORTED;
                    }
                    new_rx_chksum_tasks |= VNIF_CHKSUM_IPV4_IP;
                }

                if (pTcpIpChecksumTask->V4Receive.UdpChecksum) {
                    if (adapter->hw_chksum_task.V4Receive.UdpChecksum == 0) {
                        RPRINTK(DPRTL_CONFIG, ("\trx UDP NS.\n"));
                        return NDIS_STATUS_NOT_SUPPORTED;
                    }
                    RPRINTK(DPRTL_CONFIG, ("\tsetting rx udp.\n"));
                    new_rx_chksum_tasks |= VNIF_CHKSUM_IPV4_UDP;
                }

                /* We don't do IPv6 so just return failure. */
                if (pTcpIpChecksumTask->V6Transmit.TcpChecksum
                        || pTcpIpChecksumTask->V6Transmit.UdpChecksum
                        || pTcpIpChecksumTask->V6Receive.TcpChecksum
                        || pTcpIpChecksumTask->V6Receive.UdpChecksum) {
                    RPRINTK(DPRTL_CONFIG,
                            ("OID_TCP_TASK_OFFLOAD: V6 NS.\n"));
                    return NDIS_STATUS_NOT_SUPPORTED;
                }

                *BytesRead += sizeof(NDIS_TASK_TCP_IP_CHECKSUM);
                status = NDIS_STATUS_SUCCESS;
                break;

            case TcpLargeSendNdisTask:
                tcp_large_send = (PNDIS_TASK_TCP_LARGE_SEND)
                pTaskOffload->TaskBuffer;
                if (tcp_large_send->MaxOffLoadSize > adapter->lso_data_size
                    || tcp_large_send->MinSegmentCount
                        < VNIF_MIN_SEGMENT_COUNT) {
                    RPRINTK(DPRTL_CONFIG,
                            ("MPSetInformation: LSO, not supported.\n"));
                    return NDIS_STATUS_NOT_SUPPORTED;
                }
                RPRINTK(DPRTL_CONFIG,
                        ("MPSetInformation: LSO, s %d, c %d, i %d, t %d.\n",
                         tcp_large_send->MaxOffLoadSize,
                         tcp_large_send->MinSegmentCount,
                         tcp_large_send->IpOptions,
                         tcp_large_send->TcpOptions));

                *BytesRead += sizeof(NDIS_TASK_TCP_LARGE_SEND);
                status = NDIS_STATUS_SUCCESS;
                break;

            default:
                RPRINTK(DPRTL_CONFIG,
                        ("OID_TCP_TASK_OFFLOAD: default NS.\n"));
                status = NDIS_STATUS_NOT_SUPPORTED;
                break;
            } /* switch Task */

            if (status != NDIS_STATUS_SUCCESS) {
                break;
            }

            if (pTaskOffload->OffsetNextTask) {
                pTaskOffload = (PNDIS_TASK_OFFLOAD)((PUCHAR)
                                pTaskOffload + pTaskOffload->OffsetNextTask);
            } else {
                pTaskOffload = NULL;
            }
        } /* while pTaskOffload */
        adapter->cur_rx_tasks = new_rx_chksum_tasks;
        adapter->cur_tx_tasks = new_tx_chksum_tasks;
        RPRINTK(DPRTL_CONFIG, ("OID: cur rx %d, cur tx %d.\n",
                               adapter->cur_rx_tasks, adapter->cur_tx_tasks));
#endif
        break;

    case OID_PNP_SET_POWER:
        if (InformationBufferLength != sizeof(NDIS_DEVICE_POWER_STATE)) {
            RPRINTK(DPRTL_CONFIG,
                    ("Set for POWER: NDIS_STATUS_INVALID_LENGTH\n"));
            *BytesNeeded = sizeof(NDIS_STATUS_INVALID_LENGTH);
            return NDIS_STATUS_INVALID_LENGTH;
        }

        NewPowerState =
            *(PNDIS_DEVICE_POWER_STATE UNALIGNED)InformationBuffer;
        *BytesRead = sizeof(NDIS_DEVICE_POWER_STATE);
        RPRINTK(DPRTL_CONFIG, ("OID_PNP_SET_POWER: old %d, new %d\n",
                               adapter->power_state, NewPowerState));
        if (adapter->power_state != NewPowerState) {
            if (NewPowerState == NdisDeviceStateD0) {
                VNIF_SET_FLAG(adapter, VNF_ADAPTER_NEEDS_RSTART);
            }
#if defined NDIS60_MINIPORT
            else {
                if (g_running_hypervisor == HYPERVISOR_KVM) {
                    VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_POLLING);
                }
            }
#endif
            adapter->power_state = NewPowerState;
        }
        status = NDIS_STATUS_SUCCESS;
        break;

    default:
        status = NDIS_STATUS_NOT_SUPPORTED;
        break;
    }

    return status;
}

ULONG
VNIFGetMediaConnectStatus(PVNIF_ADAPTER Adapter)
{
    if (VNIF_TEST_FLAG(Adapter, VNF_ADAPTER_NO_LINK)) {
        return NdisMediaStateDisconnected;
    } else {
        return NdisMediaStateConnected;
    }
}

NDIS_STATUS
VNIFSetPacketFilter(PVNIF_ADAPTER adapter, ULONG PacketFilter)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (PacketFilter & ~VNIF_SUPPORTED_FILTERS) {
        RPRINTK(DPRTL_CONFIG,
            ("VNIFSetPacketFilter: %s setting an invalid filter %x.\n",
            adapter->node_name, PacketFilter));
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    if (PacketFilter != adapter->PacketFilter) {
        RPRINTK(DPRTL_CONFIG, ("VNIFSetPacketFilter: %s new filter %x.\n",
            adapter->node_name, PacketFilter));
        adapter->PacketFilter = PacketFilter;
    }

    return status;
}

NDIS_STATUS
VNIFSetMulticastList(
  IN PVNIF_ADAPTER adapter,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesRead,
  OUT PULONG BytesNeeded)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG i;

    *BytesNeeded = ETH_LENGTH_OF_ADDRESS;
    *BytesRead = InformationBufferLength;

    if (InformationBufferLength % ETH_LENGTH_OF_ADDRESS) {
        return NDIS_STATUS_INVALID_LENGTH;
    }

    if (InformationBufferLength >
            (VNIF_MAX_MCAST_LIST * ETH_LENGTH_OF_ADDRESS)) {
        *BytesNeeded = VNIF_MAX_MCAST_LIST * ETH_LENGTH_OF_ADDRESS;
        return NDIS_STATUS_MULTICAST_FULL;
    }

    NdisZeroMemory(adapter->MCList,
                   VNIF_MAX_MCAST_LIST * ETH_LENGTH_OF_ADDRESS);

    NdisMoveMemory(adapter->MCList,
                   InformationBuffer,
                   InformationBufferLength);

    adapter->ulMCListSize = InformationBufferLength / ETH_LENGTH_OF_ADDRESS;

    return NDIS_STATUS_SUCCESS;
}

#ifdef NDIS60_MINIPORT

#define     ADD_TWO_INTEGERS        1
#define     MINUS_TWO_INTEGERS      2

NDIS_STATUS
MPMethodRequest(PVNIF_ADAPTER adapter, PNDIS_OID_REQUEST Request)
{

    NDIS_OID Oid;
    ULONG  MethodId;
    PVOID InformationBuffer;
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    ULONG BytesNeeded = 0;

    Oid = Request->DATA.METHOD_INFORMATION.Oid;
    InformationBuffer = (PVOID)
        (Request->DATA.METHOD_INFORMATION.InformationBuffer);
    InputBufferLength = Request->DATA.METHOD_INFORMATION.InputBufferLength;
    OutputBufferLength = Request->DATA.METHOD_INFORMATION.OutputBufferLength;
    MethodId = Request->DATA.METHOD_INFORMATION.MethodId;
    BytesNeeded = 0;
    Request->DATA.METHOD_INFORMATION.BytesNeeded = BytesNeeded;
    return NDIS_STATUS_NOT_SUPPORTED;
}

NDIS_STATUS
MPOidRequest(IN NDIS_HANDLE  MiniportAdapterContext,
    IN  PNDIS_OID_REQUEST  NdisRequest)

{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;
    NDIS_STATUS status;

    RPRINTK(DPRTL_CONFIG, ("--> MPOidRequest\n"));

    if (VNIF_TEST_FLAG(adapter, VNF_RESET_IN_PROGRESS)) {
        return NDIS_STATUS_REQUEST_ABORTED;
    }
    if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_SURPRISE_REMOVED)) {
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    switch (NdisRequest->RequestType) {
    case NdisRequestMethod:
        status = MPMethodRequest(adapter, NdisRequest);
        break;

    case NdisRequestSetInformation:
        status = MPSetInformation(MiniportAdapterContext,
            NdisRequest->DATA.SET_INFORMATION.Oid,
            NdisRequest->DATA.SET_INFORMATION.InformationBuffer,
            NdisRequest->DATA.SET_INFORMATION.InformationBufferLength,
            &NdisRequest->DATA.SET_INFORMATION.BytesRead,
            &NdisRequest->DATA.SET_INFORMATION.BytesNeeded);
        break;

    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
        status = MPQueryInformation(MiniportAdapterContext,
            NdisRequest->DATA.QUERY_INFORMATION.Oid,
            NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer,
            NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength,
            &NdisRequest->DATA.QUERY_INFORMATION.BytesWritten,
            &NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded);
        break;

    default:
        status = NDIS_STATUS_NOT_SUPPORTED;
        break;
    }

    RPRINTK(DPRTL_CONFIG,
        ("<-- MPOidRequest: OID %x type %d, written %x, needed %x, status %x\n",
        NdisRequest->DATA.QUERY_INFORMATION.Oid,
        NdisRequest->RequestType,
        NdisRequest->DATA.QUERY_INFORMATION.BytesWritten,
        NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded,
        status));
    return status;
}

VOID
MPCancelOidRequest(IN NDIS_HANDLE MiniportAdapterContext, IN PVOID RequestId)
{
}

void
VNIFIndicateOffload(PVNIF_ADAPTER adapter)
{

    NDIS_OFFLOAD            offload;
    NDIS_STATUS_INDICATION  status_indication;

    RPRINTK(DPRTL_CONFIG, ("VNIFIndicateOffload %s: tx %x, rx %x\n",
        adapter->node_name, adapter->cur_tx_tasks, adapter->cur_rx_tasks));
    NdisZeroMemory(&offload, sizeof(NDIS_OFFLOAD));
    NdisZeroMemory(&status_indication, sizeof(NDIS_STATUS_INDICATION));

    offload.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;
    offload.Header.Revision = NDIS_OFFLOAD_REVISION_1;
    offload.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_1;

    /* Check Ipv4 */
    if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_IP) {
        offload.Checksum.IPv4Transmit.IpChecksum = NDIS_OFFLOAD_SUPPORTED;
    }
    if (adapter->cur_tx_tasks & (VNIF_CHKSUM_IPV4_TCP | VNIF_CHKSUM_IPV4_UDP)) {
        offload.Checksum.IPv4Transmit.Encapsulation =
            NDIS_ENCAPSULATION_IEEE_802_3;
        offload.Checksum.IPv4Transmit.TcpOptionsSupported =
            NDIS_OFFLOAD_SUPPORTED;

        if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_TCP) {
            offload.Checksum.IPv4Transmit.TcpChecksum = NDIS_OFFLOAD_SUPPORTED;
        }
        if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_UDP) {
            offload.Checksum.IPv4Transmit.UdpChecksum = NDIS_OFFLOAD_SUPPORTED;
        }
    }

    if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_IP) {
        offload.Checksum.IPv4Receive.IpChecksum = NDIS_OFFLOAD_SUPPORTED;
    }
    if (adapter->cur_rx_tasks & (VNIF_CHKSUM_IPV4_TCP | VNIF_CHKSUM_IPV4_UDP)) {
        offload.Checksum.IPv4Receive.Encapsulation =
            NDIS_ENCAPSULATION_IEEE_802_3;
        offload.Checksum.IPv4Receive.TcpOptionsSupported =
            NDIS_OFFLOAD_SUPPORTED;

        if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_TCP) {
            offload.Checksum.IPv4Receive.TcpChecksum = NDIS_OFFLOAD_SUPPORTED;
        }
        if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_UDP) {
            offload.Checksum.IPv4Receive.UdpChecksum = NDIS_OFFLOAD_SUPPORTED;
        }
    }

    /* Check IPv6 */
    if (adapter->cur_tx_tasks & (VNIF_CHKSUM_IPV6_TCP | VNIF_CHKSUM_IPV6_UDP)) {
        offload.Checksum.IPv6Transmit.Encapsulation =
            NDIS_ENCAPSULATION_IEEE_802_3;
        offload.Checksum.IPv6Transmit.TcpOptionsSupported =
            NDIS_OFFLOAD_SUPPORTED;

        if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_TCP) {
            offload.Checksum.IPv6Transmit.TcpChecksum = NDIS_OFFLOAD_SUPPORTED;
        }
        if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_UDP) {
            offload.Checksum.IPv6Transmit.UdpChecksum = NDIS_OFFLOAD_SUPPORTED;
        }
    }

    if (adapter->cur_rx_tasks & (VNIF_CHKSUM_IPV6_TCP | VNIF_CHKSUM_IPV6_UDP)) {
        offload.Checksum.IPv6Receive.Encapsulation =
            NDIS_ENCAPSULATION_IEEE_802_3;
        offload.Checksum.IPv6Receive.TcpOptionsSupported =
            NDIS_OFFLOAD_SUPPORTED;

        if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_TCP) {
            offload.Checksum.IPv6Receive.TcpChecksum = NDIS_OFFLOAD_SUPPORTED;
        }
        if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_UDP) {
            offload.Checksum.IPv6Receive.UdpChecksum = NDIS_OFFLOAD_SUPPORTED;
        }
    }

    if ((adapter->lso_enabled & VNIF_LSOV1_ENABLED)
            && adapter->hw_tasks & VNIF_LSO_V1_SUPPORTED) {
        offload.LsoV1.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        offload.LsoV1.IPv4.MaxOffLoadSize  = adapter->lso_data_size;
        offload.LsoV1.IPv4.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;
        offload.LsoV1.IPv4.TcpOptions      = 1;
        offload.LsoV1.IPv4.IpOptions       = 1;
    }
    if ((adapter->lso_enabled & VNIF_LSOV2_ENABLED)
            && adapter->hw_tasks & VNIF_LSO_V2_SUPPORTED) {
        offload.LsoV2.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        offload.LsoV2.IPv4.MaxOffLoadSize  = adapter->lso_data_size;
        offload.LsoV2.IPv4.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;
    }
    if ((adapter->lso_enabled & VNIF_LSOV2_IPV6_ENABLED)
            && adapter->hw_tasks & VNIF_LSO_V2_IPV6_SUPPORTED) {
        offload.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        offload.LsoV2.IPv6.MaxOffLoadSize  = adapter->lso_data_size;
        offload.LsoV2.IPv6.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;
        if (adapter->lso_enabled & VNIF_LSOV2_IPV6_EXT_HDRS_ENABLED) {
            offload.LsoV2.IPv6.IpExtensionHeadersSupported =
                NDIS_OFFLOAD_SUPPORTED;
        }
        offload.LsoV2.IPv6.TcpOptionsSupported = NDIS_OFFLOAD_SUPPORTED;
    }

    status_indication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    status_indication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    status_indication.Header.Size = sizeof(NDIS_STATUS_INDICATION);
    status_indication.SourceHandle = adapter->AdapterHandle;
    status_indication.StatusCode = NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG;
    status_indication.StatusBuffer = &offload;
    status_indication.StatusBufferSize = sizeof(offload);

    RPRINTK(DPRTL_CONFIG, ("VNIFIndicateOffload: %s NdisMIndicateStatusEx\n",
                           adapter->node_name));
    NdisMIndicateStatusEx(adapter->AdapterHandle, &status_indication);
    RPRINTK(DPRTL_CONFIG, ("VNIFIndicateOffload: %s out\n",
                           adapter->node_name));
}

void
VNIFOidRequestComplete(PVNIF_ADAPTER adapter)
{
    NdisMOidRequestComplete(adapter->AdapterHandle,
        adapter->NdisRequest, NDIS_STATUS_SUCCESS);
    adapter->NdisRequest = NULL;
}
#else
void
VNIFOidRequestComplete(PVNIF_ADAPTER adapter)
{
    KIRQL old_irql;

    KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
    NdisMQueryInformationComplete(adapter->AdapterHandle,
        NDIS_STATUS_SUCCESS);
    KeLowerIrql(old_irql);
}
#endif
