/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2025 SUSE LLC
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

#ifndef _MINIPORT_H
#define _MINIPORT_H

/*
 * we are not including ndis.h here, because the WDM lower edge
 * would use of data structure as well.
 */
#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ndis.h>
#include <ntstrsafe.h>
#include <mp_packet.h>
#include <mp_rss.h>
#include <mp_poll.h>
#include <mp_nif.h>
#include <win_cmp_strtol.h>
#include <asm/win_cpuid.h>
#include <hypervisor_is.h>

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef NDIS_INDICATE_ALL_NBLS
#define NDIS_INDICATE_ALL_NBLS      (~0ul)
#endif

#define VNIF_RX_INT         0x01
#define VNIF_TX_INT         0x02
#define VNIF_CTRL_INT       0x04
#define VNIF_UNKNOWN_INT    0x08
#define VNIF_DISABLE_INT    0x80
#define VNIF_INVALID_INT    0xff
#define VNIF_VALID_INT      \
    (VNIF_RX_INT | VNIF_TX_INT | VNIF_CTRL_INT | VNIF_UNKNOWN_INT)

#define VNIF_MAX_NODE_NAME_LEN  32

#define VNIF_POOL_TAG           ((ULONG)'FINV')
#define VNIF_MEDIA_TYPE         NdisMedium802_3

#define MIN_FREE_CP_TX_SLOTS 2

#define VNIF_XEN_MAX_TX_SG_ELEMENTS 19
#define VNIF_VIRTIO_MIN_TX_SG_ELEMENTS 20
#define VNIF_VIRTIO_DEF_TX_SG_ELEMENTS 25

#define VIRTIO_QUEUE_NET_RX      0
#define VIRTIO_QUEUE_NET_TX      1
#define VIRTIO_QUEUE_NET_CONFIG  2

#define VNIF_TX_CHECKSUM_ENABLED 1

#ifdef DBG
#define VNIF_DUMP_PRINT_CNT 0
#define VNIF_SEND_PRINT_CNT 0
#endif

#if defined(NDIS51_MINIPORT)
#define VNIF_NDIS_MAJOR_VERSION 5
#define VNIF_NDIS_MINOR_VERSION 1
#elif defined(NDIS50_MINIPORT)
#define VNIF_NDIS_MAJOR_VERSION 5
#define VNIF_NDIS_MINOR_VERSION 0
#endif

#define ETH_ADDRESS_SIZE            6
# define ETH_HEADER_SIZE             14
#define ETH_MAX_DATA_SIZE           1500
#define ETH_MAX_PACKET_SIZE         (ETH_HEADER_SIZE + ETH_MAX_DATA_SIZE)
#define ETH_MIN_PACKET_SIZE         60
#define MTU_MAX_SIZE                (61440 - ETH_HEADER_SIZE) /* 64k - 4k - 14*/
#define MTU_MIN_SIZE                576
#define MAC_LAST_DIGIT              5
#define VNIF_MAX_RCV_SIZE           65536 /* 64k */

#define VIRTIO_LSO_MAX_DATA_SIZE    61440 /* 64k - 4k */
#if NDIS_SUPPORT_NDIS6
#define XEN_LSO_MAX_DATA_SIZE       61440 /* 64k - 4k */
#else
#define XEN_LSO_MAX_DATA_SIZE       31744 /* 31k */
#endif
#define LSO_MIN_DATA_SIZE           ETH_MAX_PACKET_SIZE

#define VNIF_MAX_MCAST_LIST         32
#define VNIF_MAX_SEND_PKTS          5

#define VNIF_MIN_REG_LINK_SPEED     10          /* 10 Mbps */
#define VNIF_MAX_REG_LINK_SPEED     10000       /* 10 Gbps */
#define VNIF_DEFAULT_REG_LINK_SPEED 1000        /*  1 Gbps */
#define VNIF_BASE_LINK_SPEED        1000000ull
#define VNIF_MAX_LINK_SPEED   (VNIF_BASE_LINK_SPEED * VNIF_MAX_REG_LINK_SPEED)

#define VNIF_MAX_NUM_RCBS           4096
#define VNIF_MIN_RCV_LIMIT          20

#define VNIF_RECEIVE_DISCARD        0
#define VNIF_RECEIVE_COMPLETE       1
#define VNIF_RECEIVE_LAST_FRAG      2

#define IP_HEADER_SIZE_VAL          20
#define IP_HEADER_SIZE(_buf)        (((_buf)[ETH_HEADER_SIZE] & 0xf) << 2)
#define IP_INPLACE_HEADER_VERSION(_buf) (((_buf)[0] & 0xf0) >> 4)
#define IP_INPLACE_HEADER_SIZE(_buf)    (((_buf)[0] & 0xf) << 2)
#define IP_HDR_TCP_UDP_OFFSET       9
#define IP_HDR_SRC_ADDR_OFFSET      12
#define IP_HDR_DEST_ADDR_OFFSET     16
#define IP_SRC_ADDR_OFFSET          (ETH_HEADER_SIZE + IP_HDR_SRC_ADDR_OFFSET)
#define IP_DEST_ADDR_OFFSET         (ETH_HEADER_SIZE + IP_HDR_DEST_ADDR_OFFSET)
#define TCP_DATA_OFFSET             12
#define TCP_HEADER_SIZE             20
#define VNIF_PACKET_OFFSET_ETHER_TYPE 0xc
#define VNIF_PACKET_TYPE_IP         0x8
#define VNIF_PACKET_OFFSET_TCP_UDP  0x17
#define VNIF_PACKET_TYPE_TCP        0x6
#define VNIF_PACKET_TYPE_UDP        0x11
#define VNIF_PACKET_OFFSET_TCP_CHKSUM   0x10
#define VNIF_PACKET_BYTE_OFFSET_TCP_CHKSUM  0x10
#define VNIF_PACKET_WORD_OFFSET_TCP_CHKSUM  0x8
#define VNIF_PACKET_BYTE_OFFSET_UDP_CHKSUM  0x6
#define VNIF_PACKET_WORD_OFFSET_UDP_CHKSUM  0x3
#define VNIF_TCPIP_HEADER_LEN (ETH_HEADER_SIZE                              \
                                + IP_HEADER_SIZE_VAL                        \
                                + TCP_HEADER_SIZE)

#define VNIF_CHECKSUM_OFFLOAD_INFO_BITS 0x1c
                                        /*
                                         * Bit possition of:
                                         * info->Transmit.TcpChecksum
                                         * info->Transmit.UdpChecksum
                                         * info->Transmit.IpHeaderChecksum
                                         */

#define IS_TCP_PACKET(_buf)                                                 \
    ((_buf)[VNIF_PACKET_OFFSET_TCP_UDP] == VNIF_PACKET_TYPE_TCP)
#define IS_UDP_PACKET(_buf)                                                 \
    ((_buf)[VNIF_PACKET_OFFSET_TCP_UDP] == VNIF_PACKET_TYPE_UDP)

#define VNIF_SUPPORTED_FILTERS (                    \
    NDIS_PACKET_TYPE_DIRECTED       |               \
    NDIS_PACKET_TYPE_MULTICAST      |               \
    NDIS_PACKET_TYPE_BROADCAST      |               \
    NDIS_PACKET_TYPE_PROMISCUOUS    |               \
    NDIS_PACKET_TYPE_ALL_MULTICAST)

#define VNIF_RESOURCE_BUF_SIZE                      \
    (sizeof(NDIS_RESOURCE_LIST) +                   \
    (10 * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR)))

/* Checksum actions that can be performed. */
#define VNIF_CHKSUM_ACTION_DISABLE  0x0
#define VNIF_CHKSUM_ACTION_TX       0x1
#define VNIF_CHKSUM_ACTION_RX       0x2
#define VNIF_CHKSUM_ACTION_TXRX     0x3

/* Supported hardware features. */
#define VNIF_CHKSUM_TX_SUPPORTED    0x1
#define VNIF_CHKSUM_RX_SUPPORTED    0x2
#define VNIF_CHKSUM_TXRX_SUPPORTED  0x3
#define VNIF_LSO_V1_SUPPORTED       0x4
#define VNIF_LSO_V2_SUPPORTED       0x8
#define VNIF_LSO_SUPPORTED          0xc
#define VNIF_RX_SG                  0x10
#define VNIF_RX_SG_LARGE            0x20
#define VNIF_PMC                    0x40
#define VNIF_LSO_V2_IPV6_SUPPORTED  0x80
#define VNIF_LSO_V2_IPV6_EXT_HDRS_SUPPORTED  0x100
#define VNIF_CHKSUM_TX_IPV6_SUPPORTED        0x200
#define VNIF_CHKSUM_RX_IPV6_SUPPORTED        0x400
#define VNIF_CHKSUM_TXRX_IPV6_SUPPORTED      0x600
#define VNIF_RSS_TCP_IPV6_EXT_HDRS_SUPPORTED 0x800

#define VNIF_MIN_SEGMENT_COUNT      2

#define VNIF_LSOV1_ENABLED                  0x1
#define VNIF_LSOV2_ENABLED                  0x2
#define VNIF_LSOV2_IPV6_ENABLED             0x4
#define VNIF_LSOV2_IPV6_EXT_HDRS_ENABLED    0x8

#define VNIF_CHKSUM_IPV4_TCP        0x01
#define VNIF_CHKSUM_IPV4_UDP        0x02
#define VNIF_CHKSUM_IPV4_IP         0x04
#define VNIF_CHKSUM_IPV6_TCP        0x10
#define VNIF_CHKSUM_IPV6_UDP        0x20

#define VNIF_IP_FLAGS_BYTE          0x14
#define VNIF_IP_FRAG_OFFSET_BYTE    0x15

#define VNIF_IP_FLAGS_MF_BIT        0x20
#define VNIF_IP_FLAGS_MF_OFFSET_BIT 0x01

#define SRC_ADDR_END_BYTE           11
#define P8021_TPID_BYTE             12
#define P8021_TCI_BYTE              14
#define P8021_VLAN_BYTE             15
#define P8021_BYTE_LEN              4
#define P8021_PRIORITY_SHIFT        5
#define P8021_PRIORITY_WORD_SHIFT   13
#define P8021_PRIORITY_TAG          1
#define P8021_VLAN_TAG              2
#define P8021_PRIORITY_VLAN         3
#define P8021_TPID_TYPE             0x0081
#define P8021_HOST_MASK             0xfff8
#define P8021_NETWORK_MASK          0x1f
#define P8021_MAX_VLAN_ID           0xfff
#define P8021_NET_CTRL_VLAN_ADD     0
#define P8021_NET_CTRL_VLAN_DEL     1

#define GUID_LENGTH                 38

#define VNIF_DEF_RESOURCE_TIMEOUT   0
#define VNIF_MIN_RESOURCE_TIMEOUT   0
#define VNIF_MAX_RESOURCE_TIMEOUT   3600

#define VNIF_MAX_RCV_STAT_TIMER_INTERVAL    3600 /* 60 minutes */

#define VNF_RESET_IN_PROGRESS           0x00000001
#define VNF_DISCONNECTED                0x00000002
#define VNF_ADAPTER_HALT_IN_PROGRESS    0x00000004
#define VNF_ADAPTER_SURPRISE_REMOVED    0x00000008
#define VNF_ADAPTER_RECV_LOOKASIDE      0x00000010
#define VNF_ADAPTER_SHUTDOWN            0x00000020
#define VNF_ADAPTER_NO_LINK             0x00000040
#define VNF_ADAPTER_SUSPENDING          0x00000080
#define VNF_ADAPTER_SEND_IN_PROGRESS    0x00000100
#define VNF_ADAPTER_PAUSING             0x00000200
#define VNF_ADAPTER_PAUSED              0x00000400
#define VNF_ADAPTER_SEND_SLOWDOWN       0x00000800
#define VNF_ADAPTER_RESUMING            0x00001000
#define VNF_ADAPTER_DETACHING           0x00002000
                                     /* 0x00004000 */
#define VNF_ADAPTER_SUSPENDED           0x00008000
#define VNF_ADAPTER_POLLING             0x00010000
#define VNF_ADAPTER_NEEDS_RSTART        0x00020000
#define VNF_ADAPTER_RX_DISABLED         0x00040000
#define VNF_ADAPTER_TX_DISABLED         0x00080000


#define VNIF_IS_NOT_READY_MASK                                          \
        (VNF_DISCONNECTED                                               \
        | VNF_RESET_IN_PROGRESS                                         \
        | VNF_ADAPTER_HALT_IN_PROGRESS                                  \
        | VNF_ADAPTER_SURPRISE_REMOVED                                  \
        | VNF_ADAPTER_NO_LINK                                           \
        | VNF_ADAPTER_SUSPENDING                                        \
        | VNF_ADAPTER_SUSPENDED                                         \
        | VNF_ADAPTER_RESUMING                                          \
        | VNF_ADAPTER_SHUTDOWN                                          \
        | VNF_ADAPTER_PAUSING                                           \
        | VNF_ADAPTER_DETACHING                                         \
        | VNF_ADAPTER_PAUSED)

#define VNIF_SHOULD_EXIT_DPC_MASK                                       \
        (VNF_DISCONNECTED                                               \
        | VNF_ADAPTER_PAUSED                                            \
        | VNF_ADAPTER_SUSPENDED)

#define PV_STAT_ARRAY_SZ 8

#define VNIF_SET_FLAG(_A, _F)                                           \
{                                                                       \
    NdisAcquireSpinLock(&((_A)->adapter_flag_lock));                    \
    (_A)->adapter_flags |= (_F);                                        \
    NdisReleaseSpinLock(&((_A)->adapter_flag_lock));                    \
}
#define VNIF_CLEAR_FLAG(_A, _F)                                         \
{                                                                       \
    NdisAcquireSpinLock(&((_A)->adapter_flag_lock));                    \
    (_A)->adapter_flags &= ~(_F);                                       \
    NdisReleaseSpinLock(&((_A)->adapter_flag_lock));                    \
}
#define VNIF_CLEAR_NB_FLAG(_nb, _F) (((_nb)->Flags) &= ~(_F))
#define VNIF_TEST_FLAG(_A, _F) (((_A)->adapter_flags) & (_F))

#define VNIF_IS_NOT_READY(_A) (((_A)->adapter_flags) & (VNIF_IS_NOT_READY_MASK))
#define VNIF_IS_READY(_A) (!(((_A)->adapter_flags) & (VNIF_IS_NOT_READY_MASK)))

#define VNIF_SHOULD_EXIT_TXRX_DPC(_A, _txrx, _p)                        \
    (((_A)->adapter_flags & (VNIF_SHOULD_EXIT_DPC_MASK))                \
        || ((_p) < (_A)->num_paths &&                                   \
            ((_A)->path[(_p)].path_id_flags & (_txrx))))


#define VNIF_RING_HAS_WORK(_A, _txrx, _p)                               \
    ((_txrx) == VNIF_TX_INT ?                                           \
        VNIF_RING_HAS_UNCONSUMED_RESPONSES((_A)->path[(_p)].tx) :       \
        VNIF_RING_HAS_UNCONSUMED_RESPONSES((_A)->path[(_p)].rx))

#define VNIF_INC_REF(_A) {                                              \
   NdisInterlockedIncrement(&(_A)->RefCount);                           \
}

#define VNIF_DEC_REF(_A) {                                              \
    NdisInterlockedDecrement(&(_A)->RefCount);                          \
    ASSERT(_A->RefCount >= 0);                                          \
    if ((_A)->RefCount == 0) {                                          \
        NdisSetEvent(&(_A)->RemoveEvent);                               \
    }                                                                   \
}

#define VNIF_GET_REF(_A)    ((_A)->RefCount)

#define VNIFInterlockedIncrement(_inc) NdisInterlockedIncrement(&(_inc))

#define VNIFInterlockedDecrement(_dec) {                                \
    NdisInterlockedDecrement(&(_dec));                                  \
    ASSERT((_dec) >= 0);                                                \
}

#define VNIFIncStat(_val) {                                             \
    if (adapter->pv_stats) {                                            \
        NdisAcquireSpinLock(&adapter->stats_lock);                      \
        (_val)++;                                                       \
        NdisReleaseSpinLock(&adapter->stats_lock);                      \
    }                                                                   \
}

#define VNIFIncrementStat(_val, _inc) {                                 \
    if (adapter->pv_stats) {                                            \
        NdisAcquireSpinLock(&adapter->stats_lock);                      \
        (_val) += (_inc);                      \
        NdisReleaseSpinLock(&adapter->stats_lock);                      \
    }                                                                   \
}

#define VNIFInterlockedIncrementStat(_inc) {                            \
    if (adapter->pv_stats) {                                            \
        NdisInterlockedIncrement(&(_inc));                              \
    }                                                                   \
}

#define VNIFInterlockedDecrementStat(_dec) {                            \
    if (adapter->pv_stats) {                                            \
        NdisInterlockedDecrement(&(_dec));                              \
        ASSERT((_dec) >= 0);                                            \
    }                                                                   \
}

#define VNIFStatQueryInterruptTime(_int_time) {                         \
    if (adapter->pv_stats) {                                            \
        (_int_time) = KeQueryInterruptTime();                           \
    }                                                                   \
    else {                                                              \
        (_int_time) = 0;                                                \
    }                                                                   \
}
#if NDIS_SUPPORT_NDIS620
#define VNFI_GET_PROCESSOR_COUNT                                        \
    NdisGroupActiveProcessorCount(ALL_PROCESSOR_GROUPS)
#elif NDIS_SUPPORT_NDIS6
#define VNFI_GET_PROCESSOR_COUNT NdisSystemProcessorCount()
#else
#define VNFI_GET_PROCESSOR_COUNT 1
#endif

#ifdef DBG
#define vnif_rcb_verify(_adapter, _rcb, _path_id)                       \
{                                                                       \
    if ((_rcb)->path_id != (_path_id)) {                                                                       \
        PRINTK(("%s *** vnif_get_rx rcb path_id %d != path_id\n",       \
                __func__, (_rcb)->path_id, (_path_id)));                \
    }                                                                   \
    if ((_rcb)->cnt) {                                                  \
        PRINTK(("vnif_rcb_verify: %s, %p rcb %d %d use count %d.\n",    \
            (_adapter)->node_name, (_rcb), (_rcb)->index,               \
            (_rcb)->path_id, (_rcb)->cnt));                             \
    }                                                                   \
    VNIFInterlockedIncrement((_rcb)->cnt);                              \
}

#define vnif_return_rcb_verify(_adapter, _rcb)                          \
{                                                                       \
    VNIFInterlockedDecrement((_rcb)->cnt);                              \
    if ((_rcb)->cnt) {                                                  \
        PRINTK(("vnif_return_rcb_verify: %s, %p rcb use count %d.\n",   \
            (_adapter)->node_name, (_rcb), (_rcb)->cnt));               \
        (_rcb)->cnt = 0;                                                \
    }                                                                   \
}

#else
#define vnif_rcb_verify(_adapter, _rcb, path_id)
#define vnif_return_rcb_verify(_adapter, _rcb)
#endif

#ifdef RSS_DEBUG
#define VNIF_ADD(_a, _b) (_a) += (_b)
#else
#define VNIF_ADD(_a, _b)
#endif

#ifdef VNIF_TRACK_TX
#define VNIF_TRACK_TX_SET(_dest, _src) (_dest) = (_src)
#else
#define VNIF_TRACK_TX_SET(_dest, _src)
#endif

NTSTATUS
MPDriverEntry(PVOID DriverObject, PVOID RegistryPath);

void vnif_get_runtime_ndis_ver(UCHAR *major, UCHAR *minor);

#if NDIS_SUPPORT_NDIS6

NDIS_STATUS DriverEntry6(PVOID DriverObject, PVOID RegistryPath);
#define DRIVER_ENTRY DriverEntry6

#define VNIF_INITIALIZE(_adapter, _marray, _marraysize, _midx, _wrapctx, _res) \
    VNIFInitialize((_adapter), (_res))
#define MP_HALT(_adapter, _action) MPHalt((_adapter), (_action))
#define MP_SHUTDOWN(_adapter, _action) MPShutdown((_adapter), (_action))

#define VNIF_CANCEL_TIMER(_timer, _cancelled)                           \
    NdisCancelTimerObject((_timer))

#define VNIF_SET_TIMER(_timer, _ms) {                                   \
    LARGE_INTEGER li;                                                   \
                                                                        \
    li.QuadPart = (_ms);                                                \
    li.QuadPart *= -10000;                                              \
    NdisSetTimerObject((_timer), li, 0, NULL);                          \
}

#define VNIF_ACQUIRE_SPIN_LOCK(_lock, _dispatch_level)                  \
{                                                                       \
    if ((_dispatch_level)) {                                            \
        NdisDprAcquireSpinLock((_lock));                                \
    } else {                                                            \
        NdisAcquireSpinLock((_lock));                                   \
    }                                                                   \
}

#define VNIF_RELEASE_SPIN_LOCK(_lock, _dispatch_level)                  \
{                                                                       \
    if ((_dispatch_level)) {                                            \
        NdisDprReleaseSpinLock((_lock));                                \
    } else {                                                            \
        NdisReleaseSpinLock((_lock));                                   \
    }                                                                   \
}

typedef NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO VNIF_GSO_INFO;

#define VNIF_GET_GOS_INFO(_tcb, _gso)                                   \
{                                                                       \
    if ((_tcb)->nb_list) {                                              \
        (_gso).Value = NET_BUFFER_LIST_INFO((_tcb)->nb_list,            \
            TcpLargeSendNetBufferListInfo);                             \
    } else {                                                            \
        (_gso).Value = NULL;                                            \
    }                                                                   \
}

#define VNIF_GET_GSO_MSS(_gso) (_gso).LsoV2Transmit.MSS

#define VNIF_SET_GSO_PAYLOAD(_tcb, _gso, _len)                          \
{                                                                       \
    if ((_gso).Transmit.Type == NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE) {  \
        (_gso).LsoV1TransmitComplete.TcpPayload = (_len);               \
    } else {                                                            \
        (_gso).LsoV2TransmitComplete.Reserved = 0;                      \
    }                                                                   \
    if ((_tcb)->nb_list != NULL) {                                      \
        NET_BUFFER_LIST_INFO((_tcb)->nb_list,                           \
            TcpLargeSendNetBufferListInfo) = (_gso).Value;              \
    }                                                                   \
}

#define VNIF_CLEAR_NDIS_TCB(_tcb)                                       \
{                                                                       \
    (_tcb)->nb = NULL;                                                  \
    (_tcb)->nb_list = NULL;                                             \
}


#define VNIF_TCB_RESOURCES_AVAIABLE(_M) ((_M)->nBusySend < (_M)->NumTcb)

#define VNIF_ALLOCATE_MEMORY(_va, _len, _tag, _hndl, _pri)              \
    _va = NdisAllocateMemoryWithTagPriority((_hndl), (_len), (_tag), (_pri));

typedef struct _QUEUE_ENTRY {
    struct _QUEUE_ENTRY *Next;
} QUEUE_ENTRY, *PQUEUE_ENTRY;

typedef struct _QUEUE_HEADER {
    PQUEUE_ENTRY Head;
    PQUEUE_ENTRY Tail;
} QUEUE_HEADER, *PQUEUE_HEADER;

#define InitializeQueueHeader(QueueHeader)                              \
{                                                                       \
    (QueueHeader)->Head = (QueueHeader)->Tail = NULL;                   \
}

#define IsQueueEmpty(QueueHeader) ((QueueHeader)->Head == NULL)
#define GetHeadQueue(QueueHeader) ((QueueHeader)->Head)

#define RemoveHeadQueue(QueueHeader)                                    \
    (QueueHeader)->Head;                                                \
{                                                                       \
    PQUEUE_ENTRY pNext;                                                 \
                                                                        \
    ASSERT((QueueHeader)->Head);                                        \
    pNext = (QueueHeader)->Head->Next;                                  \
    (QueueHeader)->Head = pNext;                                        \
    if (pNext == NULL) {                                                \
        (QueueHeader)->Tail = NULL;                                     \
    }                                                                   \
}

#define InsertHeadQueue(QueueHeader, QueueEntry)                        \
{                                                                       \
    ((PQUEUE_ENTRY)QueueEntry)->Next = (QueueHeader)->Head;             \
    (QueueHeader)->Head = (PQUEUE_ENTRY)(QueueEntry);                   \
    if ((QueueHeader)->Tail == NULL) {                                  \
        (QueueHeader)->Tail = (PQUEUE_ENTRY)(QueueEntry);               \
    }                                                                   \
}

#define InsertTailQueue(QueueHeader, QueueEntry)                        \
{                                                                       \
    ((PQUEUE_ENTRY)QueueEntry)->Next = NULL;                            \
    if ((QueueHeader)->Tail) {                                          \
        (QueueHeader)->Tail->Next = (PQUEUE_ENTRY)(QueueEntry);         \
    } else {                                                            \
        (QueueHeader)->Head = (PQUEUE_ENTRY)(QueueEntry);               \
    }                                                                   \
    (QueueHeader)->Tail = (PQUEUE_ENTRY)(QueueEntry);                   \
}

#define VNIF_GET_NET_BUFFER_LIST_LINK(_NetBufferList)                   \
    (&(NET_BUFFER_LIST_NEXT_NBL(_NetBufferList)))

#define VNIF_GET_NET_BUFFER_LIST_NEXT_SEND(_NetBufferList)              \
    ((_NetBufferList)->MiniportReserved[0])

#define VNIF_GET_NET_BUFFER_LIST_REF_COUNT(_NetBufferList)              \
    ((ULONG)(ULONG_PTR)((_NetBufferList)->MiniportReserved[1]))

#define VNIF_GET_NET_BUFFER_PREV(_NetBuffer)                            \
    ((_NetBuffer)->MiniportReserved[0])

#define VNIF_GET_NET_BUFFER_LIST_FROM_QUEUE_LINK(_pEntry)               \
    (CONTAINING_RECORD((_pEntry), NET_BUFFER_LIST, Next))

#define VNIF_GET_NET_BUFFER_LIST_RFD(_NetBufferList)                    \
    ((PRCB)((_NetBufferList)->MiniportReserved[0]))

#define VNIF_PUSH_PCB(_head_nbl, _nbl)                                  \
{                                                                       \
    vnif_rss_clear_nbl_info((_nbl));                                    \
    NET_BUFFER_LIST_NEXT_NBL((_nbl)) = (_head_nbl);                     \
    (_head_nbl) = (_nbl);                                               \
}

#define VNIF_POP_PCB(_head_nbl, _nbl)                                   \
{                                                                       \
    (_nbl) = (_head_nbl);                                               \
    if ((_nbl)) {                                                       \
        (_head_nbl) = NET_BUFFER_LIST_NEXT_NBL((_nbl));                 \
        NET_BUFFER_LIST_NEXT_NBL((_nbl)) = NULL;                        \
    }                                                                   \
}

#define VNIF_GET_BUS_DATA NdisMGetBusData
#else
NDIS_STATUS DriverEntry5(PVOID DriverObject, PVOID RegistryPath);
#define DRIVER_ENTRY DriverEntry5

#define VNIF_INITIALIZE(_adapter, _marray, _marraysize, _midx, _wrapctx, _res) \
    VNIFInitialize((_adapter), (_marray), (_marraysize), (_midx), (_wrapctx))
#define MP_HALT(_adapter, _action) MPHalt((_adapter))
#define MP_SHUTDOWN(_adapter, _action) MPShutdown((_adapter))
#define VNIF_CANCEL_TIMER(_timer, _cancelled)                           \
    NdisCancelTimer(&(_timer), (_cancelled))
#define VNIF_SET_TIMER(_timer, _ms)                                     \
    NdisSetTimer(&(_timer), (_ms))
#define VNIF_ALLOCATE_MEMORY(_va, _len, _tag, _hndl,  _pri)             \
    NdisAllocateMemoryWithTag(&(_va), (_len), (_tag));

#define VNIFSetScatterGatherDma(_adapter) NDIS_STATUS_SUCCESS
#define NdisMRegisterScatterGatherDma(_adapter_handle,                  \
                                      _dma_desc,                        \
                                      _dma_handle)
#define NdisMDeregisterScatterGatherDma(_dma_handle)

typedef ULONG VNIF_GSO_INFO;

#define VNIF_GET_GOS_INFO(_tcb, _gso)                                   \
{                                                                       \
    if ((_tcb)->orig_send_packet) {                                     \
        (_gso) = PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(           \
            (_tcb)->orig_send_packet,                                   \
            TcpLargeSendPacketInfo));                                   \
    }                                                                   \
    else                                                                \
    (_gso) = 0;                                                         \
}

#define VNIF_GET_GSO_MSS(_gso) (_gso)

#define VNIF_SET_GSO_PAYLOAD(_tcb, _gso, _len)                          \
{                                                                       \
        NDIS_PER_PACKET_INFO_FROM_PACKET((_tcb)->orig_send_packet,      \
            TcpLargeSendPacketInfo) = (void *)(_len);                   \
}

#define VNIF_CLEAR_NDIS_TCB(_tcb)   ((_tcb)->orig_send_packet) = NULL

#define VNIF_GET_BUS_DATA NdisReadPciSlotInformation

#endif

#if NDIS_SUPPORT_NDIS620
#define vnif_schedule_msi_dpc(a, mid, pid, qdpc)                        \
{                                                                       \
    if ((a)->path[(pid)].dpc_affinity.Mask != 0) {                      \
        NdisMQueueDpcEx((a)->u.v.interrupt_handle,                      \
                        (mid),                                          \
                        &(a)->path[(pid)].dpc_affinity,                 \
                        NULL);                                          \
        *(qdpc) = FALSE;                                                \
    } else {                                                            \
        *(qdpc) = TRUE;                                                 \
    }                                                                   \
}
#else
#define vnif_schedule_msi_dpc(a, mid, pid, qdpc) *(qdpc) = TRUE
#endif

#ifdef VNIF_TRACK_TX
typedef struct txlist_ent_s {
    grant_ref_t ref;
    uint32_t id;
    uint32_t rid;
    uint32_t state;
    uint32_t sflags;
    uint32_t eflags;
} txlist_ent_t;

typedef struct txlist_s {
    txlist_ent_t list[NET_TX_RING_SIZE];
    uint32_t cons;
    uint32_t prod;
} txlist_t;
#endif

typedef struct vnif_pv_stats_s {
#if NDIS_SUPPORT_NDIS6
    NDIS_HANDLE     stat_timer;
#else
    NDIS_TIMER      stat_timer;
#endif
    uint64_t        stat_timer_st;
    uint64_t        ints;

    uint64_t        rx_return_delay[PV_STAT_ARRAY_SZ];
    uint64_t        rx_ring_empty_delay[PV_STAT_ARRAY_SZ];
    uint64_t        rx_max_nbusy[PV_STAT_ARRAY_SZ];
    uint64_t        rx_max_passed_up[PV_STAT_ARRAY_SZ];
    uint64_t        rx_ring_empty_calc_st;
    uint64_t        rx_pkt_cnt;
    uint64_t        spkt_cnt;
    uint64_t        rpkt_cnt;
    uint64_t        tx_pkt_cnt;
    uint32_t        interval;
    int32_t         rx_to_process_cnt;
    uint32_t        rx_ring_empty_nbusy;
    uint32_t        rx_ring_empty_calc;
#ifdef DBG
    int32_t         rx_max_busy;
    uint32_t        rcb_seq;
    uint32_t        rcb_ret_seq;
    uint32_t        starting_print_mask;
#endif
#ifdef RSS_DEBUG
    uint32_t        rx_path_cnt[4];
#endif
} vnif_pv_stats_t;

#if NDIS_SUPPORT_NDIS685
typedef struct vnif_poll_context_s {
    struct _VNIF_ADAPTER    *adapter;
    NDIS_POLL_HANDLE        nph;
    UINT                    poll_path_id;
    LONG                    poll_requested;
} vnif_poll_context_t;
#endif

typedef struct _rcv_to_process_q {
    LIST_ENTRY          rcv_to_process;
    NDIS_SPIN_LOCK      rcv_to_process_lock;
    KDPC                rcv_q_dpc;
    LONG                n_busy_rcv;
    PROCESSOR_NUMBER    rcv_processor;
    UINT                path_id;
#if NDIS_SUPPORT_NDIS685
    vnif_poll_context_t rcvq_poll_context;
#endif
    BOOLEAN             rcv_q_should_request_work;
#ifdef RSS_DEBUG
    LONG                seq;
#endif
} rcv_to_process_q_t;

typedef struct vnif_path_s {
    union {
        vnif_xq_path_t  xq;
        vnif_vq_path_t  vq;
    } u;
    void                *rx;    /* Shortcut to xq/vq */
    void                *tx;    /* Shortcut to xq/vq */
    NDIS_SPIN_LOCK      rx_path_lock;
    NDIS_SPIN_LOCK      tx_path_lock;
    rcb_ring_pool_t     rcb_rp;
    LIST_ENTRY          tcb_free_list;
    struct vring_desc   *tx_desc;
#if NDIS_SUPPORT_NDIS6
    QUEUE_HEADER        send_wait_queue;
    PNET_BUFFER_LIST    sending_nbl;
#endif
    ULONG               path_id_flags;
    UINT                cpu_idx;
#if NDIS_SUPPORT_NDIS620
    GROUP_AFFINITY      dpc_affinity;
#else
    KAFFINITY           dpc_target_proc;
#endif
#if NDIS_SUPPORT_NDIS685
    vnif_poll_context_t rx_poll_context;
    vnif_poll_context_t tx_poll_context;
#endif
    UINT                rx_should_notify;
} vnif_path_t;

/***************************************************************************/
typedef struct _VNIF_ADAPTER {
    PUCHAR              node_name;
    union {
        vnif_xen_t      x;
        vnif_virtio_t   v;
    } u;

    vnif_path_t         *path;
    UINT                num_paths;
    rcv_to_process_q_t  *rcv_q;
    UINT                num_rcv_queues; /* registry */
#if NDIS_SUPPORT_NDIS620
    vnif_rss_t          rss;
#endif

    LONG                RefCount;
    NDIS_EVENT          RemoveEvent;

#if defined(NDIS_WDM)
    PDEVICE_OBJECT      Pdo;
    PDEVICE_OBJECT      Fdo;
    PDEVICE_OBJECT      NextDevice;
#endif

    NDIS_HANDLE         AdapterHandle;
    ULONG               adapter_flags;
    UCHAR               PermanentAddress[ETH_LENGTH_OF_ADDRESS];
    UCHAR               CurrentAddress[ETH_LENGTH_OF_ADDRESS];
    WCHAR               net_cfg_guid[GUID_LENGTH + 2]; /* 2 for alignment */

    ULONG               lso_data_size;
    uint32_t            lso_enabled;
    uint32_t            hw_tasks;
    uint32_t            cur_tx_tasks;
    uint32_t            cur_rx_tasks;
    uint32_t            num_rcb;
    int32_t             rcv_limit;
    uint32_t            resource_timeout;
    uint32_t            rx_alloc_buffer_size;
    uint32_t            buffer_offset;
    uint32_t            mtu;
    uint32_t            max_frame_sz;
    NDIS_DEVICE_POWER_STATE power_state;
    NDIS_HANDLE         NdisMiniportDmaHandle;
#if NDIS_SUPPORT_NDIS6
    PNDIS_OID_REQUEST   NdisRequest;
    NDIS_HANDLE         ResetTimer;
    NDIS_HANDLE         rcv_timer;
    NDIS_HANDLE         poll_timer;
    KDPC                poll_dpc;
    LONG                nWaitSend;
#else
    NDIS_HANDLE         WrapperContext;
    NDIS_TIMER          ResetTimer;
    NDIS_TIMER          rcv_timer;
    PNDIS_PACKET        packet;
    NDIS_TASK_TCP_IP_CHECKSUM hw_chksum_task;
    uint32_t            tx_throttle_start;
    uint32_t            tx_throttle_stop;
#ifdef VNIF_RCV_DELAY
    uint32_t            rcv_delay;
#endif
#endif
    void                *oid_buffer;
    NDIS_OID            oid;

    /* Variables to track resources for the send operation */
#if NDIS_SUPPORT_NDIS6 == 0
    LIST_ENTRY          SendWaitList;
#endif
    TCB                 **TCBArray;
#ifndef XENNET
    uint8_t             *vring_tx_desc_array;
    PHYSICAL_ADDRESS    vring_tx_desc_pa;
#endif
    NDIS_SPIN_LOCK      adapter_flag_lock;
    NDIS_SPIN_LOCK      adapter_lock;
    LONG                nBusySend;
    UINT                RegNumTcb;

    /* Variables to track resources for the Reset operation */
    LONG                nResetTimerCount;

    /* Variables to track resources for the Receive operation */
#if NDIS_SUPPORT_NDIS6 == 0
    NDIS_ENCAPSULATION_FORMAT EncapsulationFormat;
#endif
    LONG                nBusyRecv;
    NDIS_HANDLE         recv_pool;
    NDIS_HANDLE         RecvBufferPoolHandle;

    ULONG               priority_vlan_support;
    ULONG               vlan_id;

    /* Packet Filter and look ahead size. */
    ULONG               PacketFilter;
    ULONG               ulLookAhead;
    ULONG64             ul64LinkSpeed;
    NDIS_MEDIA_DUPLEX_STATE duplex_state;
    ULONG               ulMaxBusySends;
    ULONG               ulMaxBusyRecvs;

    /* multicast list */
    ULONG               ulMCListSize;
    UCHAR               MCList[VNIF_MAX_MCAST_LIST][ETH_LENGTH_OF_ADDRESS];

    /* Packet counts */
    ULONG64             in_no_buffers;
    ULONG64             in_discards;
    ULONG64             ifInErrors;             /* GEN_RCV_ERROR */
    ULONG64             ifOutErrors;            /* GEN_XMIT_ERROR */
    ULONG64             ifOutDiscards;          /* GEN_XMIT_DISCARDS */
#if NDIS_SUPPORT_NDIS6
    ULONG64             ifHCInUcastPkts;        /* GEN_DIRECTED_FRAMES_RCV */
    ULONG64             ifHCInMulticastPkts;    /* GEN_MULTICAST_FRAMES_RCV */
    ULONG64             ifHCInBroadcastPkts;    /* GEN_BROADCAST_FRAMES_RCV */
    ULONG64             ifHCOutUcastPkts;       /* GEN_DIRECTED_FRAMES_XMIT */
    ULONG64             ifHCOutMulticastPkts;   /* GEN_MULTICAST_FRAMES_XMIT */
    ULONG64             ifHCOutBroadcastPkts;   /* GEN_BROADCAST_FRAMES_XMIT */
    ULONG64             ifHCInUcastOctets;      /* GEN_DIRECTED_BYTES_RCV */
    ULONG64             ifHCInMulticastOctets;  /* GEN_MULTICAST_BYTES_RCV */
    ULONG64             ifHCInBroadcastOctets;  /* GEN_BROADCAST_BYTES_RCV */
    ULONG64             ifHCOutUcastOctets;     /* GEN_DIRECTED_BYTES_XMIT */
    ULONG64             ifHCOutMulticastOctets; /* GEN_MULTICAST_BYTES_XMIT */
    ULONG64             ifHCOutBroadcastOctets; /* GEN_BROADCAST_BYTES_XMIT */
#else
    ULONG64             GoodTransmits;
    ULONG64             GoodReceives;
#endif

    vnif_pv_stats_t     *pv_stats;
    NDIS_SPIN_LOCK      stats_lock;
    UINT                max_sg_el;

    uint16_t            num_hw_queues;
    BOOLEAN             b_multi_signaled;
    BOOLEAN             b_multi_queue;
    BOOLEAN             b_rss_supported;
    BOOLEAN             b_use_split_evtchn;
    BOOLEAN             b_indirect;
    BOOLEAN             b_use_packed_rings;
    BOOLEAN             b_use_ndis_poll;

    UCHAR               running_ndis_major_ver;
    UCHAR               running_ndis_minor_ver;

#ifdef DBG
    uint32_t            dbg_print_cnt;
#endif
#ifdef VNIF_TRACK_TX
    txlist_t            txlist;
#endif
#ifdef RSS_DEBUG
    ULONG                imap[9][4];
    ULONG                cimap[9][4];
    ULONG                tmap[9][4];
    ULONG                ctmap[9][4];
    ULONG                pseq[9];
    ULONG                maybe_dpc[4];
#endif
} VNIF_ADAPTER, *PVNIF_ADAPTER;

#define ETHER_TYPE_UNKNOWN 0
#define ETHER_TYPE_IPV4 0x8
#define ETHER_TYPE_IPV6 0xdd86
#define IPV4 4
#define IPV6 6

#define IP_HEADER_LENGTH(_iphdr)       (((_iphdr)->ip_verlen & 0x0F) << 2)
#define IP_HEADER_VERSION(_iphdr)      (((_iphdr)->ip_verlen & 0xF0) >> 4)

#define IPV6_EXT_HDR_HOP_BY_HOP 0
#define IPV6_EXT_HDR_DESTINATION 60
#define IPV6_EXT_HDR_ROUTING 43
#define IPV6_EXT_HDR_FRAGMENT 44
#define IPV6_EXT_HDR_AUTHENTICATION 51
#define IPV6_EXT_HDR_ENCAPSULATION_SECURITY_PAYLOAD 50
#define IPV6_EXT_HDR_MOBILITY 135
#define IPV6_EXT_HDR_HOST_IDENTITY 139
#define IPV6_EXT_HDR_SHIM6 140
#define IPV6_EXT_HDR_RESERVED1 253
#define IPV6_EXT_HDR_RESERVED2 254
#define IPV6_EXT_HDR_NO_NEXT 59
#define IPV6_EXT_HDR_FIXED_LEN 8
#define OCTET_BITS 8

typedef ULONG IPV6_ADDRESS[4];
#pragma pack(push)
#pragma pack(1)
typedef struct ipv4_header_s {
    UCHAR       ip_verlen;             /* len low nibble, version high nibble */
    UCHAR       ip_tos;                /* Type of service */
    USHORT      ip_total_length;       /* Total length */
    USHORT      ip_id;                 /* Identification */
    USHORT      ip_offset;             /* fragment offset and flags */
    UCHAR       ip_ttl;                /* Time to live */
    UCHAR       ip_protocol;           /* Protocol */
    USHORT      ip_chksum;             /* Header checksum */
    ULONG       ip_src;                /* Source IP address */
    ULONG       ip_dest;               /* Destination IP address */
} ipv4_header_t;

typedef struct ipv6_header_s {
    UCHAR       ip6_ver_tc;            /* traffic class(low), version (high) */
    UCHAR       ip6_tc_fl;             /* traffic class(high), flow label */
    USHORT      ip6_fl;                /* flow label, the rest */
    USHORT      ip6_payload_len;       /* len of following hdrs and payload */
    UCHAR       ip6_next_header;       /* next header type */
    UCHAR       ip6_hoplimit;          /* hop limit */
    IPV6_ADDRESS ip6_src_address;
    IPV6_ADDRESS ip6_dst_address;
} ipv6_header_t;

typedef struct ipv6_common_ext_header_s {
    UCHAR       ip6ext_next_header;     /* next header type */
    UCHAR       ip6ext_hdr_len;         /* length of this header in 8 bytes */
                                        /* unit, not including first 8 bytes */
} ipv6_common_ext_header_t;

typedef struct ipv6_fragment_ext_header_s {
    uint8_t       ip6ext_next_header;     /* next header type */
    uint8_t       reserved;
    uint16_t      fragment_offset;
    uint32_t      identification;
} ipv6_fragment_ext_header_t;

typedef struct tcp_hdr_s {
    USHORT      tcp_src;                /* Source port */
    USHORT      tcp_dest;               /* Destination port */
    ULONG       tcp_seq;                /* Sequence number */
    ULONG       tcp_ack;                /* Ack number */
    USHORT      tcp_flags;              /* header length and flags */
    USHORT      tcp_window;             /* Window size */
    USHORT      tcp_chksum;             /* Checksum */
    USHORT      tcp_urgent;             /* Urgent */
} tcp_hdr_t;

typedef struct ipv4_pseudo_header_s {
    ULONG       ipph_src;              /* Source address */
    ULONG       ipph_dest;             /* Destination address */
    UCHAR       ipph_zero;             /* 0 */
    UCHAR       ipph_protocol;         /* TCP/UDP */
    USHORT      ipph_length;           /* TCP/UDP length */
} ipv4_pseudo_header_t;

typedef struct ipv6_pseudo_header_s {
    IPV6_ADDRESS ipph_src;              /* Source address */
    IPV6_ADDRESS ipph_dest;             /* Destination address */
    ULONG        ipph_length;           /* TCP/UDP length */
    UCHAR        z1;                    /* 0 */
    UCHAR        z2;                    /* 0 */
    UCHAR        z3;                    /* 0 */
    UCHAR        ipph_protocol;         /* TCP/UDP */
} ipv6_pseudo_header_t;
#pragma pack(pop)

typedef struct ip_pkt_info_s {
    uint16_t *pkt_type;
    uint16_t *ip_hdr_len;
    uint8_t *protocol;
} ip_pkt_info_t;


extern ULONG g_running_hypervisor;
extern NDIS_HANDLE NdisMiniportDriverHandle;

extern void (*VNIF_ALLOCATE_SHARED_MEMORY)(struct _VNIF_ADAPTER *adapter,
    void **va, PHYSICAL_ADDRESS *pa, uint32_t len, NDIS_HANDLE hndl);

#if NDIS_SUPPORT_NDIS6
extern NDIS_OID VNIFSupportedOids[];
extern uint32_t SupportedOidListLength;

MINIPORT_INITIALIZE MPInitialize;
MINIPORT_HALT MPHalt;
MINIPORT_RESET MPReset;
MINIPORT_SHUTDOWN MPShutdown;
MINIPORT_DEVICE_PNP_EVENT_NOTIFY MPPnPEventNotify;
MINIPORT_PROCESS_SG_LIST MpProcessSGList;
MINIPORT_SEND_NET_BUFFER_LISTS MPSendNetBufferLists;
MINIPORT_RETURN_NET_BUFFER_LISTS MPReturnNetBufferLists;
MINIPORT_OID_REQUEST MPOidRequest;
MINIPORT_CANCEL_OID_REQUEST MPCancelOidRequest;

MINIPORT_CANCEL_SEND MPCancelSends;
MINIPORT_CHECK_FOR_HANG MPCheckForHang;
MINIPORT_UNLOAD MPUnload;

NDIS_STATUS
VNIFInitialize(PVNIF_ADAPTER adapter, PNDIS_RESOURCE_LIST res_list);

NDIS_STATUS
VNIFSendNetBufferList(PVNIF_ADAPTER adapter,
    PNET_BUFFER_LIST nb_list,
    UINT path_id,
    BOOLEAN bFromQueue,
    BOOLEAN dispatch_level);

void
VNIFIndicateOffload(PVNIF_ADAPTER adapter);

NDIS_TIMER_FUNCTION VNIFPollTimerDpc;
KDEFERRED_ROUTINE vnif_poll_dpc;

NDIS_STATUS
VNIFSetScatterGatherDma(PVNIF_ADAPTER adapter);

#else

VOID
MPCancelSends(IN NDIS_HANDLE MiniportAdapterContext, IN PVOID CancelId);

VOID
MPUnload(IN PDRIVER_OBJECT DriverObject);

NDIS_STATUS
MPInitialize(
    OUT PNDIS_STATUS OpenErrorStatus,
    OUT PUINT SelectedMediumIndex,
    IN PNDIS_MEDIUM MediumArray,
    IN UINT MediumArraySize,
    IN NDIS_HANDLE MiniportAdapterHandle,
    IN NDIS_HANDLE WrapperConfigurationContext
  );

VOID
MPHalt(IN  NDIS_HANDLE MiniportAdapterContext);

NDIS_STATUS
MPReset(OUT PBOOLEAN AddressingReset, IN  NDIS_HANDLE MiniportAdapterContext);

VOID
MPShutdown(IN NDIS_HANDLE MiniportAdapterContext);

#ifdef NDIS51_MINIPORT
VOID
MPPnPEventNotify(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_DEVICE_PNP_EVENT PnPEvent,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength);
#endif

NDIS_STATUS
VNIFInitialize(PVNIF_ADAPTER adapter,
    PNDIS_MEDIUM MediumArray,
    UINT MediumArraySize,
    PUINT SelectedMediumIndex,
    NDIS_HANDLE WrapperConfigurationContext);

VOID
MPAllocateComplete(
    NDIS_HANDLE MiniportAdapterContext,
    IN PVOID VirtualAddress,
    IN PNDIS_PHYSICAL_ADDRESS PhysicalAddress,
    IN ULONG Length,
    IN PVOID Context
    );

NDIS_STATUS
MPQueryInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesWritten,
    OUT PULONG BytesNeeded);

VOID
MPReturnPacket(
    IN NDIS_HANDLE  MiniportAdapterContext,
    IN PNDIS_PACKET Packet);

NDIS_STATUS
MPSetInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesRead,
    OUT PULONG BytesNeeded);

void
MPSendPackets(PVNIF_ADAPTER adapter, PPNDIS_PACKET Packets, UINT Count);

VOID
VNIFReturnRecvPacket(IN PVNIF_ADAPTER adapter, IN PNDIS_PACKET Packet);

#endif

void vnif_set_num_paths(PVNIF_ADAPTER adapter);

void vnif_init_rcb_free_list(PVNIF_ADAPTER adapter, UINT path_id);

NDIS_STATUS
vnif_setup_rxtx(PVNIF_ADAPTER adapter);

NDIS_STATUS
VNIFSetupNdisAdapter(PVNIF_ADAPTER adapter);

NDIS_STATUS
VNIFSetupNdisAdapterEx(PVNIF_ADAPTER adapter);

NDIS_STATUS
VNIFSetupNdisAdapterRx(PVNIF_ADAPTER adapter);

VOID
VNIFFreeAdapterRx(PVNIF_ADAPTER adapter);

VOID
VNIFFreeAdapter(PVNIF_ADAPTER adapter, NDIS_STATUS status);

VOID
VNIFFreeAdapterEx(PVNIF_ADAPTER adapter);

NDIS_STATUS
VNIFReadPrintMaskRegParameter(PVNIF_ADAPTER adapter);

NDIS_STATUS
VNIFReadRegParameters(PVNIF_ADAPTER adapter);

void
VNIFDumpSettings(PVNIF_ADAPTER adapter);

NDIS_STATUS
VNIFNdisOpenConfiguration(PVNIF_ADAPTER adapter, NDIS_HANDLE *config_handle);

#if NDIS_SUPPORT_NDIS620
void
VNIFSetPowerCapabilities(NDIS_PM_CAPABILITIES *pmc);
#else
void
VNIFSetPowerCapabilities(NDIS_PNP_CAPABILITIES *pmc);
#endif

void
VNIFInitChksumOffload(PVNIF_ADAPTER adapter,
    uint32_t chksum_task,
    uint32_t chksum_action);

ULONG
VNIFGetMediaConnectStatus(PVNIF_ADAPTER adapter);

NDIS_STATUS
VNIFSetMulticastList(
    IN PVNIF_ADAPTER adapter,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesRead,
    OUT PULONG BytesNeeded);

NDIS_STATUS
VNIFSetPacketFilter(IN PVNIF_ADAPTER adapter, IN ULONG PacketFilter);

NDIS_STATUS
VNIFSetVLANFilter(PVNIF_ADAPTER adapter, ULONG new_vlan_id);

void
vnif_drain_tx_path_and_send(PVNIF_ADAPTER adapter,
                            UINT path_id,
                            UINT nbls_to_complete,
                            PNET_BUFFER_LIST *complete_nb_lists,
                            PNET_BUFFER_LIST *tail_nb_list,
                            UINT *nb_list_cnt);

int
VNIFCheckSendCompletion(PVNIF_ADAPTER adapter, UINT path_id);

void
vnif_request_rcv_q_work(PVNIF_ADAPTER adapter,
                        UINT max_nbls_to_indicate,
                        BOOLEAN request_work);
void
vnif_drain_rx_path(PVNIF_ADAPTER adapter,
                   UINT path_id,
                   UINT rcv_qidx,
                   UINT *rcb_added_to_ring,
                   UINT *rp,
                   BOOLEAN *needs_dpc);

PNET_BUFFER_LIST
vnif_mv_rcbs_to_nbl(PVNIF_ADAPTER adapter,
                    UINT path_id,
                    UINT rcv_qidx,
                    UINT nbls_to_indicate,
                    PNET_BUFFER_LIST *nb_list,
                    PNET_BUFFER_LIST *tail_nb_list,
                    UINT *nb_list_cnt);

VOID
VNIFReceivePackets(IN PVNIF_ADAPTER adapter,
                   UINT path_id,
                   UINT max_nbls_to_indicate);

VOID
VNIFFreeQueuedSendPackets(PVNIF_ADAPTER adapter, NDIS_STATUS status);

VOID
VNIFFreeQueuedRecvPackets(PVNIF_ADAPTER adapter);

void
VNIFOidRequestComplete(PVNIF_ADAPTER adapter);

BOOLEAN newcalculate_rx_checksum(RCB *rcb,
                              uint8_t *pkt_buf,
                              uint32_t pkt_len,
                              uint16_t ip_ver,
                              uint16_t ip_hdr_len,
                              uint8_t protocol,
                              BOOLEAN update_chksum);
BOOLEAN calculate_rx_checksum(RCB *rcb,
                              uint8_t *pkt_buf,
                              uint32_t pkt_len,
                              UINT ip_ver,
                              uint16_t ip_hdr_len,
                              uint8_t protocol,
                              BOOLEAN update_chksum);
uint16_t calculate_pseudo_ipv4_header_checksum(void *hdr);
uint16_t calculate_pseudo_ipv6_header_checksum(void *hdr,
                                               uint16_t ip_hdr_len,
                                               uint8_t protocol);

void vnif_gos_hdr_update(TCB *tcb,
                         uint8_t *ip_hdr,
                         uint8_t *tcp_hdr,
                         uint16_t ip_hdr_len,
                         UINT nb_len);

uint16_t calculate_ip_checksum(uint8_t *pkt_buf);
void vnif_timer(void *s1, void *context, void *s2, void *s3);
NDIS_TIMER_FUNCTION VNIFResetCompleteTimerDpc;
NDIS_TIMER_FUNCTION VNIFReceiveTimerDpc;
void VNIFReceivePacketsStats(PVNIF_ADAPTER adapter, UINT path_id,
                             uint32_t ring_size);
void VNIFReceivePacketsPostStats(PVNIF_ADAPTER adapter, UINT path_id,
                                 uint32_t ring_size,
    uint32_t cnt);
void VNIFReturnRcbStats(PVNIF_ADAPTER adapter, RCB *rcb);
NDIS_TIMER_FUNCTION VNIFPvStatTimerDpc;
void vnif_dpc(PKDPC dpc, PVNIF_ADAPTER adapter, void *s1, void *s2);
void VNIFIndicateLinkStatus(PVNIF_ADAPTER adapter, uint32_t status);
BOOLEAN vnif_should_exit_txrx_dpc(PVNIF_ADAPTER adapter, ULONG txrx_ind,
                                  UINT path_id);
void vnif_txrx_interrupt_dpc(PVNIF_ADAPTER adapter, ULONG txrx_ind,
                             UINT path_id, UINT max_nbls_to_indicate);
void vnif_call_txrx_interrupt_dpc(PVNIF_ADAPTER adapter);
KDEFERRED_ROUTINE vnif_rx_path_dpc;
NDIS_STATUS vnif_setup_rx_path_dpc(PVNIF_ADAPTER adapter);
UINT vnif_collapse_rx(PVNIF_ADAPTER adapter, RCB *rcb);
uint32_t vnif_should_complete_packet(PVNIF_ADAPTER adapter, PUCHAR dest,
    UINT len);

UINT vnif_add_rcb_to_ring_from_list(struct _VNIF_ADAPTER *adapter,
                                    UINT path_id);
void vnif_return_rcb(PVNIF_ADAPTER Adapter, RCB *rcb);
void vnif_drop_rcb(PVNIF_ADAPTER adapter, RCB *rcb, int status);
void vnif_send_arp(PVNIF_ADAPTER adapter);
void vnif_complete_lost_sends(struct _VNIF_ADAPTER *adapter);
void vnif_process_sgl(VNIF_ADAPTER *adapter, void *pkt,
    SCATTER_GATHER_LIST *pFragList,
    UINT packet_len, uint16_t flags, UINT *req_idx);

#ifdef DBG
void
vnif_dump_buf(UINT level, uint8_t *buf, UINT len);
#else
#define vnif_dump_buf(level, buf, len)
#endif


static __inline NDIS_STATUS
VNIF_GET_STATUS_FROM_FLAGS(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status;

    if (VNIF_TEST_FLAG(adapter, VNF_RESET_IN_PROGRESS)) {
        status = NDIS_STATUS_RESET_IN_PROGRESS;
    } else if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_NO_LINK)) {
        status = NDIS_STATUS_NO_CABLE;
    } else if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_SURPRISE_REMOVED)) {
        status = NDIS_STATUS_NOT_ACCEPTED;
    } else {
        status = NDIS_STATUS_FAILURE;
    }
    return status;
}

void get_ipv6_hdr_len_and_protocol(ipv6_header_t *ipv6_hdr,
                                   UINT pkt_len,
                                   uint16_t *pip_hdr_len,
                                   uint8_t *pprotocol);

static __inline uint16_t
get_ip_hdr_len(uint8_t *hdr, UINT len)
{
    uint16_t hdr_len;

    if (IP_INPLACE_HEADER_VERSION(hdr) == IPV4) {
        return IP_INPLACE_HEADER_SIZE(hdr);
    }
    get_ipv6_hdr_len_and_protocol((ipv6_header_t *)hdr,
                                  len,
                                  &hdr_len,
                                  NULL);
    return hdr_len;
}

static __inline uint8_t
get_ip_hdr_protocol(uint8_t *hdr, UINT len)
{
    uint8_t protocol;

    if (IP_INPLACE_HEADER_VERSION(hdr) == IPV4) {
        return hdr[IP_HDR_TCP_UDP_OFFSET];
    }
    get_ipv6_hdr_len_and_protocol((ipv6_header_t *)hdr,
                                  len,
                                  NULL,
                                  &protocol);
    return protocol;
}

static __inline NDIS_STATUS
get_ip_pkt_info(RCB *rcb, uint32_t buf_offset, UINT pkt_total_len)
{
    NDIS_STATUS status;
    uint8_t *pkt;
    uint8_t *ip_hdr;
    ipv6_header_t *ipv6_hdr;
    UINT pkt_len;
    uint16_t ether_pkt_type;

    status = NDIS_STATUS_SUCCESS;
    pkt = rcb->page + buf_offset;
    pkt_len = rcb->len - ETH_HEADER_SIZE;
    pkt_total_len -= ETH_HEADER_SIZE;
    ether_pkt_type = *(uint16_t *)(&pkt[VNIF_PACKET_OFFSET_ETHER_TYPE]);
    rcb->pkt_info.ip_ver = IP_INPLACE_HEADER_VERSION(pkt + ETH_HEADER_SIZE);
    do {
        if (ether_pkt_type == ETHER_TYPE_IPV4 && rcb->pkt_info.ip_ver == IPV4) {
            ip_hdr = pkt + ETH_HEADER_SIZE;
            if (RtlUshortByteSwap(((ipv4_header_t *)ip_hdr)->ip_total_length)
                    > pkt_total_len) {
                status = NDIS_STATUS_BUFFER_TOO_SHORT;
                break;
            }

            rcb->pkt_info.ip_hdr_len = IP_INPLACE_HEADER_SIZE(ip_hdr);
            if (rcb->pkt_info.ip_hdr_len > pkt_len) {
                status = NDIS_STATUS_INVALID_LENGTH;
                break;
            }

            rcb->pkt_info.protocol = ip_hdr[IP_HDR_TCP_UDP_OFFSET];
        } else if (ether_pkt_type == ETHER_TYPE_IPV6
                   && rcb->pkt_info.ip_ver == IPV6) {
            ipv6_hdr = (ipv6_header_t *)(pkt + ETH_HEADER_SIZE);
            if (RtlUshortByteSwap(ipv6_hdr->ip6_payload_len) > pkt_total_len) {
                status = NDIS_STATUS_BUFFER_TOO_SHORT;
                break;
            }

            /*
             * get_ipv6_hdr_len_and_protocol does the
             * rcb->pkt_info.ip_hdr_len > pkt_len test
             */
            get_ipv6_hdr_len_and_protocol(ipv6_hdr,
                                          pkt_len,
                                          &rcb->pkt_info.ip_hdr_len,
                                          &rcb->pkt_info.protocol);
            if (rcb->pkt_info.protocol == IPV6_EXT_HDR_NO_NEXT) {
                status = NDIS_STATUS_INVALID_PACKET;
                break;
            }
        } else {
            status = NDIS_STATUS_UNSUPPORTED_MEDIA;
            break;
        }
    } while (FALSE);
    if (status != NDIS_STATUS_SUCCESS) {
        rcb->pkt_info.ip_ver = 0;
        rcb->pkt_info.ip_hdr_len = 0;
        rcb->pkt_info.protocol = 0;
    }
    return status;
}


void vnif_validate_rcb(char *func, RCB *rcb);

#endif
