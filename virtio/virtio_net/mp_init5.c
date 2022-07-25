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


static void
VNIFSetOffloadDefaults(PVNIF_ADAPTER adapter)
{
    DPRINTK(DPRTL_ON, ("VNIFSetOffloadDefaults\n"));
    adapter->hw_chksum_task.V4Transmit.IpOptionsSupported = 0;
    adapter->hw_chksum_task.V4Transmit.IpChecksum = 0;
#ifdef VNIF_TX_CHECKSUM_ENABLED
    adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 1;
    adapter->hw_chksum_task.V4Transmit.TcpChecksum = 1;
    adapter->hw_chksum_task.V4Transmit.UdpChecksum = 1;
    adapter->cur_tx_tasks = VNIF_CHKSUM_IPV4_TCP | VNIF_CHKSUM_IPV4_UDP;
#else
    adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 0;
    adapter->hw_chksum_task.V4Transmit.TcpChecksum = 0;
    adapter->hw_chksum_task.V4Transmit.UdpChecksum = 0;
    adapter->cur_tx_tasks = 0;
#endif

    adapter->hw_chksum_task.V4Receive.IpOptionsSupported = 0;
    adapter->hw_chksum_task.V4Receive.IpChecksum = 0;
    adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 1;
    adapter->hw_chksum_task.V4Receive.TcpChecksum = 1;
    adapter->hw_chksum_task.V4Receive.UdpChecksum = 1;
    adapter->cur_rx_tasks = VNIF_CHKSUM_IPV4_TCP | VNIF_CHKSUM_IPV4_UDP;

    adapter->hw_chksum_task.V6Transmit.IpOptionsSupported = 0;
    adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 0;
    adapter->hw_chksum_task.V6Transmit.TcpChecksum = 0;
    adapter->hw_chksum_task.V6Transmit.UdpChecksum = 0;

    adapter->hw_chksum_task.V6Receive.IpOptionsSupported = 0;
    adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 0;
    adapter->hw_chksum_task.V6Receive.TcpChecksum = 0;
    adapter->hw_chksum_task.V6Receive.UdpChecksum = 0;
}

/* Used to override defaults as set through the NIC's properties.  The */
/* hardware now says that it only supports these latests settings. */
void
VNIFInitChksumOffload(PVNIF_ADAPTER adapter, uint32_t chksum_type,
    uint32_t chksum_value)
{
    DPRINTK(DPRTL_ON,
        ("VNIFInitChksumOffload type %x, value %x: tx %x rx %x\n",
        chksum_type, chksum_value,
        adapter->cur_tx_tasks, adapter->cur_rx_tasks));

    if (chksum_type == VNIF_CHKSUM_IPV4_TCP) {
        switch (chksum_value) {
        case VNIF_CHKSUM_ACTION_DISABLE:
            DPRINTK(DPRTL_INIT, ("Setting TCP off\n"));
            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV4_TCP;
            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV4_TCP;
            adapter->hw_chksum_task.V4Transmit.TcpChecksum = 0;
            adapter->hw_chksum_task.V4Receive.TcpChecksum = 0;

            if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_UDP)) {
                adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 0;
            }
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_UDP)) {
                adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_TX:
            DPRINTK(DPRTL_INIT, ("Setting TCP Tx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV4_TCP;
            adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Transmit.TcpChecksum = 1;

            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV4_TCP;
            adapter->hw_chksum_task.V4Receive.TcpChecksum = 0;
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_UDP)) {
                adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_RX:
            DPRINTK(DPRTL_INIT, ("Setting TCP Rx\n"));
            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV4_TCP;
            adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Receive.TcpChecksum = 1;

            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV4_TCP;
            adapter->hw_chksum_task.V4Transmit.TcpChecksum = 0;
            if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_UDP)) {
                adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_TXRX:
            DPRINTK(DPRTL_INIT, ("Setting TCP Tx Rx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV4_TCP;
            adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Transmit.TcpChecksum = 1;

            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV4_TCP;
            adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Receive.TcpChecksum = 1;
            break;
        default:
            DPRINTK(DPRTL_INIT,
                ("Unknown TCP chksum value %x\n", chksum_value));
            break;
        }
    } else if (chksum_type == VNIF_CHKSUM_IPV4_UDP) {
        switch (chksum_value) {
        case VNIF_CHKSUM_ACTION_DISABLE:
            DPRINTK(DPRTL_INIT, ("Setting UDP off\n"));
            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV4_UDP;
            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV4_UDP;
            adapter->hw_chksum_task.V4Transmit.UdpChecksum = 0;
            adapter->hw_chksum_task.V4Receive.UdpChecksum = 0;

            if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_TCP)) {
                adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 0;
            }
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_TCP)) {
                adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_TX:
            DPRINTK(DPRTL_INIT, ("Setting UDP Tx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV4_UDP;
            adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Transmit.UdpChecksum = 1;

            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV4_UDP;
            adapter->hw_chksum_task.V4Receive.UdpChecksum = 0;
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_TCP)) {
                adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_RX:
            DPRINTK(DPRTL_INIT, ("Setting UDP Rx\n"));
            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV4_UDP;
            adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Receive.UdpChecksum = 1;

            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV4_UDP;
            adapter->hw_chksum_task.V4Transmit.UdpChecksum = 0;
            if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_TCP)) {
                adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_TXRX:
            DPRINTK(DPRTL_INIT, ("Setting UDP Tx Rx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV4_UDP;
            adapter->hw_chksum_task.V4Transmit.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Transmit.UdpChecksum = 1;

            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV4_UDP;
            adapter->hw_chksum_task.V4Receive.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Receive.UdpChecksum = 1;
            break;
        default:
            DPRINTK(DPRTL_INIT,
                ("Unknown UDP chksum value %x\n", chksum_value));
            break;
        }

    } else if (chksum_type == VNIF_CHKSUM_IPV6_TCP) {
        switch (chksum_value) {
        case VNIF_CHKSUM_ACTION_DISABLE:
            DPRINTK(DPRTL_INIT, ("Setting TCP6 off\n"));
            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV6_TCP;
            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV6_TCP;
            adapter->hw_chksum_task.V6Transmit.UdpChecksum = 0;
            adapter->hw_chksum_task.V6Receive.UdpChecksum = 0;

            if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 0;
            }
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_TX:
            DPRINTK(DPRTL_INIT, ("Setting TCP6 Tx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV6_TCP;
            adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V6Transmit.UdpChecksum = 1;

            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV6_TCP;
            adapter->hw_chksum_task.V6Receive.UdpChecksum = 0;
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_RX:
            DPRINTK(DPRTL_INIT, ("Setting TCP6 Rx\n"));
            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV6_TCP;
            adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V6Receive.UdpChecksum = 1;

            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV6_TCP;
            adapter->hw_chksum_task.V6Transmit.UdpChecksum = 0;
            if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_TXRX:
            DPRINTK(DPRTL_INIT, ("Setting TCP6 Tx Rx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV6_TCP;
            adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V6Transmit.UdpChecksum = 1;

            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV6_TCP;
            adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V6Receive.UdpChecksum = 1;
            break;
        default:
            DPRINTK(DPRTL_INIT,
                ("Unknown TCP6 chksum value %x\n", chksum_value));
            break;
        }

    } else if (chksum_type == VNIF_CHKSUM_IPV6_UDP) {
        switch (chksum_value) {
        case VNIF_CHKSUM_ACTION_DISABLE:
            DPRINTK(DPRTL_INIT, ("Setting UDP6 off\n"));
            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV6_UDP;
            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV6_UDP;
            adapter->hw_chksum_task.V6Transmit.UdpChecksum = 0;
            adapter->hw_chksum_task.V6Receive.UdpChecksum = 0;

            if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 0;
            }
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_TX:
            DPRINTK(DPRTL_INIT, ("Setting UDP6 Tx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV6_UDP;
            adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V6Transmit.UdpChecksum = 1;

            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV6_UDP;
            adapter->hw_chksum_task.V6Receive.UdpChecksum = 0;
            if (!(adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_RX:
            DPRINTK(DPRTL_INIT, ("Setting UDP6 Rx\n"));
            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV6_UDP;
            adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V6Receive.UdpChecksum = 1;

            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV6_UDP;
            adapter->hw_chksum_task.V6Transmit.UdpChecksum = 0;
            if (!(adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_TCP)) {
                adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 0;
            }
            break;

        case VNIF_CHKSUM_ACTION_TXRX:
            DPRINTK(DPRTL_INIT, ("Setting UDP6 Tx Rx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV6_UDP;
            adapter->hw_chksum_task.V6Transmit.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V6Transmit.UdpChecksum = 1;

            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV6_UDP;
            adapter->hw_chksum_task.V6Receive.TcpOptionsSupported = 1;
            adapter->hw_chksum_task.V6Receive.UdpChecksum = 1;
            break;
        default:
            DPRINTK(DPRTL_INIT,
                ("Unknown UDP6 chksum value %x\n", chksum_value));
            break;
        }
    } else { /* IP */
        switch (chksum_value) {
        case VNIF_CHKSUM_ACTION_DISABLE:
            DPRINTK(DPRTL_INIT, ("Setting IP off\n"));
            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV4_IP;
            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV4_IP;
            adapter->hw_chksum_task.V4Transmit.IpChecksum = 0;
            adapter->hw_chksum_task.V4Transmit.IpOptionsSupported = 0;
            adapter->hw_chksum_task.V4Receive.IpOptionsSupported = 0;
            adapter->hw_chksum_task.V4Receive.IpChecksum = 0;
            break;

        case VNIF_CHKSUM_ACTION_TX:
            DPRINTK(DPRTL_INIT, ("Setting IP Tx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV4_IP;
            adapter->hw_chksum_task.V4Transmit.IpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Transmit.IpChecksum = 1;

            adapter->cur_rx_tasks &= ~VNIF_CHKSUM_IPV4_IP;
            adapter->hw_chksum_task.V4Receive.IpChecksum = 0;
            adapter->hw_chksum_task.V4Receive.IpOptionsSupported = 0;
            break;

        case VNIF_CHKSUM_ACTION_RX:
            DPRINTK(DPRTL_INIT, ("Setting IP Rx\n"));
            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV4_IP;
            adapter->hw_chksum_task.V4Receive.IpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Receive.IpChecksum = 1;

            adapter->cur_tx_tasks &= ~VNIF_CHKSUM_IPV4_IP;
            adapter->hw_chksum_task.V4Transmit.IpChecksum = 0;
            adapter->hw_chksum_task.V4Transmit.IpOptionsSupported = 0;
            break;

        case VNIF_CHKSUM_ACTION_TXRX:
            DPRINTK(DPRTL_INIT, ("Setting IP Tx Rx\n"));
            adapter->cur_tx_tasks |= VNIF_CHKSUM_IPV4_IP;
            adapter->hw_chksum_task.V4Transmit.IpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Transmit.IpChecksum = 1;

            adapter->cur_rx_tasks |= VNIF_CHKSUM_IPV4_IP;
            adapter->hw_chksum_task.V4Receive.IpOptionsSupported = 1;
            adapter->hw_chksum_task.V4Receive.IpChecksum = 1;
            break;
        default:
            DPRINTK(DPRTL_INIT,
                ("Unknown IP chksum value %x\n", chksum_value));
            break;
    }
    }
    DPRINTK(DPRTL_ON, ("VNIFInitChksumOffload resulting tx %x rx %x\n",
        adapter->cur_tx_tasks, adapter->cur_rx_tasks));
}

NDIS_STATUS
VNIFInitialize(PVNIF_ADAPTER adapter,
    PNDIS_MEDIUM MediumArray,
    UINT MediumArraySize,
    PUINT SelectedMediumIndex,
    NDIS_HANDLE WrapperConfigurationContext)
{
    NDIS_STATUS status;
    uint32_t i;

    DPRINTK(DPRTL_ON, ("==> VNIFInitialize\n"));
    for (i = 0; i < MediumArraySize; i++) {
        if (MediumArray[i] == VNIF_MEDIA_TYPE) {
            *SelectedMediumIndex = i;
            break;
        }
    }

    if (i == MediumArraySize) {
        return NDIS_STATUS_UNSUPPORTED_MEDIA;
    }

    /* Check for any overrides */
    adapter->WrapperContext = WrapperConfigurationContext;

    DPRINTK(DPRTL_ON, ("    NdisMSetAttributesEx\n"));
    NdisMSetAttributesEx(
        adapter->AdapterHandle,
        (NDIS_HANDLE) adapter,
        0,
        NDIS_ATTRIBUTE_DESERIALIZE
        | NDIS_ATTRIBUTE_BUS_MASTER
        | NDIS_ATTRIBUTE_USES_SAFE_BUFFER_APIS,
        VNIF_INTERFACE_TYPE);

    status = VNIFGetHWResources(adapter);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    status = VNIFFindAdapter(adapter);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    VNIFSetOffloadDefaults(adapter);
    VNIFReadRegParameters(adapter);

    status = NdisMInitializeScatterGatherDma(
        adapter->AdapterHandle,
        TRUE,
        adapter->hw_tasks & VNIF_LSO_SUPPORTED ?
            adapter->lso_data_size : adapter->max_frame_sz);
    if (status != NDIS_STATUS_SUCCESS) {
        PRINTK(("VNIF: VNIFInitialize - init scatter gather failed %x.\n",
            status));
        /* We don't need DMA so don't fail the load. */
        status = NDIS_STATUS_SUCCESS;
    }

#ifdef NDIS50_MINIPORT
    /*
     * Register a shutdown handler for NDIS50 or earlier miniports
     * For NDIS51 miniports, set AdapterShutdownHandler.
     */
    NdisMRegisterAdapterShutdownHandler(
        adapter->AdapterHandle,
        (PVOID) adapter,
        (ADAPTER_SHUTDOWN_HANDLER) MPShutdown);
#endif
    DPRINTK(DPRTL_ON, ("<== VNIFInitialize\n"));
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
VNIFSetupNdisAdapterEx(PVNIF_ADAPTER adapter)
{
    LARGE_INTEGER li;

    NdisInitializeTimer(&adapter->ResetTimer,
        VNIFResetCompleteTimerDpc, adapter);
    NdisInitializeTimer(&adapter->rcv_timer,
        VNIFReceiveTimerDpc, adapter);
    if (adapter->pv_stats) {
        NdisInitializeTimer(&adapter->pv_stats->stat_timer,
            VNIFPvStatTimerDpc, adapter);
    }
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
VNIFSetupNdisAdapterRx(PVNIF_ADAPTER adapter)
{
    PNDIS_PACKET packet;
    PNDIS_BUFFER buffer;
    RCB *rcb;
    void *ptr;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    uint32_t i;
    uint32_t p;

    DPRINTK(DPRTL_ON, ("VNIF: %s - IN\n", __func__));
    do {
        /* Pre-allocate packet pool and buffer pool for recveive. */
        NdisAllocatePacketPool(
            &status,
            &adapter->recv_pool,
            adapter->num_rcb,
            PROTOCOL_RESERVED_SIZE_IN_PACKET);
        if (status != NDIS_STATUS_SUCCESS) {
            PRINTK(("VNIF: NdisAllocatePacketPool failed\n"));
            break;
        }

        NdisAllocateBufferPool(
            &status,
            &adapter->RecvBufferPoolHandle,
            adapter->num_rcb);
        if (status != NDIS_STATUS_SUCCESS) {
            PRINTK(("VNIF: NdisAllocateBufferPool for recv buffer failed\n"));
            break;
        }

        /*
         * We have to initialize all of RCBs before receiving any data. The RCB
         * is the control block for a single packet data structure. And we
         * should pre-allocate the buffer and memory for receive. Because ring
         * buffer is not initialized at the moment, putting RCB grant reference
         * onto rx_ring.req is deferred.
         */
        for (p = 0; p < adapter->num_paths; p++) {
            VNIF_ALLOCATE_MEMORY(
                (void *)adapter->path[p].rcb_rp.rcb_array,
                sizeof(RCB *) * adapter->num_rcb,
                VNIF_POOL_TAG,
                NdisMiniportDriverHandle,
                NormalPoolPriority);
            if (adapter->path[p].rcb_rp.rcb_array == NULL) {
                status = STATUS_NO_MEMORY;
                break;
            }
            NdisZeroMemory(adapter->path[p].rcb_rp.rcb_array,
                           sizeof(RCB *) * adapter->num_rcb);

            for (i = 0; i < adapter->num_rcb; i++) {
                VNIF_ALLOCATE_MEMORY(
                    rcb,
                    sizeof(RCB),
                    VNIF_POOL_TAG,
                    NdisMiniportDriverHandle,
                    NormalPoolPriority);
                if (rcb == NULL) {
                    PRINTK(("VNIF: fail to allocate memory for RCBs.\n"));
                    status = STATUS_NO_MEMORY;
                    break;
                }
                NdisZeroMemory(rcb, sizeof(RCB));
                adapter->path[p].rcb_rp.rcb_array[i] = rcb;
                rcb->index = i;

                /*
                 * there used to be a bytes header option in xenstore for
                 * receive page but now it is hardwired to 0.
                 */

                NdisAllocatePacket(
                    &status,
                    &packet,
                    adapter->recv_pool);
                if (status != NDIS_STATUS_SUCCESS) {
                    PRINTK(("VNIF: NdisAllocatePacket failed\n"));
                    break;
                }
                NDIS_SET_PACKET_HEADER_SIZE(packet, ETH_HEADER_SIZE);
                rcb->packet = packet;
                *((RCB **)packet->MiniportReserved) = rcb;
                *((uint32_t *)&packet->MiniportReserved[sizeof(void *)]) =
                    0x44badd55;

                VNIF_ALLOCATE_SHARED_MEMORY(
                    adapter,
                    &rcb->page,
                    &rcb->page_pa,
                    adapter->rx_alloc_buffer_size,
                    NdisMiniportDriverHandle);

                if (rcb->page == NULL) {
                    PRINTK(("VNIF: fail to allocate receive pages.\n"));
                    status = STATUS_NO_MEMORY;
                    break;
                }

                NdisAllocateBuffer(
                    &status,
                    &buffer,
                    adapter->RecvBufferPoolHandle,
                    (PVOID)(rcb->page + adapter->buffer_offset),
                    adapter->rx_alloc_buffer_size);
                if (status != NDIS_STATUS_SUCCESS) {
                        PRINTK(("VNIF: NdisAllocateBuffer failed.\n"));
                    break;
                }
                rcb->buffer = buffer;
            }
        }

        if (status != NDIS_STATUS_SUCCESS) {
            break;      /* Get out of the do while. */
        }

    } while (FALSE);

    DPRINTK(DPRTL_ON, ("VNIF: %s - OUT\n", __func__));
    return status;
}

static void
vnif_free_rcb_array(PVNIF_ADAPTER adapter, rcb_ring_pool_t *rcb_pool)
{
    RCB *rcb;
    UINT i;

    if (rcb_pool->rcb_array) {
        for (i = 0; i < adapter->num_rcb; i++) {
            rcb = rcb_pool->rcb_array[i];
            if (!rcb) {
                continue;
            }

            if (rcb->packet) {
                NdisFreePacket(rcb->packet);
            }

            if (rcb->buffer) {
                NdisFreeBuffer(rcb->buffer);
            }

            if (rcb->page) {
                VNIF_FREE_SHARED_MEMORY(
                    adapter,
                    rcb->page,
                    rcb->page_pa,
                    adapter->rx_alloc_buffer_size,
                    NdisMiniportDriverHandle);
            }
            NdisFreeMemory(rcb_pool->rcb_array[i], sizeof(RCB), 0);
        }
        NdisFreeMemory(rcb_pool->rcb_array,
                       sizeof(void *) * adapter->num_rcb,
                       0);
        rcb_pool->rcb_array = NULL;
    }
}

VOID
VNIFFreeAdapterRx(PVNIF_ADAPTER adapter)
{
    RCB *rcb;
    uint32_t i;

    if (adapter->path == NULL) {
        for (i = 0; i < adapter->num_paths; i++) {
            RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterRx rcb_pool[%d]\n", i));
            vnif_free_rcb_array(adapter, &adapter->path[i].rcb_rp);
        }
    }

    if (adapter->recv_pool) {
        DPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterRx recv_pool.\n"));
        NdisFreePacketPool(adapter->recv_pool);
        adapter->recv_pool = NULL;
    }
    if (adapter->RecvBufferPoolHandle) {
        DPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterRx RecvBufferPoolHandle.\n"));
        NdisFreeBufferPool(adapter->RecvBufferPoolHandle);
        adapter->RecvBufferPoolHandle = NULL;
    }
}

VOID
VNIFFreeAdapterEx(PVNIF_ADAPTER adapter)
{
    BOOLEAN cancelled = TRUE;

    DPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterEx in\n"));
    if (adapter->ResetTimer.Timer.Dpc) {
        VNIF_CANCEL_TIMER(adapter->ResetTimer, &cancelled);
        adapter->ResetTimer.Timer.Dpc = NULL;
    }
    if (adapter->rcv_timer.Timer.Dpc) {
        VNIF_CANCEL_TIMER(adapter->rcv_timer, &cancelled);
        adapter->rcv_timer.Timer.Dpc = NULL;
    }
    if (adapter->pv_stats) {
        VNIF_CANCEL_TIMER(adapter->pv_stats->stat_timer, &cancelled);
        NdisAcquireSpinLock(&adapter->stats_lock);
        adapter->pv_stats->stat_timer.Timer.Dpc = NULL;
        NdisZeroMemory(adapter->pv_stats, sizeof(vnif_pv_stats_t));
        NdisFreeMemory(adapter->pv_stats, sizeof(vnif_pv_stats_t), 0);
        adapter->pv_stats = NULL;
        NdisReleaseSpinLock(&adapter->stats_lock);
    }
    DPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterEx out\n"));
}

NDIS_STATUS
VNIFNdisOpenConfiguration(PVNIF_ADAPTER adapter, NDIS_HANDLE *config_handle)
{
    NDIS_STATUS status;

    DPRINTK(DPRTL_ON,
        ("VNIFNdisOpenConfiguration: irql = %d IN\n", KeGetCurrentIrql()));
    NdisOpenConfiguration(&status, config_handle, adapter->WrapperContext);
    return status;
}
