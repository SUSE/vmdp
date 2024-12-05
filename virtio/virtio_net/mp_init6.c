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

static NDIS_STATUS
VNIFSetRegistrationAttributes(PVNIF_ADAPTER adapter)
{
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES RegistrationAttributes;
    NDIS_STATUS status;

    NdisZeroMemory(&RegistrationAttributes,
        sizeof(NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES));

    RegistrationAttributes.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
    RegistrationAttributes.Header.Revision =
        NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
    RegistrationAttributes.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;

    RegistrationAttributes.MiniportAdapterContext = (NDIS_HANDLE)adapter;
    RegistrationAttributes.AttributeFlags =
        NDIS_MINIPORT_ATTRIBUTES_HARDWARE_DEVICE |
        NDIS_MINIPORT_ATTRIBUTES_BUS_MASTER;
#if NDIS_SUPPORT_NDIS630
    RegistrationAttributes.AttributeFlags |=
        NDIS_MINIPORT_ATTRIBUTES_NO_PAUSE_ON_SUSPEND;
#endif

    RegistrationAttributes.CheckForHangTimeInSeconds = 0;
    RegistrationAttributes.InterfaceType = VNIF_INTERFACE_TYPE;

    status = NdisMSetMiniportAttributes(adapter->AdapterHandle,
        (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&RegistrationAttributes);
    RPRINTK(DPRTL_ON, ("RegistrationAttributes status %x\n", status));
    return status;
}

#if NDIS_SUPPORT_NDIS620
void
VNIFSetPowerCapabilities(NDIS_PM_CAPABILITIES *pmc)
{
    NdisZeroMemory(pmc, sizeof(*pmc));

    pmc->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;

#if NDIS_SUPPORT_NDIS650
    /* Use REVISION_2 for Win 10 and above for now. */
    pmc->Header.Revision = NDIS_PM_CAPABILITIES_REVISION_2;
    pmc->Header.Size = NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_2;
#else
    pmc->Header.Revision = NDIS_PM_CAPABILITIES_REVISION_1;
    pmc->Header.Size = NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1;
#endif

    pmc->SupportedWoLPacketPatterns = 0;
    pmc->NumTotalWoLPatterns = 0;
    pmc->MaxWoLPatternSize = 0;
    pmc->MaxWoLPatternOffset = 0;
    pmc->MaxWoLPacketSaveBuffer = 0;

    pmc->SupportedProtocolOffloads = 0;
    pmc->NumArpOffloadIPv4Addresses = 0;
    pmc->NumNSOffloadIPv6Addresses = 0;

    pmc->MinMagicPacketWakeUp = NdisDeviceStateUnspecified;
    pmc->MinLinkChangeWakeUp = NdisDeviceStateUnspecified;
    pmc->MinPatternWakeUp = NdisDeviceStateUnspecified;
}
#else
void
VNIFSetPowerCapabilities(NDIS_PNP_CAPABILITIES *pmc)
{
    NdisZeroMemory(pmc, sizeof(*pmc));
    pmc->WakeUpCapabilities.MinMagicPacketWakeUp = NdisDeviceStateUnspecified;
    pmc->WakeUpCapabilities.MinPatternWakeUp = NdisDeviceStateUnspecified;
    pmc->WakeUpCapabilities.MinLinkChangeWakeUp  = NdisDeviceStateUnspecified;
}
#endif

static NDIS_STATUS
VNIFSetGeneralAttributes(PVNIF_ADAPTER adapter)
{
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES GeneralAttributes;
    NDIS_RECEIVE_SCALE_CAPABILITIES rss_caps;
#if NDIS_SUPPORT_NDIS620
    NDIS_PM_CAPABILITIES pmc;
#else
    NDIS_PNP_CAPABILITIES pmc;
#endif
    NDIS_STATUS status;

    NdisZeroMemory(&GeneralAttributes,
        sizeof(NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES));

    GeneralAttributes.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
#if NDIS_SUPPORT_NDIS620
    GeneralAttributes.Header.Revision =
        NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
    GeneralAttributes.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
#else
    GeneralAttributes.Header.Revision =
        NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
    GeneralAttributes.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
#endif

    GeneralAttributes.MediaType = NdisMedium802_3;

    GeneralAttributes.MaxXmitLinkSpeed = adapter->ul64LinkSpeed;
    GeneralAttributes.MaxRcvLinkSpeed = adapter->ul64LinkSpeed;
    GeneralAttributes.XmitLinkSpeed = adapter->ul64LinkSpeed;
    GeneralAttributes.RcvLinkSpeed = adapter->ul64LinkSpeed;
    GeneralAttributes.MediaConnectState = MediaConnectStateUnknown;
    GeneralAttributes.MediaDuplexState = adapter->duplex_state;
    if (adapter->hw_tasks & VNIF_RX_SG_LARGE) {
        GeneralAttributes.MtuSize = VNIF_MAX_RCV_SIZE - ETH_HEADER_SIZE;
        GeneralAttributes.LookaheadSize = VNIF_MAX_RCV_SIZE - ETH_HEADER_SIZE;
    } else {
        GeneralAttributes.MtuSize = adapter->mtu;
        GeneralAttributes.LookaheadSize = adapter->mtu;
    }

    GeneralAttributes.PowerManagementCapabilities = NULL;

#if NDIS_SUPPORT_NDIS620
    VNIFSetPowerCapabilities(&pmc);
    GeneralAttributes.Header.Revision =
        NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
    GeneralAttributes.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
    GeneralAttributes.PowerManagementCapabilitiesEx = &pmc;
#else
    VNIFSetPowerCapabilities(&pmc);
    GeneralAttributes.PowerManagementCapabilities = &pmc;
#endif

    GeneralAttributes.MacOptions = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
        NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
        NDIS_MAC_OPTION_NO_LOOPBACK;
    if (adapter->priority_vlan_support & P8021_PRIORITY_TAG) {
        GeneralAttributes.MacOptions |= NDIS_MAC_OPTION_8021P_PRIORITY;
    }
    if (adapter->priority_vlan_support & P8021_VLAN_TAG) {
        GeneralAttributes.MacOptions |= NDIS_MAC_OPTION_8021Q_VLAN;
    }

    GeneralAttributes.SupportedPacketFilters = NDIS_PACKET_TYPE_DIRECTED |
        NDIS_PACKET_TYPE_MULTICAST |
        NDIS_PACKET_TYPE_ALL_MULTICAST |
        NDIS_PACKET_TYPE_PROMISCUOUS |
        NDIS_PACKET_TYPE_ALL_LOCAL |
        NDIS_PACKET_TYPE_BROADCAST;

    GeneralAttributes.MaxMulticastListSize = VNIF_MAX_MCAST_LIST;
    GeneralAttributes.MacAddressLength = ETH_LENGTH_OF_ADDRESS;
    NdisMoveMemory(GeneralAttributes.PermanentMacAddress,
        adapter->PermanentAddress,
        ETH_LENGTH_OF_ADDRESS);

    NdisMoveMemory(GeneralAttributes.CurrentMacAddress,
        adapter->CurrentAddress,
        ETH_LENGTH_OF_ADDRESS);

#if NDIS_SUPPORT_NDIS650
    GeneralAttributes.PhysicalMediumType = NdisPhysicalMediumUnspecified;
#else
    /* Must be NdisPhysicalMedium802_3 to pass WHQL test. */
    GeneralAttributes.PhysicalMediumType = NdisPhysicalMedium802_3;
#endif

    GeneralAttributes.AccessType = NET_IF_ACCESS_BROADCAST;
    GeneralAttributes.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
    GeneralAttributes.ConnectionType = NET_IF_CONNECTION_DEDICATED;
    GeneralAttributes.IfType = IF_TYPE_ETHERNET_CSMACD;

    /* RFC 2665 TRUE if physical adapter */
    GeneralAttributes.IfConnectorPresent = TRUE;

    GeneralAttributes.SupportedStatistics =
        NDIS_STATISTICS_DIRECTED_FRAMES_RCV_SUPPORTED |
        NDIS_STATISTICS_MULTICAST_FRAMES_RCV_SUPPORTED |
        NDIS_STATISTICS_BROADCAST_FRAMES_RCV_SUPPORTED |
        NDIS_STATISTICS_BYTES_RCV_SUPPORTED |
        NDIS_STATISTICS_RCV_DISCARDS_SUPPORTED |
        NDIS_STATISTICS_RCV_ERROR_SUPPORTED |
        NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED |
        NDIS_STATISTICS_MULTICAST_FRAMES_XMIT_SUPPORTED |
        NDIS_STATISTICS_BROADCAST_FRAMES_XMIT_SUPPORTED |
        NDIS_STATISTICS_BYTES_XMIT_SUPPORTED |
        NDIS_STATISTICS_XMIT_ERROR_SUPPORTED |
        NDIS_STATISTICS_XMIT_DISCARDS_SUPPORTED |
        NDIS_STATISTICS_DIRECTED_BYTES_RCV_SUPPORTED |
        NDIS_STATISTICS_MULTICAST_BYTES_RCV_SUPPORTED |
        NDIS_STATISTICS_BROADCAST_BYTES_RCV_SUPPORTED |
        NDIS_STATISTICS_DIRECTED_BYTES_XMIT_SUPPORTED |
        NDIS_STATISTICS_MULTICAST_BYTES_XMIT_SUPPORTED |
        NDIS_STATISTICS_BROADCAST_BYTES_XMIT_SUPPORTED;

    GeneralAttributes.SupportedOidList = VNIFSupportedOids;
    GeneralAttributes.SupportedOidListLength = SupportedOidListLength;

    GeneralAttributes.RecvScaleCapabilities = vnif_rss_set_generall_attributes(
        adapter, &rss_caps);

    status = NdisMSetMiniportAttributes(adapter->AdapterHandle,
        (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&GeneralAttributes);
    RPRINTK(DPRTL_ON, ("GeneralAttributes status %x\n", status));
    return status;
}

NDIS_STATUS
VNIFSetScatterGatherDma(PVNIF_ADAPTER adapter)
{
    NDIS_SG_DMA_DESCRIPTION DmaDescription;
    NDIS_STATUS status;

    NdisZeroMemory(&DmaDescription, sizeof(DmaDescription));

    DmaDescription.Header.Type = NDIS_OBJECT_TYPE_SG_DMA_DESCRIPTION;
    DmaDescription.Header.Revision = NDIS_SG_DMA_DESCRIPTION_REVISION_1;
    DmaDescription.Header.Size = NDIS_SIZEOF_SG_DMA_DESCRIPTION_REVISION_1;
    DmaDescription.Flags = NDIS_SG_DMA_64_BIT_ADDRESS;
    DmaDescription.MaximumPhysicalMapping =
        adapter->hw_tasks & (VNIF_LSO_SUPPORTED | VNIF_LSO_V2_IPV6_SUPPORTED) ?
            max(adapter->lso_data_size, adapter->max_frame_sz) :
            adapter->max_frame_sz;

    DmaDescription.ProcessSGListHandler = MpProcessSGList;
    DmaDescription.SharedMemAllocateCompleteHandler = NULL;

    status = NdisMRegisterScatterGatherDma(
                adapter->AdapterHandle,
                &DmaDescription,
                &adapter->NdisMiniportDmaHandle);

    RPRINTK(DPRTL_ON, ("NdisMRegisterScatterGatherDma status %x\n", status));
    RPRINTK(DPRTL_ON, ("NdisMRegisterScatterGatherDma dma list size %d\n",
        DmaDescription.ScatterGatherListSize));

    if (status != NDIS_STATUS_SUCCESS) {
        /* We don't use DMA fragment when we copy the packets. */
        PRINTK(("NdisMRegisterScatterGatherDma failed %x\n", status));
        adapter->NdisMiniportDmaHandle = (NDIS_HANDLE)(-1);
    }
    return status;
}

/*
 * Used to override defaults as set through the NIC's properties.  The
 * hardware now says that it only supports these latests settings.
 */
void
VNIFInitChksumOffload(PVNIF_ADAPTER adapter, uint32_t chksum_task,
    uint32_t chksum_action)
{
    RPRINTK(DPRTL_ON, ("VNIFInitChksumOffload type %x, value %x: tx %x rx %x\n",
        chksum_task, chksum_action,
        adapter->cur_tx_tasks, adapter->cur_rx_tasks));

    switch (chksum_action) {
    case VNIF_CHKSUM_ACTION_DISABLE:
        RPRINTK(DPRTL_INIT, ("Setting TCP off\n"));
        adapter->cur_tx_tasks &= ~chksum_task;
        adapter->cur_rx_tasks &= ~chksum_task;
        break;

    case VNIF_CHKSUM_ACTION_TX:
        RPRINTK(DPRTL_INIT, ("Setting TCP Tx\n"));
        adapter->cur_tx_tasks |= chksum_task;
        adapter->cur_rx_tasks &= ~chksum_task;
        break;

    case VNIF_CHKSUM_ACTION_RX:
        RPRINTK(DPRTL_INIT, ("Setting TCP Rx\n"));
        adapter->cur_rx_tasks |= chksum_task;
        adapter->cur_tx_tasks &= ~chksum_task;
        break;

    case VNIF_CHKSUM_ACTION_TXRX:
        RPRINTK(DPRTL_INIT, ("Setting TCP Tx Rx\n"));
        adapter->cur_tx_tasks |= chksum_task;
        adapter->cur_rx_tasks |= chksum_task;
        break;
    default:
        RPRINTK(DPRTL_INIT,
            ("Unknown TCP chksum value %x\n", chksum_action));
        break;

    }
    RPRINTK(DPRTL_ON, ("VNIFInitChksumOffload resulting tx %x rx %x\n",
        adapter->cur_tx_tasks, adapter->cur_rx_tasks));
}

static NDIS_STATUS
VNIFSetOffloadAttributes(PVNIF_ADAPTER adapter)
{
    NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES offload_attrs;
    NDIS_OFFLOAD hw_offload;
    NDIS_OFFLOAD def_offload;
    NDIS_TCP_CONNECTION_OFFLOAD connection;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    NdisZeroMemory(&offload_attrs,
        sizeof(NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES));
    NdisZeroMemory(&hw_offload, sizeof(NDIS_OFFLOAD));
    NdisZeroMemory(&def_offload, sizeof(NDIS_OFFLOAD));
    NdisZeroMemory(&connection, sizeof(NDIS_TCP_CONNECTION_OFFLOAD));

    RPRINTK(DPRTL_ON, ("OFFLOAD attributes size = %x, %x\n",
        NDIS_SIZEOF_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1,
        sizeof(NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES)));

    /*
     * Not supported values are 0, so just fill in the headers and
     * those values we support.
     */
    connection.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    connection.Header.Revision = NDIS_TCP_CONNECTION_OFFLOAD_REVISION_1;
    connection.Header.Size =
        NDIS_SIZEOF_TCP_CONNECTION_OFFLOAD_REVISION_1;

    offload_attrs.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES;
    offload_attrs.Header.Revision =
        NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1;
    offload_attrs.Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1;
    offload_attrs.DefaultOffloadConfiguration = &def_offload;
    offload_attrs.HardwareOffloadCapabilities = &hw_offload;

    def_offload.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;
    hw_offload.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;

#if (NDIS_SUPPORT_NDIS630)
    def_offload.Header.Revision = NDIS_OFFLOAD_REVISION_3;
    def_offload.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_3;

    hw_offload.Header.Revision = NDIS_OFFLOAD_REVISION_3;
    hw_offload.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_3;
#if (NDIS_SUPPORT_NDIS683)
    if (adapter->running_ndis_minor_ver >= 83) {
        def_offload.Header.Revision = NDIS_OFFLOAD_REVISION_6;
        def_offload.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_6;

        hw_offload.Header.Revision = NDIS_OFFLOAD_REVISION_6;
        hw_offload.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_6;
    }
#endif
#else
    def_offload.Header.Revision = NDIS_OFFLOAD_REVISION_1;
    def_offload.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_1;

    hw_offload.Header.Revision = NDIS_OFFLOAD_REVISION_1;
    hw_offload.Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_1;
#endif

    /*
     * Normally we would set the hardware capabilities based on what the
     * backend reports.  But with checksum offloads we will report the
     * hardware capabilites based on what checksum parameters have been
     * enabled as long as the backend supports the enabled parameter.
     */

    /* Set what IPV4 checksum offloads the hardware supports. */
    if (adapter->hw_tasks & VNIF_CHKSUM_TXRX_SUPPORTED) {
        /* Set what IPv4 Tx checksum offloads have been enabled. */
        if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_IP) {
            def_offload.Checksum.IPv4Transmit.IpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;
            def_offload.Checksum.IPv4Transmit.IpChecksum =
                NDIS_OFFLOAD_SUPPORTED;
        }
        if (adapter->cur_tx_tasks
                & (VNIF_CHKSUM_IPV4_TCP | VNIF_CHKSUM_IPV4_UDP)) {
            hw_offload.Checksum.IPv4Transmit.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            hw_offload.Checksum.IPv4Transmit.TcpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;
            def_offload.Checksum.IPv4Transmit.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            def_offload.Checksum.IPv4Transmit.TcpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;

            if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_TCP) {
                hw_offload.Checksum.IPv4Transmit.TcpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
                def_offload.Checksum.IPv4Transmit.TcpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
            }
            if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV4_UDP) {
                hw_offload.Checksum.IPv4Transmit.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
                def_offload.Checksum.IPv4Transmit.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
            }
        }

        /* Set what IPv4 Rx checksum offloads have been enabled. */
        if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_IP) {
            def_offload.Checksum.IPv4Receive.IpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;
            def_offload.Checksum.IPv4Receive.IpChecksum =
                NDIS_OFFLOAD_SUPPORTED;
        }
        if (adapter->cur_rx_tasks
                & (VNIF_CHKSUM_IPV4_TCP | VNIF_CHKSUM_IPV4_UDP)) {
            hw_offload.Checksum.IPv4Receive.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            hw_offload.Checksum.IPv4Receive.TcpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;
            def_offload.Checksum.IPv4Receive.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            def_offload.Checksum.IPv4Receive.TcpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;

            if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_TCP) {
                hw_offload.Checksum.IPv4Receive.TcpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
                def_offload.Checksum.IPv4Receive.TcpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
            }
            if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV4_UDP) {
                hw_offload.Checksum.IPv4Receive.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
                def_offload.Checksum.IPv4Receive.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
            }
        }
        RPRINTK(DPRTL_INIT,
                ("HW IPv4Tx: Encap %d IpO %d TO %d Tcp %d Udp %d Ip %d\n",
                hw_offload.Checksum.IPv4Transmit.Encapsulation,
                hw_offload.Checksum.IPv4Transmit.IpOptionsSupported,
                hw_offload.Checksum.IPv4Transmit.TcpOptionsSupported,
                hw_offload.Checksum.IPv4Transmit.TcpChecksum,
                hw_offload.Checksum.IPv4Transmit.UdpChecksum,
                hw_offload.Checksum.IPv4Transmit.IpChecksum));
        RPRINTK(DPRTL_INIT,
                ("Df IPv4Tx: Encap %d IpO %d TO %d Tcp %d Udp %d Ip %d\n",
                def_offload.Checksum.IPv4Transmit.Encapsulation,
                def_offload.Checksum.IPv4Transmit.IpOptionsSupported,
                def_offload.Checksum.IPv4Transmit.TcpOptionsSupported,
                def_offload.Checksum.IPv4Transmit.TcpChecksum,
                def_offload.Checksum.IPv4Transmit.UdpChecksum,
                def_offload.Checksum.IPv4Transmit.IpChecksum));
        RPRINTK(DPRTL_INIT,
                ("HW IPv4Rx: Encap %d IpO %d TO %d Tcp %d Udp %d Ip %d\n",
                hw_offload.Checksum.IPv4Receive.Encapsulation,
                hw_offload.Checksum.IPv4Receive.IpOptionsSupported,
                hw_offload.Checksum.IPv4Receive.TcpOptionsSupported,
                hw_offload.Checksum.IPv4Receive.TcpChecksum,
                hw_offload.Checksum.IPv4Receive.UdpChecksum,
                hw_offload.Checksum.IPv4Receive.IpChecksum));
        RPRINTK(DPRTL_INIT,
                ("Df IPv4Rx: Encap %d IpO %d TO %d Tcp %d Udp %d Ip %d\n",
                def_offload.Checksum.IPv4Receive.Encapsulation,
                def_offload.Checksum.IPv4Receive.IpOptionsSupported,
                def_offload.Checksum.IPv4Receive.TcpOptionsSupported,
                def_offload.Checksum.IPv4Receive.TcpChecksum,
                def_offload.Checksum.IPv4Receive.UdpChecksum,
                def_offload.Checksum.IPv4Receive.IpChecksum));
    }

    /* Set what IPV6 checksum offloads the hardware supports. */
    if (adapter->hw_tasks & VNIF_CHKSUM_TXRX_IPV6_SUPPORTED) {
        /* Set what IPv6 Tx checksum offloads have been enabled. */
        if (adapter->cur_tx_tasks
                & (VNIF_CHKSUM_IPV6_TCP | VNIF_CHKSUM_IPV6_UDP)) {
            hw_offload.Checksum.IPv6Transmit.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            hw_offload.Checksum.IPv6Transmit.TcpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;
            def_offload.Checksum.IPv6Transmit.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            def_offload.Checksum.IPv6Transmit.TcpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;

            if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_TCP) {
                hw_offload.Checksum.IPv6Transmit.TcpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
                def_offload.Checksum.IPv6Transmit.TcpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
            }
            if (adapter->cur_tx_tasks & VNIF_CHKSUM_IPV6_UDP) {
                hw_offload.Checksum.IPv6Transmit.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
                def_offload.Checksum.IPv6Transmit.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
            }
        }

        /* Set what IPv6 Rx checksum offloads have been enabled. */
        if (adapter->cur_rx_tasks
                & (VNIF_CHKSUM_IPV6_TCP | VNIF_CHKSUM_IPV6_UDP)) {
            hw_offload.Checksum.IPv6Receive.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            hw_offload.Checksum.IPv6Receive.TcpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;
            def_offload.Checksum.IPv6Receive.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            def_offload.Checksum.IPv6Receive.TcpOptionsSupported =
                NDIS_OFFLOAD_SUPPORTED;

            if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_TCP) {
                hw_offload.Checksum.IPv6Receive.TcpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
                def_offload.Checksum.IPv6Receive.TcpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
            }
            if (adapter->cur_rx_tasks & VNIF_CHKSUM_IPV6_UDP) {
                hw_offload.Checksum.IPv6Receive.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
                def_offload.Checksum.IPv6Receive.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
            }
        }
        RPRINTK(DPRTL_INIT, ("HW IPv6Tx: Encap %d IpX %d TO %d Tcp %d Udp %d\n",
                hw_offload.Checksum.IPv6Transmit.Encapsulation,
                hw_offload.Checksum.IPv6Transmit.IpExtensionHeadersSupported,
                hw_offload.Checksum.IPv6Transmit.TcpOptionsSupported,
                hw_offload.Checksum.IPv6Transmit.TcpChecksum,
                hw_offload.Checksum.IPv6Transmit.UdpChecksum));
        RPRINTK(DPRTL_INIT, ("Df IPv6Tx: Encap %d IpX %d TO %d Tcp %d Udp %d\n",
                def_offload.Checksum.IPv6Transmit.Encapsulation,
                def_offload.Checksum.IPv6Transmit.IpExtensionHeadersSupported,
                def_offload.Checksum.IPv6Transmit.TcpOptionsSupported,
                def_offload.Checksum.IPv6Transmit.TcpChecksum,
                def_offload.Checksum.IPv6Transmit.UdpChecksum));
        RPRINTK(DPRTL_INIT, ("HW IPv6Rx: Encap %d IpX %d TO %d Tcp %d Udp %d\n",
                hw_offload.Checksum.IPv6Receive.Encapsulation,
                hw_offload.Checksum.IPv6Receive.IpExtensionHeadersSupported,
                hw_offload.Checksum.IPv6Receive.TcpOptionsSupported,
                hw_offload.Checksum.IPv6Receive.TcpChecksum,
                hw_offload.Checksum.IPv6Receive.UdpChecksum));
        RPRINTK(DPRTL_INIT, ("Df IPv6Rx: Encap %d IpX %d TO %d Tcp %d Udp %d\n",
                def_offload.Checksum.IPv6Receive.Encapsulation,
                def_offload.Checksum.IPv6Receive.IpExtensionHeadersSupported,
                def_offload.Checksum.IPv6Receive.TcpOptionsSupported,
                def_offload.Checksum.IPv6Receive.TcpChecksum,
                def_offload.Checksum.IPv6Receive.UdpChecksum));
    }

    /*
     * Unlike checksum offloads, we will set the hardware capabilities for
     * LSO offloads based on what the backend reports.
     */

    /* Set LSO offloads for hardware and what is enabled. */
    if (adapter->hw_tasks & VNIF_LSO_V1_SUPPORTED) {
        hw_offload.LsoV1.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        hw_offload.LsoV1.IPv4.MaxOffLoadSize  = adapter->lso_data_size;
        hw_offload.LsoV1.IPv4.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;
        hw_offload.LsoV1.IPv4.TcpOptions      = 1;
        hw_offload.LsoV1.IPv4.IpOptions       = 1;

        if (adapter->lso_enabled & VNIF_LSOV1_ENABLED) {
            def_offload.LsoV1.IPv4.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            def_offload.LsoV1.IPv4.MaxOffLoadSize  = adapter->lso_data_size;
            def_offload.LsoV1.IPv4.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;
            def_offload.LsoV1.IPv4.TcpOptions      = 1;
            def_offload.LsoV1.IPv4.IpOptions       = 1;
        }
    }
    if (adapter->hw_tasks & VNIF_LSO_V2_SUPPORTED) {
        hw_offload.LsoV2.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        hw_offload.LsoV2.IPv4.MaxOffLoadSize  = adapter->lso_data_size;
        hw_offload.LsoV2.IPv4.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;

        if (adapter->lso_enabled & VNIF_LSOV2_ENABLED) {
            def_offload.LsoV2.IPv4.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            def_offload.LsoV2.IPv4.MaxOffLoadSize  = adapter->lso_data_size;
            def_offload.LsoV2.IPv4.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;
        }
    }
    if (adapter->hw_tasks & VNIF_LSO_V2_IPV6_SUPPORTED) {
        hw_offload.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
        hw_offload.LsoV2.IPv6.MaxOffLoadSize  = adapter->lso_data_size;
        hw_offload.LsoV2.IPv6.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;
        if (adapter->hw_tasks & VNIF_LSO_V2_IPV6_EXT_HDRS_SUPPORTED) {
            hw_offload.LsoV2.IPv6.IpExtensionHeadersSupported =
                NDIS_OFFLOAD_SUPPORTED;
        }
        hw_offload.LsoV2.IPv6.TcpOptionsSupported = NDIS_OFFLOAD_SUPPORTED;

        if (adapter->lso_enabled & VNIF_LSOV2_IPV6_ENABLED) {
            def_offload.LsoV2.IPv6.Encapsulation =
                NDIS_ENCAPSULATION_IEEE_802_3;
            def_offload.LsoV2.IPv6.MaxOffLoadSize  = adapter->lso_data_size;
            def_offload.LsoV2.IPv6.MinSegmentCount = VNIF_MIN_SEGMENT_COUNT;
            if (adapter->lso_enabled & VNIF_LSOV2_IPV6_EXT_HDRS_ENABLED) {
                def_offload.LsoV2.IPv6.IpExtensionHeadersSupported =
                    NDIS_OFFLOAD_SUPPORTED;
            }
            def_offload.LsoV2.IPv6.TcpOptionsSupported = NDIS_OFFLOAD_SUPPORTED;
        }
    }

    status = NdisMSetMiniportAttributes(adapter->AdapterHandle,
        (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&offload_attrs);
    RPRINTK(DPRTL_ON,
        ("VNIFSetOffloadAttributes NdisMSetMiniportAttributes %x\n", status));

    return status;
}

NDIS_STATUS
VNIFInitialize(PVNIF_ADAPTER adapter, PNDIS_RESOURCE_LIST res_list)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    do {
        VNIFReadPrintMaskRegParameter(adapter);

        status = VNIFSetRegistrationAttributes(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        status = VNIFQueryHWResources(adapter, res_list);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        status = VNIFFindAdapter(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            return status;
        }

        status = VNIFRegisterNdisInterrupt(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        vnif_set_num_paths(adapter);

        /* Check for any overrides */
        VNIFReadRegParameters(adapter);

        status = VNIFSetGeneralAttributes(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        status = VNIFSetOffloadAttributes(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

    } while (FALSE);

    /* If errors, the calling function will clean up as necessary. */
    return status;
}


NDIS_STATUS
VNIFSetupNdisAdapterEx(PVNIF_ADAPTER adapter)
{
    NDIS_TIMER_CHARACTERISTICS Timer;
    NDIS_STATUS status;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupNdisAdapterEx - IN\n"));

    NdisZeroMemory(&Timer, sizeof(NDIS_TIMER_CHARACTERISTICS));
    Timer.Header.Type = NDIS_OBJECT_TYPE_TIMER_CHARACTERISTICS;
    Timer.Header.Revision = NDIS_TIMER_CHARACTERISTICS_REVISION_1;
    Timer.Header.Size = sizeof(NDIS_TIMER_CHARACTERISTICS);

    Timer.AllocationTag = VNIF_POOL_TAG;

    do {
        adapter->ResetTimer = NULL;
        adapter->rcv_timer = NULL;
#if NDIS_SUPPORT_NDIS6
        if (g_running_hypervisor == HYPERVISOR_KVM) {
            adapter->poll_timer = NULL;
            KeInitializeDpc(&adapter->poll_dpc, vnif_poll_dpc, adapter);
        }
#endif
        if (adapter->pv_stats) {
            adapter->pv_stats->stat_timer = NULL;
        }

        Timer.TimerFunction = VNIFResetCompleteTimerDpc;
        Timer.FunctionContext = adapter;
        status = NdisAllocateTimerObject(
            adapter->AdapterHandle,
            &Timer,
            &adapter->ResetTimer);
        if (status != NDIS_STATUS_SUCCESS)  {
            adapter->ResetTimer = NULL;
            break;
        }

        Timer.TimerFunction = VNIFReceiveTimerDpc;
        Timer.FunctionContext = adapter;
        status = NdisAllocateTimerObject(
            adapter->AdapterHandle,
            &Timer,
            &adapter->rcv_timer);
        if (status != NDIS_STATUS_SUCCESS) {
            adapter->rcv_timer = NULL;
            break;
        }

#if NDIS_SUPPORT_NDIS6
        if (g_running_hypervisor == HYPERVISOR_KVM) {
            Timer.TimerFunction = VNIFPollTimerDpc;
            Timer.FunctionContext = adapter;
            status = NdisAllocateTimerObject(
                adapter->AdapterHandle,
                &Timer,
                &adapter->poll_timer);
            if (status != NDIS_STATUS_SUCCESS) {
                adapter->poll_timer = NULL;
                break;
            }
        }
#endif

        if (adapter->pv_stats) {
            Timer.TimerFunction = VNIFPvStatTimerDpc;
            Timer.FunctionContext = adapter;
            status = NdisAllocateTimerObject(
                adapter->AdapterHandle,
                &Timer,
                &adapter->pv_stats->stat_timer);
            if (status != NDIS_STATUS_SUCCESS) {
                adapter->pv_stats->stat_timer = NULL;
                break;
            }
        }
    } while (FALSE);

    if (status != NDIS_STATUS_SUCCESS) {
        if (adapter->ResetTimer) {
            NdisFreeTimerObject(adapter->ResetTimer);
            adapter->ResetTimer = NULL;
        }
        if (adapter->rcv_timer) {
            NdisFreeTimerObject(adapter->rcv_timer);
            adapter->rcv_timer = NULL;
        }
#if NDIS_SUPPORT_NDIS6
        if (g_running_hypervisor == HYPERVISOR_KVM) {
            if (adapter->poll_timer) {
                NdisFreeTimerObject(adapter->poll_timer);
                adapter->poll_timer = NULL;
            }
        }
#endif
        if (adapter->pv_stats && adapter->pv_stats->stat_timer) {
            NdisFreeTimerObject(adapter->pv_stats->stat_timer);
            adapter->pv_stats->stat_timer = NULL;
        }
    }

    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupNdisAdapterEx - out %x\n", status));
    return status;
}

NDIS_STATUS
VNIFSetupNdisAdapterRx(PVNIF_ADAPTER adapter)
{
    NET_BUFFER_LIST_POOL_PARAMETERS PoolParameters;
    NET_BUFFER_POOL_PARAMETERS nb_pool_parameters;
    PNET_BUFFER_LIST nb_list;
    RCB *rcb;
    void *ptr;
    PNET_BUFFER nb;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    uint32_t i;
    uint32_t p;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupNdisAdapterRx - IN\n"));
    do {

        /* Pre-allocate packet pool and buffer pool for recveive. */
        NdisZeroMemory(&PoolParameters,
                       sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
        PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        PoolParameters.Header.Revision =
            NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        PoolParameters.Header.Size = sizeof(PoolParameters);
        PoolParameters.ProtocolId = 0;
        PoolParameters.ContextSize = 0;
        PoolParameters.fAllocateNetBuffer = FALSE;
        PoolParameters.PoolTag = VNIF_POOL_TAG;

        adapter->recv_pool = NdisAllocateNetBufferListPool(
            adapter->AdapterHandle,
            &PoolParameters);
        if (adapter->recv_pool == NULL) {
            PRINTK(("VNIF: NdisAllocateNetBufferListPool failed.\n"));
            status = NDIS_ERROR_CODE_OUT_OF_RESOURCES;
            break;
        }

        nb_pool_parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        nb_pool_parameters.Header.Revision =
            NET_BUFFER_POOL_PARAMETERS_REVISION_1;
        nb_pool_parameters.Header.Size =
            NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
        nb_pool_parameters.PoolTag = VNIF_POOL_TAG;
        nb_pool_parameters.DataSize = 0;

        adapter->RecvBufferPoolHandle = NdisAllocateNetBufferPool(
            adapter->AdapterHandle,
            &nb_pool_parameters);
        if (adapter->RecvBufferPoolHandle == NULL) {
            PRINTK(("VNIF: NdisAllocateNetBufferPool failed.\n"));
            status = NDIS_ERROR_CODE_OUT_OF_RESOURCES;
            break;
        }


        for (p = 0; p < adapter->num_paths; p++) {
            VNIF_ALLOCATE_MEMORY(
                adapter->path[p].rcb_rp.rcb_array,
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

            /*
             * We have to initialize all of RCBs before receiving any data. The
             * RCB is the control block for a single packet data structure. And
             * we * should pre-allocate the buffer and memory for receive.
             * Because ring buffer is not initialized at the moment, putting
             * RCB grant reference * onto rx_ring.req is deferred.
             */
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
                rcb->path_id = p;

                /*
                 * Setting rcb->grant_rx_ref = GRANT_INVALID_REF; was handled
                 * by the memset.
                 */

                /*
                 * there used to be a bytes header option in xenstore for
                 * receive page but now it is hardwired to 0.
                 */

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

                rcb->mdl = NdisAllocateMdl(adapter->AdapterHandle,
                    rcb->page + adapter->buffer_offset,
                    min(adapter->max_frame_sz, adapter->rx_alloc_buffer_size));

                if (rcb->mdl == NULL) {
                    PRINTK(("VNIF: NdisAllocateMdl failed.\n"));
                    status = NDIS_ERROR_CODE_OUT_OF_RESOURCES;
                    break;
                }

                rcb->mdl_start_va = rcb->mdl->StartVa;
                DPRINTK(DPRTL_MM,
                  ("rcb[%d]: p %p mdl %p sva %x %x mva %x s %d bc %x min %x\n",
                        i, rcb->page, rcb->mdl, rcb->mdl->StartVa,
                        rcb->mdl_start_va,
                        rcb->mdl->MappedSystemVa, rcb->mdl->Size,
                        rcb->mdl->ByteCount,
                        min(adapter->max_frame_sz,
                            adapter->rx_alloc_buffer_size)));

                rcb->nb = NdisAllocateNetBuffer(
                    adapter->RecvBufferPoolHandle, NULL, 0, 0);
                if (rcb->nb == NULL) {
                    PRINTK(("VNIF: NdisAllocateNetBuffer failed.\n"));
                    status = NDIS_ERROR_CODE_OUT_OF_RESOURCES;
                    break;
                }

                nb_list = NdisAllocateNetBufferList(
                    adapter->recv_pool, 0, 0);

                if (nb_list == NULL) {
                    PRINTK((
                      "VNIF: NdisAllocateNetBufferAndNetBufferList failed.\n"));
                    status = NDIS_ERROR_CODE_OUT_OF_RESOURCES;
                    break;
                }

                nb_list->SourceHandle = adapter->AdapterHandle;
                nb_list->Status = NDIS_STATUS_SUCCESS;
                VNIF_PUSH_PCB(adapter->path[p].rcb_rp.rcb_nbl, nb_list);
            }
        }

        if (status != NDIS_STATUS_SUCCESS) {
            break;      /* Get out of the do while. */
        }

        if (status != NDIS_STATUS_SUCCESS) {
            break;      /* Get out of the do while. */
        }

    } while (FALSE);

    /*
     * In the failure case, the caller of this routine will end up
     * calling NICFreeAdapter to free all the successfully allocated
     * resources.
     */

    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupNdisAdapterRx - OUT %x\n", status));
    return status;
}

static void
vnif_free_rcb_array(PVNIF_ADAPTER adapter, RCB **rcb_array)
{
    RCB *rcb;
    UINT i;

    if (rcb_array == NULL) {
        RPRINTK(DPRTL_ON, ("%s: rcb_array is NULL\n", __func__));
        return;
    }
    for (i = 0; i < adapter->num_rcb; i++) {
        rcb = rcb_array[i];
        if (rcb == NULL) {
            RPRINTK(DPRTL_ON, ("%s: rcb[%d] is NULL\n", __func__, i));
            continue;
        }

        if (rcb->mdl) {
            DPRINTK(DPRTL_RX,
                    ("frcb[%d]: p %x sva %x %x mva %x s %d bc %x min %x\n",
                    i, rcb->page, rcb->mdl->StartVa,
                    rcb->mdl_start_va,
                    rcb->mdl->MappedSystemVa, rcb->mdl->Size,
                    rcb->mdl->ByteCount,
                    min(adapter->max_frame_sz, adapter->rx_alloc_buffer_size)));
            NdisFreeMdl(rcb->mdl);
            rcb->mdl = NULL;
        } else {
            RPRINTK(DPRTL_ON, ("%s: rcb[%d]->mdl is NULL\n", __func__, i));
        }

        if (rcb->nb) {
            NdisFreeNetBuffer(rcb->nb);
            rcb->nb = NULL;
        } else {
            RPRINTK(DPRTL_ON, ("%s: rcb[%d]->nb is NULL\n", __func__, i));
        }

        if (rcb->page) {
            VNIF_FREE_SHARED_MEMORY(
                adapter,
                rcb->page,
                rcb->page_pa,
                adapter->rx_alloc_buffer_size,
                NdisMiniportDriverHandle);
            rcb->page = NULL;
        } else {
            RPRINTK(DPRTL_ON, ("%s: rcb[%d]->page is NULL\n", __func__, i));
        }
        NdisFreeMemory(rcb, sizeof(RCB), 0);
        rcb = NULL;
    }
}

VOID
VNIFFreeAdapterRx(PVNIF_ADAPTER adapter)
{
    RCB *rcb;
    PNET_BUFFER_LIST nbl;
    uint32_t i;

    if (adapter->path != NULL) {
        for (i = 0; i < adapter->num_paths; i++) {
            RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterRx rcb_pool[%d]\n", i));
            if (adapter->path[i].rcb_rp.rcb_array != NULL) {
                vnif_free_rcb_array(adapter, adapter->path[i].rcb_rp.rcb_array);
                NdisFreeMemory(adapter->path[i].rcb_rp.rcb_array,
                               sizeof(void *) * adapter->num_rcb,
                               0);
                adapter->path[i].rcb_rp.rcb_array = NULL;
            }

            RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterRx nbl rcb_rp[%d]\n", i));
            VNIF_POP_PCB(adapter->path[i].rcb_rp.rcb_nbl, nbl);
            while (nbl) {
                NdisFreeNetBufferList(nbl);
                VNIF_POP_PCB(adapter->path[i].rcb_rp.rcb_nbl, nbl);
            }
        }
    }

    if (adapter->recv_pool) {
        RPRINTK(DPRTL_ON,
            ("VNIF: VNIFFreeAdapterRx NdisFreeNetBufferListPool\n"));
        NdisFreeNetBufferListPool(adapter->recv_pool);
        adapter->recv_pool = NULL;
    }
    if (adapter->RecvBufferPoolHandle) {
        RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterRx NdisFreeNetBufferPool\n"));
        NdisFreeNetBufferPool(adapter->RecvBufferPoolHandle);
        adapter->RecvBufferPoolHandle = NULL;
    }
    RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterRx out\n"));
}

VOID
VNIFFreeAdapterEx(PVNIF_ADAPTER adapter)
{
    BOOLEAN cancelled = TRUE;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterEx in, irql %d\n",
                       KeGetCurrentIrql()));
    if (adapter->ResetTimer) {
        VNIF_CANCEL_TIMER(adapter->ResetTimer, &cancelled);
        NdisFreeTimerObject(adapter->ResetTimer);
        adapter->ResetTimer = NULL;
    }
    if (adapter->rcv_timer) {
        VNIF_CANCEL_TIMER(adapter->rcv_timer, &cancelled);
        NdisFreeTimerObject(adapter->rcv_timer);
        adapter->rcv_timer = NULL;
    }
#if NDIS_SUPPORT_NDIS6
    if (g_running_hypervisor == HYPERVISOR_KVM) {
        if (adapter->poll_timer) {
            NdisAcquireSpinLock(&adapter->adapter_flag_lock);
            adapter->adapter_flags &= ~VNF_ADAPTER_POLLING;
            NdisReleaseSpinLock(&adapter->adapter_flag_lock);

            VNIF_CANCEL_TIMER(adapter->poll_timer, &cancelled);

            NdisAcquireSpinLock(&adapter->adapter_flag_lock);
            NdisFreeTimerObject(adapter->poll_timer);
            adapter->poll_timer = NULL;
            NdisReleaseSpinLock(&adapter->adapter_flag_lock);
        }
        KeRemoveQueueDpc(&adapter->poll_dpc);
    }
#endif
    if (adapter->pv_stats) {
        VNIF_CANCEL_TIMER(adapter->pv_stats->stat_timer, &cancelled);
        NdisAcquireSpinLock(&adapter->stats_lock);
        NdisFreeTimerObject(adapter->pv_stats->stat_timer);
        adapter->pv_stats->stat_timer = NULL;
        NdisZeroMemory(adapter->pv_stats, sizeof(vnif_pv_stats_t));
        NdisFreeMemory(adapter->pv_stats, sizeof(vnif_pv_stats_t), 0);
        adapter->pv_stats = NULL;
        NdisReleaseSpinLock(&adapter->stats_lock);
    }
    RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterEx out\n"));
}

NDIS_STATUS
VNIFNdisOpenConfiguration(PVNIF_ADAPTER adapter, NDIS_HANDLE *config_handle)
{
    NDIS_CONFIGURATION_OBJECT config_obj;

    RPRINTK(DPRTL_ON,
        ("VNIFNdisOpenConfiguration: irql = %d IN\n", KeGetCurrentIrql()));
    config_obj.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    config_obj.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    config_obj.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
    config_obj.NdisHandle = adapter->AdapterHandle;
    config_obj.Flags = 0;

    return NdisOpenConfigurationEx(&config_obj, config_handle);
}
