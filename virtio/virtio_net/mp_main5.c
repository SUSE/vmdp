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

#ifdef NDIS51_MINIPORT
#pragma NDIS_PAGEABLE_FUNCTION(MPPnPEventNotify)
#endif

NDIS_HANDLE NdisWrapperHandle;

NDIS_STATUS
DriverEntry5(PVOID DriverObject, PVOID RegistryPath)
{
    NDIS_MINIPORT_CHARACTERISTICS mp_char;
    NDIS_STATUS status;
    UCHAR major_ver;
    UCHAR minor_ver;

    DPRINTK(DPRTL_ON, ("VNIF: DriverEntry5 - IN.\n"));

    vnif_get_runtime_ndis_ver(&major_ver, &minor_ver);

    NdisZeroMemory(&mp_char, sizeof(mp_char));

    NdisMInitializeWrapper(&NdisWrapperHandle, DriverObject,
                           RegistryPath, NULL);

    mp_char.MajorNdisVersion = major_ver;
    mp_char.MinorNdisVersion = minor_ver;

    mp_char.InitializeHandler = MPInitialize;
    mp_char.HaltHandler = MPHalt;

    mp_char.SetInformationHandler = MPSetInformation;
    mp_char.QueryInformationHandler = MPQueryInformation;

    mp_char.SendPacketsHandler = MPSendPackets;
    mp_char.ReturnPacketHandler = MPReturnPacket;

    mp_char.ResetHandler = MPReset;

    DriverEntryEx(&mp_char);

#ifdef NDIS51_MINIPORT
    mp_char.CancelSendPacketsHandler = MPCancelSends;
    mp_char.PnPEventNotifyHandler    = MPPnPEventNotify;
    mp_char.AdapterShutdownHandler   = MPShutdown;
#endif


    status = NdisMRegisterMiniport(NdisWrapperHandle, &mp_char,
        sizeof(NDIS_MINIPORT_CHARACTERISTICS));

    if (status != NDIS_STATUS_SUCCESS) {
        PRINTK(("VNIF: NdisMRegisterMiniport, status=0x%08x.\n", status));
        NdisTerminateWrapper(NdisWrapperHandle, NULL);
        return status;
    }
    NdisMRegisterUnloadHandler(NdisWrapperHandle, MPUnload);

    DPRINTK(DPRTL_ON, ("VNIF: DriverEntry5 - OUT.\n"));
    return status;
}

#ifdef NDIS51_MINIPORT
VOID
MPCancelSends(IN NDIS_HANDLE MiniportAdapterContext, IN PVOID CancelId)
{
    PNDIS_PACKET packet;
    PVOID packetId;
    PLIST_ENTRY thisEntry, nextEntry, listHead;
    SINGLE_LIST_ENTRY sendCancelList;
    PSINGLE_LIST_ENTRY entry;

    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)MiniportAdapterContext;

#define MP_GET_PACKET_MR(_p)  (PSINGLE_LIST_ENTRY)(&(_p)->MiniportReserved[0])

    DPRINTK(DPRTL_ON,
        ("VNIF: MPCancelSendPackets CancelId = %p - IN\n", CancelId));
    sendCancelList.Next = NULL;

    NdisAcquireSpinLock(&adapter->path[0].tx_path_lock);

    /* Walk through the send wait queue and complete sends with matching Id */
    listHead = &adapter->SendWaitList;

    for (thisEntry = listHead->Flink, nextEntry = thisEntry->Flink;
          thisEntry != listHead;
          thisEntry = nextEntry, nextEntry = thisEntry->Flink) {
        packet = CONTAINING_RECORD(thisEntry, NDIS_PACKET, MiniportReserved);

        packetId = NdisGetPacketCancelId(packet);
        if (packetId == CancelId) {
            RemoveEntryList(thisEntry);
            PushEntryList(&sendCancelList, MP_GET_PACKET_MR(packet));
        }
    }

    NdisReleaseSpinLock(&adapter->path[0].tx_path_lock);

    /* Get the packets from SendCancelList and complete them if any */
    entry = PopEntryList(&sendCancelList);
    while (entry) {
        packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReserved);
        NdisMSendComplete(
            adapter->AdapterHandle,
            packet,
            NDIS_STATUS_REQUEST_ABORTED);
        entry = PopEntryList(&sendCancelList);
    }
    DPRINTK(DPRTL_ON, ("VNIF: MPCancelSendPackets - OUT\n"));
}
#endif
