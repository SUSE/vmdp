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

NDIS_HANDLE MiniportDriverContext;

SET_OPTIONS MPSetOptions;
MINIPORT_PAUSE MPPause;
MINIPORT_RESTART MPRestart;

NDIS_STATUS
DriverEntry6(PVOID DriverObject, PVOID RegistryPath)
{
    NDIS_STATUS status;
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS mp_char;

    RPRINTK(DPRTL_ON, ("VNIF: DriverEntry6 - IN.\n"));
    NdisZeroMemory(&mp_char, sizeof(mp_char));

    mp_char.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
#ifdef NDIS620_MINIPORT
    mp_char.Header.Size =
        NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
    mp_char.Header.Revision =
        NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
#else
    mp_char.Header.Size =
        NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
    mp_char.Header.Revision =
        NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
#endif

    mp_char.MajorNdisVersion    = NDIS_MINIPORT_MAJOR_VERSION;
    mp_char.MinorNdisVersion    = NDIS_MINIPORT_MINOR_VERSION;
    mp_char.MajorDriverVersion  = VNIF_MAJOR_DRIVER_VERSION;
    mp_char.MinorDriverVersion  = VNIF_MINOR_DRIVER_VERSION;

    mp_char.SetOptionsHandler           = MPSetOptions;

    mp_char.InitializeHandlerEx         = MPInitialize;
    mp_char.HaltHandlerEx               = MPHalt;

    mp_char.UnloadHandler               = MPUnload;

    mp_char.PauseHandler                = MPPause;
    mp_char.RestartHandler              = MPRestart;
    mp_char.OidRequestHandler           = MPOidRequest;
    mp_char.SendNetBufferListsHandler   = MPSendNetBufferLists;
    mp_char.ReturnNetBufferListsHandler = MPReturnNetBufferLists;
    mp_char.CancelSendHandler           = MPCancelSends;
    mp_char.DevicePnPEventNotifyHandler = MPPnPEventNotify;
    mp_char.ShutdownHandlerEx           = MPShutdown;
    mp_char.CheckForHangHandlerEx       = MPCheckForHang;
    mp_char.ResetHandlerEx              = MPReset;
    mp_char.CancelOidRequestHandler     = MPCancelOidRequest;

    RPRINTK(DPRTL_INIT, ("Calling NdisMRegisterMiniportDriver...\n"));

    status = NdisMRegisterMiniportDriver(DriverObject, RegistryPath,
        (PNDIS_HANDLE)MiniportDriverContext,
        &mp_char,
        &NdisMiniportDriverHandle);
    RPRINTK(DPRTL_ON, ("VNIF: DriverEntry6 - OUT %x.\n", status));
    return status;
}

NDIS_STATUS
MPSetOptions(IN NDIS_HANDLE NdisMiniportDriverHandle,
    IN NDIS_HANDLE MiniportDriverContext)
{
    UNREFERENCED_PARAMETER(NdisMiniportDriverHandle);
    UNREFERENCED_PARAMETER(MiniportDriverContext);

    RPRINTK(DPRTL_ON, ("VNIF: MPSetOptions.\n"));
    return NDIS_STATUS_SUCCESS;
}

VOID
MPCancelSends(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;
    PQUEUE_ENTRY entry, prev_entry, next_entry;
    PNET_BUFFER_LIST nb_list;
    PNET_BUFFER_LIST cancel_head_nb_list = NULL;
    PNET_BUFFER_LIST cancel_tail_nb_list = NULL;
    PVOID nb_list_id;
    UINT i;

    RPRINTK(DPRTL_ON, ("====> MPCancelSendNetBufferLists\n"));

    for (i = 0; i < adapter->num_paths; i++) {
        prev_entry = NULL;

        NdisAcquireSpinLock(&adapter->path[i].tx_path_lock);

        /*
         * Walk through the send wait queue and complete sends
         * with matching Id
         */
        do {
            if (IsQueueEmpty(&adapter->path[i].send_wait_queue)) {
                break;
            }

            entry = GetHeadQueue(&adapter->path[i].send_wait_queue);

            while (entry != NULL) {
                nb_list = VNIF_GET_NET_BUFFER_LIST_FROM_QUEUE_LINK(entry);

                nb_list_id = NDIS_GET_NET_BUFFER_LIST_CANCEL_ID(nb_list);

                if ((nb_list_id == CancelId) &&
                        (nb_list != adapter->path[i].sending_nbl)) {
                    /* This packet has the right CancelId */
                    NET_BUFFER_LIST_STATUS(nb_list) =
                        NDIS_STATUS_REQUEST_ABORTED;
                    adapter->nWaitSend--;
                    next_entry = entry->Next;

                    if (prev_entry == NULL) {
                        adapter->path[i].send_wait_queue.Head = next_entry;
                        if (next_entry == NULL) {
                            adapter->path[i].send_wait_queue.Tail = NULL;
                        }
                    } else {
                        prev_entry->Next = next_entry;
                        if (next_entry == NULL) {
                            adapter->path[i].send_wait_queue.Tail = prev_entry;
                        }
                    }

                    entry = entry->Next;

                    /* Queue this NetBufferList for cancellation */
                    if (cancel_head_nb_list == NULL) {
                        cancel_head_nb_list = nb_list;
                        cancel_tail_nb_list = nb_list;
                    } else {
                        NET_BUFFER_LIST_NEXT_NBL(cancel_tail_nb_list) = nb_list;
                        cancel_tail_nb_list = nb_list;
                    }
                } else {
                    /* This packet doesn't have the right CancelId */
                    prev_entry = entry;
                    entry = entry->Next;
                }
            }
        } while (FALSE);

        NdisReleaseSpinLock(&adapter->path[i].tx_path_lock);

        /* Get the packets from SendCancelQueue and complete them if any */
        if (cancel_head_nb_list != NULL) {
            NET_BUFFER_LIST_NEXT_NBL(cancel_tail_nb_list) = NULL;

            NdisMSendNetBufferListsComplete(
                adapter->AdapterHandle,
                cancel_head_nb_list,
                NDIS_STATUS_SEND_ABORTED);
        }
    }

    RPRINTK(DPRTL_ON, ("<==== MPCancelSendNetBufferLists\n"));
}

NDIS_STATUS
MPPause(IN NDIS_HANDLE MiniportAdapterContext,
    IN PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;

    RPRINTK(DPRTL_ON, ("VNIF: MPPause %s %x - IN\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));

    VNIF_SET_FLAG(adapter, VNF_ADAPTER_PAUSING);

    VNIFQuiesce(adapter);

    VNIF_SET_FLAG(adapter, VNF_ADAPTER_PAUSED);
    VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_PAUSING);

    RPRINTK(DPRTL_ON, ("VNIF: MPPause %s %x - OUT\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
MPRestart(IN NDIS_HANDLE MiniportAdapterContext,
    IN PNDIS_MINIPORT_RESTART_PARAMETERS  MiniportRestartParameters)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;

    RPRINTK(DPRTL_ON, ("VNIF: MPRestart %s %x - IN\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));

    VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_PAUSED);

    if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_NEEDS_RSTART)) {
        vnif_restart_interface(adapter);
        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_NEEDS_RSTART);
    }

    RPRINTK(DPRTL_ON, ("VNIF: MPRestart %s %x - OUT\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));
    return NDIS_STATUS_SUCCESS;
}
