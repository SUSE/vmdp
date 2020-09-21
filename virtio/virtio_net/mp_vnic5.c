/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2011-2015 Novell, Inc.
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

static VOID MPHandleInterrupt(IN NDIS_HANDLE MiniportAdapterContext);

static VOID MPIsr(
    OUT PBOOLEAN InterruptRecognized,
    OUT PBOOLEAN QueueMiniportHandleInterrupt,
    IN NDIS_HANDLE MiniportAdapterContext);

void
MPV_DriverEntryEx(NDIS_MINIPORT_CHARACTERISTICS *mp_char)
{
    mp_char->HandleInterruptHandler = MPHandleInterrupt;
    mp_char->ISRHandler = MPIsr;
}

NDIS_STATUS
VNIFV_GetHWResources(PVNIF_ADAPTER adapter)
{
    PNDIS_RESOURCE_LIST  res_list;
    NDIS_STATUS status = NDIS_STATUS_RESOURCES;
    UINT size;

    DPRINTK(DPRTL_ON, ("==> VNIFGetHWResources5\n"));
    size = 0;
    res_list = (PNDIS_RESOURCE_LIST)&size;
    NdisMQueryAdapterResources(&status, adapter->WrapperContext,
        res_list, &size);
    VNIF_ALLOCATE_MEMORY(
        res_list,
        size,
        VNIF_POOL_TAG,
        NdisMiniportDriverHandle,
        NormalPoolPriority);
    if (res_list) {
        DPRINTK(DPRTL_ON, ("    VNIFGetHWResources5 size %d\n", size));
        NdisMQueryAdapterResources(&status, adapter->WrapperContext,
            res_list, &size);
        if (res_list) {
            status = VNIFQueryHWResources(adapter, res_list);
        }
        NdisFreeMemory(res_list, size, 0);
    }
    DPRINTK(DPRTL_ON, ("<== VNIFGetHWResources5\n"));
    return status;
}

NDIS_STATUS
vnifv_setup_path_info_ex(VNIF_ADAPTER *adapter)
{
    return NDIS_STATUS_SUCCESS;
}

UINT
vnifv_get_num_paths(VNIF_ADAPTER *adapter)
{
    return 1;
}

NDIS_STATUS
VNIFV_RegisterNdisInterrupt(VNIF_ADAPTER *adapter)
{
    return NdisMRegisterInterrupt(
        &adapter->u.v.interrupt,
        adapter->AdapterHandle,
        adapter->u.v.interrupt_vector,
        adapter->u.v.interrupt_level,
        TRUE,
        TRUE,
        NdisInterruptLevelSensitive);
}

void
VNIFV_DeregisterHardwareResources(VNIF_ADAPTER *adapter)
{
    DPRINTK(DPRTL_ON, ("VNIFDeregisterNdisInterrupt\n"));
    if (adapter->u.v.interrupt.InterruptObject) {
        DPRINTK(DPRTL_ON,
            ("VNIFDeregisterNdisInterrupt: NdisMDeregisterInterrupt\n"));
        NdisMDeregisterInterrupt(&adapter->u.v.interrupt);
        adapter->u.v.interrupt.InterruptObject = NULL;
    }
}

VOID
MPHandleInterrupt(IN NDIS_HANDLE MiniportAdapterContext)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)MiniportAdapterContext;
    LONG int_status;

    int_status = InterlockedExchange(&adapter->path[0].u.vq.interrupt_status,
                                     0);
    if (int_status & VIRTIO_NET_DEV_INT_CTRL) {
        vnif_report_link_status(adapter);
    }
    vnif_txrx_interrupt_dpc(adapter,
                            VNF_ADAPTER_TX_DPC_IN_PROGRESS,
                            0,
                            NDIS_INDICATE_ALL_NBLS);
    vnif_txrx_interrupt_dpc(adapter,
                            VNF_ADAPTER_RX_DPC_IN_PROGRESS,
                            0,
                            NDIS_INDICATE_ALL_NBLS);
    vring_enable_interrupt(adapter->path[0].rx);
    vring_enable_interrupt(adapter->path[0].tx);
}

VOID
MPIsr(
    OUT PBOOLEAN InterruptRecognized,
    OUT PBOOLEAN QueueMiniportHandleInterrupt,
    IN NDIS_HANDLE MiniportAdapterContext)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)MiniportAdapterContext;
    ULONG status;

    DPRINTK(DPRTL_INT, ("MPIsr in %d.\n", KeGetCurrentProcessorNumber()));
    status = virtio_device_read_isr_status(&adapter->u.v.vdev);
    if (status) {
        DPRINTK(DPRTL_INT,
            ("%s: claiming the interrupt %x\n", __func__, status));
        InterlockedOr(&adapter->path[0].u.vq.interrupt_status, (LONG)status);
        *InterruptRecognized = TRUE;
        *QueueMiniportHandleInterrupt = TRUE;
        vring_disable_interrupt(adapter->path[0].rx);
        vring_disable_interrupt(adapter->path[0].tx);
    } else {
        DPRINTK(DPRTL_INT, ("%s: interrupt not ours %x", __func__, status));
        *InterruptRecognized = FALSE;
        *QueueMiniportHandleInterrupt = FALSE;
    }
    DPRINTK(DPRTL_INT, ("MPIsr out %d.\n", KeGetCurrentProcessorNumber()));
}
