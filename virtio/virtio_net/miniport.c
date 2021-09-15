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

#include "miniport.h"

NDIS_HANDLE NdisMiniportDriverHandle;
static KEVENT vnif_init_event;

#ifdef DBG
PVNIF_ADAPTER gmyadapter;
#endif

void (*VNIF_ALLOCATE_SHARED_MEMORY)(VNIF_ADAPTER *adapter, void **va,
    PHYSICAL_ADDRESS *pa, uint32_t len, NDIS_HANDLE hndl);

NTSTATUS
MPDriverEntry(PVOID DriverObject, PVOID RegistryPath)
{
    NDIS_STATUS status;

    status = DRIVER_ENTRY(DriverObject, RegistryPath);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    KeInitializeEvent(&vnif_init_event, SynchronizationEvent, TRUE);

    DPRINTK(DPRTL_ON, ("VNIF: DriverEntry - OUT %x.\n", status));
    return status;
}

#if NDIS_SUPPORT_NDIS6
NDIS_STATUS
MPInitialize(
    IN NDIS_HANDLE MiniportAdapterHandle,
    IN NDIS_HANDLE MiniportDriverContext,
    IN PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
#else
NDIS_STATUS
MPInitialize(
    OUT PNDIS_STATUS OpenErrorStatus,
    OUT PUINT SelectedMediumIndex,
    IN PNDIS_MEDIUM MediumArray,
    IN UINT MediumArraySize,
    IN NDIS_HANDLE MiniportAdapterHandle,
    IN NDIS_HANDLE WrapperConfigurationContext)
#endif
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_STATUS dmastatus = NDIS_STATUS_FAILURE;
    PVNIF_ADAPTER adapter;

    RPRINTK(DPRTL_ON, ("VNIF: MPInitialize.\n"));

    KeWaitForSingleObject(
        &vnif_init_event,
        Executive,
        KernelMode,
        FALSE,
        NULL);

    do {

        VNIF_ALLOCATE_MEMORY(
            adapter,
            sizeof(VNIF_ADAPTER),
            VNIF_POOL_TAG,
            NdisMiniportDriverHandle,
            NormalPoolPriority);
        if (adapter == NULL) {
            PRINTK(("VNIF: fail to allocate memory for adapter context\n"));
            status = STATUS_NO_MEMORY;
            break;
        }

        DPRINTK(DPRTL_ON, ("VNIF: MPInitialize - adapter = %p.\n", adapter));
#ifdef DBG
        gmyadapter = adapter;
#endif
        NdisZeroMemory(adapter, sizeof(VNIF_ADAPTER));
        vnif_get_runtime_ndis_ver(&adapter->running_ndis_major_ver,
                                  &adapter->running_ndis_minor_ver);
        adapter->adapter_flags |= VNF_DISCONNECTED;
        adapter->AdapterHandle = MiniportAdapterHandle;
        adapter->buffer_offset = 0;
        adapter->NdisMiniportDmaHandle = (NDIS_HANDLE)(-1);

        NdisMGetDeviceProperty(adapter->AdapterHandle,
            &adapter->Pdo,
            &adapter->Fdo,
            &adapter->NextDevice,
            NULL,
            NULL);
        DPRINTK(DPRTL_ON, ("VNIF: MPInitialize - adapter pdo = %p, fdo %p.\n",
            adapter->Pdo, adapter->Fdo));

        status = VNIF_INITIALIZE(adapter,
            MediumArray,
            MediumArraySize,
            SelectedMediumIndex,
            WrapperConfigurationContext,
            MiniportInitParameters->AllocatedResources);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        dmastatus = VNIFSetScatterGatherDma(adapter);
        if (dmastatus != NDIS_STATUS_SUCCESS) {
            status = dmastatus;
            break;
        }

        /* Do all the Ndis and basic setup. */
        status = VNIFSetupNdisAdapter(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        /* Do all the virtualization interface specific setup. */
        status = VNIFSetupAdapterInterface(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        adapter->power_state = NdisDeviceStateD0;

        VNIF_INC_REF(adapter);
        KeSetEvent(&vnif_init_event, 0, FALSE);

        VNIFDumpSettings(adapter);

    } while (FALSE);

    if (status != NDIS_STATUS_SUCCESS) {
        if (dmastatus == NDIS_STATUS_SUCCESS) {
            NdisMDeregisterScatterGatherDma(adapter->NdisMiniportDmaHandle);
            adapter->NdisMiniportDmaHandle = (NDIS_HANDLE)(-1);
        }
        VNIFFreeAdapter(adapter, status);
        KeSetEvent(&vnif_init_event, 0, FALSE);
        PRINTK(("MPInitialize failed = %x.\n", status));
        NdisWriteErrorLogEntry(MiniportAdapterHandle,
            NDIS_ERROR_CODE_OUT_OF_RESOURCES, 0);
    }
    RPRINTK(DPRTL_ON, ("VNIF: MPInitialize %x.\n", status));
    return status;
}

#if NDIS_SUPPORT_NDIS6
VOID
MPHalt(IN NDIS_HANDLE MiniportAdapterContext, IN NDIS_HALT_ACTION HaltAction)
#else
VOID
MPHalt(IN NDIS_HANDLE MiniportAdapterContext)
#endif
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;

    RPRINTK(DPRTL_ON, ("VNIF: Miniport Halt irql %d for %s %x.\n",
        KeGetCurrentIrql(),
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));

    VNIF_SET_FLAG(adapter, VNF_ADAPTER_HALT_IN_PROGRESS);

    VNIFQuiesce(adapter);

    /* Free the packets on SendWaitList */
    RPRINTK(DPRTL_ON, ("VNIF: halt VNIFFreeQueuedSendPackets\n"));
    VNIFFreeQueuedSendPackets(adapter, NDIS_STATUS_FAILURE);

#ifdef NDIS50_MINIPORT
    /* Deregister shutdown handler as it's being halted */
    NdisMDeregisterAdapterShutdownHandler(adapter->AdapterHandle);
#endif

    RPRINTK(DPRTL_ON, ("VNIF: halt VNIF_DEC_REF\n"));
    VNIF_DEC_REF(adapter);

    RPRINTK(DPRTL_ON, ("VNIF: halt NdisWaitEvent\n"));
    NdisWaitEvent(&adapter->RemoveEvent, 0);

    /* We must wait for all our recources to be returned from the backend. */
    while (VNIFDisconnectBackend(adapter)) {
        ;
    }

    /*
     * We haven't release any receive refs in rx ring,
     * but after disconnect, we don't care.
     */

    NdisMDeregisterScatterGatherDma(adapter->NdisMiniportDmaHandle);
    adapter->NdisMiniportDmaHandle = (NDIS_HANDLE)(-1);

    VNIFFreeAdapter(adapter, NDIS_STATUS_SUCCESS);
    RPRINTK(DPRTL_ON, ("VNIF: MPHalt - OUT.\n"));
}

#if NDIS_SUPPORT_NDIS6
NDIS_STATUS
MPReset(IN NDIS_HANDLE MiniportAdapterContext, OUT PBOOLEAN AddressingReset)
#else
NDIS_STATUS
MPReset(OUT PBOOLEAN AddressingReset, IN NDIS_HANDLE MiniportAdapterContext)
#endif
{
    NDIS_STATUS status;
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;
    BOOLEAN done = TRUE;

    RPRINTK(DPRTL_ON, ("VNIF: Miniport Reset %s %x - IN.\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));

    if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_HALT_IN_PROGRESS)) {
        PRINTK(("VNIF: halt in progress, can't reset!\n"));
        return NDIS_STATUS_FAILURE;
    }

    if (VNIF_TEST_FLAG(adapter, VNF_RESET_IN_PROGRESS)) {
        return NDIS_STATUS_RESET_IN_PROGRESS;
    }

    VNIF_SET_FLAG(adapter, VNF_RESET_IN_PROGRESS);

    VNIFFreeQueuedSendPackets(adapter, NDIS_STATUS_RESET_IN_PROGRESS);

    if (adapter->nBusyRecv) {
        done = FALSE;
    }
    if (adapter->nBusySend) {
        done = FALSE;
    }

    *AddressingReset = FALSE;

    if (!done) {
        adapter->nResetTimerCount = 0;
        VNIF_SET_TIMER(adapter->ResetTimer, 500);
        RPRINTK(DPRTL_ON, ("VNIF: Miniport reset OUT %p: nrx = %x ntx = %x.\n",
            adapter, adapter->nBusyRecv, adapter->nBusySend));
        return NDIS_STATUS_PENDING;
    }

    VNIF_CLEAR_FLAG(adapter, VNF_RESET_IN_PROGRESS);
    RPRINTK(DPRTL_ON, ("VNIF: Miniport Reset %s %x - OUT.\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));
    return NDIS_STATUS_SUCCESS;
}

VOID
VNIFResetCompleteTimerDpc(
    IN PVOID SystemSpecific1,
    IN PVOID FunctionContext,
    IN PVOID SystemSpecific2,
    IN PVOID SystemSpecific3)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) FunctionContext;
    UINT i;
    BOOLEAN done = TRUE;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFResetCompleteTimerDpc - IN.\n"));
    VNIF_INC_REF(adapter);

    if (adapter->nBusyRecv) {
        done = FALSE;
    }

    if (adapter->nBusySend) {
        done = FALSE;
        vnif_call_txrx_interrupt_dpc(adapter);
        VNIFFreeQueuedSendPackets(adapter, NDIS_STATUS_RESET_IN_PROGRESS);
    }

    if (!done && ++adapter->nResetTimerCount <= 20) {
        /* continue to try waiting */
        RPRINTK(DPRTL_ON, ("VNIF: %s %p: nrx = %x, ntx = %x.\n",
            __func__, adapter, adapter->nBusyRecv, adapter->nBusySend));
        VNIF_SET_TIMER(adapter->ResetTimer, 500);
    } else {
        if (!done) {
            /* try enough, fail the reset */
            PRINTK(("VNIF: reset time out!\n"));
            NdisMResetComplete(adapter->AdapterHandle,
                NDIS_STATUS_SOFT_ERRORS, FALSE);
        } else {
            VNIF_CLEAR_FLAG(adapter, VNF_RESET_IN_PROGRESS);
            NdisMResetComplete(adapter->AdapterHandle,
                NDIS_STATUS_SUCCESS, FALSE);
        }
    }

    VNIF_DEC_REF(adapter);
    RPRINTK(DPRTL_ON, ("VNIF: VNIFResetCompleteTimerDpc - OUT.\n"));
}

VOID
MPUnload(IN PDRIVER_OBJECT DriverObject)
{
    RPRINTK(DPRTL_ON, ("VNIF: Miniport Unload - IN.\n"));

#if NDIS_SUPPORT_NDIS6
    NdisMDeregisterMiniportDriver(NdisMiniportDriverHandle);
#endif
    RPRINTK(DPRTL_ON, ("VNIF: Miniport Unload - OUT.\n"));
}

/*
 * typical shutdown just disable the interrupt and stop DMA,
 * do nothing else. We are doing nothing in this function.
 */
#if NDIS_SUPPORT_NDIS6
VOID
MPShutdown(IN NDIS_HANDLE MiniportAdapterContext,
    IN  NDIS_SHUTDOWN_ACTION ShutdownAction)
#else
VOID
MPShutdown(IN NDIS_HANDLE MiniportAdapterContext)
#endif
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;

    RPRINTK(DPRTL_ON, ("VNIF: MPShutdown %s %x - IN\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));

    if (KeGetCurrentIrql() < DISPATCH_LEVEL) {
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_SHUTDOWN);
    }

    VNIFQuiesce(adapter);

    RPRINTK(DPRTL_ON, ("VNIF: MPShutdown %s %x - OUT\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));
}

BOOLEAN
MPCheckForHang(IN NDIS_HANDLE MiniportAdapterContext)
{
    return FALSE;
}

VOID
MPAllocateComplete(
    NDIS_HANDLE MiniportAdapterContext,
    IN PVOID VirtualAddress,
    IN PNDIS_PHYSICAL_ADDRESS PhysicalAddress,
    IN ULONG Length,
    IN PVOID Context)
{
    RPRINTK(DPRTL_ON, ("VNIF: MPAllocateComplete.\n"));
}

#if NDIS_SUPPORT_NDIS6 || defined(NDIS51_MINIPORT)
#if NDIS_SUPPORT_NDIS6
VOID
MPPnPEventNotify(NDIS_HANDLE MiniportAdapterContext,
    IN PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent)
{
    NDIS_DEVICE_PNP_EVENT   PnPEvent = NetDevicePnPEvent->DevicePnPEvent;
#elif defined(NDIS51_MINIPORT)
VOID
MPPnPEventNotify(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_DEVICE_PNP_EVENT PnPEvent,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength)
{
#endif
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER) MiniportAdapterContext;
    PNDIS_POWER_PROFILE NdisPowerProfile;

    RPRINTK(DPRTL_ON, ("VNIF: MPPnPEventNotify - IN %x\n", PnPEvent));
    switch (PnPEvent) {
    case NdisDevicePnPEventQueryRemoved:
        /* Called when NDIS receives IRP_MN_QUERY_REMOVE_DEVICE. */
        break;

    case NdisDevicePnPEventRemoved:
        /*
         * Called when NDIS receives IRP_MN_REMOVE_DEVICE.
         * NDIS calls MiniportHalt function after this call returns.
         */
        break;

    case NdisDevicePnPEventSurpriseRemoved:
        /*
         * Called when NDIS receives IRP_MN_SUPRISE_REMOVAL.
         * NDIS calls MiniportHalt function after this call returns.
         */
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_SURPRISE_REMOVED);
        break;

    case NdisDevicePnPEventQueryStopped:
        /* Called when NDIS receives IRP_MN_QUERY_STOP_DEVICE. ?? */
        break;

    case NdisDevicePnPEventStopped:
        /*
         * Called when NDIS receives IRP_MN_STOP_DEVICE.
         * NDIS calls MiniportHalt function after this call returns.
         */
        break;

    case NdisDevicePnPEventPowerProfileChanged:
        /*
         * After initializing a miniport driver and after miniport driver
         * receives an OID_PNP_SET_POWER notification that specifies
         * a device power state of NdisDeviceStateD0 (the powered-on state),
         * NDIS calls the miniport's MiniportPnPEventNotify function with
         * PnPEvent set to NdisDevicePnPEventPowerProfileChanged.
         */
        break;

    default:
        break;
    }
    RPRINTK(DPRTL_ON, ("VNIF: MPPnPEventNotify - OUT\n"));
}
#endif
