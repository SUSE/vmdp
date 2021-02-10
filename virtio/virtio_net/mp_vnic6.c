/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2011-2012 Novell, Inc.
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

#include <ndis.h>
#include "miniport.h"
#include <virtio_queue_ops.h>

MINIPORT_INTERRUPT_DPC MPInterruptDPC;
MINIPORT_ISR  MPInterrupt;
MINIPORT_ENABLE_MESSAGE_INTERRUPT MPEnableMSIInterrupt;
MINIPORT_DISABLE_MESSAGE_INTERRUPT MPDisableMSIInterrupt;
MINIPORT_MESSAGE_INTERRUPT MPMsiInterrupt;
MINIPORT_MESSAGE_INTERRUPT_DPC MPMsiInterruptDpc;

static VOID
vnif_disable_interrupt_from_status(PVNIF_ADAPTER adapter,
                                   UINT path_id,
                                   LONG int_status)
{
    if (int_status & VNIF_RX_INT) {
        vq_disable_interrupt(adapter->path[path_id].u.vq.rx);
    }
    if (int_status & VNIF_TX_INT) {
        vq_disable_interrupt(adapter->path[path_id].u.vq.tx);
    }
}

static VOID
vnif_enable_interrupt_from_status(PVNIF_ADAPTER adapter,
                                   UINT path_id,
                                   LONG int_status)
{
    if (int_status & VNIF_RX_INT) {
        vq_enable_interrupt(adapter->path[path_id].u.vq.rx);
    }
    if (int_status & VNIF_TX_INT) {
        vq_enable_interrupt(adapter->path[path_id].u.vq.tx);
    }
}

static VOID
MPDisableMSIInterrupt(
    IN PVOID  MiniportInterruptContext,
    IN ULONG  MessageId)
{
    PVNIF_ADAPTER adapter;
    UINT path_id;

    adapter = (PVNIF_ADAPTER)MiniportInterruptContext;
    path_id = MessageId >> 1;

    DPRINTK(DPRTL_INT, ("[%s] message %d path %d\n",
                       __func__, MessageId, path_id));
    if (path_id < adapter->num_paths) {
        if (MessageId & 1) {
            vq_disable_interrupt(adapter->path[path_id].u.vq.tx);
        } else {
            vq_disable_interrupt(adapter->path[path_id].u.vq.rx);
        }
    }
}

static VOID
MPEnableMSIInterrupt(
    IN PVOID  MiniportInterruptContext,
    IN ULONG  MessageId)
{
    PVNIF_ADAPTER adapter;
    UINT path_id;

    adapter = (PVNIF_ADAPTER)MiniportInterruptContext;
    path_id = MessageId >> 1;

    DPRINTK(DPRTL_INT, ("[%s] message %d path %d\n",
                       __func__, MessageId, path_id));
    if (path_id < adapter->num_paths) {
        if (MessageId & 1) {
            vq_enable_interrupt(adapter->path[path_id].u.vq.tx);
        } else {
            vq_enable_interrupt(adapter->path[path_id].u.vq.rx);
        }
    }
}

static BOOLEAN
sync_q_enable(sync_ctx_t *sync)
{
    vnif_enable_interrupt_from_status(sync->adapter,
                                      sync->path_id,
                                      sync->int_status);
    return TRUE;
}

static void
vnif_miniport_interrupt_dpc(
    IN NDIS_HANDLE  MiniportInterruptContext,
    IN PVOID  MiniportDpcContext,
    IN ULONG msg_id,
    IN UINT max_nbls_to_indicate)
{
    sync_ctx_t sync;
    PVNIF_ADAPTER adapter;
#if NDIS_SUPPORT_NDIS620
    GROUP_AFFINITY affinity;
    KAFFINITY kaffinity;
    PROCESSOR_NUMBER processor_number;
#else
    ULONG kaffinity;
#endif
    ULONG path_id;
    LONG int_status;
    UINT more_to_do;

    adapter = (PVNIF_ADAPTER)MiniportInterruptContext;

    if (msg_id == adapter->u.v.ctrl_msg) {
        DPRINTK(DPRTL_DPC, ("%s: vnif_report_link_status msg_id %x\n",
                            __func__, msg_id));
        vnif_report_link_status(adapter);
        return;
    }

    if (adapter->b_multi_signaled == TRUE) {
        path_id = vnif_get_current_processor(NULL);
    } else {
        path_id = 0;
    }

    if (path_id < adapter->num_paths) {
        int_status = InterlockedExchange(
            &adapter->path[path_id].u.vq.interrupt_status,
            0);
        DPRINTK(DPRTL_DPC, ("%s: IN msg_id %d path_id %d int status %x\n",
                            __func__, msg_id, path_id, int_status));
        if (int_status & VNIF_CTRL_INT) {
            vnif_report_link_status(adapter);
        }

        sync.adapter = adapter;
        sync.path_id = path_id;
        sync.int_status = int_status;

    } else {
        DPRINTK(DPRTL_DPC, ("%s: msg_id %d path_id %d >= num paths %d\n",
                __func__, msg_id, path_id, adapter->num_paths));
        int_status = 0;
    }

    do {
        more_to_do = 0;

        if (int_status & VNIF_TX_INT) {
            vnif_txrx_interrupt_dpc(adapter,
                                    VNF_ADAPTER_TX_DPC_IN_PROGRESS,
                                    path_id,
                                    max_nbls_to_indicate);
        }

        /* int_status will also be 0 when RX is processed on the target CPU. */
        if ((int_status & VNIF_RX_INT) || int_status == 0) {
            vnif_txrx_interrupt_dpc(adapter,
                                    VNF_ADAPTER_RX_DPC_IN_PROGRESS,
                                    path_id,
                                    max_nbls_to_indicate);
        }

        if (path_id < adapter->num_paths
                && int_status != 0
                && VNIF_IS_READY(adapter)) {
            if ((int_status & VNIF_TX_INT)
                    && (VNIF_RING_HAS_UNCONSUMED_RESPONSES(
                            adapter->path[path_id].u.vq.tx))) {
                DPRINTK(DPRTL_DPC,
                       ("%s more tx work: msg_id %d path_id %d int_status %d\n",
                       __func__, msg_id, path_id, int_status));
                more_to_do = VNIF_TX_INT;
            }
        }
    } while (more_to_do);

    if (path_id < adapter->num_paths && int_status != 0) {
        NdisMSynchronizeWithInterruptEx(adapter->u.v.interrupt_handle,
                                        msg_id, sync_q_enable, &sync);

        /*
         * If we are servicing an interrupt and there is still more work to do
         * after enabling interrupts, schedule a dpc.  This prevents having
         * work to do and not getting an interrupt.
         */
        if ((int_status & (VNIF_RX_INT | VNIF_TX_INT))
            && (VNIF_RING_HAS_UNCONSUMED_RESPONSES(
                    adapter->path[path_id].u.vq.rx)
                || VNIF_RING_HAS_UNCONSUMED_RESPONSES(
                    adapter->path[path_id].u.vq.tx))) {

            InterlockedOr(&adapter->path[path_id].u.vq.interrupt_status,
                          int_status);

#if NDIS_SUPPORT_NDIS620
            KeGetCurrentProcessorNumberEx(&processor_number);

            affinity.Group = processor_number.Group;
            affinity.Mask = 1;
            affinity.Mask <<= processor_number.Number;

            kaffinity = NdisMQueueDpcEx(adapter->u.v.interrupt_handle,
                            msg_id,
                            &affinity,
                            MiniportDpcContext);
#else
            kaffinity = NdisMQueueDpc(adapter->u.v.interrupt_handle,
                          msg_id,
                          1 << KeGetCurrentProcessorNumber(),
                          MiniportDpcContext);
#endif
            DPRINTK(DPRTL_DPC,
                  ("%s more rx work: (%x) msg_id %d path_id %d int_status %d\n",
                  __func__, kaffinity, msg_id, path_id, int_status));
        }
    }

    DPRINTK(DPRTL_DPC, ("%s: OUT msg_id %d\n", __func__, msg_id));
}

static void
MPInterruptDPC(
    IN NDIS_HANDLE MiniportInterruptContext,
    IN PVOID MiniportDpcContext,
    IN PVOID ReceiveThrottleParameters,
    IN PVOID NdisReserved2)
{
    UINT max_nbls_to_indicate;

#if NDIS_SUPPORT_NDIS620
    PNDIS_RECEIVE_THROTTLE_PARAMETERS rtp;

    rtp = (PNDIS_RECEIVE_THROTTLE_PARAMETERS)ReceiveThrottleParameters;
    rtp->MoreNblsPending = 0;
    max_nbls_to_indicate = rtp->MaxNblsToIndicate;
#else
    max_nbls_to_indicate = NDIS_INDICATE_ALL_NBLS;
#endif
    DPRINTK(DPRTL_DPC, ("%s: IN dpc context %p\n",
                        __func__, MiniportDpcContext));

    vnif_miniport_interrupt_dpc(MiniportInterruptContext,
                                MiniportDpcContext,
                                0,
                                max_nbls_to_indicate);

    DPRINTK(DPRTL_DPC, ("%s: OUT\n", __func__));
}

static BOOLEAN
MPInterrupt(
    IN PVOID MiniportInterruptContext,
    OUT PBOOLEAN QueueDefaultInterruptDpc,
    OUT PULONG TargetProcessors)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)MiniportInterruptContext;
    LONG int_status;
    ULONG status;

    DPRINTK(DPRTL_INT, ("MPInterrupt in %d\n", KeGetCurrentProcessorNumber()));

    *QueueDefaultInterruptDpc = TRUE;
    *TargetProcessors = 0;

    status = virtio_device_read_isr_status(&adapter->u.v.vdev);
    if (status == 0 || status == VNIF_INVALID_INT) {
        /* Not our interrupt */
        if (!(VNIF_RING_HAS_UNCONSUMED_RESPONSES(adapter->path[0].rx)
              || VNIF_RING_HAS_UNCONSUMED_RESPONSES(adapter->path[0].tx))) {
            /* No work to do */
            *QueueDefaultInterruptDpc = FALSE;
            DPRINTK(DPRTL_INT, ("%s: DPC 0, claim 0, cpu %d.\n",
                                __func__, KeGetCurrentProcessorNumber()));
        }
        return FALSE;
    }

    if (adapter->adapter_flags & VNF_ADAPTER_POLLING) {
        DPRINTK(DPRTL_ON, ("%s %x: clearing polling flag.\n",
                           __func__, adapter->CurrentAddress[MAC_LAST_DIGIT]));
        adapter->adapter_flags &= ~VNF_ADAPTER_POLLING;
    }

    if (status & VIRTIO_NET_DEV_INT_CTRL) {
        int_status = VNIF_CTRL_INT | VNIF_RX_INT | VNIF_TX_INT;
    } else {
        int_status = VNIF_RX_INT | VNIF_TX_INT;
    }
    InterlockedOr(&adapter->path[0].u.vq.interrupt_status, (LONG)int_status);
    vnif_disable_interrupt_from_status(adapter, 0, int_status);

    DPRINTK(DPRTL_INT, ("MPInterrupt out %d\n", KeGetCurrentProcessorNumber()));
    return TRUE;
}

static VOID
MPMsiInterruptDpc(
    IN PVOID MiniportInterruptContext,
    IN ULONG MessageId,
    IN PVOID MiniportDpcContext,
#if NDIS_SUPPORT_NDIS620
    IN PVOID ReceiveThrottleParameters,
    IN PVOID NdisReserved2)
#else
    IN PULONG ReceiveThrottleParameters,
    IN PULONG NdisReserved2)
#endif
{
    UINT max_nbls_to_indicate;

#if NDIS_SUPPORT_NDIS620
    PNDIS_RECEIVE_THROTTLE_PARAMETERS rtp;

    rtp = (PNDIS_RECEIVE_THROTTLE_PARAMETERS)ReceiveThrottleParameters;
    rtp->MoreNblsPending = 0;
    max_nbls_to_indicate = rtp->MaxNblsToIndicate;
#else
    max_nbls_to_indicate = NDIS_INDICATE_ALL_NBLS;
#endif
    DPRINTK(DPRTL_DPC, ("%s: IN msg_id %d dpc context %p\n",
                       __func__, MessageId, MiniportDpcContext));

    vnif_miniport_interrupt_dpc(MiniportInterruptContext,
                                MiniportDpcContext,
                                MessageId,
                                max_nbls_to_indicate);

    DPRINTK(DPRTL_DPC, ("%s: OUT msg_id %d\n", __func__, MessageId));
}

static BOOLEAN
MPMsiInterrupt(
    IN PVOID  MiniportInterruptContext,
    IN ULONG  MessageId,
    OUT PBOOLEAN  QueueDefaultInterruptDpc,
    OUT PULONG  TargetProcessors)
{
    PVNIF_ADAPTER adapter;
    LONG interrupt_source;
    UINT path_id;

    adapter = (PVNIF_ADAPTER)MiniportInterruptContext;
    interrupt_source = 0;
    path_id = MessageId >> 1;
    DPRINTK(DPRTL_INT, ("%s MessageId %d path %d cpu %d\n",
            __func__, MessageId, path_id, vnif_get_current_processor(NULL)));

    if (path_id < adapter->num_paths) {
        MPDisableMSIInterrupt(adapter, MessageId);
        interrupt_source |= MessageId & 1 ? VNIF_TX_INT : VNIF_RX_INT;
        InterlockedOr(&adapter->path[path_id].u.vq.interrupt_status,
                      interrupt_source);
        vnif_disable_interrupt_from_status(adapter,
                                           path_id,
                                           interrupt_source);
        DPRINTK(DPRTL_INT, ("   int source %d\n", interrupt_source));


        vnif_schedule_msi_dpc(adapter,
                              MessageId,
                              path_id,
                              QueueDefaultInterruptDpc);

        if (adapter->adapter_flags & VNF_ADAPTER_POLLING) {
            DPRINTK(DPRTL_ON, ("%s %x: clearing polling flag.\n",
                    __func__, adapter->CurrentAddress[MAC_LAST_DIGIT]));
            adapter->adapter_flags &= ~VNF_ADAPTER_POLLING;
        }
    } else if (adapter->u.v.ctrl_msg == MessageId) {
        *QueueDefaultInterruptDpc = TRUE;
    } else {
        *QueueDefaultInterruptDpc = FALSE;
    }

    DPRINTK(DPRTL_DPC, ("%s OUT: do dpc %d MessageId %d path %d cpu %d\n",
            __func__, *QueueDefaultInterruptDpc, MessageId, path_id,
            vnif_get_current_processor(NULL)));
    *TargetProcessors = 0;
#ifdef DBG
    if (adapter->pv_stats != NULL) {
        dbg_print_mask = adapter->pv_stats->starting_print_mask;
    }
#endif
    return TRUE;
}

static NDIS_STATUS
vnif_set_msi_msg(VNIF_ADAPTER *adapter, UINT vq_idx, UINT qidx)
{
    NDIS_STATUS status;
    uint16_t  vector;
    uint16_t val;

    status = NDIS_STATUS_SUCCESS;

    vector = qidx < adapter->u.v.msi_info_tbl->MessageCount ?
        (uint16_t)qidx :
        (uint16_t)(adapter->u.v.msi_info_tbl->MessageCount - 1);

    val = VIRTIO_DEVICE_SET_QUEUE_VECTOR(&adapter->u.v.vdev,
                                         (uint16_t)qidx,
                                         vector);
    if (val != vector) {
        RPRINTK(DPRTL_INIT, ("[%s] val %d != vector %d\n", __func__,
                             val, vector));
    }
    adapter->path[vq_idx].u.vq.rx_msg = (uint16_t)vector;
    RPRINTK(DPRTL_INIT, ("[%s] rx qidx %d vector %d val %d\n", __func__,
                         qidx, vector, val));

    qidx++;
    vector = qidx < adapter->u.v.msi_info_tbl->MessageCount ?
        (uint16_t)qidx :
        (uint16_t)(adapter->u.v.msi_info_tbl->MessageCount - 1);

    val = VIRTIO_DEVICE_SET_QUEUE_VECTOR(&adapter->u.v.vdev,
                                         (uint16_t)qidx,
                                         vector);
    if (val != vector) {
        RPRINTK(DPRTL_INIT, ("[%s] val %d != vector %d\n", __func__,
                             val, vector));
    }

    adapter->path[vq_idx].u.vq.tx_msg = (uint16_t)vector;
    RPRINTK(DPRTL_INIT, ("[%s] tx qidx %d vector %d val %d\n", __func__,
                         qidx, vector, val));
    RPRINTK(DPRTL_INIT, ("[%s] vq[%d] rx_msg %d tx_msg %d\n", __func__,
                         vq_idx,
                         adapter->path[vq_idx].u.vq.rx_msg,
                         adapter->path[vq_idx].u.vq.tx_msg));

    return status;
}

NDIS_STATUS
vnifv_msi_config(VNIF_ADAPTER *adapter)
{
    PIO_INTERRUPT_MESSAGE_INFO pTable;
    NDIS_STATUS status;
    UINT i;
    uint16_t vector;

    if (!(adapter->u.v.interrupt_flags & CM_RESOURCE_INTERRUPT_MESSAGE)) {
        return NDIS_STATUS_SUCCESS;
    }

    status = NDIS_STATUS_RESOURCES;
    pTable = adapter->u.v.msi_info_tbl;

    if (pTable && pTable->MessageCount) {
        status = NDIS_STATUS_SUCCESS;
        RPRINTK(DPRTL_INIT, ("[%s] Using msi ints (%d messages, irql %d)\n",
            __func__, pTable->MessageCount, pTable->UnifiedIrql));

        for (i = 0; i < adapter->u.v.msi_info_tbl->MessageCount; ++i) {
            RPRINTK(DPRTL_INIT,  ("[%s] msi message %d = %08X => %I64X\n",
                __func__, i,
                pTable->MessageInfo[i].MessageData,
                pTable->MessageInfo[i].MessageAddress));
        }

        for (i = 0;
             i < adapter->num_paths && status == NDIS_STATUS_SUCCESS;
             ++i) {
            status = vnif_set_msi_msg(adapter, i, i * 2);
        }

        vector = (i * 2) < adapter->u.v.msi_info_tbl->MessageCount ?
            (uint16_t)(i * 2) :
            (uint16_t)(adapter->u.v.msi_info_tbl->MessageCount - 1);

        RPRINTK(DPRTL_INIT,  ("[%s] set config vector %d\n", __func__, vector));
        VIRTIO_DEVICE_SET_CONFIG_VECTOR(&adapter->u.v.vdev, vector);
        adapter->u.v.ctrl_msg = (uint16_t)vector;
    }
    return status;
}

NDIS_STATUS
vnifv_setup_path_info_ex(VNIF_ADAPTER *adapter)
{
    NDIS_STATUS status;
    UINT i;

    for (i = 0; i < adapter->num_paths; i++) {
        adapter->path[i].u.vq.rx_msg = VIRTIO_MSI_NO_VECTOR;
        adapter->path[i].u.vq.tx_msg = VIRTIO_MSI_NO_VECTOR;
    }

    vnif_setup_rx_path_dpc(adapter);

    adapter->u.v.ctrl_msg = VIRTIO_MSI_NO_VECTOR;

    return NDIS_STATUS_SUCCESS;
}

void
VNIFV_DeregisterHardwareResources(VNIF_ADAPTER *adapter)
{
    if (adapter->u.v.interrupt_handle) {
        NdisMDeregisterInterruptEx(adapter->u.v.interrupt_handle);
        adapter->u.v.interrupt_handle = NULL;
    }
}

UINT
vnifv_get_num_paths(struct _VNIF_ADAPTER *adapter)
{
    UINT num_paths;

    if (adapter->u.v.msi_info_tbl != NULL) {
        if (adapter->u.v.msi_info_tbl->MessageCount <= 2) {
            num_paths = 1;
            RPRINTK(DPRTL_INIT, ("[%s] msg cnt %lu, use 1 queue\n",
                    __func__, adapter->u.v.msi_info_tbl->MessageCount));
        } else {
            num_paths = (adapter->u.v.msi_info_tbl->MessageCount - 1) / 2;
            RPRINTK(DPRTL_INIT, ("[%s] message count %lu num paths %d\n",
                    __func__, adapter->u.v.msi_info_tbl->MessageCount,
                    num_paths));
        }
    } else {
        num_paths = 1;
    }

    return num_paths;
}

NDIS_STATUS
VNIFV_RegisterNdisInterrupt(struct _VNIF_ADAPTER *adapter)
{
    NDIS_MINIPORT_INTERRUPT_CHARACTERISTICS mic;
    NDIS_STATUS status;

    NdisZeroMemory(&mic, sizeof(mic));

    mic.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_INTERRUPT;
    mic.Header.Revision = NDIS_MINIPORT_INTERRUPT_REVISION_1;
    mic.Header.Size = NDIS_SIZEOF_MINIPORT_INTERRUPT_CHARACTERISTICS_REVISION_1;
    mic.DisableInterruptHandler = MPDisableInterrupt;
    mic.EnableInterruptHandler  = MPEnableInterrupt;
    mic.InterruptDpcHandler = MPInterruptDPC;
    mic.InterruptHandler = MPInterrupt;
    if (adapter->u.v.interrupt_flags & CM_RESOURCE_INTERRUPT_MESSAGE) {
        mic.MsiSupported = TRUE;
        mic.MsiSyncWithAllMessages = TRUE;
        mic.EnableMessageInterruptHandler = MPEnableMSIInterrupt;
        mic.DisableMessageInterruptHandler = MPDisableMSIInterrupt;
        mic.MessageInterruptHandler = MPMsiInterrupt;
        mic.MessageInterruptDpcHandler = MPMsiInterruptDpc;
    }

    status = NdisMRegisterInterruptEx(adapter->AdapterHandle,
        adapter,
        &mic,
        &adapter->u.v.interrupt_handle);

    if (status == NDIS_STATUS_SUCCESS) {
        if (mic.InterruptType == NDIS_CONNECT_MESSAGE_BASED) {
            adapter->u.v.msi_info_tbl = mic.MessageInfoTable;
        } else if (adapter->u.v.interrupt_flags &
                   CM_RESOURCE_INTERRUPT_MESSAGE) {
            RPRINTK(DPRTL_ON, ("[%s] ERR: int type %d, message table %p\n",
                    __func__, mic.InterruptType, mic.MessageInfoTable));
            adapter->u.v.interrupt_flags &= ~CM_RESOURCE_INTERRUPT_MESSAGE;
        }
    } else {
        PRINTK(("%s: failed 0x%x\n", __func__, status));
    }
    return status;
}
