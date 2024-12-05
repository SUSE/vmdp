/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2024 SUSE LLC
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

static NDIS_POLL vnif_rcv_q_ndis_poll;
static NDIS_POLL vnif_rx_ndis_poll;
static NDIS_POLL vnif_tx_ndis_poll;
static NDIS_POLL vnif_txrx_ndis_poll;

static NDIS_SET_POLL_NOTIFICATION vnif_ndis_set_poll_notification;
static NDIS_SET_POLL_NOTIFICATION vnif_rcvq_ndis_set_poll_notification;

NDIS_STATUS
vnif_ndis_register_poll(PVNIF_ADAPTER adapter)
{
    NDIS_POLL_CHARACTERISTICS poll_char;
    PROCESSOR_NUMBER proc_num;
    NDIS_STATUS status;
    UINT i;

    RPRINTK(DPRTL_INIT, ("---> %s: num paths %d num rcv queues %d\n", __func__,
                         adapter->num_paths, adapter->num_rcv_queues));

    status = NDIS_STATUS_SUCCESS;

    poll_char.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    poll_char.Header.Revision = NDIS_POLL_CHARACTERISTICS_REVISION_1;
    poll_char.Header.Size = NDIS_SIZEOF_NDIS_POLL_CHARACTERISTICS_REVISION_1;
    if (adapter->b_multi_signaled && adapter->b_use_split_evtchn) {
        poll_char.SetPollNotificationHandler = vnif_ndis_set_poll_notification;
        poll_char.PollHandler = vnif_rx_ndis_poll;

        for (i = 0; i < adapter->num_paths; ++i) {
            adapter->path[i].rx_poll_context.adapter = adapter;
            adapter->path[i].rx_poll_context.path_rcv_q_id = i;
            adapter->path[i].rx_poll_context.poll_requested = VNIF_RX_INT;
            status = NdisRegisterPoll(adapter->AdapterHandle,
                                      &adapter->path[i].rx_poll_context,
                                      &poll_char,
                                      &adapter->path[i].rx_poll_context.nph);
            if (status != NDIS_STATUS_SUCCESS) {
                PRINTK(("NdisRegisterPoll: RX[%d] failed %x\n", i, status));
            }
        }

        poll_char.PollHandler = vnif_tx_ndis_poll;
        for (i = 0; i < adapter->num_paths; ++i) {
            adapter->path[i].tx_poll_context.adapter = adapter;
            adapter->path[i].tx_poll_context.path_rcv_q_id = i;
            adapter->path[i].tx_poll_context.poll_requested = VNIF_TX_INT;
            status = NdisRegisterPoll(adapter->AdapterHandle,
                                      &adapter->path[i].tx_poll_context,
                                      &poll_char,
                                      &adapter->path[i].tx_poll_context.nph);
            if (status != NDIS_STATUS_SUCCESS) {
                PRINTK(("NdisRegisterPoll: TX[%d] failed %x\n", i, status));
            }
        }
    } else {
        /* Handle both txrx on the rx poll context. */
        RPRINTK(DPRTL_INIT, ("  Handle both txrx on same poll context.\n"));
        poll_char.SetPollNotificationHandler = vnif_ndis_set_poll_notification;
        poll_char.PollHandler = vnif_txrx_ndis_poll;

        for (i = 0; i < adapter->num_paths; ++i) {
            adapter->path[i].rx_poll_context.adapter = adapter;
            adapter->path[i].rx_poll_context.path_rcv_q_id = i;
            adapter->path[i].rx_poll_context.poll_requested =
                (VNIF_RX_INT | VNIF_TX_INT);
            status = NdisRegisterPoll(adapter->AdapterHandle,
                                      &adapter->path[i].rx_poll_context,
                                      &poll_char,
                                      &adapter->path[i].rx_poll_context.nph);
            if (status != NDIS_STATUS_SUCCESS) {
                PRINTK(("NdisRegisterPoll: RX[%d] failed %x\n", i, status));
            }
        }
    }

    RPRINTK(DPRTL_INIT, ("<--- %s\n", __func__));
    return status;
}

static void
vnif_rx_ndis_poll(void *context,
                  NDIS_POLL_DATA *poll_data)
{
    vnif_poll_context_t *poll_context;
    PVNIF_ADAPTER adapter;
    PNET_BUFFER_LIST nb_list;
    PNET_BUFFER_LIST tail_nb_list;
    rcv_to_process_q_t *rcv_q;
    ULONG in_poll;
    UINT path_id;
    UINT nb_list_cnt;
    UINT rp;
    UINT old;
    UINT rcb_added_to_ring;
    UINT rcv_qidx;
    int more_to_do;
    UINT nbls_to_indicate;
    BOOLEAN needs_rcv_q_work;

    poll_context = (vnif_poll_context_t *)context;

    adapter = poll_context->adapter;
    path_id = poll_context->path_rcv_q_id;
    rcv_qidx = vnif_rss_get_rcv_qidx_for_cur_cpu(adapter);
    if (rcv_qidx == VNIF_NO_RECEIVE_QUEUE) {
        rcv_qidx = adapter->num_rcv_queues - 1;
    }
    rcv_q = &adapter->rcv_q[rcv_qidx];

    rp = 0;
    nb_list = NULL;
    tail_nb_list = NULL;
    nb_list_cnt = 0;
    rcb_added_to_ring = 0;
    more_to_do = 0;
    needs_rcv_q_work = FALSE;
    nbls_to_indicate = min(poll_data->Receive.MaxNblsToIndicate,
                           VNIF_RX_RING_SIZE(adapter));

    DPRINTK(DPRTL_RXDPC,
            ("---> %s: rcv_qidx %d path_id %d irql %d cpu %d %d.\n",
             __func__,
             rcv_qidx, path_id,
             KeGetCurrentIrql(),
             KeGetCurrentProcessorNumber(),
             vnif_get_current_processor(NULL)));

    VNIF_INC_REF(adapter);
    NdisAcquireSpinLock(&adapter->path[path_id].rx_path_lock);
    NdisAcquireSpinLock(&rcv_q->rcv_to_process_lock);
    VNIF_GET_RX_REQ_PROD(adapter, path_id, &old);
    do {
        vnif_drain_rx_path(adapter,
                           path_id,
                           rcv_qidx,
                           &rcb_added_to_ring,
                           &rp,
                           &needs_rcv_q_work);



        nb_list = vnif_mv_rcbs_to_nbl(adapter,
                                      path_id,
                                      rcv_qidx,
                                      nbls_to_indicate,
                                      &nb_list,
                                      &tail_nb_list,
                                      &nb_list_cnt);

        VNIF_RING_FINAL_CHECK_FOR_RESPONSES(adapter->path[path_id].rx,
                                            &more_to_do);
    } while (more_to_do && nb_list_cnt < nbls_to_indicate);

    if (!IsListEmpty(&rcv_q->rcv_to_process) || more_to_do) {

        DPRINTK(DPRTL_RXDPC,
            ("%s: RecvToProcess not empty %d, schedule dpc, nbls %d ind %d\n",
             __func__,
             more_to_do,
             nb_list_cnt,
             nbls_to_indicate));
        poll_data->Receive.NumberOfRemainingNbls = NDIS_ANY_NUMBER_OF_NBLS;
    } else {
        poll_data->Receive.NumberOfRemainingNbls = 0;
    }

    /* No need to request work for the current rcvq, Poll will call us back. */
    rcv_q->rcv_q_should_request_work = FALSE;
    vnif_request_rcv_q_work(adapter,
                            poll_data->Receive.MaxNblsToIndicate,
                            needs_rcv_q_work);

    NdisReleaseSpinLock(&rcv_q->rcv_to_process_lock);
    NdisReleaseSpinLock(&adapter->path[path_id].rx_path_lock);

    if (nb_list_cnt == 0) {
        VNIF_RX_NOTIFY(adapter, path_id, rcb_added_to_ring, old);
    } else {
        VNIFReceivePacketsPostStats(adapter,
                                    path_id,
                                    nbls_to_indicate,
                                    nb_list_cnt);
    }

    poll_data->Receive.IndicatedNblChain =  nb_list;
    poll_data->Receive.NumberOfIndicatedNbls =  nb_list_cnt;
    poll_data->Receive.Flags = NDIS_RECEIVE_FLAGS_PERFECT_FILTERED;
    VNIF_DEC_REF(adapter);

    if (g_running_hypervisor == HYPERVISOR_XEN) {
        vnif_enable_adapter_notifications(adapter,
                                          path_id,
                                          poll_context->poll_requested);
    }

    DPRINTK(DPRTL_RXDPC,
            ("<--- %s: rcv_qidx %d path_id %d nb_list_cnt %d/%d.\n",
             __func__,
             rcv_qidx,
             path_id,
             nb_list_cnt,
             nbls_to_indicate));

}

static void
vnif_tx_ndis_poll(void *context,
                  NDIS_POLL_DATA *poll_data)
{
    vnif_poll_context_t *poll_context;
    PVNIF_ADAPTER adapter;
    PNET_BUFFER_LIST nb_list;
    PNET_BUFFER_LIST tail_nb_list;
    ULONG in_poll;
    UINT path_id;
    UINT nbls_to_complete;
    UINT nb_list_cnt;
    UINT more_to_do;

    poll_context = (vnif_poll_context_t *)context;

    adapter = poll_context->adapter;
    path_id = poll_context->path_rcv_q_id;

    DPRINTK(DPRTL_TXDPC, ("---> %s: path_id %d irql %d cpu %d.\n",
                          __func__,
                          path_id,
                          KeGetCurrentIrql(),
                          KeGetCurrentProcessorNumber()));

    nbls_to_complete = min(poll_data->Transmit.MaxNblsToComplete,
                           VNIF_TX_RING_SIZE(adapter));
    nb_list = NULL;
    tail_nb_list = NULL;
    nb_list_cnt = 0;
    do {
        vnif_drain_tx_path_and_send(adapter,
                                    path_id,
                                    nbls_to_complete,
                                    &nb_list,
                                    &tail_nb_list,
                                    &nb_list_cnt);

        more_to_do = VNIF_RING_HAS_UNCONSUMED_RESPONSES(
            adapter->path[path_id].tx);

    } while (nb_list_cnt < nbls_to_complete && more_to_do);

    if (more_to_do) {
        poll_data->Transmit.NumberOfRemainingNbls = NDIS_ANY_NUMBER_OF_NBLS;
    } else {
        poll_data->Transmit.NumberOfRemainingNbls = 0;
    }
    poll_data->Transmit.CompletedNblChain =  nb_list;
    poll_data->Transmit.NumberOfCompletedNbls =  nb_list_cnt;
    poll_data->Transmit.SendCompleteFlags = 0;

    if (g_running_hypervisor == HYPERVISOR_XEN) {
        vnif_enable_adapter_notifications(adapter,
                                          path_id,
                                          poll_context->poll_requested);
    }

    DPRINTK(DPRTL_TXDPC,
            ("<--- %s: path_id %d cpu %d nbl %p nbcnt %d/%d/%d/%d.\n",
             __func__,
             path_id,
             KeGetCurrentProcessorNumber(),
             nb_list, nb_list_cnt,
             nbls_to_complete,
             poll_data->Transmit.MaxNblsToComplete,
             VNIF_TX_RING_SIZE(adapter)));
}

static void
vnif_txrx_ndis_poll(void *context,
                    NDIS_POLL_DATA *poll_data)
{
    vnif_poll_context_t *poll_context;
    DPRINTK(DPRTL_TXDPC | DPRTL_RXDPC, ("---> %s\n", __func__));

    poll_context = (vnif_poll_context_t *)context;

    vnif_tx_ndis_poll(poll_context, poll_data);
    vnif_rx_ndis_poll(poll_context, poll_data);

    DPRINTK(DPRTL_TXDPC | DPRTL_RXDPC, ("<--- %s\n", __func__));

}

static void
vnif_ndis_set_poll_notification(void *context,
                                NDIS_POLL_NOTIFICATION *notification)
{
    vnif_poll_context_t *poll_context;
    PVNIF_ADAPTER adapter;
    UINT path_id;

    poll_context = (vnif_poll_context_t *)context;

    adapter = poll_context->adapter;
    path_id = poll_context->path_rcv_q_id;

    DPRINTK(DPRTL_DPC,
       ("---> %s: en %d path_id %d txrx %d irql %d cpu %d.\n",
       __func__, notification->Enabled, path_id,
        poll_context->poll_requested,
        KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber()));

    if (notification->Enabled) {
        vnif_enable_adapter_notifications(adapter,
                                          path_id,
                                          poll_context->poll_requested);

    } else {
        vnif_disable_adapter_notifications(adapter,
                                          path_id,
                                          poll_context->poll_requested);
    }

    DPRINTK(DPRTL_DPC,
       ("<--- %s: en %d path_id %d txrx %d irql %d cpu %d.\n",
       __func__, notification->Enabled, path_id,
        poll_context->poll_requested,
        KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber()));
}

static void
vnif_rcvq_ndis_set_poll_notification(void *context,
                                     NDIS_POLL_NOTIFICATION *notification)
{
    vnif_poll_context_t *poll_context;
    PVNIF_ADAPTER adapter;
    rcv_to_process_q_t *rcv_q;
    UINT rcv_qidx;

    poll_context = (vnif_poll_context_t *)context;
    adapter = poll_context->adapter;
    rcv_qidx = poll_context->path_rcv_q_id;
    rcv_q = &adapter->rcv_q[rcv_qidx];
    DPRINTK(DPRTL_RXDPC, ("%s: rcvq[%d]\n", __func__, rcv_qidx));
}


void
vnif_continue_ndis_request_poll(PVNIF_ADAPTER adapter,
                                UINT path_id,
                                LONG poll_requested)
{
    int rx_more_to_do;
    int tx_more_to_do;

    rx_more_to_do = 0;
    tx_more_to_do = 0;

    if (poll_requested & VNIF_RX_INT) {
        VNIF_RING_FINAL_CHECK_FOR_RESPONSES(adapter->path[path_id].rx,
                                            &rx_more_to_do);
        /* Check for RX multi signled case. */
        if (((poll_requested & (VNIF_RX_INT | VNIF_TX_INT)) == VNIF_RX_INT)
                && rx_more_to_do) {
            DPRINTK(DPRTL_RXPOLL,
               ("---> %s: RX RequestPoll path_id %d req %d irql %d cpu %d\n",
               __func__,
                path_id,
                poll_requested,
                KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber()));

            NdisRequestPoll(adapter->path[path_id].rx_poll_context.nph, NULL);
        }
    }
    if (poll_requested & VNIF_TX_INT) {
        tx_more_to_do = VNIF_RING_HAS_UNCONSUMED_RESPONSES(
            adapter->path[path_id].tx);

        /* Check for TX multi signled case. */
        if (((poll_requested & (VNIF_RX_INT | VNIF_TX_INT)) == VNIF_TX_INT)
                && tx_more_to_do) {
            DPRINTK(DPRTL_TXPOLL,
               ("---> %s: TX RequestPoll path_id %d req %d irql %d cpu %d\n",
                __func__,
                path_id,
                poll_requested,
                KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber()));

            NdisRequestPoll(adapter->path[path_id].tx_poll_context.nph, NULL);
        }
    }

    /* Check for TXRX on same queue. */
    if ((poll_requested & (VNIF_RX_INT | VNIF_TX_INT))
                == (VNIF_RX_INT | VNIF_TX_INT)) {
        if (rx_more_to_do || tx_more_to_do) {
            DPRINTK(DPRTL_TXDPC,
               ("---> %s: TXRX RequestPoll path_id %d req %d irql %d cpu %d\n",
                __func__,
                path_id,
                poll_requested,
                KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber()));

            NdisRequestPoll(adapter->path[path_id].rx_poll_context.nph, NULL);
        }
    }

    DPRINTK(DPRTL_DPC,
            ("<--- %s: path_id %d req %d irql %d cpu %d.\n",
             __func__,
             path_id,
             poll_requested,
             KeGetCurrentIrql(),
             KeGetCurrentProcessorNumber()));
}
