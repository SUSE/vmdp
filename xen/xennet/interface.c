/*-
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

/*
 * Our vnif driver have to know nodename, otherend and backend ID of the
 * device, they are part of the target device pdo's device extension. We
 * are here access them using the exported functions by bus driver.
 *
 * A normal driver should not rely on such techniques. However, in our driver,
 * this is a much easier way to implement. By this approach, some of the kernel
 * mode driver stack characteristics are circumvented. The internal device
 * control or driver interface may be the way to go.
 *
 * Trying to use defeinitions from ntddk.h in a network miniport driver is
 * simply a disaster. so we are not trying to include ntddk.h and use
 * ExFreePool to free he string from xenstore, this is done by exported
 * functions again.
 *
 * These behaviors are subjected to change in the future.
 */


static domid_t VNIFGetBackendIDFromPDO(PDEVICE_OBJECT pdo);
static int VNIFSetupPermanentAddress(PVNIF_ADAPTER adapter);
static int VNIFSetupXenFlags(PVNIF_ADAPTER Adapter);
static int VNIFTalkToBackend(PVNIF_ADAPTER Adapter);
static NDIS_STATUS VNIFInitRxGrants(PVNIF_ADAPTER adapter);
static NDIS_STATUS VNIFInitTxGrants(PVNIF_ADAPTER adapter);
static void xennet_frontend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len);
static void xennet_backend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len);
static void MPResume(PVNIF_ADAPTER adapter, uint32_t suspend_canceled);
static uint32_t MPSuspend(PVNIF_ADAPTER adapter, uint32_t reason);
static uint32_t MPIoctl(PVNIF_ADAPTER adapter, pv_ioctl_t data);

void
VNIFFreeAdapterInterface(PVNIF_ADAPTER adapter)
{
    DPR_INIT(("VNIFFreeXenAdapter: IN\n"));

    if (adapter->vif.node_name) {
        DPR_INIT(("VNIFFreeXenAdapter: freeing %s\n", adapter->vif.node_name));
        NdisFreeMemory(adapter->vif.node_name,
                       strlen(adapter->vif.node_name) + 1, 0);
        adapter->vif.node_name = NULL;
    }
    if (adapter->vif.otherend) {
        DPR_INIT(("VNIFFreeXenAdapter: freeing %s\n", adapter->vif.otherend));
        NdisFreeMemory(adapter->vif.otherend,
                       strlen(adapter->vif.otherend) + 1, 0);
        adapter->vif.otherend = NULL;
    }
    if (adapter->vif.rx.sring) {
        DPR_INIT(("VNIFFreeXenAdapter: freeing adapter->rx.sring\n"));
        NdisFreeMemory(adapter->vif.rx.sring, PAGE_SIZE, 0);
        adapter->vif.rx.sring = NULL;
    }
    if (adapter->vif.tx.sring) {
        DPR_INIT(("VNIFFreeXenAdapter: freeing adapter->tx.sring\n"));
        NdisFreeMemory(adapter->vif.tx.sring, PAGE_SIZE, 0);
        adapter->vif.tx.sring = NULL;
    }
    adapter->nBusyRecv = 0;
    adapter->nBusySend = 0;
    DPR_INIT(("VNIFFreeXenAdapter: OUT\n"));
}

void
VNIFCleanupInterface(PVNIF_ADAPTER adapter)
{
    xenbus_release_device_t release_data;

    release_data.action = RELEASE_REMOVE;
    release_data.type = vnif;

    VNIFCleanupRings(adapter);
    xenbus_release_device(adapter, NULL, release_data);
}

NDIS_STATUS
VNIFFindAdapter(PVNIF_ADAPTER adapter)
{
    PUCHAR nodename, otherend;
    NDIS_STATUS status;
    UINT i;

    DPR_INIT(("VNIFFindXenAdapter: claim %p\n", adapter));
    status = xenbus_claim_device(adapter, NULL, vnif, none, MPIoctl, MPIoctl);
    if (status != NDIS_STATUS_SUCCESS && status != STATUS_RESOURCE_IN_USE) {
        return status;
    }

    status = NDIS_STATUS_SUCCESS;
    do {
        /* Nodename */
        DPR_INIT(("VNIFFindXenAdapter: IN VNIFGetNodenameFromPDO\n"));
        nodename = xenbus_get_nodename_from_pdo(adapter->Pdo);
        if (nodename == NULL) {
            DBG_PRINT(("VNIF: failed to get nodename.\n"));
            status = NDIS_STATUS_FAILURE;
            break;
        }
        i = strlen(nodename) + 1;
        VNIF_ALLOCATE_MEMORY(
            adapter->vif.node_name,
            i,
            VNIF_POOL_TAG,
            NdisMiniportDriverHandle,
            NormalPoolPriority);
        if (adapter->vif.node_name == NULL) {
            DBG_PRINT(("VNIF: allocating memory for nodename fail.\n"));
            status = STATUS_NO_MEMORY;
            break;
        }
        NdisMoveMemory(adapter->vif.node_name, nodename, i);

        /* Otherend */
        otherend = xenbus_get_otherend_from_pdo(adapter->Pdo);
        if (otherend == NULL) {
            DBG_PRINT(("VNIF: failed to get otherend.\n"));
            status = NDIS_STATUS_FAILURE;
            break;
        }
        i = strlen(otherend) + 1;
        VNIF_ALLOCATE_MEMORY(
            adapter->vif.otherend,
            i,
            VNIF_POOL_TAG,
            NdisMiniportDriverHandle,
            NormalPoolPriority);
        if (adapter->vif.otherend == NULL) {
            DBG_PRINT(("VNIF: allocating memory for otherend fail.\n"));
            status = STATUS_NO_MEMORY;
            break;
        }
        NdisMoveMemory(adapter->vif.otherend, otherend, i);

        /* Backend */
        adapter->vif.backend_id = VNIFGetBackendIDFromPDO(adapter->Pdo);
        if (adapter->vif.backend_id == (domid_t)-1) {
            DBG_PRINT(("VNIF: failed to get backend id.\n"));
            status = NDIS_STATUS_FAILURE;
            break;
        }

        /* MAC */
        if (!VNIFSetupPermanentAddress(adapter)) {
            DBG_PRINT(("VNIF: set NIC MAC fail.\n"));
            status = NDIS_STATUS_FAILURE;
            break;
        }

        adapter->vif.gref_tx_head = GRANT_INVALID_REF;
        adapter->vif.gref_rx_head = GRANT_INVALID_REF;

        DPR_INIT(("VNIFFindXenAdapter: OUT %p, %s\n",
            adapter, adapter->vif.node_name));
    } while (FALSE);

    if (status != NDIS_STATUS_SUCCESS) {
        VNIFFreeAdapterInterface(adapter);
    }
    return status;
}

NDIS_STATUS
VNIFSetupAdapterInterface(PVNIF_ADAPTER adapter)
{
    NTSTATUS status;

    /* Set Flags */
    if (!VNIFSetupXenFlags(adapter)) {
        DBG_PRINT(("VNIF: set xen features fail.\n"));
        return NDIS_STATUS_FAILURE;
    }
    /* Let backend know our configuration */
    if (VNIFTalkToBackend(adapter)) {
        DBG_PRINT(("VNIF: NIC talk to backend fail.\n"));
        return NDIS_STATUS_FAILURE;
    }

    status = VNIFInitRxGrants(adapter);
    if (status != NDIS_STATUS_SUCCESS) {
        return NDIS_STATUS_FAILURE;
    }

    status = VNIFInitTxGrants(adapter);
    if (status != NDIS_STATUS_SUCCESS) {
        return NDIS_STATUS_FAILURE;
    }

    /* At this point we are successful. */
    xenbus_switch_state(adapter->vif.node_name, XenbusStateConnected);

    adapter->vif.watch.callback = xennet_frontend_changed;
    adapter->vif.watch.node = adapter->vif.node_name;
    adapter->vif.watch.flags = XBWF_new_thread;
    adapter->vif.watch.context = adapter;

    adapter->vif.backend_watch.callback = xennet_backend_changed;
    adapter->vif.backend_watch.node = adapter->vif.otherend;
    adapter->vif.backend_watch.flags = XBWF_new_thread;
    adapter->vif.backend_watch.context = adapter;

    /* Get the initial status. */
    DPR_INIT(("VNIFSetupXenAdapter: xennet_frontend_changed %p, %s\n",
        adapter, adapter->vif.node_name));
    VNIFIndicateLinkStatus(adapter, 1);
    xennet_frontend_changed(&adapter->vif.watch, NULL, 0);

    /* Enable the interrupt */
    register_dpc_to_evtchn(adapter->vif.evtchn, VNIFInterruptDpc,
                           adapter, NULL);

    /* Now register for the watch. */
    DPR_INIT(("VNIFSetupXenAdapter: register_xenbus_watch %p, %s\n",
        adapter, adapter->vif.node_name));
    register_xenbus_watch(&adapter->vif.watch);
    register_xenbus_watch(&adapter->vif.backend_watch);

    DPR_INIT(("VNIFSetupXenAdapter: OUT %p, %s\n",
              adapter, adapter->vif.node_name));
    return STATUS_SUCCESS;
}

static domid_t
VNIFGetBackendIDFromPDO(PDEVICE_OBJECT pdo)
{
    char *bidstr;
    domid_t bid;

    bidstr = xenbus_get_backendid_from_pdo(pdo);
    if (bidstr) {
        bid = (domid_t) cmp_strtoul(bidstr, NULL, 10);
        return bid;
    }
    return (domid_t)-1;

}

static int
VNIFSetupPermanentAddress(PVNIF_ADAPTER adapter)
{
    int res, i;
    unsigned long val;
    char *mac, *ptr, *str;

    res = xenbus_exists(XBT_NIL, adapter->vif.otherend, "mac");
    if (res == 0) {
        return 0;
    }

    str = mac = (char *)xenbus_read(XBT_NIL, adapter->vif.otherend,
                                    "mac", &res);
    if (mac == NULL) {
        return 0;
    }

    res = 1;
    for (i = 0; i < ETH_LENGTH_OF_ADDRESS; i++) {
        val = (unsigned long)cmp_strtoul(mac, &ptr, 16);
        if (ptr != mac) {
            adapter->PermanentAddress[i] = (UCHAR) val;
        } else {
            res = 0;
        }
        mac = ptr + 1;
    }
    xenbus_free_string(str);

    /* If the current address isn't already setup do it now. */
    if (adapter->CurrentAddress[0] == 0
        && adapter->CurrentAddress[1] == 0
        && adapter->CurrentAddress[2] == 0
        && adapter->CurrentAddress[3] == 0
        && adapter->CurrentAddress[4] == 0
        && adapter->CurrentAddress[5] == 0) {

        ETH_COPY_NETWORK_ADDRESS(
            adapter->CurrentAddress,
            adapter->PermanentAddress);
    }

    DPR_INIT(("VNIFSetupPermAddr: Perm Addr = %02x-%02x-%02x-%02x-%02x-%02x\n",
        adapter->PermanentAddress[0],
        adapter->PermanentAddress[1],
        adapter->PermanentAddress[2],
        adapter->PermanentAddress[3],
        adapter->PermanentAddress[4],
        adapter->PermanentAddress[5]));

    DPR_INIT(("VNIFSetupPermAddr: Cur Addr = %02x-%02x-%02x-%02x-%02x-%02x\n",
        adapter->CurrentAddress[0],
        adapter->CurrentAddress[1],
        adapter->CurrentAddress[2],
        adapter->CurrentAddress[3],
        adapter->CurrentAddress[4],
        adapter->CurrentAddress[5]));

    return res;
}

static int
VNIFSetupXenFlags(PVNIF_ADAPTER Adapter)
{
    int res;
    unsigned int feature_rx_copy;
    char *val;

    val = xenbus_read(XBT_NIL, Adapter->vif.otherend, "feature-rx-copy", NULL);
    if (val == NULL) {
        DBG_PRINT(("VNIF: backend/feature-rx-copy missing.\n"));
        return 0;
    }

    feature_rx_copy = (unsigned int)cmp_strtoul(val, NULL, 10);
    Adapter->vif.copyall = feature_rx_copy;
    xenbus_free_string(val);

    return 1;
}

static int
VNIFSetupDevice(PVNIF_ADAPTER Adapter)
{
    struct netif_tx_sring *txs;
    struct netif_rx_sring *rxs;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    int err;

    DPR_INIT(("VNIF: VNIFSetupDevice - IN\n"));

    Adapter->vif.tx_ring_ref = GRANT_INVALID_REF;
    Adapter->vif.rx_ring_ref = GRANT_INVALID_REF;
    Adapter->vif.rx.sring = NULL;
    Adapter->vif.tx.sring = NULL;

    VNIF_ALLOCATE_MEMORY(
        txs,
        PAGE_SIZE,
        VNIF_POOL_TAG,
        NdisMiniportDriverHandle,
        NormalPoolPriority);
    if (txs == NULL) {
        DBG_PRINT(("VNIF: allocating tx ring page fail.\n"));
        status = STATUS_NO_MEMORY;
        goto fail;
    }

    SHARED_RING_INIT(txs);
    WIN_FRONT_RING_INIT(&Adapter->vif.tx, txs, PAGE_SIZE);

    err = xenbus_grant_ring(Adapter->vif.backend_id, virt_to_mfn(txs));
    if (err < 0) {
        NdisFreeMemory(txs, PAGE_SIZE, 0);
        goto fail;
    }
    Adapter->vif.tx_ring_ref = err;

    VNIF_ALLOCATE_MEMORY(
        rxs,
        PAGE_SIZE,
        VNIF_POOL_TAG,
        NdisMiniportDriverHandle,
        NormalPoolPriority);
    if (rxs == NULL) {
        DBG_PRINT(("VNIF: allocating rx ring page fail.\n"));
        status = STATUS_NO_MEMORY;
        goto fail;
    }

    SHARED_RING_INIT(rxs);
    WIN_FRONT_RING_INIT(&Adapter->vif.rx, rxs, PAGE_SIZE);

    err = xenbus_grant_ring(Adapter->vif.backend_id, virt_to_mfn(rxs));
    if (err < 0) {
        NdisFreeMemory(txs, PAGE_SIZE, 0);
        NdisFreeMemory(rxs, PAGE_SIZE, 0);
        goto fail;
    }
    Adapter->vif.rx_ring_ref = err;

    err = xenbus_alloc_evtchn(Adapter->vif.backend_id, &Adapter->vif.evtchn);
    if (err) {
        NdisFreeMemory(txs, PAGE_SIZE, 0);
        NdisFreeMemory(rxs, PAGE_SIZE, 0);
        goto fail;
    }

    DPR_INIT(("VNIF: VNIFSetupDevice - OUT success\n"));
    return 0;

 fail:
     DPR_INIT(("VNIF: VNIFSetupDevice - OUT error %x\n", err));
    return err;
}

static int
VNIFTalkToBackend(PVNIF_ADAPTER Adapter)
{
    int err;
    struct xenbus_transaction xbt;

    DPR_INIT(("VNIF: VNIFTalkToBackend - IN\n"));

    err = VNIFSetupDevice(Adapter);
    if (err) {
        goto out;
    }

again:
    DPR_INIT(("VNIF: xenbus starting transaction.\n"));
    err = xenbus_transaction_start(&xbt);
    if (err) {
        DBG_PRINT(("VNIF: xenbus starting transaction fail.\n"));
        goto out;
    }

    DPR_INIT(("VNIF: xenbus writing tx ring-ref.\n"));
    err = xenbus_printf(xbt, Adapter->vif.node_name, "tx-ring-ref", "%u",
                  Adapter->vif.tx_ring_ref);
    if (err) {
        DBG_PRINT(("VNIF: xenbus writing tx ring-ref fail.\n"));
        goto abort_transaction;
    }

    DPR_INIT(("VNIF: xenbus writing rx ring-ref.\n"));
    err = xenbus_printf(xbt, Adapter->vif.node_name, "rx-ring-ref", "%u",
                  Adapter->vif.rx_ring_ref);
    if (err) {
        DBG_PRINT(("VNIF: xenbus writing rx ring-ref fail.\n"));
        goto abort_transaction;
    }

    DPR_INIT(("VNIF: xenbus writing event-channel.\n"));
    err = xenbus_printf(xbt, Adapter->vif.node_name, "event-channel", "%u",
                  Adapter->vif.evtchn);
    if (err) {
        DBG_PRINT(("VNIF: xenbus writing event-channel fail.\n"));
        goto abort_transaction;
    }

    DPR_INIT(("VNIF: xenbus writing feature-rx-notify.\n"));
    err = xenbus_printf(xbt, Adapter->vif.node_name,
                        "feature-rx-notify", "%d", 1);
    if (err) {
        DBG_PRINT(("VNIF: xenbus writing feature-rx-notify fail.\n"));
        goto abort_transaction;
    }

    /* 1=copyall, 0=page-flipping */
    DPR_INIT(("VNIF: xenbus writing request-rx-copy.\n"));
    err = xenbus_printf(xbt, Adapter->vif.node_name, "request-rx-copy", "%u",
                  Adapter->vif.copyall);
    if (err) {
        DBG_PRINT(("VNIF: xenbus writing request-rx-copy fail.\n"));
        goto abort_transaction;
    }

    /* Setting "feature-gso-tcpv4" causes Hot replace D3 power test to
     * blue screen.
     */

    /*
    * this field is for backward compatibility
    */
    DPR_INIT(("VNIF: xenbus writing copy-delivery-offset.\n"));
    err = xenbus_printf(xbt, Adapter->vif.node_name,
                        "copy-delivery-offset", "%u", 0);
    if (err) {
        DBG_PRINT(("VNIF: xenbus writing copy-delivery-offset fail.\n"));
        goto abort_transaction;
    }

    /* If not supporting checksuming, need to tell backend. */
    DPR_INIT(("VNIF: xenbus writing feature-no-csum-offload.\n"));
    err = xenbus_printf(xbt, Adapter->vif.node_name,
        "feature-no-csum-offload", "%d",
        !(Adapter->cur_rx_tasks &
            (VNIF_CHKSUM_IPV4_TCP | VNIF_CHKSUM_IPV4_UDP)));
    if (err) {
        DBG_PRINT(("VNIF: xenbus writing feature-no-csum-offload fail.\n"));
        goto abort_transaction;
    }

    DPR_INIT(("VNIF: xenbus transcation end.\n"));
    err = xenbus_transaction_end(xbt, 0);
    if (err) {
        if (err == -EAGAIN) {
            goto again;
        }
        DBG_PRINT(("VNIF: xenbus transcation end fail.\n"));
        goto out;
    }

    DPR_INIT(("VNIF: VNIFTalkToBackend - OUT 1\n"));

    return 0;

abort_transaction:
    xenbus_transaction_end(xbt, 1);
out:
    DPR_INIT(("VNIF: VNIFTalkToBackend - OUT 0\n"));
    return err;
}

/*
 * we don't have any resource to handle, this function is for initializations
 * that must be done after connected to the backend.
 */
static NDIS_STATUS
VNIFInitRxGrants(PVNIF_ADAPTER adapter)
{
    PLIST_ENTRY entry;
    RCB *rcb;
    netif_rx_request_t *req;
    ULONG i;
    grant_ref_t ref;
    RING_IDX req_prod;

    DPR_INIT(("VNIF: VNIFInitRxGrants irql = %d - IN\n", KeGetCurrentIrql()));

    if (!adapter->vif.copyall) {
        DBG_PRINT(("VNIF: page-flipping is not supported.\n"));
        return NDIS_STATUS_FAILURE;
    }

    /* Putting all receive buffers' grant table refs to net ring */
    NdisAcquireSpinLock(&adapter->RecvLock);

    if (gnttab_alloc_grant_references(
            (uint16_t)adapter->num_rcb,
            &adapter->vif.gref_rx_head) < 0) {
        DBG_PRINT(("VNIF: netfront can't alloc rx grant refs\n"));
        NdisReleaseSpinLock(&adapter->RecvLock);
        return NDIS_STATUS_FAILURE;
    }

    NdisInitializeListHead(&adapter->RecvFreeList);
    for (i = 0; i < adapter->num_rcb /*VNIF_RCB_ARRAY_SIZE*/; i++) {
        rcb = adapter->RCBArray[i];
        ref = gnttab_claim_grant_reference(&adapter->vif.gref_rx_head);
        if ((signed short)ref < 0) {
            DBG_PRINT(("VNIF: gnttab_claim_grant_reference gref_rx_head.\n"));
            NdisReleaseSpinLock(&adapter->RecvLock);
            return NDIS_STATUS_FAILURE;
        }

        rcb->grant_rx_ref = ref;
        gnttab_grant_foreign_access_ref(
            ref,
            adapter->vif.backend_id,
            virt_to_mfn(rcb->page),
            0);
        InsertTailList(&adapter->RecvFreeList, &rcb->list);
    }

    req_prod = adapter->vif.rx.req_prod_pvt;
    for (i = 0; i < NET_RX_RING_SIZE; i++) {
        rcb = (RCB *) RemoveHeadList(&adapter->RecvFreeList);
        req = RING_GET_REQUEST(&adapter->vif.rx, req_prod + i);
        req->gref = rcb->grant_rx_ref;
        req->id = (UINT16) rcb->index;
    }

    KeMemoryBarrier();
    adapter->vif.rx.req_prod_pvt = req_prod + i;
    RING_PUSH_REQUESTS(&adapter->vif.rx);

    NdisReleaseSpinLock(&adapter->RecvLock);

    DPR_INIT(("Xennet using %d receive buffers.\n", adapter->num_rcb));
    DPR_INIT(("VNIF: VNIFInitRxGrants `- OUT\n"));
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
VNIFInitTxGrants(PVNIF_ADAPTER adapter)
{
#ifdef VNIF_COPY_TX
    TCB *tcb;
#endif
    xen_ulong_t xi;
    ULONG mfn;
    uint32_t i;
    grant_ref_t ref;

    /* Pre-allocate grant table references for send. */
    DPR_INIT(("VNIF: VNIFInitTxGrants - gnttab_alloc_grant_references\n"));
    if (gnttab_alloc_grant_references(TX_MAX_GRANT_REFS,
            &adapter->vif.gref_tx_head) < 0) {
        DBG_PRINT(("VNIF: netfront can't alloc tx grant refs\n"));
        return NDIS_STATUS_FAILURE;
    }

#ifdef VNIF_COPY_TX
    /* Allocate for each TCB, because sizeof(TCB) is less than PAGE_SIZE, */
    /* it will not cross page boundary. */
    NdisInitializeListHead(&adapter->SendFreeList);
    for (i = 0; i < VNIF_MAX_BUSY_SENDS; i++) {
        tcb = adapter->TCBArray[i];
        ref = gnttab_claim_grant_reference(&adapter->vif.gref_tx_head);
        if ((signed short)ref < 0) {
            DBG_PRINT(("VNIF: fail to claim grant reference for tx.\n"));
            return NDIS_STATUS_FAILURE;
        }

        mfn = virt_to_mfn(tcb->data);
        gnttab_grant_foreign_access_ref(
            ref, adapter->vif.backend_id, mfn, GNTMAP_readonly);
        tcb->grant_tx_ref = ref;

        NdisInterlockedInsertTailList(
            &adapter->SendFreeList,
            &tcb->list,
            &adapter->SendLock);
    }
#else
    ref = gnttab_claim_grant_reference(&adapter->vif.gref_tx_head);
    if ((signed short)ref < 0) {
        DBG_PRINT(("VNIF: fail to claim grant reference for tx.\n"));
        return NDIS_STATUS_FAILURE;
    }
    mfn = virt_to_mfn(adapter->zero_data);
    gnttab_grant_foreign_access_ref(
        ref, adapter->vif.backend_id, mfn, GNTMAP_readonly);
    adapter->zero_ref = ref;
    adapter->zero_offset = BYTE_OFFSET(adapter->zero_data);

    for (xi = 0; xi < VNIF_MAX_BUSY_SENDS; xi++) {
        adapter->vif.tx_packets[xi] = (NDIS_PACKET *)(xi + 1);
        adapter->vif.grant_tx_ref[xi] =
            gnttab_claim_grant_reference(&adapter->vif.gref_tx_head);
    }
    adapter->vif.tx_id_alloc_head = 0;
#endif
    return NDIS_STATUS_SUCCESS;
}

static uint32_t
VNIFOutstanding(PVNIF_ADAPTER adapter)
{
    struct netif_tx_request *tx;
    TCB *tcb;
    RING_IDX cons, prod;
    uint32_t cnt;
    uint32_t gnt_flags;
    uint32_t outstanding;

    outstanding = 0;
    cnt = 0;
    prod = adapter->vif.tx.req_prod_pvt;

    for (cnt = 0; cnt < VNIF_MAX_BUSY_SENDS; cnt++) {
        tcb = adapter->TCBArray[cnt];
        if (!tcb) {
            continue;
        }
        gnt_flags = gnttab_query_foreign_access_flags(tcb->grant_tx_ref);
        if (gnt_flags & (GTF_reading | GTF_writing)) {
            outstanding++;
            DBG_PRINT(("\n\tid %x, refs %x, flags %x",
                cnt, tcb->grant_tx_ref, gnt_flags));
#ifdef VNIF_TRACK_TX
            DBG_PRINT((", granted %x, ringidx %x.",
                tcb->granted, tcb->ringidx));
#endif
        }
    }

    DBG_PRINT(("\nVNIF: Outstanding refs %d, busy %d: out.\n",
        outstanding, adapter->nBusySend));
    return outstanding;
}

uint32_t
VNIFQuiesce(PVNIF_ADAPTER adapter)
{
    KIRQL old_irql;
    uint32_t waiting;
    uint32_t wait_count = 0;
    char *buf;

    if (VNIF_TEST_FLAG(adapter, VNF_DISCONNECTED)) {
        DBG_PRINT(("VNIFQuiesce: adapter already discconnected, %x\n",
            adapter->Flags));
        return 0;
    }
#ifdef DBG
    buf = xenbus_read(XBT_NIL, adapter->vif.otherend, "state", NULL);
    if (buf) {
        DBG_PRINT(("VNIFQuiesce: backend state %s, ", buf));
        xenbus_free_string(buf);
    }
    buf = xenbus_read(XBT_NIL, adapter->vif.node_name, "state", NULL);
    if (buf) {
        DBG_PRINT(("frontend state %s\n", buf));
        xenbus_free_string(buf);
    }
#endif
    if (adapter->nBusySend) {
        DBG_PRINT((
            "VNIFQuiesce %s: busy sends %x: flags %x, pvt %x, rcons %x\n",
            &adapter->vif.node_name[7], adapter->nBusySend, adapter->Flags,
            adapter->vif.tx.req_prod_pvt, adapter->vif.tx.rsp_cons));
    }
    do {
        if (adapter->nBusySend) {
            if (adapter->vif.evtchn) {
                if (notify_remote_via_evtchn(adapter->vif.evtchn)) {
                    DBG_PRINT(("VNIFQuiesce notify failed.\n"));
                }
            }
            KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
            VNIFInterruptDpc(NULL, adapter, NULL, NULL);
            KeLowerIrql(old_irql);
        }

        /* Only need to wory about the receives that are in the process of */
        /* VNIFReceivePackets and xennet_return_packet. */
        waiting = adapter->nBusyRecv;
        waiting += adapter->nBusySend;

        if (!waiting) {
            break;
        }

        if (adapter->resource_timeout) {
            wait_count++;
            NdisMSleep(1000000);  /* 1 second */
        }
    } while (waiting && wait_count < adapter->resource_timeout);

    if (waiting) {
        DBG_PRINT(("VNIFQuiesce %s: flags %x, waiting %d, wait_count %d.\n",
            &adapter->vif.node_name[7], adapter->Flags, waiting, wait_count));
        if (adapter->nBusyRecv) {
            DBG_PRINT(("\toutstanding receives %d: pvt %x, srsp %x, rsc %x\n",
                adapter->nBusyRecv,
                adapter->vif.rx.req_prod_pvt,
                adapter->vif.rx.sring->rsp_prod,
                adapter->vif.rx.rsp_cons));
        }
        if (adapter->nBusySend) {
            DBG_PRINT(("\toutstanding sends %d: pvt %x, rcons %x\n",
                adapter->nBusySend,
                adapter->vif.tx.req_prod_pvt,
                adapter->vif.tx.rsp_cons));
            DBG_PRINT(("\tsring: req_prod %x, rsp_prod %x, ",
                adapter->vif.tx.sring->req_prod,
                adapter->vif.tx.sring->rsp_prod));
            DBG_PRINT(("req_event %x, rsp_event %x\n",
                adapter->vif.tx.sring->req_event,
                adapter->vif.tx.sring->rsp_event));
            if (VNIFOutstanding(adapter) == 0) {
                DBG_PRINT((
                    "VNIFQuiesce %s: failed to find outstanding sends.\n",
                    &adapter->vif.node_name[7]));
                waiting = 0;
            }
        }
    }
    DPR_INIT(("VNIF: VNIFQuiesce OUT\n"));
    return waiting;
}

static void
VNIFWaitStateChange(PVNIF_ADAPTER adapter,
    enum xenbus_state front_state, enum xenbus_state end_state)
{
    char *buf;
    uint32_t i;
    enum xenbus_state backend_state;

    DPR_INIT(("VNIFWaitStateChange: switching front end state to %d\n",
        front_state));
    for (i = 0; i < 1000; i++) {
        if (xenbus_switch_state(adapter->vif.node_name, front_state) == 0) {
            DPR_INIT((
                "VNIFWaitStateChange: front end state switched to %d: %d\n",
                front_state, i));
            break;
        }
        NdisMSleep(1000);
    }
    DPR_INIT(("VNIFWaitStateChange: waiting for backend state to be %d\n",
        end_state));
    for (i = 0; i < 1000; i++) {
        buf = xenbus_read(XBT_NIL, adapter->vif.otherend, "state", NULL);
        if (buf) {
            backend_state = (enum xenbus_state)cmp_strtoul(buf, NULL, 10);
            xenbus_free_string(buf);
            if (backend_state == end_state) {
                break;
            }
        }
        NdisMSleep(1000);
    }
    DPR_INIT(("VNIFWaitStateChange: waited %d, for state %d, reached %d\n",
        i, end_state, backend_state));
}

void
VNIFCleanupRings(PVNIF_ADAPTER adapter)
{
#ifdef VNIF_COPY_TX
    TCB *tcb;
#endif
    RCB *rcb;
    uint32_t i;

#ifdef VNIF_COPY_TX
    DPR_INIT(("VNIF: VNIFCleanupRings XENNET_COPY_TX\n"));
    for (i = 0; i < VNIF_MAX_BUSY_SENDS; i++) {
        tcb = adapter->TCBArray[i];
        if (!tcb) {
            continue;
        }
        if (tcb->grant_tx_ref != GRANT_INVALID_REF) {
            gnttab_end_foreign_access_ref(
                tcb->grant_tx_ref, GNTMAP_readonly);
            gnttab_release_grant_reference(
                &adapter->vif.gref_tx_head, tcb->grant_tx_ref);
            tcb->grant_tx_ref = GRANT_INVALID_REF;
        }
    }
#else
    if (adapter->zero_ref != GRANT_INVALID_REF) {
        gnttab_end_foreign_access_ref(
          adapter->zero_ref, GNTMAP_readonly);
        gnttab_release_grant_reference(
          &adapter->vif.gref_tx_head, adapter->zero_ref);
        adapter->zero_ref = GRANT_INVALID_REF;
    }
    for (i = 0; i < VNIF_MAX_BUSY_SENDS; i++) {
        if (adapter->vif.grant_tx_ref[i] != GRANT_INVALID_REF) {
            gnttab_end_foreign_access_ref(
                adapter->vif.grant_tx_ref[i], GNTMAP_readonly);

            gnttab_release_grant_reference(
                &adapter->vif.gref_tx_head, adapter->vif.grant_tx_ref[i]);
            adapter->vif.grant_tx_ref[i] = GRANT_INVALID_REF;
        }
    }
#endif

    if (adapter->vif.tx_ring_ref != GRANT_INVALID_REF) {
        DPR_INIT(("VNIF: VNIFCleanupRings - end tx ring ref\n"));
        gnttab_end_foreign_access(adapter->vif.tx_ring_ref, 0);
        adapter->vif.tx_ring_ref = GRANT_INVALID_REF;
    }

    if (adapter->vif.gref_tx_head != GRANT_INVALID_REF) {
        DPR_INIT(("VNIF: VNIFCleanupRings gnttab_free_grant_references tx %x\n",
            adapter->vif.gref_tx_head));
        gnttab_free_grant_references(adapter->vif.gref_tx_head);
        adapter->vif.gref_tx_head = GRANT_INVALID_REF;
    }

    /* Now do the receive resources. */
    for (i = 0; i < NET_RX_RING_SIZE; i++) {
        rcb = adapter->RCBArray[i];
        if (!rcb) {
            continue;
        }

        if (rcb->grant_rx_ref != GRANT_INVALID_REF) {
            gnttab_end_foreign_access_ref(
                rcb->grant_rx_ref, 0);
            gnttab_release_grant_reference(
                &adapter->vif.gref_rx_head, rcb->grant_rx_ref);
            rcb->grant_rx_ref = GRANT_INVALID_REF;
        }
    }
    if (adapter->vif.rx_ring_ref != GRANT_INVALID_REF) {
        DPR_INIT(("VNIF: VNIFCleanupRings - end rx ring ref\n"));
        gnttab_end_foreign_access(adapter->vif.rx_ring_ref, 0);
        adapter->vif.rx_ring_ref = GRANT_INVALID_REF;
    }

    if (adapter->vif.gref_rx_head != GRANT_INVALID_REF) {
        DPR_INIT(("VNIF: VNIFCleanupRings gnttab_free_grant_references rx %x\n",
            adapter->vif.gref_rx_head));
        gnttab_free_grant_references(adapter->vif.gref_rx_head);
        adapter->vif.gref_rx_head = GRANT_INVALID_REF;
    }
}

uint32_t
VNIFDisconnectBackend(PVNIF_ADAPTER adapter)
{
    xenbus_release_device_t release_data;
    BOOLEAN cancelled = TRUE;

    DPR_INIT(("VNIF: VNIFDisconnectBackend - IN\n"));

    if (VNIF_TEST_FLAG(adapter, VNF_DISCONNECTED)) {
        DBG_PRINT(("VNIFDisconnectBackend: adapter already discconnected, %x\n",
            adapter->Flags));
        return 0;
    }

    /* Wait to become idle for all sends and receives. */
    if (VNIFQuiesce(adapter)) {
        return 1;
    }

    VNIF_SET_FLAG(adapter, VNF_DISCONNECTED);

    /* Make sure we are out of the DPC and that NDIS doesn't have any */
    /* of our receives before continuing. */
    if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_DPC_IN_PROGRESS)
            || adapter->nBusyRecv) {
        DBG_PRINT(("VNIFDisconnect: wait on DPC or receives. f %x, r %d s %d\n",
            adapter->Flags, adapter->nBusyRecv, adapter->nBusySend));
    }
    while (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_DPC_IN_PROGRESS)
            || adapter->nBusyRecv)
        NdisMSleep(500000);  /* 1/2 second */

    if (adapter->vif.evtchn) {
        DPR_INIT(("VNIF: VNIFDisconnectBackend unregister_dpc_from_evtchn %d\n",
            adapter->vif.evtchn));
        unregister_dpc_from_evtchn(adapter->vif.evtchn);
        xenbus_free_evtchn(adapter->vif.evtchn);
        adapter->vif.evtchn = 0;
    }

    if (!VNIF_TEST_FLAG(adapter, VNF_ADAPTER_DETACHING)) {
        /* Switch the state to closing, closed, initializign.  This will */
        /* allow the backend to release its references. */
        unregister_xenbus_watch(&adapter->vif.backend_watch);
        unregister_xenbus_watch(&adapter->vif.watch);
        VNIFWaitStateChange(adapter, XenbusStateClosing, XenbusStateClosing);
        VNIFWaitStateChange(adapter, XenbusStateClosed, XenbusStateClosed);
        VNIFWaitStateChange(adapter, XenbusStateInitialising,
            XenbusStateInitWait);

        release_data.action = RELEASE_ONLY;
        release_data.type = vnif;
        xenbus_release_device(adapter, NULL, release_data);
    }

    VNIFCleanupRings(adapter);

    /* cancel all the timers */
    DPR_INIT(("VNIF: NdisCancelTimer\n"));
    if (adapter->pv_stats) {
        VNIF_CANCEL_TIMER(adapter->pv_stats->stat_timer, &cancelled);
    }
    VNIF_CANCEL_TIMER(adapter->rcv_timer, &cancelled);
    VNIF_CANCEL_TIMER(adapter->ResetTimer, &cancelled);

    if (cancelled) {
        DPR_INIT(("VNIF: halt VNIFFreeQueuedRecvPackets\n"));
        VNIFFreeQueuedRecvPackets(adapter);
    }

    DPR_INIT(("VNIF: VNIFDisconnectBackend - flags %x. OUT\n", adapter->Flags));
    return 0;
}

static void
xennet_frontend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)watch->context;
    char *buf;
    uint32_t link_status;

    buf = xenbus_read(XBT_NIL, adapter->vif.node_name, "link-status", NULL);
    if (buf == NULL || IS_ERR(buf)) {
        return;
    }

    link_status = (uint32_t)cmp_strtoul(buf, NULL, 10);
    xenbus_free_string(buf);
    DPR_INIT(("xennet_frontend_changed: %p, link status = %d.\n",
        adapter, link_status));

    if (link_status != !VNIF_TEST_FLAG(adapter, VNF_ADAPTER_NO_LINK)) {
        if (link_status) {
            VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_NO_LINK);
        } else {
            VNIF_SET_FLAG(adapter, VNF_ADAPTER_NO_LINK);
        }

        /* Indicate the media event */
        DPR_INIT(("xennet_frontend_changed: indicating status change.\n"));
        VNIFIndicateLinkStatus(adapter, link_status);
#ifdef DBG
        adapter->dbg_print_cnt = 0;
#endif
    }
}

static void
xennet_backend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)watch->context;
    char *buf;
    enum xenbus_state backend_state;
    xenbus_release_device_t release_data;

    DPR_INIT(("xennet:backend_changed for %s: node %s.\n",
        vec[0], adapter->vif.node_name));

    buf = xenbus_read(XBT_NIL, adapter->vif.otherend, "state", NULL);
    if (buf == NULL) {
        xenbus_printf(XBT_NIL, adapter->vif.node_name,
                      "reading state", "%x", buf);
        DBG_PRINT(("xennet:backend_changed failed to read state from\n"));
        DBG_PRINT(("         %s.\n", adapter->vif.otherend));
        backend_state = XenbusStateClosed;
    } else {
        backend_state = (enum xenbus_state)cmp_strtoul(buf, NULL, 10);
        xenbus_free_string(buf);
        DPR_INIT(("xennet:backend_changed to state %d.\n", backend_state));
    }
    if (backend_state == XenbusStateClosing) {
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_DETACHING);

        while (VNIFQuiesce(adapter)) {
            NdisMSleep(1000000);  /* 1 second */
        }

        unregister_xenbus_watch(&adapter->vif.backend_watch);
        unregister_xenbus_watch(&adapter->vif.watch);

        DPR_INIT(("xennet:backend_changed switching to state closed.\n"));
        xenbus_switch_state(adapter->vif.node_name, XenbusStateClosed);

        DPR_INIT(("xennet:backend_changed: xenbus_release_device.\n"));
        release_data.action = RELEASE_REMOVE;
        release_data.type = vnif;
        xenbus_release_device(adapter, NULL, release_data);
    }
    DPR_INIT(("xennet:backend_changed for %s: out.\n", adapter->vif.node_name));
}

static void
xennet_resume_failue_cleanup(PVNIF_ADAPTER adapter)
{
    xenbus_release_device_t release_data;
    BOOLEAN cancelled = TRUE;

    DPR_INIT(("xennet_resume_failue_cleanup - IN\n"));

    VNIF_SET_FLAG(adapter, VNF_DISCONNECTED);

    DPR_INIT(("xennet_resume_failue_cleanup - OUT\n"));
}

static void
MPResume(PVNIF_ADAPTER adapter, uint32_t suspend_canceled)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    DPR_INIT(("MPResume: %p, %x\n", adapter, suspend_canceled));
    if (suspend_canceled) {
        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SUSPENDED);
    } else {
#ifdef DBG
        adapter->dbg_print_cnt = 0;
#endif
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_RESUMING);
        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SUSPENDED);

        if (adapter->nBusySend) {
#ifdef NDIS60_MINIPORT
            DBG_PRINT(("MPResume: starting, nBusySend = %d, nWaitSend = %d\n",
                adapter->nBusySend, adapter->nWaitSend));
#else
            DBG_PRINT(("MPResume: starting, nBusySend = %d\n",
                adapter->nBusySend));
#endif
        }
        if (adapter->nBusySend) {
            vnif_complete_lost_sends(adapter);
        }
        VNIFFreeAdapterInterface(adapter);
        status = VNIFFindAdapter(adapter);
        if (status == STATUS_SUCCESS) {
            status = VNIFSetupAdapterInterface(adapter);
            if (status == STATUS_SUCCESS) {
                VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_RESUMING);
            }
        }
        if (adapter->nBusySend) {
#ifdef NDIS60_MINIPORT
            DBG_PRINT(("MPResume %s: nBusySend %d, nWaitSend %d, flags 0x%x\n",
                adapter->vif.otherend, adapter->nBusySend,
                adapter->nWaitSend, adapter->Flags));
#else
            DBG_PRINT(("MPResume %s: nBusySend = %d, flags = 0x%x\n",
                adapter->vif.otherend, adapter->nBusySend, adapter->Flags));
#endif
        }
        if (status == STATUS_SUCCESS) {
            vnif_send_arp(adapter);
        } else {
            DBG_PRINT(("MPResume %s: failed resume = 0x%x\n",
                adapter->vif.node_name, status));
            xennet_resume_failue_cleanup(adapter);
        }
    }
}

static uint32_t
MPSuspend(PVNIF_ADAPTER adapter, uint32_t reason)
{
    uint32_t waiting;

    DBG_PRINT(("MPSuspend: %s, due to %x\n", adapter->vif.node_name, reason));
    VNIF_SET_FLAG(adapter, VNF_ADAPTER_SUSPENDING);
    if (reason == SHUTDOWN_suspend) {
        /* We could force a wait here, but then that's what */
        /* adapter->resource_timeout is for. */
        waiting = VNIFQuiesce(adapter);
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_SUSPENDED);
        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SUSPENDING);

        /* Make sure we are out of the DPC and that NDIS doesn't have any */
        /* of our receives before returning. */
        if (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_DPC_IN_PROGRESS)
                || adapter->nBusyRecv) {
            DBG_PRINT(("MPSuspend: wait on DPC or receives. f %x, s %d r %d\n",
                adapter->Flags, adapter->nBusySend, adapter->nBusyRecv));
        }
        while (VNIF_TEST_FLAG(adapter, VNF_ADAPTER_DPC_IN_PROGRESS)
                || adapter->nBusyRecv) {
            NdisMSleep(500000);  /* 1/2 second */
        }
    } else {
        waiting = VNIFDisconnectBackend(adapter);
        if (waiting == 0) {
            VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SUSPENDING);
            VNIFFreeAdapterInterface(adapter);
        }
    }
    DBG_PRINT(("MPSuspend: OUT, waiting %d for sends %d, recv %d\n",
        waiting, adapter->nBusySend, adapter->nBusyRecv));
    return waiting;
}

static uint32_t
MPIoctl(PVNIF_ADAPTER adapter, pv_ioctl_t data)
{
    uint32_t cc = 0;

    switch (data.cmd) {
    case PV_SUSPEND:
        cc = MPSuspend(adapter, data.arg);
        break;
    case PV_RESUME:
        MPResume(adapter, data.arg);
        break;
    case PV_ATTACH:
        break;
    case PV_DETACH:
        break;
    default:
        break;
    }
    return cc;
}
