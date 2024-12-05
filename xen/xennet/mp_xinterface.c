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
VNIFX_ALLOCATE_SHARED_MEMORY(struct _VNIF_ADAPTER *adapter,
    void **va, PHYSICAL_ADDRESS *pa, uint32_t len, NDIS_HANDLE hndl)
{
#if NDIS_SUPPORT_NDIS6
    *va = NdisAllocateMemoryWithTagPriority(
        hndl,
        len,
        VNIF_POOL_TAG,
        NormalPoolPriority);
#else
    NdisAllocateMemoryWithTag(va, PAGE_SIZE, VNIF_POOL_TAG);
#endif
        pa->QuadPart = __pa(*va);
}

void
VNIFX_FreeAdapterInterface(PVNIF_ADAPTER adapter)
{
    UINT i;

    RPRINTK(DPRTL_ON, ("VNIFFreeXenAdapter: IN\n"));

    if (adapter->node_name) {
        RPRINTK(DPRTL_ON,
            ("VNIFFreeXenAdapter: freeing %s\n", adapter->node_name));
        NdisFreeMemory(adapter->node_name,
            strlen(adapter->node_name) + 1, 0);
        adapter->node_name = NULL;
    }
    if (adapter->u.x.otherend) {
        RPRINTK(DPRTL_ON,
            ("VNIFFreeXenAdapter: freeing %s\n", adapter->u.x.otherend));
        NdisFreeMemory(adapter->u.x.otherend,
            strlen(adapter->u.x.otherend) + 1, 0);
        adapter->u.x.otherend = NULL;
    }

    if (adapter->path != NULL) {
        for (i = 0; i < adapter->num_paths; i++) {
            if (adapter->path[i].u.xq.rx_front_ring.sring) {
                RPRINTK(DPRTL_ON,
                        ("VNIFFreeXenAdapter: freeing adapter->rx.sring\n"));
                NdisFreeMemory(adapter->path[i].u.xq.rx_front_ring.sring,
                               PAGE_SIZE, 0);
                adapter->path[i].u.xq.rx_front_ring.sring = NULL;
            }
            if (adapter->path[i].u.xq.tx_front_ring.sring) {
                RPRINTK(DPRTL_ON,
                        ("VNIFFreeXenAdapter: freeing adapter->tx.sring\n"));
                NdisFreeMemory(adapter->path[i].u.xq.tx_front_ring.sring,
                               PAGE_SIZE, 0);
                adapter->path[i].u.xq.tx_front_ring.sring = NULL;
            }
        }
    }

    RPRINTK(DPRTL_ON, ("VNIFFreeXenAdapter: OUT\n"));
}

void
VNIFX_CleanupInterface(PVNIF_ADAPTER adapter, NDIS_STATUS status)
{
    xenbus_release_device_t release_data;

    if (status == NDIS_STATUS_SUCCESS) {
        release_data.action = RELEASE_REMOVE;
    } else {
        release_data.action = RELEASE_ONLY;
    }
    release_data.type = vnif;

    VNIFCleanupRings(adapter);
    xenbus_release_device(adapter, NULL, release_data);
}

NDIS_STATUS
VNIFX_FindAdapter(PVNIF_ADAPTER adapter)
{
    PUCHAR nodename, otherend, str, ptr;
    NDIS_STATUS status;
    ULONG val;
    UINT i;

    RPRINTK(DPRTL_ON, ("VNIFFindXenAdapter: claim %p\n", adapter));
    status = xenbus_claim_device(adapter, NULL, vnif, none, MPIoctl, MPIoctl);
    if (status != NDIS_STATUS_SUCCESS && status != STATUS_RESOURCE_IN_USE) {
        return status;
    }

    status = NDIS_STATUS_SUCCESS;
    do {
        /*
         * All adapter fields are zeroed out when adapter was allocated.
         * No need to set any values to 0.
         */

        VNIF_ALLOCATE_SHARED_MEMORY = VNIFX_ALLOCATE_SHARED_MEMORY;

        /* Nodename */
        RPRINTK(DPRTL_ON, ("VNIFFindXenAdapter: IN VNIFGetNodenameFromPDO\n"));
        nodename = xenbus_get_nodename_from_pdo(adapter->Pdo);
        if (nodename == NULL) {
            PRINTK(("VNIF: failed to get nodename.\n"));
            status = NDIS_STATUS_FAILURE;
            break;
        }
        i = strlen(nodename) + 1;
        VNIF_ALLOCATE_MEMORY(
            adapter->node_name,
            i,
            VNIF_POOL_TAG,
            NdisMiniportDriverHandle,
            NormalPoolPriority);
        if (adapter->node_name == NULL) {
            PRINTK(("VNIF: allocating memory for nodename fail.\n"));
            status = STATUS_NO_MEMORY;
            break;
        }
        NdisMoveMemory(adapter->node_name, nodename, i);

        /* Otherend */
        otherend = xenbus_get_otherend_from_pdo(adapter->Pdo);
        if (otherend == NULL) {
            PRINTK(("VNIF: failed to get otherend.\n"));
            status = NDIS_STATUS_FAILURE;
            break;
        }
        i = strlen(otherend) + 1;
        VNIF_ALLOCATE_MEMORY(
            adapter->u.x.otherend,
            i,
            VNIF_POOL_TAG,
            NdisMiniportDriverHandle,
            NormalPoolPriority);
        if (adapter->u.x.otherend == NULL) {
            PRINTK(("VNIF: allocating memory for otherend fail.\n"));
            status = STATUS_NO_MEMORY;
            break;
        }
        NdisMoveMemory(adapter->u.x.otherend, otherend, i);

        /* Backend */
        adapter->u.x.backend_id = VNIFGetBackendIDFromPDO(adapter->Pdo);
        if (adapter->u.x.backend_id == (domid_t)-1) {
            PRINTK(("VNIF: failed to get backend id.\n"));
            status = NDIS_STATUS_FAILURE;
            break;
        }

        adapter->hw_tasks |= VNIF_CHKSUM_TXRX_SUPPORTED;
        if (xenbus_exists(XBT_NIL, adapter->u.x.otherend,
                          "feature-no-csum-offload")) {
            RPRINTK(DPRTL_ON, ("VNIF backend no csum offload exists.\n"));
            str = xenbus_read(XBT_NIL, adapter->u.x.otherend,
                "feature-no-csum-offload", &i);
            if (str) {
                RPRINTK(DPRTL_ON, ("VNIF backend no csum offload read %s.\n",
                                   str));
                val = (ULONG)cmp_strtoul(str, &ptr, 10);
                RPRINTK(DPRTL_ON, ("VNIF backend no csum offload val %d.\n",
                                   val));
                if (ptr != str && val) {
                    adapter->hw_tasks &= ~VNIF_CHKSUM_TXRX_SUPPORTED;
                    RPRINTK(DPRTL_ON, ("VNIF backend csum not supported.\n"));
                }
                xenbus_free_string(str);
            }
        }

        if (xenbus_exists(XBT_NIL, adapter->u.x.otherend,
                          "feature-ipv6-csum-offload")) {
            RPRINTK(DPRTL_ON, ("VNIF backend supports ipv6 csum offload.\n"));
            str = xenbus_read(XBT_NIL, adapter->u.x.otherend,
                "feature-ipv6-csum-offload", &i);
            if (str) {
                RPRINTK(DPRTL_ON, ("VNIF backend ipv6 csum offload read %s.\n",
                                   str));
                val = (ULONG)cmp_strtoul(str, &ptr, 10);
                RPRINTK(DPRTL_ON, ("VNIF backend ipv6 csum offload val %d.\n",
                                   val));
                if (ptr != str && val) {
                    adapter->hw_tasks |= VNIF_CHKSUM_TXRX_IPV6_SUPPORTED;
                    RPRINTK(DPRTL_ON, ("VNIF enabling frontend ipv6 csum.\n"));
                }
                xenbus_free_string(str);
            }
        }

        if (xenbus_exists(XBT_NIL, adapter->u.x.otherend,
                          "feature-gso-tcpv4")) {
            RPRINTK(DPRTL_ON, ("VNIF backend LSO exists.\n"));
            str = xenbus_read(XBT_NIL, adapter->u.x.otherend,
                "feature-gso-tcpv4", &i);
            if (str) {
                RPRINTK(DPRTL_ON, ("VNIF backend LSO read %s.\n", str));
                val = (ULONG)cmp_strtoul(str, &ptr, 16);
                RPRINTK(DPRTL_ON, ("VNIF backend LSO val %d.\n", val));
                if (ptr != str && val) {
                    adapter->hw_tasks |= VNIF_LSO_SUPPORTED;
                    RPRINTK(DPRTL_ON, ("VNIF backend LSO supported.\n"));
                }
                xenbus_free_string(str);
            }
        }

        if (xenbus_exists(XBT_NIL, adapter->u.x.otherend,
                          "feature-gso-tcpv6")) {
            RPRINTK(DPRTL_ON, ("VNIF backend LSO IPv6 exists.\n"));
            str = xenbus_read(XBT_NIL, adapter->u.x.otherend,
                "feature-gso-tcpv6", &i);
            if (str) {
                RPRINTK(DPRTL_ON, ("VNIF backend LSO IPv6 read %s.\n", str));
                val = (ULONG)cmp_strtoul(str, &ptr, 16);
                RPRINTK(DPRTL_ON, ("VNIF backend LSO IPv6 val %d.\n", val));
                if (ptr != str && val) {
                    adapter->hw_tasks |= VNIF_LSO_V2_IPV6_SUPPORTED;
                    RPRINTK(DPRTL_ON, ("VNIF backend LSO IPv6 supported.\n"));
                }
                xenbus_free_string(str);
            }
        }

        adapter->num_hw_queues = 1;
        adapter->b_multi_queue = FALSE;
        if (xenbus_exists(XBT_NIL, adapter->u.x.otherend,
                          "multi-queue-max-queues")) {
            RPRINTK(DPRTL_ON,
                    ("VNIF backend multi-queue-max-queues exists.\n"));
            str = xenbus_read(XBT_NIL, adapter->u.x.otherend,
                              "multi-queue-max-queues", NULL);
            if (str) {
                RPRINTK(DPRTL_ON, ("  multi-queue-max-queues str: %s\n",
                                   str));
                adapter->num_hw_queues = (uint16_t)cmp_strtoul(str, NULL, 10);
                adapter->b_multi_queue = TRUE;
                adapter->b_multi_signaled = TRUE;
                RPRINTK(DPRTL_ON, ("  multi-queue-max-queues val: %d\n",
                                   adapter->num_hw_queues));
                xenbus_free_string(str);
            }
        }

        adapter->u.x.feature_split_evtchn = 0;
        if (xenbus_exists(XBT_NIL, adapter->u.x.otherend,
                          "feature-split-event-channels")) {
            RPRINTK(DPRTL_ON,
                    ("VNIF backend feature-split-event-channels exists.\n"));
            str = xenbus_read(XBT_NIL, adapter->u.x.otherend,
                              "feature-split-event-channels", NULL);
            if (str) {
                RPRINTK(DPRTL_ON, ("  feature-split-event-channels str: %s\n",
                                   str));
                adapter->u.x.feature_split_evtchn =
                    (UCHAR)cmp_strtoul(str, NULL, 10);
                RPRINTK(DPRTL_ON, ("  feature-split-event-channels val: %d\n",
                                   adapter->u.x.feature_split_evtchn));
                xenbus_free_string(str);
            }
        }

        adapter->duplex_state = MediaDuplexStateFull;

        /* MAC */
        if (!VNIFSetupPermanentAddress(adapter)) {
            PRINTK(("VNIF: set NIC MAC fail.\n"));
            status = NDIS_STATUS_FAILURE;
            break;
        }

        RPRINTK(DPRTL_ON, ("VNIFFindXenAdapter: OUT %p, %s\n",
            adapter, adapter->node_name));
    } while (FALSE);

    if (status != NDIS_STATUS_SUCCESS) {
        VNIFFreeAdapterInterface(adapter);
    }
    return status;
}

static enum xenbus_state
xennet_get_backend_state(PVNIF_ADAPTER adapter)
{
    char *buf;
    enum xenbus_state backend_state;

    buf = xenbus_read(XBT_NIL, adapter->u.x.otherend, "state", NULL);
    if (buf != NULL) {
        backend_state = (enum xenbus_state)cmp_strtoul(buf, NULL, 10);
        xenbus_free_string(buf);
        RPRINTK(DPRTL_ON,
            ("xennet:backend_changed to state %d.\n", backend_state));
    } else {
        backend_state = XenbusStateClosed;
        xenbus_printf(XBT_NIL, adapter->node_name,
                      "reading state", "%x", buf);
        PRINTK(("xennet_get_backend_stat:failed to read state from\n"));
        PRINTK(("         %s.\n", adapter->u.x.otherend));
    }
    return backend_state;
}

static void
vnifx_setup_watches(PVNIF_ADAPTER adapter)
{
    adapter->u.x.watch.callback = xennet_frontend_changed;
    adapter->u.x.watch.node = adapter->node_name;
    adapter->u.x.watch.flags = XBWF_new_thread;
    adapter->u.x.watch.context = adapter;

    adapter->u.x.backend_watch.callback = xennet_backend_changed;
    adapter->u.x.backend_watch.node = adapter->u.x.otherend;
    adapter->u.x.backend_watch.flags = XBWF_new_thread;
    adapter->u.x.backend_watch.context = adapter;

    /* Now register for the watch. */
    RPRINTK(DPRTL_INIT, ("%s: register_xenbus_watch %p, %s\n",
                         __func__, adapter, adapter->node_name));
    register_xenbus_watch(&adapter->u.x.watch);
    register_xenbus_watch(&adapter->u.x.backend_watch);
}

static void
vnifx_initial_connect(PVNIF_ADAPTER adapter)
{
    enum xenbus_state backend_state;
    UINT i;

    VNIF_CLEAR_FLAG(adapter, VNF_DISCONNECTED);

    xenbus_switch_state(adapter->node_name, XenbusStateConnected);

    /* Wait for connect */
    for (i = 0; i < 50; i++) {
        backend_state = xennet_get_backend_state(adapter);
        if (backend_state == XenbusStateConnected) {
            break;
        }
        NdisMSleep(1000);
    }
    if (i > 1) {
        RPRINTK(DPRTL_INIT,
                ("%s: waited for backend to conect %d. End state %x\n",
                 __func__, i, backend_state));
    }

    /* Get the initial status. */
    RPRINTK(DPRTL_INIT, ("%s: xennet_frontend_changed %p, %s\n",
                         __func__, adapter, adapter->node_name));
    VNIFIndicateLinkStatus(adapter, 1);
    xennet_frontend_changed(&adapter->u.x.watch, NULL, 0);
}

NDIS_STATUS
VNIFX_SetupAdapterInterface(PVNIF_ADAPTER adapter)
{
    NTSTATUS status;
    UINT i;

    RPRINTK(DPRTL_INIT, ("%s: IN %p, %s\n",
                         __func__, adapter, adapter->node_name));

    if (adapter->lso_data_size > XEN_LSO_MAX_DATA_SIZE)  {
        adapter->lso_data_size = XEN_LSO_MAX_DATA_SIZE;
    }

    status = vnif_setup_rxtx(adapter);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    /* Set Flags */
    if (!VNIFSetupXenFlags(adapter)) {
        PRINTK(("VNIF: set xen features fail.\n"));
        return NDIS_STATUS_FAILURE;
    }
    /* Let backend know our configuration */
    if (VNIFTalkToBackend(adapter)) {
        PRINTK(("VNIF: NIC talk to backend fail.\n"));
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

    vnifx_setup_watches(adapter);

    if (adapter->b_use_ndis_poll == TRUE) {
        status = vnif_ndis_register_poll(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            return NDIS_STATUS_FAILURE;
        }
    }

    vnifx_initial_connect(adapter);

    RPRINTK(DPRTL_INIT, ("%s: OUT %p, %s\n",
                         __func__, adapter, adapter->node_name));
    return STATUS_SUCCESS;
}

NDIS_STATUS
VNIFX_QueryHWResources(PVNIF_ADAPTER adapter, PNDIS_RESOURCE_LIST res_list)
{
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

    res = xenbus_exists(XBT_NIL, adapter->u.x.otherend, "mac");
    if (res == 0) {
        return 0;
    }

    str = mac = (char *)xenbus_read(XBT_NIL, adapter->u.x.otherend,
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

    RPRINTK(DPRTL_INIT,
        ("VNIFSetupPermAddr: Perm Addr = %02x-%02x-%02x-%02x-%02x-%02x\n",
        adapter->PermanentAddress[0],
        adapter->PermanentAddress[1],
        adapter->PermanentAddress[2],
        adapter->PermanentAddress[3],
        adapter->PermanentAddress[4],
        adapter->PermanentAddress[5]));

    RPRINTK(DPRTL_INIT,
        ("VNIFSetupPermAddr: Cur Addr = %02x-%02x-%02x-%02x-%02x-%02x\n",
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

    val = xenbus_read(XBT_NIL, Adapter->u.x.otherend, "feature-rx-copy", NULL);
    if (val == NULL) {
        PRINTK(("VNIF: backend/feature-rx-copy missing.\n"));
        return 0;
    }

    feature_rx_copy = (unsigned int)cmp_strtoul(val, NULL, 10);
    Adapter->u.x.copyall = feature_rx_copy;
    xenbus_free_string(val);

    return 1;
}

static int
vinfx_setup_evtchns(PVNIF_ADAPTER Adapter, vnif_xq_path_t *path)
{
    int err;

    err = 0;
    do {
        if (Adapter->b_use_split_evtchn) {
            err = xenbus_alloc_evtchn(Adapter->u.x.backend_id,
                                      &path->tx_evtchn);
            if (err) {
                break;
            }

            err = xenbus_alloc_evtchn(Adapter->u.x.backend_id,
                                      &path->rx_evtchn);
            if (err) {
                break;
            }
            RPRINTK(DPRTL_ON, ("%s: [%d] split register_dpc_to_evtchn %d %d\n",
                               __func__, path->path_id,
                               path->tx_evtchn, path->rx_evtchn));
            register_dpc_to_evtchn(path->tx_evtchn,
                                   vnifx_tx_interrupt_dpc,
                                   path,
                                   NULL);
            register_dpc_to_evtchn(path->rx_evtchn,
                                   vnifx_rx_interrupt_dpc,
                                   path,
                                   NULL);
        } else {
            err = xenbus_alloc_evtchn(Adapter->u.x.backend_id,
                                      &path->tx_evtchn);
            if (err) {
                break;
            }

            path->rx_evtchn = path->tx_evtchn;

            RPRINTK(DPRTL_ON, ("%s: [%d] register_dpc_to_evtchn %d\n",
                               __func__, path->path_id,
                               path->tx_evtchn));
            register_dpc_to_evtchn(path->tx_evtchn,
                                   vnifx_interrupt_dpc,
                                   path,
                                   NULL);
        }
        if (err) {
            break;
        }
    } while (FALSE);

    return err;
}

static int
VNIFSetupDevice(PVNIF_ADAPTER Adapter)
{
    struct netif_tx_sring *txs;
    struct netif_rx_sring *rxs;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UINT i;
    int err;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupDevice - IN\n"));

    RPRINTK(DPRTL_INIT, ("%s: num paths %d\n", __func__, Adapter->num_paths));
    for (i = 0; i < Adapter->num_paths; i++) {
        Adapter->path[i].u.xq.adapter = Adapter;
        Adapter->path[i].u.xq.path_id = i;
        Adapter->path[i].tx = &Adapter->path[i].u.xq.tx_front_ring;
        Adapter->path[i].rx = &Adapter->path[i].u.xq.rx_front_ring;

        Adapter->path[i].u.xq.tx_ring_ref = GRANT_INVALID_REF;
        Adapter->path[i].u.xq.rx_ring_ref = GRANT_INVALID_REF;
        Adapter->path[i].u.xq.rx_front_ring.sring = NULL;
        Adapter->path[i].u.xq.tx_front_ring.sring = NULL;

        VNIF_ALLOCATE_MEMORY(
            txs,
            PAGE_SIZE,
            VNIF_POOL_TAG,
            NdisMiniportDriverHandle,
            NormalPoolPriority);
        if (txs == NULL) {
            PRINTK(("VNIF: allocating tx ring page fail.\n"));
            status = STATUS_NO_MEMORY;
            goto fail;
        }

        SHARED_RING_INIT(txs);
        WIN_FRONT_RING_INIT(&Adapter->path[i].u.xq.tx_front_ring,
                            txs, PAGE_SIZE);

        err = xenbus_grant_ring(Adapter->u.x.backend_id, virt_to_mfn(txs));
        if (err < 0) {
            goto fail;
        }
        Adapter->path[i].u.xq.tx_ring_ref = err;

        VNIF_ALLOCATE_MEMORY(
            rxs,
            PAGE_SIZE,
            VNIF_POOL_TAG,
            NdisMiniportDriverHandle,
            NormalPoolPriority);
        if (rxs == NULL) {
            PRINTK(("VNIF: allocating rx ring page fail.\n"));
            status = STATUS_NO_MEMORY;
            goto fail;
        }

        SHARED_RING_INIT(rxs);
        WIN_FRONT_RING_INIT(&Adapter->path[i].u.xq.rx_front_ring, rxs,
                            PAGE_SIZE);

        err = xenbus_grant_ring(Adapter->u.x.backend_id, virt_to_mfn(rxs));
        if (err < 0) {
            goto fail;
        }
        Adapter->path[i].u.xq.rx_ring_ref = err;
        RPRINTK(DPRTL_INIT, ("%s: grant rx ring, backend id %d ref %d\n",
                __func__, Adapter->u.x.backend_id, err));

        err = vinfx_setup_evtchns(Adapter, &Adapter->path[i].u.xq);
        if (err) {
            goto fail;
        }
    }
    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupDevice - OUT success\n"));
    return 0;

 fail:
    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupDevice - OUT error %x\n", err));
    return err;
}

static int
vnifx_write_path_keys(PVNIF_ADAPTER adapter, struct xenbus_transaction *xbt)
{
    vnif_xq_path_t *path;
    UCHAR xs_path_buf[VNIF_MAX_NODE_NAME_LEN];
    UCHAR *xs_path;
    UINT i;
    int err;

    err = 0;
    for (i = 0; i < adapter->num_paths; i++) {
        path = &adapter->path[i].u.xq;

        if (adapter->num_paths > 1) {
            xs_path = xs_path_buf;
            RtlStringCbPrintfA(xs_path, VNIF_MAX_NODE_NAME_LEN, "%s/queue-%u",
                    adapter->node_name, i);
        } else {
            xs_path = adapter->node_name;
        }

        RPRINTK(DPRTL_INIT, ("%s: writing %s tx-ring-ref %d\n",
                             __func__, xs_path, path->tx_ring_ref));
        err = xenbus_printf(*xbt, xs_path, "tx-ring-ref", "%u",
                            path->tx_ring_ref);
        if (err) {
            PRINTK(("%s: failed writing %s tx-ring-ref %d\n",
                    __func__, xs_path, path->tx_ring_ref));
            break;
        }

        RPRINTK(DPRTL_INIT, ("%s: writing %s rx-ring-ref %d\n",
                             __func__, xs_path, path->rx_ring_ref));
        err = xenbus_printf(*xbt, xs_path, "rx-ring-ref", "%u",
                            path->rx_ring_ref);
        if (err) {
            PRINTK(("%s: failed writing %s rx-ring-ref %d\n",
                    __func__, xs_path, path->rx_ring_ref));
            break;
        }

        if (path->tx_evtchn == path->rx_evtchn) {
            RPRINTK(DPRTL_INIT, ("%s: writing %s event-channel %d\n",
                                 __func__, xs_path, path->tx_evtchn));
            err = xenbus_printf(*xbt, xs_path, "event-channel", "%u",
                                path->tx_evtchn);
            if (err) {
                PRINTK(("%s: failed writing %s event-channel %d\n",
                        __func__, xs_path, path->tx_evtchn));
                break;
            }
        } else {
            RPRINTK(DPRTL_INIT, ("%s: writing %s event-channel-tx %d\n",
                                 __func__, xs_path, path->tx_evtchn));
            err = xenbus_printf(*xbt, xs_path, "event-channel-tx", "%u",
                                path->tx_evtchn);
            if (err) {
                PRINTK(("%s: failed writing %s event-channel-tx %d\n",
                        __func__, xs_path, path->tx_evtchn));
                break;
            }

            RPRINTK(DPRTL_INIT, ("%s: writing %s event-channel-rx %d\n",
                                 __func__, xs_path, path->rx_evtchn));
            err = xenbus_printf(*xbt, xs_path, "event-channel-rx", "%u",
                                path->rx_evtchn);
            if (err) {
                PRINTK(("%s: failed writing %s event-channel-rx %d\n",
                        __func__, xs_path, path->rx_evtchn));
                break;
            }
        }
    }
    return err;
}

static int
vnifx_rm_path_keys(PVNIF_ADAPTER adapter, struct xenbus_transaction *xbt)
{
    vnif_xq_path_t *path;
    UCHAR xs_path_buf[VNIF_MAX_NODE_NAME_LEN];
    UCHAR *xs_path;
    UINT i;
    int err;

    err = 0;
    for (i = 0; i < adapter->num_paths; i++) {
        path = &adapter->path[i].u.xq;

        if (adapter->num_paths > 1) {
            xs_path = xs_path_buf;
            RtlStringCbPrintfA(xs_path, VNIF_MAX_NODE_NAME_LEN, "%s/queue-%u",
                    adapter->node_name, i);
        } else {
            xs_path = adapter->node_name;
        }

        DPRINTK(DPRTL_INIT, ("%s: rm %s ring ref\n", __func__, xs_path));
        xenbus_rm(XBT_NIL, xs_path, "tx-ring-ref");
        xenbus_rm(XBT_NIL, xs_path, "rx-ring-ref");

        if (adapter->b_use_split_evtchn) {
            DPRINTK(DPRTL_INIT,
                    ("%s: rm %s event-channel tx/rx\n", __func__, xs_path));
            xenbus_rm(XBT_NIL, xs_path, "event-channel-tx");
            xenbus_rm(XBT_NIL, xs_path, "event-channel-rx");
        } else {
            DPRINTK(DPRTL_INIT,
                    ("%s: rm %s event-channel\n", __func__, xs_path));
            xenbus_rm(XBT_NIL, xs_path, "event-channel");
        }
    }
    return err;
}

static int
VNIFTalkToBackend(PVNIF_ADAPTER Adapter)
{
    int err;
    struct xenbus_transaction xbt;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFTalkToBackend - IN\n"));

    err = VNIFSetupDevice(Adapter);
    if (err) {
        goto out;
    }

again:
    RPRINTK(DPRTL_INIT, ("VNIF: xenbus starting transaction.\n"));
    err = xenbus_transaction_start(&xbt);
    if (err) {
        PRINTK(("VNIF: xenbus starting transaction fail.\n"));
        goto out;
    }

    if (Adapter->b_multi_queue == TRUE) {
        err = xenbus_printf(xbt, Adapter->node_name,
                            "multi-queue-num-queues", "%u", Adapter->num_paths);
        if (err) {
            PRINTK(("VNIF: xenbus writing multi-queue-num-queues fail.\n"));
            goto abort_transaction;
        }
    }

    err = vnifx_write_path_keys(Adapter, &xbt);
    if (err) {
        goto abort_transaction;
    }

    RPRINTK(DPRTL_INIT,
        ("VNIF: xenbus writing feature-rx-notify.\n"));
    err = xenbus_printf(xbt, Adapter->node_name,
        "feature-rx-notify", "%d", 1);
    if (err) {
        PRINTK(("VNIF: xenbus writing feature-rx-notify fail.\n"));
        goto abort_transaction;
    }

    /* 1=copyall, 0=page-flipping */
    RPRINTK(DPRTL_INIT, ("VNIF: xenbus writing request-rx-copy.\n"));
    err = xenbus_printf(xbt, Adapter->node_name, "request-rx-copy", "%u",
                  Adapter->u.x.copyall);
    if (err) {
        PRINTK(("VNIF: xenbus writing request-rx-copy fail.\n"));
        goto abort_transaction;
    }

    if (Adapter->hw_tasks & VNIF_RX_SG) {
        err = xenbus_printf(xbt, Adapter->node_name, "feature-sg", "%d", 1);
        if (err) {
            PRINTK(("VNIF: xenbus writing feature-sg fail.\n"));
            goto abort_transaction;
        }
    } else {
        err = xenbus_rm(xbt, Adapter->node_name, "feature-sg");
        if (err) {
            PRINTK(("VNIF: xenbus rm feature-sg fail.\n"));
            goto abort_transaction;
        }
    }

    if (Adapter->lso_enabled & (VNIF_LSOV1_ENABLED | VNIF_LSOV2_ENABLED)) {
        err = xenbus_printf(xbt, Adapter->node_name,
            "feature-gso-tcpv4", "%d", 1);
        if (err) {
            PRINTK(("VNIF: xenbus writing feature-gso-tcpv4 fail.\n"));
            goto abort_transaction;
        }
    }

    if (Adapter->lso_enabled & VNIF_LSOV2_IPV6_ENABLED) {
        err = xenbus_printf(xbt, Adapter->node_name,
            "feature-gso-tcpv6", "%d", 1);
        if (err) {
            PRINTK(("VNIF: xenbus writing feature-gso-tcpv6 fail.\n"));
            goto abort_transaction;
        }
    }

    /* this field is for backward compatibility */
    RPRINTK(DPRTL_INIT, ("VNIF: xenbus writing copy-delivery-offset.\n"));
    err = xenbus_printf(xbt, Adapter->node_name,
        "copy-delivery-offset", "%u", 0);
    if (err) {
        PRINTK(("VNIF: xenbus writing copy-delivery-offset fail.\n"));
        goto abort_transaction;
    }

    /* If not supporting checksuming, need to tell backend. */
    RPRINTK(DPRTL_INIT, ("VNIF: xenbus writing feature-no-csum-offload.\n"));
    err = xenbus_printf(xbt, Adapter->node_name,
        "feature-no-csum-offload", "%d",
        !(Adapter->cur_rx_tasks
            & (VNIF_CHKSUM_IPV4_TCP | VNIF_CHKSUM_IPV4_UDP)));
    if (err) {
        PRINTK(("VNIF: xenbus writing feature-no-csum-offload fail.\n"));
        goto abort_transaction;
    }

    RPRINTK(DPRTL_INIT, ("VNIF: xenbus writing feature-ipv6-csum-offload.\n"));
    err = xenbus_printf(xbt, Adapter->node_name,
        "feature-ipv6-csum-offload", "%d",
        !!(Adapter->cur_rx_tasks
            & (VNIF_CHKSUM_IPV6_TCP | VNIF_CHKSUM_IPV6_UDP)));
    if (err) {
        PRINTK(("VNIF: xenbus writing feature-ipv6-csum-offload fail.\n"));
        goto abort_transaction;
    }

    RPRINTK(DPRTL_INIT, ("VNIF: xenbus transcation end.\n"));
    err = xenbus_transaction_end(xbt, 0);
    if (err) {
        if (err == -EAGAIN) {
            goto again;
        }
        PRINTK(("VNIF: xenbus transcation end fail.\n"));
        goto out;
    }

    RPRINTK(DPRTL_ON, ("VNIF: VNIFTalkToBackend - OUT 1\n"));

    return 0;

abort_transaction:
    xenbus_transaction_end(xbt, 1);
out:
    RPRINTK(DPRTL_ON, ("VNIF: VNIFTalkToBackend - OUT 0\n"));
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
    vnif_xq_path_t  *xq;
    rcb_ring_pool_t *rcb_rp;
    RCB *rcb;
    netif_rx_request_t *req;
    ULONG i;
    ULONG p;
    grant_ref_t ref;
    RING_IDX req_prod;

    RPRINTK(DPRTL_ON,
        ("VNIF: VNIFInitRxGrants irql = %d - IN\n", KeGetCurrentIrql()));

    if (!adapter->u.x.copyall) {
        PRINTK(("VNIF: page-flipping is not supported.\n"));
        return NDIS_STATUS_FAILURE;
    }

    if (adapter->pv_stats && adapter->pv_stats->rx_to_process_cnt) {
        adapter->pv_stats->rx_to_process_cnt = 0;
    }

    adapter->nBusyRecv = 0;

    /* Putting all receive buffers' grant table refs to net ring */
    if (adapter->path != NULL) {
        for (p = 0; p < adapter->num_paths; p++) {
            NdisAcquireSpinLock(&adapter->path[p].rx_path_lock);

            xq = &adapter->path[p].u.xq;
            rcb_rp = &adapter->path[p].rcb_rp;

            if (gnttab_alloc_grant_references((uint16_t)adapter->num_rcb,
                                              &xq->gref_rx_head) < 0) {
                PRINTK(("VNIF: netfront can't alloc rx grant refs\n"));
                NdisReleaseSpinLock(&adapter->path[p].rx_path_lock);
                return NDIS_STATUS_FAILURE;
            }

            for (i = 0; i < adapter->num_rcb; i++) {
                rcb = rcb_rp->rcb_array[i];
                ref = gnttab_claim_grant_reference(&xq->gref_rx_head);
                if ((signed short)ref < 0) {
                    PRINTK((
                        "VNIF: gnttab_claim_grant_reference gref_rx_head.\n"));
                    NdisReleaseSpinLock(&adapter->path[p].rx_path_lock);
                    return NDIS_STATUS_FAILURE;
                }

                rcb->grant_rx_ref = ref;
                gnttab_grant_foreign_access_ref(
                    ref,
                    adapter->u.x.backend_id,
                    virt_to_mfn(rcb->page),
                    0);
            }

            vnif_init_rcb_free_list(adapter, p);

            req_prod = xq->rx_front_ring.req_prod_pvt;
            for (i = 0; i < NET_RX_RING_SIZE; i++) {
                rcb = (RCB *)RemoveHeadList(
                    &rcb_rp->rcb_free_list);
                req = RING_GET_REQUEST(&xq->rx_front_ring, req_prod + i);
                req->gref = rcb->grant_rx_ref;
                req->id = (UINT16) rcb->index;
                rcb_rp->rcb_ring[i] = rcb;
            }

            KeMemoryBarrier();
            xq->rx_front_ring.req_prod_pvt = req_prod + i;
            RING_PUSH_REQUESTS(&xq->rx_front_ring);

            NdisReleaseSpinLock(&adapter->path[p].rx_path_lock);
        }
    }

    RPRINTK(DPRTL_ON, ("Xennet using %d receive buffers.\n", adapter->num_rcb));
    RPRINTK(DPRTL_ON, ("VNIF: VNIFInitRxGrants `- OUT\n"));
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
VNIFInitTxGrants(PVNIF_ADAPTER adapter)
{
    TCB *tcb;
    ULONG mfn;
    UINT p;
    UINT i;
    grant_ref_t ref;

    /* Pre-allocate grant table references for send. */
    for (p = 0; p < adapter->num_paths; p++) {
        NdisInitializeListHead(&adapter->path[p].tcb_free_list);

        RPRINTK(DPRTL_ON,
                ("VNIF: VNIFInitTxGrants - gnttab_alloc_grant_references[%d]\n",
                 p));
        if (gnttab_alloc_grant_references(TX_MAX_GRANT_REFS,
                &adapter->path[p].u.xq.gref_tx_head) < 0) {
            PRINTK(("VNIF: netfront can't alloc tx grant refs[%d]\n", p));
            return NDIS_STATUS_FAILURE;
        }
    }

#if NDIS_SUPPORT_NDIS6 == 0
    NdisInitializeListHead(&adapter->SendWaitList);
#endif
    adapter->nBusySend = 0;

    /*
     * Allocate for each TCB, because sizeof(TCB) is less than PAGE_SIZE,
     * it will not cross page boundary.
     */
    for (p = 0; p < adapter->num_paths; p++) {
        for (i = 0; i < NET_TX_RING_SIZE; i++) {
            tcb = adapter->TCBArray[(p * NET_TX_RING_SIZE) + i];

            NdisInterlockedInsertTailList(&adapter->path[p].tcb_free_list,
                                          &tcb->list,
                                          &adapter->path[p].tx_path_lock);

            adapter->path[p].u.xq.tx_packets[i] = (void *)((ULONG_PTR)i + 1);
            adapter->path[p].u.xq.grant_tx_ref[i] =
                gnttab_claim_grant_reference(
                    &adapter->path[p].u.xq.gref_tx_head);
        }
        adapter->path[p].u.xq.tx_id_alloc_head = 0;
    }

    return NDIS_STATUS_SUCCESS;
}

static uint32_t
VNIFOutstanding(PVNIF_ADAPTER adapter)
{
    TCB *tcb;
    UINT p;
    uint32_t cnt;
    uint32_t gnt_flags;
    uint32_t outstanding;

    outstanding = 0;
    cnt = 0;

    for (p = 0; p < adapter->num_paths; p++) {
        for (cnt = 0; cnt < NET_TX_RING_SIZE; cnt++) {
            tcb = adapter->path[p].u.xq.tx_packets[cnt];
            if (tcb > (TCB *)NET_TX_RING_SIZE) {
                outstanding++;
                gnt_flags =
                    gnttab_query_foreign_access_flags(tcb->grant_tx_ref);
                if (gnt_flags & (GTF_reading | GTF_writing)) {
                    PRINTK(("\n\tid %x, refs %x, flags %x",
                        cnt, tcb->grant_tx_ref, gnt_flags));
    #ifdef VNIF_TRACK_TX
                    PRINTK((", granted %x, ringidx %x.",
                        tcb->granted, tcb->ringidx));
    #endif
                }
            }
        }
    }

    PRINTK(("VNIF: Outstanding sends %d, busy %d: out.\n",
        outstanding, adapter->nBusySend));
    return outstanding;
}

uint32_t
VNIFX_Quiesce(PVNIF_ADAPTER adapter)
{
    char *buf;
    KIRQL old_irql;
    KDPC Dpc = {0};
    UINT p;
    uint32_t waiting = 0;
    uint32_t wait_count = 0;
    uint32_t resources_outstanding = 0;
    uint32_t busy_r = 0;

    if (VNIF_TEST_FLAG(adapter, VNF_DISCONNECTED)) {
        PRINTK(("VNIFQuiesce: adapter already discconnected, %x\n",
            adapter->adapter_flags));
        return 0;
    }
#ifdef DBG
    buf = xenbus_read(XBT_NIL, adapter->u.x.otherend, "state", NULL);
    if (buf) {
        PRINTK(("VNIFQuiesce: backend state %s, ", buf));
        xenbus_free_string(buf);
    }
    buf = xenbus_read(XBT_NIL, adapter->node_name, "state", NULL);
    if (buf) {
        PRINTK(("frontend state %s\n", buf));
        xenbus_free_string(buf);
    }
#endif
    if (adapter->nBusyRecv) {
        PRINTK(("VNIF: ** %s quiesce %d receives **\n",
            &adapter->node_name[7], adapter->nBusyRecv));
        resources_outstanding = 1;
        waiting = adapter->nBusyRecv;
    }
    if (adapter->nBusySend) {
        PRINTK(("VNIF: ** %s quiesce %d sends **\n",
            &adapter->node_name[7], adapter->nBusySend));
        for (p = 0; p < adapter->num_paths; p++) {
            PRINTK(("\t[%d]: flags %x, pvt %x, rcons %x\n",
                p,
                adapter->adapter_flags,
                adapter->path[p].u.xq.tx_front_ring.req_prod_pvt,
                adapter->path[p].u.xq.tx_front_ring.rsp_cons));
        }
        resources_outstanding = 1;
        waiting += adapter->nBusySend;
    }

    while (waiting && wait_count <= adapter->resource_timeout) {
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
        for (p = 0; p < adapter->num_paths; p++) {
            if (adapter->path[p].u.xq.rx_evtchn) {
                if (notify_remote_via_evtchn(
                        adapter->path[p].u.xq.rx_evtchn)) {
                    PRINTK(("VNIFQuiesce notify failed.\n"));
                }
            }
        }
        vnif_call_txrx_interrupt_dpc(adapter);
        KeLowerIrql(old_irql);

        /*
         * Only need to wory about the receives that are in the process of
         * VNIFReceivePackets and xennet_return_packet.
         */
        waiting = adapter->nBusyRecv;
        waiting += adapter->nBusySend;

        if (!waiting) {
            break;
        }

        if (adapter->resource_timeout) {
            wait_count++;
            NdisMSleep(1000000);  /* 1 second */
        }
    }

    if (waiting) {
        PRINTK(("VNIFQuiesce %s: flags %x, waiting %d, wait_count %d.\n",
            &adapter->node_name[7],
            adapter->adapter_flags, waiting, wait_count));
        if (adapter->nBusyRecv) {
            for (p = 0; p < adapter->num_paths; p++) {
                PRINTK(("\t[%d]:nbusy %d: pvt %x, srsp %x, rsc %x busy %d\n",
                    p,
                    adapter->nBusyRecv,
                    adapter->path[p].u.xq.rx_front_ring.req_prod_pvt,
                    adapter->path[p].u.xq.rx_front_ring.sring->rsp_prod,
                    adapter->path[p].u.xq.rx_front_ring.rsp_cons,
                    adapter->path[p].u.xq.rx_front_ring.sring->rsp_prod -
                        adapter->path[p].u.xq.rx_front_ring.rsp_cons));
                busy_r += adapter->path[p].u.xq.rx_front_ring.sring->rsp_prod -
                    adapter->path[p].u.xq.rx_front_ring.rsp_cons;
            }
        }
        if (adapter->nBusySend) {
            for (p = 0; p < adapter->num_paths; p++) {
                PRINTK(("\t[%d]: sends outstanding %d: pvt %x, rcons %x\n",
                    p,
                    adapter->nBusySend,
                    adapter->path[p].u.xq.tx_front_ring.req_prod_pvt,
                    adapter->path[p].u.xq.tx_front_ring.rsp_cons));
                PRINTK((
                    "\tsring: rq_prd %x, rsp_prd %x, rq_evt %x, rsp_evt %x\n",
                    adapter->path[p].u.xq.tx_front_ring.sring->req_prod,
                    adapter->path[p].u.xq.tx_front_ring.sring->rsp_prod,
                    adapter->path[p].u.xq.tx_front_ring.sring->req_event,
                    adapter->path[p].u.xq.tx_front_ring.sring->rsp_event));
            }
            if (VNIFOutstanding(adapter) == 0) {
                PRINTK(("VNIFQuiesce %s: failed to find outstanding sends.\n",
                    &adapter->node_name[7]));
                waiting = 0;
            }
        }
    } else {
        if (resources_outstanding) {
            PRINTK(("VNIF: ** %s resources quiesced **\n",
                &adapter->node_name[7]));
        }
    }
    RPRINTK(DPRTL_ON, ("VNIF: VNIFQuiesce OUT busy_r %d\n", busy_r));
    return 0;
}

static void
VNIFWaitStateChange(PVNIF_ADAPTER adapter,
    enum xenbus_state front_state, enum xenbus_state end_state)
{
    char *buf;
    uint32_t i;
    enum xenbus_state backend_state;

    RPRINTK(DPRTL_ON, ("VNIFWaitStateChange: switching front end state to %d\n",
        front_state));
    for (i = 0; i < 1000; i++) {
        if (xenbus_switch_state(adapter->node_name, front_state) == 0) {
            RPRINTK(DPRTL_INIT,
                ("VNIFWaitStateChange: front end state switched to %d: %d\n",
                front_state, i));
            break;
        }
        NdisMSleep(1000);
    }
    RPRINTK(DPRTL_INIT,
        ("VNIFWaitStateChange: waiting for backend state to be %d\n",
        end_state));
    for (i = 0; i < 1000; i++) {
        buf = xenbus_read(XBT_NIL, adapter->u.x.otherend, "state", NULL);
        if (buf) {
            backend_state = (enum xenbus_state)cmp_strtoul(buf, NULL, 10);
            xenbus_free_string(buf);
            if (backend_state == end_state) {
                break;
            }
        }
        NdisMSleep(1000);
    }
    RPRINTK(DPRTL_ON,
        ("VNIFWaitStateChange: waited %d, for state %d, reached %d\n",
        i, end_state, backend_state));
}

void
VNIFX_CleanupRings(PVNIF_ADAPTER adapter)
{
    TCB *tcb;
    RCB *rcb;
    UINT i;
    UINT p;
    UINT r;
    if (adapter->path == NULL) {
        return;
    }

    RPRINTK(DPRTL_ON, ("VNIF: VNIFCleanupRings XENNET_COPY_TX\n"));
    for (p = 0; p < adapter->num_paths; p++) {
        for (r = 0; r < NET_TX_RING_SIZE; r++) {
            if (adapter->path[p].u.xq.grant_tx_ref[r] != GRANT_INVALID_REF) {
                gnttab_end_foreign_access_ref(
                    adapter->path[p].u.xq.grant_tx_ref[r], GNTMAP_readonly);

                gnttab_release_grant_reference(
                    &adapter->path[p].u.xq.gref_tx_head,
                    adapter->path[p].u.xq.grant_tx_ref[r]);
                adapter->path[p].u.xq.grant_tx_ref[r] = GRANT_INVALID_REF;
            }
        }

        if (adapter->path[p].u.xq.tx_ring_ref != GRANT_INVALID_REF) {
            RPRINTK(DPRTL_INIT, ("VNIF: VNIFCleanupRings - end tx ring ref\n"));
            gnttab_end_foreign_access(adapter->path[p].u.xq.tx_ring_ref, 0);
            adapter->path[p].u.xq.tx_ring_ref = GRANT_INVALID_REF;
        }

        if (adapter->path[p].u.xq.gref_tx_head != GRANT_INVALID_REF) {
            RPRINTK(DPRTL_INIT,
                ("VNIF: VNIFCleanupRings gnttab_free_grant_references tx %x\n",
                 adapter->path[p].u.xq.gref_tx_head));
            gnttab_free_grant_references(adapter->path[p].u.xq.gref_tx_head);
            adapter->path[p].u.xq.gref_tx_head = GRANT_INVALID_REF;
        }

        /* Now do the receive resources. */
        if (adapter->path[p].rcb_rp.rcb_array != NULL) {
            for (i = 0; i < NET_RX_RING_SIZE; i++) {
                rcb = adapter->path[p].rcb_rp.rcb_array[i];
                if (!rcb) {
                    continue;
                }

                if (rcb->grant_rx_ref != GRANT_INVALID_REF) {
                    gnttab_end_foreign_access_ref(
                        rcb->grant_rx_ref, 0);
                    gnttab_release_grant_reference(
                        &adapter->path[p].u.xq.gref_rx_head,
                        rcb->grant_rx_ref);
                    rcb->grant_rx_ref = GRANT_INVALID_REF;
                }
            }
        }
        if (adapter->path[p].u.xq.rx_ring_ref != GRANT_INVALID_REF) {
            RPRINTK(DPRTL_INIT, ("VNIF: VNIFCleanupRings - end rx ring ref\n"));
            gnttab_end_foreign_access(adapter->path[p].u.xq.rx_ring_ref, 0);
            adapter->path[p].u.xq.rx_ring_ref = GRANT_INVALID_REF;
        }

        if (adapter->path[p].u.xq.gref_rx_head != GRANT_INVALID_REF) {
            RPRINTK(DPRTL_INIT,
                ("VNIF: VNIFCleanupRings gnttab_free_grant_references rx %x\n",
                adapter->path[p].u.xq.gref_rx_head));
            gnttab_free_grant_references(adapter->path[p].u.xq.gref_rx_head);
            adapter->path[p].u.xq.gref_rx_head = GRANT_INVALID_REF;
        }
    }
}

uint32_t
VNIFX_DisconnectBackend(PVNIF_ADAPTER adapter)
{
    xenbus_release_device_t release_data;
    UINT p;
    BOOLEAN cancelled = TRUE;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFDisconnectBackend - IN\n"));

    if (VNIF_TEST_FLAG(adapter, VNF_DISCONNECTED)) {
        PRINTK(("VNIFDisconnectBackend: adapter already discconnected, %x\n",
            adapter->adapter_flags));
        return 0;
    }

    /* Wait to become idle for all sends and receives. */
    if (VNIFQuiesce(adapter)) {
        return 1;
    }

    VNIF_SET_FLAG(adapter, VNF_DISCONNECTED);

    /*
     * Make sure we are out of the DPC and that NDIS doesn't have any
     * of our receives before continuing.
     */
    if (adapter->nBusyRecv) {
        PRINTK(("VNIFDisconnect: wait on DPC or receives. f %x, r %d s %d\n",
            adapter->adapter_flags, adapter->nBusyRecv, adapter->nBusySend));
    }
    while (adapter->nBusyRecv) {
        NdisMSleep(500000);  /* 1/2 second */
    }

    for (p = 0; p < adapter->num_paths; p++) {
        if (adapter->path[p].u.xq.tx_evtchn
                != adapter->path[p].u.xq.rx_evtchn) {
            if (adapter->path[p].u.xq.rx_evtchn != 0) {
                RPRINTK(DPRTL_INIT,
                    ("VNIF: %s[%d] rx unregister_dpc_from_evtchn %d\n",
                     __func__, p, adapter->path[p].u.xq.rx_evtchn));
                unregister_dpc_from_evtchn(adapter->path[p].u.xq.rx_evtchn);
                xenbus_free_evtchn(adapter->path[p].u.xq.rx_evtchn);
                adapter->path[p].u.xq.rx_evtchn = 0;
            }
        }
        if (adapter->path[p].u.xq.tx_evtchn != 0) {
            RPRINTK(DPRTL_INIT,
                ("VNIF: %s[%d] unregister_dpc_from_evtchn %d\n",
                 __func__, p, adapter->path[p].u.xq.tx_evtchn));
            unregister_dpc_from_evtchn(adapter->path[p].u.xq.tx_evtchn);
            xenbus_free_evtchn(adapter->path[p].u.xq.tx_evtchn);
            adapter->path[p].u.xq.tx_evtchn = 0;
        }
    }

    if (!VNIF_TEST_FLAG(adapter, VNF_ADAPTER_DETACHING)) {
        /*
         * Switch the state to closing, closed, initializign.  This will
         * allow the backend to release its references.
         */
        unregister_xenbus_watch(&adapter->u.x.backend_watch);
        unregister_xenbus_watch(&adapter->u.x.watch);
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
    RPRINTK(DPRTL_INIT, ("VNIF: NdisCancelTimer\n"));
    if (adapter->pv_stats) {
        VNIF_CANCEL_TIMER(adapter->pv_stats->stat_timer, &cancelled);
    }
    VNIF_CANCEL_TIMER(adapter->rcv_timer, &cancelled);
    VNIF_CANCEL_TIMER(adapter->ResetTimer, &cancelled);

    if (cancelled) {
        RPRINTK(DPRTL_INIT, ("VNIF: halt VNIFFreeQueuedRecvPackets\n"));
        VNIFFreeQueuedRecvPackets(adapter);
    }
    vnifx_rm_path_keys(adapter, &XBT_NIL);

    RPRINTK(DPRTL_ON,
        ("VNIF: VNIFDisconnectBackend - flags %x. OUT\n",
         adapter->adapter_flags));
    return 0;
}

static void
xennet_frontend_changed(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    PVNIF_ADAPTER adapter = (PVNIF_ADAPTER)watch->context;
    char *buf;
    uint32_t link_status;

    buf = xenbus_read(XBT_NIL, adapter->node_name, "link-status", NULL);
    if (buf == NULL || IS_ERR(buf)) {
        return;
    }

    link_status = (uint32_t)cmp_strtoul(buf, NULL, 10);
    xenbus_free_string(buf);
    RPRINTK(DPRTL_ON, ("xennet_frontend_changed: %p, link status = %d.\n",
        adapter, link_status));

    if (link_status != !VNIF_TEST_FLAG(adapter, VNF_ADAPTER_NO_LINK)) {
        if (link_status) {
            VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_NO_LINK);
        } else {
            VNIF_SET_FLAG(adapter, VNF_ADAPTER_NO_LINK);
        }

        /* Indicate the media event */
        RPRINTK(DPRTL_ON,
            ("xennet_frontend_changed: indicating status change.\n"));
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
    enum xenbus_state backend_state;
    xenbus_release_device_t release_data;

    RPRINTK(DPRTL_ON, ("xennet:backend_changed for %s: node %s.\n",
        vec[0], adapter->node_name));

    backend_state = xennet_get_backend_state(adapter);
    if (backend_state == XenbusStateClosing) {
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_DETACHING);

        while (VNIFQuiesce(adapter)) {
            NdisMSleep(1000000);  /* 1 second */
        }

        unregister_xenbus_watch(&adapter->u.x.backend_watch);
        unregister_xenbus_watch(&adapter->u.x.watch);

        RPRINTK(DPRTL_ON,
            ("xennet:backend_changed switching to state closed.\n"));
        xenbus_switch_state(adapter->node_name, XenbusStateClosed);

        RPRINTK(DPRTL_ON, ("xennet:backend_changed: xenbus_release_device.\n"));
        release_data.action = RELEASE_REMOVE;
        release_data.type = vnif;
        xenbus_release_device(adapter, NULL, release_data);
    }
    RPRINTK(DPRTL_ON,
        ("xennet:backend_changed for %s: out.\n", adapter->node_name));
}

void
vnifx_restart_interface(PVNIF_ADAPTER adapter)
{
}

void
vnifx_send_packet_filter(PVNIF_ADAPTER adapter)
{
}

void
vnifx_send_multicast_list(PVNIF_ADAPTER adapter)
{
}

void
vnifx_send_vlan_filter(PVNIF_ADAPTER adapter, UCHAR add_del)
{
}

static void
xennet_resume_failue_cleanup(PVNIF_ADAPTER adapter)
{
    xenbus_release_device_t release_data;
    BOOLEAN cancelled = TRUE;

    RPRINTK(DPRTL_ON, ("xennet_resume_failue_cleanup - IN\n"));

    VNIF_SET_FLAG(adapter, VNF_DISCONNECTED);

    RPRINTK(DPRTL_ON, ("xennet_resume_failue_cleanup - OUT\n"));
}

static void
MPResume(PVNIF_ADAPTER adapter, uint32_t suspend_canceled)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UINT i;

    RPRINTK(DPRTL_ON, ("MPResume: %p, %x\n", adapter, suspend_canceled));
    if (suspend_canceled) {
        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SUSPENDED);
    } else {
#ifdef DBG
        adapter->dbg_print_cnt = 0;
#endif
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_RESUMING);
        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SUSPENDED);

        if (adapter->pv_stats && adapter->pv_stats->rx_to_process_cnt) {
            PRINTK(("%s: rx_to_process_cnt %d\n",
                    __func__, adapter->pv_stats->rx_to_process_cnt));
        }
        for (i = 0; i < adapter->num_rcv_queues; ++i) {
            if (!IsListEmpty(&adapter->rcv_q[i].rcv_to_process)) {
                PRINTK(("%s: RecvToProcess[%d] not empty\n", __func__, i));
            }
        }
        if (adapter->nBusySend) {
#if NDIS_SUPPORT_NDIS6
            PRINTK(("MPResume: starting, nBusySend = %d, nWaitSend = %d\n",
                adapter->nBusySend, adapter->nWaitSend));
#else
            PRINTK(("MPResume: starting, nBusySend = %d\n",
                adapter->nBusySend));
#endif
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
#if NDIS_SUPPORT_NDIS6
            PRINTK(("MPResume %s: nBusySend %d, nWaitSend %d, flags 0x%x\n",
                adapter->u.x.otherend, adapter->nBusySend,
                adapter->nWaitSend, adapter->adapter_flags));
#else
            PRINTK(("MPResume %s: nBusySend = %d, flags = 0x%x\n",
                adapter->u.x.otherend, adapter->nBusySend,
                adapter->adapter_flags));
#endif
        }
        if (status == STATUS_SUCCESS) {
            vnif_send_arp(adapter);
        } else {
            PRINTK(("MPResume %s: failed resume = 0x%x\n",
                adapter->node_name, status));
            xennet_resume_failue_cleanup(adapter);
        }
    }
    VNIFDumpSettings(adapter);
}

static uint32_t
MPSuspend(PVNIF_ADAPTER adapter, uint32_t reason)
{
    uint32_t waiting;
    RCB *rcb;
    UINT i;
    BOOLEAN cancelled = TRUE;

    PRINTK(("MPSuspend: %s, due to %x\n", adapter->node_name, reason));
    VNIF_SET_FLAG(adapter, VNF_ADAPTER_SUSPENDING);
    if (reason == SHUTDOWN_suspend) {
        /*
         * We could force a wait here, but then that's what
         * adapter->resource_timeout is for.
         */
        VNIFQuiesce(adapter);
        VNIF_SET_FLAG(adapter, VNF_ADAPTER_SUSPENDED);
        VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SUSPENDING);

        /*
         * Make sure we are out of the DPC and that NDIS doesn't have any
         * of our receives before returning.
         */
        if (adapter->nBusyRecv) {
            PRINTK(("MPSuspend: wait on DPC or receives. f %x, s %d r %d\n",
                    adapter->adapter_flags,
                    adapter->nBusySend, adapter->nBusyRecv));
        }
        while (adapter->nBusyRecv) {
            NdisMSleep(500000);  /* 1/2 second */
        }
        VNIF_CANCEL_TIMER(adapter->rcv_timer, &cancelled);

        if (adapter->pv_stats && adapter->pv_stats->rx_to_process_cnt) {
            PRINTK(("%s: rx_to_process_cnt %d\n",
                    __func__, adapter->pv_stats->rx_to_process_cnt));
        }
        for (i = 0; i < adapter->num_rcv_queues; ++i) {
            if (!IsListEmpty(&adapter->rcv_q[i].rcv_to_process)) {
                PRINTK(("%s: RecvToProcess[%d] not empty\n", __func__, i));
            }
        }
        waiting = adapter->nBusyRecv;
        waiting += adapter->nBusySend;
    } else {
        waiting = VNIFDisconnectBackend(adapter);
        if (waiting == 0) {
            VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_SUSPENDING);
            VNIFFreeAdapterInterface(adapter);
        }
    }
    PRINTK(("MPSuspend: OUT, waiting %d for sends %d, recv %d\n",
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
