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

static NDIS_STRING reg_tcp_chksum_name =
    NDIS_STRING_CONST("TCPChecksumOffloadIPv4");
static NDIS_STRING reg_udp_chksum_name =
    NDIS_STRING_CONST("UDPChecksumOffloadIPv4");
static NDIS_STRING reg_tcp6_chksum_name =
    NDIS_STRING_CONST("TCPChecksumOffloadIPv6");
static NDIS_STRING reg_udp6_chksum_name =
    NDIS_STRING_CONST("UDPChecksumOffloadIPv6");
static NDIS_STRING reg_calc_chksum_name =
    NDIS_STRING_CONST("CalcMissingChecksum");
static NDIS_STRING reg_lso_v1_name =
    NDIS_STRING_CONST("LsoV1IPv4");
static NDIS_STRING reg_lso_v2_name =
    NDIS_STRING_CONST("*LsoV2IPv4");
static NDIS_STRING reg_lso_v2_ipv6_name =
    NDIS_STRING_CONST("*LsoV2IPv6");
static NDIS_STRING reg_lso_v2_ipv6_ext_hdrs_name =
    NDIS_STRING_CONST("LsoV2IPv6ExtHdrsSupport");
static NDIS_STRING reg_lso_data_size_name =
    NDIS_STRING_CONST("LsoDataSize");
static NDIS_STRING reg_rx_sg_name =
    NDIS_STRING_CONST("FragmentedReceives");
static NDIS_STRING reg_numrfd_name =
    NDIS_STRING_CONST("NumRcb");
static NDIS_STRING reg_rcv_limit_name =
    NDIS_STRING_CONST("RcvLimit");
static NDIS_STRING reg_resource_timeout_name =
    NDIS_STRING_CONST("ResourceTimeout");
static NDIS_STRING net_cfg_instance_id_name =
    NDIS_STRING_CONST("NetCfgInstanceId");
static NDIS_STRING reg_stat_interval_name =
    NDIS_STRING_CONST("StatInterval");
static NDIS_STRING reg_mtu_name =
    NDIS_STRING_CONST("MTU");
static NDIS_STRING reg_link_speed_name =
    NDIS_STRING_CONST("LinkSpeed");

#ifdef VNIF_RCV_DELAY
static NDIS_STRING reg_delay_name =
    NDIS_STRING_CONST("RcvDelay");
#endif

#ifndef NDIS60_MINIPORT
static NDIS_STRING reg_tx_throttle_start_name =
    NDIS_STRING_CONST("TxThrottleStart");
static NDIS_STRING reg_tx_throttle_stop_name =
    NDIS_STRING_CONST("TxThrottleStop");
#endif

#ifdef TARGET_OS_GE_Win8
static NDIS_STRING reg_pmc_name =
    NDIS_STRING_CONST("PMC");
#endif

#ifdef DBG
static NDIS_STRING reg_dbg_print_mask_name =
    NDIS_STRING_CONST("dbg_print_mask");
#else
static NDIS_STRING reg_dbg_print_mask_name =
    NDIS_STRING_CONST("rel_print_mask");
#endif

#ifdef NDIS620_MINIPORT
static NDIS_STRING reg_rss = NDIS_STRING_CONST("*RSS");
static NDIS_STRING reg_num_rss_qs = NDIS_STRING_CONST("*NumRssQueues");
static NDIS_STRING reg_num_paths = NDIS_STRING_CONST("NumPaths");
static NDIS_STRING reg_rss_tcp_ipv6_ext_hdrs_name =
    NDIS_STRING_CONST("RssTCPIPv6ExtHdrsSupport");
#endif

static NDIS_STRING reg_split_evtchn = NDIS_STRING_CONST("SplitEvtchn");

static NDIS_STRING reg_indirect_desc = NDIS_STRING_CONST("IndirectDescriptors");

static NDIS_STRING reg_tx_sg_cnt = NDIS_STRING_CONST("TxSgCnt");

static NDIS_STATUS
VNIFSetupNdisAdapterTx(PVNIF_ADAPTER adapter)
{
    TCB *tcb;
    uint8_t *vdesc;
    PHYSICAL_ADDRESS desc_pa;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG num_ring_desc;
#ifndef XENNET
    ULONG desc_per_page;
    ULONG num_desc_pages;
    ULONG bytes_per_desc;
    ULONG total_desc_bytes;
#endif
    ULONG i;

    do {
        vdesc = NULL;
        desc_pa.QuadPart = 0;
        num_ring_desc = VNIF_TX_RING_SIZE(adapter);
        VNIF_ALLOCATE_MEMORY(
            (void *)adapter->TCBArray,
            sizeof(TCB *) * num_ring_desc * adapter->num_paths,
            VNIF_POOL_TAG,
            NdisMiniportDriverHandle,
            NormalPoolPriority);
        if (adapter->TCBArray == NULL) {
            PRINTK(("VNIF: Failed to allocate memory for TCBArray\n"));
            status = STATUS_NO_MEMORY;
            break;
        }
        NdisZeroMemory(
            adapter->TCBArray,
            sizeof(TCB *) * num_ring_desc * adapter->num_paths);

#ifndef XENNET
        if (adapter->b_indirect == TRUE) {
            bytes_per_desc = sizeof(struct vring_desc) * adapter->max_sg_el;
            desc_per_page = PAGE_SIZE / bytes_per_desc;
            num_desc_pages = (num_ring_desc / desc_per_page)
                            + (num_ring_desc % desc_per_page ? 1 : 0);
            total_desc_bytes = num_desc_pages * PAGE_SIZE * adapter->num_paths;

            RPRINTK(DPRTL_INIT,
                ("sizeof(desc) %d, max_sg_el %d, num_ring_desc %d\n",
                sizeof(struct vring_desc), adapter->max_sg_el, num_ring_desc));
            RPRINTK(DPRTL_INIT,
                ("desc_per_page %d, num_desc_pages %d, total_desc_bytes %d\n",
                desc_per_page, num_desc_pages, total_desc_bytes));

            VNIF_ALLOCATE_SHARED_MEMORY(
                adapter,
                &adapter->vring_tx_desc_array,
                &adapter->vring_tx_desc_pa,
                total_desc_bytes,
                NdisMiniportDriverHandle);

            if (adapter->vring_tx_desc_array != NULL) {
                vdesc = adapter->vring_tx_desc_array;
                desc_pa = adapter->vring_tx_desc_pa;
            } else {
                adapter->b_indirect = FALSE;
                PRINTK(("VNIF: failed to allocate tx descriptor array.\n"));
                PRINTK(("VNIF: setting Indirector Descriptors to FALSE.\n"));
            }
            RPRINTK(DPRTL_INIT, ("vring_des_pa %llx\n", desc_pa.QuadPart));
        }
#endif

        /*
         * Allocate for each TCB, because sizeof(TCB) is less than PAGE_SIZE,
         * it will not cross page boundary.
         */

        for (i = 0; i < num_ring_desc * adapter->num_paths; i++) {
            VNIF_ALLOCATE_MEMORY(
                tcb,
                sizeof(TCB),
                VNIF_POOL_TAG,
                NdisMiniportDriverHandle,
                NormalPoolPriority);
            if (tcb == NULL) {
                PRINTK(("VNIF: Failed to allocate memory for TCB's\n"));
                status = STATUS_NO_MEMORY;
                break;
            }
            NdisZeroMemory(tcb, sizeof(TCB));
            adapter->TCBArray[i] = tcb;
            tcb->index = i;

            VNIF_ALLOCATE_SHARED_MEMORY(
                adapter,
                &tcb->data,
                &tcb->data_pa,
                PAGE_SIZE,
                NdisMiniportDriverHandle);

            if (tcb->data == NULL) {
                PRINTK(("VNIF: fail to allocate tx data.\n"));
                status = STATUS_NO_MEMORY;
                break;
            }

#ifndef XENNET
            if (adapter->b_indirect == TRUE && vdesc != NULL) {
                if ((i % desc_per_page == 0) && i != 0) {
                    vdesc += PAGE_SIZE;
                    desc_pa.QuadPart += PAGE_SIZE;
                    RPRINTK(DPRTL_INIT,
                            ("vring_des_pa %llx\n", desc_pa.QuadPart));
                }
                tcb->vr_desc = vdesc +
                    ((uint64_t)bytes_per_desc * (uint64_t)(i % desc_per_page));
                tcb->vr_desc_pa.QuadPart = desc_pa.QuadPart +
                    ((uint64_t)bytes_per_desc * (uint64_t)(i % desc_per_page));
            }
#endif
        }

        /*
         * No need to set adapter->grant_tx_ref[i] = GRANT_INVALID_REF;
         * It was handled by memset of adapter.
         */

    } while (FALSE);
    return status;
}

static VOID
VNIFFreeAdapterTx(PVNIF_ADAPTER adapter)
{
    TCB *tcb;
    ULONG num_ring_desc;
#ifndef XENNET
    ULONG desc_per_page;
    ULONG num_desc_pages;
    ULONG bytes_per_desc;
    ULONG total_desc_bytes;
#endif
    uint32_t i;

    /* Free all the resources we allocated for sends. */
    RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapterTx NdisFreeMemory\n"));

    num_ring_desc = VNIF_TX_RING_SIZE(adapter);

#ifndef XENNET
    if (adapter->vring_tx_desc_array != NULL) {
        bytes_per_desc = sizeof(struct vring_desc) * adapter->max_sg_el;
        desc_per_page = PAGE_SIZE / bytes_per_desc;
        num_desc_pages = (num_ring_desc / desc_per_page)
                        + (num_ring_desc % desc_per_page ? 1 : 0);
        total_desc_bytes = num_desc_pages * PAGE_SIZE * adapter->num_paths;

        RPRINTK(DPRTL_INIT,
            ("sizeof(desc) %d, max_sg_el %d, num_ring_desc %d\n",
            sizeof(struct vring_desc), adapter->max_sg_el, num_ring_desc));
        RPRINTK(DPRTL_INIT,
            ("desc_per_page %d, num_desc_pages %d, total_desc_bytes %d\n",
            desc_per_page, num_desc_pages, total_desc_bytes));

        VNIF_FREE_SHARED_MEMORY(adapter,
                                adapter->vring_tx_desc_array,
                                adapter->vring_tx_desc_pa,
                                total_desc_bytes,
                                NdisMiniportDriverHandle);
        adapter->vring_tx_desc_array = NULL;
    }
#endif

    if (adapter->TCBArray == NULL) {
        RPRINTK(DPRTL_ON, ("%s: TCBArray is NULL\n", __func__));
        return;
    }
    for (i = 0; i < num_ring_desc * adapter->num_paths; i++) {
        tcb = adapter->TCBArray[i];
        if (tcb) {
            if (tcb->data) {
                VNIF_FREE_SHARED_MEMORY(adapter,
                                        tcb->data,
                                        tcb->data_pa,
                                        PAGE_SIZE,
                                        NdisMiniportDriverHandle);
                tcb->data = NULL;
            } else {
                RPRINTK(DPRTL_ON, ("%s: tcb[%d]->data is NULL\n", __func__, i));
            }
            NdisFreeMemory(tcb, sizeof(TCB), 0);
            adapter->TCBArray[i] = NULL;
        } else {
            RPRINTK(DPRTL_ON, ("%s: tcb[%d] is NULL\n", __func__, i));
        }
    }
    NdisFreeMemory(adapter->TCBArray,
                   sizeof(TCB *) * num_ring_desc * adapter->num_paths,
                   0);
    adapter->TCBArray = NULL;
}

static void
vnif_free_path_info(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status;
    UINT i;
    UINT r;

    if (adapter->path != NULL) {
        for (i = 0; i < adapter->num_paths; ++i) {
            NdisFreeSpinLock(&adapter->path[i].rx_path_lock);
            NdisFreeSpinLock(&adapter->path[i].tx_path_lock);
        }
        NdisFreeMemory(adapter->path,
                       sizeof(vnif_path_t *) * adapter->num_paths,
                       0);
        adapter->path = NULL;
        adapter->num_paths = 0;
    }
    if (adapter->rcv_q != NULL) {
        for (i = 0; i < adapter->num_rcv_queues; ++i) {
            NdisFreeSpinLock(&adapter->rcv_q[i].rcv_to_process_lock);
        }
        NdisFreeMemory(
            adapter->rcv_q,
            sizeof(rcv_to_process_q_t *) * adapter->num_rcv_queues,
            0);
        adapter->rcv_q = NULL;
        adapter->num_rcv_queues = 0;
    }
}

static void
vnif_set_num_paths(PVNIF_ADAPTER adapter)
{
    UINT num_cpus;
    UINT num_paths;
    UINT max_paths;

    num_paths = 1;
    do {
        if (!adapter->b_multi_signaled) {
            RPRINTK(DPRTL_INIT, ("[%s] Not multi signled, use 1 queue\n",
                                 __func__));
            break;
        }

        if (!adapter->b_multi_queue) {
            RPRINTK(DPRTL_INIT, ("[%s] Not multiple queues, use 1 queue\n",
                                 __func__));
            break;
        }

        num_cpus = VNFI_GET_PROCESSOR_COUNT & 0xFFFF;

        RPRINTK(DPRTL_INIT, ("[%s] num cpus %d\n",
            __func__, num_cpus));

        max_paths = (adapter->num_hw_queues < num_cpus)
            ? adapter->num_hw_queues : num_cpus;

        num_paths = VNIF_GET_NUM_PATHS(adapter);

        if (num_paths > max_paths) {
            num_paths = max_paths;
        }

        if (num_paths > adapter->num_paths) {
            num_paths = adapter->num_paths;
        }

    } while (FALSE);

    adapter->num_paths = num_paths;

    RPRINTK(DPRTL_INIT, ("[%s] num paths %u\n", __func__, num_paths));
}

static NDIS_STATUS
vnif_setup_path_info(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status;
#if NDIS620_MINIPORT_SUPPORT
    PROCESSOR_NUMBER target_processor;
#endif
    UINT i;
    UINT r;

    vnif_set_num_paths(adapter);

    VNIF_ALLOCATE_MEMORY(
        adapter->path,
        sizeof(vnif_path_t) * adapter->num_paths,
        VNIF_POOL_TAG,
        NdisMiniportDriverHandle,
        NormalPoolPriority);
    if (adapter->path == NULL) {
        return STATUS_NO_MEMORY;
    }
    NdisZeroMemory(adapter->path, sizeof(vnif_path_t)
                   * adapter->num_paths);

    VNIF_ALLOCATE_MEMORY(
        adapter->rcv_q,
        sizeof(rcv_to_process_q_t) * adapter->num_rcv_queues,
        VNIF_POOL_TAG,
        NdisMiniportDriverHandle,
        NormalPoolPriority);
    if (adapter->rcv_q == NULL) {
        return STATUS_NO_MEMORY;
    }
    NdisZeroMemory(adapter->rcv_q, sizeof(rcv_to_process_q_t)
                   * adapter->num_rcv_queues);

    for (i = 0; i < adapter->num_rcv_queues; ++i) {
        NdisAllocateSpinLock(&adapter->rcv_q[i].rcv_to_process_lock);
        NdisInitializeListHead(&adapter->rcv_q[i].rcv_to_process);
        adapter->rcv_q[i].n_busy_rcv = 0;
    }
    for (i = 0; i < adapter->num_paths; ++i) {
        NdisAllocateSpinLock(&adapter->path[i].rx_path_lock);
        NdisAllocateSpinLock(&adapter->path[i].tx_path_lock);

#ifdef NDIS60_MINIPORT
        InitializeQueueHeader(&adapter->path[i].send_wait_queue);
#endif

        status = vnif_rss_setup_queue_dpc_path(adapter, i);
        if (status != NDIS_STATUS_SUCCESS) {
            return status;
        }
    }

    status = VNIF_SETUP_PATH_INFO_EX(adapter);

    return NDIS_STATUS_SUCCESS;
}

void
vnif_init_rcb_free_list(PVNIF_ADAPTER adapter, UINT path_id)
{
    UINT i;
    RCB *rcb;

    NdisInitializeListHead(&adapter->path[path_id].rcb_rp.rcb_free_list);
    if (adapter->path[path_id].rcb_rp.rcb_array != NULL) {
        for (i = 0; i < adapter->num_rcb; i++) {
            rcb = adapter->path[path_id].rcb_rp.rcb_array[i];
            if (rcb != NULL) {
                InsertTailList(&adapter->path[path_id].rcb_rp.rcb_free_list,
                               &rcb->list);
            }
        }
    }
}

NDIS_STATUS
vnif_setup_rxtx(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    RPRINTK(DPRTL_ON, ("VNIF: %s - IN\n", __func__));
    do {
        status = VNIFSetupNdisAdapterRx(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        status = VNIFSetupNdisAdapterTx(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }
    } while (FALSE);

    return status;
}

NDIS_STATUS
VNIFSetupNdisAdapter(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupNdisAdapter - IN\n"));
    do {
        NdisAllocateSpinLock(&adapter->stats_lock);
        NdisAllocateSpinLock(&adapter->adapter_flag_lock);
        NdisAllocateSpinLock(&adapter->adapter_lock);

        /* initialize event first, so VNIF_DEC_REF can use it. */
        NdisInitializeEvent(&adapter->RemoveEvent);

        status = VNIFSetupNdisAdapterEx(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        status = VNIFRegisterNdisInterrupt(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        status = vnif_setup_path_info(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            break;
        }

        if (adapter->oid_buffer) {
            switch (adapter->oid) {
            case OID_802_3_PERMANENT_ADDRESS:
                ETH_COPY_NETWORK_ADDRESS(
                    adapter->oid_buffer,
                    adapter->PermanentAddress);
                break;
            case OID_802_3_CURRENT_ADDRESS:
                ETH_COPY_NETWORK_ADDRESS(
                    adapter->oid_buffer,
                    adapter->CurrentAddress);
                break;
            }
            adapter->oid = 0;
            adapter->oid_buffer = NULL;
            VNIFOidRequestComplete(adapter);
        }
    } while (FALSE);

    RPRINTK(DPRTL_ON, ("VNIF: VNIFSetupNdisAdapter - OUT\n"));
    return status;
}

VOID
VNIFFreeAdapter(PVNIF_ADAPTER adapter, NDIS_STATUS status)
{
    uint32_t i;
    uint32_t mac;

    if (adapter == NULL) {
        RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapter with NULL adapter\n"));
        return;
    }

    mac = adapter->CurrentAddress[MAC_LAST_DIGIT];
    RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapter %x - IN\n", mac));
    if (adapter->node_name != NULL) {
        RPRINTK(DPRTL_ON, ("\tFor %s\n", adapter->node_name));
    }

    VNIFDeregisterHardwareResources(adapter);
    VNIFCleanupInterface(adapter, status);
    VNIFFreeAdapterTx(adapter);
    VNIFFreeAdapterRx(adapter);
    VNIFFreeAdapterInterface(adapter);
    vnif_free_path_info(adapter);
    vnif_rss_free_info(adapter);
    VNIFFreeAdapterEx(adapter);

    if (adapter->adapter_flag_lock.SpinLock) {
        NdisFreeSpinLock(&adapter->adapter_flag_lock);
        adapter->adapter_flag_lock.SpinLock = 0;
    }
    if (adapter->stats_lock.SpinLock) {
        NdisFreeSpinLock(&adapter->stats_lock);
        adapter->stats_lock.SpinLock = 0;
    }
    if (adapter->nBusyRecv || adapter->nBusySend) {
        PRINTK(("VNIFFreeAdapter: busy recives = %d, sends = %d.\n",
            adapter->nBusyRecv, adapter->nBusySend));
    }

    NdisZeroMemory(adapter, sizeof(VNIF_ADAPTER));
    NdisFreeMemory(adapter, sizeof(VNIF_ADAPTER), 0);
    adapter = NULL;

    RPRINTK(DPRTL_ON, ("VNIF: VNIFFreeAdapter %x - OUT\n", mac));
}

NDIS_STATUS
VNIFReadPrintMaskRegParameter(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status;
    NDIS_HANDLE config_handle;
    PNDIS_CONFIGURATION_PARAMETER returned_value;

    status = VNIFNdisOpenConfiguration(adapter, &config_handle);
    if (status == NDIS_STATUS_SUCCESS) {
        NdisReadConfiguration(&status,
                              &returned_value,
                              config_handle,
                              &reg_dbg_print_mask_name,
                              NdisParameterHexInteger);
        if (status == NDIS_STATUS_SUCCESS) {
            RPRINTK(DPRTL_INIT,
                    ("VNIF: NdisReadConfiguration dbg_print_mask %x\n",
                     returned_value->ParameterData.IntegerData));
            dbg_print_mask = returned_value->ParameterData.IntegerData;
        }
        NdisCloseConfiguration(config_handle);
    }

    RPRINTK(DPRTL_INIT, ("VNIF: status 0x%x, dbg_print_mask %x\n",
                         status, dbg_print_mask));

    return status;
}

NDIS_STATUS
VNIFReadRegParameters(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status;
    NDIS_HANDLE config_handle;
    NDIS_CONFIGURATION_PARAMETER reg_value;
    PNDIS_CONFIGURATION_PARAMETER returned_value;
    WCHAR wbuffer[16] = {0};
    PUCHAR net_addr;
    PUCHAR str;
    UNICODE_STRING ustr;
    ULONG max_multi_queues;
    uint32_t calc_chksum;
    UINT length;

    status = VNIFNdisOpenConfiguration(adapter, &config_handle);

    RPRINTK(DPRTL_ON,
        ("VNIF: VNIFReadRegParameters back from NdisOpenConfiguration\n"));
    if (status != NDIS_STATUS_SUCCESS) {
        PRINTK(("VNIF: NdisOpenConfiguration failed\n"));
        ETH_COPY_NETWORK_ADDRESS(adapter->CurrentAddress,
            adapter->PermanentAddress);
        return NDIS_STATUS_FAILURE;
    }

    /*
     * Read NetworkAddress registry value and use it as the current address
     * if there is a software configurable NetworkAddress specified in
     * the registry.
     */
    NdisReadNetworkAddress(&status, &net_addr, &length, config_handle);
    RPRINTK(DPRTL_INIT,
        ("VNIF: VNIFReadRegParameters back from NdisReadNetworkAddress\n"));

    if ((status == NDIS_STATUS_SUCCESS) && (length == ETH_LENGTH_OF_ADDRESS)) {
        if (ETH_IS_MULTICAST(net_addr) || ETH_IS_BROADCAST(net_addr)) {
            /* cannot assign a multicast address as a mac address. */
            ETH_COPY_NETWORK_ADDRESS(adapter->CurrentAddress,
                adapter->PermanentAddress);
        } else {
            ETH_COPY_NETWORK_ADDRESS(adapter->CurrentAddress, net_addr);
        }
    } else {
        ETH_COPY_NETWORK_ADDRESS(adapter->CurrentAddress,
            adapter->PermanentAddress);
    }

    RPRINTK(DPRTL_INIT,
        ("VNIF: Permanent Address = %02x-%02x-%02x-%02x-%02x-%02x\n",
              adapter->PermanentAddress[0],
              adapter->PermanentAddress[1],
              adapter->PermanentAddress[2],
              adapter->PermanentAddress[3],
              adapter->PermanentAddress[4],
              adapter->PermanentAddress[5]));

    RPRINTK(DPRTL_INIT,
        ("VNIF: Current Address = %02x-%02x-%02x-%02x-%02x-%02x\n",
              adapter->CurrentAddress[0],
              adapter->CurrentAddress[1],
              adapter->CurrentAddress[2],
              adapter->CurrentAddress[3],
              adapter->CurrentAddress[4],
              adapter->CurrentAddress[5]));

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &net_cfg_instance_id_name,
        NdisParameterString);
    if (status == NDIS_STATUS_SUCCESS) {
        ustr.Length = 0;
        ustr.MaximumLength = GUID_LENGTH * sizeof(WCHAR);
        ustr.Buffer = adapter->net_cfg_guid;
        RtlUnicodeStringCopy(&ustr, &returned_value->ParameterData.StringData);
        adapter->net_cfg_guid[ustr.Length] = 0;
        RPRINTK(DPRTL_INIT, ("NetCfgInstanceId = %ws, len = %d\n",
            adapter->net_cfg_guid, ustr.Length));
    } else {
        PRINTK(("NdisReadConfiguration failed for NetCfgInstanceId %x\n",
            status));
    }

    /* Checksum offloads */
    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_tcp_chksum_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration TCP %x\n", status));
    if (status == NDIS_STATUS_SUCCESS) {
        if (adapter->hw_tasks & VNIF_CHKSUM_TXRX_SUPPORTED) {
            VNIFInitChksumOffload(adapter,
                                  VNIF_CHKSUM_IPV4_TCP,
                                  returned_value->ParameterData.IntegerData &
                                      VNIF_CHKSUM_ACTION_TXRX);
        }
    } else {
        VNIFInitChksumOffload(adapter, VNIF_CHKSUM_IPV4_TCP,
            VNIF_CHKSUM_ACTION_DISABLE);
    }

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_udp_chksum_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration UDP %x\n", status));
    if (status == NDIS_STATUS_SUCCESS) {
        if (adapter->hw_tasks & VNIF_CHKSUM_TXRX_SUPPORTED) {
            VNIFInitChksumOffload(adapter,
                                  VNIF_CHKSUM_IPV4_UDP,
                                  returned_value->ParameterData.IntegerData &
                                      VNIF_CHKSUM_ACTION_TXRX);
        }
    } else {
        VNIFInitChksumOffload(adapter, VNIF_CHKSUM_IPV4_UDP,
            VNIF_CHKSUM_ACTION_DISABLE);
    }

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_tcp6_chksum_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration TCP6 %x\n", status));
    if (status == NDIS_STATUS_SUCCESS) {
        if (adapter->hw_tasks & VNIF_CHKSUM_TXRX_IPV6_SUPPORTED) {
            VNIFInitChksumOffload(adapter,
                                  VNIF_CHKSUM_IPV6_TCP,
                                  returned_value->ParameterData.IntegerData &
                                      VNIF_CHKSUM_ACTION_TXRX);
        }
    } else {
        VNIFInitChksumOffload(adapter, VNIF_CHKSUM_IPV6_TCP,
            VNIF_CHKSUM_ACTION_DISABLE);
    }

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_udp6_chksum_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration UDP6 %x\n", status));
    if (status == NDIS_STATUS_SUCCESS) {
        if (adapter->hw_tasks & VNIF_CHKSUM_TXRX_IPV6_SUPPORTED) {
            VNIFInitChksumOffload(adapter,
                                  VNIF_CHKSUM_IPV6_UDP,
                                  returned_value->ParameterData.IntegerData &
                                      VNIF_CHKSUM_ACTION_TXRX);
        }
    } else {
        VNIFInitChksumOffload(adapter, VNIF_CHKSUM_IPV6_UDP,
            VNIF_CHKSUM_ACTION_DISABLE);
    }

    adapter->lso_enabled = 0;

#ifdef NDIS51_MINIPORT
    /* If hardware supports LSO V1 IpV4, check registry overrides. */
    if (adapter->hw_tasks & VNIF_LSO_V1_SUPPORTED) {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_lso_v1_name,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS
                && returned_value->ParameterData.IntegerData == 1) {
            adapter->lso_enabled |= VNIF_LSOV1_ENABLED;
        }
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration LSO V1 IpV4 %x (status %x)\n",
             adapter->lso_enabled, status));
    }
#else
    /* If hardware supoprts LSO V2 IpV4, check registry overrides. */
    if (adapter->hw_tasks & VNIF_LSO_V2_SUPPORTED) {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_lso_v2_name,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS
                && returned_value->ParameterData.IntegerData == 1) {
            adapter->lso_enabled |= VNIF_LSOV1_ENABLED | VNIF_LSOV2_ENABLED;
        }
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration LSO V2 IpV4 %x (status %x)\n",
             adapter->lso_enabled, status));
    }

    /* If hardware supoprts LSO V2 IpV6, check registry overrides. */
    if (adapter->hw_tasks & VNIF_LSO_V2_IPV6_SUPPORTED) {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_lso_v2_ipv6_name,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS
                && returned_value->ParameterData.IntegerData == 1) {
            adapter->lso_enabled |= VNIF_LSOV2_IPV6_ENABLED;
        }
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration LSO V2 IPv6 %x (status %x)\n",
             adapter->lso_enabled, status));

        /*
         * With the hardware supporting LSO V2 IpV6, check if extension
         * headers support is also to be enabled.
         */
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_lso_v2_ipv6_ext_hdrs_name,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS
                && returned_value->ParameterData.IntegerData == 1) {
            adapter->hw_tasks |= VNIF_LSO_V2_IPV6_EXT_HDRS_SUPPORTED;
            adapter->lso_enabled |= VNIF_LSOV2_IPV6_EXT_HDRS_ENABLED;
        }
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration IPv6 Extensions %x (status %x\n",
             adapter->lso_enabled, status));
    }
#endif

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_lso_data_size_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT,
        ("VNIF: NdisReadConfiguration LSO %x\n", status));
    if (status == NDIS_STATUS_SUCCESS) {
        adapter->lso_data_size = returned_value->ParameterData.IntegerData;

        /*
         * Too large of a value will be handled in the specific
         * VNIFV_SetupAdapterInterface and VNIFX_SetupAdapterInterface.
         */
        if (adapter->lso_data_size < LSO_MIN_DATA_SIZE) {
            adapter->lso_data_size = LSO_MIN_DATA_SIZE;
        }
    } else {
        adapter->lso_data_size = LSO_MIN_DATA_SIZE;
    }
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration LSO data size %d.\n",
        adapter->lso_data_size));

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_rx_sg_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT,
        ("VNIF: NdisReadConfiguration FragmentedReceives %x\n", status));
    if (status == NDIS_STATUS_SUCCESS) {
        if (returned_value->ParameterData.IntegerData == 1) {
            adapter->hw_tasks |= VNIF_RX_SG;
        } else if (returned_value->ParameterData.IntegerData == 2) {
            adapter->hw_tasks |= VNIF_RX_SG_LARGE | VNIF_RX_SG;
        }
    }
    RPRINTK(DPRTL_INIT,
        ("VNIF: %s FragmentedReceives status %x, hw_tasks %x val %d\n",
         __func__, status, adapter->hw_tasks,
         returned_value->ParameterData.IntegerData));

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_numrfd_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration NumRcb %d\n",
        returned_value->ParameterData.IntegerData));
    if (status == NDIS_STATUS_SUCCESS) {
        adapter->num_rcb = returned_value->ParameterData.IntegerData;
        if (adapter->num_rcb > VNIF_MAX_NUM_RCBS || adapter->num_rcb == 0) {
            adapter->num_rcb = NET_RX_RING_SIZE;
        } else if (adapter->num_rcb == 0) {
            adapter->num_rcb = NET_RX_RING_SIZE;
        }
    } else {
        adapter->num_rcb = NET_RX_RING_SIZE;
        status = NDIS_STATUS_SUCCESS;
    }

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_rcv_limit_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration rcv limit %d\n",
        returned_value->ParameterData.IntegerData));
    if (status == NDIS_STATUS_SUCCESS) {
        adapter->rcv_limit = returned_value->ParameterData.IntegerData;
        if (adapter->rcv_limit > NET_RX_RING_SIZE) {
            adapter->rcv_limit = NET_RX_RING_SIZE;
        } else if (adapter->rcv_limit < 1) {
            adapter->rcv_limit = 1;
        }
    } else {
        adapter->rcv_limit = VNIF_DEFAULT_BUSY_RECVS;
        status = NDIS_STATUS_SUCCESS;
    }

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_resource_timeout_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration resource timeout %d\n",
        returned_value->ParameterData.IntegerData));
    if (status == NDIS_STATUS_SUCCESS) {
        adapter->resource_timeout = returned_value->ParameterData.IntegerData;
        if (adapter->resource_timeout > VNIF_MAX_RESOURCE_TIMEOUT) {
            adapter->resource_timeout = VNIF_DEF_RESOURCE_TIMEOUT;
        }
    } else {
        adapter->resource_timeout = VNIF_DEF_RESOURCE_TIMEOUT;
        status = NDIS_STATUS_SUCCESS;
    }

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_stat_interval_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT,
        ("VNIF: NdisReadConfiguration reg_stat_interval_name %d\n",
        returned_value->ParameterData.IntegerData));
    if (status == NDIS_STATUS_SUCCESS) {
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration reg_stat_timer_success\n"));
        if (returned_value->ParameterData.IntegerData
                > VNIF_MAX_RCV_STAT_TIMER_INTERVAL) {
            returned_value->ParameterData.IntegerData =
                 VNIF_MAX_RCV_STAT_TIMER_INTERVAL;
        }
        if (returned_value->ParameterData.IntegerData) {
            if (adapter->pv_stats == NULL) {
                VNIF_ALLOCATE_MEMORY(
                    adapter->pv_stats,
                    sizeof(vnif_pv_stats_t),
                    VNIF_POOL_TAG,
                    NdisMiniportDriverHandle,
                    NormalPoolPriority);
                if (adapter->pv_stats != NULL) {
                    NdisZeroMemory(adapter->pv_stats, sizeof(vnif_pv_stats_t));
                    adapter->pv_stats->interval = 1000 *
                        returned_value->ParameterData.IntegerData;
#ifdef DBG
                    adapter->pv_stats->starting_print_mask = dbg_print_mask;
#endif
                } else {
                    PRINTK(("VNIF: Failed to allocate memory for rcv_stats\n"));
                    status = STATUS_NO_MEMORY;
                }
            }
        }
    } else {
        RPRINTK(DPRTL_ON,
            ("VNIF: NdisReadConfiguration reg_stat_timer_failed\n"));
        status = NDIS_STATUS_SUCCESS;
    }

    /* If set, use its value.  Otherwise, get it from the registry .*/
    if (adapter->mtu == 0) {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_mtu_name,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS) {
            adapter->mtu = returned_value->ParameterData.IntegerData;
        } else {
            adapter->mtu = ETH_MAX_DATA_SIZE;
        }
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration MTU (%d) status %x\n",
             adapter->mtu, status));
    }
    if (adapter->mtu > MTU_MAX_SIZE) {
        adapter->mtu = MTU_MAX_SIZE;
    } else if (adapter->mtu < MTU_MIN_SIZE) {
        adapter->mtu = MTU_MIN_SIZE;
    }
    adapter->max_frame_sz = adapter->mtu + ETH_HEADER_SIZE;
    status = NDIS_STATUS_SUCCESS;

    adapter->rx_alloc_buffer_size = g_running_hypervisor == HYPERVISOR_KVM ?
        (((adapter->max_frame_sz + adapter->buffer_offset - 1)
          >> PAGE_SHIFT) + 1) * PAGE_SIZE :
        PAGE_SIZE;

    RPRINTK(DPRTL_INIT, ("VNIF: mtu %d mfz %d bfz 0x%x\n",
        adapter->mtu, adapter->max_frame_sz, adapter->rx_alloc_buffer_size));

    /* If set, use its value.  Otherwise, get it from the registry. */
    if (adapter->ul64LinkSpeed == 0) {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_link_speed_name,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS) {
            adapter->ul64LinkSpeed = returned_value->ParameterData.IntegerData;
        } else {
            adapter->ul64LinkSpeed = VNIF_DEFAULT_REG_LINK_SPEED;
        }
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration LinkSpeed (%lld) status %x\n",
             adapter->ul64LinkSpeed, status));
    }
    if (adapter->ul64LinkSpeed > VNIF_MAX_REG_LINK_SPEED) {
        adapter->ul64LinkSpeed = VNIF_MAX_REG_LINK_SPEED;
    } else if (adapter->ul64LinkSpeed < VNIF_MIN_REG_LINK_SPEED) {
        adapter->ul64LinkSpeed = VNIF_MIN_REG_LINK_SPEED;
    }
    adapter->ul64LinkSpeed *= VNIF_BASE_LINK_SPEED;
    status = NDIS_STATUS_SUCCESS;

#ifndef NDIS60_MINIPORT

#ifdef VNIF_RCV_DELAY
    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_delay_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration rcv delay %d\n",
        returned_value->ParameterData.IntegerData));
    if (status == NDIS_STATUS_SUCCESS) {
        adapter->rcv_delay = returned_value->ParameterData.IntegerData;
    } else {
        adapter->rcv_delay = 0;
        status = NDIS_STATUS_SUCCESS;
    }
#endif

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_tx_throttle_start_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration tx_throttle_start %d\n",
        returned_value->ParameterData.IntegerData));
    if (status == NDIS_STATUS_SUCCESS) {
        adapter->tx_throttle_start = returned_value->ParameterData.IntegerData;
        if (adapter->tx_throttle_start > adapter->num_rcb) {
            adapter->tx_throttle_start = adapter->num_rcb;
        }
    } else {
        adapter->tx_throttle_start = adapter->num_rcb;
        status = NDIS_STATUS_SUCCESS;
    }
    RPRINTK(DPRTL_INIT,
        ("VNIF: tx_throttle_start %d\n", adapter->tx_throttle_start));

    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_tx_throttle_stop_name,
        NdisParameterInteger);
    RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration tx_throttle_stop %d\n",
        returned_value->ParameterData.IntegerData));
    if (status == NDIS_STATUS_SUCCESS) {
        if (returned_value->ParameterData.IntegerData <=
                adapter->tx_throttle_start) {
            adapter->tx_throttle_stop =
                returned_value->ParameterData.IntegerData;
        } else {
            /*
             * It makes no sense to have the stop value greater than the
             * start value.  Set the stop to the start and then write
             * the value back to the registry so that NIC configuration
             * will accurately reflect what is being used.
             */
            adapter->tx_throttle_stop = adapter->tx_throttle_start;
            reg_value.ParameterType = NdisParameterString;
            reg_value.ParameterData.StringData.Length = 0;
            reg_value.ParameterData.StringData.MaximumLength = sizeof(wbuffer);
            reg_value.ParameterData.StringData.Buffer = wbuffer;
            RtlIntegerToUnicodeString(adapter->tx_throttle_start, 10,
                &reg_value.ParameterData.StringData);
            reg_value.ParameterData.StringData.Length += sizeof(WCHAR);
            NdisWriteConfiguration(
                &status,
                config_handle,
                &reg_tx_throttle_stop_name,
                &reg_value);
        }
    } else {
        adapter->tx_throttle_stop = adapter->tx_throttle_start;
        status = NDIS_STATUS_SUCCESS;
    }
    RPRINTK(DPRTL_INIT,
        ("VNIF: tx_throttle_stop %d\n", adapter->tx_throttle_stop));
#endif

#ifdef TARGET_OS_GE_Win8
    if (g_running_hypervisor == HYPERVISOR_KVM) {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_pmc_name ,
            NdisParameterInteger);
        RPRINTK(DPRTL_INIT, ("VNIF: NdisReadConfiguration PMC status %x\n",
            status));
        if (status == NDIS_STATUS_SUCCESS) {
            if (returned_value->ParameterData.IntegerData == 0) {
                adapter->hw_tasks &= ~VNIF_PMC;
            } else {
                adapter->hw_tasks |= VNIF_PMC;
            }
        } else {
            adapter->hw_tasks &= ~VNIF_PMC;
            status = NDIS_STATUS_SUCCESS;
        }
        RPRINTK(DPRTL_INIT, ("VNIF: PMC %x\n", adapter->hw_tasks & VNIF_PMC));
    }

#endif

    adapter->num_paths = 1;
    adapter->num_rcv_queues = 1;
#ifdef NDIS620_MINIPORT
    NdisReadConfiguration(
        &status,
        &returned_value,
        config_handle,
        &reg_rss,
        NdisParameterInteger);
    if (status == NDIS_STATUS_SUCCESS) {
        if (returned_value->ParameterData.IntegerData == 0) {
            adapter->b_rss_supported = FALSE;
        } else {
            adapter->b_rss_supported = TRUE;
        }
    } else {
        RPRINTK(DPRTL_INIT,
                ("VNIF: NdisReadConfiguration RSS status %x\n", status));
        adapter->b_rss_supported = FALSE;
        status = NDIS_STATUS_SUCCESS;
    }

    if (adapter->b_rss_supported) {

        /* Default to min of number of active CPUs and max. */
        adapter->num_rcv_queues = min(
            KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS),
            VNIF_MAX_NUM_RSS_QUEUES);

        NdisReadConfiguration(&status,
                              &returned_value,
                              config_handle,
                              &reg_num_rss_qs,
                              NdisParameterInteger);

        if (status == NDIS_STATUS_SUCCESS) {
            max_multi_queues = returned_value->ParameterData.IntegerData;
            RPRINTK(DPRTL_INIT,
                ("VNIF: NdisReadConfiguration reg_num_rss_qs value: %d\n",
                 max_multi_queues));
            adapter->num_rcv_queues = min(adapter->num_rcv_queues,
                                          max_multi_queues);
        } else {
            RPRINTK(DPRTL_INIT,
               ("VNIF: NdisReadConfiguration failed to read reg_num_rss_qs\n"));
            adapter->num_rcv_queues = min(adapter->num_rcv_queues,
                                          adapter->num_hw_queues);
            status = NDIS_STATUS_SUCCESS;
        }

        if (adapter->num_rcv_queues == 1) {
            /* No need to enable RSS if there is only 1 receive queue. */
            adapter->b_rss_supported = FALSE;

            /* Disable *RSS in the registry. */
            reg_value.ParameterType = NdisParameterString;
            reg_value.ParameterData.StringData.Length = 0;
            reg_value.ParameterData.StringData.MaximumLength = sizeof(wbuffer);
            reg_value.ParameterData.StringData.Buffer = wbuffer;
            RtlIntegerToUnicodeString(0,
                                      10,
                                      &reg_value.ParameterData.StringData);
            reg_value.ParameterData.StringData.Length += sizeof(WCHAR);
            NdisWriteConfiguration(
                &status,
                config_handle,
                &reg_rss,
                &reg_value);
        } else {
            adapter->num_rcv_queues++; /* Add 1 for the VNIF_NO_RECEIVE_QUEUE */

            NdisReadConfiguration(
                &status,
                &returned_value,
                config_handle,
                &reg_rss_tcp_ipv6_ext_hdrs_name,
                NdisParameterInteger);
            if (status == NDIS_STATUS_SUCCESS
                    && returned_value->ParameterData.IntegerData == 1) {
                adapter->hw_tasks |= VNIF_RSS_TCP_IPV6_EXT_HDRS_SUPPORTED;
            }
        }
    } else {
        RPRINTK(DPRTL_ON,
                ("VNIF: NdisReadConfiguration reg_num_rss_qs not supported\n"));
    }
    RPRINTK(DPRTL_INIT,
        ("VNIF: NdisReadConfiguration num_rss_qs set to %d\n",
         adapter->num_rcv_queues));

    NdisReadConfiguration(&status,
                          &returned_value,
                          config_handle,
                          &reg_num_paths,
                          NdisParameterInteger);

    if (status == NDIS_STATUS_SUCCESS) {
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration reg_num_paths value: %d\n",
             returned_value->ParameterData.IntegerData));
        if (returned_value->ParameterData.IntegerData == 0
                && adapter->b_rss_supported) {
            adapter->num_paths = adapter->num_hw_queues;
        } else if (returned_value->ParameterData.IntegerData
                > adapter->num_hw_queues) {
            adapter->num_paths = adapter->num_hw_queues;
        } else if (returned_value->ParameterData.IntegerData != 0) {
            adapter->num_paths = returned_value->ParameterData.IntegerData;
        }
    } else {
        RPRINTK(DPRTL_INIT,
           ("VNIF: NdisReadConfiguration failed to read reg_num_paths\n"));
        status = NDIS_STATUS_SUCCESS;
    }

    RPRINTK(DPRTL_INIT,
        ("VNIF: NdisReadConfiguration num_paths set to %d\n",
         adapter->num_paths));
#endif

    adapter->b_use_split_evtchn = FALSE;
#if defined XENNET || defined PVVXNET
    if (g_running_hypervisor == HYPERVISOR_XEN) {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_split_evtchn,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS) {
            if (returned_value->ParameterData.IntegerData == 1
                    && adapter->u.x.feature_split_evtchn) {
                adapter->b_use_split_evtchn = TRUE;
            }
        } else {
            RPRINTK(DPRTL_INIT,
               ("VNIF: NdisReadConfiguration SplitEvtchn status %x\n", status));
            status = NDIS_STATUS_SUCCESS;
        }
        RPRINTK(DPRTL_INIT,
            ("VNIF: NdisReadConfiguration split_evtchn set to %d\n",
             adapter->b_use_split_evtchn));
    }
#endif

    /* ONly check for indirect descriptors if the feature is enabled. */
    if (adapter->b_indirect == TRUE) {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_indirect_desc,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS) {
            if (returned_value->ParameterData.IntegerData == 0) {
                adapter->b_indirect = FALSE;
                RPRINTK(DPRTL_INIT,
                   ("VNIF: NdisReadConfiguration disabe IndirectDesc\n"));
            }
        } else {
            RPRINTK(DPRTL_INIT,
               ("VNIF: NdisReadConfiguration IndirectDescriptors status %x\n",
                status));
            status = NDIS_STATUS_SUCCESS;
        }
    }

    if (g_running_hypervisor == HYPERVISOR_XEN) {
        adapter->max_sg_el = VNIF_XEN_MAX_TX_SG_ELEMENTS;
    } else {
        NdisReadConfiguration(
            &status,
            &returned_value,
            config_handle,
            &reg_tx_sg_cnt,
            NdisParameterInteger);
        if (status == NDIS_STATUS_SUCCESS) {
            adapter->max_sg_el = returned_value->ParameterData.IntegerData;
            if (adapter->max_sg_el < VNIF_VIRTIO_MIN_TX_SG_ELEMENTS) {
                RPRINTK(DPRTL_INIT,
                   ("VNIF: NdisReadConfiguration tx sgl %d < %d\n",
                    adapter->max_sg_el, VNIF_VIRTIO_MIN_TX_SG_ELEMENTS));
                adapter->max_sg_el = VNIF_VIRTIO_MIN_TX_SG_ELEMENTS;
            } else if (adapter->max_sg_el > VNIF_MAX_TX_SG_ELEMENTS) {
                RPRINTK(DPRTL_INIT,
                   ("VNIF: NdisReadConfiguration tx sgl %d > %d\n",
                    adapter->max_sg_el, VNIF_MAX_TX_SG_ELEMENTS));
                adapter->max_sg_el = VNIF_MAX_TX_SG_ELEMENTS;
            }
        } else {
            RPRINTK(DPRTL_INIT,
               ("VNIF: NdisReadConfiguration set tx sgl to default status %x\n",
                status));
            adapter->max_sg_el = VNIF_VIRTIO_DEF_TX_SG_ELEMENTS;
            status = NDIS_STATUS_SUCCESS;
        }
    }

    NdisCloseConfiguration(config_handle);

    RPRINTK(DPRTL_ON, ("VNIF: VNIFReadRegParameters - OUT\n"));
    return status;
}

void
VNIFDumpSettings(PVNIF_ADAPTER adapter)
{
    PRINTK(("%s %x: initialization complete.\n",
        adapter->node_name, adapter->CurrentAddress[MAC_LAST_DIGIT]));
    PRINTK(("\thw_tasks = 0x%x\n", adapter->hw_tasks));
    PRINTK(("\tlso_enabled = 0x%x\n", adapter->lso_enabled));
    PRINTK(("\ttx_checksum = 0x%x\n\trx_checksum = 0x%x\n",
        adapter->cur_tx_tasks, adapter->cur_rx_tasks));
    PRINTK(("\tmtu = %d\n", adapter->mtu));
    PRINTK(("\tlink speed = %d\n",
        (uint32_t)(adapter->ul64LinkSpeed / VNIF_BASE_LINK_SPEED)));
    PRINTK(("\tduplex state = %d\n", adapter->duplex_state));
    PRINTK(("\tLSO size %d\n", adapter->lso_data_size));
    PRINTK(("\trcbs = %d\n", adapter->num_rcb));
    PRINTK(("\trcv limit = %d\n", adapter->rcv_limit));
    PRINTK(("\tresource timeout = %d\n", adapter->resource_timeout));
    if (adapter->pv_stats) {
        adapter->pv_stats->stat_timer_st = KeQueryInterruptTime();
        VNIF_SET_TIMER(adapter->pv_stats->stat_timer,
            adapter->pv_stats->interval);
        PRINTK(("\tstats timer interval = %d\n",
            adapter->pv_stats->interval));
    }
    PRINTK(("\tdbg_print_mask = 0x%x\n", dbg_print_mask));
    PRINTK(("\tindirect descriptors = %d\n", adapter->b_indirect));
    PRINTK(("\tTx sgl elements = %d\n", adapter->max_sg_el));
#if defined XENNET || defined PVVXNET
    if (g_running_hypervisor == HYPERVISOR_XEN) {
        PRINTK(("\tfeature-split-event-channels = %d\n",
                adapter->u.x.feature_split_evtchn));
        PRINTK(("\tfront end using split-event-channels = %d\n",
                adapter->b_use_split_evtchn));
    }
#endif
    PRINTK(("\tnum hw queues = %d\n", adapter->num_hw_queues));
    PRINTK(("\tnum paths = %d\n", adapter->num_paths));
#ifdef NDIS620_MINIPORT
    PRINTK(("\tmulti-queue supported = %d\n", adapter->b_multi_queue));
    PRINTK(("\trss supported = %d\n", adapter->b_rss_supported));

    /* Don't count the VNIVF_NO_RECEIVE_QUEUE if supported. */
    PRINTK(("\trss num receive queues = %d\n",
            adapter->num_rcv_queues - adapter->b_rss_supported));
#endif
#ifndef NDIS60_MINIPORT
#ifdef VNIF_RCV_DELAY
    PRINTK(("\trcv delay = %d\n", adapter->rcv_delay));
#endif
    PRINTK(("\ttx throttle start = %d\n\ttx throttle stop = %d\n",
        adapter->tx_throttle_start, adapter->tx_throttle_stop));
#endif
}
