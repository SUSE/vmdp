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
#include <virtio_ring.h>
#include <virtio_config.h>
#include <virtio_utils.h>
#include <virtio_net.h>

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

static int VNIFSetupPermanentAddress(PVNIF_ADAPTER adapter);
static void MPResume(PVNIF_ADAPTER adapter, uint32_t suspend_canceled);

void VNIFV_ALLOCATE_SHARED_MEMORY(VNIF_ADAPTER *adapter, void **va,
    PHYSICAL_ADDRESS *pa, uint32_t len, NDIS_HANDLE hndl)
{
    NdisMAllocateSharedMemory(
        adapter->AdapterHandle,
        len,
        adapter->u.v.cached,
        va,
        pa);
}

void
vnifv_unmap_io_space(PVNIF_ADAPTER adapter)
{
    ULONG i;

    for (i = 0; i < PCI_TYPE0_ADDRESSES; i++) {
        if (adapter->u.v.vbar[i].va != NULL) {
            if (adapter->u.v.vbar[i].bPortSpace == FALSE) {
                NdisMUnmapIoSpace(adapter->AdapterHandle,
                                  adapter->u.v.vbar[i].va,
                                  adapter->u.v.vbar[i].len);
            } else {
                NdisMDeregisterIoPortRange(adapter->AdapterHandle,
                                           adapter->u.v.vbar[i].pa.u.LowPart,
                                           adapter->u.v.vbar[i].len,
                                           adapter->u.v.vbar[i].va);
            }
            adapter->u.v.vbar[i].va = NULL;
            adapter->u.v.vbar[i].len = 0;
        }
    }
}

void
VNIFV_FreeAdapterInterface(PVNIF_ADAPTER adapter)
{
    UINT i;
    RPRINTK(DPRTL_ON, ("%s %s %x: IN\n",
                       VNIF_DRIVER_NAME, __func__,
                       adapter->CurrentAddress[MAC_LAST_DIGIT]));

    if (adapter->u.v.vdev.dev_op == NULL) {
        return;
    }

    RPRINTK(DPRTL_ON, ("\tdoing a reset.\n"));
    VIRTIO_DEVICE_RESET(&adapter->u.v.vdev);

    RPRINTK(DPRTL_ON, ("\tdoing a reset features.\n"));
    virtio_device_reset_features(&adapter->u.v.vdev);

    if (adapter->path != NULL) {
        for (i = 0; i < adapter->num_paths; ++i) {
            if (adapter->path[i].rx) {
                RPRINTK(DPRTL_ON, ("\tdeleting rx queue.\n"));
                VIRTIO_DEVICE_QUEUE_DELETE(&adapter->u.v.vdev,
                                           adapter->path[i].rx, TRUE);
                adapter->path[i].rx = NULL;
                adapter->path[i].u.vq.rx = NULL;
            }
            if (adapter->path[i].tx) {
                RPRINTK(DPRTL_ON, ("\tdeleting tx queue.\n"));
                VIRTIO_DEVICE_QUEUE_DELETE(&adapter->u.v.vdev,
                                           adapter->path[i].tx, TRUE);
                adapter->path[i].tx = NULL;
                adapter->path[i].u.vq.tx = NULL;
            }
        }
    }

    if (adapter->u.v.ctrl_q) {
        VIRTIO_DEVICE_QUEUE_DELETE(&adapter->u.v.vdev,
                                   adapter->u.v.ctrl_q,
                                   TRUE);
        adapter->u.v.ctrl_q = NULL;
    }

    if (!(adapter->adapter_flags & VNF_ADAPTER_NEEDS_RSTART)) {
        vnifv_unmap_io_space(adapter);
    }

    if (adapter->u.v.ctrl_buf) {
        VNIF_FREE_SHARED_MEMORY(
            adapter,
            adapter->u.v.ctrl_buf,
            adapter->u.v.ctrl_buf_pa,
            VNIF_CTRL_BUF_SIZE,
            NdisMiniportDriverHandle);
        adapter->u.v.ctrl_buf = NULL;
        adapter->u.v.ctrl_buf_pa.QuadPart = 0;
        NdisFreeSpinLock(&adapter->u.v.ctrl_lock);
    }
    RPRINTK(DPRTL_ON, ("%s %s %x: OUT\n",
             VNIF_DRIVER_NAME, __func__,
             adapter->CurrentAddress[MAC_LAST_DIGIT]));
}

void
VNIFV_CleanupInterface(PVNIF_ADAPTER adapter, NDIS_STATUS status)
{
}

NDIS_STATUS
VNIFV_FindAdapter(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status;
    uint32_t link_speed;
    uint16_t linkStatus;
    uint8_t duplex;

    RPRINTK(DPRTL_ON, ("VNIFFindAdapter: IN\n"));
    status = NDIS_STATUS_SUCCESS;
    do {
        /* All adapter fields are zeroed out when adapter was allocated.
         * No need to set any values to 0.
         */

        VNIF_ALLOCATE_SHARED_MEMORY = VNIFV_ALLOCATE_SHARED_MEMORY;

        adapter->node_name = VNIF_DRIVER_NAME;
        adapter->u.v.cached = TRUE;

        vnif_virtio_dev_reset(adapter);

        adapter->u.v.features = VIRTIO_DEVICE_GET_FEATURES(
            &adapter->u.v.vdev);
        PRINTK(("%s: host features 0x%llx\n",
                VNIF_DRIVER_NAME, adapter->u.v.features));

        if (virtio_is_feature_enabled(adapter->u.v.features,
                                      VIRTIO_NET_F_CSUM)) {
            RPRINTK(DPRTL_INIT, ("VNIFFindAdapter: backend supports csum.\n"));
            adapter->hw_tasks |=
                VNIF_CHKSUM_TXRX_SUPPORTED | VNIF_CHKSUM_TXRX_IPV6_SUPPORTED;
        }

        if (virtio_is_feature_enabled(adapter->u.v.features,
                                      VIRTIO_NET_F_HOST_TSO4)) {
            RPRINTK(DPRTL_INIT, ("VNIFFindAdapter: backend LSO.\n"));
            adapter->hw_tasks |= VNIF_LSO_SUPPORTED;
        }

        if (virtio_is_feature_enabled(adapter->u.v.features,
                                      VIRTIO_NET_F_HOST_TSO6)) {
            RPRINTK(DPRTL_INIT, ("VNIFFindAdapter: backend LSO.\n"));
            adapter->hw_tasks |= VNIF_LSO_V2_IPV6_SUPPORTED;
        }

        if (virtio_is_feature_enabled(adapter->u.v.features,
                                      VIRTIO_NET_F_MRG_RXBUF)) {
            adapter->buffer_offset = sizeof(virtio_net_hdr_mrg_t);
            RPRINTK(DPRTL_INIT, ("%s: Using mergable buffers, offset %d\n",
                                 VNIF_DRIVER_NAME,
                                 adapter->buffer_offset));
        } else {
            PRINTK(("%s: Not using mergable buffers.\n", VNIF_DRIVER_NAME));
        }

        VIRTIO_DEVICE_GET_CONFIG(&adapter->u.v.vdev,
            ETH_LENGTH_OF_ADDRESS,
            &linkStatus,
            sizeof(linkStatus));
        RPRINTK(DPRTL_INIT, ("VNIFFindAdapter: link status %x.\n", linkStatus));

        adapter->duplex_state = MediaDuplexStateFull;

        if (virtio_is_feature_enabled(adapter->u.v.features,
                                      VIRTIO_NET_F_MTU)) {
            RPRINTK(DPRTL_INIT, ("VNIFFindAdapter: backend supports MTU.\n"));
            VIRTIO_DEVICE_GET_CONFIG(&adapter->u.v.vdev,
                offsetof(virtio_net_config_t, mtu),
                &adapter->mtu,
                sizeof(uint16_t));
            RPRINTK(DPRTL_INIT, ("VNIFFindAdapter: backend MTU %d.\n",
                                 adapter->mtu));
        }

        if (virtio_is_feature_enabled(adapter->u.v.features,
                                      VIRTIO_NET_F_SPEED_DUPLEX)) {
            RPRINTK(DPRTL_INIT,
                    ("VNIFFindAdapter: backend supports speed duplex.\n"));
            VIRTIO_DEVICE_GET_CONFIG(&adapter->u.v.vdev,
                offsetof(virtio_net_config_t, speed),
                &link_speed,
                sizeof(uint32_t));
            if (link_speed != VIRTIO_NET_SPEED_UNKNOWN) {
                adapter->ul64LinkSpeed = link_speed;
            }

            VIRTIO_DEVICE_GET_CONFIG(&adapter->u.v.vdev,
                offsetof(virtio_net_config_t, duplex),
                &duplex,
                sizeof(uint8_t));
            if (duplex == VIRTIO_NET_DUPLEX_HALF) {
                adapter->duplex_state = MediaDuplexStateHalf;
            }
            RPRINTK(DPRTL_INIT, ("VNIFFindAdapter: speed %d, duplex %d.\n",
                                 link_speed, duplex));
        }

        if (virtio_is_feature_enabled(adapter->u.v.features,
                                      VIRTIO_NET_F_CTRL_VQ)) {
            adapter->u.v.b_control_queue = TRUE;
        }

        if (adapter->u.v.b_control_queue == TRUE
                && virtio_is_feature_enabled(adapter->u.v.features,
                                             VIRTIO_NET_F_MQ)) {
            adapter->b_multi_queue = TRUE;
            VIRTIO_DEVICE_GET_CONFIG(&adapter->u.v.vdev,
                ETH_LENGTH_OF_ADDRESS + sizeof(uint16_t),
                &adapter->num_hw_queues,
                sizeof(uint16_t));
        } else {
            adapter->num_hw_queues = 1;
        }
        RPRINTK(DPRTL_INIT,
                ("VNIFFindAdapter: control_q %d, multi_q %d num_hw_q %d.\n",
                 adapter->u.v.b_control_queue,
                 adapter->b_multi_queue,
                 adapter->num_hw_queues));

        if (virtio_is_feature_enabled(adapter->u.v.features,
                                      VIRTIO_RING_F_INDIRECT_DESC)) {
            adapter->b_indirect = TRUE;
            RPRINTK(DPRTL_INIT, ("VNIFFindAdapter: indirect descriptors %d.\n",
                                 adapter->b_indirect));
        }

        /* MAC */
        status = VNIFSetupPermanentAddress(adapter);
        if (status != NDIS_STATUS_SUCCESS) {
            PRINTK(("VNIF: set NIC MAC fail.\n"));
            break;
        }
    } while (FALSE);

    if (status != NDIS_STATUS_SUCCESS) {
        VNIFFreeAdapterInterface(adapter);
    }
    RPRINTK(DPRTL_ON, ("VNIFFindAdapter: OUT %p, %s, status %x\n",
        adapter, adapter->node_name, status));
    return status;
}

static NDIS_STATUS
vnif_init_rcb_pool(PVNIF_ADAPTER adapter)
{
    PLIST_ENTRY entry;
    RCB *rcb;
    virtio_buffer_descriptor_t sg;
    UINT path_id;
    UINT i;

    RPRINTK(DPRTL_ON, ("%s: irql = %d - IN\n", __func__, KeGetCurrentIrql()));
    for (path_id = 0; path_id < adapter->num_paths; path_id++) {
        NdisAcquireSpinLock(&adapter->path[path_id].rx_path_lock);

        vnif_init_rcb_free_list(adapter, path_id);

        sg.len = adapter->rx_alloc_buffer_size;
        for (i = 0; i < adapter->path[path_id].u.vq.rx->vring.num; i++) {
            rcb = (RCB *)RemoveHeadList(
                &adapter->path[path_id].rcb_rp.rcb_free_list);
            sg.phys_addr = rcb->page_pa.QuadPart;
            vring_add_buf(adapter->path[path_id].u.vq.rx, &sg, 0, 1, rcb);
        }

        NdisReleaseSpinLock(&adapter->path[path_id].rx_path_lock);

        RPRINTK(DPRTL_ON,
          ("%s: using %d receive buffers. OUT\n", __func__, adapter->num_rcb));
    }
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
vnif_init_tx(PVNIF_ADAPTER adapter)
{
    TCB *tcb;
    ULONG num_ring_desc;
    UINT i;
    UINT p;

    /* Allocate for each TCB, because sizeof(TCB) is less than PAGE_SIZE,
     * it will not cross page boundary.
     */
    for (i = 0; i < adapter->num_paths; i++) {
        NdisInitializeListHead(&adapter->path[i].tcb_free_list);
    }
#ifndef NDIS60_MINIPORT
    NdisInitializeListHead(&adapter->SendWaitList);
#endif
    adapter->nBusySend = 0;

    num_ring_desc = VNIF_TX_RING_SIZE(adapter);
    for (p = 0; p < adapter->num_paths; p++) {
        for (i = 0; i < num_ring_desc; i++) {
            tcb = adapter->TCBArray[(p * num_ring_desc) + i];
            NdisInterlockedInsertTailList(
                &adapter->path[p].tcb_free_list,
                &tcb->list,
                &adapter->path[p].tx_path_lock);
        }
    }
    return NDIS_STATUS_SUCCESS;
}

static void
vnif_set_guest_features(PVNIF_ADAPTER adapter)
{
    uint64_t guest_features;

    guest_features = 0;

    if (virtio_is_feature_enabled(adapter->u.v.features,
                                  VIRTIO_F_VERSION_1)) {
        virtio_feature_enable(guest_features, VIRTIO_F_VERSION_1);
    }

    if (virtio_is_feature_enabled(adapter->u.v.features,
                                  VIRTIO_RING_F_INDIRECT_DESC)) {
        virtio_feature_enable(guest_features, VIRTIO_RING_F_INDIRECT_DESC);
    }

    if ((adapter->cur_rx_tasks & (VNIF_CHKSUM_IPV4_TCP
                                  | VNIF_CHKSUM_IPV4_UDP
                                  | VNIF_CHKSUM_IPV6_TCP
                                  | VNIF_CHKSUM_IPV6_UDP))
            && virtio_is_feature_enabled(adapter->u.v.features,
                                  VIRTIO_NET_F_CSUM)) {
        virtio_feature_enable(guest_features, VIRTIO_NET_F_CSUM);
        virtio_feature_enable(guest_features, VIRTIO_NET_F_GUEST_CSUM);
    }

    if (adapter->lso_enabled & (VNIF_LSOV1_ENABLED | VNIF_LSOV2_ENABLED)) {
        virtio_feature_enable(guest_features, VIRTIO_NET_F_HOST_TSO4);
    }

    if (adapter->lso_enabled & VNIF_LSOV2_IPV6_ENABLED) {
        virtio_feature_enable(guest_features, VIRTIO_NET_F_HOST_TSO6);
    }

    if (adapter->buffer_offset) {
        virtio_feature_enable(guest_features, VIRTIO_NET_F_MRG_RXBUF);
    }
    if (adapter->b_multi_queue) {
        virtio_feature_enable(guest_features, VIRTIO_NET_F_MQ);
    }

    PRINTK(("Virtio_net: setting guest features 0x%llx\n", guest_features));
    virtio_device_set_guest_feature_list(&adapter->u.v.vdev,
                                         guest_features);
}

static NDIS_STATUS
vnif_setup_queues(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status;
    UINT i;

    status = NDIS_STATUS_SUCCESS;

    for (i = 0; i < adapter->num_paths; ++i) {
        RPRINTK(DPRTL_INIT,
                ("%s: virtio_q_setup [%d] rx[%d] m %d tx[%d] m %d\n",
                 __func__, i,
                 i*2, adapter->path[i].u.vq.rx_msg,
                 (i*2) + 1, adapter->path[i].u.vq.tx_msg));
        adapter->path[i].u.vq.rx = VIRTIO_DEVICE_QUEUE_SETUP(
            &adapter->u.v.vdev,
            i * 2,
            NULL,
            NULL,
            0,
            adapter->path[i].u.vq.rx_msg,
            FALSE);
        if (adapter->path[i].u.vq.rx == NULL) {
            PRINTK(("Failed to setup rx queue for path %d msg %d\n",
                    i, adapter->path[i].u.vq.rx_msg));
            status = NDIS_ERROR_CODE_OUT_OF_RESOURCES;
            break;
        }
        adapter->path[i].rx = adapter->path[i].u.vq.rx;

        adapter->path[i].u.vq.tx = VIRTIO_DEVICE_QUEUE_SETUP(
            &adapter->u.v.vdev,
            (i * 2) + 1,
            NULL,
            NULL,
            0,
            adapter->path[i].u.vq.tx_msg,
            FALSE);
        if (adapter->path[i].u.vq.tx == NULL) {
            PRINTK(("Failed to setup tx queue for path %d msg %d\n",
                    i, adapter->path[i].u.vq.tx_msg));
            status = NDIS_ERROR_CODE_OUT_OF_RESOURCES;
            break;
        }
        adapter->path[i].tx = adapter->path[i].u.vq.tx;
    }
    if (status == NDIS_STATUS_SUCCESS) {
        if (adapter->u.v.b_control_queue == TRUE) {
            NdisAllocateSpinLock(&adapter->u.v.ctrl_lock);

            VNIF_ALLOCATE_SHARED_MEMORY(
                adapter,
                &adapter->u.v.ctrl_buf,
                &adapter->u.v.ctrl_buf_pa,
                VNIF_CTRL_BUF_SIZE,
                NdisMiniportDriverHandle);
            if (adapter->u.v.ctrl_buf == NULL) {
                PRINTK(("VNIF: fail to allocate control buffer.\n"));
                status = STATUS_NO_MEMORY;
            }
            if (status == NDIS_STATUS_SUCCESS) {
                adapter->u.v.ctrl_q = VIRTIO_DEVICE_QUEUE_SETUP(
                    &adapter->u.v.vdev,
                    adapter->num_hw_queues * 2,
                    NULL,
                    NULL,
                    0,
                    adapter->u.v.ctrl_msg,
                    FALSE);
                if (adapter->u.v.ctrl_q == NULL) {
                    PRINTK(("Failed to setup ctrl queu\n"));
                    status = NDIS_ERROR_CODE_OUT_OF_RESOURCES;
                }
            }
        }
    }

    return status;
}
static BOOLEAN
vnif_send_control_msg(PVNIF_ADAPTER adapter,
                      UCHAR cls,
                      UCHAR cmd,
                      PVOID buffer1,
                      ULONG size1,
                      PVOID buffer2,
                      ULONG size2)
{
    virtio_buffer_descriptor_t sg[VNIF_CTRL_SG_ELEMENTS];
    void *p;
    PUCHAR pBase;
    PHYSICAL_ADDRESS phBase;
    ULONG offset = 0;
    UINT sg_cnt = 1;
    UINT len;
    int i;
    BOOLEAN cc = FALSE;

    NdisAcquireSpinLock(&adapter->u.v.ctrl_lock);
    pBase = adapter->u.v.ctrl_buf;
    phBase = adapter->u.v.ctrl_buf_pa;

    if (adapter->u.v.ctrl_buf != NULL
            && (size1 + size2 + 16) <= VNIF_CTRL_BUF_SIZE) {

        ((virtio_net_ctrl_hdr_t *)pBase)->class_of_command = cls;
        ((virtio_net_ctrl_hdr_t *)pBase)->cmd = cmd;
        sg[0].phys_addr = phBase.QuadPart;
        sg[0].len = sizeof(virtio_net_ctrl_hdr_t);
        offset += sg[0].len;
        offset = (offset + 3) & ~3;
        if (size1) {
            NdisMoveMemory(pBase + offset, buffer1, size1);
            sg[sg_cnt].phys_addr = phBase.QuadPart;
            sg[sg_cnt].phys_addr += offset;
            sg[sg_cnt].len = size1;
            offset += size1;
            offset = (offset + 3) & ~3;
            sg_cnt++;
        }
        if (size2) {
            NdisMoveMemory(pBase + offset, buffer2, size2);
            sg[sg_cnt].phys_addr = phBase.QuadPart;
            sg[sg_cnt].phys_addr += offset;
            sg[sg_cnt].len = size2;
            offset += size2;
            offset = (offset + 3) & ~3;
            sg_cnt++;
        }
        sg[sg_cnt].phys_addr = phBase.QuadPart;
        sg[sg_cnt].phys_addr += offset;
        sg[sg_cnt].len = sizeof(virtio_net_ctrl_ack_t);
        *(virtio_net_ctrl_ack_t *)(pBase + offset) = VNIF_NET_ERR;

        if (vring_add_buf(adapter->u.v.ctrl_q, sg, sg_cnt, 1, (void *)1) >= 0) {

            vring_kick(adapter->u.v.ctrl_q);
            p = vring_get_buf(adapter->u.v.ctrl_q, &len);
            for (i = 0; i < 1000 && !p; ++i) {
                UINT interval = 1;
                NdisStallExecution(interval);
                p = vring_get_buf(adapter->u.v.ctrl_q, &len);
            }

            if (!p) {
                PRINTK(("%s - ERROR: get_buf failed (%d)\n", __func__, i));
            } else if (len != sizeof(virtio_net_ctrl_ack_t)) {
                PRINTK(("%s - ERROR: wrong len %d\n", __func__, len));
            }
            else if (*(virtio_net_ctrl_ack_t *)(pBase + offset) != VNIF_NET_OK) {
                PRINTK(("%s - ERROR: error %d returned for class %d\n",
                        __func__, *(virtio_net_ctrl_ack_t *)(pBase + offset),
                        cls));
            } else {
                RPRINTK(DPRTL_ON,
                        ("%s OK(%d, %d.%d, buffers of size %d and %d) \n",
                        __func__, i, cls, cmd, size1, size2));
                cc = TRUE;
            }
        }
        else {
            PRINTK(("%s - ERROR: add_buf failed\n", __func__));
        }
    }
    else {
        PRINTK(("%s (buffer %d, %d) - ERROR: message too LARGE\n",
                __func__, size1, size2));
    }
    NdisReleaseSpinLock(&adapter->u.v.ctrl_lock);
    return cc;
}

static NDIS_STATUS
vnifv_setup_rxtx(PVNIF_ADAPTER adapter)
{
    NDIS_STATUS status;


    status = vnif_setup_rxtx(adapter);

    vnif_init_rcb_pool(adapter);
    vnif_init_tx(adapter);

    return status;
}

NDIS_STATUS
VNIFV_SetupAdapterInterface(PVNIF_ADAPTER adapter)
{
    struct virtqueue *vq;
    NDIS_STATUS status;
    UINT i;
    int err;
    u16 num;

    RPRINTK(DPRTL_ON, ("VNIFSetupAdapterInterface: In\n"));
    status = NDIS_STATUS_SUCCESS;

    if (adapter->lso_data_size > VIRTIO_LSO_MAX_DATA_SIZE)  {
        adapter->lso_data_size = VIRTIO_LSO_MAX_DATA_SIZE;
    }

    vnif_set_guest_features(adapter);

    status = vnif_setup_queues(adapter);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    status = vnifv_setup_rxtx(adapter);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    status = vnifv_msi_config(adapter);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    VNIF_CLEAR_FLAG(adapter, VNF_DISCONNECTED);

    virtio_device_add_status(&adapter->u.v.vdev, VIRTIO_CONFIG_S_DRIVER_OK);

    if (adapter->num_paths > 1) {
        num = (uint16_t)adapter->num_paths;
        vnif_send_control_msg(adapter,
                              VIRTIO_NET_CTRL_MQ,
                              VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET,
                              &num,
                              sizeof(num),
                              NULL,
                              0);
    }

    RPRINTK(DPRTL_INIT,
        ("VNIFSetupAdapterInterface: VNIFIndicateLinkStatus\n"));
    VNIFIndicateLinkStatus(adapter, 1);

    for (i = 0; i < adapter->num_paths; ++i) {
        vring_kick(adapter->path[i].rx);
    }

    RPRINTK(DPRTL_ON, ("VNIFSetupAdapterInterface: out success\n"));

    return status;
}

NDIS_STATUS
VNIFV_QueryHWResources(PVNIF_ADAPTER adapter, PNDIS_RESOURCE_LIST res_list)
{
    PHYSICAL_ADDRESS pa;
    uint8_t pci_config_space[sizeof(PCI_COMMON_CONFIG)];
    PCM_PARTIAL_RESOURCE_DESCRIPTOR rdes;
    PHYSICAL_ADDRESS mem_base;
    void *va;
    NDIS_STATUS status;
    ULONG read_bytes;
    ULONG len;
    uint32_t mmiolen;
    uint32_t i;
    int iBar;
    BOOLEAN port_space;

    RPRINTK(DPRTL_ON, ("==> %s\n", __func__));

    read_bytes = VNIF_GET_BUS_DATA(adapter->AdapterHandle,
                                   PCI_WHICHSPACE_CONFIG,
                                   0,
                                   &pci_config_space,
                                   sizeof(pci_config_space));
    if (read_bytes != sizeof(pci_config_space)) {
        PRINTK(("%s %s: could not read PCI config space\n",
                VNIF_DRIVER_NAME, __func__));
        return STATUS_UNSUCCESSFUL;
    }

    memset(adapter->u.v.vbar, 0, sizeof(adapter->u.v.vbar));

    for (i = 0; i < res_list->Count; i++) {
        rdes = &res_list->PartialDescriptors[i];
        switch (rdes->Type) {
        case CmResourceTypePort:
        case CmResourceTypeMemory:
            port_space = !!(rdes->Flags & CM_RESOURCE_PORT_IO);
            RPRINTK(DPRTL_INIT, ("  i %d: port_space %d\n", i, port_space));

            if (port_space) {
                pa = rdes->u.Port.Start;
                len = rdes->u.Port.Length;

                RPRINTK(DPRTL_ON, ("  NdisMRegisterIoPortRange\n"));
                status = NdisMRegisterIoPortRange(
                    &va,
                    adapter->AdapterHandle,
                    pa.u.LowPart,
                    len);
                RPRINTK(DPRTL_ON, ("  base_addr %x, port_offset %p range %x\n",
                                   pa.u.LowPart,
                                   va,
                                   len));
                if (status != NDIS_STATUS_SUCCESS) {
                    PRINTK(("  NdisMRegisterIoPortRange failed 0x%x\n",
                            status));
                    return status;
                }
            } else {
                pa = rdes->u.Memory.Start;
                len = rdes->u.Memory.Length;
                status = NdisMMapIoSpace(&va,
                                         adapter->AdapterHandle,
                                         pa,
                                         len);
                if (status != NDIS_STATUS_SUCCESS) {
                    PRINTK(("  NdisMMapIoSpace port failed for 0x%llx\n",
                            pa.QuadPart));
                    return status;
                }
            }

            iBar = virtio_get_bar_index((PPCI_COMMON_HEADER)
                                        pci_config_space, pa);
            adapter->u.v.vbar[iBar].pa = pa;
            adapter->u.v.vbar[iBar].va = va;
            adapter->u.v.vbar[iBar].len = len;
            adapter->u.v.vbar[iBar].bPortSpace = port_space;

            RPRINTK(DPRTL_INIT, ("  i %d: port pa %llx va %p len %d iBar %d\n",
                                 i, pa.QuadPart, va, len, iBar));
            break;

        case CmResourceTypeInterrupt:
            adapter->u.v.interrupt_flags = rdes->Flags;
            adapter->u.v.interrupt_level = rdes->u.Interrupt.Level;
            adapter->u.v.interrupt_vector = rdes->u.Interrupt.Vector;
            adapter->u.v.interruopt_affinity = rdes->u.Interrupt.Affinity;
            adapter->b_multi_signaled =
                !!(rdes->Flags & CM_RESOURCE_INTERRUPT_MESSAGE);

            RPRINTK(DPRTL_ON, ("%s: MSI enabled [%d] message signled %d\n",
                    VNIF_DRIVER_NAME, i, adapter->b_multi_signaled));
            RPRINTK(DPRTL_ON, ("  f %x, level %x, vector %x, af %x\n",
                    adapter->u.v.interrupt_flags,
                    adapter->u.v.interrupt_level,
                    adapter->u.v.interrupt_vector,
                    adapter->u.v.interruopt_affinity));
            break;

        default:
            break;
        }
    }

    status = virtio_device_init(&adapter->u.v.vdev,
                                adapter->u.v.vbar,
                                pci_config_space,
                                VNIF_DRIVER_NAME,
                                adapter->b_multi_signaled);

    RPRINTK(DPRTL_ON, ("<== %s: 0x%x\n", __func__, status));
    return status;
}

static int
VNIFSetupPermanentAddress(PVNIF_ADAPTER adapter)
{
    RPRINTK(DPRTL_ON, ("    Try to get MAC\n"));
    VIRTIO_DEVICE_GET_CONFIG(&adapter->u.v.vdev,
        0,
        &adapter->PermanentAddress,
        ETH_LENGTH_OF_ADDRESS);

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

    return NDIS_STATUS_SUCCESS;
}

uint32_t
VNIFV_Quiesce(PVNIF_ADAPTER adapter)
{
    KIRQL old_irql;
    UINT i;
    uint32_t waiting = 0;
    uint32_t wait_count = 0;
    uint32_t resources_outstanding = 0;

    if (adapter->nBusyRecv) {
        PRINTK(("Virtio_net %x: ** quiesce %d receives **\n",
            adapter->CurrentAddress[MAC_LAST_DIGIT],
            adapter->nBusyRecv));
        resources_outstanding = 1;
        waiting = adapter->nBusyRecv;
    }
    if (adapter->nBusySend) {
        PRINTK(("Virtio_net %x: ** quiesce %d sends **\n",
            adapter->CurrentAddress[MAC_LAST_DIGIT],
            adapter->nBusySend));
        resources_outstanding = 1;
        waiting += adapter->nBusySend;
    }

    while (waiting && wait_count <= adapter->resource_timeout) {
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
        vnif_call_txrx_interrupt_dpc(adapter);
        KeLowerIrql(old_irql);

        /* Only need to wory about the receives that are in the process of
         * VNIFReceivePackets and xennet_return_packet.
         */
        waiting = adapter->nBusyRecv;
        waiting += adapter->nBusySend;

        if (!waiting) {
            break;
        }

        wait_count++;
        if (wait_count < adapter->resource_timeout) {
            NdisMSleep(1000000);  /* 1 second */
        }
    }

    if (waiting == 0 && resources_outstanding) {
        PRINTK(("Virtio_net %x: ** resources quiesce **\n",
            adapter->CurrentAddress[MAC_LAST_DIGIT]));
    }

    return waiting;
}

void
VNIFV_CleanupRings(PVNIF_ADAPTER adapter)
{
}

uint32_t
VNIFV_DisconnectBackend(PVNIF_ADAPTER adapter)
{
    return VNIFQuiesce(adapter);
}

void
vnifv_restart_interface(PVNIF_ADAPTER adapter)
{
    RPRINTK(DPRTL_ON, ("vnif_restart_interface: In\n"));
    MPResume(adapter, 0);
    vnif_send_arp(adapter);
    RPRINTK(DPRTL_ON, ("vnif_restart_interface: out\n"));
}

static void
MPResume(PVNIF_ADAPTER adapter, uint32_t suspend_canceled)
{
    UINT i;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    RPRINTK(DPRTL_ON, ("MPResume: %p, %x\n", adapter, suspend_canceled));
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
            PRINTK(("MPResume: starting, nBusySend = %d, nWaitSend = %d\n",
                adapter->nBusySend, adapter->nWaitSend));
#else
            PRINTK(("MPResume: starting, nBusySend = %d\n",
                adapter->nBusySend));
#endif
        }
        if (adapter->nBusySend) {
            vnif_complete_lost_sends(adapter);
        }
        VNIFFreeAdapterInterface(adapter);

        status = VNIFFindAdapter(adapter);
        if (status == STATUS_SUCCESS) {
#if defined NDIS60_MINIPORT
            status = VNIF_SETUP_PATH_INFO_EX(adapter);
#endif
            status = VNIFSetupAdapterInterface(adapter);
            if (status == STATUS_SUCCESS) {
                for (i = 0; i < adapter->num_paths; i++) {
                    vring_enable_interrupt(adapter->path[i].rx);
                    vring_enable_interrupt(adapter->path[i].tx);
                }
                VNIF_CLEAR_FLAG(adapter, VNF_ADAPTER_RESUMING);
                VNIF_SET_FLAG(adapter, VNF_ADAPTER_POLLING);
#if defined NDIS60_MINIPORT
                VNIF_SET_TIMER(adapter->poll_timer, 1);
#endif
            }
        }
        if (status == STATUS_SUCCESS) {
            RPRINTK(DPRTL_INIT, ("NetCfgInstanceId = %ws\n",
                                 adapter->net_cfg_guid));
            vnif_send_arp(adapter);
        } else {
            PRINTK(("MPResume %s: failed resume = 0x%x\n",
                adapter->node_name, status));
        }
    }
    VNIFDumpSettings(adapter);
}

static uint32_t
MPSuspend(PVNIF_ADAPTER adapter, uint32_t reason)
{
    return 0;
}
