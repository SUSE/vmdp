/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2013-2021 SUSE LLC
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

ULONG g_running_hypervisor = HYPERVISOR_KVM;

#ifdef DBG
uint32_t dbg_print_mask = DPRTL_ON | DPRTL_INIT | DPRTL_UNEXPD;
#else
uint32_t dbg_print_mask = DPRTL_OFF;
#endif

DRIVER_INITIALIZE DriverEntry;
void (*printk)(char *_fmt, ...);

/* Indirect function pointers from mp_vutils and mp_xutils. */
void (*vnif_notify_always_tx)(PVNIF_ADAPTER adapter, UINT path_id);
void (*vnif_add_tx)(PVNIF_ADAPTER adapter, UINT path_id, TCB *tcb,
                    UINT send_len, UINT pkt_len, uint16_t flags, UINT *prod);
void *(*vnif_get_tx)(PVNIF_ADAPTER adapter, UINT path_id, UINT *cons, UINT prod,
    UINT cnt, UINT *len, UINT *status);
RCB *(*vnif_get_rx)(PVNIF_ADAPTER adapter, UINT path_id,
                    UINT prod, UINT *_cons, INT *len);

/* Indirect function pointers from mp_vinterface and mp_xinterface. */
void (*VNIFFreeAdapterInterface)(PVNIF_ADAPTER adapter);
void (*VNIFCleanupInterface)(PVNIF_ADAPTER adapter, NDIS_STATUS status);
NDIS_STATUS (*VNIFFindAdapter)(PVNIF_ADAPTER adapter);
NDIS_STATUS (*VNIFSetupAdapterInterface)(PVNIF_ADAPTER adapter);
NDIS_STATUS (*VNIFQueryHWResources)(PVNIF_ADAPTER adapter,
    PNDIS_RESOURCE_LIST res_list);
uint32_t (*VNIFQuiesce)(PVNIF_ADAPTER adapter);
void (*VNIFCleanupRings)(PVNIF_ADAPTER adapter);
uint32_t (*VNIFDisconnectBackend)(PVNIF_ADAPTER adapter);
void (*vnif_restart_interface)(PVNIF_ADAPTER adapter);

/* Indirect function pointers from mp_vnif and mp_xnif */
void (*VNIF_FREE_SHARED_MEMORY)(VNIF_ADAPTER *adapter, void *va,
    PHYSICAL_ADDRESS pa, uint32_t len, NDIS_HANDLE _hndl);
void (*VNIF_ADD_RCB_TO_RING)(VNIF_ADAPTER *adapter, RCB *rcb);
ULONG (*VNIF_RX_RING_SIZE)(VNIF_ADAPTER *adapter);
ULONG (*VNIF_TX_RING_SIZE)(VNIF_ADAPTER *adapter);
void (*VNIF_GET_TX_REQ_PROD_PVT)(VNIF_ADAPTER *adapter, UINT path_id, UINT *i);
void (*VNIF_GET_RX_REQ_PROD)(VNIF_ADAPTER *adapter, UINT path_id, UINT *i);

/* Indirect function pointers from mp_nif */
void (*VNIF_SET_TX_REQ_PROD_PVT)(VNIF_ADAPTER *adapter, UINT path_id, UINT i);
void (*VNIF_GET_TX_RSP_PROD)(VNIF_ADAPTER *adapter, UINT path_id, UINT *prod);
void (*VNIF_GET_RX_RSP_PROD)(VNIF_ADAPTER *adapter, UINT path_id, UINT *prod);
void (*VNIF_GET_TX_RSP_CONS)(VNIF_ADAPTER *adapter, UINT path_id, UINT *cons);
void (*VNIF_GET_RX_RSP_CONS)(VNIF_ADAPTER *adapter, UINT path_id, UINT *cons);
void (*VNIF_SET_TX_RSP_CONS)(VNIF_ADAPTER *adapter, UINT path_id, UINT cons);
void (*VNIF_SET_RX_RSP_CONS)(VNIF_ADAPTER *adapter, UINT path_id, UINT cons);
void (*VNIF_SET_TX_EVENT)(VNIF_ADAPTER *adapter, UINT path_id, UINT prod);
void (*VNIF_SET_RX_EVENT)(VNIF_ADAPTER *adapter, UINT path_id, UINT prod);
void (*VNIF_RX_RING_KICK_ALWAYS)(void *vq);
void (*VNIF_RX_NOTIFY)(VNIF_ADAPTER *adapter, UINT path_id,
                       UINT rcb_added_to_ring, UINT old);
UINT (*VRING_CAN_ADD_TX)(VNIF_ADAPTER *adapter, UINT path_id, UINT num);
UINT (*VNIF_RING_FREE_REQUESTS)(VNIF_ADAPTER *adapter, UINT path_id);
UINT (*VNIF_HAS_UNCONSUMED_RESPONSES)(void *vq, UINT cons, UINT prod);
UINT (*VNIF_IS_VALID_RCB)(RCB *rcb);
UINT (*VNIF_DATA_VALID_CHECKSUM_VALID)(RCB *rcb);
UINT (*VNIF_CHECKSUM_SUCCEEDED)(RCB *rcb);
UINT (*VNIF_IS_PACKET_DATA_VALID)(RCB *rcb);
UINT (*VNIF_PACKET_NEEDS_CHECKSUM)(RCB *rcb);
UINT (*MP_RING_FULL)(void *vq);
UINT (*MP_RING_EMPTY)(void *vq);
UINT (*VNIF_RING_HAS_UNCONSUMED_RESPONSES)(void *vq);
void (*VNIF_RING_FINAL_CHECK_FOR_RESPONSES)(void *vq, int *more_to_do);
void (*vnif_ndis_queue_dpc)(VNIF_ADAPTER *adapter,
                            UINT rcv_qidx,
                            UINT max_nbls_to_indicate);

#ifdef NDIS60_MINIPORT
#else
void (*DriverEntryEx)(NDIS_MINIPORT_CHARACTERISTICS *mp_char);
NDIS_STATUS (*VNIFGetHWResources)(struct _VNIF_ADAPTER *adapter);
#endif

NDIS_STATUS (*VNIFRegisterNdisInterrupt)(struct _VNIF_ADAPTER *adapter);
void (*VNIFDeregisterHardwareResources)(struct _VNIF_ADAPTER *adapter);

UINT (*VNIF_GET_NUM_PATHS)(struct _VNIF_ADAPTER *adapter);
NDIS_STATUS (*VNIF_SETUP_PATH_INFO_EX)(struct _VNIF_ADAPTER *adapter);

#ifdef DBG
void (*VNIF_DUMP)(struct _VNIF_ADAPTER *adapter, UINT path_id, PUCHAR str,
                  uint32_t rxtx, uint32_t force);
void (*vnif_rcv_stats_dump)(PVNIF_ADAPTER adapter, UINT path_id);
#endif


NDIS_INTERFACE_TYPE VNIF_INTERFACE_TYPE;
char VNIF_DRIVER_NAME[12];
char VNIF_VENDOR_DESC[4];
ULONG VNIF_VENDOR_ID;

void
vnifv_setup(void)
{
    KeInitializeSpinLock(&virtio_print_lock);
    printk = virtio_dbg_printk;
    vnif_notify_always_tx = vnifv_notify_always_tx;
    vnif_add_tx = vnifv_add_tx;
    vnif_get_tx = vnifv_get_tx;
    vnif_get_rx = vnifv_get_rx;

    VNIFFreeAdapterInterface = VNIFV_FreeAdapterInterface;
    VNIFCleanupInterface = VNIFV_CleanupInterface;
    VNIFFindAdapter = VNIFV_FindAdapter;
    VNIFSetupAdapterInterface = VNIFV_SetupAdapterInterface;
    VNIFQueryHWResources = VNIFV_QueryHWResources;
    VNIFQuiesce = VNIFV_Quiesce;
    VNIFCleanupRings = VNIFV_CleanupRings;
    VNIFDisconnectBackend = VNIFV_DisconnectBackend;
    vnif_restart_interface = vnifv_restart_interface;
    VNIF_INTERFACE_TYPE = NdisInterfacePci;

    VNIF_FREE_SHARED_MEMORY = VNIFV_FREE_SHARED_MEMORY;
    VNIF_ADD_RCB_TO_RING = VNIFV_ADD_RCB_TO_RING;
    VNIF_RX_RING_SIZE = VNIFV_RX_RING_SIZE;
    VNIF_TX_RING_SIZE = VNIFV_TX_RING_SIZE;
    VNIF_GET_TX_REQ_PROD_PVT = VNIFV_GET_TX_REQ_PROD_PVT;
    VNIF_GET_RX_REQ_PROD = VNIFV_GET_RX_REQ_PROD;

    VNIF_SET_TX_REQ_PROD_PVT = VNIFV_SET_TX_REQ_PROD_PVT;
    VNIF_GET_TX_RSP_PROD = VNIFV_GET_TX_RSP_PROD;
    VNIF_GET_RX_RSP_PROD = VNIFV_GET_RX_RSP_PROD;
    VNIF_GET_TX_RSP_CONS = VNIFV_GET_TX_RSP_CONS;
    VNIF_GET_RX_RSP_CONS = VNIFV_GET_RX_RSP_CONS;
    VNIF_SET_TX_RSP_CONS = VNIFV_SET_TX_RSP_CONS;
    VNIF_SET_RX_RSP_CONS = VNIFV_SET_RX_RSP_CONS;
    VNIF_SET_TX_EVENT = VNIFV_SET_TX_EVENT;
    VNIF_SET_RX_EVENT = VNIFV_SET_RX_EVENT;
    VNIF_RX_RING_KICK_ALWAYS = VNIFV_RX_RING_KICK_ALWAYS;
    VNIF_RX_NOTIFY = VNIFV_RX_NOTIFY;
    VRING_CAN_ADD_TX = VRINGV_CAN_ADD_TX;
    VNIF_RING_FREE_REQUESTS = VNIFV_RING_FREE_REQUESTS;
    VNIF_HAS_UNCONSUMED_RESPONSES = VNIFV_HAS_UNCONSUMED_RESPONSES;
    VNIF_IS_VALID_RCB = VNIFV_IS_VALID_RCB;
    VNIF_DATA_VALID_CHECKSUM_VALID = VNIFV_DATA_VALID_CHECKSUM_VALID;
    VNIF_CHECKSUM_SUCCEEDED = VNIFV_CHECKSUM_SUCCEEDED;
    VNIF_IS_PACKET_DATA_VALID = VNIFV_IS_PACKET_DATA_VALID;
    VNIF_PACKET_NEEDS_CHECKSUM = VNIFV_PACKET_NEEDS_CHECKSUM;
    MP_RING_FULL = MPV_RING_FULL;
    MP_RING_EMPTY = MPV_RING_EMPTY;
    VNIF_RING_HAS_UNCONSUMED_RESPONSES = VNIFV_RING_HAS_UNCONSUMED_RESPONSES;
    VNIF_RING_FINAL_CHECK_FOR_RESPONSES = VNIFV_RING_FINAL_CHECK_FOR_RESPONSES;

#ifdef NDIS60_MINIPORT
    vnif_ndis_queue_dpc = vnifv_ndis_queue_dpc;
#else
    DriverEntryEx = MPV_DriverEntryEx;
    VNIFGetHWResources = VNIFV_GetHWResources;
#endif

    VNIFRegisterNdisInterrupt = VNIFV_RegisterNdisInterrupt;
    VNIFDeregisterHardwareResources = VNIFV_DeregisterHardwareResources;
    VNIF_GET_NUM_PATHS = vnifv_get_num_paths;
    VNIF_SETUP_PATH_INFO_EX = vnifv_setup_path_info_ex;
#ifdef DBG
    VNIF_DUMP = VNIFV_DUMP;
    vnif_rcv_stats_dump = vnifv_rcv_stats_dump;
#endif


    RtlStringCbCopyA(VNIF_DRIVER_NAME, sizeof(VNIF_DRIVER_NAME), "Virtio_net");
    RtlStringCbCopyA(VNIF_VENDOR_DESC, sizeof(VNIF_VENDOR_DESC), "KVM");
    VNIF_VENDOR_ID = 0x00525400;
}

NTSTATUS
vnifx_setup(void)
{
    NTSTATUS status;

    status = xenbus_get_apis();
    if (status != STATUS_SUCCESS) {
        return status;
    }
    printk = xenbus_printk;
    vnif_notify_always_tx = vnifx_notify_always_tx;
    vnif_add_tx = vnifx_add_tx;
    vnif_get_tx = vnifx_get_tx;
    vnif_get_rx = vnifx_get_rx;

    VNIFFreeAdapterInterface = VNIFX_FreeAdapterInterface;
    VNIFCleanupInterface = VNIFX_CleanupInterface;
    VNIFFindAdapter = VNIFX_FindAdapter;
    VNIFSetupAdapterInterface = VNIFX_SetupAdapterInterface;
    VNIFQueryHWResources = VNIFX_QueryHWResources;
    VNIFQuiesce = VNIFX_Quiesce;
    VNIFCleanupRings = VNIFX_CleanupRings;
    VNIFDisconnectBackend = VNIFX_DisconnectBackend;
    vnif_restart_interface = vnifx_restart_interface;

    VNIF_FREE_SHARED_MEMORY = VNIFX_FREE_SHARED_MEMORY;
    VNIF_ADD_RCB_TO_RING = VNIFX_ADD_RCB_TO_RING;
    VNIF_RX_RING_SIZE = VNIFX_RX_RING_SIZE;
    VNIF_TX_RING_SIZE = VNIFX_TX_RING_SIZE;
    VNIF_GET_TX_REQ_PROD_PVT = VNIFX_GET_TX_REQ_PROD_PVT;
    VNIF_GET_RX_REQ_PROD = VNIFX_GET_RX_REQ_PROD;

    VNIF_SET_TX_REQ_PROD_PVT = VNIFX_SET_TX_REQ_PROD_PVT;
    VNIF_GET_TX_RSP_PROD = VNIFX_GET_TX_RSP_PROD;
    VNIF_GET_RX_RSP_PROD = VNIFX_GET_RX_RSP_PROD;
    VNIF_GET_TX_RSP_CONS = VNIFX_GET_TX_RSP_CONS;
    VNIF_GET_RX_RSP_CONS = VNIFX_GET_RX_RSP_CONS;
    VNIF_SET_TX_RSP_CONS = VNIFX_SET_TX_RSP_CONS;
    VNIF_SET_RX_RSP_CONS = VNIFX_SET_RX_RSP_CONS;
    VNIF_SET_TX_EVENT = VNIFX_SET_TX_EVENT;
    VNIF_SET_RX_EVENT = VNIFX_SET_RX_EVENT;
    VNIF_RX_RING_KICK_ALWAYS = VNIFX_RX_RING_KICK_ALWAYS;
    VNIF_RX_NOTIFY = VNIFX_RX_NOTIFY;
    VRING_CAN_ADD_TX = VRINGX_CAN_ADD_TX;
    VNIF_RING_FREE_REQUESTS = VNIFX_RING_FREE_REQUESTS;
    VNIF_HAS_UNCONSUMED_RESPONSES = VNIFX_HAS_UNCONSUMED_RESPONSES;
    VNIF_IS_VALID_RCB = VNIFX_IS_VALID_RCB;
    VNIF_DATA_VALID_CHECKSUM_VALID = VNIFX_DATA_VALID_CHECKSUM_VALID;
    VNIF_CHECKSUM_SUCCEEDED = VNIFX_CHECKSUM_SUCCEEDED;
    VNIF_IS_PACKET_DATA_VALID = VNIFX_IS_PACKET_DATA_VALID;
    VNIF_PACKET_NEEDS_CHECKSUM = VNIFX_PACKET_NEEDS_CHECKSUM;
    MP_RING_FULL = MPX_RING_FULL;
    MP_RING_EMPTY = MPX_RING_EMPTY;
    VNIF_RING_HAS_UNCONSUMED_RESPONSES = VNIFX_RING_HAS_UNCONSUMED_RESPONSES;
    VNIF_RING_FINAL_CHECK_FOR_RESPONSES = VNIFX_RING_FINAL_CHECK_FOR_RESPONSES;
    vnif_ndis_queue_dpc = vnifx_ndis_queue_dpc;

#ifdef NDIS60_MINIPORT
#else
    DriverEntryEx = MPX_DriverEntryEx;
    VNIFGetHWResources = VNIFX_GetHWResources;
#endif

    VNIFRegisterNdisInterrupt = VNIFX_RegisterNdisInterrupt;
    VNIFDeregisterHardwareResources = VNIFX_DeregisterHardwareResources;
    VNIF_GET_NUM_PATHS = vnifx_get_num_paths;
    VNIF_SETUP_PATH_INFO_EX = vnifx_setup_path_info_ex;
#ifdef DBG
    VNIF_DUMP = VNIFX_DUMP;
    vnif_rcv_stats_dump = vnifx_rcv_stats_dump;
#endif

    VNIF_INTERFACE_TYPE = NdisInterfaceInternal;
    RtlStringCbCopyA(VNIF_DRIVER_NAME, sizeof(VNIF_DRIVER_NAME), "Xennet");
    RtlStringCbCopyA(VNIF_VENDOR_DESC, sizeof(VNIF_VENDOR_DESC), "Xen");
    VNIF_VENDOR_ID = 0x0000163E;

    if (NET_TX_RING_SIZE !=
            __WIN_RING_SIZE((struct netif_tx_sring *)0, PAGE_SIZE)) {
        PRINTK(("*** %s: NET_TX_RING_SIZE %d != actual ring size %d ***",
            NET_TX_RING_SIZE,
            __WIN_RING_SIZE((struct netif_tx_sring *)0, PAGE_SIZE)));
    }
    if (NET_RX_RING_SIZE !=
            __WIN_RING_SIZE((struct netif_rx_sring *)0, PAGE_SIZE)) {
        PRINTK(("*** %s: NET_RX_RING_SIZE %d != actual ring size %d ***",
            NET_TX_RING_SIZE,
            __WIN_RING_SIZE((struct netif_rx_sring *)0, PAGE_SIZE)));
    }
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    g_running_hypervisor = hypervisor_is();
    switch (g_running_hypervisor) {
    case HYPERVISOR_KVM:
        vnifv_setup();
        PRINTK(("pvvxnet loading for virtio_net.\n"));
        break;
    case HYPERVISOR_XEN:
        status = vnifx_setup();
        if (status != STATUS_SUCCESS) {
            return status;
        }
        PRINTK(("pvvxnet loading for xennet.\n"));
        break;
    default:
        return STATUS_UNSUCCESSFUL;
        break;
    }
    PRINTK(("%s Ndis %d.%d Miniport Driver: Version %s.\n",
        VNIF_DRIVER_NAME, VNIF_NDIS_MAJOR_VERSION,
        VNIF_NDIS_MINOR_VERSION, VER_FILEVERSION_STR));
    return MPDriverEntry(DriverObject, RegistryPath);
}
