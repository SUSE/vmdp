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

#ifndef _VIRTIO_BALLOON_H
#define _VIRTIO_BALLOON_H

#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <win_version.h>
#include <win_stdint.h>
#include <win_mmio_map.h>
#include <virtio_dbg_print.h>
#include <win_mem_barrier.h>
#include <virtio_pci.h>
#include <virtio_pci_wdm.h>
#include <virtio_utils.h>
#include <virtio_config.h>
#include <virtio_blnx.h>
#include <virtio_queue_ops.h>
#include "virtio_balloon_pub.h"

#define VIRTIO_BLN_POOL_TAG         (ULONG) 'nlbV'
#define VIRTIO_BLN_SIG              (ULONG) 'nlbV'
#define VDEV_DRIVER_NAME            "VBLN"

#define SYSTEM_START_OPTIONS_LEN    256
#define NULL_WSTR                   L""
#define SAFE_BOOT_WSTR              L"SAFEBOOT"
#define SYSTEM_START_OPTIONS_WSTR   L"SystemStartOptions"
#define PVCTRL_FLAGS_WSTR           L"pvctrl_flags"
#define VIRTIO_BALLOON_DEVICE_NAME_WSTR L"\\Device\\virtio_balloon"

#define BALLOON_MAX_RESERVATION 0xffffffffffffffff

#define WDM_DEVICE_MAX_INTS 1

#define VIRTIO_QUEUE_BALLOON_INFLATE    0
#define VIRTIO_QUEUE_BALLOON_DEFLATE    1
#define VIRTIO_QUEUE_BALLOON_STAT       2

#define VIRTIO_BALLOON_F_MUST_TELL_HOST 0 /* Tell before reclaiming pages */
#define VIRTIO_BALLOON_F_STATS_VQ       1 /* Memory status virtqueue */

typedef uint32_t virtio_bln_pfn_t;
typedef int32_t virtio_bln_long_t;
typedef uint32_t virtio_bln_ulong_t;

#define MAX_PFN_ENTRIES (PAGE_SIZE / sizeof(virtio_bln_pfn_t))
#define PfnHighMem(_pfn) ((_pfn) > (0xffffffff >> PAGE_SHIFT)) ? 1 : 0

typedef struct virtio_bln_config_s {
    uint32_t num_pages;
    uint32_t actual;
} virtio_bln_config_t;

typedef struct virtio_bln_mdl_list_s {
    PMDL head;
    PMDL tail;
} virtio_bln_mdl_list_t;

typedef enum _PNP_STATE {
    NotStarted = 0,         /* Not started yet */
    Started,                /* Device has received the START_DEVICE IRP */
    StopPending,            /* Device has received the QUERY_STOP IRP */
    Stopped,                /* Device has received the STOP_DEVICE IRP */
    RemovePending,          /* Device has received the QUERY_REMOVE IRP */
    SurpriseRemovePending,  /* Device has received the SURPRISE_REMOVE IRP */
    Deleted,                /* Device has received the REMOVE_DEVICE IRP */
    UnKnown                 /* Unknown state */

} PNP_STATE;

/* FDO device extension as function driver */
typedef struct _FDO_DEVICE_EXTENSION {
    PDEVICE_OBJECT              Self;

    PNP_STATE                   pnpstate;
    DEVICE_POWER_STATE          devpower;
    SYSTEM_POWER_STATE          syspower;

    ULONG                       sig;
    PDEVICE_OBJECT              Pdo;
    PDEVICE_OBJECT              LowerDevice;
    UNICODE_STRING              ifname;
    SYSTEM_POWER_STATE          power_state;

    virtio_device_t             vdev;
    virtio_bar_t                vbar[PCI_TYPE0_ADDRESSES];
    wdm_device_int_info_t       int_info[WDM_DEVICE_MAX_INTS];
    ULONG                       int_cnt;
    virtio_queue_t              *inflate_q;
    virtio_queue_t              *deflate_q;
    virtio_queue_t              *stat_q;
    virtio_bln_stat_t           *stats;
    uint64_t                    guest_features;
    KEVENT                      inflate_event;
    KEVENT                      deflate_event;
    KDPC                        dpc;
    KSPIN_LOCK                  balloon_lock;
    virtio_bln_mdl_list_t       mdl_list;
    virtio_bln_pfn_t            *pfn_list;
    virtio_bln_pfn_t            num_pfns;
    virtio_bln_ulong_t          low_mem_pages;
    virtio_bln_ulong_t          high_mem_pages;
    virtio_bln_ulong_t          num_pages;
    virtio_bln_ulong_t          presuspend_page_cnt;
    BOOLEAN                     IsFdo;
    BOOLEAN                     tell_host_first;
    BOOLEAN                     worker_running;
    BOOLEAN                     backend_wants_mem_stats;
    BOOLEAN                     has_new_mem_stats;
    IRP                         *PendingSIrp;
    DEVICE_POWER_STATE          dpower_state;
#ifdef TARGET_OS_GTE_WinLH
    IO_INTERRUPT_MESSAGE_INFO *int_connection_ctx;
#endif
} vbln_dev_extn_t, FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

typedef struct virtio_bln_work_item_s {
    PIO_WORKITEM                work_item;
    vbln_dev_extn_t             *fdx;
} virtio_bln_work_item_t;

extern PKINTERRUPT DriverInterruptObj;
extern uint32_t use_pv_drivers;
extern uint32_t vbnctrl_flags;

DRIVER_INITIALIZE KvmDriverEntry;
IO_WORKITEM_ROUTINE virtio_bln_worker;
KDEFERRED_ROUTINE virtio_bln_dpc;

virtio_bln_ulong_t virtio_bln_free_pages(vbln_dev_extn_t *fdx,
                                         virtio_bln_ulong_t target);
void virtio_bln_balloon_pages(vbln_dev_extn_t *fdx);
void virtio_bln_update_stats(vbln_dev_extn_t *fdx);
void virtio_bln_suspend(vbln_dev_extn_t *fdx);
void virtio_bln_destroy(vbln_dev_extn_t *fdx);

#endif
