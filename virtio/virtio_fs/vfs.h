/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2022 SUSE LLC
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

#ifndef _VFS_H
#define _VFS_H

#include <ntddk.h>
#include <initguid.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <win_stdint.h>
#include <win_mmio_map.h>
#include <virtio_dbg_print.h>
#include <virtio_pci.h>
#include <virtio_pci_wdm.h>
#include <virtio_queue_ops.h>
#include "vfs_ver.h"
#include "shared\virtiofs.h"

#define VDEV_DRIVER_NAME "virtio_fs"
#define VFS_REG_PARAM_DEVICE_KEY_WSTR L"virtio_fs\\Parameters\\Device"
#define VFS_POOL_TAG (ULONG) 'sf_v'
#define VFS_DEVICE_NAME L"\\Device\\virtio_fs"
#define VFS_DOS_DEVICE_NAME L"\\DosDevices\\Global\\virtio_fs_dev"

#define VIRTIO_FS_MAX_INTS 2
#define WDM_DEVICE_MAX_INTS VIRTIO_FS_MAX_INTS

enum {
    VQ_TYPE_HIPRIO = 0,
    VQ_TYPE_REQUEST = 1,
    VQ_TYPE_MAX = 2
};

typedef struct _VIRTIO_FS_CONFIG {
    CHAR tag[MAX_FILE_SYSTEM_NAME];
    uint32_t request_queues;

} virtio_fs_config_t;

typedef struct _VIRTIO_FS_REQUEST {
    SINGLE_LIST_ENTRY list_entry;
    PIRP irp;
    PMDL in_mdl;            /* Device-readable part */
    size_t in_len;
    PMDL out_mdl;           /* Device-writable part */
    size_t out_len;
} virtio_fs_request_t;

typedef struct _virtio_fs_hold_request {
    LIST_ENTRY list_entry;
    PIRP irp;
} virtio_fs_hold_request_t;


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

typedef struct _COMMON_DEVICE_EXTENSION {
    BOOLEAN IsFdo;
    PDEVICE_OBJECT Self;

    PNP_STATE pnpstate;
    DEVICE_POWER_STATE devpower;
    SYSTEM_POWER_STATE syspower;

} COMMON_DEVICE_EXTENSION, *PCOMMON_DEVICE_EXTENSION;

/* FDO device extension as function driver */
typedef struct _FDO_DEVICE_EXTENSION {
    COMMON_DEVICE_EXTENSION;

    uint32_t sig;
    virtio_device_t vdev;
    virtio_bar_t vbar[PCI_TYPE0_ADDRESSES];
    wdm_device_int_info_t int_info[WDM_DEVICE_MAX_INTS];
    virtio_queue_t **vqs;
    SINGLE_LIST_ENTRY request_list;
    LIST_ENTRY hold_list;
    UNICODE_STRING ifname;
    PDEVICE_OBJECT Pdo;
    PDEVICE_OBJECT LowerDevice;
    KDPC int_dpc;
    KSPIN_LOCK *qlock;
    KSPIN_LOCK req_lock;
    SYSTEM_POWER_STATE power_state;
    DEVICE_POWER_STATE dpower_state;
    uint64_t guest_features;
    uint32_t num_queues;
    uint32_t int_cnt;
#ifdef TARGET_OS_GTE_WinLH
    IO_INTERRUPT_MESSAGE_INFO *int_connection_ctx;
#endif
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

extern PKINTERRUPT DriverInterruptObj;

#ifdef DBG
#define vfs_complete_request(_r, _i)                                     \
{                                                                           \
    DPRINTK(DPRTL_TRC, ("  %s: Complete request %p\n", __func__, (_r)));    \
    IoCompleteRequest((_r), (_i));                                          \
}
#else
#define vfs_complete_request(_r, _i) IoCompleteRequest((_r), (_i))
#endif

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH vfs_dispatch_device_control;

/* function device subdispatch routines */
NTSTATUS vfs_fdo_power(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS vfs_fdo_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

void vfs_free_request(virtio_fs_request_t *fs_req);

KDEFERRED_ROUTINE vfs_int_dpc;

NTSTATUS vfs_get_volume_name(IN PFDO_DEVICE_EXTENSION fdx,
                             IN PIRP Request,
                             IN size_t outbuf_len);
NTSTATUS vfs_fuse_request(PFDO_DEVICE_EXTENSION fdx,
                          PIRP Irp,
                          ULONG OutputBufferLength,
                          ULONG InputBufferLength);
#ifdef DBG
void vfs_dump_buf(unsigned char *buf, unsigned int len);
#else
#define vfs_dump_buf(_buf, _len)
#endif

#ifdef USES_DDK_BUILD
#define VFS_MDL_PAGE_PRIORITY NormalPagePriority
#else
#define VFS_MDL_PAGE_PRIORITY (NormalPagePriority  | MdlMappingNoExecute)
#endif

#endif
