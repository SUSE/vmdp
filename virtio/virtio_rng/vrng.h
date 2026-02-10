/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2026 SUSE LLC
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

#ifndef _VRNG_H
#define _VRNG_H

#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <win_version.h>
#include <win_stdint.h>
#include <win_mmio_map.h>
#include <win_exalloc.h>
#include <virtio_dbg_print.h>
#include <virtio_pci.h>
#include <virtio_pci_wdm.h>
#include <virtio_config.h>
#include <virtio_queue_ops.h>
#include "vrng_guid.h"
#include "vrng_ver.h"

#define VDEV_DRIVER_NAME "Virtio_rng"
#define VRNG_REG_PARAM_DEVICE_KEY_WSTR L"Virtio_Rng\\Parameters\\Device"
#define VRNG_POOL_TAG (ULONG) 'gnrv'
#define VIRTIO_RNG_MAX_INTS      1
#define WDM_DEVICE_MAX_INTS VIRTIO_RNG_MAX_INTS

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

typedef struct _read_buffer_entry_s {
    SINGLE_LIST_ENTRY list_entry;
    PIRP request;
    PVOID buffer;

} read_buffer_entry_t, *pread_buffer_entry_t;

#pragma warning(push)
#pragma warning(disable:4201) // Disable nameless struct/union warning
/* FDO device extension as function driver */
typedef struct _FDO_DEVICE_EXTENSION {
    COMMON_DEVICE_EXTENSION;

    uint32_t sig;
    virtio_device_t vdev;
    virtio_bar_t vbar[PCI_TYPE0_ADDRESSES];
    virtio_queue_t *vq;
    wdm_device_int_info_t int_info[WDM_DEVICE_MAX_INTS];
    ULONG int_cnt;
    SINGLE_LIST_ENTRY   read_buffers_list;
    KSPIN_LOCK vq_lock;
    UNICODE_STRING ifname;
    PDEVICE_OBJECT Pdo;
    PDEVICE_OBJECT LowerDevice;
    KDPC int_dpc;
    SYSTEM_POWER_STATE power_state;
    DEVICE_POWER_STATE dpower_state;
    uint64_t host_features;
    uint64_t guest_features;
    BOOLEAN in_dpc;
#ifdef TARGET_OS_GTE_WinLH
    IO_INTERRUPT_MESSAGE_INFO *int_connection_ctx;
#endif
    BOOLEAN mapped_port;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;
#pragma warning(pop)


#ifdef DBG
#define vrng_complete_request(_r, _i)                                       \
{                                                                           \
    DPRINTK(DPRTL_TRC, ("  %s: Complete request %p\n", __func__, (_r)));    \
    IoCompleteRequest((_r), (_i));                                          \
}
#else
#define vrng_complete_request(_r, _i) IoCompleteRequest((_r), (_i))
#endif

extern PKINTERRUPT DriverInterruptObj;

/* function device subdispatch routines */
NTSTATUS vrng_read(PFDO_DEVICE_EXTENSION fdx, PIRP request);
NTSTATUS vrng_fdo_power(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS vrng_fdo_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

/******************** vsint.c ****************/
KSERVICE_ROUTINE vrng_isr;
KMESSAGE_SERVICE_ROUTINE vrng_interrupt_message_service;
KDEFERRED_ROUTINE vrng_int_dpc;

#endif
