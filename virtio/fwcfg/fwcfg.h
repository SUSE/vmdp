/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018-2020 SUSE LLC
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

#ifndef _FWCFG_H
#define _FWCFG_H

#include <ntddk.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <win_stdint.h>
#include <win_mmio_map.h>
#include <win_exalloc.h>
#include <virtio_dbg_print.h>
#include "fwcfg_helper.h"
#include "fwcfg_ver.h"

#define VDEV_DRIVER_NAME "FwCfg"
#define FWCFG_REG_PARAM_DEVICE_KEY_WSTR L"fwcfg\\Parameters\\Device"
#define FWCFG_POOL_TAG (ULONG) 'fcwf'
#define FWCFG_DEVICE_NAME L"\\Device\\fwcfg"
#define FWCFG_DOS_DEVICE_NAME L"\\DosDevices\\Global\\fwcfg"

#define DUMP_TYPE_FULL 1

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
    PVOID ioBase;
    ULONG ioSize;
    PDEVICE_OBJECT Pdo;
    PDEVICE_OBJECT LowerDevice;
    PDMA_ADAPTER dma_adapter_obj;
    PCBUF_DATA common_buf;
    PHYSICAL_ADDRESS common_buf_pa;
    VMCI_DATA vmci_data;
    FWCfgDmaAccess *dma_access;
    LONGLONG dma_access_pa;
    PUCHAR kdbg;
    SYSTEM_POWER_STATE power_state;
    DEVICE_POWER_STATE dpower_state;
    ULONG map_registers;
    uint16_t index;
    BOOLEAN mapped_port;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;


#ifdef DBG
#define fwcfg_complete_request(_r, _i)                                      \
{                                                                           \
    DPRINTK(DPRTL_TRC, ("  %s: Complete request %p\n", __func__, (_r)));    \
    IoCompleteRequest((_r), (_i));                                          \
}
#else
#define fwcfg_complete_request(_r, _i) IoCompleteRequest((_r), (_i))
#endif

/* function device subdispatch routines */
NTSTATUS fwcfg_fdo_power(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS fwcfg_fdo_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#ifdef USES_DDK_BUILD
NTSTATUS
KeInitializeCrashDumpHeader(
    ULONG DumpType,
    ULONG Flags,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BufferNeeded);
#endif

NTSTATUS fwcfg_check_sig(PVOID ioBase);
NTSTATUS fwcfg_check_features(PVOID ioBase, UINT32 features);
NTSTATUS fwcfg_check_dma(PVOID ioBase);
NTSTATUS fwcfg_find_entry(PVOID ioBase, const char *name,
                          PUSHORT index, ULONG size);

NTSTATUS fwcfg_get_kdbg(PFDO_DEVICE_EXTENSION fdx);
NTSTATUS fwcfg_vm_core_info_send(FDO_DEVICE_EXTENSION *fdx);
NTSTATUS fwcfg_evt_device_d0_entry(FDO_DEVICE_EXTENSION *fdx);

#endif
