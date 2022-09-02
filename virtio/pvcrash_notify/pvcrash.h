/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2022 SUSE LLC
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

#ifndef _PVCRASH_H
#define _PVCRASH_H

#include <ntddk.h>
#include <initguid.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <win_stdint.h>
#include <win_mmio_map.h>
#include <virtio_dbg_print.h>
#include "pvcrash_guid.h"
#include "pvcrash_ver.h"

#define VDEV_DRIVER_NAME "PVCrash"
#define PVCRASH_REG_PARAM_DEVICE_KEY_WSTR L"pvcrash_notify\\Parameters\\Device"
#define PVCRASH_POOL_TAG (ULONG) 'ndcv'
#define PVCRASH_DEVICE_NAME L"\\Device\\pvcrash_notify"
#define PVPANIC_DOS_DEVICE_NAME L"\\DosDevices\\Global\\PVPanicDevice"

#define IOCTL_GET_CRASH_DUMP_HEADER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

/* The bit of supported PV event. */
#define PVPANIC_F_PANICKED      0
#define PVPANIC_F_CRASHLOADED   1

/* The PV event value. */
#define PVPANIC_PANICKED        (1 << PVPANIC_F_PANICKED)
#define PVPANIC_CRASHLOADED     (1 << PVPANIC_F_CRASHLOADED)

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
    PVOID IoBaseAddress;
    ULONG IoRange;
    PDEVICE_OBJECT Pdo;
    PDEVICE_OBJECT LowerDevice;
    UNICODE_STRING ifname;
    SYSTEM_POWER_STATE power_state;
    DEVICE_POWER_STATE dpower_state;
    BOOLEAN mapped_port;
    UCHAR supported_crash_features;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;


#ifdef DBG
#define pvcrash_complete_request(_r, _i)                                     \
{                                                                           \
    DPRINTK(DPRTL_TRC, ("  %s: Complete request %p\n", __func__, (_r)));    \
    IoCompleteRequest((_r), (_i));                                          \
}
#else
#define pvcrash_complete_request(_r, _i) IoCompleteRequest((_r), (_i))
#endif

/* function device subdispatch routines */
NTSTATUS pvcrash_fdo_power(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS pvcrash_fdo_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
VOID pvcrash_notify_bugcheck(IN PVOID buffer, IN ULONG len);
VOID pvcrash_notify_mem_bugcheck(IN PVOID buffer, IN ULONG len);
VOID pvcrash_on_dump_bugCheck(KBUGCHECK_CALLBACK_REASON reason,
                              PKBUGCHECK_REASON_CALLBACK_RECORD record,
                              PVOID data,
                              ULONG length);
VOID pvcrash_on_dump_mem_bugCheck(KBUGCHECK_CALLBACK_REASON reason,
                                  PKBUGCHECK_REASON_CALLBACK_RECORD record,
                                  PVOID data,
                                  ULONG length);

#ifdef USES_DDK_BUILD
#define PVCRASH_MDL_PAGE_PRIORITY NormalPagePriority
NTSTATUS
KeInitializeCrashDumpHeader(
    ULONG DumpType,
    ULONG Flags,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BufferNeeded);
#else
#define PVCRASH_MDL_PAGE_PRIORITY (NormalPagePriority  | MdlMappingNoExecute)
#endif

extern PVOID g_pvcrash_port_addr;
extern PVOID g_pvcrash_mem_addr;
extern BOOLEAN g_emit_crash_loaded_event;
extern BOOLEAN g_emit_crash_mem_loaded_event;

#endif
