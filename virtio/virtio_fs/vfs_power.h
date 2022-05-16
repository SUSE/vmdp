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

#ifndef _VFS_POWER_H
#define _VFS_POWER_H

#include "vfs.h"

#define MAGIC_NUMBER -1

typedef enum {
    IRP_NEEDS_FORWARDING = 1,
    IRP_ALREADY_FORWARDED

} IRP_DIRECTION;

typedef struct _POWER_COMPLETION_CONTEXT {
    PDEVICE_OBJECT  DeviceObject;
    PIRP            SIrp;
} POWER_COMPLETION_CONTEXT, *PPOWER_COMPLETION_CONTEXT;


static NTSTATUS
PciDrvDispatchPowerDefault(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static NTSTATUS
PciDrvDispatchSetPowerState(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static PCHAR
DbgPowerMinorFunctionString(__in UCHAR MinorFunction);

static PCHAR
DbgSystemPowerString(__in SYSTEM_POWER_STATE Type);

static PCHAR
DbgDevicePowerString(__in DEVICE_POWER_STATE Type);


#endif


