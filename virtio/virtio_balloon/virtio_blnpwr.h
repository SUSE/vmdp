/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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

#ifndef __VIRTIO_BLNPWR_H
#define __VIRTIO_BLNPWR_H

#define MAGIC_NUMBER -1

typedef enum {

    IRP_NEEDS_FORWARDING = 1,
    IRP_ALREADY_FORWARDED

} IRP_DIRECTION;

typedef struct _POWER_COMPLETION_CONTEXT {

    PDEVICE_OBJECT  DeviceObject;
    PIRP            SIrp;
} POWER_COMPLETION_CONTEXT, *PPOWER_COMPLETION_CONTEXT;

typedef struct _WORKER_ITEM_CONTEXT {
    PIO_WORKITEM   WorkItem;
    PVOID          Callback; /* Callback pointer */
    PVOID          Argument1;
    PVOID          Argument2;
} WORKER_ITEM_CONTEXT, *PWORKER_ITEM_CONTEXT;


/* DRIVER_DISPATCH PciDrvDispatchPowerDefault; */
static NTSTATUS
PciDrvDispatchPowerDefault(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* DRIVER_DISPATCH PciDrvDispatchQueryPowerState; */
static NTSTATUS
PciDrvDispatchQueryPowerState(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* DRIVER_DISPATCH PciDrvDispatchSetPowerState; */
static NTSTATUS
PciDrvDispatchSetPowerState(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* DRIVER_DISPATCH PciDrvDispatchSystemPowerIrp; */
static NTSTATUS
PciDrvDispatchSystemPowerIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* DRIVER_DISPATCH PciDrvDispatchDeviceQueryPower; */
static NTSTATUS
PciDrvDispatchDeviceQueryPower(PDEVICE_OBJECT  DeviceObject, PIRP Irp);

/* DRIVER_DISPATCH PciDrvDispatchDeviceSetPower; */
static NTSTATUS
PciDrvDispatchDeviceSetPower(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* IO_COMPLETION_ROUTINE PciDrvCompletionSystemPowerUp; */
static NTSTATUS
PciDrvCompletionSystemPowerUp(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID ctx);

/* IO_COMPLETION_ROUTINE PciDrvCompletionDevicePowerUp; */
static NTSTATUS
PciDrvCompletionDevicePowerUp(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID NotUsed
    );

/* IO_WORKITEM_ROUTINE PciDrvCallbackHandleDeviceQueryPower; */
static VOID
PciDrvCallbackHandleDeviceQueryPower(
    PDEVICE_OBJECT      DeviceObject,
    PVOID Context
    );

/* IO_WORKITEM_ROUTINE PciDrvCallbackHandleDeviceSetPower; */
static VOID
PciDrvCallbackHandleDeviceSetPower(
    PDEVICE_OBJECT      DeviceObject,
    PWORKER_ITEM_CONTEXT Context
    );

static VOID
PciDrvQueueCorrespondingDeviceIrp(
    __in PIRP SIrp,
    __in PDEVICE_OBJECT DeviceObject
    );

/* REQUEST_POWER_COMPLETE PciDrvCompletionOnFinalizedDeviceIrp; */
static VOID
PciDrvCompletionOnFinalizedDeviceIrp(
    PDEVICE_OBJECT              DeviceObject,
    UCHAR                       MinorFunction,
    POWER_STATE                 PowerState,
    PVOID                       PowerContext,
    PIO_STATUS_BLOCK            IoStatus
    );

static NTSTATUS
PciDrvFinalizeDevicePowerIrp(
    __in  PDEVICE_OBJECT      DeviceObject,
    __in  PIRP                Irp,
    __in  IRP_DIRECTION       Direction,
    __in  NTSTATUS            Result
    );

static NTSTATUS
PciDrvGetPowerPoliciesDeviceState(
    __in  PIRP                SIrp,
    __in  PDEVICE_OBJECT      DeviceObject,
    __out PDEVICE_POWER_STATE DevicePowerState
    );

static NTSTATUS
PciDrvCanSuspendDevice(
    __in PDEVICE_OBJECT   DeviceObject
    );

static PCHAR
DbgPowerMinorFunctionString(
    __in UCHAR MinorFunction
    );

static PCHAR
DbgSystemPowerString(
    __in SYSTEM_POWER_STATE Type
    );

static PCHAR
DbgDevicePowerString(
    __in DEVICE_POWER_STATE Type
    );


#endif


