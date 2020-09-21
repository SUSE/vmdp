/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2020 SUSE LLC
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

#include "pvcrash.h"
#include "pvcrash_power.h"

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH vrng_dispatch_power;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE_PWR, PciDrvDispatchPowerDefault)
#pragma alloc_text(PAGE_PWR, PciDrvDispatchSetPowerState)
#endif

#define PciDrvIoDecrement(fdx)
#define PciDrvIoIncrement(fdx)


NTSTATUS
pvcrash_fdo_power(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    PFDO_DEVICE_EXTENSION fdx;
    NTSTATUS status;

    stack = IoGetCurrentIrpStackLocation(Irp);
    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    RPRINTK(DPRTL_PWR, ("--> %s\n", __func__));
    RPRINTK(DPRTL_PWR, ("  %s %s IRP:0x%p %s %s\n",
                  DbgPowerMinorFunctionString(stack->MinorFunction),
                  stack->Parameters.Power.Type ==
                        SystemPowerState ? "SIRP" : "DIRP",
                  Irp,
                  DbgSystemPowerString(fdx->power_state),
                  DbgDevicePowerString(fdx->dpower_state)));

    PciDrvIoIncrement(fdx);

    if (Deleted == fdx->pnpstate) {
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        pvcrash_complete_request(Irp, IO_NO_INCREMENT);
        PciDrvIoDecrement (fdx);
        return STATUS_NO_SUCH_DEVICE;
    }

    if (NotStarted == fdx->pnpstate) {
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        status = PoCallDriver(fdx->LowerDevice, Irp);
        PciDrvIoDecrement (fdx);
        return status;
    }

    switch (stack->MinorFunction) {
    case IRP_MN_SET_POWER:
        status = PciDrvDispatchSetPowerState(DeviceObject, Irp);
        status = PciDrvDispatchPowerDefault(DeviceObject, Irp);
        break;

    case IRP_MN_QUERY_POWER:
        status = PciDrvDispatchPowerDefault(DeviceObject, Irp);
        break;

    case IRP_MN_WAIT_WAKE:
    case IRP_MN_POWER_SEQUENCE:
    default:
        status = PciDrvDispatchPowerDefault(DeviceObject, Irp);
        PciDrvIoDecrement(fdx);
        break;
    }

    RPRINTK(DPRTL_PWR, ("<-- %s: %x\n", __func__, status));
    return status;
}

static NTSTATUS
PciDrvDispatchPowerDefault(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;

    PAGED_CODE();

    RPRINTK(DPRTL_PWR, ("--> %s\n", __func__));
    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    status = PoCallDriver(fdx->LowerDevice, Irp);
    RPRINTK(DPRTL_PWR, ("<-- %s: status %x\n", __func__, status));

    return status;
}


static NTSTATUS
PciDrvDispatchSetPowerState(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    PFDO_DEVICE_EXTENSION fdx;
    POWER_STATE powerState;
    POWER_STATE_TYPE powerType;

    RPRINTK(DPRTL_PWR, ("--> %s\n", __func__));

    PAGED_CODE();

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    powerType = stack->Parameters.Power.Type;
    powerState = stack->Parameters.Power.State;
    RPRINTK(DPRTL_PWR, ("    powerType %x, powerState %x\n",
                        powerType, powerState));

    if (powerType == SystemPowerState) {
        if (powerState.SystemState >= PowerSystemSleeping3 &&
                fdx->power_state == PowerSystemWorking) {
            /* Hibernating, Suspending, Shutting down. */
            fdx->power_state = powerState.SystemState;
        } else if (powerState.SystemState == PowerSystemWorking &&
                   fdx->power_state != PowerSystemWorking) {
            /* Coming back up from hibernate etc. */
            fdx->power_state = PowerSystemWorking;
        }
    }
    RPRINTK(DPRTL_PWR, ("<-- %s\n", __func__));
    return STATUS_SUCCESS;
}

static PCHAR
DbgPowerMinorFunctionString (__in UCHAR MinorFunction)
{
    switch (MinorFunction) {
    case IRP_MN_SET_POWER:
        return "IRP_MN_SET_POWER";
    case IRP_MN_QUERY_POWER:
        return "IRP_MN_QUERY_POWER";
    case IRP_MN_POWER_SEQUENCE:
        return "IRP_MN_POWER_SEQUENCE";
    case IRP_MN_WAIT_WAKE:
        return "IRP_MN_WAIT_WAKE";
    default:
        return "unknown_power_irp";
    }
}

static PCHAR
DbgSystemPowerString(__in SYSTEM_POWER_STATE Type)
{
    switch (Type) {
    case PowerSystemUnspecified:
        return "PowerSystemUnspecified";
    case PowerSystemWorking:
        return "PowerSystemWorking";
    case PowerSystemSleeping1:
        return "PowerSystemSleeping1";
    case PowerSystemSleeping2:
        return "PowerSystemSleeping2";
    case PowerSystemSleeping3:
        return "PowerSystemSleeping3";
    case PowerSystemHibernate:
        return "PowerSystemHibernate";
    case PowerSystemShutdown:
        return "PowerSystemShutdown";
    case PowerSystemMaximum:
        return "PowerSystemMaximum";
    default:
        return "UnKnown System Power State";
    }
 }

static PCHAR
DbgDevicePowerString(__in DEVICE_POWER_STATE Type)
{
    switch (Type) {
    case PowerDeviceUnspecified:
        return "PowerDeviceUnspecified";
    case PowerDeviceD0:
        return "PowerDeviceD0";
    case PowerDeviceD1:
        return "PowerDeviceD1";
    case PowerDeviceD2:
        return "PowerDeviceD2";
    case PowerDeviceD3:
        return "PowerDeviceD3";
    case PowerDeviceMaximum:
        return "PowerDeviceMaximum";
    default:
        return "UnKnown Device Power State";
    }
}
