/*
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

#include "xenbus.h"
#include "xen_support.h"

KDEFERRED_ROUTINE xenbus_dpc_shutdown;
static NTSTATUS FDO_Power(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
static NTSTATUS PDO_Power(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
static IO_WORKITEM_ROUTINE xenbus_shutdown_worker;
static IO_COMPLETION_ROUTINE xenbus_shutdown_completion;

NTSTATUS
XenbusDispatchPower(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    PCOMMON_DEVICE_EXTENSION pdx;

    RPRINTK(DPRTL_ON, ("XenbusDispatchPower\n"));
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(irpStack->MajorFunction == IRP_MJ_POWER);

    pdx = (PCOMMON_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    if (pdx->pnpstate == Deleted) {
        RPRINTK(DPRTL_ON, ("XenbusDispatchPower: pnpstatus already deleted\n"));
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NO_SUCH_DEVICE;
    }

    if (pdx->IsFdo) {
        return FDO_Power(DeviceObject, Irp);
    } else {
        return PDO_Power(DeviceObject, Irp);
    }
}

static NTSTATUS
xenbus_shutdown_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, void *context)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)context;

    if (fdx == NULL) {
        RPRINTK(DPRTL_ON, ("xenbus_shutdown_completion: in/out fdx == NULL\n"));
        return STATUS_UNSUCCESSFUL;
    }

    RPRINTK(DPRTL_ON,
            ("xenbus_shutdown_completeion: irql = %d, irp %p, fdx->irp %p\n",
             KeGetCurrentIrql(), Irp, fdx->irp));

    IoQueueWorkItem(fdx->item, xenbus_shutdown_worker, DelayedWorkQueue, fdx);

    RPRINTK(DPRTL_ON,
            ("xenbus_shutdown_completeion: STATUS_MORE_PROCESSING_REQUIRED\n"));
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static void
xenbus_shutdown_worker(PDEVICE_OBJECT DeviceObject, void *context)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)context;
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;
    pv_ioctl_t ioctl_data;

    if (fdx == NULL) {
        RPRINTK(DPRTL_ON, ("xenbus_shutdown_worker: in/out: fdx == NULL\n"));
        return;
    }
    RPRINTK(DPRTL_ON,
            ("xenbus_shutdown_worker: in: irql = %d\n", KeGetCurrentIrql()));
    RPRINTK(DPRTL_ON,
            ("xenbus_shutdown_worker: fdx %p, irp %p\n", fdx, fdx->irp));

    for (entry = fdx->ListOfPDOs.Flink;
        entry != &fdx->ListOfPDOs;
        entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if (pdx->Type == vnif && pdx->frontend_dev &&
                pdx->shutdown_try_cnt < delayed_resource_try_cnt) {
            RPRINTK(DPRTL_ON,
                    ("   xenbus_shutdown_worker: shutting down %s\n",
                     pdx->Nodename));
            ioctl_data.cmd = PV_SUSPEND;
            ioctl_data.arg = (uint16_t)SHUTDOWN_poweroff;
            if (pdx->ioctl(pdx->frontend_dev, ioctl_data)) {
                IoCopyCurrentIrpStackLocationToNext(fdx->irp);
                IoSetCompletionRoutine(
                    fdx->irp,
                    xenbus_shutdown_completion,
                    fdx,
                    TRUE,
                    TRUE,
                    TRUE);
                RPRINTK(DPRTL_ON, ("xenbus_shutdown_worker: PoCallDriver\n"));
                PoCallDriver(fdx->LowerDevice, fdx->irp);
                pdx->shutdown_try_cnt++;
                return;
            }
        }
    }

    RPRINTK(DPRTL_ON, ("xenbus_shutdown_worker: IoFreeWorkItem\n"));
    IoFreeWorkItem(fdx->item);

    RPRINTK(DPRTL_ON, ("xenbus_shutdown_worker: PoStartNextPowerIrp\n"));
    PoStartNextPowerIrp(fdx->irp);

    RPRINTK(DPRTL_ON, ("xenbus_shutdown_worker: IoCompleteRequest\n"));
    fdx->irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(fdx->irp, IO_NO_INCREMENT);

    fdx->power_state = PowerActionShutdownOff;
    RPRINTK(DPRTL_ON,
            ("xenbus_shutdown_worker out: pdx %p, irp %p\n", fdx, fdx->irp));
}

static void
xenbus_dpc_shutdown(PKDPC dpc, void *context, void *s1, void *s2)
{
    COMMON_DEVICE_EXTENSION *dev_ext = context;

    if (dev_ext == NULL) {
        PRINTK(("** Powering down for shutdown, NULL.\n"));
        HYPERVISOR_shutdown(SHUTDOWN_poweroff);
    } else if (dev_ext->syspower == PowerActionShutdown) {
        PRINTK(("** Powering down for shutdown.\n"));
        HYPERVISOR_shutdown(SHUTDOWN_poweroff);
    } else if (dev_ext->syspower == PowerActionShutdownReset) {
        PRINTK(("** Powering down for reboot.\n"));
        HYPERVISOR_shutdown(SHUTDOWN_reboot);
    }
}

static NTSTATUS
FDO_Power(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    POWER_STATE powerState;
    POWER_STATE_TYPE powerType;
    POWER_ACTION action;
    PFDO_DEVICE_EXTENSION fdx;
    PIO_STACK_LOCATION stack;
    PLIST_ENTRY entry, listHead;
    pv_ioctl_t ioctl_data;
    uint32_t minor_func;
    xenbus_pv_port_options_t options;
    PPDO_DEVICE_EXTENSION pdx;

    RPRINTK(DPRTL_PWR,
            ("xenbu.sys: FDO_Power, gfdo = %p %p, irql %d, cpu %x\n",
             DeviceObject, gfdo, KeGetCurrentIrql(),
             KeGetCurrentProcessorNumber()));

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    powerType = stack->Parameters.Power.Type;
    powerState = stack->Parameters.Power.State;
    action = stack->Parameters.Power.ShutdownType;
    minor_func = stack->MinorFunction;

    RPRINTK(DPRTL_PWR,
            ("  FDO_Power: MinFunc == %x, t = %x, s = %x, a = %x, fdx s %x\n",
             stack->MinorFunction, powerType, powerState, action,
             fdx->power_state));
    if (minor_func == IRP_MN_QUERY_POWER && powerType == SystemPowerState &&
            powerState.SystemState == PowerSystemSleeping3) {
        if ((pvctrl_flags & XENBUS_PVCTRL_ALLOW_STAND_BY) == 0) {
            PRINTK(("FDO_Power: stand by was requested.\n"));
            PoStartNextPowerIrp(Irp);
            Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            PRINTK(("FDO_Power: returning not suported.\n"));
            return STATUS_NOT_SUPPORTED;
        }
    }
    if (fdx->pnpstate == NotStarted || shared_info_area == NULL) {
        RPRINTK(DPRTL_PWR,
            ("           FDO_Power: notstarted PoStartNextPowerIrp\n"));
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        RPRINTK(DPRTL_PWR,
                ("           FDO_Power: notstarted PoCallDriver\n"));
        status = PoCallDriver(fdx->LowerDevice, Irp);
        RPRINTK(DPRTL_PWR, ("           FDO_Power: notstarted OUT\n"));
        return status;
    }

    /* If powering off, shutdown any remaining NICs. */
    if (minor_func == IRP_MN_SET_POWER &&
            powerState.SystemState == PowerActionShutdownOff &&
            powerType == SystemPowerState) {
        unregister_xenbus_watch(&vbd_watch);
        unregister_xenbus_watch(&vif_watch);
        unregister_xenbus_watch(&vscsi_watch);
        unregister_xenbus_watch(&vusb_watch);
        for (entry = fdx->ListOfPDOs.Flink;
            entry != &fdx->ListOfPDOs;
            entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            RPRINTK(DPRTL_PWR,
                    ("  FDO_Power power off: %s\n", pdx->Nodename));
            if (pdx->Type == vnif && pdx->frontend_dev && pdx->ioctl) {
                RPRINTK(DPRTL_PWR,
                        ("           FDO_Power:shutting down %s: %p, irp %p\n",
                         pdx->Nodename, fdx, Irp));
                pdx->shutdown_try_cnt = 0;
                ioctl_data.cmd = PV_SUSPEND;
                ioctl_data.arg = (uint16_t)SHUTDOWN_poweroff;
                if (pdx->ioctl(pdx->frontend_dev, ioctl_data) &&
                        delayed_resource_try_cnt) {
                    fdx->item = IoAllocateWorkItem(DeviceObject);
                    fdx->irp = Irp;
                    IoMarkIrpPending(Irp);
                    IoQueueWorkItem(
                        fdx->item,
                        xenbus_shutdown_worker,
                        DelayedWorkQueue,
                        fdx);
                    RPRINTK(DPRTL_PWR,
                            ("          FDO_Power: returning PENDING\n"));
                    return STATUS_PENDING;
                }
            }
        }
    }
#if defined TARGET_OS_WinNET
    /* Only Win2k, WinXP and Win2k3 actually hibernate and power off. */
    else if (minor_func == IRP_MN_SET_POWER &&
             powerState.SystemState == PowerSystemHibernate &&
             powerType == SystemPowerState) {
        RPRINTK(DPRTL_PWR,
                ("           FDO_Power: hibernating so unregister\n"));
        unregister_xenbus_watch(&vbd_watch);
        unregister_xenbus_watch(&vif_watch);
        unregister_xenbus_watch(&vscsi_watch);
        unregister_xenbus_watch(&vusb_watch);

        /*
         * Since we are hibernating, we need to give back any ballooned
         * pages to Windows else the hibernate will hang.
         */
        balloon_do_reservation(BALLOON_MAX_RESERVATION);
    } else if (minor_func == IRP_MN_SET_POWER &&
            powerType == SystemPowerState &&
            powerState.SystemState == PowerSystemWorking &&
            fdx->power_state == PowerSystemHibernate) {
        RPRINTK(DPRTL_ON, ("FDO_Power: srt %p, [0] %p, [1] %p, irql %d\n",
                           fdx, fdx->info[0], fdx->info[1],
                           KeGetCurrentIrql()));
        xenbus_prepare_shared_for_init(fdx, SHARED_INFO_NOT_INITIALIZED);
        xenbus_xen_shared_init(fdx->mmio, fdx->mem, fdx->mmiolen,
            fdx->dvector, OP_MODE_NORMAL);
        set_callback_irq(fdx->dvector);
        RPRINTK(DPRTL_ON, ("FDO_Power: end %p, [0] %p, [1] %p\n",
                           fdx, fdx->info[0], fdx->info[1]));
    }
#endif

    RPRINTK(DPRTL_PWR,
            ("           FDO_Power: PoStartNextPowerIrp, loc %x size %x\n",
             Irp->CurrentLocation, Irp->StackCount));
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    RPRINTK(DPRTL_PWR, ("           FDO_Power: PoCallDriver\n"));
    status = PoCallDriver(fdx->LowerDevice, Irp);

    if (minor_func == IRP_MN_SET_POWER) {
        fdx->power_state = powerState.SystemState;
    }

#ifdef DDBG
    RPRINTK(DPRTL_PWR, ("           FDO_Power: dumping debug info.\n"));
    xenbus_debug_dump();
    for (entry = fdx->ListOfPDOs.Flink;
        entry != &fdx->ListOfPDOs;
        entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if (pdx->ioctl && (pdx->Type == vbd || pdx->Type == vscsi) &&
                pdx->controller) {
            ioctl_data.cmd = PV_SUSPEND;
            ioctl_data.arg = (uint16_t)SHUTDOWN_DEBUG_DUMP;
            pdx->ioctl(pdx->controller, ioctl_data);
            break;
        }
    }
#endif

    if (minor_func == IRP_MN_SET_POWER &&
            powerState.SystemState == PowerActionShutdownOff &&
            powerType == SystemPowerState &&
            ((pvctrl_flags & PVCTRL_DISABLE_FORCED_SHUTDOWN) == 0)) {
        if (action == PowerActionShutdown
                || action == PowerActionShutdownOff) {
            PRINTK(("Xenbus: powering off for shutdown - action %x\n", action));
            HYPERVISOR_shutdown(SHUTDOWN_poweroff);
        } else if (action == PowerActionShutdownReset) {
            PRINTK(("Xenbus: powering off for reboot\n"));
            HYPERVISOR_shutdown(SHUTDOWN_reboot);
        }
    }

    RPRINTK(DPRTL_PWR, ("  FDO_Power: OUT %p, state %x %x, status %x\n",
                          fdx, fdx->power_state, fdx->sig, status));
    return status;
}

static NTSTATUS
PDO_Power(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    PPDO_DEVICE_EXTENSION pdx;
    PIO_STACK_LOCATION stack;
    POWER_STATE powerState;
    POWER_STATE_TYPE powerType;
    POWER_ACTION action;
    pv_ioctl_t ioctl_data;
    LARGE_INTEGER shutdown_timeout;

    RPRINTK(DPRTL_PWR, ("xenbu.sys: PDO_Power, gfdo = %p\n", gfdo));
    pdx = (PPDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    powerType = stack->Parameters.Power.Type;
    powerState = stack->Parameters.Power.State;
    action = stack->Parameters.Power.ShutdownType;

    RPRINTK(DPRTL_PWR,
            ("PDO_Power: irql %x, MinorFunction %x, t %x, s %x, a %x, %s\n",
             KeGetCurrentIrql(), stack->MinorFunction, powerType,
             powerState.SystemState, action, pdx->Nodename));

    switch (stack->MinorFunction) {
    case IRP_MN_SET_POWER:
        RPRINTK(DPRTL_PWR, ("    PDO_Power: IRP_MN_SET_POWER\n"));
        switch (powerType) {
        case DevicePowerState:
            RPRINTK(DPRTL_PWR, ("    PDO_Power: DevicePowerState\n"));
            if (powerState.SystemState == PowerActionShutdown &&
                    pdx->Type == vscsi &&
                    pdx->Otherend &&
                    pdx->ioctl) {
                RPRINTK(DPRTL_PWR,
                        ("    PDO_Power:shutting down %s\n", pdx->Nodename));
                if ((pvctrl_flags & XENBUS_PVCTRL_USE_VSCSI_SHUTDOWN_TIMER)) {
                    PRINTK(("%s: Cancel power action timer.\n", __func__));
                    KeCancelTimer(&pdx->shutdown_timer);
                }
                ioctl_data.cmd = PV_SUSPEND;
                ioctl_data.arg = (uint16_t)SHUTDOWN_poweroff;
                pdx->ioctl(pdx->Otherend, ioctl_data);
            }
            PoSetPowerState (DeviceObject, powerType, powerState);
            pdx->devpower = powerState.DeviceState;
            status = STATUS_SUCCESS;
            break;

        case SystemPowerState:
            RPRINTK(DPRTL_PWR, ("    PDO_Power: SystemPowerState\n"));
            pdx->syspower = action;
            status = STATUS_SUCCESS;

            /* Halt the vnifs first. */
            if (powerState.SystemState == PowerActionShutdownOff &&
                    pdx->Type == vnif &&
                    pdx->frontend_dev &&
                    pdx->ioctl) {
                RPRINTK(DPRTL_PWR,
                        ("    PDO_Power: Halting irp %p, %p, %s\n",
                         Irp, pdx->frontend_dev, pdx->Nodename));

                /*
                 * We'll try once from here.  If still outstanding
                 * resources, we will try from FDO_Power.
                 */
                ioctl_data.cmd = PV_SUSPEND;
                ioctl_data.arg = (uint16_t)SHUTDOWN_poweroff;
                pdx->ioctl(pdx->frontend_dev, ioctl_data);
            }
            if (powerState.SystemState == PowerActionShutdownOff &&
                    pdx->Type == vscsi &&
                    pdx->Otherend &&
                    pdx->ioctl &&
                    (pvctrl_flags & XENBUS_PVCTRL_USE_VSCSI_SHUTDOWN_TIMER)) {
                PRINTK(("  %s: preapre for possible shutdown/restart %x\n",
                        __func__, action));
                shutdown_timeout.QuadPart = -100000000; /* 10 sec. */
                KeInitializeDpc(&pdx->shutdown_dpc, xenbus_dpc_shutdown, pdx);
                KeInitializeTimer(&pdx->shutdown_timer);
                KeSetTimer(&pdx->shutdown_timer, shutdown_timeout,
                           &pdx->shutdown_dpc);
            }
            break;

        default:
            RPRINTK(DPRTL_PWR, ("    PDO_Power: power type default\n"));
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        break;

    case IRP_MN_QUERY_POWER:
        RPRINTK(DPRTL_PWR, ("    PDO_Power: IRP_MN_QUERY_POWER\n"));
        status = STATUS_SUCCESS;
        break;

    case IRP_MN_WAIT_WAKE:
        RPRINTK(DPRTL_PWR, ("    PDO_Power: IRP_MN_WAIT_WAKE\n"));
        status = STATUS_NOT_SUPPORTED;
        break;
    case IRP_MN_POWER_SEQUENCE:
        RPRINTK(DPRTL_PWR, ("    PDO_Power: IRP_MN_POWER_SEQUENCE\n"));
        status = STATUS_NOT_SUPPORTED;
        break;
    default:
        RPRINTK(DPRTL_PWR, ("    PDO_Power: default\n"));
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    if (status != STATUS_NOT_SUPPORTED) {
        Irp->IoStatus.Status = status;
    }

    RPRINTK(DPRTL_PWR, ("    PDO_Power: PoStartNextPowerIrp\n"));
    PoStartNextPowerIrp(Irp);
    status = Irp->IoStatus.Status;
    RPRINTK(DPRTL_PWR, ("     PDO_Power: IoCompleteRequest\n"));
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    RPRINTK(DPRTL_PWR, ("PDO_Power: OUT\n"));
    return status;
}
