/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2008-2012 Novell, Inc.
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

#ifdef XENBUS_HAS_IOCTLS

#include "xenbus.h"

VOID
xenbus_cancel_ioctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFDO_DEVICE_EXTENSION fdx;
    XEN_LOCK_HANDLE lh;
    xenbus_register_shutdown_event_t *ioctl;

    RPRINTK(DPRTL_ON, ("==>xenbus_cancel_ioctl %p\n", Irp));
    fdx = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    IoReleaseCancelSpinLock(Irp->CancelIrql);
    ioctl = Irp->Tail.Overlay.DriverContext[3];
    if (ioctl) {
        XenAcquireSpinLock(&fdx->qlock, &lh);
        RemoveEntryList(&ioctl->list);
        XenReleaseSpinLock(&fdx->qlock, lh);

        Irp->Tail.Overlay.DriverContext[3] = NULL;
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else {
        RPRINTK(DPRTL_ON, ("xenbus_cancel_ioctl had no context\n", Irp));
    }

    RPRINTK(DPRTL_ON, ("<==xenbus_cancel_ioctl %p\n", Irp));
    return;
}

NTSTATUS
xenbus_ioctl(PFDO_DEVICE_EXTENSION fdx, PIRP Irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack;
    XEN_LOCK_HANDLE lh;

    RPRINTK(DPRTL_ON, ("==> xenbus_ioctl\n"));

    stack = IoGetCurrentIrpStackLocation(Irp);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_XENBUS_REGISTER_SHUTDOWN_EVENT: {
        xenbus_register_shutdown_event_t *ioctl;

        if (stack->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(xenbus_register_shutdown_event_t)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ioctl = (xenbus_register_shutdown_event_t *)
            Irp->AssociatedIrp.SystemBuffer;
        ioctl->irp = Irp;
        XenAcquireSpinLock(&fdx->qlock, &lh);
        IoSetCancelRoutine (Irp, xenbus_cancel_ioctl);
        if (Irp->Cancel) {
            if (IoSetCancelRoutine (Irp, NULL) != NULL) {
                /* Since we were able to clear the cancel routine, then
                 * we can return canceled.  Otherwise the cancel routine
                 * will take care of it.
                 */
                XenReleaseSpinLock(&fdx->qlock, lh);
                return STATUS_CANCELLED;
            }
        }
        RPRINTK(DPRTL_ON, ("    marking irp pending: shutdown = %x\n",
                           ioctl->shutdown_type));
        IoMarkIrpPending(Irp);
        InsertTailList(&fdx->shutdown_requests, &ioctl->list);
        Irp->Tail.Overlay.DriverContext[3] = ioctl;
        XenReleaseSpinLock(&fdx->qlock, lh);
        status = STATUS_PENDING;;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    RPRINTK(DPRTL_ON, ("<== xenbus_ioctl\n"));
    return status;
}

#endif
