/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2020 SUSE LLC
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

#ifndef _VIRTIO_PCI_WDM_H
#define _VIRTIO_PCI_WDM_H

typedef struct _wdm_device_int_info {
    ULONG               message_number;
    ULONG               vector;
    KIRQL               irql;
    KINTERRUPT_MODE     mode;
    KAFFINITY           affinity;
    UCHAR               shared;
    BOOLEAN             message_signaled;
} wdm_device_int_info_t;

void wdm_unmap_io_space(struct _FDO_DEVICE_EXTENSION *fdx);
NTSTATUS wdm_start_device(IN PDEVICE_OBJECT fdo,
                                 IN PCM_PARTIAL_RESOURCE_LIST raw,
                                 IN PCM_PARTIAL_RESOURCE_LIST translated);
NTSTATUS wdm_finish_init(struct _FDO_DEVICE_EXTENSION *fdx);

NTSTATUS wdm_device_virtio_init(struct _FDO_DEVICE_EXTENSION *fdx);
NTSTATUS wdm_device_powerup(struct _FDO_DEVICE_EXTENSION *fdx);
void wdm_device_powerdown(struct _FDO_DEVICE_EXTENSION *fdx);
VOID wdm_fdo_stop_device(IN PDEVICE_OBJECT fdo);
VOID wdm_fdo_remove_device(IN PDEVICE_OBJECT fdo);
NTSTATUS wdm_send_irp_synchronous(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

KSERVICE_ROUTINE wdm_device_isr;
KMESSAGE_SERVICE_ROUTINE wdm_device_interrupt_message_service;

#endif
