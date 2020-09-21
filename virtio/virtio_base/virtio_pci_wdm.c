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

#if defined VIRTIO_DEVICE_BALLOON
#include "virtio_balloon.h"
#elif defined VIRTIO_DEVICE_SERIAL
#include "vserial.h"
#elif defined VIRTIO_DEVICE_RNG
#include "vrng.h"
#else
#endif

void
wdm_unmap_io_space(FDO_DEVICE_EXTENSION *fdx)
{
    ULONG i;

    for (i = 0; i < PCI_TYPE0_ADDRESSES; i++) {
        if (fdx->vbar[i].bPortSpace == FALSE && fdx->vbar[i].va != NULL) {
            MmUnmapIoSpace(fdx->vbar[i].va, fdx->vbar[i].len);
            fdx->vbar[i].va = NULL;
            fdx->vbar[i].len = 0;
        }
    }
}

static NTSTATUS
wdm_prepare_hardware(
   IN FDO_DEVICE_EXTENSION *fdx,
   IN PCM_PARTIAL_RESOURCE_LIST raw,
   IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    PHYSICAL_ADDRESS pa;
    uint8_t pci_config_space[sizeof(PCI_COMMON_CONFIG)];
    PCM_PARTIAL_RESOURCE_DESCRIPTOR resource;
    void *va;
    ULONG nres, i;
    ULONG len;
    NTSTATUS status;
    uint32_t int_cnt;
    int iBar;
    BOOLEAN port_space;

    status = STATUS_SUCCESS;
    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    memset(fdx->vbar, 0, sizeof(fdx->vbar));

    resource = translated->PartialDescriptors;
    nres = translated->Count;
    status = virtio_get_pci_config_space(fdx->Self,
                                         pci_config_space,
                                         sizeof(PCI_COMMON_CONFIG));
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s %s: Failed to get pci config space 0x%x\n",
                VDEV_DRIVER_NAME, __func__, status));
        return status;
    }

    int_cnt = 0;

    RPRINTK(DPRTL_INIT, ("%s %s: number of resources %d\n",
                         VDEV_DRIVER_NAME, __func__, nres));

    for (i = 0, status = STATUS_SUCCESS;
            i < nres && status == STATUS_SUCCESS;
            i++, resource++) {
        switch (resource->Type) {
        case CmResourceTypePort:
        case CmResourceTypeMemory:
            port_space = !!(resource->Flags & CM_RESOURCE_PORT_IO);
            RPRINTK(DPRTL_INIT, ("  i %d: port_space %d\n", i, port_space));

            if (port_space) {
                pa = resource->u.Port.Start;
                len = resource->u.Port.Length;
                va = (void *)pa.u.LowPart;
            } else {
                pa = resource->u.Memory.Start;
                len = resource->u.Memory.Length;
                va = mm_map_io_space(pa, len, MmNonCached);
                if (va == NULL) {
                    PRINTK(("  MmMpapIoSpace port failed for 0xllx\n",
                            pa.QuadPart));
                    status = STATUS_NO_MEMORY;
                    break;
                }
            }

            iBar = virtio_get_bar_index((PPCI_COMMON_HEADER)
                                        pci_config_space, pa);
            fdx->vbar[iBar].pa = pa;
            fdx->vbar[iBar].va = va;
            fdx->vbar[iBar].len = len;
            fdx->vbar[iBar].bPortSpace = port_space;

            RPRINTK(DPRTL_INIT, ("  i %d: port pa %llx va %p len %d iBar %d\n",
                    i, pa.QuadPart, va, len, iBar));
            break;

        case CmResourceTypeInterrupt:
            if (int_cnt < WDM_DEVICE_MAX_INTS) {
                fdx->int_info[int_cnt].message_number = int_cnt;
                fdx->int_info[int_cnt].vector = resource->u.Interrupt.Vector;
                fdx->int_info[int_cnt].irql =
                    (KIRQL)resource->u.Interrupt.Level;
                fdx->int_info[int_cnt].mode = resource->Flags;
                fdx->int_info[int_cnt].affinity =
                    resource->u.Interrupt.Affinity;
                fdx->int_info[int_cnt].message_signaled =
                    !!(resource->Flags & CM_RESOURCE_INTERRUPT_MESSAGE);
                fdx->int_info[int_cnt].shared = resource->ShareDisposition;

                PRINTK(("%s: MSI enabled [%d] %d\n", VDEV_DRIVER_NAME,
                        int_cnt, fdx->int_info[int_cnt].message_signaled));

                RPRINTK(DPRTL_INIT, ("  i %d: irql %x v %x flg %x s %x\n",
                        i, fdx->int_info[int_cnt].irql,
                        fdx->int_info[int_cnt].vector,
                        resource->Flags, resource->ShareDisposition));
            }
            int_cnt++;
            break;
        default:
            RPRINTK(DPRTL_INIT, ("  resource type default: %x, i %d\n",
                resource->Type, i));
            break;
        }
    }
    fdx->int_cnt = int_cnt;

    RPRINTK(DPRTL_INIT, ("  int count: %d, i %d\n", fdx->int_cnt, i));

    if (status == STATUS_SUCCESS) {
        status = virtio_device_init(&fdx->vdev,
                                    fdx->vbar,
                                    pci_config_space,
                                    VDEV_DRIVER_NAME,
                                    fdx->int_info[0].message_signaled);
    } else {
        wdm_unmap_io_space(fdx);
    }

    RPRINTK(DPRTL_INIT, ("<-- %s %s: status %x\n",
                         VDEV_DRIVER_NAME, __func__, status));
    return status;
}

static NTSTATUS
wdm_connect_int(IN FDO_DEVICE_EXTENSION *fdx)
{
#ifdef TARGET_OS_GTE_WinLH
    IO_CONNECT_INTERRUPT_PARAMETERS int_params;
#endif
    NTSTATUS status;
    ULONG j;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    if (fdx->int_info[0].message_signaled) {
#ifdef TARGET_OS_GTE_WinLH
        fdx->int_connection_ctx = NULL;
        int_params.Version = CONNECT_MESSAGE_BASED;
        int_params.MessageBased.PhysicalDeviceObject = fdx->Pdo;
        int_params.MessageBased.ConnectionContext.InterruptMessageTable =
            &fdx->int_connection_ctx;
        int_params.MessageBased.MessageServiceRoutine =
            wdm_device_interrupt_message_service;
        int_params.MessageBased.ServiceContext = fdx;
        int_params.MessageBased.SpinLock = NULL;
        int_params.MessageBased.SynchronizeIrql = PASSIVE_LEVEL;
        int_params.MessageBased.FloatingSave = FALSE;
        int_params.MessageBased.FallBackServiceRoutine =
            wdm_device_isr;
        status = IoConnectInterruptEx(&int_params);
        RPRINTK(DPRTL_ON, ("  IoConnectInterruptEx: 0x%x\n", status));
        if (NT_SUCCESS(status)) {
            if (fdx->int_connection_ctx != NULL) {
                RPRINTK(DPRTL_ON, ("  msg count %d\n",
                    fdx->int_connection_ctx->MessageCount));
                for (j = 0; j < fdx->int_connection_ctx->MessageCount; j++) {
                    RPRINTK(DPRTL_ON, ("    vector[%d] %x\n", j,
                        fdx->int_connection_ctx->MessageInfo[j].Vector));
                }
            }
        }
#endif
    } else {
        /* interrupt initialization */
        status = IoConnectInterrupt(
            &DriverInterruptObj,
            (PKSERVICE_ROUTINE)wdm_device_isr,
            (PVOID) fdx,
            NULL,
            fdx->int_info[0].vector,
            (KIRQL)fdx->int_info[0].irql,
            (KIRQL)fdx->int_info[0].irql,
            LevelSensitive,
            fdx->int_info[0].shared,
            fdx->int_info[0].affinity,
            FALSE);
        RPRINTK(DPRTL_ON, ("  IoConnectInterrupt: 0x%x\n", status));
    }

    if (!NT_SUCCESS(status)) {
        PRINTK(("%s %s: IoConnectInterrupt fail.\n",
                VDEV_DRIVER_NAME, __func__));
        wdm_unmap_io_space(fdx);
    }
    RPRINTK(DPRTL_ON, ("<-- %s %s: status 0x%x\n",
                       VDEV_DRIVER_NAME, __func__, status));
    return status;
}

NTSTATUS
wdm_start_device(
  IN PDEVICE_OBJECT fdo,
  IN PCM_PARTIAL_RESOURCE_LIST raw,
  IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;
    POWER_STATE powerState;

    fdx = (PFDO_DEVICE_EXTENSION)fdo->DeviceExtension;
    RPRINTK(DPRTL_ON, ("--> %s %s: (irql %d) fdo = %p\n",
                       VDEV_DRIVER_NAME, __func__, KeGetCurrentIrql(), fdo));

    do {
        status = IoSetDeviceInterfaceState(&fdx->ifname, TRUE);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: IosetDeviceInterfaceState failed: %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        status = wdm_prepare_hardware(fdx, raw, translated);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: wdm_prepare_haredware failed: %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        status = wdm_device_virtio_init(fdx);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: wdm_device_virtio_init failed: %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        status = wdm_connect_int(fdx);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: wdm_connect_int failed: %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        status = wdm_device_powerup(fdx);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: wdm_device_powerup failed: %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        powerState.DeviceState = PowerDeviceD0;
        PoSetPowerState (fdo, DevicePowerState, powerState);
        fdx->power_state = PowerSystemWorking;
        fdx->dpower_state = PowerDeviceD0;
        fdx->pnpstate = Started;

    } while (0);

    RPRINTK(DPRTL_ON, ("<-- %s %s: status 0x%x\n",
                       VDEV_DRIVER_NAME, __func__, status));

    return status;
}

NTSTATUS
wdm_finish_init(PFDO_DEVICE_EXTENSION fdx)
{
    NTSTATUS status = STATUS_SUCCESS;
    uint8_t dev_status;

    dev_status = VIRTIO_DEVICE_GET_STATUS(&fdx->vdev);
    if (!(dev_status & VIRTIO_CONFIG_S_ACKNOWLEDGE)) {
        RPRINTK(DPRTL_ON, ("%s: add VIRTIO_CONFIG_S_ACKNOWLEDGE\n",
                           VDEV_DRIVER_NAME));
        virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_ACKNOWLEDGE);
    }
    if (!(dev_status & VIRTIO_CONFIG_S_DRIVER)) {
        RPRINTK(DPRTL_ON, ("%s: add VIRTIO_CONFIG_S_DRIVER\n",
                           VDEV_DRIVER_NAME));
        virtio_device_add_status(&fdx->vdev, VIRTIO_CONFIG_S_DRIVER);
    }
    if (!(dev_status & VIRTIO_CONFIG_S_FEATURES_OK)) {
        RPRINTK(DPRTL_ON, ("%s: set guest features\n",
                           VDEV_DRIVER_NAME));
        status = virtio_device_set_guest_feature_list(&fdx->vdev,
                                                      fdx->guest_features);
    }

    return status;
}


VOID
wdm_fdo_stop_device(IN PDEVICE_OBJECT fdo)
{
    PFDO_DEVICE_EXTENSION fdx;
    NTSTATUS status;

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    if (fdx->ifname.Buffer != NULL) {
        status = IoSetDeviceInterfaceState(&fdx->ifname, FALSE);
        if (status != STATUS_SUCCESS) {
            PRINTK(("%s: IoSetDeviceInterfaceState failed: %x\n",
                    VDEV_DRIVER_NAME, status));
        }
    }

    wdm_device_powerdown(fdx);

    if (fdx->int_info[0].message_signaled) {
#ifdef TARGET_OS_GTE_WinLH
        IO_DISCONNECT_INTERRUPT_PARAMETERS discon;

        discon.Version = CONNECT_MESSAGE_BASED;
        discon.ConnectionContext.InterruptMessageTable =
            fdx->int_connection_ctx;
        RPRINTK(DPRTL_ON, ("  IoDisconnectInterruptEx\n"));
        IoDisconnectInterruptEx(&discon);
#endif
    } else {
        if (DriverInterruptObj) {
            RPRINTK(DPRTL_ON, ("  IoDisconnectInterrupt\n"));
            IoDisconnectInterrupt(DriverInterruptObj);
            DriverInterruptObj = NULL;
        }
    }

    fdx->pnpstate = Stopped;
    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
}

VOID
wdm_fdo_remove_device(IN PDEVICE_OBJECT fdo)
{
    PFDO_DEVICE_EXTENSION fdx;

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    if (fdx->ifname.Buffer != NULL) {
        ExFreePool(fdx->ifname.Buffer);
        RtlZeroMemory(&fdx->ifname, sizeof(UNICODE_STRING));
    }

    RPRINTK(DPRTL_ON, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
}

static NTSTATUS
wdm_io_completion(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp,
  IN PVOID Context)
{
    if (Irp->PendingReturned == TRUE && Context != NULL) {
        KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
wdm_send_irp_synchronous(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp)
{
    NTSTATUS status;
    KEVENT event;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(
      Irp,
      wdm_io_completion,
      &event,
      TRUE,
      TRUE,
      TRUE);
    status = IoCallDriver(DeviceObject, Irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(
          &event,
          Executive,
          KernelMode,
          FALSE,
          NULL);
        status = Irp->IoStatus.Status;
    }

    return status;
}
