/*-
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

#include "fwcfg.h"

static NTSTATUS
fwcfg_init_dma(IN FDO_DEVICE_EXTENSION *fdx)
{
    DEVICE_DESCRIPTION device_desc;

    RtlZeroMemory(&device_desc, sizeof(DEVICE_DESCRIPTION));
    device_desc.Version = DEVICE_DESCRIPTION_VERSION2;
    device_desc.Master = TRUE;
    device_desc.ScatterGather = TRUE;
    device_desc.Dma32BitAddresses = TRUE;
    device_desc.Dma64BitAddresses = TRUE;
    device_desc.InterfaceType = PCIBus;
    device_desc.MaximumLength = sizeof(CBUF_DATA);
    fdx->dma_adapter_obj = IoGetDmaAdapter(fdx->Pdo,
                                        &device_desc,
                                        &fdx->map_registers);
    if (fdx->dma_adapter_obj == NULL) {
        PRINTK(("%s: failed IoGetDmaAdapter\n", __func__));
        return STATUS_UNSUCCESSFUL;
    }

    fdx->common_buf = fdx->dma_adapter_obj->DmaOperations->AllocateCommonBuffer(
        fdx->dma_adapter_obj,
        sizeof(CBUF_DATA),
        &fdx->common_buf_pa,
        FALSE);
    if (fdx->common_buf == NULL) {
        PRINTK(("%s: failed AllocateCommonBuffer\n", __func__));
        return STATUS_UNSUCCESSFUL;
    }

    fdx->vmci_data.pNote = &fdx->common_buf->note;
    fdx->vmci_data.note_pa = fdx->common_buf_pa.QuadPart
        + FIELD_OFFSET(CBUF_DATA, note);

    fdx->vmci_data.pVmci = &fdx->common_buf->vmci;
    fdx->vmci_data.vmci_pa = fdx->common_buf_pa.QuadPart
        + FIELD_OFFSET(CBUF_DATA, vmci);

    fdx->dma_access = &fdx->common_buf->fwcfg_da;
    fdx->dma_access_pa = fdx->common_buf_pa.QuadPart
        + FIELD_OFFSET(CBUF_DATA, fwcfg_da);

    return STATUS_SUCCESS;
}

static NTSTATUS
fwcfg_prepare_hardware(
   IN FDO_DEVICE_EXTENSION *fdx,
   IN PCM_PARTIAL_RESOURCE_LIST raw,
   IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    PHYSICAL_ADDRESS pa;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR resource;
    void *va;
    ULONG nres, i;
    ULONG len;
    NTSTATUS status;
    BOOLEAN port_space;

    status = STATUS_SUCCESS;
    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    resource = translated->PartialDescriptors;
    nres = translated->Count;
    RPRINTK(DPRTL_INIT, ("    Number of resources %d\n", nres));

    for (i = 0, status = STATUS_SUCCESS;
            i < nres && status == STATUS_SUCCESS;
            i++, resource++) {
        switch (resource->Type) {
        case CmResourceTypePort:
        case CmResourceTypeMemory:
            port_space = !!(resource->Flags & CM_RESOURCE_PORT_IO);
            RPRINTK(DPRTL_INIT, ("    i %d: port space %d\n", i, port_space));

            if (port_space) {
                pa = resource->u.Port.Start;
                len = resource->u.Port.Length;
                va = (void *)pa.u.LowPart;
            } else {
                pa = resource->u.Memory.Start;
                len = resource->u.Memory.Length;
                va = mm_map_io_space(pa, len, MmNonCached);
                if (va == NULL) {
                    PRINTK(("    MmMpapIoSpace port failed for 0xllx\n",
                            pa.QuadPart));
                    status = STATUS_NO_MEMORY;
                    break;
                }
            }

            fdx->ioBase = va;
            fdx->ioSize = len;
            fdx->mapped_port = !port_space;

            RPRINTK(DPRTL_INIT, ("    i %d: port pa %llx va %p len %d\n",
                    i, pa.QuadPart, va, len));
            break;

        default:
            RPRINTK(DPRTL_INIT, ("    resource type default: %x, i %d\n",
                resource->Type, i));
            break;
        }
    }
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s %s: failed to find ports\n",
                VDEV_DRIVER_NAME, __func__));
        return status;
    }

    if ((status = fwcfg_check_sig(fdx->ioBase))
            != STATUS_SUCCESS ||
        (status = fwcfg_check_features(fdx->ioBase, FW_CFG_VERSION_DMA))
            != STATUS_SUCCESS ||
        (status = fwcfg_check_dma(fdx->ioBase))
            != STATUS_SUCCESS) {
        PRINTK(("%s %s: failed checks 0x%x\n",
                VDEV_DRIVER_NAME, __func__, status));
        return status;
    }

    fdx->index = 0;
    status = fwcfg_find_entry(fdx->ioBase,
                              ENTRY_NAME,
                              &fdx->index,
                              sizeof(VMCOREINFO));
    if (!fdx->index) {
        PRINTK(("<-- %s %s: no index 0x%x\n",
                VDEV_DRIVER_NAME, __func__, status));
        return status;
    }

    RPRINTK(DPRTL_INIT, ("<-- %s %s: ioBase %x ioSize %x index %d\n",
        VDEV_DRIVER_NAME, __func__, fdx->ioBase, fdx->ioSize, fdx->index));
    return status;
}

static NTSTATUS
fwcfg_start_device(
  IN PDEVICE_OBJECT fdo,
  IN PCM_PARTIAL_RESOURCE_LIST raw,
  IN PCM_PARTIAL_RESOURCE_LIST translated)
{
    NTSTATUS status;
    PFDO_DEVICE_EXTENSION fdx;
    POWER_STATE powerState;
    DECLARE_UNICODE_STRING_SIZE(symbolic_link_name, 128);
    DECLARE_UNICODE_STRING_SIZE(device_name, 128);
    BOOLEAN res;

    fdx = (PFDO_DEVICE_EXTENSION)fdo->DeviceExtension;
    RPRINTK(DPRTL_ON, ("--> %s %s: (irql %d) fdo = %p\n",
                       VDEV_DRIVER_NAME, __func__, KeGetCurrentIrql(), fdo));

    do {
        status = fwcfg_prepare_hardware(fdx, raw, translated);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: fwcfg_prepare_haredware failed %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        status = fwcfg_init_dma(fdx);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: fwcfg_init_dma failed %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        status = fwcfg_get_kdbg(fdx);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: fwcfg_get_kdbg failed %x\n",
                    VDEV_DRIVER_NAME, status));
            break;
        }

        status = fwcfg_evt_device_d0_entry(fdx);
        if (!NT_SUCCESS(status)) {
            PRINTK(("%s: fwcfg_evt_device_d0_entry failed %x\n",
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

static void
fwcfg_stop_device(FDO_DEVICE_EXTENSION *fdx)
{

    if (fdx->mapped_port && fdx->ioBase != NULL) {
        RPRINTK(DPRTL_ON, ("    MmUnmapIoSpace %p\n", fdx->ioBase));
        MmUnmapIoSpace(fdx->ioBase, fdx->ioSize);
    }

    if (fdx->kdbg) {
        ExFreePool(fdx->kdbg);
        fdx->kdbg = NULL;
        fwcfg_vm_core_info_send(fdx);
    }

    if (fdx->dma_adapter_obj) {
        if (fdx->common_buf) {
            fdx->dma_adapter_obj->DmaOperations->FreeCommonBuffer(
                fdx->dma_adapter_obj,
                sizeof(CBUF_DATA),
                fdx->common_buf_pa,
                fdx->common_buf,
                FALSE);
            fdx->common_buf = NULL;
        }
        fdx->dma_adapter_obj->DmaOperations->PutDmaAdapter(fdx->dma_adapter_obj);
        fdx->dma_adapter_obj = NULL;
    }
}

static NTSTATUS
fwcfg_io_completion(IN PDEVICE_OBJECT DeviceObject,
                    IN PIRP Irp,
                    IN PVOID Context)
{
    if (Irp->PendingReturned == TRUE && Context != NULL) {
        KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
fwcfg_send_irp_synchronous(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    KEVENT event;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           fwcfg_io_completion,
                           &event,
                           TRUE,
                           TRUE,
                           TRUE);
    status = IoCallDriver(DeviceObject, Irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        status = Irp->IoStatus.Status;
    }

    return status;
}


NTSTATUS
fwcfg_fdo_pnp( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status;
    ULONG length, prevcount, numNew, i;
    PFDO_DEVICE_EXTENSION fdx;
    PIO_STACK_LOCATION stack;
    PCM_PARTIAL_RESOURCE_LIST raw, translated;
    PLIST_ENTRY entry, listHead, nextEntry;
    PDEVICE_RELATIONS relations, oldRelations;

    fdx = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IRP_MJ_PNP == stack->MajorFunction);

    switch (stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        RPRINTK(DPRTL_ON, ("--> %s %s: IRP_MN_START_DEVICE.\n",
                           VDEV_DRIVER_NAME, __func__));
        status = fwcfg_send_irp_synchronous(fdx->LowerDevice, Irp);

        if  (NT_SUCCESS(status)) {
            raw = &stack->Parameters.StartDevice
                .AllocatedResources->List[0].PartialResourceList;

            translated = &stack->Parameters.StartDevice
                .AllocatedResourcesTranslated->List[0].PartialResourceList;

            fwcfg_start_device(DeviceObject, raw, translated);
        }

        Irp->IoStatus.Status = status;
        fwcfg_complete_request(Irp, IO_NO_INCREMENT);

        RPRINTK(DPRTL_ON, ("<-- %s %s: IRP_MN_START_DEVICE return status %x\n",
                           VDEV_DRIVER_NAME, __func__, status));
        return status;

    case IRP_MN_QUERY_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_QUERY_STOP_DEVICE.\n", __func__));
        fdx->pnpstate = StopPending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        RPRINTK(DPRTL_ON,
            ("%s: IRP_MN_CANCEL_STOP_DEVICE.\n", __func__));
        if (fdx->pnpstate == StopPending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_STOP_DEVICE:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_STOP_DEVICE.\n", __func__));
        /* TODO: Irps and resources */

        fdx->pnpstate = Stopped;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        fwcfg_stop_device(fdx);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_QUERY_REMOVE_DEVICE.\n", __func__));
        fdx->pnpstate = RemovePending;
        Irp->IoStatus.Status = status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_CANCEL_REMOVE_DEVICE.\n", __func__));
        if (fdx->pnpstate == RemovePending) {
            fdx->pnpstate = Started;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_SURPRISE_REMOVAL.\n", __func__));
        fdx->pnpstate = SurpriseRemovePending;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        RPRINTK(DPRTL_ON, ("%s: IRP_MN_REMOVE_DEVICE.\n", __func__));

        fdx->pnpstate = Deleted;
        Irp->IoStatus.Status = STATUS_SUCCESS;

        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(fdx->LowerDevice, Irp);

        fwcfg_stop_device(fdx);

        /* Seems we crash if we try to print from here down. */
        IoDetachDevice(fdx->LowerDevice);

        /* The DeviceObject, aka gfdo, should be able to be set to NULL
         * eventhough there is an interaction between xnebus and xenblk.
         */
        IoDeleteDevice(DeviceObject);

        return status;

    default:
        RPRINTK(DPRTL_PNP,
            ("%s: default irp %x.\n", __func__, stack->MinorFunction));
        break;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(fdx->LowerDevice, Irp);

    return status;
}
