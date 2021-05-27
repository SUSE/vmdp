/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2017-2021 SUSE LLC
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

#if defined VIRTIO_BLK_DRIVER
#include <virtio_blk.h>
#elif defined VIRTIO_SCSI_DRIVER
#include <virtio_scsi.h>
#elif defined XEN_BLK_DRIVER
#include "xenblk.h"
#elif defined XEN_SCSI_DRIVER
#include "xenscsi.h"
#else
#endif

#ifdef DBG
uint32_t g_addb;
ULONG g_int_to_send;
#endif

#ifdef VBIF_DBG_TRACK_SRBS
uint32_t srbs_seen;
uint32_t srbs_returned;
uint32_t io_srbs_seen;
uint32_t io_srbs_returned;
uint32_t sio_srbs_seen;
uint32_t sio_srbs_returned;
#endif

static void virtio_sp_dump_config_info(virtio_sp_dev_ext_t *dev_ext,
    PPORT_CONFIGURATION_INFORMATION config_info);
static NTSTATUS virtio_sp_get_uncached_size_offsets(
    virtio_sp_dev_ext_t *dev_ext,
    PPORT_CONFIGURATION_INFORMATION config_info);
static NTSTATUS virtio_sp_find_device(virtio_sp_dev_ext_t *dev_ext,
    PPORT_CONFIGURATION_INFORMATION config_info);
static void virtio_sp_init_config_info(virtio_sp_dev_ext_t *dev_ext,
    PPORT_CONFIGURATION_INFORMATION config_info);
static NTSTATUS virtio_sp_find_vq(virtio_sp_dev_ext_t *dev_ext);
static void virtio_sp_shutdown(virtio_sp_dev_ext_t *dev_ext);
static SCSI_ADAPTER_CONTROL_STATUS virtio_sp_restart(
    virtio_sp_dev_ext_t *dev_ext);

ULONG
KvmDriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath)
{
    HW_INITIALIZATION_DATA hwInitializationData;
    NTSTATUS status;
    uint32_t i;
    KIRQL irql;

    irql = KeGetCurrentIrql();

    /* Don't printf before we know if we should be running. */
    RPRINTK(DPRTL_ON, ("%s DriverEntry %x, irql = %d, HIGH_LEVEL = %d\n",
        VIRTIO_SP_DRIVER_NAME, DriverObject, irql, HIGH_LEVEL));
    if (irql >= DISPATCH_LEVEL) {
        PRINTK(("%s: DriverEntry for hibernate/crashdump: Begin.\n",
                VIRTIO_SP_DRIVER_NAME));
    }

    for (i = 0; i < sizeof(HW_INITIALIZATION_DATA); i++) {
        ((PCHAR)&hwInitializationData)[i] = 0;
    }

    hwInitializationData.HwInitializationDataSize =
        sizeof(HW_INITIALIZATION_DATA);

    /* Set entry points into the miniport. */
    hwInitializationData.HwFindAdapter = sp_find_adapter;
    hwInitializationData.HwInitialize = sp_initialize;
    hwInitializationData.HwResetBus = sp_reset_bus;
    hwInitializationData.HwAdapterControl = sp_adapter_control;
    hwInitializationData.HwInterrupt = sp_interrupt;

    /* Sizes of the structures that port needs to allocate. */
    hwInitializationData.DeviceExtensionSize = sizeof(virtio_sp_dev_ext_t);
    hwInitializationData.SrbExtensionSize = sizeof(virtio_sp_srb_ext_t);
    hwInitializationData.SpecificLuExtensionSize = 0;

    hwInitializationData.NeedPhysicalAddresses = TRUE;
    hwInitializationData.TaggedQueuing = TRUE;
    hwInitializationData.AutoRequestSense = TRUE;
    hwInitializationData.MultipleRequestPerLu = TRUE;

    hwInitializationData.NumberOfAccessRanges = SP_NUMBER_OF_ACCESS_RANGES;
    hwInitializationData.AdapterInterfaceType = SP_BUS_INTERFACE_TYPE;


    hwInitializationData.HwStartIo = sp_start_io;
    hwInitializationData.HwBuildIo = sp_build_io;
    hwInitializationData.MapBuffers = STOR_MAP_NON_READ_WRITE_BUFFERS;

    RPRINTK(DPRTL_ON, ("\tcalling StorPoprtInitialize\n"));
    status = StorPortInitialize(DriverObject,
                                RegistryPath,
                                &hwInitializationData,
                                NULL);

    RPRINTK(DPRTL_ON, ("\tDriverEntry - out StorPortInitialize status = %x\n",
        status));

    if (irql >= DISPATCH_LEVEL) {
        PRINTK(("%s: DriverEntry hibernate/crashdump returning: %x.\n",
                VIRTIO_SP_DRIVER_NAME, status));
        PRINTK(("%s: *** hibernate/crashdump should now begin ***\n",
                VIRTIO_SP_DRIVER_NAME));
    }

    RPRINTK(DPRTL_ON, ("%s: DriverEntry returning %x.\n",
                       VIRTIO_SP_DRIVER_NAME, status));
    return status;
}

NTSTATUS
sp_find_adapter(
    IN PVOID dev_extt,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCSTR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION config_info,
    OUT PBOOLEAN Again)
{
    virtio_sp_dev_ext_t *dev_ext = (virtio_sp_dev_ext_t *)dev_extt;
    NTSTATUS status = 0;
    ULONG len;
    uint32_t flags = 0;

    status = virtio_sp_find_device(dev_ext, config_info);
    if (!NT_SUCCESS(status)) {
        return SP_RETURN_ERROR;
    }

    virtio_sp_get_device_config(dev_ext);

    virtio_sp_init_config_info(dev_ext, config_info);

    if (virtio_sp_get_uncached_size_offsets(dev_ext, config_info)
            != STATUS_SUCCESS) {
        return SP_RETURN_ERROR;
    }

    virtio_sp_dump_config_info(dev_ext, config_info);

    RPRINTK(DPRTL_ON,
        ("%s %s: out: dev_ext = %p\n",
         VIRTIO_SP_DRIVER_NAME, __func__, dev_ext));
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        PRINTK(("%s %s: hibernate/crashdump end.\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
    }
    return SP_RETURN_FOUND;
}

BOOLEAN
sp_initialize(virtio_sp_dev_ext_t *dev_ext)
{
    uint32_t i;

    if (!(dev_ext->op_mode & OP_MODE_NORMAL)) {
        PRINTK(("%s %s: hibernate/crashdump Begin\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
    }
    VBIF_SET_FLAG(dev_ext->sp_locks, (BLK_IZE_L | BLK_INT_L));
    VBIF_SET_FLAG(dev_ext->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
    RPRINTK(DPRTL_ON, ("%s %s: IN irql = %d, dev = %p, op_mode %x, state %x\n",
        VIRTIO_SP_DRIVER_NAME, __func__, KeGetCurrentIrql(), dev_ext,
        dev_ext->op_mode, dev_ext->state));

    if (virtio_sp_find_vq(dev_ext) != STATUS_SUCCESS) {
        return FALSE;
    }

    virtio_sp_initialize(dev_ext);

    virtio_device_add_status(&dev_ext->vdev, VIRTIO_CONFIG_S_DRIVER_OK);

    if (dev_ext->state == REMOVED) {
        dev_ext->state = WORKING;
        RPRINTK(DPRTL_ON, ("%s %s: returning TRUE: in REMOVED state.\n",
            VIRTIO_SP_DRIVER_NAME, __func__));
        VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_IZE_L | BLK_INT_L));
        VBIF_CLEAR_FLAG(dev_ext->cpu_locks,
            (1 << KeGetCurrentProcessorNumber()));
        return TRUE;
    }

    if (dev_ext->state != WORKING) {
        dev_ext->state = INITIALIZING;
        if (dev_ext->op_mode & OP_MODE_NORMAL) {
            /* Scsi passive initialization starts from sp_adapter_control. */
            StorPortEnablePassiveInitialization(dev_ext, sp_passive_init);
            RPRINTK(DPRTL_ON, ("%s %s: we'll do passive init from control\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
        } else {
            if (!sp_passive_init(dev_ext)) {
                return TRUE;
            }
            PRINTK(("%s %s: hibernate/crashdump end.\n",
                    VIRTIO_SP_DRIVER_NAME, __func__));
        }
    }

    VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_IZE_L | BLK_INT_L));
    VBIF_CLEAR_FLAG(dev_ext->cpu_locks,
        (1 << KeGetCurrentProcessorNumber()));
    RPRINTK(DPRTL_ON, ("%s %s: OUT\n", VIRTIO_SP_DRIVER_NAME, __func__));
    return TRUE;
}

BOOLEAN
sp_passive_init(virtio_sp_dev_ext_t *dev_ext)
{
    RPRINTK(DPRTL_ON, ("%s %s: IN dev %p, irql = %d\n",
        VIRTIO_SP_DRIVER_NAME, __func__, dev_ext, KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber()));

    if (dev_ext->state == WORKING) {
        RPRINTK(DPRTL_ON, ("%s %s: already initialized %p\n",
            VIRTIO_SP_DRIVER_NAME, __func__, dev_ext));
        return TRUE;
    }

    if (dev_ext->op_mode & OP_MODE_NORMAL) {
#ifdef USE_STORPORT_DPC
        StorPortInitializeDpc(dev_ext,
            &dev_ext->srb_complete_dpc,
            virtio_sp_int_dpc);
#endif
        StorPortResume(dev_ext);
    }
    dev_ext->state = WORKING;

    RPRINTK(DPRTL_ON, ("%s %s: OUT irql %d, cpu %x\n",
                       VIRTIO_SP_DRIVER_NAME, __func__,
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    return TRUE;
}


SCSI_ADAPTER_CONTROL_STATUS
sp_adapter_control(
    IN virtio_sp_dev_ext_t *dev_ext,
    IN SCSI_ADAPTER_CONTROL_TYPE control_type,
    IN PVOID parameters)
{
    SP_LOCK_HANDLE lh;
    SCSI_ADAPTER_CONTROL_STATUS status;
    uint32_t i;
    int j;
    KIRQL irql;

    irql = KeGetCurrentIrql();
    RPRINTK(DPRTL_ON,
            ("%s %s: IN ct = %x\n\tdev = %p, irql = %d, cpu %d, op %x, st %x\n",
             VIRTIO_SP_DRIVER_NAME, __func__, control_type, dev_ext, irql,
             KeGetCurrentProcessorNumber(), dev_ext->op_mode, dev_ext->state));
    DPR_SRB("AC");

    status = ScsiAdapterControlSuccess;
    switch (control_type) {
    case ScsiQuerySupportedControlTypes: {
        PSCSI_SUPPORTED_CONTROL_TYPE_LIST supportedList = parameters;

        supportedList->SupportedTypeList[ScsiStopAdapter] = TRUE;
        supportedList->SupportedTypeList[ScsiRestartAdapter] = TRUE;
        supportedList->SupportedTypeList[ScsiQuerySupportedControlTypes] =
            TRUE;
        if (dev_ext->state == INITIALIZING) {
            sp_passive_init(dev_ext);
        }
        break;
    }

    case ScsiStopAdapter:
        virtio_sp_shutdown(dev_ext);
        break;

    case ScsiRestartAdapter: {
        status = virtio_sp_restart(dev_ext);
        break;
    }
    default:
        RPRINTK(DPRTL_ON, ("%s: unknown control type %d\n",
                           __func__, control_type));
        break;
    }

    RPRINTK(DPRTL_ON, ("%s %s: irql %d, cpu %d OUT\n",
                       VIRTIO_SP_DRIVER_NAME, __func__,
                       irql, KeGetCurrentProcessorNumber()));
    DPRINTK(DPRTL_ON, ("  locks %x\n", dev_ext->sp_locks));
    DPR_SRB("ACE");

    return status;
}

BOOLEAN
sp_interrupt(virtio_sp_dev_ext_t *dev_ext)
{
    ULONG reason;
    BOOLEAN int_serviced;

    DPRINTK(DPRTL_INT, ("%s %s: in (irql %d)\n",
        VIRTIO_SP_DRIVER_NAME, __func__, KeGetCurrentIrql()));

    if (dev_ext->op_mode & OP_MODE_RESET) {
        dev_ext->op_mode &= ~OP_MODE_RESET;
        PRINTK(("%s %s: clear reset mode.\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
    }
    if (dev_ext->op_mode & OP_MODE_POLLING) {
        dev_ext->op_mode &= ~OP_MODE_POLLING;
        PRINTK(("%s %s: clear polling mode.\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
    }
    reason = virtio_device_read_isr_status(&dev_ext->vdev);
    DPRINTK(DPRTL_INT, ("%s %s: isr reason %d\n",
                        VIRTIO_SP_DRIVER_NAME, __func__, reason));
    if (reason > 0
            || (dev_ext->op_mode & (OP_MODE_HIBERNATE | OP_MODE_CRASHDUMP))) {

        virtio_sp_int_complete_cmd(dev_ext, reason,
                                   VIRTIO_SCSI_QUEUE_REQUEST,
                                   int_serviced);
    } else {
        int_serviced = FALSE;
    }

    DPRINTK(DPRTL_INT, ("%s %s: out reason %d, serviced interrupt %d\n",
        VIRTIO_SP_DRIVER_NAME, __func__, reason, int_serviced));

    return int_serviced;
}

#ifdef CAN_USE_MSI
BOOLEAN
sp_msinterrupt_routine(virtio_sp_dev_ext_t *dev_ext, ULONG  msg_id)
{
    ULONG i;
    BOOLEAN int_serviced = TRUE;

    DPRINTK(DPRTL_INT, ("%s %s: in (irql %d) msg_id 0x%x\n",
        VIRTIO_SP_DRIVER_NAME, __func__, KeGetCurrentIrql(), msg_id));

    if (msg_id > dev_ext->msi_vectors) {
        PRINTK(("%s %s: Too large message id %d\n",
                VIRTIO_SP_DRIVER_NAME, __func__, msg_id));
        return FALSE;
    }

    if (dev_ext->op_mode & OP_MODE_RESET) {
        dev_ext->op_mode &= ~OP_MODE_RESET;
        PRINTK(("%s %s: clear reset mode.\n", VIRTIO_SP_DRIVER_NAME, __func__));
    }
    if (dev_ext->op_mode & OP_MODE_POLLING) {
        dev_ext->op_mode &= ~OP_MODE_POLLING;
        PRINTK(("%s %s: clear polling mode.\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
    }

    if (dev_ext->msix_uses_one_vector == FALSE) {
        int_serviced = virtio_sp_complete_cmd(dev_ext, 0, msg_id - 1);
    } else {
        for (i = 0; i < dev_ext->num_queues + VIRTIO_SCSI_QUEUE_REQUEST; i++) {
            int_serviced |= virtio_sp_complete_cmd(dev_ext, 0, i);
        }
    }

    DPRINTK(DPRTL_INT, ("%s %s: out, msg_id 0x%x\n",
                        VIRTIO_SP_DRIVER_NAME, __func__, msg_id));
    return int_serviced;
}
#endif

BOOLEAN
virtio_scsi_do_cmd(virtio_sp_dev_ext_t *dev_ext, SCSI_REQUEST_BLOCK *srb)
{
    STARTIO_PERFORMANCE_PARAMETERS param;
    PHYSICAL_ADDRESS pa;
    virtio_sp_srb_ext_t *srb_ext;
    NTSTATUS status;
    ULONG len;
    ULONG qidx;
    int num_free;

    VBIF_SET_FLAG(dev_ext->sp_locks, (BLK_ADD_L));
    DPRINTK(DPRTL_TRC, ("%s %s: in srb %p, irql %x, Srb->Cdb[0] %x\n",
                        VIRTIO_SP_DRIVER_NAME, __func__,
                        srb,
                        KeGetCurrentIrql(),
                        srb->Cdb[0]));

    srb_ext = (virtio_sp_srb_ext_t *)srb->SrbExtension;

    if (dev_ext->num_queues > 1) {
        param.Size = sizeof(STARTIO_PERFORMANCE_PARAMETERS);
        status = StorPortGetStartIoPerfParams(dev_ext, srb, &param);
        if (status == STOR_STATUS_SUCCESS && param.MessageNumber != 0) {
            qidx = param.MessageNumber - 1;
        } else {
            qidx = VIRTIO_SCSI_QUEUE_REQUEST;
        }
    } else {
        qidx = VIRTIO_SCSI_QUEUE_REQUEST;
    }

    if (dev_ext->indirect) {
        pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, srb_ext->vr_desc, &len);
        num_free = vq_add_buf_indirect(dev_ext->vq[qidx],
            &srb_ext->sg[0],
            srb_ext->out,
            srb_ext->in,
            &srb_ext->vbr,
            srb_ext->vr_desc,
            pa.QuadPart);
    } else {
        num_free = vq_add_buf(dev_ext->vq[qidx],
            &srb_ext->sg[0],
            srb_ext->out,
            srb_ext->in,
            &srb_ext->vbr);
    }
    if (num_free >= 0) {
        vq_kick(dev_ext->vq[qidx]);
        SP_SHOULD_NOTIFY_NEXT(dev_ext, srb, srb_ext, num_free);
        DPRINTK(DPRTL_TRC, ("%s %s: out TRUE, added %d\n",
                            VIRTIO_SP_DRIVER_NAME,  __func__, ++g_addb));
        VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_ADD_L));
        return TRUE;
    }

    SP_BUSY(dev_ext, max(dev_ext->queue_depth, 5));
    DPRINTK(DPRTL_UNEXPD, ("%s %s: busy out FALSE\n",
                           VIRTIO_SP_DRIVER_NAME, __func__));
    VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_ADD_L));
    return FALSE;
}

#ifdef IS_STORPORT
BOOLEAN
virtio_sp_scsi_do_cmd(virtio_sp_dev_ext_t *dev_ext,
    SCSI_REQUEST_BLOCK *srb)
{
#ifdef UUSE_STORPORT_DPC
    KLOCK_QUEUE_HANDLE lh;
    BOOLEAN cc;
#endif
#ifdef DBG
    if (!(dev_ext->op_mode & OP_MODE_NORMAL)) {
        DPRINTK(DPRTL_INT, ("%s: Ints between sends = %d\n",
                            VIRTIO_SP_DRIVER_NAME, g_int_to_send));
        g_int_to_send = 0;
    }
#endif
#ifdef UUSE_STORPORT_DPC
    KeAcquireInStackQueuedSpinLock(&dev_ext->dev_lock, &lh);
    cc =  virtio_scsi_do_cmd(dev_ext, srb);
    KeReleaseInStackQueuedSpinLock(&lh);
    return cc;
#else
    return StorPortSynchronizeAccess(dev_ext, virtio_scsi_do_cmd, srb);
#endif
}
#endif

BOOLEAN
virtio_sp_do_poll(virtio_sp_dev_ext_t *dev_ext, void *not_used)
{
    RPRINTK(DPRTL_ON, ("%s %s: in\n", VIRTIO_SP_DRIVER_NAME, __func__));
    virtio_sp_complete_cmd(dev_ext, 1, VIRTIO_SCSI_QUEUE_REQUEST);
    RPRINTK(DPRTL_ON, ("%s %s: out\n", VIRTIO_SP_DRIVER_NAME, __func__));
    return TRUE;
}

void
virtio_sp_poll(IN virtio_sp_dev_ext_t *dev_ext)
{
    RPRINTK(DPRTL_ON, ("%s %s: in\n", VIRTIO_SP_DRIVER_NAME, __func__));
    SP_SYNCHRONIZE_ACCESS(dev_ext, virtio_sp_do_poll, NULL);
    if (dev_ext->op_mode & OP_MODE_POLLING) {
        SP_NOTIFICATION(RequestTimerCall, dev_ext, virtio_sp_poll, 100);
    }
    RPRINTK(DPRTL_ON, ("%s %s: out\n", VIRTIO_SP_DRIVER_NAME, __func__));
}

static NTSTATUS
virtio_sp_init_dev_ext(virtio_sp_dev_ext_t *dev_ext, KIRQL irql)
{
    void *pvoid;
    NTSTATUS status = 0;
    PUCHAR reg_buf;
    ULONG len;
    DWORD use_packed_rings;

    VBIF_ZERO_VALUE(dev_ext->alloc_cnt_i);
    VBIF_ZERO_VALUE(dev_ext->alloc_cnt_s);
    VBIF_ZERO_VALUE(dev_ext->alloc_cnt_v);

    dev_ext->msi_enabled = FALSE;
    dev_ext->msi_vectors = 0;
    dev_ext->indirect = 0;
    dev_ext->state = STOPPED;
    use_packed_rings = 1;

    if (irql <= DISPATCH_LEVEL) {
        if (irql == PASSIVE_LEVEL) {
            dev_ext->op_mode = OP_MODE_NORMAL;
            len = sizeof(uint32_t);
            sp_registry_read(dev_ext, PVCTRL_DBG_PRINT_MASK_STR, REG_DWORD,
                             &dbg_print_mask, &len);
            len = sizeof(uint32_t);
            sp_registry_read(dev_ext, PVCTRL_PACKED_RINGS_STR, REG_DWORD,
                             &use_packed_rings, &len);
            dev_ext->b_use_packed_rings = (BOOLEAN)use_packed_rings;
#ifdef DBG
            len = sizeof(uint32_t);
            sp_registry_read(dev_ext, PVCTRL_CDBG_PRINT_LIMIT_STR, REG_DWORD,
                             &conditional_times_to_print_limit, &len);
#endif
        } else {
            dev_ext->op_mode = OP_MODE_HIBERNATE;
            PRINTK(("%s %s: setting up for hibernate\n",
                    VIRTIO_SP_DRIVER_NAME, __func__));
        }
    } else {
        PRINTK(("%s %s: setting up for hibernate/crashdump\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
        dev_ext->op_mode = OP_MODE_CRASHDUMP;
    }

#if defined VIRTIO_BLK_DRIVER
    InitializeListHead(&dev_ext->srb_list);

    dev_ext->queue_depth = VSP_QUEUE_DEPTH_NOT_SET;
    len = sizeof(uint32_t);
    sp_registry_read(dev_ext, PVCTRL_QDEPTH_STR, REG_DWORD,
                     &dev_ext->queue_depth, &len);
#elif defined VIRTIO_SCSI_DRIVER
#ifdef USE_STORPORT_DPC
    KeInitializeSpinLock(&dev_ext->dev_lock);
#endif
    dev_ext->underruns = 0;
    dev_ext->inquiry_supported = FALSE;
#endif

    VBIF_CLEAR_FLAG(dev_ext->sp_locks, 0xffffffff);
    VBIF_CLEAR_FLAG(dev_ext->cpu_locks, 0xffffffff);

    return STATUS_SUCCESS;
}

static NTSTATUS
virtio_sp_virtio_dev_init(virtio_sp_dev_ext_t *dev_ext,
                          PPORT_CONFIGURATION_INFORMATION config_info)
{
    PPCI_MSIX_CAPABILITY pMsixCapOffset;
    PPCI_COMMON_HEADER  pPciComHeader;
    PPCI_COMMON_CONFIG pPciConf = NULL;
    PACCESS_RANGE accessRange;
    NTSTATUS status;
    ULONG pci_cfg_len;
    ULONG i;
    UCHAR CapOffset;
    int iBar;

    pPciConf = (PPCI_COMMON_CONFIG)dev_ext->pci_cfg_buf;
    pPciComHeader = (PPCI_COMMON_HEADER)dev_ext->pci_cfg_buf;

    pci_cfg_len = StorPortGetBusData(dev_ext,
                                     PCIConfiguration,
                                     config_info->SystemIoBusNumber,
                                     (ULONG)config_info->SlotNumber,
                                     (PVOID)dev_ext->pci_cfg_buf,
                                     sizeof(PCI_COMMON_CONFIG));
    if (pci_cfg_len != sizeof(PCI_COMMON_CONFIG)) {
        PRINTK(("%s: Cannot read PCI CONFIGURATION SPACE %d\n",
                VIRTIO_SP_DRIVER_NAME, pci_cfg_len));
        return SP_RETURN_ERROR;
    }

    RPRINTK(DPRTL_ON, ("%s %s: AccessRanges %d\n",
                       VIRTIO_SP_DRIVER_NAME, __func__,
                       config_info->NumberOfAccessRanges));

    for (i = 0; i < config_info->NumberOfAccessRanges; i++) {
        accessRange = *config_info->AccessRanges + i;
        if (accessRange->RangeLength != 0) {
            iBar = virtio_get_bar_index(pPciComHeader, accessRange->RangeStart);
            if (iBar == -1) {
                PRINTK(("%s: Cannot get index for BAR %lld\n",
                        VIRTIO_SP_DRIVER_NAME,
                        accessRange->RangeStart.QuadPart));
                return SP_RETURN_ERROR;
            }
            dev_ext->bar[iBar].pa = accessRange->RangeStart;
            dev_ext->bar[iBar].len = accessRange->RangeLength;
            dev_ext->bar[iBar].bPortSpace = !accessRange->RangeInMemory;
            dev_ext->bar[iBar].va = StorPortGetDeviceBase(dev_ext,
                config_info->AdapterInterfaceType,
                config_info->SystemIoBusNumber,
                accessRange->RangeStart,
                accessRange->RangeLength,
                (BOOLEAN)!accessRange->RangeInMemory);
            RPRINTK(DPRTL_ON,
                    ("%s %s: AR[%d] ibar %d pa %llx\n\tva %p len %d inmem %d\n",
                     VIRTIO_SP_DRIVER_NAME, __func__, i,
                     iBar, accessRange->RangeStart, dev_ext->bar[iBar].va,
                     accessRange->RangeLength, accessRange->RangeInMemory));
        }
    }

#ifdef CAN_USE_MSI
    if ((pPciComHeader->Status & PCI_STATUS_CAPABILITIES_LIST) == 0) {
        RPRINTK(DPRTL_ON, ("%s: No PCI CAPABILITIES_LIST\n",
                           VIRTIO_SP_DRIVER_NAME));
    } else {
        if ((pPciComHeader->HeaderType & (~PCI_MULTIFUNCTION))
                == PCI_DEVICE_TYPE) {
            CapOffset = pPciComHeader->u.type0.CapabilitiesPtr;
            while (CapOffset != 0) {
                pMsixCapOffset =
                    (PPCI_MSIX_CAPABILITY)(dev_ext->pci_cfg_buf + CapOffset);
                if (pMsixCapOffset->Header.CapabilityID
                        == PCI_CAPABILITY_ID_MSIX) {
                    RPRINTK(DPRTL_ON, ("\tMessageControl.TableSize = %d\n",
                        pMsixCapOffset->MessageControl.TableSize));
                    RPRINTK(DPRTL_ON, ("\tMessageControl.FunctionMask = %d\n",
                        pMsixCapOffset->MessageControl.FunctionMask));
                    RPRINTK(DPRTL_ON, ("\tMessageControl.MSIXEnable = %d\n",
                        pMsixCapOffset->MessageControl.MSIXEnable));
                    RPRINTK(DPRTL_ON, ("\tMessageTable = %p\n",
                        pMsixCapOffset->MessageTable));
                    RPRINTK(DPRTL_ON, ("\tPBATable = %d\n",
                        pMsixCapOffset->PBATable));
                    dev_ext->msi_enabled =
                        (pMsixCapOffset->MessageControl.MSIXEnable == 1);
                } else {
                    RPRINTK(DPRTL_ON,
                            ("CapabilityID = %x, Next CapOffset = %x\n",
                            pMsixCapOffset->Header.CapabilityID, CapOffset));
             }
             CapOffset = pMsixCapOffset->Header.Next;
          }
        } else {
            PRINTK(("%s: Not a PCI_DEVICE_TYPE\n", VIRTIO_SP_DRIVER_NAME));
        }
    }
#endif

    /* Reset and add status VIRTIO_CONFIG_S_ACKNOWLEDGE are handled in init */
    status = virtio_device_init(&dev_ext->vdev,
                                dev_ext->bar,
                                dev_ext->pci_cfg_buf,
                                VIRTIO_SP_DRIVER_NAME,
                                dev_ext->msi_enabled);
    return status;
}

static NTSTATUS
virtio_sp_find_device(virtio_sp_dev_ext_t *dev_ext,
                      PPORT_CONFIGURATION_INFORMATION config_info)
{
    KIRQL irql;
    NTSTATUS status;

    irql = KeGetCurrentIrql();
    if (irql >= DISPATCH_LEVEL) {
        PRINTK(("%s %s: hibernate/crashdump begin.\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
    }

    RPRINTK(DPRTL_ON, ("%s %s: - IN irql = %d, dev = %p\n",
                       VIRTIO_SP_DRIVER_NAME, __func__, irql, dev_ext));

    virtio_sp_init_dev_ext(dev_ext, irql);
    status = virtio_sp_virtio_dev_init(dev_ext, config_info);
    if (!NT_SUCCESS(status)) {
        PRINTK(("%s %s: failed to initialize virtio device, 0x%x\n",
                VIRTIO_SP_DRIVER_NAME, __func__, status));
        return SP_RETURN_ERROR;
    }
    dev_ext->features = VIRTIO_DEVICE_GET_FEATURES(&dev_ext->vdev);

    virtio_sp_enable_features(dev_ext);

    RPRINTK(DPRTL_ON, ("%s %s: - OUT\n", VIRTIO_SP_DRIVER_NAME, __func__));
    return status;
}

static void
virtio_sp_init_config_info(virtio_sp_dev_ext_t *dev_ext,
                           PPORT_CONFIGURATION_INFORMATION config_info)
{
    RPRINTK(DPRTL_ON, ("\tStarting MTS = %ld, NPB = %ld, BA = %d, CD = %d\n",
        config_info->MaximumTransferLength, config_info->NumberOfPhysicalBreaks,
        config_info->BufferAccessScsiPortControlled, config_info->CachesData));
    RPRINTK(DPRTL_ON, ("\tStarting Dma32BitAddresses = %d\n",
        config_info->Dma32BitAddresses));
    RPRINTK(DPRTL_ON, ("\tStarting Dma64BitAddresses = %d\n",
        config_info->Dma64BitAddresses));

    config_info->Master                         = TRUE;
    config_info->NeedPhysicalAddresses          = TRUE;
    config_info->TaggedQueuing                  = TRUE;
    config_info->ScatterGather                  = TRUE;
    config_info->DmaWidth                       = Width32Bits;
    config_info->AlignmentMask                  = 0x3;
    config_info->Dma32BitAddresses              = TRUE;
    config_info->NumberOfBuses                  = 1;

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        config_info->NumberOfPhysicalBreaks =
            VIRTIO_SP_PHYS_CRASH_DUMP_SEGMENTS;
        config_info->MaximumTransferLength =
            VIRTIO_SP_MAX_SGL_ELEMENTS * PAGE_SIZE;
    } else {
        dev_ext->indirect =
            IS_BIT_SET(dev_ext->features, VIRTIO_RING_F_INDIRECT_DESC)
                ? TRUE : FALSE;
        if (dev_ext->indirect) {
            config_info->NumberOfPhysicalBreaks = MAX_PHYS_SEGMENTS + 1;
            config_info->MaximumTransferLength =
                (MAX_PHYS_SEGMENTS + 1) * PAGE_SIZE;
        } else {
            config_info->NumberOfPhysicalBreaks = VIRTIO_SP_MAX_SGL_ELEMENTS;
            config_info->MaximumTransferLength =
                VIRTIO_SP_MAX_SGL_ELEMENTS * PAGE_SIZE;
        }
    }

    if (config_info->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED) {
        RPRINTK(DPRTL_ON, ("\tsetting SCSI_DMA64_MINIPORT_SUPPORTED\n"));
        config_info->Dma64BitAddresses          = SCSI_DMA64_MINIPORT_SUPPORTED;
    }
    config_info->SynchronizationModel           = StorSynchronizeFullDuplex;
#ifdef CAN_USE_MSI
    RPRINTK(DPRTL_ON, ("sp_find_adapter: msi_supported\n"));
    config_info->HwMSInterruptRoutine = sp_msinterrupt_routine;
    config_info->InterruptSynchronizationMode = InterruptSynchronizePerMessage;
#endif

#if defined VIRTIO_BLK_DRIVER
    config_info->MaximumNumberOfTargets         = 1;
    config_info->MaximumNumberOfLogicalUnits    = 1;
    config_info->WmiDataProvider                = FALSE;
    config_info->CachesData =
        IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_WCACHE) ? TRUE : FALSE;
#elif defined VIRTIO_SCSI_DRIVER
    config_info->MaximumNumberOfTargets         =
        (UCHAR)dev_ext->scsi_config.max_target;
    config_info->MaximumNumberOfLogicalUnits    =
        (UCHAR)dev_ext->scsi_config.max_lun;
#endif
}

static void
virtio_sp_dump_config_info(virtio_sp_dev_ext_t *dev_ext,
                           PPORT_CONFIGURATION_INFORMATION config_info)
{

    virtio_sp_dump_device_config_info(dev_ext, config_info);

    PRINTK(("\tindirect: %d\n", dev_ext->indirect));
    PRINTK(("\tNumberOfPhysicalBreaks: %d\n",
            config_info->NumberOfPhysicalBreaks));
    PRINTK(("\tMaximumTransferLength: %d\n",
            config_info->MaximumTransferLength));
    PRINTK(("\tqueue depth: %d\n", dev_ext->queue_depth));
    PRINTK(("\treg packed rings: %d\n", dev_ext->b_use_packed_rings));
    PRINTK(("\tuse packed rings: %d\n", dev_ext->vdev.packed_ring));
    PRINTK(("\tdbg_print_mask: 0x%x\n", dbg_print_mask));

    RPRINTK(DPRTL_ON, ("\n\tInterrupt level 0x%x, vector 0x%x, mode 0x%x\n",
            config_info->BusInterruptLevel,
            config_info->BusInterruptVector, config_info->InterruptMode));
    RPRINTK(DPRTL_ON, ("\tAdapterInterfaceType: %d\n",
            config_info->AdapterInterfaceType));
    RPRINTK(DPRTL_ON, ("\tDemandMode: %d\n", config_info->DemandMode));
    RPRINTK(DPRTL_ON, ("\tMaster: %d\n", config_info->Master));
    RPRINTK(DPRTL_ON, ("\tScatterGather: %d\n", config_info->ScatterGather));
    RPRINTK(DPRTL_ON, ("\tDmaWidth: %d\n", config_info->DmaWidth));
    RPRINTK(DPRTL_ON, ("\tDma32BitAddresses: %d\n",
            config_info->Dma32BitAddresses));
    RPRINTK(DPRTL_ON, ("\tDma64BitAddresses: %d\n",
            config_info->Dma64BitAddresses));
    RPRINTK(DPRTL_ON, ("\tWmiDataProvider: %d\n",
            config_info->WmiDataProvider));
    RPRINTK(DPRTL_ON, ("\tAlignmentMask: %d\n", config_info->AlignmentMask));
    RPRINTK(DPRTL_ON, ("\tMapBuffers: %d\n", config_info->MapBuffers));
    RPRINTK(DPRTL_ON, ("\tSynchronizationModel: %d\n",
            config_info->SynchronizationModel));
    RPRINTK(DPRTL_ON, ("\tNumberOfBuses: %d\n", config_info->NumberOfBuses));
    RPRINTK(DPRTL_ON, ("\tMaximumNumberOfTargets: %d\n",
            config_info->MaximumNumberOfTargets));
    RPRINTK(DPRTL_ON, ("\tMaximumNumberOfLogicalUnits: %d\n",
            config_info->MaximumNumberOfLogicalUnits));
    RPRINTK(DPRTL_ON, ("\tNeedPhysicalAddresses: %d\n",
            config_info->NeedPhysicalAddresses));
    RPRINTK(DPRTL_ON, ("\tTaggedQueuing: %d\n", config_info->TaggedQueuing));
    RPRINTK(DPRTL_ON, ("\tCachesData: %d\n", config_info->CachesData));
}

static void
virtio_sp_init_num_queues(virtio_sp_dev_ext_t *dev_ext, ULONG *max_queues)
{
#ifdef MSI_SUPPORTED
    ULONG num_cpus;
    ULONG max_cpus;
#endif

    *max_queues = 1;
    dev_ext->num_queues = 1;

#ifdef MSI_SUPPORTED
    if ((dev_ext->op_mode & OP_MODE_NORMAL) && dev_ext->msi_enabled) {
        if (IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_MQ)) {
            PRINTK(("%s %s: features %x, VIRTIO_BLK_F_MQ is set\n",
                    VIRTIO_SP_DRIVER_NAME, __func__,
                    dev_ext->features));
            VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
                                     FIELD_OFFSET(vbif_info_ex_t, num_queues),
                                     &dev_ext->num_queues, sizeof(ULONG));
            PRINTK(("%s %s: VIRTIO_BLK_F_MQ num queues %d\n",
                    VIRTIO_SP_DRIVER_NAME, __func__,
                    dev_ext->num_queues));
            if (dev_ext->num_queues > 1) {
#if (NTDDI_VERSION >= NTDDI_WIN7)
                num_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
                max_cpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
#else
                num_cpus = KeQueryActiveProcessorCount(NULL);
                max_cpus = KeQueryMaximumProcessorCount();
#endif
                if (dev_ext->num_queues < num_cpus) {
                    dev_ext->num_queues = 1;
                } else {
#if (NTDDI_VERSION > NTDDI_WIN7)
                    dev_ext->num_queues = (USHORT)num_cpus;
#else
                    dev_ext->num_queues = 1;
#endif
                }
                *max_queues = min(max_cpus, dev_ext->num_queues);
            }
        }
    }
#endif
    if (*max_queues != dev_ext->num_queues) {
        PRINTK(("%s %s: max_queues (%d) != num_queues (%d)\n",
                VIRTIO_SP_DRIVER_NAME, __func__,
                *max_queues, dev_ext->num_queues));
    }
}

static NTSTATUS
virtio_sp_get_uncached_size_offsets(virtio_sp_dev_ext_t *dev_ext,
                                    PPORT_CONFIGURATION_INFORMATION config_info)
{
    ULONG vr_size;
    ULONG vq_size;
    ULONG_PTR ptr;
    ULONG_PTR ring_va;
    ULONG_PTR queue_va;
    ULONG rsize;
    ULONG qsize;
    ULONG roffset;
    ULONG qoffset;
    ULONG total_vring_size;
    ULONG total_vq_size;
    ULONG total_srb_ext_size;
    ULONG total_event_node_size;
    ULONG max_queues;
    ULONG num_queues;
    ULONG i;
    uint16_t num;


    virtio_sp_init_num_queues(dev_ext, &num_queues);
    max_queues = num_queues + VIRTIO_SCSI_QUEUE_REQUEST;

    total_vring_size = 0;
    total_vq_size = 0;
    total_srb_ext_size = 0;
    total_event_node_size = 0;
#ifdef VIRTIO_SCSI_DRIVER
    total_srb_ext_size = ROUND_TO_CACHE_LINES(sizeof(vscsi_srb_ext_t));
    total_event_node_size = ROUND_TO_CACHE_LINES(
        sizeof(virtio_scsi_event_node_t) * VIRTIO_SCSI_T_EVENTS_IN_QUEUE);
#endif
    for (i = 0; i < max_queues; i++) {
        VIRTIO_DEVICE_QUERY_QUEUE_ALLOC(&dev_ext->vdev,
                                        i,
                                        &num,
                                        &rsize,
                                        &qsize);
        if (num == 0) {
            PRINTK(("%s %s: Failed to get queue allocation sizes\n",
                    VIRTIO_SP_DRIVER_NAME, __func__));
            return SP_RETURN_ERROR;
        }
        total_vring_size += ROUND_TO_PAGES(rsize);
        total_vq_size += ROUND_TO_CACHE_LINES(qsize);
        RPRINTK(DPRTL_ON, ("%s %s: num = %d\n\trsize = %d %d, qsize = %d %d\n",
                           VIRTIO_SP_DRIVER_NAME, __func__,
                           num, rsize, total_vring_size, qsize, total_vq_size));
    }
    ring_va = (ULONG_PTR)StorPortGetUncachedExtension(dev_ext, config_info,
             (VIRTIO_PCI_VRING_ALIGN
                 + total_vring_size
                 + total_vq_size
                 + total_srb_ext_size
                 + total_event_node_size
                 + sizeof(void *) * max_queues
                 + sizeof(virtio_queue_t *) * max_queues));
    if (ring_va == (ULONG_PTR)NULL) {
        PRINTK(("%s %s: failed to get get_uncached_extension\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
        StorPortLogError(
            dev_ext, NULL, 0, 0, 0, SP_INTERNAL_ADAPTER_ERROR, __LINE__);
        return SP_RETURN_ERROR;
    }

    dev_ext->ring_va = ROUND_TO_PAGES(ring_va);
    dev_ext->queue_va = dev_ext->ring_va
        + total_vring_size;
#ifdef VIRTIO_SCSI_DRIVER
    dev_ext->tmf_cmd_srb.SrbExtension = (vscsi_srb_ext_t *)(dev_ext->ring_va
        + total_vring_size
        + total_vq_size);
    dev_ext->event_node = (virtio_scsi_event_node_t *)(dev_ext->ring_va
        + total_vring_size
        + total_vq_size
        + total_srb_ext_size);
#endif
    dev_ext->vr = (void **)(dev_ext->ring_va
        + total_vring_size
        + total_vq_size
        + total_srb_ext_size
        + total_event_node_size);
    dev_ext->vq = (virtio_queue_t **)(dev_ext->ring_va
        + total_vring_size
        + total_vq_size
        + total_srb_ext_size
        + total_event_node_size
        + sizeof(void *) * max_queues);
    RPRINTK(DPRTL_ON, ("%s %s:\n\tring_va %p %p, queue_va %p\n\tvr %p vq %p\n",
            VIRTIO_SP_DRIVER_NAME, __func__,
            ring_va,
            dev_ext->ring_va,
            dev_ext->queue_va,
            dev_ext->vr,
            dev_ext->vq));
    return STATUS_SUCCESS;
}

static NTSTATUS
virtio_sp_find_vq(virtio_sp_dev_ext_t *dev_ext)
{
#ifdef CAN_USE_MSI
    MESSAGE_INTERRUPT_INFORMATION msi_info;
#endif
    virtio_queue_t *vq;
    NTSTATUS status;
    ULONG rsize;
    ULONG qsize;
    ULONG roffset;
    ULONG qoffset;
    ULONG i;
    uint16_t num;
    uint16_t msix_vector;

    vq = NULL;

    dev_ext->msix_uses_one_vector = TRUE;
    dev_ext->msi_vectors = 0;
#ifdef CAN_USE_MSI
    while ((status = StorPortGetMSIInfo(dev_ext,
            dev_ext->msi_vectors, &msi_info)) == STOR_STATUS_SUCCESS) {
        RPRINTK(DPRTL_ON, ("\tMSI vector[%d]: %x\n",
            dev_ext->msi_vectors, msi_info.InterruptVector));
        RPRINTK(DPRTL_ON, ("\tMessageId = %x\n", msi_info.MessageId));
        RPRINTK(DPRTL_ON, ("\tMessageData = %x\n", msi_info.MessageData));
        RPRINTK(DPRTL_ON, ("\tInterruptVector = %x\n",
            msi_info.InterruptVector));
        RPRINTK(DPRTL_ON, ("\tInterruptLevel = %x\n",
            msi_info.InterruptLevel));
        RPRINTK(DPRTL_ON, ("\tInterruptMode = %s\n",
            msi_info.InterruptMode == LevelSensitive ?
            "Level" : "Latched"));
        RPRINTK(DPRTL_ON, ("\tMessageAddress = %p\n\n",
            msi_info.MessageAddress));
        dev_ext->msi_vectors++;
    }
    if (dev_ext->num_queues > 1
            && ((dev_ext->num_queues + VIRTIO_SP_MSI_NUM_QUEUE_ADJUST)
                > dev_ext->msi_vectors)) {
        dev_ext->num_queues = 1;
        RPRINTK(DPRTL_ON, ("\tfixup num_queues to 1\n"));
    }

    if (dev_ext->msi_vectors >=
            (dev_ext->num_queues + VIRTIO_SP_MSI_NUM_QUEUE_ADJUST)) {
        dev_ext->msix_uses_one_vector = FALSE;
        RPRINTK(DPRTL_ON, ("\tmsix_uses_one_vector false\n"));
    }

    PRINTK(("\tnum_queues %d\n", dev_ext->num_queues));
    PRINTK(("\tMSI enabled %d\n", dev_ext->msi_enabled));
    PRINTK(("\tMSI vectors %d\n", dev_ext->msi_vectors));
    PRINTK(("\tMSI uses one vector %d\n", dev_ext->msix_uses_one_vector));

    /* If we have multiple msi vectors, stup the configure vector. */
    if (dev_ext->msix_uses_one_vector == FALSE) {
        msix_vector = VIRTIO_DEVICE_SET_CONFIG_VECTOR(
            &dev_ext->vdev, VIRTIO_BLK_MSIX_CONFIG_VECTOR);
        if (msix_vector == VIRTIO_MSI_NO_VECTOR) {
            PRINTK(("\tMultiple vectors but no config vector\n"));
            return SP_RETURN_ERROR;
        }
    }
#endif

    roffset = 0;
    qoffset = 0;
    for (i = 0; i < dev_ext->num_queues + VIRTIO_SCSI_QUEUE_REQUEST; i++) {
        VIRTIO_DEVICE_QUERY_QUEUE_ALLOC(&dev_ext->vdev,
                                        i,
                                        &num,
                                        &rsize,
                                        &qsize);
        rsize = ROUND_TO_PAGES(rsize);
        qsize = ROUND_TO_CACHE_LINES(qsize);
        dev_ext->vr[i] = (void *)(dev_ext->ring_va + roffset);
        dev_ext->vq[i] = (virtio_queue_t *)(dev_ext->queue_va + qoffset);

        RPRINTK(DPRTL_ON, ("\tnum %d, roff %d, r_size %d, qoff %d, q_size %d\n",
                num, roffset, rsize, qoffset, qsize));
        RPRINTK(DPRTL_ON, ("\tvr[%d] %p, vq[%d] %p\n",
                i, dev_ext->vr[i], i, dev_ext->vq[i]));

        roffset += rsize;
        qoffset += qsize;

        RPRINTK(DPRTL_ON, ("\tCall VIRTIO_DEVICE_QUEUE_SETUP\n"));
        RPRINTK(DPRTL_ON, ("\t\tvq %p vq[%d] %p\n\t\tdev->vr %p dev->vq %p\n",
                           vq, i, dev_ext->vq[i], dev_ext->vr, dev_ext->vq));

        vq = VIRTIO_DEVICE_QUEUE_SETUP(&dev_ext->vdev,
                                       (uint16_t)i,
                                       dev_ext->vq[i],
                                       dev_ext->vr[i],
                                       num,
                                       (uint16_t)(dev_ext->msi_enabled ?
                                               dev_ext->msix_uses_one_vector ?
                                                  0 : i + 1
                                           : VIRTIO_MSI_NO_VECTOR));

        RPRINTK(DPRTL_ON, ("\tBack from Call to VIRTIO_DEVICE_QUEUE_SETUP\n"));
        RPRINTK(DPRTL_ON, ("\t\tvq %p vq[%d] %p\n\t\tdev->vr %p dev->vq %p\n",
                           vq, i, dev_ext->vq[i], dev_ext->vr, dev_ext->vq));
    }
    if (!vq) {
        StorPortLogError(
            dev_ext, NULL, 0, 0, 0, SP_INTERNAL_ADAPTER_ERROR, __LINE__);
        PRINTK(("%s %s: failed to find virtio queue\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
        return SP_RETURN_ERROR;
    }

    return STATUS_SUCCESS;
}

static void
virtio_sp_shutdown(virtio_sp_dev_ext_t *dev_ext)
{
    ULONG i;

    /*
     * Skip doing a vbif_do_flush(dev_ext, &srb);  A flush will cause a hang
     * waiting for the flush that will never complete.
     */

    PRINTK(("%s %s: doing a reset.\n", VIRTIO_SP_DRIVER_NAME, __func__));
    VIRTIO_DEVICE_RESET(&dev_ext->vdev);

    PRINTK(("%s %s: doing a reset features.\n",
            VIRTIO_SP_DRIVER_NAME, __func__));
    virtio_device_reset_features(&dev_ext->vdev);

    for (i = 0; i < dev_ext->num_queues + VIRTIO_SCSI_QUEUE_REQUEST; i++) {
        if (dev_ext->vq[i]) {
            /*
             * Memory for the disk's queue comes from the uncached extension and
             * isn't aloocated noramlly.  Therefore, don't set dev_ext->vq to
             * NULL.  dev_ext->vq needs to be valid so coming up from a
             * hibernate does not cause a pagefault.
             */
            PRINTK(("%s %s: deleting the queue %d.\n",
                    VIRTIO_SP_DRIVER_NAME, __func__, i));
            VIRTIO_DEVICE_QUEUE_DELETE(&dev_ext->vdev, dev_ext->vq[i], FALSE);

        }
    }
    PRINTK(("%s %s: done.\n", VIRTIO_SP_DRIVER_NAME, __func__));
}

static SCSI_ADAPTER_CONTROL_STATUS
virtio_sp_restart(virtio_sp_dev_ext_t *dev_ext)
{
    NTSTATUS nt_status;
    BOOLEAN ret;

    nt_status = virtio_device_init(&dev_ext->vdev,
                                   dev_ext->bar,
                                   dev_ext->pci_cfg_buf,
                                   VIRTIO_SP_DRIVER_NAME,
                                   dev_ext->msi_enabled);
    if (!NT_SUCCESS(nt_status)) {
        PRINTK(("%s %s: failed virtio_device_init %x\n",
                VIRTIO_SP_DRIVER_NAME, __func__, nt_status));
        return ScsiAdapterControlUnsuccessful;
    }

    dev_ext->features = VIRTIO_DEVICE_GET_FEATURES(&dev_ext->vdev);
    virtio_sp_enable_features(dev_ext);

    ret = sp_initialize(dev_ext);
    if (ret == FALSE) {
        PRINTK(("%s %s: failed sp_initialize\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
        return ScsiAdapterControlUnsuccessful;
    }
    return ScsiAdapterControlSuccess;
}

#ifdef DBG
static ULONG g_max_len;
static ULONG g_max_sgs;

void
virtio_sp_verify_sgl(virtio_sp_dev_ext_t *dev_ext,
                     PSCSI_REQUEST_BLOCK srb,
                     STOR_SCATTER_GATHER_LIST *sgl)
{
    ULONG i;

    if (dev_ext->indirect) {
        if (sgl->NumberOfElements > MAX_PHYS_SEGMENTS + 1) {
            PRINTK(("%s %s: sgl too big, el %d, len %d.\n",
                    VIRTIO_SP_DRIVER_NAME, __func__,
                    sgl->NumberOfElements, srb->DataTransferLength));
        }
    } else {
        if (sgl->NumberOfElements > VIRTIO_SP_MAX_SGL_ELEMENTS) {
            PRINTK(("%s %s: sgl too big, el %d, len %d.\n",
                    VIRTIO_SP_DRIVER_NAME, __func__,
                    sgl->NumberOfElements, srb->DataTransferLength));
        }
    }
    if (g_max_len < srb->DataTransferLength) {
        g_max_len = srb->DataTransferLength;
        PRINTK(("%s %s: new max_len %d, el %d.\n",
                VIRTIO_SP_DRIVER_NAME, __func__, g_max_len,
                sgl->NumberOfElements));
        if (g_max_len > 4096) {
            for (i = 0; i < sgl->NumberOfElements; i++) {
                DPRINTK(DPRTL_IO, ("\tsgl[%d] %llx (%x%x) len %d\n", i,
                    sgl->List[i].PhysicalAddress.QuadPart,
                    sgl->List[i].PhysicalAddress.u.HighPart,
                    sgl->List[i].PhysicalAddress.u.LowPart,
                    sgl->List[i].Length));
            }
        }
    }
    if (g_max_sgs < sgl->NumberOfElements) {
        g_max_sgs = sgl->NumberOfElements;
        PRINTK(("%s %s: new max_sgs %d, len %d.\n",
                VIRTIO_SP_DRIVER_NAME, __func__,
                sgl->NumberOfElements, srb->DataTransferLength));
    }

    if (sgl->NumberOfElements > 19) {
        CDPRINTK(DPRTL_COND, 0, 0, 1,
            ("%s %s: sgl el %d, len %d.\n", VIRTIO_SP_DRIVER_NAME, __func__,
            sgl->NumberOfElements, srb->DataTransferLength));
        for (i = 0; i < sgl->NumberOfElements; i++) {
            CDPRINTK(DPRTL_COND, 0, 0, 1, ("\tlen %d, %x, %x.\n",
                sgl->List[i].Length,
                sgl->List[i].PhysicalAddress.u.LowPart,
                sgl->List[i].PhysicalAddress.u.LowPart >> PAGE_SHIFT));
        }
    }
}
#endif

