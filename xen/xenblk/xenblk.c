/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2021 SUSE LLC
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

#include "xenblk.h"

#ifdef XENBLK_DBG_TRACK_SRBS
uint32_t srbs_seen;
uint32_t srbs_returned;
uint32_t io_srbs_seen;
uint32_t io_srbs_returned;
uint32_t sio_srbs_seen;
uint32_t sio_srbs_returned;
#endif

/* Miniport entry point decls. */

static NTSTATUS XenBlkFindAdapter(
    IN PVOID dev_ext,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCSTR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN Again);

static BOOLEAN XenBlkInitialize(XENBLK_DEVICE_EXTENSION *dev_ext);
static void XenBlkInit(XENBLK_DEVICE_EXTENSION *dev_ext);
static BOOLEAN XenBlkXenbusInit(XENBLK_DEVICE_EXTENSION *dev_ext);
static NTSTATUS XenBlkClaim(XENBLK_DEVICE_EXTENSION *dev_ext);
static void XenBlkInitHiberCrash(XENBLK_DEVICE_EXTENSION *dev_ext);

static BOOLEAN XenBlkStartIo(XENBLK_DEVICE_EXTENSION *dev_ext,
    PSCSI_REQUEST_BLOCK Srb);

static NTSTATUS XenBlkStartReadWrite(XENBLK_DEVICE_EXTENSION *dev_ext,
    SCSI_REQUEST_BLOCK *Srb);

static KDEFERRED_ROUTINE XenBlkRestartDpc;

#ifndef XENBLK_STORPORT
static KDEFERRED_ROUTINE XenBlkStartReadWriteDpc;
#endif

static BOOLEAN XenBlkBuildIo(XENBLK_DEVICE_EXTENSION *dev_ext,
    PSCSI_REQUEST_BLOCK Srb);

static BOOLEAN XenBlkResetBus(XENBLK_DEVICE_EXTENSION *dev_ext, ULONG PathId);

static BOOLEAN XenBlkInterruptPoll(XENBLK_DEVICE_EXTENSION *dev_ext);

static SCSI_ADAPTER_CONTROL_STATUS XenBlkAdapterControl (
    IN PVOID dev_ext,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters);

static void XenBlkRestartAdapter(IN PDEVICE_OBJECT DeviceObject,
    XENBLK_DEVICE_EXTENSION *dev_ext);

static void XenBlkResume(XENBLK_DEVICE_EXTENSION *dev_ext,
    uint32_t suspend_canceled);
static uint32_t XenBlkSuspend(XENBLK_DEVICE_EXTENSION *dev_ext,
    uint32_t reason);

static uint32_t
XenBlkIoctl(XENBLK_DEVICE_EXTENSION *dev_ext, pv_ioctl_t data);

static uint32_t g_interrupt_count;
uint32_t g_max_segs_per_req = XENBLK_DEFAULT_MAX_SEGS;


/*
 * Routine Description:
 *
 *  This routine initializes the XenBlk Storage class driver.
 *
 * Arguments:
 *
 *  DriverObject - Pointer to driver object created by system.
 *   RegistryPath - Pointer to the name of the services node for this driver.
 *
 * Return Value:
 *
 *   The function value is the final status from the initialization operation.
 *
 */
ULONG
XenDriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath)
{

    HW_INITIALIZATION_DATA hwInitializationData;
    NTSTATUS status;
    uint32_t i;
    uint8_t vendorId[4]   = {'5', '8', '5', '3'};
    uint8_t deviceId1[4]  = {'0', '0', '0', '1'};

    for (i = 0; i < sizeof(HW_INITIALIZATION_DATA); i++) {
        ((PCHAR)&hwInitializationData)[i] = 0;
    }

    hwInitializationData.HwInitializationDataSize =
        sizeof(HW_INITIALIZATION_DATA);

    /* Set entry points into the miniport. */
    hwInitializationData.HwInitialize = XenBlkInitialize;
    hwInitializationData.HwFindAdapter = XenBlkFindAdapter;
    hwInitializationData.HwResetBus = XenBlkResetBus;
    hwInitializationData.HwAdapterControl = XenBlkAdapterControl;

    /* Sizes of the structures that port needs to allocate. */
    hwInitializationData.DeviceExtensionSize = sizeof(XENBLK_DEVICE_EXTENSION);
    hwInitializationData.SrbExtensionSize = sizeof(xenblk_srb_extension);
    hwInitializationData.SpecificLuExtensionSize = 0;

    hwInitializationData.NeedPhysicalAddresses = TRUE;
    hwInitializationData.TaggedQueuing = TRUE;
    hwInitializationData.AutoRequestSense = TRUE;
    hwInitializationData.MultipleRequestPerLu = TRUE;
    hwInitializationData.ReceiveEvent = TRUE;

    hwInitializationData.HwInterrupt = XenBlkInterruptPoll;
    hwInitializationData.NumberOfAccessRanges = 1;
    hwInitializationData.AdapterInterfaceType = Internal;


#ifndef XENBLK_STORPORT
    hwInitializationData.HwStartIo = XenBlkBuildIo;
    hwInitializationData.MapBuffers = TRUE;
    status = ScsiPortInitialize(DriverObject,
        RegistryPath,
        &hwInitializationData,
        NULL);
#else
    hwInitializationData.HwStartIo = XenBlkStartIo;
    hwInitializationData.HwBuildIo = XenBlkBuildIo;

    /*
     * For StorPort MapBuffers is set to STOR_MAP_NON_READ_WRITE_BUFFERS so
     * that virtual addresses are only generated for non read/write requests.
     */
    hwInitializationData.MapBuffers = STOR_MAP_NON_READ_WRITE_BUFFERS;

    /* Call StorPort for each supported adapter. */
    status = StorPortInitialize(DriverObject,
        RegistryPath,
        &hwInitializationData,
        NULL);
#endif
    return status;
}

static NTSTATUS
XenBlkInitDevExt(
    XENBLK_DEVICE_EXTENSION *dev_ext,
    PPORT_CONFIGURATION_INFORMATION config_info,
    KIRQL irql)
{
#ifdef USE_INDIRECT_XENBUS_APIS
    xenbus_apis_t api = {0};
    xenbus_shared_info_t *xenbus_shared_info;
#endif
    NTSTATUS status = 0;
    PACCESS_RANGE accessRange = &((*(config_info->AccessRanges))[0]);

#ifndef XENBLK_STORPORT
    KeInitializeDpc(&dev_ext->rwdpc, XenBlkStartReadWriteDpc, dev_ext);
    KeInitializeSpinLock(&dev_ext->dev_lock);
#endif
    KeInitializeDpc(&dev_ext->restart_dpc, XenBlkRestartDpc, dev_ext);

    dev_ext->mem = NULL;
    dev_ext->info = NULL;

    dev_ext->qdepth = 0;
    if (irql <= DISPATCH_LEVEL) {
        if (irql == PASSIVE_LEVEL) {
            dev_ext->qdepth = PVCTRL_MAX_BLK_QDEPTH;
            dev_ext->op_mode = OP_MODE_NORMAL;
            sp_registry_read(dev_ext, PVCTRL_QDEPTH_STR, REG_DWORD,
                             &dev_ext->qdepth);
            sp_registry_read(dev_ext, PVCTRL_DBG_PRINT_MASK_STR, REG_DWORD,
                             &dbg_print_mask);
#ifdef DBG
            sp_registry_read(dev_ext, PVCTRL_CDBG_PRINT_LIMIT_STR, REG_DWORD,
                             &conditional_times_to_print_limit);
#endif
        } else {
            PRINTK(("Xenblk: setting up for hibernate\n"));
            dev_ext->op_mode = OP_MODE_HIBERNATE;
        }
    } else {
        PRINTK(("Xenblk: setting up for hibernate/crashdump\n"));
        dev_ext->op_mode = OP_MODE_CRASHDUMP;
    }

    dev_ext->mmio = (uint64_t)accessRange->RangeStart.QuadPart;
    dev_ext->mmio_len = accessRange->RangeLength;

    dev_ext->mem = xenblk_get_device_base(dev_ext,
        config_info->AdapterInterfaceType,
        config_info->SystemIoBusNumber,
        accessRange->RangeStart,
        accessRange->RangeLength,
        (BOOLEAN)!accessRange->RangeInMemory);

    RPRINTK(DPRTL_INIT,
            ("\tmmio = %llx, mem %p len = %x\n",
             dev_ext->mmio,
             dev_ext->mem,
             dev_ext->mmio_len));

#ifdef USE_INDIRECT_XENBUS_APIS
    if (dev_ext->mem == NULL) {
        PRINTK(("XenBlkInitDevExt mem == NULL\n"));
        return STATUS_UNSUCCESSFUL;
    }
    RPRINTK(DPRTL_INIT, ("\tgfdo %p\n",
         *(PDEVICE_OBJECT *)(((shared_info_t *)dev_ext->mem) + 1)));

    xenbus_shared_info = (xenbus_shared_info_t *)
        (((shared_info_t *)dev_ext->mem) + 1);

    xenbus_shared_info->xenbus_set_apis(&api);

    xenbus_fill_apis(&api);
    printk = xenbus_printk;
#endif

    dev_ext->state = STOPPED;

    XENBLK_ZERO_VALUE(dev_ext->alloc_cnt_i);
    XENBLK_ZERO_VALUE(dev_ext->alloc_cnt_s);
    XENBLK_ZERO_VALUE(dev_ext->alloc_cnt_v);

    XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, 0xffffffff);
    XENBLK_CLEAR_FLAG(dev_ext->cpu_locks, 0xffffffff);

    return STATUS_SUCCESS;
}

static NTSTATUS
XenBlkFindAdapter(
    IN PVOID dev_extt,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCSTR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION config_info,
    OUT PBOOLEAN Again)
{
    XENBLK_DEVICE_EXTENSION *dev_ext = (XENBLK_DEVICE_EXTENSION *)dev_extt;
    void *nc;
    NTSTATUS status = 0;
    KIRQL irql;
    uint32_t flags = 0;
    uint32_t i;
    uint32_t q_depth;

    if (config_info->NumberOfAccessRanges == 0) {
        PRINTK(("Find adapter start: No access ranges\n"));
        return SP_RETURN_NOT_FOUND;
    }

    irql = KeGetCurrentIrql();
    PRINTK(("Xenblk: Version %s.\n", VER_FILEVERSION_STR));
    if (irql >= CRASHDUMP_LEVEL) {
        PRINTK(("XenBlk XenBlkFindAdapter for hibernate/crashdump: Begin.\n"));
    }

    if (XenBlkInitDevExt(dev_ext, config_info, irql) != STATUS_SUCCESS) {
        return SP_RETURN_NOT_FOUND;
    }

    RPRINTK(DPRTL_INIT,
            ("XenBlk: XenBlkFindAdapter - IN %s, irql = %d, dev = %p\n",
             ArgumentString, irql, dev_ext));
    RPRINTK(DPRTL_INIT,
            ("  MTS = %ld, NPB = %ld, BA = %d, CD = %d\n",
             config_info->MaximumTransferLength,
             config_info->NumberOfPhysicalBreaks,
             config_info->BufferAccessScsiPortControlled,
             config_info->CachesData));
    RPRINTK(DPRTL_INIT,
            ("  AdptrInterfaceType = %d\n", config_info->AdapterInterfaceType));
    RPRINTK(DPRTL_INIT,
            ("  Dma32BitAddresses = %d\n", config_info->Dma32BitAddresses));
    RPRINTK(DPRTL_INIT,
            ("  Dma64BitAddresses = %d\n", config_info->Dma64BitAddresses));
    RPRINTK(DPRTL_INIT, ("  DemandMode = %d\n", config_info->DemandMode));

    xenbus_get_pvctrl_param(dev_ext->mem, PVCTRL_PARAM_MAX_DISKS,
        &dev_ext->max_targets);
    if (dev_ext->max_targets) {
        config_info->MaximumNumberOfTargets  = (UCHAR)dev_ext->max_targets;
    } else {
        dev_ext->max_targets = 1;
        config_info->MaximumNumberOfTargets  = 1;
    }
    xenbus_get_pvctrl_param(dev_ext->mem, PVCTRL_PARAM_FLAGS,
        &dev_ext->pvctrl_flags);

    xenbus_get_pvctrl_param(dev_ext->mem, PVCTRL_PARAM_MAX_SEGS_PER_REQ,
        &g_max_segs_per_req);

    XenBlkInit(dev_ext);

    if (dev_ext->info[0] != NULL) {
        config_info->MaximumTransferLength   =
            dev_ext->info[0]->max_segs_per_req * PAGE_SIZE;
        config_info->NumberOfPhysicalBreaks  =
            dev_ext->info[0]->max_segs_per_req;
    } else {
        /*
         * Must be during install.  Just do default.  It will get fixed
         * up on the next boot.
         */
        config_info->MaximumTransferLength   =
            XENBLK_MAX_SGL_ELEMENTS * PAGE_SIZE;
        config_info->NumberOfPhysicalBreaks  = XENBLK_MAX_SGL_ELEMENTS;
    }

    PRINTK(("  NumberOfPhysicalBreaks: %ld\n",
            config_info->NumberOfPhysicalBreaks));
    PRINTK(("  MaximumTransferLength: %ld\n",
            config_info->MaximumTransferLength));
    PRINTK(("  Control flags: 0x%x\n", dev_ext->pvctrl_flags));
    if (dev_ext->qdepth) {
        /* If just one controller, all infos will be the same. */
        /* If each has their own contrller, there will only be one info. */
        if (dev_ext->info != NULL && dev_ext->info[0] != NULL) {
            q_depth = RING_SIZE(&dev_ext->info[0]->ring) /
            ((XENBLK_MAX_SGL_ELEMENTS /
              BLKIF_MAX_SEGMENTS_PER_REQUEST) + 1) > PVCTRL_MAX_BLK_QDEPTH ?
                PVCTRL_MAX_BLK_QDEPTH :
                RING_SIZE(&dev_ext->info[0]->ring) /
                    ((XENBLK_MAX_SGL_ELEMENTS /
                      BLKIF_MAX_SEGMENTS_PER_REQUEST) + 1);
            if (dev_ext->qdepth > q_depth) {
                dev_ext->qdepth = q_depth;
            }
        }
    }
    PRINTK(("  Queue depth: %d\n", dev_ext->qdepth));

    config_info->MaximumNumberOfLogicalUnits = 1;
    config_info->NumberOfBuses          = 1;
    config_info->Master                 = TRUE;
    config_info->NeedPhysicalAddresses  = TRUE;
    config_info->TaggedQueuing          = TRUE;
    config_info->CachesData             = TRUE;
    config_info->ScatterGather          = TRUE;
    config_info->AlignmentMask          = 0x3;
    if (config_info->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED) {
        RPRINTK(DPRTL_INIT,
                ("  setting SCSI_DMA64_MINIPORT_SUPPORTED\n"));
        config_info->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;
    }
#ifndef XENBLK_STORPORT
    else {
        /* Dma32BitAddresses should only be set in the scsi port model. */
        config_info->Dma32BitAddresses  = TRUE;
        RPRINTK(DPRTL_INIT, ("  setting Dma32BitAddresses to TRUE\n")));
    }

    /*
     * InitiatorBusId[0] should only be set in the scsi port model.
     * If not set to 7, secondary disks don't show up.
     */
    config_info->InitiatorBusId[0]       = 7;
#endif
#ifdef XENBLK_STORPORT
    config_info->SynchronizationModel    = StorSynchronizeFullDuplex;
#endif

    RPRINTK(DPRTL_INIT,
        ("  AdapterInterfaceType %x, SystemIoBusNumber %x, AccessRanges %d\n",
        config_info->AdapterInterfaceType,
        config_info->SystemIoBusNumber,
        config_info->NumberOfAccessRanges));

    RPRINTK(DPRTL_INIT,
        ("  BusIntLevel 0x%x, BusInterVector 0x%x, InterruptMode %x\n",
        config_info->BusInterruptLevel,
        config_info->BusInterruptVector,
        config_info->InterruptMode));

    dev_ext->vector = config_info->BusInterruptVector;
    dev_ext->irql = (KIRQL)config_info->BusInterruptLevel;

    RPRINTK(DPRTL_INIT,
            ("  XenBlkFindAdapter - out: d = %x, c = %x, mtl = %x, npb = %x\n",
             dev_ext, config_info, config_info->MaximumTransferLength,
             config_info->NumberOfPhysicalBreaks));
    if (irql >= CRASHDUMP_LEVEL) {
        PRINTK(("XenBlk XenBlkFindAdapter for hibernate/crashdump: End.\n"));
    }
#ifdef XENBLK_DBG_TRACK_SRBS
    srbs_seen = 0;
    srbs_returned = 0;
    io_srbs_seen = 0;
    io_srbs_returned = 0;
    sio_srbs_seen = 0;
    sio_srbs_returned = 0;
#endif

    return SP_RETURN_FOUND;
}

static BOOLEAN
XenBlkInitialize(XENBLK_DEVICE_EXTENSION *dev_ext)
{
    uint32_t i;

    if (dev_ext->op_mode != OP_MODE_NORMAL) {
        PRINTK(("XenBlk: XenBlkInitialize for hibernate/crashdump: Begin\n"));
    }
    XENBLK_SET_FLAG(dev_ext->xenblk_locks, (BLK_IZE_L | BLK_INT_L));
    XENBLK_SET_FLAG(dev_ext->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
    RPRINTK(DPRTL_INIT,
            ("XenBlk: XenBlkInitialize - IN irql = %d, dev = %p, op_mode %x\n",
             KeGetCurrentIrql(), dev_ext, dev_ext->op_mode));

    if (dev_ext->state == REMOVED) {
        for (i = 0; i < dev_ext->max_targets; i++) {
            if (dev_ext->info[i]) {
                unmask_evtchn(dev_ext->info[i]->evtchn);
            }
        }
        dev_ext->state = WORKING;
        RPRINTK(DPRTL_INIT,
                ("XenBlkInitialize returning TRUE: in REMOVED state.\n"));
        XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_IZE_L | BLK_INT_L));
        XENBLK_CLEAR_FLAG(dev_ext->cpu_locks,
            (1 << KeGetCurrentProcessorNumber()));
        return TRUE;
    }

    XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_IZE_L | BLK_INT_L));
    XENBLK_CLEAR_FLAG(dev_ext->cpu_locks, (1 << KeGetCurrentProcessorNumber()));

    if (dev_ext->op_mode != OP_MODE_NORMAL) {
        PRINTK(("XenBlk XenBlkInitialize for hibernate/crashdump: End.\n"));
    }
    RPRINTK(DPRTL_INIT, ("  XenBlkInitialize - OUT\n"));
    return TRUE;
}

static void
XenBlkInit(XENBLK_DEVICE_EXTENSION *dev_ext)
{
    xenbus_pv_port_options_t options;
    xenbus_release_device_t release_data;
    uint32_t devices_to_probe;
    uint32_t i;

    RPRINTK(DPRTL_INIT,
            ("XenBlk: XenBlkInit - IN dev %p, sizeof(info) %d, irql = %d\n",
             dev_ext, sizeof(struct blkfront_info), KeGetCurrentIrql(),
             KeGetCurrentProcessorNumber()));

    if (dev_ext->state == WORKING) {
        RPRINTK(DPRTL_INIT, ("  XenBlkInit already initialized %p\n", dev_ext));
        return;
    }

    if (!XenBlkXenbusInit(dev_ext)) {
        return;
    }

    RPRINTK(DPRTL_INIT,
            ("XenBlk: XenBlkXenbusInit - xenbus_register_xenblk\n"));
    if (xenbus_register_xenblk(dev_ext, dev_ext->op_mode, &dev_ext->info)
            == STATUS_SUCCESS) {
        if (dev_ext->info[0] != NULL) {
            RPRINTK(DPRTL_INIT,
                    ("XenBlk: XenBlkInit - info[0] = %p\n",
                     dev_ext->info[0]));
            /* Replace the original dev_ext with the hibernate dev_ext. */
            dev_ext->info[0]->xbdev = dev_ext;
        }
    } else {
        PRINTK(("XenBlkInit: xenbus_register_xenblk failed\n"));
        dev_ext->state = WORKING;
        return;
    }

    /*
     * When coming up from hibernate, we need to do the claim since
     * we disconnected form the backend.
     */
    if (dev_ext->op_mode == OP_MODE_NORMAL
            || dev_ext->op_mode == OP_MODE_HIBERNATE) {
        RPRINTK(DPRTL_INIT, ("XenBlk: XenBlkInit - XenBlkClaim\n"));
        XenBlkClaim(dev_ext);
        dev_ext->state = WORKING;
        xenblk_resume(dev_ext);
    } else {
        XenBlkInitHiberCrash(dev_ext);
    }

    RPRINTK(DPRTL_INIT, ("XenBlkInit - OUT irql %d, cpu %x\n",
                         KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
}

static BOOLEAN
XenBlkXenbusInit(XENBLK_DEVICE_EXTENSION *dev_ext)
{
    RPRINTK(DPRTL_INIT,
            ("XenBlk: XenBlkXenbusInit - op_mode %x, state %x\n",
             dev_ext->op_mode, dev_ext->state));

    /*
     * Need to init xenbus if xenblk has the device or we are doing
     * a crashdump or hybernate.  If xenblk has the the device mem
     * will contain a value.  If xenbus has the device it will be null.
     */
    if (dev_ext->mem != NULL
            || dev_ext->op_mode == OP_MODE_HIBERNATE
            || dev_ext->op_mode == OP_MODE_CRASHDUMP) {
        /*
         * When restarting from hibernate etc. we always need to
         * init the shared info in OP_MODE_NORMAL.
         * Xenbus has already done the shared init when it has the device
         */
        if (dev_ext->op_mode == OP_MODE_RESTARTING) {
            dev_ext->op_mode = OP_MODE_NORMAL;
        }

        if (xenbus_xen_shared_init(dev_ext->mmio, dev_ext->mem,
                dev_ext->mmio_len, dev_ext->vector, dev_ext->op_mode)
            != STATUS_SUCCESS) {
            PRINTK(("XenBlkXenbusInit: failed to initialize shared info.\n"));
            dev_ext->mem = NULL;
            dev_ext->state = WORKING;
            dev_ext->op_mode = OP_MODE_SHUTTING_DOWN;
            return FALSE;
        }

        /* Shared init is done.  Can safely use the backend. */
        dev_ext->state = REGISTERING;
    }

    if (dev_ext->op_mode == OP_MODE_RESTARTING) {
        dev_ext->op_mode = OP_MODE_NORMAL;
    }
    RPRINTK(DPRTL_INIT, ("XenBlk: XenBlkXenbusInit - out\n"));
    return TRUE;
}

static NTSTATUS
XenBlkClaim(XENBLK_DEVICE_EXTENSION *dev_ext)
{
    struct blkfront_info *info;
    NTSTATUS status;
    uint32_t i;

    /*
     * The info array of pointers comes form xenbus and all pointers
     * will be null to start with but will be filled out already
     * when hibernating.
     */
    RPRINTK(DPRTL_INIT, ("Xenblk: XenBlkClaim.\n"));
    status = STATUS_UNSUCCESSFUL;
    for (i = 0; i < dev_ext->max_targets; i++) {
        if (dev_ext->info[i]) {
            /* info already exists, no need to try to claim it again. */
            RPRINTK(DPRTL_TRC, ("Xenblk: XenBlkClaim [%d] exist %p.\n",
                                i, dev_ext->info[i]));
            continue;
        }

        /* Check if we would succeed in claiming the device. */
        RPRINTK(DPRTL_INIT,
                ("Xenblk: XenBlkClaim - pre xenbus_claim_device.\n"));
        status = xenbus_claim_device(NULL, dev_ext, vbd, disk,
            XenBlkIoctl, XenBlkIoctl);
        if (status == STATUS_NO_MORE_ENTRIES
                || status == STATUS_RESOURCE_IN_USE) {
            /*
             * There are no more devices to claim or we are still installing
             * so return success.
             */
            RPRINTK(DPRTL_INIT,
                    ("Xenblk: XenBlkClaim - returned %x.\n", status));
            status = STATUS_SUCCESS;
            break;
        }
        if (status != STATUS_SUCCESS) {
            PRINTK(("Xenblk: XenBlkClaim - failed %x.\n", status));
            break;
        }
        RPRINTK(DPRTL_INIT, ("Xenblk: XenBlkClaim - allocate info %d.\n",
                             sizeof(struct blkfront_info)));
        info = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                             sizeof(struct blkfront_info),
                             XENBLK_TAG_GENERAL);
        if (info == NULL) {
            PRINTK(("  failed to alloc info.\n"));
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RPRINTK(DPRTL_INIT,
                ("Xenblk: XenBlkClaim - allocate was successful.\n"));
        XENBLK_INC(dev_ext->alloc_cnt_i);
        memset(info, 0, sizeof(struct blkfront_info));
        info->xbdev = dev_ext;

        /* Use info as the identifier to xenbus. */
        RPRINTK(DPRTL_INIT,
                ("Xenblk: XenBlkClaim - xenbus_claim_device[%u].\n", i));
        status = xenbus_claim_device(info, dev_ext, vbd, disk,
            XenBlkIoctl, XenBlkIoctl);
        if (status == STATUS_UNSUCCESSFUL || status == STATUS_NO_MORE_ENTRIES) {
            PRINTK(("  failed to claim device: %x.\n", status));
            ExFreePool(info);
            XENBLK_DEC(dev_ext->alloc_cnt_i);
            break;
        }

        /* Now do the Xen initialization. */
        RPRINTK(DPRTL_INIT,
                ("Xenblk: XenBlkClaim - blkfront_probe, ints %d.\n",
                 g_interrupt_count));
        status = blkfront_probe(info);
        if (status != STATUS_SUCCESS) {
            PRINTK(("  blkfront_probe failed: %x\n", status));
            /*
             * We cannot release the device because the next time through
             * the loop we would just try to claim it again.
             */
            if (status != STATUS_NO_SUCH_DEVICE) {
                ExFreePool(info);
                XENBLK_DEC(dev_ext->alloc_cnt_i);
            }
            continue;
        }
        RPRINTK(DPRTL_INIT,
                ("Xenblk: XenBlkClaim - blkfront_probe complete.\n"));
#ifdef XENBLK_STORPORT
        StorPortInitializeDpc(dev_ext,
            &info->dpc,
            (PHW_DPC_ROUTINE)blkif_int_dpc);
#endif
        dev_ext->info[i] = info;
        PRINTK(("Xenblk: initialization complete for %s.\n", info->nodename));
    }
    return status;
}

static void
XenBlkInitHiberCrashInfo(XENBLK_DEVICE_EXTENSION *dev_ext,
    struct blkfront_info *info)
{
    uint32_t j;

    /*
     * The info array of pointers comes form xenbus and all pointers
     * will be null to start with but will be filled out already
     * when hibernating.
     */
    if (info != NULL) {
        RPRINTK(DPRTL_INIT, ("\thibernate or crash dump\n");
        xenblk_print_save_req(&info->xbdev->req);
        mask_evtchn(info->evtchn));

        /* Clear out any grants that may still be around. */
        RPRINTK(DPRTL_INIT, ("\tdoing shadow completion\n"));
        for (j = 0; j < BLK_RING_SIZE; j++) {
            info->shadow[j].req.nr_segments = 0;
        }

        /*
         * In hibernate mode we get a new dev_ext, but we are using
         * the original info.  Replace the original dev_ext in info
         * with the one used to hibernate.
         */
        if (info->xbdev) {
            RPRINTK(DPRTL_INIT, ("\tdev %p, xbdev: %p, op %x, xop %x\n",
                                 dev_ext, info->xbdev,
                                 dev_ext->op_mode, info->xbdev->op_mode));
            info->xbdev->state = REMOVED;
            info->xbdev->op_mode = dev_ext->op_mode;
        }

        /* Since we are hibernating and didn't go through probe. */
    }
}

static void
XenBlkInitHiberCrash(XENBLK_DEVICE_EXTENSION *dev_ext)
{
    struct blkfront_info *info;
    uint32_t i, j;
    KIRQL irql;

    RPRINTK(DPRTL_INIT, ("XenBlk XenBlkInitHiberCrash: IN.\n"));
    irql = KeGetCurrentIrql();
    if (irql >= CRASHDUMP_LEVEL) {
        PRINTK(("XenBlk XenBlkInitHiberCrash: Begin.\n"));
    }

    RPRINTK(DPRTL_INIT,
            ("XenBlk XenBlkInitHiberCrash: info[0] %p, max_t %d.\n",
             dev_ext->info[0], dev_ext->max_targets));
    i = 0;
    do {
        info = xenbus_enum_xenblk_info(&i);
        if (info) {
            XenBlkInitHiberCrashInfo(dev_ext, info);
        }
    } while (info);
    dev_ext->info[0]->xbdev = dev_ext;
    xenblk_resume(dev_ext);
    dev_ext->state = WORKING;
    if (irql >= CRASHDUMP_LEVEL) {
        PRINTK(("XenBlk XenBlkInitHiberCrash: End.\n"));
    }
    RPRINTK(DPRTL_INIT, ("XenBlk XenBlkInitHiberCrash: OUT.\n"));
}

static UCHAR
xenblk_mode_sense(struct blkfront_info *info, SCSI_REQUEST_BLOCK *srb)
{
    PCDB cdb;
    PMODE_PARAMETER_HEADER header;
    PMODE_CACHING_PAGE cache_page;
    PMODE_PARAMETER_BLOCK param_block;
    ULONG len;

    cdb = (PCDB)&srb->Cdb[0];
    len = srb->DataTransferLength;
    if ((cdb->MODE_SENSE.PageCode == MODE_PAGE_CACHING)
            || (cdb->MODE_SENSE.PageCode == MODE_SENSE_RETURN_ALL)
            || (cdb->MODE_SENSE.PageCode == MODE_PAGE_VENDOR_SPECIFIC)) {
        if (sizeof(MODE_PARAMETER_HEADER) > len) {
            return SRB_STATUS_ERROR;
        }


        header = srb->DataBuffer;
        memset(header, 0, sizeof(MODE_PARAMETER_HEADER));
        header->DeviceSpecificParameter = MODE_DSP_FUA_SUPPORTED;
        if (info->flags & BLKIF_READ_ONLY_F) {
            header->DeviceSpecificParameter |= MODE_DSP_WRITE_PROTECT;
        }

        len -= sizeof(MODE_PARAMETER_HEADER);

        if (cdb->MODE_SENSE.PageCode == MODE_PAGE_VENDOR_SPECIFIC) {
            if (len >= sizeof(MODE_PARAMETER_BLOCK)) {
                header->BlockDescriptorLength = sizeof(MODE_PARAMETER_BLOCK);
                param_block = (PMODE_PARAMETER_BLOCK)header;
                param_block = (PMODE_PARAMETER_BLOCK)(
                    (unsigned char *)(param_block)
                    + (ULONG)sizeof(MODE_PARAMETER_HEADER));
                memset(param_block, 0, sizeof(MODE_PARAMETER_HEADER));
                srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER) +
                    sizeof(MODE_PARAMETER_BLOCK);
            } else {
                srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER);
            }
        } else {
            if (len >= sizeof(MODE_CACHING_PAGE)) {
                header->ModeDataLength = sizeof(MODE_CACHING_PAGE) + 3;
                cache_page = (PMODE_CACHING_PAGE)header;
                cache_page = (PMODE_CACHING_PAGE)((unsigned char *)(cache_page)
                    + (ULONG)sizeof(MODE_PARAMETER_HEADER));
                memset(cache_page, 0, sizeof(MODE_CACHING_PAGE));
                cache_page->PageCode = MODE_PAGE_CACHING;
                cache_page->PageLength = 10;
                cache_page->WriteCacheEnable = 1;
                srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER) +
                    sizeof(MODE_CACHING_PAGE);

            } else {
               srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER);
            }

        }
        return SRB_STATUS_SUCCESS;
    }
    return SRB_STATUS_INVALID_REQUEST;
}


static BOOLEAN
XenBlkStartIo(XENBLK_DEVICE_EXTENSION *dev_ext, PSCSI_REQUEST_BLOCK Srb)
{
    struct blkfront_info *info;
    xenblk_srb_extension *srb_ext;
    XENBLK_LOCK_HANDLE lh;
    uint32_t i;

    /* StorPort already has the lock.  Just need it for scsiport. */
    XENBLK_INC_SRB(srbs_seen);
    srb_ext = (xenblk_srb_extension *)Srb->SrbExtension;
    XENBLK_SET_VALUE(srb_ext->dev_ext, dev_ext);
    XENBLK_INC_SRB(sio_srbs_seen);

    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("XenBlkStartIo i %d c %d l %x: should dev %p srb %p - IN\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
        dev_ext->xenblk_locks, dev_ext, Srb));

    scsiport_acquire_spinlock(&dev_ext->dev_lock, &lh);
    XENBLK_SET_FLAG(dev_ext->xenblk_locks, (BLK_STI_L | BLK_SIO_L));

    CDPRINTK(DPRTL_COND, 1, 0, 1,
        ("   XenBlkStartIo dev %p, irql = %d, s = %p, f = %x, cbd %x, c = %x\n",
        dev_ext, KeGetCurrentIrql(), Srb, Srb->Function, Srb->Cdb[0],
        KeGetCurrentProcessorNumber()));

    /* Check that we are in a working state before accessing info. */
    if (dev_ext->state != WORKING && dev_ext->state != STOPPED) {
        PRINTK(("XenBlkStartIo: dev %p st %x info %p i %d, t %d, f %x cb %x\n",
            dev_ext, dev_ext->state, dev_ext->info, KeGetCurrentIrql(),
            Srb->TargetId, Srb->Function, Srb->Cdb[0]));
        Srb->SrbStatus = SRB_STATUS_BUSY;
        XENBLK_INC_SRB(srbs_returned);
        XENBLK_INC_SRB(sio_srbs_returned);
        xenblk_request_complete(RequestComplete, dev_ext, Srb);
        xenblk_next_request(NextRequest, dev_ext);
        XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_STI_L | BLK_SIO_L));
        xenblk_pause(dev_ext, 1);
        scsiport_release_spinlock(&dev_ext->dev_lock, lh);
        return TRUE;
    }

    info = dev_ext->info[Srb->TargetId];
    if (info == NULL || info->connected != BLKIF_STATE_CONNECTED) {
        RPRINTK(DPRTL_ON,
                ("XenBlkStartIo irql %d, dev %p, tid = %d, f = %x cdb = %x\n",
                 KeGetCurrentIrql(), dev_ext, Srb->TargetId,
                 Srb->Function, Srb->Cdb[0]));

        if (info == NULL && dev_ext->state == WORKING) {
            Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
            RPRINTK(DPRTL_ON, ("\tReturning SRB_STATUS_NO_DEVICE\n"));
        } else {
            Srb->SrbStatus = SRB_STATUS_BUSY;
            RPRINTK(DPRTL_ON,
                    ("\tBlk not ready yet, returning SRB_STATUS_BUSY\n"));
        }

        XENBLK_INC_SRB(srbs_returned);
        XENBLK_INC_SRB(sio_srbs_returned);
        xenblk_request_complete(RequestComplete, dev_ext, Srb);
        xenblk_next_request(NextRequest, dev_ext);
        if (Srb->SrbStatus == SRB_STATUS_BUSY) {
            xenblk_pause(dev_ext, 1);
        }
        XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_STI_L | BLK_SIO_L));
        scsiport_release_spinlock(&dev_ext->dev_lock, lh);
        return TRUE;
    }

    if (Srb->Lun > 0) {
        RPRINTK(DPRTL_ON, ("  TargetId = %d, Lun = %d, func = %d, sf = %x.\n",
                           Srb->TargetId, Srb->Length, Srb->Function,
                           Srb->Cdb[0]));
        Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        XENBLK_INC_SRB(srbs_returned);
        XENBLK_INC_SRB(sio_srbs_returned);
        xenblk_request_complete(RequestComplete, dev_ext, Srb);
        xenblk_next_request(NextRequest, dev_ext);
        XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_STI_L | BLK_SIO_L));
        scsiport_release_spinlock(&dev_ext->dev_lock, lh);
        return TRUE;
    }
    XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_STI_L | BLK_SIO_L));
    scsiport_release_spinlock(&dev_ext->dev_lock, lh);

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI: {
        switch (Srb->Cdb[0]) {
        case SCSIOP_MEDIUM_REMOVAL:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_MEDIUM_REMOVAL\n", Srb->TargetId));
            /* BsaPowerManagement 6.4.6.13 */
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;
        case SCSIOP_REQUEST_SENSE:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_REQUEST_SENSE\n", Srb->TargetId));
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;

        case SCSIOP_MODE_SENSE:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_MODE_SENSE\n", Srb->TargetId));
            Srb->SrbStatus = xenblk_mode_sense(info, Srb);
            break;

        case SCSIOP_READ_CAPACITY: {
            uint32_t last_sector;

            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_READ_CAPACITY\n", Srb->TargetId));
            REVERSE_BYTES(
                &((PREAD_CAPACITY_DATA)Srb->DataBuffer)->BytesPerBlock,
                &info->sector_size);

            if (info->sectors > 0xffffffff) {
                RPRINTK(DPRTL_TRC,
                        ("%x: Disk > 2TB: %x%08x, returning 0xffffffff.\n",
                         Srb->TargetId,
                         (uint32_t)(info->sectors >> 32),
                         (uint32_t)info->sectors));
                last_sector = 0xffffffff;
            } else {
                last_sector = (uint32_t)(info->sectors - 1);
            }
            REVERSE_BYTES(
                &((PREAD_CAPACITY_DATA)
                    Srb->DataBuffer)->LogicalBlockAddress,
                &last_sector);

            RPRINTK(DPRTL_ON,
                    ("%x: sectors 0x%llx sector-sz %u last sector 0x%x\n",
                     Srb->TargetId,
                     info->sectors,
                     info->sector_size,
                     last_sector));

            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;
        }

        case SCSIOP_READ_CAPACITY16: {
            uint64_t last_sector;
            PCDB cdb;
            PSENSE_DATA senseBuffer;

            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_READ_CAPACITY16\n", Srb->TargetId));

            cdb = (PCDB)&Srb->Cdb[0];
            if (cdb->READ_CAPACITY16.PMI == 0 &&
                    *(uint64_t *)&cdb->READ_CAPACITY16.LogicalBlock[0]) {
                PRINTK(("XenBlk: %x PMI 0, logical block non-zero.\n",
                        Srb->TargetId));
                Srb->ScsiStatus = SCSISTAT_CHECK_CONDITION;
                senseBuffer = (PSENSE_DATA) Srb->SenseInfoBuffer;
                senseBuffer->SenseKey = SCSI_SENSE_ILLEGAL_REQUEST;
                senseBuffer->AdditionalSenseCode = SCSI_ADSENSE_INVALID_CDB;
                Srb->SrbStatus = SRB_STATUS_SUCCESS;
                break;
            }
            REVERSE_BYTES(
                &((PREAD_CAPACITY_DATA_EX)
                    Srb->DataBuffer)->BytesPerBlock,
                &info->sector_size);

            last_sector = info->sectors - 1;
            REVERSE_BYTES_QUAD(
                &((PREAD_CAPACITY_DATA_EX)
                    Srb->DataBuffer)->LogicalBlockAddress,
                &last_sector);

            RPRINTK(DPRTL_ON,
                    ("16 %x: sectors 0x%llx sector-sz %u last sector 0x%llx\n",
                     Srb->TargetId,
                     info->sectors,
                     info->sector_size,
                     last_sector));

            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;
        }

        case SCSIOP_READ:
        case SCSIOP_WRITE:
        case SCSIOP_READ16:
        case SCSIOP_WRITE16: {
            NTSTATUS status;

            DPRINTK(DPRTL_TRC,
                    ("%x: SCSIOP_WRITE SCSIOP_READ %x, dev=%x,srb=%x\n",
                     Srb->TargetId, Srb->Cdb[0], dev_ext, Srb));
            CDPRINTK(DPRTL_COND, 0, 0, 1,
                    ("XenBlkStartIo id %d i %d c %d: dev %p s %x srb %p do\n",
                    Srb->TargetId,
                    KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
                    dev_ext, dev_ext->state, Srb));

            status = do_blkif_request(info, Srb);
            if (status  == STATUS_SUCCESS) {
                xenblk_next_request(NextRequest, dev_ext);
                CDPRINTK(DPRTL_COND, 0, 0, 1,
                           ("%x: XBStrtIo: do success OUT cpu=%x.\n",
                           Srb->TargetId,
                           KeGetCurrentProcessorNumber()));
                DPRINTK(DPRTL_TRC,
                        ("%x: SCSIOP_WRITE SCSIOP_READ returning %x\n",
                         Srb->TargetId, status));
                DPRINTK(DPRTL_TRC,
                        ("    cbd %x, dev = %p, srb = %p\n",
                         Srb->Cdb[0], dev_ext, Srb));
                XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks,
                                  (BLK_STI_L | BLK_SIO_L));
                return TRUE;
            } else {
                Srb->SrbStatus = SRB_STATUS_BUSY;
                StorPortBusy(dev_ext, 2);
                RPRINTK(DPRTL_UNEXPD, ("Xenblk %x: SRB_STATUS_BUSY\n",
                                       Srb->TargetId));
            }
            DPRINTK(DPRTL_TRC, ("    SCSIOP_WRITE SCSIOP_READ out\n"));
            break;
        }

        case SCSIOP_INQUIRY: {
            PINQUIRYDATA inquiryData;
            uint8_t *rbuf;

            RPRINTK(DPRTL_ON,
                ("%x: SCSIOP_INQUIRY DTlen = 0x%x, iqd sisz = 0x%x, srb = %x\n",
                Srb->TargetId,
                Srb->DataTransferLength, sizeof(INQUIRYDATA), Srb));
            RPRINTK(DPRTL_ON,
                    ("    Cdb[] 0 %x, 1 %x, 2 %x, 3 %x, 4 %x\n",
                     Srb->Cdb[0], Srb->Cdb[1], Srb->Cdb[2],
                     Srb->Cdb[3], Srb->Cdb[4]));

            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            if (Srb->Cdb[1] == 0) {
                inquiryData = Srb->DataBuffer;
                memset(inquiryData, 0, Srb->DataTransferLength);

                inquiryData->DeviceType = DIRECT_ACCESS_DEVICE;
                inquiryData->DeviceTypeQualifier = DEVICE_CONNECTED;
                inquiryData->RemovableMedia = 0;
                if (dev_ext->qdepth) {
                    inquiryData->CommandQueue = 1;
                }
                inquiryData->Versions = 4;
                inquiryData->ResponseDataFormat = 2;
                inquiryData->HiSupport = 1;
                inquiryData->Wide32Bit = 1;

                for (i = 0; i < 8; i++) {
                    inquiryData->VendorId[i] = ' ';
                }

                inquiryData->VendorId[0] = 'S';
                inquiryData->VendorId[1] = 'U';
                inquiryData->VendorId[2] = 'S';
                inquiryData->VendorId[3] = 'E';

                for (i = 0; i < 16; i++) {
                    inquiryData->ProductId[i] = ' ';
                }

                inquiryData->ProductId[0] = 'X';
                inquiryData->ProductId[1] = 'e';
                inquiryData->ProductId[2] = 'n';
                inquiryData->ProductId[3] = ' ';
                inquiryData->ProductId[4] = 'B';
                inquiryData->ProductId[5] = 'l';
                inquiryData->ProductId[6] = 'o';
                inquiryData->ProductId[7] = 'c';
                inquiryData->ProductId[8] = 'k';

                inquiryData->ProductRevisionLevel[0] = '0';
                inquiryData->ProductRevisionLevel[1] = '.';
                inquiryData->ProductRevisionLevel[2] = '0';
                inquiryData->ProductRevisionLevel[3] = '1';

                RPRINTK(DPRTL_ON, ("    VendorId _"));
                for (i = 0; i < 8; i++) {
                    RPRINTK(DPRTL_ON, ("%c", inquiryData->VendorId[i]));
                }
                RPRINTK(DPRTL_ON, ("_\n"));

                RPRINTK(DPRTL_ON, ("    ProductId _"));
                for (i = 0; i < 16; i++) {
                    RPRINTK(DPRTL_ON, ("%c", inquiryData->ProductId[i]));
                }
                RPRINTK(DPRTL_ON, ("_\n"));

                RPRINTK(DPRTL_ON, ("    ProductRevisionLevel _"));
                for (i = 0; i < 4; i++) {
                    RPRINTK(DPRTL_ON, ("%c",
                                       inquiryData->ProductRevisionLevel[i]));
                }
                RPRINTK(DPRTL_ON, ("_\n"));
            } else if (Srb->Cdb[1] & 1) {
                /* The EVPD bit is set.  Check which page to return. */
                switch (Srb->Cdb[2]) {
                case VPD_SUPPORTED_PAGES: {
                    PVPD_SUPPORTED_PAGES_PAGE rbuf;

                    rbuf = (PVPD_SUPPORTED_PAGES_PAGE)Srb->DataBuffer;

                    RPRINTK(DPRTL_ON, ("%x: SCSIOP_INQUIRY page 0.\n",
                                       Srb->TargetId));
                    rbuf->DeviceType = DIRECT_ACCESS_DEVICE;
                    rbuf->DeviceTypeQualifier = DEVICE_CONNECTED;
                    rbuf->PageCode = VPD_SUPPORTED_PAGES;
                    /* rbuf->Reserved; */
                    rbuf->PageLength = 3;
                    rbuf->SupportedPageList[0] = VPD_SUPPORTED_PAGES;
                    rbuf->SupportedPageList[1] = VPD_SERIAL_NUMBER;
                    rbuf->SupportedPageList[2] = VPD_DEVICE_IDENTIFIERS;
                    break;
                }
                case VPD_DEVICE_IDENTIFIERS: {
                    PVPD_IDENTIFICATION_PAGE rbuf;

                    rbuf = (PVPD_IDENTIFICATION_PAGE)Srb->DataBuffer;

                    RPRINTK(DPRTL_ON, ("%x: SCSIOP_INQUIRY page 83, size %d.\n",
                                       Srb->TargetId,
                                       sizeof(VPD_IDENTIFICATION_PAGE)));
                    RPRINTK(DPRTL_ON, ("    Id: %s, len %d\n",
                                       XENBLK_DESIGNATOR_STR,
                                       strlen(XENBLK_DESIGNATOR_STR)));

                    rbuf->DeviceType = DIRECT_ACCESS_DEVICE;
                    rbuf->DeviceTypeQualifier = DEVICE_CONNECTED;
                    rbuf->PageCode = VPD_DEVICE_IDENTIFIERS;
                    /* rbuf->Reserved; */
                    rbuf->PageLength = sizeof(VPD_IDENTIFICATION_PAGE) +
                        (uint8_t)strlen(XENBLK_DESIGNATOR_STR);
                    rbuf->Descriptors[0] = VpdCodeSetAscii;
                    rbuf->Descriptors[1] = VpdIdentifierTypeSCSINameString;
                    /* rbuf->Descriptors[2] = reserved; */
                    rbuf->Descriptors[3] =
                        (uint8_t)strlen(XENBLK_DESIGNATOR_STR);

                    memcpy(&rbuf->Descriptors[4],
                           XENBLK_DESIGNATOR_STR,
                           strlen(XENBLK_DESIGNATOR_STR));
                    break;
                }
                case VPD_SERIAL_NUMBER: {
                    PVPD_SERIAL_NUMBER_PAGE rbuf;

                    rbuf = (PVPD_SERIAL_NUMBER_PAGE)
                    Srb->DataBuffer;

                    rbuf->DeviceType = DIRECT_ACCESS_DEVICE;
                    rbuf->DeviceTypeQualifier = DEVICE_CONNECTED;
                    rbuf->PageCode = VPD_SERIAL_NUMBER;
                    /* rbuf->Reserved; */
                    rbuf->PageLength = 1;
                    rbuf->SerialNumber[0] = '0';
                    RPRINTK(DPRTL_ON, ("%x: SCSIOP_INQUIRY page 80, SN _%c_\n",
                                       Srb->TargetId,
                                       rbuf->SerialNumber[0]));
                    break;
                }
                default:
                    RPRINTK(DPRTL_ON, ("Invalid Inquery Page Request\n"));
                    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
                    break;
                }
            } else {
                RPRINTK(DPRTL_ON, ("Invalid Inquery Request\n"));
                Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            }

            if (dev_ext->qdepth) {
                i = xenblk_set_queue_depth(
                    dev_ext,
                    Srb,
                    dev_ext->qdepth);
                RPRINTK(DPRTL_ON,
                        ("Xenblk [%d]: Queue depth set to %d, status %x\n",
                        Srb->TargetId, dev_ext->qdepth, i));
            }

            break;
        }

        case SCSIOP_TEST_UNIT_READY:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_TEST_UNIT_READY\n", Srb->TargetId));
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;

        case SCSIOP_VERIFY:
        case SCSIOP_VERIFY16:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_VERIFY %x\n",
                                Srb->TargetId, Srb->Cdb[0]));
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;

        case SCSIOP_SYNCHRONIZE_CACHE:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_SYNCHRONIZE_CACHE\n",
                                Srb->TargetId));
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;

        case SCSIOP_START_STOP_UNIT:
            RPRINTK(DPRTL_ON, ("%x: SCSIOP_START_STOP_UNIT\n", Srb->TargetId));
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;

        case SCSIOP_RESERVE_UNIT:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_RESERVE_UNIT\n", Srb->TargetId));
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;

        case SCSIOP_RELEASE_UNIT:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_RELEASE_UNIT\n", Srb->TargetId));
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;

        case SCSIOP_REPORT_LUNS:
            RPRINTK(DPRTL_TRC, ("%x: SCSIOP_REPORT_LUNSS\n", Srb->TargetId));
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;

        default:
            RPRINTK(DPRTL_TRC, ("%x: default %x\n",
                                Srb->TargetId, Srb->Cdb[0]));
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;
        }
        break;
    }
    case SRB_FUNCTION_SHUTDOWN:
        if (KeGetCurrentIrql() >= CRASHDUMP_LEVEL) {
            PRINTK(("XenBlk: *** hibernate/crashdump is now complete ***\n"));
            PRINTK(("  XenBlkStartIo hibernate/crashdump: Shutting down.\n"));
        }
        RPRINTK(DPRTL_ON, ("%x: SRB_FUNCTION_SHUTDOWN %d: op = %x, st = %x\n",
                           Srb->TargetId,
                           KeGetCurrentIrql(),
                           dev_ext->op_mode, dev_ext->state));
        for (i = 0; i < dev_ext->max_targets; i++) {
            if (dev_ext->info[i]) {
                blkif_quiesce(dev_ext->info[i]);
            }
        }
        if (dev_ext->op_mode == OP_MODE_NORMAL) {
            dev_ext->op_mode = OP_MODE_SHUTTING_DOWN;
        }
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        if (KeGetCurrentIrql() >= CRASHDUMP_LEVEL) {
            PRINTK(("XenBlkStartIo hibernate/crashdump Shutdown returning.\n"));
        }
        XENBLK_SET_VALUE(conditional_times_to_print_limit, 0);
        break;

    case SRB_FUNCTION_FLUSH:
        RPRINTK(DPRTL_TRC, ("%x: SRB_FUNCTION_FLUSH\n", Srb->TargetId));
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case SRB_FUNCTION_IO_CONTROL:
        sp_io_control(Srb);
        break;

    case SRB_FUNCTION_RESET_LOGICAL_UNIT:
    case SRB_FUNCTION_RESET_DEVICE:
        PRINTK(("%x: SRB_FUNCTION_RESET_%x, Srb %p, ext %p\n",
                Srb->TargetId, Srb->Function, Srb, Srb->SrbExtension));
        if (dev_ext->op_mode == OP_MODE_SHUTTING_DOWN) {
            dev_ext->op_mode = OP_MODE_NORMAL;
        }
        Srb->SrbStatus = SRB_STATUS_SUCCESS;

        blkif_quiesce(info);
        xenbus_debug_dump();
        XenBlkDebugDump(dev_ext);

        PRINTK(("%x: SRB_FUNCTION_RESET_%x complete, ext %p.\n",
                Srb->TargetId, Srb->Function, Srb->SrbExtension));
        break;

    case SRB_FUNCTION_PNP: {
        SCSI_PNP_REQUEST_BLOCK *pnp = (SCSI_PNP_REQUEST_BLOCK *)Srb;
        RPRINTK(DPRTL_TRC,
                ("%x:%x: SRB_FUNCTION_PNP, action %x, sub %x, path %x\n",
                 Srb->TargetId, pnp->Lun,
                 pnp->PnPAction, pnp->PnPSubFunction, pnp->PathId));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }

    case SRB_FUNCTION_WMI: {
        SCSI_WMI_REQUEST_BLOCK *wmi = (SCSI_WMI_REQUEST_BLOCK *)Srb;
        RPRINTK(DPRTL_TRC,
                ("%x: SRB_FUNCTION_WMI, flag %x, sub %x, lun %x\n",
                 Srb->TargetId,
                 wmi->WMIFlags, wmi->WMISubFunction, wmi->Lun));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }

    default:
        RPRINTK(DPRTL_TRC, ("%x: SRB_ default %x\n",
                            Srb->TargetId, Srb->Function));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }

    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("XenBlkStartIo i %d c %d: dev %p srb %p - xbk_req_complete\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));
    XENBLK_INC_SRB(srbs_returned);
    XENBLK_INC_SRB(sio_srbs_returned);
    xenblk_request_complete(RequestComplete, dev_ext, Srb);

    DPR_SRB("C");
    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("XenBlkStartIo i %d c %d: dev %p srb %p - xbk_next_request\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));
    xenblk_next_request(NextRequest, dev_ext);

    DPRINTK(DPRTL_IO, ("  XenBlkStartIo srb %x, status = %x - Out\n",
                       Srb, Srb->SrbStatus));
    XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_STI_L | BLK_SIO_L));
    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("XenBlkStartIo i %d c %d: dev %p srb %p - OUT XBDD\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));
    return TRUE;
}

#ifdef DBG
ULONG g_max_len;
ULONG g_max_sgs;
static void
XenBlkVerifySGL(xenblk_srb_extension *srb_ext, ULONG tlen)
{
    uint32_t i;
    uint32_t len;

    if (g_max_len < tlen) {
        g_max_len = tlen;
        PRINTK(("sp_build_io: new max_len %d, el %d.\n", g_max_len,
            srb_ext->sgl->NumberOfElements));
    }
    if (g_max_sgs < srb_ext->sgl->NumberOfElements) {
        g_max_sgs = srb_ext->sgl->NumberOfElements;
        PRINTK(("sp_build_io: new max_sgs %d, len %d.\n",
            srb_ext->sgl->NumberOfElements, tlen));
    }

    len = 0;
    for (i = 0; i < srb_ext->sgl->NumberOfElements; i++) {
        if ((((uint32_t)srb_ext->sgl->List[i].PhysicalAddress.QuadPart) &
                (PAGE_SIZE - 1)
            && ((uint32_t)srb_ext->sgl->List[i].PhysicalAddress.QuadPart) &
                0x1ff)) {
            PRINTK(("XenBlkVerifySGL va %p:SGL element %x not aligned;%x.\n",
                srb_ext->va, i,
                ((uint32_t)srb_ext->sgl->List[i].PhysicalAddress.QuadPart)));
        }
        if (srb_ext->sgl->List[i].Length % 512) {
            PRINTK(("XenBlkVerifySGL va %p: SGL element %x has lenght %x.\n",
                srb_ext->va, i, srb_ext->sgl->List[i].Length));
        }
        if (srb_ext->sgl->List[i].Length == 0) {
            PRINTK(("XenBlkVerifySGL: SGL element %x has lenght %x.\n",
                i,  srb_ext->sgl->List[i].Length));
        }
        len += srb_ext->sgl->List[i].Length;
    }
    if (len != tlen) {
        PRINTK(("XenBlkVerifySGL sgl len %x != DataTransferlen %x.\n",
            len, tlen));
    }

    len = 0;
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        len += srb_ext->sys_sgl->List[i].Length;
    }
    if (len != tlen) {
        PRINTK(("XenBlkVerifySGL sys_sgl len %x != DataTransferlen %x.\n",
            len, tlen));
    }
}
#else
#define XenBlkVerifySGL(_srb_ext, _DataTransferLength)
#endif

#ifdef XENBLK_DBG_MAP_SGL_ONLY
static void
xenblk_map_system_sgl_only(SCSI_REQUEST_BLOCK *srb,
    MEMORY_CACHING_TYPE cache_type)
{
    xenblk_srb_extension *srb_ext;
    uint32_t i;

#ifdef DBG
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > DISPATCH_LEVEL && irql < HIGH_LEVEL) {
        PRINTK(("*** xenblk_map_system_sgl_only at irql %d ***\n", irql));
    }
#endif
    srb_ext = (xenblk_srb_extension *)srb->SrbExtension;
    ASSERT(srb_ext->sys_sgl->NumberOfElements <= XENBLK_MAX_SGL_ELEMENTS);
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        srb_ext->sa[i] = mm_map_io_space(
            srb_ext->sys_sgl->List[i].PhysicalAddress,
            srb_ext->sys_sgl->List[i].Length,
            cache_type);
        if (srb_ext->sa[i] == NULL) {
            PRINTK(("xenblk_map_system_sgl_only: MmMapIoSpace failed.\n"));
        }
        DPRINTK(DPRTL_MM,
                ("\tMmMapIoSpace addr = %p, paddr = %lx, len = %x\n",
                 srb_ext->sa[i],
                 (uint32_t)srb_ext->sys_sgl->List[0].PhysicalAddress.QuadPart,
                 srb_ext->sys_sgl->List[0].Length));
    }
}
#endif

static NTSTATUS
XenBlkStartReadWrite(XENBLK_DEVICE_EXTENSION *dev_ext,
    SCSI_REQUEST_BLOCK *Srb)
{
    xenblk_srb_extension *srb_ext;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG len;
    uint32_t va_size;
    uint32_t sa_size;
    uint32_t working_sgl_size;
#ifdef DBG
    ULONG i;
#endif

    DPRINTK(DPRTL_TRC,
            (" XenBlkStartReadWrite dev %x-IN srb = %p, ext = %p, irql = %d\n",
             dev_ext, Srb, Srb->SrbExtension, KeGetCurrentIrql()));
    CDPRINTK(DPRTL_COND, 0, 1, (dev_ext->state != WORKING),
        ("XenBlkStartReadWrite dev %p is stopped: irql = %d\n",
        dev_ext, KeGetCurrentIrql()));
    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("\tXenBlkStartReadWrite i %d c %d: dev %p  srb %p - IN\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));
    srb_ext = (xenblk_srb_extension *)Srb->SrbExtension;
    srb_ext->sys_sgl = xenblk_build_sgl(dev_ext, Srb);
    if (srb_ext->sys_sgl) {
        /* If not on a sector boundry, double buffer. */
        if ((((uint32_t)srb_ext->sys_sgl->List[0].PhysicalAddress.QuadPart) &
                0x1ff)) {
#ifdef DBG
            DPRINTK(DPRTL_MM,
                ("%x alloc va: srb %p op %x els %d tlen %d, irq %d\n",
                 Srb->TargetId,
                 Srb, Srb->Cdb[0],
                 srb_ext->sys_sgl->NumberOfElements,
                 Srb->DataTransferLength,
                 KeGetCurrentIrql()));
            for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
                DPRINTK(DPRTL_MM,
                   ("   el[%d]: paddr %x, len %d\n", i,
                   (uint32_t)srb_ext->sys_sgl->List[i].PhysicalAddress.QuadPart,
                   srb_ext->sys_sgl->List[i].Length));
            }
#endif

            va_size = ((((size_t)Srb->DataTransferLength >> PAGE_SHIFT)
                + PAGE_ROUND_UP) << PAGE_SHIFT);
            sa_size = sizeof(void *) * srb_ext->sys_sgl->NumberOfElements;
            working_sgl_size = sizeof(STOR_SCATTER_GATHER_LIST)
                + (sizeof(STOR_SCATTER_GATHER_ELEMENT) *
                    (va_size >> PAGE_SHIFT));
            srb_ext->va = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                (size_t)va_size + (size_t)sa_size + (size_t)working_sgl_size,
                XENBLK_TAG_GENERAL);
            if (srb_ext->va) {
                XENBLK_INC(dev_ext->alloc_cnt_v);
                srb_ext->pa.QuadPart = __pa(srb_ext->va);

                srb_ext->sa = (void **)(srb_ext->va + va_size);
                srb_ext->working_sgl_buf = srb_ext->va + va_size + sa_size;
                DPRINTK(DPRTL_MM,
                        ("va %p size %d\n", srb_ext->va, va_size));
                DPRINTK(DPRTL_MM,
                        ("sa %p size %d\n", srb_ext->sa, sa_size));
                DPRINTK(DPRTL_MM,
                        ("gl %p size %d, elements %d - %d %d\n",
                         srb_ext->working_sgl_buf, working_sgl_size,
                         va_size >> PAGE_SHIFT,
                         sizeof(STOR_SCATTER_GATHER_LIST),
                         sizeof(STOR_SCATTER_GATHER_ELEMENT)));

                xenblk_map_system_sgl(Srb, MmCached);
                XenBlkVerifySGL(srb_ext, Srb->DataTransferLength);

                if (Srb->Cdb[0] == SCSIOP_WRITE
                        || Srb->Cdb[0] == SCSIOP_WRITE16) {
                    DPRINTK(DPRTL_MM, ("  Doing a write, do memcpy.\n"));
                    xenblk_cp_from_sa(srb_ext->sa, srb_ext->sys_sgl,
                        srb_ext->va);
                    xenblk_unmap_system_address(srb_ext->sa, srb_ext->sys_sgl);
                }
#ifdef XENBLK_REQUEST_VERIFIER
                else {
                    memset(srb_ext->va + Srb->DataTransferLength,
                        0xab, PAGE_SIZE);
                }
#endif
            } else {
                PRINTK(("XenBlkStartReadWrite: Failed to alloc memory.\n"));
                status = STATUS_NO_MEMORY;
            }
            DPRINTK(DPRTL_MM,
                    ("XenBlkStartReadWrite: Srb %p, ext %p, va %p, sa %p\n",
                     Srb, srb_ext, srb_ext->va, srb_ext->sa));
        } else {
            srb_ext->va = NULL;
            srb_ext->sgl = srb_ext->sys_sgl;
#ifdef XENBLK_DBG_MAP_SGL_ONLY
            if (Srb->Cdb[0] == SCSIOP_READ || Srb->Cdb[0] == SCSIOP_READ16) {
                xenblk_map_system_sgl_only(Srb, MmCached);
            }
#endif
            XenBlkVerifySGL(srb_ext, Srb->DataTransferLength);
        }
    } else {
        PRINTK(("XenBlkStartReadWrite: Failed to build sgl.\n"));
        status = STATUS_UNSUCCESSFUL;
    }
    DPRINTK(DPRTL_TRC,
            (" XenBlkStartReadWrite dev %x-IN srb = %p, ext = %p, irql = %d\n",
             dev_ext, Srb, Srb->SrbExtension, KeGetCurrentIrql()));
    return status;
}

#ifndef XENBLK_STORPORT
static void
XenBlkStartReadWriteDpc(PKDPC dpc, XENBLK_DEVICE_EXTENSION *dev_ext,
    SCSI_REQUEST_BLOCK *Srb, PVOID sa2)
{
    XenBlkStartReadWrite(dev_ext, Srb);
    XenBlkStartIo(dev_ext, Srb);
}
#endif

static BOOLEAN
XenBlkBuildIo(XENBLK_DEVICE_EXTENSION *dev_ext, PSCSI_REQUEST_BLOCK Srb)
{
    xenblk_srb_extension *srb_ext;
    BOOLEAN status;
#ifndef XENBLK_STORPORT
    KIRQL irql;
#endif

    if (dev_ext->state != WORKING) {
        PRINTK(("%s: non WORKING dev state %x cpu %d irql %d\n",
                __func__, dev_ext->state,
                KeGetCurrentProcessorNumber(), KeGetCurrentIrql()));
        Srb->SrbStatus = SRB_STATUS_BUSY;
        xenblk_request_complete(RequestComplete, dev_ext, Srb);
        xenblk_next_request(NextRequest, dev_ext);
        status = xenblk_pause(dev_ext, 1);
        if (status == FALSE) {
            PRINTK(("%s: failed to pasuse device\n", __func__));
        }
        return FALSE;
    }

    DPRINTK(DPRTL_TRC, ("XenBlk: XenBlkBuildIo %p-IN irql %d\n",
                        Srb, KeGetCurrentIrql()));
    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("XenBlkBuildIo i %d c %d l %x: dev %p srb %p, f %x, cbd %x\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
        dev_ext->xenblk_locks, dev_ext, Srb, Srb->Function, Srb->Cdb[0]));

    XENBLK_INC_SRB(srbs_seen);
    srb_ext = (xenblk_srb_extension *)Srb->SrbExtension;
    XENBLK_SET_VALUE(srb_ext->dev_ext, dev_ext);
    if ((Srb->Function == SRB_FUNCTION_EXECUTE_SCSI) &&
        ((Srb->Cdb[0] == SCSIOP_READ)
            || (Srb->Cdb[0] == SCSIOP_WRITE)
            || (Srb->Cdb[0] == SCSIOP_READ16)
            || (Srb->Cdb[0] == SCSIOP_WRITE16))) {
        DPRINTK(DPRTL_TRC,
                ("  It's a read or write: srb = %p, data = %p, l = %lx\n",
                 Srb, Srb->DataBuffer, Srb->DataTransferLength));

        CDPRINTK(DPRTL_COND, 0, 1, (dev_ext->state != WORKING),
            ("XenBlkBuildIodev %p is stopped: irql = %d\n",
            dev_ext, KeGetCurrentIrql()));

#ifndef XENBLK_STORPORT
        /* Scsiport StartIo comes in at greater than DISPATCH_LEVEL. */
        irql = KeGetCurrentIrql();
        if (irql >= CRASHDUMP_LEVEL) {
            XenBlkStartReadWriteDpc(NULL, dev_ext, Srb, NULL);
        } else if (irql > DISPATCH_LEVEL) {
            if (KeInsertQueueDpc(&dev_ext->rwdpc, Srb, NULL) == FALSE) {
                PRINTK(("XenBlkBuildIo  SRB_STATUS_BUSY irql = %d\n", irql));
                Srb->SrbStatus = SRB_STATUS_BUSY;
                ScsiPortNotification(RequestComplete, dev_ext, Srb);
            }
        } else {
            XenBlkStartReadWriteDpc(NULL, dev_ext, Srb, NULL);
        }
#else
        if (XenBlkStartReadWrite(dev_ext, Srb) != STATUS_SUCCESS) {
            Srb->SrbStatus = SRB_STATUS_BUSY;
            XENBLK_INC_SRB(srbs_returned);
            xenblk_request_complete(RequestComplete, dev_ext, Srb);
            xenblk_next_request(NextRequest, dev_ext);
            return FALSE;
        }
#endif

    }
#ifndef XENBLK_STORPORT
    else {
        /* This not a read/write, so for scsiport call StartIo. */
        DPRINTK(DPRTL_TRC, ("  Call into StartIo\n"));
        if (!XenBlkStartIo(dev_ext, Srb)) {
            return FALSE;
        }
    }
#endif
    DPRINTK(DPRTL_TRC, ("XenBlk: XenBlkBuildIo %p - Out\n", Srb));
    return TRUE;
}

static BOOLEAN
XenBlkResetBus(
    XENBLK_DEVICE_EXTENSION *dev_ext,
    IN ULONG PathId)
{
    XENBLK_SET_FLAG(dev_ext->xenblk_locks, (BLK_RBUS_L | BLK_SIO_L));
    xenblk_next_request(NextRequest, dev_ext);
    RPRINTK(DPRTL_ON, ("XenBlk: XenBlkResetBus - Out\n"));
    XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_RBUS_L | BLK_SIO_L));
    return TRUE;
}

static BOOLEAN
XenBlkInterruptPoll(XENBLK_DEVICE_EXTENSION *dev_ext)
{
    struct blkfront_info *info;
    uint32_t i;
    BOOLEAN claimed;

    DPRINTK(DPRTL_TRC, ("==> XenBlkInterruptPoll: cpu %d irql = %x\n",
                        KeGetCurrentProcessorNumber(),
                        KeGetCurrentIrql()));

    /*
     * If not doing a hibernate or crash dump, let xenbus handle the
     * interrupt and call us back.
     */
    claimed = FALSE;
    if (dev_ext->op_mode != OP_MODE_NORMAL
            && (dev_ext->op_mode == OP_MODE_HIBERNATE
                ||  dev_ext->op_mode == OP_MODE_CRASHDUMP)) {
        for (i = 0; i < dev_ext->max_targets; i++) {
            info = dev_ext->info[i];
            if (info) {
                if (RING_HAS_UNCONSUMED_RESPONSES(&info->ring)) {
                    blkif_complete_int(info);
                    claimed = TRUE;
                }
            }
        }
    } else {
        claimed = (BOOLEAN)xenbus_handle_evtchn_callback();
    }
    DPRINTK(DPRTL_TRC, ("<== XenBlkInterruptPoll: claimed %d\n", claimed));
    return claimed;
}

static void
XenBlkRestartAdapter(
    IN PDEVICE_OBJECT DeviceObject,
    XENBLK_DEVICE_EXTENSION *dev_ext)
{
    XENBLK_SET_VALUE(conditional_times_to_print_limit, 0);
    DPR_SRB("Rs");

    RPRINTK(DPRTL_ON,
            ("XenBlkRestartAdapter IN: dev = %p, irql = %d, cpu %x, op = %x\n",
             dev_ext, KeGetCurrentIrql(),
             KeGetCurrentProcessorNumber(), dev_ext->op_mode));

    XenBlkFreeAllResources(dev_ext, RELEASE_ONLY);
    dev_ext->state = RESTARTING;

    XenBlkInit(dev_ext);

    DPR_SRB("Re");

    RPRINTK(DPRTL_ON,
            ("XenBlkRestartAdapter OUT: dev = %p, irql = %d, cpu %x\n",
             dev_ext, KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
}

static void
XenBlkRestartDpc(PKDPC dpc, void *context, void *s1, void *s2)
{
    XENBLK_DEVICE_EXTENSION *dev_ext = (XENBLK_DEVICE_EXTENSION  *)context;
    RPRINTK(DPRTL_ON,
            ("XenBlk: XenBlkRestartDpc - IN irql = %d, cpu %x\n",
             KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    XENBLK_SET_FLAG(dev_ext->xenblk_locks, (BLK_RDPC_L | BLK_SIO_L));

    XenBlkRestartAdapter(NULL, dev_ext);
    XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_RDPC_L | BLK_SIO_L));

    RPRINTK(DPRTL_ON,
            ("XenBlk: XenBlkRestartDpc - OUT irql = %d, cpu %x\n",
             (KeGetCurrentIrql(), KeGetCurrentProcessorNumber())));
}

static SCSI_ADAPTER_CONTROL_STATUS
XenBlkAdapterControl (
    IN XENBLK_DEVICE_EXTENSION *dev_ext,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters)
{
    XENBLK_LOCK_HANDLE lh = {0};
    uint32_t i;
    int j;
    KIRQL irql;

    irql = KeGetCurrentIrql();

     PRINTK(("XenBlk: ACtrl-IN control type = %x, irql = %d, cpu %d\n",
        ControlType, irql, KeGetCurrentProcessorNumber()));
     PRINTK(("        dev = %p, op_mode %x, state %x\n",
        dev_ext, dev_ext->op_mode, dev_ext->state));
    DPR_SRB("AC");

    switch (ControlType) {
    case ScsiQuerySupportedControlTypes: {
        PSCSI_SUPPORTED_CONTROL_TYPE_LIST supportedList = Parameters;

        /* Indicate support for this type + Stop and Restart. */
        supportedList->SupportedTypeList[ScsiStopAdapter] = TRUE;
        supportedList->SupportedTypeList[ScsiRestartAdapter] = TRUE;
        supportedList->SupportedTypeList[ScsiQuerySupportedControlTypes] = TRUE;

        xenblk_acquire_spinlock(dev_ext, &dev_ext->dev_lock, StartIoLock,
                                NULL, &lh);
        XENBLK_SET_FLAG(dev_ext->xenblk_locks, (BLK_ACTR_L | BLK_SIO_L));

        if (dev_ext->state == REMOVING
                || dev_ext->state == UNLOADING) {
            for (i = 0; i < dev_ext->max_targets; i++) {
                if (dev_ext->info[i]) {
                    blkif_quiesce(dev_ext->info[i]);
                }
            }

            if (dev_ext->state == UNLOADING) {
                /*
                 * It's safe to free resources since we are not setting
                 * up for a hibernate or xenbus has the device and we
                 * will go through the relase and claim process.
                 */
                RPRINTK(DPRTL_ON, ("  Disconnecting from the backend.\n"));
                blkif_disconnect_backend(dev_ext);
            }

            dev_ext->state = REMOVED;
            XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_ACTR_L | BLK_SIO_L));
            xenblk_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);
            break;
        }

        if (dev_ext->state == REMOVED) {
            dev_ext->state = RESTARTING;
            XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_ACTR_L | BLK_SIO_L));
            xenblk_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);
            break;
        }

        if (dev_ext->state == RESTARTING) {
            /* If > PASSIVE_LEVEL, we didn't actuall hibernate. */
            if (irql > PASSIVE_LEVEL) {
                dev_ext->op_mode = OP_MODE_RESTARTING;
            }
            XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_ACTR_L | BLK_SIO_L));
            xenblk_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);
            break;
        }

        if (dev_ext->state == INITIALIZING) {
            XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_ACTR_L | BLK_SIO_L));
            xenblk_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);
            XenBlkInit(dev_ext);
            break;
        }
        XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_ACTR_L | BLK_SIO_L));
        xenblk_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);

        break;
    }

    case ScsiStopAdapter:
        XENBLK_SET_FLAG(dev_ext->xenblk_locks, (BLK_ACTR_L | BLK_INT_L));
        XENBLK_SET_FLAG(dev_ext->cpu_locks,
                        (1 << KeGetCurrentProcessorNumber()));

        if (irql == PASSIVE_LEVEL) {
            dev_ext->state = UNLOADING;
        } else {
            dev_ext->state = REMOVING;
        }

        for (i = 0; i < dev_ext->max_targets; i++) {
            if (dev_ext->info[i]) {
                /*
                 * Can't quiesce at this time because the irql
                 * may be too high so just mask.
                 */
                mask_evtchn(dev_ext->info[i]->evtchn);
            }
        }
        XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_ACTR_L | BLK_INT_L));
        XENBLK_CLEAR_FLAG(dev_ext->cpu_locks,
                          (1 << KeGetCurrentProcessorNumber()));
        break;

    case ScsiRestartAdapter:
        if (dev_ext->op_mode == OP_MODE_RESTARTING) {
            /* We didn't power down, so just unmask the evtchn. */
            RPRINTK(DPRTL_ON, ("  ScsiRestartAdapter - just unmask.\n"));
            for (i = 0; i < dev_ext->max_targets; i++) {
                if (dev_ext->info[i]) {
                    unmask_evtchn(dev_ext->info[i]->evtchn);
                }
            }
            dev_ext->state = WORKING;
            break;
        }

        dev_ext->op_mode = OP_MODE_RESTARTING;

        for (i = 0; i < dev_ext->max_targets; i++) {
            if (dev_ext->info[i]) {
                dev_ext->info[i]->xbdev = dev_ext;
                dev_ext->info[i]->connected = BLKIF_STATE_DISCONNECTED;
            }
        }

        if (irql <= DISPATCH_LEVEL) {
            XenBlkRestartAdapter(NULL, dev_ext);
        } else {
            KeInsertQueueDpc(&dev_ext->restart_dpc, NULL, NULL);
        }
        break;
    }
    RPRINTK(DPRTL_ON, ("  XenBlkAdapterControl -  irql %d, cpu %d OUT\n",
             irql, KeGetCurrentProcessorNumber()));
    DPRINTK(DPRTL_ON,
            ("    locks %x OUT:\n", dev_ext->xenblk_locks));

    DPR_SRB("ACE");
    return ScsiAdapterControlSuccess;
}

void
XenBlkFreeResource(struct blkfront_info *info, uint32_t info_idx,
    XENBUS_RELEASE_ACTION action)
{
    xenbus_release_device_t release_data;
    uint32_t i;

    release_data.action = action;
    release_data.type = vbd;
    if (info) {
        /*
         * We don't need to unregister watches here.  If we get here due
         * to a shutdown/hibernate/crashdump, the watch has already been
         * unregistered in disconnect_backend.  It we get here from a
         * resume ,we didn't need to unregister the watches.
         */
        DPR_SRB("FR");
        if (info_idx != XENBLK_MAXIMUM_TARGETS) {
            info->xbdev->info[info_idx] = NULL;
        }
        xenblk_unmap_system_addresses(info);
        xenbus_release_device(info, info->xbdev, release_data);
        blkif_free(info, 0);
        if (action == RELEASE_REMOVE) {
            xenblk_notification(BusChangeDetected, info->xbdev, 0);
        }
        RPRINTK(DPRTL_ON, ("XenBlkFreeResource: resume free info: %p **.\n",
                           info));
        XENBLK_DEC(info->xbdev->alloc_cnt_i);
        ExFreePool(info);
    }
}

void
XenBlkFreeAllResources(XENBLK_DEVICE_EXTENSION *dev_ext,
    XENBUS_RELEASE_ACTION action)
{
    uint32_t i;

    for (i = 0; i < dev_ext->max_targets; i++) {
        XenBlkFreeResource(dev_ext->info[i], i, action);
    }
    dev_ext->info = NULL;
}

static void
XenBlkResume(XENBLK_DEVICE_EXTENSION *dev_ext, uint32_t suspend_canceled)
{
    xenbus_release_device_t release_data;
    struct blkfront_info *info;

    PRINTK(("XenBlkResume IN canceled = %d, dev = %p, irql = %d, cpu = %d\n",
        suspend_canceled, dev_ext, KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber()));

    g_interrupt_count = 0;
    if (suspend_canceled) {
        /*
         * We were only suspneded long enough to do a checkpoint. Just
         * mark the state as working and continue as if nothing happened.
         */
        dev_ext->state = WORKING;
    } else {
        RPRINTK(DPRTL_ON, ("XenBlk: XenBlkResume - XenBlkRestartAdapter\n"));
        dev_ext->state = RESUMING;
        XenBlkRestartAdapter(NULL, dev_ext);
    }
    xenblk_resume(dev_ext);

    XENBLK_CLEAR_FLAG(dev_ext->xenblk_locks, (BLK_RSU_L | BLK_SIO_L));
    RPRINTK(DPRTL_ON, ("XenBlkResume OUT: dev = %p, irql = %d, cpu %x\n",
                       dev_ext, KeGetCurrentIrql(),
                       KeGetCurrentProcessorNumber()));
    XENBLK_SET_VALUE(conditional_times_to_print_limit, 0);
}

static uint32_t
XenBlkSuspend(XENBLK_DEVICE_EXTENSION *dev_ext, uint32_t reason)
{
    XENBLK_LOCK_HANDLE io_lh = {0};
    uint32_t i;
    BOOLEAN status;

    if (reason == SHUTDOWN_suspend) {
        XENBLK_SET_FLAG(dev_ext->xenblk_locks, (BLK_RSU_L | BLK_SIO_L));

        storport_acquire_spinlock(dev_ext, StartIoLock, NULL, &io_lh);
        /* Let the state prevent us from doing I/O during a suspend/migrate. */
        dev_ext->state = PENDINGREMOVE;
        status = xenblk_pause(dev_ext, 10);
        if (status == FALSE) {
            PRINTK(("%s: failed to pasuse device cpu %d irql %d\n",
                __func__, KeGetCurrentProcessorNumber(), KeGetCurrentIrql()));
        }
        storport_release_spinlock(dev_ext, io_lh);

        for (i = 0; i < dev_ext->max_targets; i++) {
            if (dev_ext->info[i]) {
                /* Wait until all outstanding requests have finished. */
                RPRINTK(DPRTL_ON, ("XenBlkSuspend: blkif_quiesce\n"));
                blkif_quiesce(dev_ext->info[i]);
            }
        }
    } else if (reason == SHUTDOWN_DEBUG_DUMP) {
        XenBlkDebugDump(dev_ext);
    }
    return 0;
}

static uint32_t
XenBlkIoctl(XENBLK_DEVICE_EXTENSION *dev_ext, pv_ioctl_t data)
{
    uint32_t cc = 0;

    switch (data.cmd) {
    case PV_SUSPEND:
        cc = XenBlkSuspend(dev_ext, data.arg);
        break;
    case PV_RESUME:
        XenBlkResume(dev_ext, data.arg);
        break;
    case PV_ATTACH:
        PRINTK(("XenBlkIoctl: attach.\n"));
        if (XenBlkClaim(dev_ext) == STATUS_SUCCESS) {
            RPRINTK(DPRTL_ON, ("XenBlkIoctl calling StorPortNotification.\n"));
            xenblk_notification(BusChangeDetected, dev_ext, 0);
            PRINTK(("XenBlkIoctl: attach complete.\n"));
        } else {
            PRINTK(("XenBlkIoctl: attach failed.\n"));
        }
        break;
    case PV_DETACH:
        break;
    default:
        break;
    }
    return cc;
}

void
XenBlkDebugDump(XENBLK_DEVICE_EXTENSION *dev_ext)
{
    uint32_t i;

    for (i = 0; i < dev_ext->max_targets; i++) {
        if (dev_ext->info[i]) {
            PRINTK(("*** XenBlk state dump for disk %d:\n", i));
            PRINTK(("\tstate %x, connected %x, irql %d, cpu %x\n",
                dev_ext->state, dev_ext->info[i]->connected,
                KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));

            PRINTK(("\tsring: req_prod %x, rsp_prod %x\n",
                dev_ext->info[i]->ring.sring->req_prod,
                dev_ext->info[i]->ring.sring->rsp_prod));

            PRINTK(("\tsring: req_event %x, rsp_event %x\n",
                dev_ext->info[i]->ring.sring->req_event,
                dev_ext->info[i]->ring.sring->rsp_event));
            PRINTK(("\tring: req_prod_pvt %x, rsp_cons %x\n",
                dev_ext->info[i]->ring.req_prod_pvt,
                dev_ext->info[i]->ring.rsp_cons));
            PRINTK(("\tglobal interrupt count: %d.\n", g_interrupt_count));
#ifdef DBG
            PRINTK(("\tsrbs_seen %x, ret %x, io_srbs_seen %x ret %x\n",
                srbs_seen, srbs_returned, io_srbs_seen, io_srbs_returned));
            PRINTK(("\tsio_srbs_seen %x, ret %x\n",
                sio_srbs_seen, sio_srbs_returned));
            PRINTK(("\tlocks held %x\n",
                dev_ext->info[i]->xenblk_locks));
#endif
        } else {
            break;
        }
    }
}
