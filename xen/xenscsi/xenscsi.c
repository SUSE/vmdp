/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
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

#include "xenscsi.h"

#ifdef XENSCSI_DBG_TRACK_SRBS
uint32_t srbs_seen;
uint32_t srbs_returned;
uint32_t io_srbs_seen;
uint32_t io_srbs_returned;
uint32_t sio_srbs_seen;
uint32_t sio_srbs_returned;
#endif

/* Miniport entry point decls. */

static NTSTATUS XenScsiFindAdapter(
    IN PVOID dev_ext,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCSTR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN Again);

static BOOLEAN XenScsiInitialize(XENSCSI_DEVICE_EXTENSION *dev_ext);
static BOOLEAN XenScsiPassiveInit(XENSCSI_DEVICE_EXTENSION *dev_ext);
static BOOLEAN XenScsiXenbusInit(XENSCSI_DEVICE_EXTENSION *dev_ext);
static NTSTATUS XenScsiClaim(XENSCSI_DEVICE_EXTENSION *dev_ext);
static void XenScsiInitHiberCrash(XENSCSI_DEVICE_EXTENSION *dev_ext);

static BOOLEAN XenScsiStartIo(XENSCSI_DEVICE_EXTENSION *dev_ext,
    PSCSI_REQUEST_BLOCK Srb);

static KDEFERRED_ROUTINE XenScsiRestartDpc;

static BOOLEAN XenScsiBuildIo(XENSCSI_DEVICE_EXTENSION *dev_ext,
    PSCSI_REQUEST_BLOCK Srb);

static BOOLEAN XenScsiResetBus(XENSCSI_DEVICE_EXTENSION *dev_ext, ULONG PathId);

static BOOLEAN XenScsiInterruptPoll(XENSCSI_DEVICE_EXTENSION *dev_ext);

static SCSI_ADAPTER_CONTROL_STATUS XenScsiAdapterControl(
    IN PVOID dev_ext,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters);

static void XenScsiRestartAdapter(IN PDEVICE_OBJECT DeviceObject,
    XENSCSI_DEVICE_EXTENSION *dev_ext);

static void XenScsiResume(XENSCSI_DEVICE_EXTENSION *dev_ext,
    uint32_t suspend_canceled);
static uint32_t XenScsiSuspend(XENSCSI_DEVICE_EXTENSION *dev_ext,
                               uint32_t reason);

static uint32_t
XenScsiIoctl(XENSCSI_DEVICE_EXTENSION *dev_ext, pv_ioctl_t data);

static uint32_t g_interrupt_count;


/*
 * Routine Description:
 *
 *  This routine initializes the XenScsi Storage class driver.
 *
 * Arguments:
 *
 *     DriverObject - Pointer to driver object created by system.
 *     RegistryPath - Pointer to the name of the services node for this driver.
 *
 * Return Value:
 *
 *     The function value is the final status from the initialization operation.
 *
 */

ULONG
XenDriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath)
{

    HW_INITIALIZATION_DATA hwInitializationData;
    NTSTATUS status;
    uint32_t i;
    KIRQL irql;

    irql = KeGetCurrentIrql();

    /* Don't printf before we know if we should be running. */

    for (i = 0; i < sizeof(HW_INITIALIZATION_DATA); i++) {
        ((PCHAR)&hwInitializationData)[i] = 0;
    }

    hwInitializationData.HwInitializationDataSize =
        sizeof(HW_INITIALIZATION_DATA);

    /* Set entry points into the miniport. */
    hwInitializationData.HwInitialize = XenScsiInitialize;
    hwInitializationData.HwFindAdapter = XenScsiFindAdapter;
    hwInitializationData.HwResetBus = XenScsiResetBus;
    hwInitializationData.HwAdapterControl = XenScsiAdapterControl;

    /* Sizes of the structures that port needs to allocate. */
    hwInitializationData.DeviceExtensionSize = sizeof(XENSCSI_DEVICE_EXTENSION);
    hwInitializationData.SrbExtensionSize = sizeof(xenscsi_srb_extension);
    hwInitializationData.SpecificLuExtensionSize = 0;

    hwInitializationData.NeedPhysicalAddresses = TRUE;
    hwInitializationData.TaggedQueuing = TRUE;
    hwInitializationData.AutoRequestSense = TRUE;
    hwInitializationData.MultipleRequestPerLu = TRUE;
    hwInitializationData.ReceiveEvent = TRUE;

    hwInitializationData.HwInterrupt = XenScsiInterruptPoll;
    hwInitializationData.NumberOfAccessRanges = 1;
    hwInitializationData.AdapterInterfaceType = Internal;


    hwInitializationData.HwStartIo = XenScsiStartIo;
    hwInitializationData.HwBuildIo = XenScsiBuildIo;

    /*
     * For StorPort MapBuffers is set to STOR_MAP_NON_READ_WRITE_BUFFERS so
     * that virtual addresses are only generated for non read/write requests.
     */
    hwInitializationData.MapBuffers = STOR_MAP_NON_READ_WRITE_BUFFERS;

    status = StorPortInitialize(DriverObject,
        RegistryPath,
        &hwInitializationData,
        NULL);
    return status;
}

static NTSTATUS
XenScsiInitDevExt(
    XENSCSI_DEVICE_EXTENSION *dev_ext,
    PPORT_CONFIGURATION_INFORMATION config_info,
    KIRQL irql)
{
#ifdef USE_INDIRECT_XENBUS_APIS
    xenbus_apis_t api = {0};
    xenbus_shared_info_t *xenbus_shared_info;
#endif
    NTSTATUS status = 0;
    PACCESS_RANGE accessRange = &((*(config_info->AccessRanges))[0]);
    ULONG len;

    KeInitializeDpc(&dev_ext->restart_dpc, XenScsiRestartDpc, dev_ext);

    dev_ext->port = 0;
    dev_ext->mem = NULL;
    dev_ext->info = NULL;

    if (irql <= DISPATCH_LEVEL) {
        if (irql == PASSIVE_LEVEL) {
            dev_ext->op_mode = OP_MODE_NORMAL;
            len = sizeof(uint32_t);
            sp_registry_read(dev_ext, PVCTRL_DBG_PRINT_MASK_STR, REG_DWORD,
                             &dbg_print_mask, &len);
#ifdef DBG
            len = sizeof(uint32_t);
            sp_registry_read(dev_ext, PVCTRL_CDBG_PRINT_LIMIT_STR, REG_DWORD,
                             &conditional_times_to_print_limit, &len);
#endif
        } else {
            PRINTK(("XenScsi: setting up for hibernate\n"));
            dev_ext->op_mode = OP_MODE_HIBERNATE;
        }
    } else {
        PRINTK(("XenScsi: setting up for crashdump\n"));
        dev_ext->op_mode = OP_MODE_CRASHDUMP;
    }

    dev_ext->mmio = (uint64_t)accessRange->RangeStart.QuadPart;
    dev_ext->mmio_len = accessRange->RangeLength;

    dev_ext->mem = xenscsi_get_device_base(dev_ext,
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

    XENSCSI_ZERO_VALUE(dev_ext->alloc_cnt_s);
    XENSCSI_ZERO_VALUE(dev_ext->alloc_cnt_v);

    XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, 0xffffffff);
    XENSCSI_CLEAR_FLAG(dev_ext->cpu_locks, 0xffffffff);

    return STATUS_SUCCESS;
}

static NTSTATUS
XenScsiFindAdapter(
    IN PVOID dev_extt,
    IN PVOID HwContext,
    IN PVOID BusInformation,
    IN PCSTR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION config_info,
    OUT PBOOLEAN Again)
{
    XENSCSI_DEVICE_EXTENSION *dev_ext = (XENSCSI_DEVICE_EXTENSION *)dev_extt;
    void *nc;
    NTSTATUS status = 0;
    KIRQL irql;
    uint32_t flags = 0;

    if (config_info->NumberOfAccessRanges == 0) {
        PRINTK(("Find adapter start: No access ranges\n"));
        return SP_RETURN_NOT_FOUND;
    }

    irql = KeGetCurrentIrql();
    PRINTK(("XenScsi: Version %s.\n", VER_FILEVERSION_STR));
    if (irql >= CRASHDUMP_LEVEL) {
        PRINTK(("XenScsi XenScsiFindAdapter for crashdump: Begin.\n"));
    }

    if (XenScsiInitDevExt(dev_ext, config_info, irql) != STATUS_SUCCESS) {
        return SP_RETURN_NOT_FOUND;
    }

    RPRINTK(DPRTL_INIT,
            ("XenScsiFindAdapter - IN %s, irql = %d, dev = %p\n",
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

    xenbus_get_pvctrl_param(dev_ext->mem, PVCTRL_PARAM_MAX_VSCSI_DISKS,
        &dev_ext->max_targets);
    xenbus_get_pvctrl_param(dev_ext->mem, PVCTRL_PARAM_FLAGS,
        &dev_ext->pvctrl_flags);

    if (dev_ext->max_targets == 0) {
        dev_ext->max_targets = 1;
    }

    config_info->NumberOfBuses = 1;
    config_info->MaximumNumberOfTargets = 1;
    config_info->MaximumNumberOfLogicalUnits = 1;

    if (dev_ext->max_targets > VS_MAX_LUNS) {
        config_info->MaximumNumberOfLogicalUnits = VS_MAX_LUNS;
        if (dev_ext->max_targets > VS_MAX_LUNS * VS_MAX_TIDS) {
            config_info->MaximumNumberOfTargets = VS_MAX_TIDS;
            if (dev_ext->max_targets > VS_MAX_DEVS) {
                config_info->NumberOfBuses = VS_MAX_CHNS;
            } else {
                config_info->NumberOfBuses =
                    (UCHAR)(((dev_ext->max_targets - 1) >> VS_BUS_SHIFT) + 1);
            }
        } else {
            config_info->MaximumNumberOfTargets =
                (UCHAR)(((dev_ext->max_targets - 1) >> VS_TID_SHIFT) + 1);
        }
    } else {
        config_info->MaximumNumberOfLogicalUnits = (UCHAR)dev_ext->max_targets;
    }

    RPRINTK(DPRTL_ON,
        ("XenScsiFindAdapter: max disks %d, buses %d, tids %d, luns %d\n",
        dev_ext->max_targets,
        config_info->NumberOfBuses,
        config_info->MaximumNumberOfTargets,
        config_info->MaximumNumberOfLogicalUnits));

    config_info->NumberOfPhysicalBreaks = VSCSIIF_SG_TABLESIZE - 1;
    config_info->MaximumTransferLength  = VSCSIIF_SG_TABLESIZE * PAGE_SIZE;

    PRINTK(("  NumberOfPhysicalBreaks: %ld\n",
            config_info->NumberOfPhysicalBreaks));
    PRINTK(("  MaximumTransferLength: %ld\n",
            config_info->MaximumTransferLength));

    /* config_info->InitiatorBusId[0] is not to be set for stor port. */

    config_info->Master                 = TRUE;
    config_info->NeedPhysicalAddresses  = TRUE;
    config_info->TaggedQueuing          = TRUE;
    config_info->CachesData             = TRUE;
    config_info->ScatterGather          = TRUE;
    config_info->AlignmentMask          = 0x3;
    if (config_info->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED) {
        RPRINTK(DPRTL_ON, ("  setting SCSI_DMA64_MINIPORT_SUPPORTED\n"));
        config_info->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;
    }
    config_info->SynchronizationModel   = StorSynchronizeFullDuplex;

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
        ("XenScsiFindAdapter - out: d = %x, c = %x, mtl = %x, npb = %x\n",
        dev_ext, config_info, config_info->MaximumTransferLength,
        config_info->NumberOfPhysicalBreaks));
    if (irql >= CRASHDUMP_LEVEL) {
        PRINTK(("XenScsi XenScsiFindAdapter for crashdump: End.\n"));
    }
#ifdef XENSCSI_DBG_TRACK_SRBS
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
XenScsiInitialize(XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    uint32_t i;

    if (dev_ext->op_mode != OP_MODE_NORMAL) {
        PRINTK(("XenScsi: XenScsiInitialize for hibernate/crashdump: Begin\n"));
    }
    XENSCSI_SET_FLAG(dev_ext->xenscsi_locks, (BLK_IZE_L | BLK_INT_L));
    XENSCSI_SET_FLAG(dev_ext->cpu_locks, (1 << KeGetCurrentProcessorNumber()));
    RPRINTK(DPRTL_INIT,
        ("XenScsiInitialize - IN irql = %d, dev = %p, op_mode %x\n",
        KeGetCurrentIrql(), dev_ext, dev_ext->op_mode));

    if (dev_ext->state == REMOVED) {
        for (i = 0; i < dev_ext->max_targets; i++) {
            unmask_evtchn(dev_ext->info->evtchn);
        }
        dev_ext->state = WORKING;
        RPRINTK(DPRTL_ON,
            ("XenScsiInitialize returning TRUE: in REMOVED state.\n"));
        XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, (BLK_IZE_L | BLK_INT_L));
        XENSCSI_CLEAR_FLAG(dev_ext->cpu_locks,
            (1 << KeGetCurrentProcessorNumber()));
        return TRUE;
    }

    dev_ext->state = INITIALIZING;

    if (dev_ext->op_mode == OP_MODE_NORMAL) {
        /* Scsi passive initialization will start from XenScsiAdapterControl. */
        StorPortEnablePassiveInitialization(dev_ext, XenScsiPassiveInit);
        RPRINTK(DPRTL_ON, ("XenScsiInitialize, we'll do init from control\n"));
    } else {
        if (!XenScsiPassiveInit(dev_ext)) {
            return TRUE;
        }
        PRINTK(("XenScsiInitialize for hibernate/crashdump: End.\n"));
    }

    XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, (BLK_IZE_L | BLK_INT_L));
    XENSCSI_CLEAR_FLAG(dev_ext->cpu_locks,
        (1 << KeGetCurrentProcessorNumber()));
    RPRINTK(DPRTL_INIT, ("XenScsiInitialize - OUT\n"));
    return TRUE;
}

static BOOLEAN
XenScsiPassiveInit(XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    xenbus_pv_port_options_t options;
    xenbus_release_device_t release_data;
    uint32_t devices_to_probe;
    uint32_t i;

    RPRINTK(DPRTL_INIT,
        ("XenScsiPassiveInit - IN dev %p, sizeof(info) %d, irql = %d\n",
        dev_ext, sizeof(struct vscsi_front_info), KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber()));

    if (dev_ext->state == WORKING) {
        RPRINTK(DPRTL_ON, ("XenScsiPassiveInit - OUT already initialized %p\n",
            dev_ext));
        return TRUE;
    }

    if (!XenScsiXenbusInit(dev_ext)) {
        return TRUE;
    }

    /*
     * When coming up from hibernate, we need to do the claim since
     * we disconnected form the backend.
     */
    if (dev_ext->op_mode == OP_MODE_NORMAL
            || dev_ext->op_mode == OP_MODE_HIBERNATE) {
        RPRINTK(DPRTL_ON, ("XenScsiPassiveInit - XenScsiClaim\n"));
        XenScsiClaim(dev_ext);
        xenscsi_resume(dev_ext);
        dev_ext->state = WORKING;
    } else {
        XenScsiInitHiberCrash(dev_ext);
    }

    RPRINTK(DPRTL_INIT, ("XenScsiInit - OUT irql %d, cpu %x\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    return TRUE;
}

static BOOLEAN
XenScsiXenbusInit(XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    RPRINTK(DPRTL_INIT, ("XenScsiXenbusInit - op_mode %x, state %x\n",
        dev_ext->op_mode, dev_ext->state));

    /*
     * Need to init xenbus if xenscsi has the device or we are doing
     * a crashdump or hybernate.  If xenscsi has the the device mem
     * will contain a value.  If xenbus has the device it will be null.
     */
    if (dev_ext->mem != NULL
            || dev_ext->op_mode == OP_MODE_HIBERNATE
            || dev_ext->op_mode == OP_MODE_CRASHDUMP) {
        /*
         * When restarting from hibernate etc. we always need to
         * init the shared info in OP_MODE_NORMAL.
         * Xenbus has already done the shared init when it has the device.
         */
        if (dev_ext->op_mode == OP_MODE_RESTARTING) {
            dev_ext->op_mode = OP_MODE_NORMAL;
        }

        if (xenbus_xen_shared_init(dev_ext->mmio, dev_ext->mem,
                dev_ext->mmio_len, dev_ext->vector, dev_ext->op_mode)
            != STATUS_SUCCESS) {
            PRINTK(("XenScsiXenbusInit: failed to initialize shared info.\n"));
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

    RPRINTK(DPRTL_ON, ("XenScsiXenbusInit - xenbus_register_xenscsi\n"));
    if (xenbus_register_vscsi(dev_ext, dev_ext->op_mode,
            (void **)&dev_ext->pinfo) == STATUS_SUCCESS) {
        RPRINTK(DPRTL_ON,
            ("XenScsiXenbusInit - back from xenbus_register_xenblk\n"));
        if (*dev_ext->pinfo != NULL) {
            dev_ext->info = *dev_ext->pinfo;

            /* Replace the original dev_ext with the hibernate dev_ext. */
            dev_ext->info->xbdev = dev_ext;

            RPRINTK(DPRTL_ON, ("XenScsiXenbusInit - pinfo != null, info %p\n",
                dev_ext->info));
        }
    } else {
        PRINTK(("XenScsiXenbusInit: xenbus_register_xenblk failed\n"));
        dev_ext->state = WORKING;
        return FALSE;
    }
    RPRINTK(DPRTL_INIT, ("XenScsiXenbusInit - out info = %p\n",
        dev_ext->info));
    return TRUE;
}

static NTSTATUS
XenScsiClaim(XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    struct vscsi_front_info *info;
    NTSTATUS status;

    /*
     * The info array of pointers comes form xenbus and all pointers
     * will be null to start with but will be filled out already
     * when hibernating.
     */
    RPRINTK(DPRTL_INIT, ("XenScsiClaim.\n"));
    status = STATUS_UNSUCCESSFUL;
    do {
        if (dev_ext->info) {
            /* info already set, no need to try to claim it again. */
            status = STATUS_SUCCESS;
            break;
        }
        /* Check if we would succeed in claiming the device. */
        RPRINTK(DPRTL_ON, ("XenScsiClaim - pre xenbus_claim_device.\n"));
        status = xenbus_claim_device(NULL, dev_ext, vscsi, none,
            XenScsiIoctl, XenScsiIoctl);
        if (status == STATUS_NO_MORE_ENTRIES
                || status == STATUS_RESOURCE_IN_USE) {
            /*
             * There are no more devices to claim or we are still installing
             * so return success.
             */
            RPRINTK(DPRTL_ON,
                ("XenScsiClaim - can claim returned %x.\n", status));
            status = STATUS_SUCCESS;
            break;
        }
        if (status != STATUS_SUCCESS) {
            break;
        }

        dev_ext->info = &dev_ext->info_buffer;
        memset(dev_ext->info, 0, sizeof(struct vscsi_front_info));
        dev_ext->info->xbdev = dev_ext;

        /* Use info as the identifier to xenbus. */
        RPRINTK(DPRTL_ON, ("XenScsiClaim - xenbus_claim_device.\n"));
        status = xenbus_claim_device(dev_ext->info, dev_ext, vscsi, none,
            XenScsiIoctl, XenScsiIoctl);
        if (status == STATUS_UNSUCCESSFUL || status == STATUS_NO_MORE_ENTRIES) {
            PRINTK(("  failed to claim device: %x.\n", status));
            break;
        }

        /* Now do the Xen initialization. */
        RPRINTK(DPRTL_ON, ("XenScsiClaim - vscsi_probe, ints %d.\n",
            g_interrupt_count));
        status = vscsi_probe(dev_ext->info);
        if (status != STATUS_SUCCESS) {
            PRINTK(("  vscsi_probe failed: %x\n", status));
            /*
             * We cannot release the device because the next time through
             * the loop we would just try to claim it again.
             */
            break;
        }
        RPRINTK(DPRTL_ON, ("XenScsiClaim - vscsi_probe complete.\n"));

        /* Save the info pointer in the xenbus array of info pointers. */
        RPRINTK(DPRTL_ON, ("XenScsiClaim - info %p, pinfo %p *pinfo %p.\n",
            dev_ext->info, dev_ext->pinfo, *dev_ext->pinfo));

        *dev_ext->pinfo = dev_ext->info;

        RPRINTK(DPRTL_ON, ("XenScsiClaim - info %p, pinfo %p *pinfo %p.\n",
            dev_ext->info, dev_ext->pinfo, *dev_ext->pinfo));

        StorPortInitializeDpc(dev_ext,
            &dev_ext->info->vscsi_int_dpc,
            (PHW_DPC_ROUTINE)vscsi_int_dpc);

        PRINTK(("XenScsiClaim - initialization complete for %s.\n",
            dev_ext->info->nodename));
    } while (0);
    RPRINTK(DPRTL_INIT, ("XenScsiClaim - out %x.\n", status));
    return status;
}

static void
XenScsiInitHiberCrashInfo(XENSCSI_DEVICE_EXTENSION *dev_ext,
    struct vscsi_front_info *info)
{
    uint32_t j;

    /*
     * The info array of pointers comes form xenbus and all pointers
     * will be null to start with but will be filled out already
     * when hibernating.
     */
    RPRINTK(DPRTL_INIT, ("XenScsiInitHiberCrashInfo - in.\n"));
    if (info != NULL) {
        RPRINTK(DPRTL_ON, ("\thibernate or crash dump\n"));
        mask_evtchn(info->evtchn);

        /* Clear out any grants that may still be around. */
        RPRINTK(DPRTL_ON, ("\tdoing shadow completion\n"));
        for (j = 0; j < VSCSI_RING_SIZE; j++) {
            info->shadow[j].req.nr_segments = 0;
        }

        /*
         * In hibernate mode we get a new dev_ext, but we are using
         * the original info.  Replace the original dev_ext in info
         * with the one used to hibernate.
         */
        if (info->xbdev) {
            RPRINTK(DPRTL_ON, ("\tdev %p, xbdev: %p, op %x, xop %x\n",
                dev_ext, info->xbdev,
                dev_ext->op_mode, info->xbdev->op_mode));
            info->xbdev->state = REMOVED;
            info->xbdev->op_mode = dev_ext->op_mode;
        }
    }
    RPRINTK(DPRTL_INIT, ("XenScsiInitHiberCrashInfo - out.\n"));
}

static void
XenScsiInitHiberCrash(XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    struct vscsi_front_info *info;
    uint32_t i, j;
    KIRQL irql;

    RPRINTK(DPRTL_INIT, ("XenScsiInitHiberCrash: IN.\n"));
    irql = KeGetCurrentIrql();
    if (irql >= CRASHDUMP_LEVEL) {
        PRINTK(("XenScsi XenScsiInitHiberCrash: Begin.\n"));
    }

    RPRINTK(DPRTL_ON, ("XenScsi XenScsiInitHiberCrash: info[0] %p, max_t %d.\n",
        dev_ext->info, dev_ext->max_targets));
    i = 0;
    do {
        info = xenbus_enum_xenblk_info(&i);
        if (info) {
            XenScsiInitHiberCrashInfo(dev_ext, info);
        }
    } while (info);
    dev_ext->info->xbdev = dev_ext;
    xenscsi_resume(dev_ext);
    dev_ext->state = WORKING;
    if (irql >= CRASHDUMP_LEVEL) {
        PRINTK(("XenScsi XenScsiInitHiberCrash: End.\n"));
    }
    RPRINTK(DPRTL_INIT, ("XenScsiInitHiberCrash: OUT.\n"));
}

static UCHAR
vs_start_io_chk(XENSCSI_DEVICE_EXTENSION *dev_ext, PSCSI_REQUEST_BLOCK Srb)
{
    struct vscsi_front_info *info;
    xenscsi_srb_extension *srb_ext;
    XENSCSI_LOCK_HANDLE lh;
    UCHAR status;

    /* StorPort already has the lock.  Just need it for scsiport. */
    scsiport_acquire_spinlock(&dev_ext->dev_lock, &lh);
    XENSCSI_SET_FLAG(dev_ext->xenscsi_locks, (BLK_STI_L | BLK_SIO_L));

    srb_ext = (xenscsi_srb_extension *)Srb->SrbExtension;
    XENSCSI_SET_VALUE(srb_ext->dev_ext, dev_ext);
    XENSCSI_INC_SRB(srbs_seen);
    XENSCSI_INC_SRB(sio_srbs_seen);

    status = SRB_STATUS_SUCCESS;
    do {
        if (dev_ext->state != WORKING && dev_ext->state != STOPPED) {
            DPRINTK(DPRTL_INIT,
                ("vs_start_io_chk: dev %p, st %x, i %d, t %d, f %x cb %x\n",
                dev_ext, dev_ext->state, KeGetCurrentIrql(),
                Srb->TargetId, Srb->Function, Srb->Cdb[0]));
            DPRINTK(DPRTL_INIT,
                    ("\tBlk not ready yet, returning SRB_STATUS_BUSY\n"));
            status = SRB_STATUS_BUSY;
            break;
        }

        info = dev_ext->info;
        if (info == NULL || info->connected != BLKIF_STATE_CONNECTED) {
            DPRINTK(DPRTL_INIT,
                ("vs_start_io_chk: irql %d dev %p tid %d f %x cdb %x\n",
                KeGetCurrentIrql(), dev_ext, Srb->TargetId,
                Srb->Function, Srb->Cdb[0]));

            if (info == NULL && dev_ext->state == WORKING) {
                status = SRB_STATUS_NO_DEVICE;
                DPRINTK(DPRTL_INIT, ("\tReturning SRB_STATUS_NO_DEVICE\n"));
            } else {
                status = SRB_STATUS_BUSY;
                DPRINTK(DPRTL_INIT,
                ("\tBlk not ready yet, returning SRB_STATUS_BUSY\n"));
            }

            if (status == SRB_STATUS_BUSY) {
                xenscsi_pause(dev_ext, 1);
            }
            break;
        }
    } while (0);


    if (status != SRB_STATUS_SUCCESS) {
        XENSCSI_INC_SRB(srbs_returned);
        XENSCSI_INC_SRB(sio_srbs_returned);
    }

    XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, (BLK_STI_L | BLK_SIO_L));
    scsiport_release_spinlock(&dev_ext->dev_lock, lh);
    if (status != SRB_STATUS_SUCCESS) {
        PRINTK(("vs_start_io_chk: returning %x\n", status));
    }
    return status;
}

static UCHAR
xenscsi_mode_sense(XENSCSI_DEVICE_EXTENSION *dev_ext, PSCSI_REQUEST_BLOCK srb)
{
    PCDB cdb;
    PMODE_PARAMETER_HEADER header;
    PMODE_PARAMETER_BLOCK param_block;
    ULONG len;

    cdb = (PCDB)&srb->Cdb[0];
    len = srb->DataTransferLength;
    if (cdb->MODE_SENSE.PageCode == MODE_SENSE_RETURN_ALL
            || cdb->MODE_SENSE.PageCode == MODE_PAGE_VENDOR_SPECIFIC) {
        if (sizeof(MODE_PARAMETER_HEADER) > len) {
            return SRB_STATUS_ERROR;
        }

        header = srb->DataBuffer;
        memset(header, 0, sizeof(MODE_PARAMETER_HEADER));
        header->DeviceSpecificParameter = MODE_DSP_FUA_SUPPORTED;

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
            srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER);
        }
        return SRB_STATUS_SUCCESS;
    }
    return SRB_STATUS_INVALID_REQUEST;
}

#ifdef DBG
static uint8_t exc_func[0x100] = {0};
static uint8_t srb_func[0x100] = {0};

static void
xenscsi_report_srb_action(uint8_t *func_type, uint8_t action)
{
    if (func_type == srb_func) {
        if (func_type[action] == 0) {
            PRINTK(("Srb_func %x\n", action));
            func_type[action] = 1;
        }
    } else if (func_type == srb_func) {
        if (func_type[action] == 0) {
            PRINTK(("Exc_func %x\n", action));
            func_type[action] = 1;
        }
    }
}

static void
XenScsiVerifySGL(xenscsi_srb_extension *srb_ext, ULONG tlen)
{
    uint32_t i;
    uint32_t len;

    if (srb_ext->sgl->NumberOfElements > XENSCSI_MAX_SGL_ELEMENTS) {
        PRINTK(("XenScsiVerifySGL va %p: too many sgl emements %x.\n",
           srb_ext->va, srb_ext->sgl->NumberOfElements));
    }

    len = 0;
    for (i = 0; i < srb_ext->sgl->NumberOfElements; i++) {
        if ((((uint32_t)srb_ext->sgl->List[i].PhysicalAddress.QuadPart) &
                (PAGE_SIZE - 1)
            && ((uint32_t)srb_ext->sgl->List[i].PhysicalAddress.QuadPart) &
                0x1ff)) {
            DPRINTK(DPRTL_ON,
                ("XenScsiVerifySGL va %p:SGL element %x not aligned;%x.\n",
                srb_ext->va, i,
                ((uint32_t)srb_ext->sgl->List[i].PhysicalAddress.QuadPart)));
        }
        if (srb_ext->sgl->List[i].Length % 512) {
            DPRINTK(DPRTL_ON,
                ("XenScsiVerifySGL va %p: SGL element %x has lenght %x.\n",
                srb_ext->va, i, srb_ext->sgl->List[i].Length));
        }
        if (srb_ext->sgl->List[i].Length == 0) {
            DPRINTK(DPRTL_ON,
                ("XenScsiVerifySGL: SGL element %x has lenght %x.\n",
                i,  srb_ext->sgl->List[i].Length));
        }
        len += srb_ext->sgl->List[i].Length;
    }
    if (len != tlen) {
        DPRINTK(DPRTL_ON,
            ("XenScsiVerifySGL sgl len %x != DataTransferlen %x.\n",
            len, tlen));
    }

    len = 0;
    for (i = 0; i < srb_ext->sys_sgl->NumberOfElements; i++) {
        len += srb_ext->sys_sgl->List[i].Length;
    }
    if (len != tlen) {
        DPRINTK(DPRTL_ON,
            ("XenScsiVerifySGL sys_sgl len %x != DataTransferlen %x.\n",
            len, tlen));
    }
}
#else
#define xenscsi_report_srb_action(srb_func, action)
#define XenScsiVerifySGL(_srb_ext, _DataTransferLength)
#endif

static BOOLEAN
XenScsiStartIo(XENSCSI_DEVICE_EXTENSION *dev_ext, PSCSI_REQUEST_BLOCK srb)
{
    UCHAR status;
    int i;

    /* Make some checks to see if we are really readly to do IO. */
    status = vs_start_io_chk(dev_ext, srb);
    if (status != SRB_STATUS_SUCCESS) {
        srb->SrbStatus = status;
        xenscsi_request_complete(RequestComplete, dev_ext, srb);
        xenscsi_next_request(NextRequest, dev_ext);
        return TRUE;
    }

    xenscsi_report_srb_action(srb_func, srb->Function);

#ifdef DBG
    if (srb->Function == SRB_FUNCTION_EXECUTE_SCSI) {
        DPRINTK(DPRTL_IO,
            ("%s: srb %p function %x sub %x\n",
            __func__, srb, srb->Function, srb->Cdb[0]));
    } else {
        DPRINTK(DPRTL_IO,
            ("%s: srb %p function %x\n",
            __func__, srb, srb->Function));
    }
#endif

    switch (srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:

        xenscsi_report_srb_action(exc_func, srb->Cdb[0]);

        switch (srb->Cdb[0]) {
        case SCSIOP_MEDIUM_REMOVAL:
        case SCSIOP_REPORT_LUNS:
            RPRINTK(DPRTL_IO,
                ("Cdb %x target %x\n", srb->Cdb[0], srb->TargetId));
            srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;

        case SCSIOP_MODE_SENSE:
            RPRINTK(DPRTL_IO,
                ("Cdb %x target %x\n", srb->Cdb[0], srb->TargetId));
            if (xenscsi_mode_sense(dev_ext, srb)
                    == SRB_STATUS_INVALID_REQUEST) {
                srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
                break;
            }
            /* Fall through. */
        default:
            DPRINTK(DPRTL_IO,
                ("%p: chn %d tid %d lun %d, fn %x, sf %x, len %d.\n",
                srb, srb->PathId, srb->TargetId, srb->Lun,
                srb->Function, srb->Cdb[0], srb->CdbLength));
            #ifdef DBG
            for (i = 0; i < srb->CdbLength; i++) {
                DPRINTK(DPRTL_IO, ("%x ", srb->Cdb[i]));
            }
            DPRINTK(DPRTL_IO, ("\n"));
            #endif

            srb->SrbStatus = vscsi_do_request(dev_ext->info, srb);
            break;
        }
        break;

    case SRB_FUNCTION_PNP:
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        RPRINTK(DPRTL_IO, ("PNP success\n"));
        break;

    case SRB_FUNCTION_IO_CONTROL:
        sp_io_control(srb);
        break;

    case SRB_FUNCTION_POWER:
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        RPRINTK(DPRTL_IO, ("SRB_FUNCTION_POWER\n"));
        break;

    case SRB_FUNCTION_RESET_DEVICE:
    case SRB_FUNCTION_RESET_LOGICAL_UNIT:
        PRINTK(("SRB_FUNCTION_RESET: begin\n"));
        xenbus_debug_dump();
        XenScsiDebugDump(dev_ext);
        srb->SrbStatus = vscsi_do_reset(dev_ext->info, srb);
        PRINTK(("SRB_FUNCTION_RESET complete: status %x\n", srb->SrbStatus));
        break;

    case SRB_FUNCTION_FLUSH:
        RPRINTK(DPRTL_IO, ("SRB_FUNCTION_FLUSH\n"));
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    default:
        RPRINTK(DPRTL_IO,
            ("%s: Bad fn = %x, chn %d tid %d lun %d, sf %x, len %d.\n",
             __func__,
             srb->Function,
             srb->PathId,
             srb->TargetId,
             srb->Lun,
             srb->Cdb[0],
             srb->CdbLength));
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }

    if (srb->SrbStatus != SRB_STATUS_PENDING) {
        RPRINTK(DPRTL_IO,
            ("XenScsiStartIo: bad status for func %x, cumpleting request %x\n",
            srb->Function, srb->SrbStatus));
        xenscsi_request_complete(RequestComplete, dev_ext, srb);
        xenscsi_next_request(NextRequest, dev_ext);
    }
    return TRUE;
}

static NTSTATUS
XenScsiStartReadWrite(XENSCSI_DEVICE_EXTENSION *dev_ext,
    SCSI_REQUEST_BLOCK *Srb)
{
    xenscsi_srb_extension *srb_ext;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG len;

    DPRINTK(DPRTL_TRC,
        (" XenScsiStartReadWrite dev %x-IN srb = %p, ext = %p, irql = %d\n",
        dev_ext, Srb, Srb->SrbExtension, KeGetCurrentIrql()));
    CDPRINTK(DPRTL_COND, 0, 1, (dev_ext->state != WORKING),
        ("XenScsiStartReadWrite dev %p is stopped: irql = %d\n",
        dev_ext, KeGetCurrentIrql()));
    CDPRINTK(DPRTL_COND, 1, 0, 1,
        ("\tXenScsiStartReadWrite i %d c %d: dev %p  srb %p - IN\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));

    srb_ext = (xenscsi_srb_extension *)Srb->SrbExtension;
    srb_ext->sys_sgl = xenscsi_build_sgl(dev_ext, Srb);

    if (srb_ext->sys_sgl) {
        /* If not on a good xen boundry, double buffer. */
        if ((((uint32_t)srb_ext->sys_sgl->List[0].PhysicalAddress.QuadPart) &
                0x1ff)) {
            DPRINTK(DPRTL_MM,
                ("%x  Need to alloc: srb %p, op %x, addr %x, len %d irql %d\n",
                Srb->TargetId,
                Srb, Srb->Cdb[0],
                ((uint32_t)srb_ext->sys_sgl->List[0].PhysicalAddress.QuadPart),
                Srb->DataTransferLength,
                KeGetCurrentIrql()));
            srb_ext->va = ExAllocatePoolWithTag(
                NonPagedPoolNx,
                (((size_t)Srb->DataTransferLength >> PAGE_SHIFT)
                    + PAGE_ROUND_UP) << PAGE_SHIFT,
                XENSCSI_TAG_GENERAL);
            if (srb_ext->va) {

                XENSCSI_INC(dev_ext->alloc_cnt_v);

                DPRINTK(DPRTL_MM,
                    ("\tXenScsiStartReadWrite va %p, op %x\n",
                    srb_ext->va, Srb->Cdb[0]));

                xenscsi_map_system_sgl(Srb, MmCached);

                XenScsiVerifySGL(srb_ext, Srb->DataTransferLength);

                if (Srb->Cdb[0] == SCSIOP_WRITE
                        || Srb->Cdb[0] == SCSIOP_WRITE16){
                    DPRINTK(DPRTL_MM,
                        ("  Doing a write, do memcpy.\n"));

                    xenscsi_cp_from_sa(srb_ext->sa, srb_ext->sys_sgl,
                        srb_ext->va);

                    /*
                     * Rather than doing xenscsi_unmap_system_address(
                     * srb_ext->sa, srb_ext->sys_sgl); here, just let the
                     * normal xenscsi_save_system_address() and
                     * xenscsi_unmap_system_addresses() take care of it.
                     */
                }
            } else {
                PRINTK(("XenScsiStartReadWrite: Failed to alloc memory.\n"));
                status = STATUS_NO_MEMORY;
            }

            DPRINTK(DPRTL_MM,
                ("XenScsiStartReadWrite: Srb %p, ext %p, va %p, sa %p\n",
                Srb, srb_ext, srb_ext->va, srb_ext->sa));
        } else {
            /* We are an aligned boundry.  Just use the provided sgl. */
            srb_ext->va = NULL;
            srb_ext->sgl = srb_ext->sys_sgl;
            if (srb_ext->sgl == NULL) {
                PRINTK(("XenScsiStartReadWrite sgl/sys_sgl null.\n"));
            }

            XenScsiVerifySGL(srb_ext, Srb->DataTransferLength);
        }
    } else {
        PRINTK(("XenScsiStartReadWrite failed to get sgl.\n"));
        status = STATUS_UNSUCCESSFUL;
    }

    DPRINTK(DPRTL_TRC,
        (" %s: dev %x-IN srb = %p, ext = %p, irql = %d, status %x\n",
        __func__, dev_ext, Srb, Srb->SrbExtension, KeGetCurrentIrql(), status));

    return status;
}

static BOOLEAN
XenScsiBuildIo(XENSCSI_DEVICE_EXTENSION *dev_ext, PSCSI_REQUEST_BLOCK srb)
{
    xenscsi_srb_extension *srb_ext;

    XENSCSI_INC_SRB(srbs_seen);

    srb_ext = (xenscsi_srb_extension *)srb->SrbExtension;
    XENSCSI_SET_VALUE(srb_ext->dev_ext, dev_ext);

#ifdef DBG
    if (srb->Function == SRB_FUNCTION_EXECUTE_SCSI) {
        DPRINTK(DPRTL_IO,
            ("%s: srb %p function %x sub %x va %p sgl %p\n",
            __func__, srb, srb->Function, srb->Cdb[0],
            srb_ext->va, srb_ext->sgl));
    } else {
        DPRINTK(DPRTL_IO,
            ("%s: srb %p function %x va %p sgl %p\n",
            __func__, srb, srb->Function, srb_ext->va, srb_ext->sgl));
    }
#endif

    /* Start each new request clean. */
    srb_ext->va = NULL;
    srb_ext->sgl = NULL;
    srb_ext->next = NULL;
    srb_ext->srb = srb;
    srb_ext->use_cnt = 0;

    if ((srb->Function == SRB_FUNCTION_EXECUTE_SCSI) &&
        ((srb->Cdb[0] == SCSIOP_READ)
            || (srb->Cdb[0] == SCSIOP_WRITE)
            || (srb->Cdb[0] == SCSIOP_READ16)
            || (srb->Cdb[0] == SCSIOP_WRITE16))) {
        if (XenScsiStartReadWrite(dev_ext, srb) != STATUS_SUCCESS) {
            srb->SrbStatus = SRB_STATUS_BUSY;
            XENSCSI_INC_SRB(srbs_returned);
            xenscsi_request_complete(RequestComplete, dev_ext, srb);
            xenscsi_next_request(NextRequest, dev_ext);
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN
XenScsiResetBus(
    XENSCSI_DEVICE_EXTENSION *dev_ext,
    IN ULONG PathId)
{
    XENSCSI_SET_FLAG(dev_ext->xenscsi_locks, (BLK_RBUS_L | BLK_SIO_L));
    xenscsi_next_request(NextRequest, dev_ext);
    RPRINTK(DPRTL_ON, ("XenScsiResetBus - Out\n"));
    XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, (BLK_RBUS_L | BLK_SIO_L));
    return TRUE;
}

static BOOLEAN
XenScsiInterruptPoll(XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    struct vscsi_front_info *info;
    uint32_t i;
    BOOLEAN claimed;

    DPRINTK(DPRTL_TRC, ("==> XenScsiInterruptPoll: cpu %d irql = %x\n",
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
        info = dev_ext->info;
        if (info) {
            if (RING_HAS_UNCONSUMED_RESPONSES(&info->ring)) {
                vscsi_complete_int(info);
                claimed = TRUE;
            }
        }
    } else {
        claimed = (BOOLEAN)xenbus_handle_evtchn_callback();
    }
    DPRINTK(DPRTL_TRC,  ("<== XenScsiInterruptPoll: claimed %d\n", claimed));
    return claimed;
}

static void
XenScsiRestartAdapter(
    IN PDEVICE_OBJECT DeviceObject,
    XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    XENSCSI_SET_VALUE(conditional_times_to_print_limit, 0);
    DPR_SRB("Rs");

    RPRINTK(DPRTL_ON,
        ("XenScsiRestartAdapter IN: dev = %p, irql = %d, cpu %x, op = %x\n",
        dev_ext, KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber(), dev_ext->op_mode));

    dev_ext->state = RESTARTING;
    XenScsiFreeAllResources(dev_ext, RELEASE_ONLY);

    XenScsiPassiveInit(dev_ext);

    DPR_SRB("Re");

    RPRINTK(DPRTL_ON,
        ("XenScsiRestartAdapter OUT: dev = %p, irql = %d, cpu %x\n",
        dev_ext, KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
}

static void
XenScsiRestartDpc(PKDPC dpc, void *context, void *s1, void *s2)
{
    XENSCSI_DEVICE_EXTENSION *dev_ext = (XENSCSI_DEVICE_EXTENSION *)context;

    if (dev_ext == NULL) {
        return;
    }
    RPRINTK(DPRTL_ON, ("XenScsiRestartDpc - IN irql = %d, cpu %x\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    XENSCSI_SET_FLAG(dev_ext->xenscsi_locks, (BLK_RDPC_L | BLK_SIO_L));

    XenScsiRestartAdapter(NULL, dev_ext);
    XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, (BLK_RDPC_L | BLK_SIO_L));

    RPRINTK(DPRTL_ON, ("XenScsiRestartDpc - OUT irql = %d, cpu %x\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
}

static SCSI_ADAPTER_CONTROL_STATUS
XenScsiAdapterControl (
    IN XENSCSI_DEVICE_EXTENSION *dev_ext,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters)
{
    XENSCSI_LOCK_HANDLE lh = {0};
    uint32_t i;
    int j;
    KIRQL irql;

    irql = KeGetCurrentIrql();

    PRINTK(("XenScsiAdapterControl-IN control type %x irql %d cpu %d\n",
        ControlType, irql, KeGetCurrentProcessorNumber()));
    PRINTK(("                         dev %p op_mode %x state %x\n",
        dev_ext, dev_ext->op_mode, dev_ext->state));
    DPR_SRB("AC");

    switch (ControlType) {
    case ScsiQuerySupportedControlTypes: {
        PSCSI_SUPPORTED_CONTROL_TYPE_LIST supportedList = Parameters;

        /* Indicate support for this type + Stop and Restart. */
        supportedList->SupportedTypeList[ScsiStopAdapter] = TRUE;
        supportedList->SupportedTypeList[ScsiRestartAdapter] = TRUE;
        supportedList->SupportedTypeList[ScsiQuerySupportedControlTypes] = TRUE;

        xenscsi_acquire_spinlock(dev_ext, &dev_ext->dev_lock, StartIoLock,
                                 NULL, &lh);
        XENSCSI_SET_FLAG(dev_ext->xenscsi_locks, (BLK_ACTR_L | BLK_SIO_L));

        if (dev_ext->state == REMOVING || dev_ext->state == UNLOADING) {
            if (dev_ext->info) {
                vscsi_quiesce(dev_ext->info);
                if (dev_ext->state == UNLOADING) {
                    /*
                     * It's safe to free resources since we are not
                     * setting up for a hibernate or xenbus has the
                     * device and we will go through the relase and
                     * claim process.
                     */
                    RPRINTK(DPRTL_ON, ("  Disconnecting from the backend.\n"));
                        vscsi_disconnect_backend(dev_ext);
                }
            }

            dev_ext->state = REMOVED;
            XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks,
                               (BLK_ACTR_L | BLK_SIO_L));
            xenscsi_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);
            break;
        }

        if (dev_ext->state == REMOVED) {
            dev_ext->state = RESTARTING;
            XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks,
                               (BLK_ACTR_L | BLK_SIO_L));
            xenscsi_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);
            break;
        }

        if (dev_ext->state == RESTARTING) {
            /* If > PASSIVE_LEVEL, we didn't actuall hibernate. */
            if (irql > PASSIVE_LEVEL) {
                dev_ext->op_mode = OP_MODE_RESTARTING;
            }
            XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks,
                               (BLK_ACTR_L | BLK_SIO_L));
            xenscsi_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);
            break;
        }

        if (dev_ext->state == INITIALIZING) {
            XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks,
                               (BLK_ACTR_L | BLK_SIO_L));
            xenscsi_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);
            XenScsiPassiveInit(dev_ext);
            break;
        }
        XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, (BLK_ACTR_L | BLK_SIO_L));
        xenscsi_release_spinlock(dev_ext, &dev_ext->dev_lock, lh);

        break;
    }

    case ScsiStopAdapter:
        XENSCSI_SET_FLAG(dev_ext->xenscsi_locks, (BLK_ACTR_L | BLK_INT_L));
        XENSCSI_SET_FLAG(dev_ext->cpu_locks,
                         (1 << KeGetCurrentProcessorNumber()));

        if (irql == PASSIVE_LEVEL) {
            dev_ext->state = UNLOADING;
        } else {
            dev_ext->state = REMOVING;
        }

        if (dev_ext->info) {
            mask_evtchn(dev_ext->info->evtchn);
        }

        XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, (BLK_ACTR_L | BLK_INT_L));
        XENSCSI_CLEAR_FLAG(dev_ext->cpu_locks,
                           (1 << KeGetCurrentProcessorNumber()));
        break;

    case ScsiRestartAdapter:
        if (dev_ext->op_mode == OP_MODE_RESTARTING) {
            /* We didn't power down, so just unmask the evtchn. */
            RPRINTK(DPRTL_ON, ("  ScsiRestartAdapter - just unmask.\n"));
            unmask_evtchn(dev_ext->info->evtchn);
            dev_ext->state = WORKING;
            break;
        }

        dev_ext->op_mode = OP_MODE_RESTARTING;
        dev_ext->info->xbdev = dev_ext;
        dev_ext->info->connected = BLKIF_STATE_DISCONNECTED;

        if (irql <= DISPATCH_LEVEL) {
            XenScsiRestartAdapter(NULL, dev_ext);
        } else {
            KeInsertQueueDpc(&dev_ext->restart_dpc, NULL, NULL);
        }
        break;
    }
    RPRINTK(DPRTL_ON,
            ("  XenScsiAdapterControl -  irql %d, cpu %d OUT:\n",
            irql, KeGetCurrentProcessorNumber()));
    DPRINTK(DPRTL_ON,
            ("    locks %x OUT:\n", dev_ext->xenscsi_locks));

    DPR_SRB("ACE");
    return ScsiAdapterControlSuccess;
}

void
XenScsiFreeResource(struct vscsi_front_info *info, uint32_t info_idx,
    XENBUS_RELEASE_ACTION action)
{
    XENSCSI_DEVICE_EXTENSION *dev_ext;
    xenbus_release_device_t release_data;
    uint32_t i;

    release_data.action = action;
    release_data.type = vscsi;
    dev_ext = info->xbdev;
    if (dev_ext) {
        /*
         * We don't need to unregister watches here.  If we get here due
         * to a shutdown/hibernate/crashdump, the watch has already been
         * unregistered in disconnect_backend.  It we get here from a
         * resume ,we didn't need to unregister the watches.
         */
        DPR_SRB("FR");
        dev_ext->info = NULL;
        *dev_ext->pinfo = NULL;
        dev_ext->pinfo = NULL;
        xenbus_release_device(info, dev_ext, release_data);
        if (info->ring.sring) {
            RPRINTK(DPRTL_ON, ("XenScsiFreeResource: free sring: %p **.\n",
                info->ring.sring));
            ExFreePool(info->ring.sring);
            info->ring.sring = NULL;
            XENSCSI_DEC(dev_ext->alloc_cnt_s);
        }

        info->xbdev = NULL;
        if (action == RELEASE_REMOVE) {
            RPRINTK(DPRTL_ON,
                    ("XenScsiFreeResource: doing BusChangeDetected\n"));
            xenscsi_notification(BusChangeDetected, dev_ext, 0);
        }
    } else {
        PRINTK(("XenScsiFreeResource: dev_ext is null\n"));
    }
}

void
XenScsiFreeAllResources(XENSCSI_DEVICE_EXTENSION *dev_ext,
    XENBUS_RELEASE_ACTION action)
{
    XenScsiFreeResource(dev_ext->info, 0, action);
}

static void
XenScsiResume(XENSCSI_DEVICE_EXTENSION *dev_ext, uint32_t suspend_canceled)
{
    xenbus_release_device_t release_data;
    struct vscsi_front_info *info;
    uint32_t i;

    PRINTK(("XenScsiResume IN canceled = %d, dev = %p, irql = %d, cpu = %d\n",
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
        RPRINTK(DPRTL_ON, ("XenScsiResume - XenScsiRestartAdapter\n"));
        XenScsiRestartAdapter(NULL, dev_ext);
    }

    XENSCSI_CLEAR_FLAG(dev_ext->xenscsi_locks, (BLK_RSU_L | BLK_SIO_L));
    RPRINTK(DPRTL_ON, ("XenScsiResume OUT: dev = %p, irql = %d, cpu %x\n",
        dev_ext, KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    XENSCSI_SET_VALUE(conditional_times_to_print_limit, 0);
}

static uint32_t
XenScsiSuspend(XENSCSI_DEVICE_EXTENSION *dev_ext, uint32_t reason)
{
    uint32_t i;

    if (reason == SHUTDOWN_suspend) {
        XENSCSI_SET_FLAG(dev_ext->xenscsi_locks, (BLK_RSU_L | BLK_SIO_L));

        /*
         * We won't grab the StartIoLock so that we stay at irql 0.
         * Let the state prevent us from doing I/O until we have resumed
         * and have finished initalizing.
         */
        dev_ext->state = PENDINGREMOVE;
        vscsi_quiesce(dev_ext->info);

    } else if (reason == SHUTDOWN_poweroff) {
        PRINTK(("XenScsiSuspend for power off.\n"));
        vscsi_shutdown_backend((char *)dev_ext);
    } else if (reason == SHUTDOWN_DEBUG_DUMP) {
        XenScsiDebugDump(dev_ext);
    }
    return 0;
}

static uint32_t
XenScsiIoctl(XENSCSI_DEVICE_EXTENSION *dev_ext, pv_ioctl_t data)
{
    uint32_t cc = 0;

    switch (data.cmd) {
    case PV_SUSPEND:
        cc = XenScsiSuspend(dev_ext, data.arg);
        break;
    case PV_RESUME:
        XenScsiResume(dev_ext, data.arg);
        break;
    case PV_ATTACH:
        PRINTK(("XenScsiIoctl: attach.\n"));
        if (XenScsiClaim(dev_ext) == STATUS_SUCCESS) {
            RPRINTK(DPRTL_ON, ("XenScsiIoctl calling StorPortNotification.\n"));
            xenscsi_notification(BusChangeDetected, dev_ext, 0);
            PRINTK(("XenScsiIoctl: attach complete.\n"));
        } else {
            PRINTK(("XenScsiIoctl: attach failed.\n"));
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
XenScsiDebugDump(XENSCSI_DEVICE_EXTENSION *dev_ext)
{
    uint32_t i;

    PRINTK(("*** XenScsi state dump for disk %d:\n", 0));
    PRINTK(("\tstate %x, connected %x, irql %d, cpu %x\n",
        dev_ext->state, dev_ext->info->connected,
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    PRINTK(("\tsring: req_prod %x, rsp_prod %x, req_event %x, rsp_event %x\n",
        dev_ext->info->ring.sring->req_prod,
        dev_ext->info->ring.sring->rsp_prod,
        dev_ext->info->ring.sring->req_event,
        dev_ext->info->ring.sring->rsp_event));
    PRINTK(("\tring: req_prod_pvt %x, rsp_cons %x\n",
        dev_ext->info->ring.req_prod_pvt,
        dev_ext->info->ring.rsp_cons));
    PRINTK(("\tglobal interrupt count: %d.\n", g_interrupt_count));
#ifdef DBG
    PRINTK(("\tsrbs_seen %x, ret %x, io_srbs_seen %x ret %x\n",
        srbs_seen, srbs_returned, io_srbs_seen, io_srbs_returned));
    PRINTK(("\tsio_srbs_seen %x, ret %x\n",
        sio_srbs_seen, sio_srbs_returned));
    PRINTK(("\tlocks held %x\n", dev_ext->info->xenscsi_locks));
#endif
}
