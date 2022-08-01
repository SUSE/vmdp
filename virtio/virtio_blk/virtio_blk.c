/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2011-2012 Novell, Inc.
 * Copyright 2012-2022 SUSE LLC
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

#include "virtio_blk.h"

#ifdef DBG
static ULONG g_no_work;
#endif

BOOLEAN
sp_start_io(virtio_sp_dev_ext_t *dev_ext, PSCSI_REQUEST_BLOCK Srb)
{
    uint32_t i;
    BOOLEAN flush_status;

    VBIF_INC_SRB(sio_srbs_seen);
    VBIF_SET_FLAG(dev_ext->sp_locks, (BLK_STI_L | BLK_SIO_L));

    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("%s %s: i %d c %d l %x: dev %p srb %p - IN\n",
        VIRTIO_SP_DRIVER_NAME, __func__,
         KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
        dev_ext->sp_locks, dev_ext, Srb));

    CDPRINTK(DPRTL_COND, 1, 0, 1,
        ("\tdev %p, irql = %d, s = %p, f = %x, cbd %x, c = %x\n",
        dev_ext, KeGetCurrentIrql(), Srb, Srb->Function, Srb->Cdb[0],
        KeGetCurrentProcessorNumber()));

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI: {
        switch (Srb->Cdb[0]) {
        case SCSIOP_READ_CAPACITY:
        case SCSIOP_READ_CAPACITY16: {
            vbif_info_t *info;
            uint64_t last_sector;
            PCDB cdb;
            PSENSE_DATA senseBuffer;

            RPRINTK(DPRTL_TRC,
                ("%s %x: SCSIOP_READ_CAPACITY(16)\n",
                 VIRTIO_SP_DRIVER_NAME, Srb->TargetId));

            info = &dev_ext->info;
            last_sector =
                (info->capacity / (info->blk_size / SECTOR_SIZE)) - 1;

            if (Srb->Cdb[0] == SCSIOP_READ_CAPACITY) {
                if (last_sector > 0xffffffff) {
                    RPRINTK(DPRTL_TRC,
                        ("%s %x: Disk > 2TB: %x%08x, returning -1.\n",
                        VIRTIO_SP_DRIVER_NAME, Srb->TargetId,
                        (uint32_t)(last_sector >> 32),
                        (uint32_t)last_sector));
                    last_sector = (uint64_t) -1;
                }
                REVERSE_BYTES(
                    &((PREAD_CAPACITY_DATA)
                        Srb->DataBuffer)->LogicalBlockAddress,
                    &last_sector);
                REVERSE_BYTES(
                    &((PREAD_CAPACITY_DATA)
                        Srb->DataBuffer)->BytesPerBlock,
                    &info->blk_size);
            } else {
                cdb = (PCDB)&Srb->Cdb[0];
                if (cdb->READ_CAPACITY16.PMI == 0 &&
                        *(uint64_t *)&cdb->READ_CAPACITY16.LogicalBlock[0]) {
                    PRINTK(("%s %x: PMI 0, logical block non-zero.\n",
                            VIRTIO_SP_DRIVER_NAME, Srb->TargetId));
                    Srb->ScsiStatus = SCSISTAT_CHECK_CONDITION;
                    senseBuffer = (PSENSE_DATA) Srb->SenseInfoBuffer;
                    senseBuffer->SenseKey = SCSI_SENSE_ILLEGAL_REQUEST;
                    senseBuffer->AdditionalSenseCode = SCSI_ADSENSE_INVALID_CDB;
                    Srb->SrbStatus = SRB_STATUS_SUCCESS;
                    break;
                }

                REVERSE_BYTES_QUAD(
                    &((PREAD_CAPACITY_DATA_EX)
                        Srb->DataBuffer)->LogicalBlockAddress,
                    &last_sector);
                REVERSE_BYTES(
                    &((PREAD_CAPACITY_DATA_EX)
                        Srb->DataBuffer)->BytesPerBlock,
                    &info->blk_size);
            }

            RPRINTK(DPRTL_TRC,
                ("%s %x: last sector %x%08x, sector size %u\n",
                VIRTIO_SP_DRIVER_NAME, Srb->TargetId,
                (uint32_t)(last_sector >> 32),
                (uint32_t)last_sector,
                info->blk_size));
            RPRINTK(DPRTL_TRC,
                ("   bytes per block %x%08x, log blk addr %llx\n",
                ((PREAD_CAPACITY_DATA)Srb->DataBuffer)->BytesPerBlock,
                ((PREAD_CAPACITY_DATA_EX)
                    Srb->DataBuffer)->LogicalBlockAddress));

            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;
        }

        case SCSIOP_READ:
        case SCSIOP_WRITE:
        case SCSIOP_READ16:
        case SCSIOP_WRITE16: {
            NTSTATUS status;

            DPRINTK(DPRTL_TRC,
                ("%s %x: SCSIOP_WRITE SCSIOP_READ %x, dev=%x,srb=%x\n",
                VIRTIO_SP_DRIVER_NAME, Srb->TargetId,
                 Srb->Cdb[0], dev_ext, Srb));
            CDPRINTK(DPRTL_COND, 0, 0, 1,
                ("%s %s %x: i %d c %d: dev %p s %x srb %p do\n",
                VIRTIO_SP_DRIVER_NAME, __func__, Srb->TargetId,
                KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
                dev_ext, dev_ext->state, Srb));

            if (virtio_sp_do_cmd(dev_ext, Srb)) {
                SP_NEXT_REQUEST(NextRequest, dev_ext);
                CDPRINTK(DPRTL_COND, 0, 0, 1,
                    ("%s %s %x: do success OUT cpu=%x.\n",
                    VIRTIO_SP_DRIVER_NAME, __func__, Srb->TargetId,
                    KeGetCurrentProcessorNumber()));
                DPRINTK(DPRTL_TRC,
                    ("%s %x: SCSIOP_WRITE SCSIOP_READ returning %x\n",
                    VIRTIO_SP_DRIVER_NAME, Srb->TargetId, TRUE));
                DPRINTK(DPRTL_TRC,
                    ("\tcbd %x, dev = %p, srb = %p\n",
                    Srb->Cdb[0], dev_ext, Srb));
                VBIF_CLEAR_FLAG(dev_ext->sp_locks,
                    (BLK_STI_L | BLK_SIO_L));
                return TRUE;
            } else {
                Srb->SrbStatus = SRB_STATUS_BUSY;
                PRINTK(("%s %x:  SRB_STATUS_BUSY\n",
                        VIRTIO_SP_DRIVER_NAME, Srb->TargetId));
            }
            DPRINTK(DPRTL_TRC,
                ("\tSCSIOP_WRITE SCSIOP_READ out\n"));
            break;
        }

        case SCSIOP_INQUIRY:
            virtio_blk_inquery_data(dev_ext, Srb);
            break;

        case SCSIOP_MEDIUM_REMOVAL:
        case SCSIOP_TEST_UNIT_READY:
        case SCSIOP_VERIFY:
        case SCSIOP_VERIFY16:
        case SCSIOP_START_STOP_UNIT:
        case SCSIOP_RESERVE_UNIT:
        case SCSIOP_RELEASE_UNIT:
        case SCSIOP_REQUEST_SENSE:
            RPRINTK(DPRTL_TRC,
                ("%s %x: cdb %x\n",
                 VIRTIO_SP_DRIVER_NAME, Srb->TargetId, Srb->Cdb[0]));
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            Srb->ScsiStatus = SCSISTAT_GOOD;
            break;

        case SCSIOP_MODE_SENSE:
            Srb->SrbStatus = virtio_blk_mode_sense(dev_ext, Srb);
            break;

        case SCSIOP_REPORT_LUNS: {
            uint8_t *data;

            data = (uint8_t *)Srb->DataBuffer;
            data[3] = 8;
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            Srb->ScsiStatus = SCSISTAT_GOOD;
            Srb->DataTransferLength = 16;
            RPRINTK(DPRTL_INIT,
                ("%s %x: SRB_STATUS_INVALID_REQUEST cdb %x\n",
                VIRTIO_SP_DRIVER_NAME, Srb->TargetId, Srb->Cdb[0]));
            break;
        }

        case SCSIOP_SYNCHRONIZE_CACHE:
        case SCSIOP_SYNCHRONIZE_CACHE16:
            /* SrbStatus set when complete. */
            RPRINTK(DPRTL_TRC, ("%s: SYNCHRONIZE_CACHE\n",
                                VIRTIO_SP_DRIVER_NAME));
            Srb->SrbStatus = SRB_STATUS_PENDING;
            Srb->ScsiStatus = SCSISTAT_GOOD;
            flush_status = virtio_blk_do_flush(dev_ext, Srb);
#ifdef IS_STORPORT
            if (flush_status == FALSE) {
                Srb->SrbStatus = SRB_STATUS_ERROR;
                PRINTK(("%s: SYNCHRONIZE_CACHE flush fail\n",
                        VIRTIO_SP_DRIVER_NAME));
                break;
            }
            RPRINTK(DPRTL_TRC, ("%s: SYNCHRONIZE_CACHE flush ok\n",
                                VIRTIO_SP_DRIVER_NAME));
            return TRUE;
#else
            /* srb->SrbStatus is set in the flush: error or success. */
            DPRINTK(DPRTL_TRC, ("%s: SYNCHRONIZE_CACHE: %d\n",
                               VIRTIO_SP_DRIVER_NAME,
                               flush_status));
            break;
#endif

        default:
            RPRINTK(DPRTL_TRC,
                ("%s %x: default %x\n",
                 VIRTIO_SP_DRIVER_NAME, Srb->TargetId, Srb->Cdb[0]));
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;
        }
        break;

    } /* case SRB_FUNCTION_EXECUTE_SCSI */
    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_SHUTDOWN:
        RPRINTK(DPRTL_TRC, ("%s: flush/shutdown.\n", VIRTIO_SP_DRIVER_NAME));
        if (KeGetCurrentIrql() >= CRASHDUMP_LEVEL) {
            PRINTK(("%s %s: ** hibernate/crashdump is now complete **\n",
                VIRTIO_SP_DRIVER_NAME, __func__));
            PRINTK(("\thibernate/crashdump: shutting down.\n"));
        }

        if (Srb->Function == SRB_FUNCTION_SHUTDOWN
                && (dev_ext->op_mode & OP_MODE_NORMAL)) {
            dev_ext->op_mode &= ~OP_MODE_NORMAL;
            dev_ext->op_mode |= OP_MODE_SHUTTING_DOWN;
            PRINTK(("%s: shutdown.\n", VIRTIO_SP_DRIVER_NAME));
        }

        if (KeGetCurrentIrql() >= CRASHDUMP_LEVEL) {
            /* Not really done until the flush finishes. */
            PRINTK(("\thibernate/crashdump returning from shutdown.\n"));
        }

        /* SrbStatus set when complete. */
        Srb->SrbStatus = SRB_STATUS_PENDING;
        Srb->ScsiStatus = SCSISTAT_GOOD;
        flush_status = virtio_blk_do_flush(dev_ext, Srb);
#ifdef IS_STORPORT
        if (flush_status == FALSE) {
            Srb->SrbStatus = SRB_STATUS_ERROR;
            break;
        }
        return TRUE;
#else
        /* srb->SrbStatus is set in the flush: error or success. */
        DPRINTK(DPRTL_TRC, ("%s: FLUSH/SHUTDOWN: %d\n",
                           VIRTIO_SP_DRIVER_NAME,
                           flush_status));
        break;
#endif

    case SRB_FUNCTION_RESET_LOGICAL_UNIT:
    case SRB_FUNCTION_RESET_DEVICE:
        PRINTK(("%s SRB_FUNC_RESET 0x%x: op = %x, st = %x, %x %x\n",
                VIRTIO_SP_DRIVER_NAME,
                Srb->Function, dev_ext->op_mode, dev_ext->state,
                ((virtio_queue_split_t *)dev_ext->vq[0])->last_used_idx,
                ((virtio_queue_split_t *)dev_ext->vq[0])->vring.used->idx));

        if ((dev_ext->op_mode & OP_MODE_SHUTTING_DOWN)) {
            dev_ext->op_mode &= OP_MODE_SHUTTING_DOWN;
            dev_ext->op_mode |= OP_MODE_NORMAL;
        }

        dev_ext->op_mode |= OP_MODE_RESET;

        if (vq_has_unconsumed_responses(
                dev_ext->vq[VIRTIO_SCSI_QUEUE_REQUEST])) {
            /* Try to clean up any outstanding requests. */
            dev_ext->op_mode |= OP_MODE_POLLING;
            virtio_sp_poll(dev_ext);
        }

        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        DPR_SRB("RD");
        break;

    case SRB_FUNCTION_POWER:
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case SRB_FUNCTION_PNP: {
        SCSI_PNP_REQUEST_BLOCK *pnp = (SCSI_PNP_REQUEST_BLOCK *)Srb;
        RPRINTK(DPRTL_TRC,
            ("%s %x:%x: SRB_FUNCTION_PNP, action %x, sub %x, path %x\n",
              VIRTIO_SP_DRIVER_NAME, Srb->TargetId, pnp->Lun,
              pnp->PnPAction, pnp->PnPSubFunction, pnp->PathId));
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    }

    case SRB_FUNCTION_IO_CONTROL:
        sp_io_control(Srb);
        break;

    case SRB_FUNCTION_WMI: {
        SCSI_WMI_REQUEST_BLOCK *wmi = (SCSI_WMI_REQUEST_BLOCK *)Srb;
        RPRINTK(DPRTL_TRC,
            ("%s %x: SRB_FUNCTION_WMI, flag %x, sub %x, lun %x\n",
              VIRTIO_SP_DRIVER_NAME, Srb->TargetId,
              wmi->WMIFlags, wmi->WMISubFunction, wmi->Lun));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }

    default:
        RPRINTK(DPRTL_TRC,
            ("%s %x: SRB_ default %x\n",
             VIRTIO_SP_DRIVER_NAME, Srb->TargetId, Srb->Function));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    } /*switch (Srb->Function) */

    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("%s %s: i %d c %d: dev %p srb %p - vbif_req_complete\n",
         VIRTIO_SP_DRIVER_NAME, __func__,
         KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));

    DPRINTK(DPRTL_IO,
        ("%s %s: srb %x, status = %x - Out\n",
         VIRTIO_SP_DRIVER_NAME, __func__, Srb, Srb->SrbStatus));
    SP_COMPLETE_SRB(dev_ext, Srb);

    VBIF_INC_SRB(srbs_returned);
    VBIF_INC_SRB(sio_srbs_returned);
    DPR_SRB("C");
    VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_STI_L | BLK_SIO_L));
    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("%s %s: i %d c %d: dev %p srb %p - OUT\n",
         VIRTIO_SP_DRIVER_NAME, __func__,
         KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));
    return TRUE;
}

BOOLEAN
sp_build_io(virtio_sp_dev_ext_t *dev_ext, PSCSI_REQUEST_BLOCK srb)
{
    PHYSICAL_ADDRESS pa;
    vbif_srb_ext_t *srb_ext;
    sp_sgl_t *sgl;
    CDB *cdb;
    ULONG i;
    ULONG el;
    ULONG len;

    DPRINTK(DPRTL_TRC,
        ("%s %s: srb %p - IN irql %d\n",
         VIRTIO_SP_DRIVER_NAME, __func__, srb, KeGetCurrentIrql()));
    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("%s %s: i %d c %d l %x: dev %p srb %p, f %x, cbd %x\n",
         VIRTIO_SP_DRIVER_NAME, __func__,
         KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
         dev_ext->sp_locks, dev_ext, srb, srb->Function, srb->Cdb[0]));

    if (dev_ext->state != WORKING && dev_ext->state != STOPPED) {
        RPRINTK(DPRTL_ON,
            ("%s %s: dev %p, i = %d, t = %d, f = %x cb = %x\n",
             VIRTIO_SP_DRIVER_NAME, __func__,
             dev_ext, KeGetCurrentIrql(),
            srb->TargetId, srb->Function, srb->Cdb[0]));
        srb->SrbStatus = SRB_STATUS_BUSY;
        SP_COMPLETE_SRB(dev_ext, srb);
        return SP_BUILDIO_BOOL;
    }

    if (srb->PathId || srb->TargetId || srb->Lun) {
        DPRINTK(DPRTL_ON, ("\tTargetId = %d, Lun = %d, func = %d, sf = %x.\n",
            srb->TargetId, srb->Length, srb->Function, srb->Cdb[0]));
        srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        SP_COMPLETE_SRB(dev_ext, srb);
        return SP_BUILDIO_BOOL;
    }

    VBIF_INC_SRB(srbs_seen);
    cdb = (CDB *)srb->Cdb;
    srb_ext = (vbif_srb_ext_t *)srb->SrbExtension;

    switch (cdb->CDB6GENERIC.OperationCode) {
    case SCSIOP_READ6:
    case SCSIOP_WRITE6:
    case SCSIOP_READ12:
    case SCSIOP_WRITE12:
    case SCSIOP_WRITE_VERIFY:
    case SCSIOP_WRITE_VERIFY12:
    case SCSIOP_WRITE_VERIFY16:
        PRINTK(("%s %s: unusual read/write 0x%x.\n",
                VIRTIO_SP_DRIVER_NAME, __func__, srb->Cdb[0]));
    case SCSIOP_READ:
    case SCSIOP_WRITE:
    case SCSIOP_READ16:
    case SCSIOP_WRITE16:
        sgl = sp_build_sgl(dev_ext, srb);

        virtio_sp_verify_sgl(dev_ext, srb, sgl);

        pa = SP_GET_PHYSICAL_ADDRESS(
            dev_ext, NULL, &srb_ext->vbr.out_hdr, &len);
        srb_ext->sg[0].phys_addr = pa.QuadPart;
        srb_ext->sg[0].len = sizeof(srb_ext->vbr.out_hdr);

        for (i = 0, el = 1; i < sgl->NumberOfElements; i++, el++) {
            srb_ext->sg[el].phys_addr =
                sgl->List[i].PhysicalAddress.QuadPart;
            srb_ext->sg[el].len   = sgl->List[i].Length;
        }

        srb_ext->vbr.out_hdr.sector = virtio_blk_get_lba(dev_ext, srb);
        srb_ext->vbr.out_hdr.ioprio = 0;
        srb_ext->vbr.req = srb;

        if (srb->SrbFlags & SRB_FLAGS_DATA_OUT) {
            srb_ext->vbr.out_hdr.type = VIRTIO_BLK_T_OUT;
            srb_ext->out = el;
            srb_ext->in = 1;
        } else {
            srb_ext->vbr.out_hdr.type = VIRTIO_BLK_T_IN;
            srb_ext->out = 1;
            srb_ext->in = el;
        }

        pa = SP_GET_PHYSICAL_ADDRESS(
            dev_ext, NULL, &srb_ext->vbr.status, &len);
        srb_ext->sg[el].phys_addr = pa.QuadPart;
        srb_ext->sg[el].len = sizeof(srb_ext->vbr.status);
        srb_ext->force_unit_access = virtio_is_feature_enabled(
            dev_ext->features, VIRTIO_BLK_F_WCACHE)
                ? (cdb->CDB10.ForceUnitAccess == 1)
                : FALSE;
#ifdef DBG
        if (srb_ext->force_unit_access) {
            DPRINTK(DPRTL_TRC, ("srb_ext->force_unit_access is set\n"));
        }
#endif
        break;
    default:
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    }
#ifdef IS_STORPORT
    return TRUE;
#else
    return sp_start_io(dev_ext, srb);
#endif
}

BOOLEAN
sp_reset_bus(virtio_sp_dev_ext_t *dev_ext, ULONG PathId)
{
    RPRINTK(DPRTL_ON, ("%s %s: In\n", VIRTIO_SP_DRIVER_NAME, __func__));
    VBIF_SET_FLAG(dev_ext->sp_locks, (BLK_RBUS_L | BLK_SIO_L));
    SP_NEXT_REQUEST(NextRequest, dev_ext);
    VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_RBUS_L | BLK_SIO_L));
    RPRINTK(DPRTL_ON, ("%s %s: Out\n", VIRTIO_SP_DRIVER_NAME, __func__));
    return TRUE;
}

BOOLEAN
virtio_sp_complete_cmd(virtio_sp_dev_ext_t *dev_ext,
                       ULONG reason,
                       ULONG  msg_id,
                       BOOLEAN from_int)
{
    vbif_srb_ext_t *srb_ext;
    PSCSI_REQUEST_BLOCK srb;
    virtio_blk_req_t *vbr;
    LIST_ENTRY srb_complete_list;
    KLOCK_QUEUE_HANDLE lh;
    unsigned int len;

    DPRINTK(DPRTL_INT, ("%s %s: msg_id %d\n",
                        VIRTIO_SP_DRIVER_NAME, __func__, msg_id));
    if (reason == 1 || (LONG)msg_id >= VIRTIO_SCSI_QUEUE_REQUEST) {
        VBIF_INC(g_int_to_send);

        InitializeListHead(&srb_complete_list);

        KeAcquireInStackQueuedSpinLockAtDpcLevel(&dev_ext->request_lock, &lh);
        while ((vbr = vq_get_buf(dev_ext->vq[msg_id], &len)) != NULL) {
            InsertTailList(&srb_complete_list, &vbr->list_entry);
        }
        KeReleaseInStackQueuedSpinLockFromDpcLevel(&lh);


        while (!IsListEmpty(&srb_complete_list)) {
            vbr  = (virtio_blk_req_t *)RemoveHeadList(&srb_complete_list);
            srb = (PSCSI_REQUEST_BLOCK)vbr->req;
            srb_ext = (vbif_srb_ext_t *)srb->SrbExtension;

            switch (vbr->status) {
            case VIRTIO_BLK_S_OK:
                srb->SrbStatus = SRB_STATUS_SUCCESS;
                break;
            case VIRTIO_BLK_S_UNSUPP:
                srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
                break;
            default:
                srb->SrbStatus = SRB_STATUS_ERROR;
                PRINTK(("%s %s: SRB_STATUS_ERROR\n",
                                    VIRTIO_SP_DRIVER_NAME, __func__));
                break;
            }

            if (vbr->out_hdr.type == VIRTIO_BLK_T_FLUSH) {
                dev_ext->op_mode &= ~OP_MODE_FLUSH;
            }
#ifdef IS_STORPORT
            if (srb_ext->force_unit_access == TRUE) {
                srb_ext->force_unit_access = FALSE;
                srb->SrbStatus = SRB_STATUS_PENDING;
                if (virtio_blk_do_flush(dev_ext, srb) == FALSE) {
                    srb->SrbStatus = SRB_STATUS_ERROR;
                    SP_COMPLETE_SRB(dev_ext, srb);
                }
            }
#endif
            else {
                SP_COMPLETE_SRB(dev_ext, srb);
            }
        }
    } else if (reason == 3 || msg_id + 1 == VIRTIO_BLK_MSIX_CONFIG_VECTOR) {
        RPRINTK(DPRTL_ON, ("%s %s: reason %d, msg_id %d\n",
                            VIRTIO_SP_DRIVER_NAME, __func__, reason, msg_id));
        virtio_sp_get_device_config(dev_ext);
        SP_NOTIFICATION(BusChangeDetected, dev_ext, 0);
    }
#ifdef USE_STORPORT_DPC
    if (from_int == FALSE) {
        StorPortSynchronizeAccess(dev_ext, virtio_sp_enable_interrupt,
                                  dev_ext->vq[msg_id]);
        if (vq_has_unconsumed_responses(dev_ext->vq[msg_id])) {
            RPRINTK(DPRTL_DPC, ("%s: issue DPC, msg_id %d has work to do: %d\n",
                    VIRTIO_SP_DRIVER_NAME,
                    msg_id,
                    vq_has_unconsumed_responses(dev_ext->vq[msg_id])));
            StorPortIssueDpc(dev_ext,
                             &dev_ext->srb_complete_dpc[msg_id],
                             (void *)reason,
                             (void *)msg_id);
        }
    }
#endif
    return TRUE;
}
