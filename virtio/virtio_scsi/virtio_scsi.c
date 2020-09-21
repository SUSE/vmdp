/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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

#include "virtio_scsi.h"

#ifdef DBG
static uint32_t g_getb;
#endif

static void
virtio_scsi_complete_request(virtio_sp_dev_ext_t *dev_ext,
                             PSCSI_REQUEST_BLOCK srb)
{
    PCDB cdb;
    int i;

    cdb = (PCDB)&srb->Cdb[0];

    if (cdb->CDB6GENERIC.OperationCode == SCSIOP_INQUIRY) {

        SP_SET_QUEUE_DEPTH(dev_ext, srb);

        if (srb->Cdb[1] & 1) {
            /* The EVPD bit is set.  Check which page to return. */
            switch (srb->Cdb[2]) {
            case VPD_SUPPORTED_PAGES: {
                PVPD_SUPPORTED_PAGES_PAGE rbuf;

                rbuf = (PVPD_SUPPORTED_PAGES_PAGE)
                    srb->DataBuffer;

                RPRINTK(DPRTL_ON, ("%s: Supported Pages: ",
                                   VIRTIO_SP_DRIVER_NAME));
                dev_ext->inquiry_supported = FALSE;
                for (i = 0; i < rbuf->PageLength; i++) {
                    RPRINTK(DPRTL_ON, ("%x ", rbuf->SupportedPageList[i]));
                    if (rbuf->SupportedPageList[i] == VPD_SERIAL_NUMBER) {
                        dev_ext->inquiry_supported = TRUE;
                    }
                }
                RPRINTK(DPRTL_ON, ("\n"));
                if (!dev_ext->inquiry_supported) {
                    RPRINTK(DPRTL_ON, ("%s: Adding VPD_SERIAL_NUMBER support\n",
                            VIRTIO_SP_DRIVER_NAME));
                    rbuf->PageLength++;
                    rbuf->SupportedPageList[i] = VPD_SERIAL_NUMBER;
                }
                break;
            }
            case VPD_SERIAL_NUMBER: {
                PVPD_SERIAL_NUMBER_PAGE rbuf;

                rbuf = (PVPD_SERIAL_NUMBER_PAGE)
                    srb->DataBuffer;

                RPRINTK(DPRTL_ON, ("%s: SCSIOP_INQUIRY page %x: ",
                                   VIRTIO_SP_DRIVER_NAME));
                RPRINTK(DPRTL_ON, ("type %x, q %x, c %x, l %x\n",
                    rbuf->DeviceType,
                    rbuf->DeviceTypeQualifier,
                    rbuf->PageCode,
                    rbuf->PageLength));
                break;
            }
            default:
                break;
            }
        }
    }
    SP_COMPLETE_SRB(dev_ext, srb);
}

BOOLEAN
sp_start_io(virtio_sp_dev_ext_t *dev_ext, PSCSI_REQUEST_BLOCK Srb)
{
    VBIF_INC_SRB(sio_srbs_seen);
    VBIF_SET_FLAG(dev_ext->sp_locks, (BLK_STI_L | BLK_SIO_L));

    DPRINTK(DPRTL_TRC, ("%s %s: in\n", VIRTIO_SP_DRIVER_NAME, __func__));
    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("%s %s: i %d c %d l %x: should dev %p srb %p - IN\n",
         VIRTIO_SP_DRIVER_NAME, __func__,
         KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
        dev_ext->sp_locks, dev_ext, Srb));

    CDPRINTK(DPRTL_COND, 1, 0, 1,
        ("\tdev %p, irql = %d, s = %p, f = %x, cbd %x, c = %x\n",
        dev_ext, KeGetCurrentIrql(), Srb, Srb->Function, Srb->Cdb[0],
        KeGetCurrentProcessorNumber()));

    switch (Srb->Function) {
    case SRB_FUNCTION_PNP:
        RPRINTK(DPRTL_ON, ("%s: SRB_FUNCTION_PNP\n", VIRTIO_SP_DRIVER_NAME));
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case SRB_FUNCTION_POWER:
        RPRINTK(DPRTL_ON, ("%s: SRB_FUNCTION_POWER\n", VIRTIO_SP_DRIVER_NAME));
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case SRB_FUNCTION_RESET_DEVICE:
    case SRB_FUNCTION_RESET_LOGICAL_UNIT:
        RPRINTK(DPRTL_ON, ("%s: SRB_FUNC_RESET 0x%x: op = %x, st = %x, %x %x\n",
                VIRTIO_SP_DRIVER_NAME, Srb->Function,
                dev_ext->op_mode, dev_ext->state,
                dev_ext->vq[VIRTIO_SCSI_QUEUE_REQUEST]->last_used_idx,
                dev_ext->vq[VIRTIO_SCSI_QUEUE_REQUEST]->vring.used->idx));

        if ((dev_ext->op_mode & OP_MODE_SHUTTING_DOWN)) {
            RPRINTK(DPRTL_ON, ("  anding in OP_MODE_SHUTTING_DOWN\n"));
            dev_ext->op_mode &= OP_MODE_SHUTTING_DOWN;
            dev_ext->op_mode |= OP_MODE_NORMAL;
        }

        dev_ext->op_mode |= OP_MODE_RESET;
        RPRINTK(DPRTL_ON, ("  new op_mode %x\n", dev_ext->op_mode));

        if (dev_ext->vq[VIRTIO_SCSI_QUEUE_REQUEST]->last_used_idx
                != dev_ext->vq[VIRTIO_SCSI_QUEUE_REQUEST]->vring.used->idx) {
            /* Try to clean up any outstanding requests. */
            dev_ext->op_mode |= OP_MODE_POLLING;
            virtio_sp_poll(dev_ext);
        }

        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        DPR_SRB("RD");
        break;

    case SRB_FUNCTION_WMI: {
        /* With config_info->WmiDataProvider defaulting to TRUE, we need to
         * fail these requests or the system will crash in strange places.
         */
        SCSI_WMI_REQUEST_BLOCK *wmi = (SCSI_WMI_REQUEST_BLOCK *)Srb;
        RPRINTK(DPRTL_ON,
            ("%s %x: SRB_FUNCTION_WMI, flag %x, sub %x, lun %x\n",
              VIRTIO_SP_DRIVER_NAME, Srb->TargetId,
              wmi->WMIFlags, wmi->WMISubFunction, wmi->Lun));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }

    default:
        if (Srb->Function == SRB_FUNCTION_EXECUTE_SCSI
                && Srb->Cdb[0] == SCSIOP_INQUIRY) {
            if ((Srb->Cdb[1] & 1) && Srb->Cdb[2] == VPD_SERIAL_NUMBER) {
                if (!dev_ext->inquiry_supported) {
                    PVPD_SERIAL_NUMBER_PAGE rbuf;

                    RPRINTK(DPRTL_ON, ("%s: Setting VPD_SERIAL_NUMBER.\n",
                            VIRTIO_SP_DRIVER_NAME));
                    if (Srb->DataTransferLength
                            < sizeof(VPD_SERIAL_NUMBER_PAGE) + 1) {
                        PRINTK(("%s: VPD_SERIAL_NUMBER buffe too small, %d\n",
                            VIRTIO_SP_DRIVER_NAME, Srb->DataTransferLength));
                        break;
                    }
                    rbuf = (PVPD_SERIAL_NUMBER_PAGE)Srb->DataBuffer;
                    rbuf->DeviceType = DIRECT_ACCESS_DEVICE;
                    rbuf->DeviceTypeQualifier = DEVICE_CONNECTED;
                    rbuf->PageCode = VPD_SERIAL_NUMBER;
                    rbuf->PageLength = 1;
                    rbuf->SerialNumber[0] = '0';
                    Srb->SrbStatus = SRB_STATUS_SUCCESS;
                    break;
                }
            }
        }

        if (virtio_sp_do_cmd(dev_ext, Srb)) {
            CDPRINTK(DPRTL_COND, 0, 0, 1,
                ("%s %x: XBStrtIo: do success OUT cpu=%x.\n",
                VIRTIO_SP_DRIVER_NAME, Srb->TargetId,
                KeGetCurrentProcessorNumber()));
            DPRINTK(DPRTL_TRC,
                ("%s %x: SCSIOP_WRITE SCSIOP_READ returning %x\n",
                VIRTIO_SP_DRIVER_NAME, Srb->TargetId, TRUE));
            DPRINTK(DPRTL_TRC,
                ("\tcbd %x, dev = %p, srb = %p\n",
                Srb->Cdb[0], dev_ext, Srb));
            SP_NEXT_REQUEST(NextRequest, dev_ext);
            VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_STI_L | BLK_SIO_L));
            return TRUE;
        }
        DPRINTK(DPRTL_UNEXPD, ("%s %x:  SRB_STATUS_BUSY\n",
                               VIRTIO_SP_DRIVER_NAME, Srb->TargetId));
        Srb->SrbStatus = SRB_STATUS_BUSY;
        break;
    }

    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("%s %s: i %d c %d: dev %p srb %p - vscsi_req_complete\n",
         VIRTIO_SP_DRIVER_NAME, __func__,
         KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));

    DPRINTK(DPRTL_IO,
        ("%s %s: srb %x, func %x status = %x - Out\n",
        VIRTIO_SP_DRIVER_NAME, __func__, Srb, Srb->Function, Srb->SrbStatus));
    VBIF_INC_SRB(srbs_returned);
    VBIF_INC_SRB(sio_srbs_returned);
    DPR_SRB("C");
    VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_STI_L | BLK_SIO_L));

    virtio_scsi_complete_request(dev_ext, Srb);

    CDPRINTK(DPRTL_COND, 0, 0, 1,
        ("%s %s: i %d c %d: dev %p srb %p - OUT\n",
         VIRTIO_SP_DRIVER_NAME, __func__,
          KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), dev_ext, Srb));
    DPRINTK(DPRTL_TRC, ("%s %s: out\n", VIRTIO_SP_DRIVER_NAME, __func__));
    return TRUE;
}

BOOLEAN
sp_build_io(virtio_sp_dev_ext_t *dev_ext, PSCSI_REQUEST_BLOCK srb)
{
    PHYSICAL_ADDRESS pa;
    PCDB cdb;
    vscsi_srb_ext_t *srb_ext;
    virtio_scsi_cmd_t *cmd;
    sp_sgl_t *sgl;
    ULONG i;
    ULONG el;
    ULONG max_el;
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
        virtio_scsi_complete_request(dev_ext, srb);
        DPRINTK(DPRTL_TRC, ("%s %s: out busy\n",
                            VIRTIO_SP_DRIVER_NAME, __func__));
        return SP_BUILDIO_BOOL;
    }

    if ((srb->PathId > 0) ||
            (srb->TargetId >= dev_ext->scsi_config.max_target) ||
            (srb->Lun >= dev_ext->scsi_config.max_lun)) {
        srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        virtio_scsi_complete_request(dev_ext, srb);
        DPRINTK(DPRTL_TRC, ("%s %s: out no device\n",
                            VIRTIO_SP_DRIVER_NAME, __func__));
        return SP_BUILDIO_BOOL;
    }

    VBIF_INC_SRB(srbs_seen);
    cdb = (PCDB)&srb->Cdb[0];
    srb_ext = (vscsi_srb_ext_t *)srb->SrbExtension;

    memset(srb_ext, 0, sizeof(*srb_ext));

    cmd = &srb_ext->vbr;
    cmd->sc = srb;
    cmd->req.cmd.lun[0] = 1;
    cmd->req.cmd.lun[1] = srb->TargetId;
    cmd->req.cmd.lun[2] = 0;
    cmd->req.cmd.lun[3] = srb->Lun;
    cmd->req.cmd.tag = *(uintptr_t *)&srb;
    cmd->req.cmd.task_attr = VIRTIO_SCSI_S_SIMPLE;
    cmd->req.cmd.prio = 0;
    cmd->req.cmd.crn = 0;
    if (srb->CdbLength > VIRTIO_SCSI_CDB_SIZE) {
        PRINTK(("%s: srb->CdbLength > VIRTIO_SCSI_CDB_SIZE) %d\n",
                VIRTIO_SP_DRIVER_NAME, srb->CdbLength));
        srb->CdbLength = VIRTIO_SCSI_CDB_SIZE;
    }
    memcpy(cmd->req.cmd.cdb, cdb, srb->CdbLength);

    el = 0;
    srb_ext->sg[el].phys_addr = SP_GET_PHYSICAL_ADDRESS(
       dev_ext, NULL, &cmd->req.cmd, &len).QuadPart;

    srb_ext->sg[el].len   = sizeof(cmd->req.cmd);
    el++;

    sgl = sp_build_sgl(dev_ext, srb);
    if (sgl) {
        virtio_sp_verify_sgl(dev_ext, srb, sgl);

        max_el = sgl->NumberOfElements;

        if ((srb->SrbFlags & SRB_FLAGS_DATA_OUT) == SRB_FLAGS_DATA_OUT) {
            for (i = 0; i < max_el; i++, el++) {
                srb_ext->sg[el].phys_addr =
                    sgl->List[i].PhysicalAddress.QuadPart;
                srb_ext->sg[el].len   = sgl->List[i].Length;
                srb_ext->Xfer += sgl->List[i].Length;
            }
        }
    }
    srb_ext->out = el;
    srb_ext->sg[el].phys_addr = SP_GET_PHYSICAL_ADDRESS(
       dev_ext, NULL, &cmd->resp.cmd, &len).QuadPart;
    srb_ext->sg[el].len = sizeof(cmd->resp.cmd);
    el++;
    if (sgl) {
        max_el = sgl->NumberOfElements;

        if ((srb->SrbFlags & SRB_FLAGS_DATA_OUT) != SRB_FLAGS_DATA_OUT) {
            for (i = 0; i < max_el; i++, el++) {
                srb_ext->sg[el].phys_addr =
                    sgl->List[i].PhysicalAddress.QuadPart;
                srb_ext->sg[el].len = sgl->List[i].Length;
                srb_ext->Xfer += sgl->List[i].Length;
            }
        }
    }
    srb_ext->in = el - srb_ext->out;
    srb_ext->q_idx = VIRTIO_SCSI_QUEUE_REQUEST;

#ifdef IS_STORPORT
    DPRINTK(DPRTL_TRC, ("%s %s: out TRUE\n", VIRTIO_SP_DRIVER_NAME, __func__));
    return TRUE;
#else
    DPRINTK(DPRTL_TRC, ("%s %s: out sp_start_io\n",
                        VIRTIO_SP_DRIVER_NAME, __func__));
    return sp_start_io(dev_ext, srb);
#endif
}

BOOLEAN
sp_reset_bus(virtio_sp_dev_ext_t *dev_ext, ULONG PathId)
{
    PRINTK(("%s %s: op = %x, st = %x, %x %x\n",
        VIRTIO_SP_DRIVER_NAME, __func__, dev_ext->op_mode, dev_ext->state,
        dev_ext->vq[VIRTIO_SCSI_QUEUE_REQUEST]->last_used_idx,
        dev_ext->vq[VIRTIO_SCSI_QUEUE_REQUEST]->vring.used->idx));
    return TRUE;
#if 0
    /* Enable this code to send down the reset. Currently this seems cause
     * more problems that it solves.
     */
    PSCSI_REQUEST_BLOCK srb;
    vscsi_srb_ext_t *srb_ext;
    virtio_scsi_cmd_t *cmd;
    ULONG len;
    ULONG el;

    if (!(dev_ext->op_mode & OP_MODE_NORMAL)) {
        PRINTK(("%s: not normal out TURE\n", __func__));
        return TRUE;
    }
    if (dev_ext->tmf_infly == TRUE) {
        PRINTK(("%s: infly out TURE\n", __func__));
        return TRUE;
    }

    srb = &dev_ext->tmf_cmd_srb;
    srb_ext = (vscsi_srb_ext_t *)dev_ext->tmf_cmd_srb.SrbExtension;
    cmd = &srb_ext->cmd;

    memset((void *)cmd, 0, sizeof(virtio_scsi_cmd_t));
    cmd->sc = srb;
    cmd->req.tmf.lun[0] = 1;
    cmd->req.tmf.lun[1] = 0;
    cmd->req.tmf.lun[2] = 0;
    cmd->req.tmf.lun[3] = 0;
    cmd->req.tmf.type = VIRTIO_SCSI_T_TMF;
    cmd->req.tmf.subtype = VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET;

    el = 0;
    srb_ext->sg[el].phys_addr = vscsi_get_physical_address(
       dev_ext, NULL, &cmd->req.tmf, &len).QuadPart;
    srb_ext->sg[el].len   = sizeof(cmd->req.tmf);
    el++;
    srb_ext->out = el;
    srb_ext->sg[el].phys_addr = vscsi_get_physical_address(
       dev_ext, NULL, &cmd->resp.tmf, &len).QuadPart;
    srb_ext->sg[el].len   = sizeof(cmd->resp.tmf);
    el++;
    srb_ext->in = el - srb_ext->out;
    srb_ext->q_idx = VIRTIO_SCSI_QUEUE_CONTROL;
    vscsi_pause(dev_ext, 60);
    dev_ext->tmf_infly = TRUE;
    if (!vscsi_do_cmd(dev_ext, srb)) {
        vscsi_resume(dev_ext);
        PRINTK(("%s: out FALSE\n", __func__));
        dev_ext->tmf_infly = FALSE;
        return FALSE;
    }
    PRINTK(("%s: out TRUE\n", __func__));
    return TRUE;
#endif
}

BOOLEAN
virtio_sp_complete_cmd(virtio_sp_dev_ext_t *dev_ext,
                         ULONG reason,
                         ULONG  msg_id)
{
    virtio_scsi_cmd_t *cmd;
    virtio_scsi_event_node_t *event_node;
    virtio_scsi_event_t *evt;
    PSCSI_REQUEST_BLOCK srb;
    vscsi_srb_ext_t *srb_ext;
    virtio_scsi_cmd_resp_t   *resp;
    unsigned int len;
    int cnt;
    BOOLEAN int_serviced = TRUE;

    VBIF_SET_FLAG(dev_ext->sp_locks, (BLK_ISR_L));
    DPRINTK(DPRTL_INT, ("%s %s: in\n", VIRTIO_SP_DRIVER_NAME, __func__));
    if (reason == 1 || msg_id >= VIRTIO_SCSI_QUEUE_REQUEST) {
        cnt = 0;
        while ((cmd = vring_get_buf(dev_ext->vq[VIRTIO_SCSI_QUEUE_REQUEST],
                &len)) != NULL) {
            srb = (PSCSI_REQUEST_BLOCK)cmd->sc;
            resp = &cmd->resp.cmd;
            srb_ext = (vscsi_srb_ext_t *)srb->SrbExtension;

            DPRINTK(DPRTL_INT,
                    ("%s %s: dv_ext %x, srb %x, rsp %x, cmd %x, g %d\n",
                    VIRTIO_SP_DRIVER_NAME, __func__,
                    dev_ext, srb, resp->response, cmd, ++g_getb));
            DPRINTK(DPRTL_INT, ("  func %x cmd %x\n",
                                srb->Function, srb->Cdb[0]));

            switch (resp->response) {
            case VIRTIO_SCSI_S_OK:
                srb->SrbStatus = SRB_STATUS_SUCCESS;
                break;
            case VIRTIO_SCSI_S_UNDERRUN:
                dev_ext->underruns++;
                if ((dev_ext->underruns % VIRTIO_SCSI_UNDERRUN_MOD) == 0) {
                    PRINTK(("%s: VIRTIO_SCSI_S_UNDERRUN %d\n",
                        VIRTIO_SP_DRIVER_NAME, dev_ext->underruns));
                }
                srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
                break;
            case VIRTIO_SCSI_S_ABORTED:
                PRINTK(("%s: VIRTIO_SCSI_S_ABORTED\n", VIRTIO_SP_DRIVER_NAME));
                srb->SrbStatus = SRB_STATUS_ABORTED;
                break;
            case VIRTIO_SCSI_S_BAD_TARGET:
                DPRINTK(DPRTL_IO, ("%s: VIRTIO_SCSI_S_BAD_TARGET\n",
                                   VIRTIO_SP_DRIVER_NAME));
                srb->SrbStatus = SRB_STATUS_INVALID_TARGET_ID;
                break;
            case VIRTIO_SCSI_S_RESET:
                PRINTK(("%s: VIRTIO_SCSI_S_RESET\n", VIRTIO_SP_DRIVER_NAME));
                srb->SrbStatus = SRB_STATUS_BUS_RESET;
                break;
            case VIRTIO_SCSI_S_BUSY:
                PRINTK(("%s: VIRTIO_SCSI_S_BUSY\n", VIRTIO_SP_DRIVER_NAME));
                srb->SrbStatus = SRB_STATUS_BUSY;
                break;
            case VIRTIO_SCSI_S_TRANSPORT_FAILURE:
                PRINTK(("%s: VIRTIO_SCSI_S_TRANSPORT_FAILURE\n"
                         VIRTIO_SP_DRIVER_NAME));
                srb->SrbStatus = SRB_STATUS_ERROR;
                break;
            case VIRTIO_SCSI_S_TARGET_FAILURE:
                PRINTK(("%s: VIRTIO_SCSI_S_TARGET_FAILURE\n",
                        VIRTIO_SP_DRIVER_NAME));
                srb->SrbStatus = SRB_STATUS_ERROR;
                break;
            case VIRTIO_SCSI_S_NEXUS_FAILURE:
                PRINTK(("%s: VIRTIO_SCSI_S_NEXUS_FAILURE\n",
                        VIRTIO_SP_DRIVER_NAME));
                srb->SrbStatus = SRB_STATUS_ERROR;
                break;
            case VIRTIO_SCSI_S_FAILURE:
                PRINTK(("%s VIRTIO_SCSI_S_FAILURE\n", VIRTIO_SP_DRIVER_NAME));
                srb->SrbStatus = SRB_STATUS_ERROR;
                break;
            default:
                srb->SrbStatus = SRB_STATUS_ERROR;
                PRINTK(("%s: Unknown response %d\n",
                        VIRTIO_SP_DRIVER_NAME, resp->response));
                break;
            }

            if (srb->DataBuffer) {
                memcpy(srb->DataBuffer, resp->sense,
                    min(resp->sense_len, srb->DataTransferLength));
            }
            if (srb_ext->Xfer && srb->DataTransferLength > srb_ext->Xfer) {
                srb->DataTransferLength = srb_ext->Xfer;
                srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
            }

            DPRINTK(DPRTL_INT, ("\tvscsi_complete_srb_int d %x, s %x, sx %x\n",
                dev_ext, srb, srb_ext));

            virtio_scsi_complete_request(dev_ext, srb);

            DPRINTK(DPRTL_INT, ("\tsrb_ext->cmd %x\n", srb_ext->vbr));
            DPRINTK(DPRTL_INT, ("\tcmd->sc %x %x %x\n",
                srb_ext->vbr.sc, &srb_ext->vbr.sc, cmd->sc));
        }
    }
    if (reason == 1 || msg_id == VIRTIO_SCSI_QUEUE_CONTROL) {
        if (dev_ext->tmf_infly) {
            PRINTK(("%s: ** int infly\n", VIRTIO_SP_DRIVER_NAME));
            while ((cmd = vring_get_buf(dev_ext->vq[VIRTIO_SCSI_QUEUE_CONTROL],
                    &len)) != NULL) {
                virtio_scsi_ctrl_tmf_resp_t *resp;

                srb = (PSCSI_REQUEST_BLOCK)cmd->sc;
                ASSERT(srb == &dev_ext->tmf_cmd_srb);
                resp = &cmd->resp.tmf;
                switch (resp->response) {
                case VIRTIO_SCSI_S_OK:
                case VIRTIO_SCSI_S_FUNCTION_SUCCEEDED:
                    break;
                default:
                    PRINTK(("%s: Unknown response %d\n",
                            VIRTIO_SP_DRIVER_NAME, resp->response));
                    ASSERT(0);
                    break;
                }
                dev_ext->tmf_infly = FALSE;
                SP_RESUME(dev_ext);
            }
        }
    }
    if (reason == 1 || msg_id == VIRTIO_SCSI_QUEUE_EVENT) {

        while ((event_node = vring_get_buf(dev_ext->vq[VIRTIO_SCSI_QUEUE_EVENT],
                &len)) != NULL) {
           evt = &event_node->event;
           RPRINTK(DPRTL_ON, ("VioScsiInterruptevent event %x\n",evt->event));
           switch (evt->event) {
           case VIRTIO_SCSI_T_NO_EVENT:
              break;
           case VIRTIO_SCSI_T_TRANSPORT_RESET:
              virtio_scsi_transport_reset(dev_ext, evt);
              break;
           case VIRTIO_SCSI_T_PARAM_CHANGE:
              virtio_scsi_param_change(dev_ext, evt);
              break;
           default:
              PRINTK(("%s: Unsupport virtio scsi event %x\n",
                      VIRTIO_SP_DRIVER_NAME, evt->event));
              break;
           }
           virtio_scsi_add_event(dev_ext, event_node);
        }
    }
    if (reason == 3) {
        PRINTK(("%s: ** int reason 3\n", VIRTIO_SP_DRIVER_NAME));
        SP_NOTIFICATION(BusChangeDetected, dev_ext, 0);
    } else if (reason == 2 || reason > 3) {
        RPRINTK(DPRTL_UNEXPD,("%s %s: int serviced set to FALSE, reason = %d\n",
            VIRTIO_SP_DRIVER_NAME, __func__, reason));
        int_serviced = FALSE;
    }
    DPRINTK(DPRTL_INT, ("%s %s: out %d\n",
                        VIRTIO_SP_DRIVER_NAME, __func__, int_serviced));
    VBIF_CLEAR_FLAG(dev_ext->sp_locks, (BLK_ISR_L));
    return int_serviced;
}

#ifdef USE_STORPORT_DPC
void
virtio_sp_int_dpc(PSTOR_DPC Dpc, PVOID context, PVOID s1, PVOID s2)
{
    KLOCK_QUEUE_HANDLE lh;
    virtio_sp_dev_ext_t *dev_ext = context;

    KeAcquireInStackQueuedSpinLock(&dev_ext->dev_lock, &lh);
    virtio_sp_complete_cmd(dev_ext, (ULONG)s1, 0);
    KeReleaseInStackQueuedSpinLock(&lh);
}
#endif
