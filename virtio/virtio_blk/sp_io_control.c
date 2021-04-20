/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2021 SUSE LLC
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

#include <sp_io_control.h>

static void
sp_firmware_info(PSCSI_REQUEST_BLOCK srb,
                 PSRB_IO_CONTROL srb_ctrl,
                 PFIRMWARE_REQUEST_BLOCK req_blk)
{
    PSTORAGE_FIRMWARE_INFO_V2 firmware_info;

    if (req_blk->DataBufferLength < sizeof(STORAGE_FIRMWARE_INFO_V2)) {
        srb_ctrl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
        srb->SrbStatus = SRB_STATUS_BAD_SRB_BLOCK_LENGTH;
        return;
    }

    firmware_info = (PSTORAGE_FIRMWARE_INFO_V2)(
                    (PUCHAR)srb_ctrl + req_blk->DataBufferOffset);

    if ((firmware_info->Version != STORAGE_FIRMWARE_INFO_STRUCTURE_VERSION_V2)
            || (firmware_info->Size < sizeof(STORAGE_FIRMWARE_INFO_V2))) {
        srb_ctrl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
        srb->SrbStatus = SRB_STATUS_BAD_SRB_BLOCK_LENGTH;
        return;
    }

    RtlZeroMemory((PCHAR)firmware_info, req_blk->DataBufferLength);

    firmware_info->Version = STORAGE_FIRMWARE_INFO_STRUCTURE_VERSION_V2;
    firmware_info->Size = sizeof(STORAGE_FIRMWARE_INFO_V2);
    firmware_info->UpgradeSupport = TRUE;
    firmware_info->SlotCount = 1;
    firmware_info->ActiveSlot = 0;
    firmware_info->PendingActivateSlot = STORAGE_FIRMWARE_INFO_INVALID_SLOT;
    firmware_info->FirmwareShared = FALSE;
    firmware_info->ImagePayloadAlignment = PAGE_SIZE;
    firmware_info->ImagePayloadMaxSize = PAGE_SIZE * 2;

    if ((sizeof(STORAGE_FIRMWARE_INFO_V2)
             + sizeof(STORAGE_FIRMWARE_SLOT_INFO_V2))
        <= req_blk->DataBufferLength) {
        firmware_info->Slot[0].SlotNumber = 0;
        firmware_info->Slot[0].ReadOnly = FALSE;
        StorPortCopyMemory(&firmware_info->Slot[0].Revision, "01234567", 8);
        srb_ctrl->ReturnCode = FIRMWARE_STATUS_SUCCESS;
        srb->SrbStatus = SRB_STATUS_SUCCESS;
    } else {
        req_blk->DataBufferLength = sizeof(STORAGE_FIRMWARE_INFO_V2)
            + sizeof(STORAGE_FIRMWARE_SLOT_INFO_V2);
        srb_ctrl->ReturnCode = FIRMWARE_STATUS_OUTPUT_BUFFER_TOO_SMALL;
        srb->SrbStatus = SRB_STATUS_SUCCESS;
    }
}

static void
sp_firmware_control(PSCSI_REQUEST_BLOCK srb, PSRB_IO_CONTROL srb_ctrl)
{
    PFIRMWARE_REQUEST_BLOCK req_blk;
    ULONG buf_len;

    buf_len = SrbGetDataTransferLength(srb);

    if (buf_len < (sizeof(SRB_IO_CONTROL) + sizeof(FIRMWARE_REQUEST_BLOCK))) {
        srb->SrbStatus = SRB_STATUS_BAD_SRB_BLOCK_LENGTH;
        return;
    }

    req_blk = (PFIRMWARE_REQUEST_BLOCK)(srb_ctrl + 1);

    if ((ULONGLONG)buf_len < ((ULONGLONG)req_blk->DataBufferOffset
                              + (ULONGLONG)req_blk->DataBufferLength)) {
        srb_ctrl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
        srb->SrbStatus = SRB_STATUS_BAD_SRB_BLOCK_LENGTH;
        return;
    }

    if (req_blk->Version < FIRMWARE_REQUEST_BLOCK_STRUCTURE_VERSION) {
        srb_ctrl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
        srb->SrbStatus = SRB_STATUS_BAD_SRB_BLOCK_LENGTH;
        return;
    }

    if (req_blk->DataBufferOffset <
            ALIGN_UP(sizeof(SRB_IO_CONTROL) + sizeof(FIRMWARE_REQUEST_BLOCK),
                     PVOID)) {
        srb_ctrl->ReturnCode = FIRMWARE_STATUS_INVALID_PARAMETER;
        srb->SrbStatus = SRB_STATUS_BAD_SRB_BLOCK_LENGTH;
        return;
    }

    switch (req_blk->Function) {
    case FIRMWARE_FUNCTION_GET_INFO:
        sp_firmware_info(srb, srb_ctrl, req_blk);
        break;
    case FIRMWARE_FUNCTION_DOWNLOAD:
    case FIRMWARE_FUNCTION_ACTIVATE:
    default:
        srb_ctrl->ReturnCode = FIRMWARE_STATUS_SUCCESS;
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    }
}

void
sp_io_control(PSCSI_REQUEST_BLOCK srb)
{
    PSRB_IO_CONTROL srb_ctrl;

    srb_ctrl = (PSRB_IO_CONTROL)SrbGetDataBuffer(srb);
    RPRINTK(DPRTL_ON, ("%s %x: control code %x\n",
                       __func__,
                       srb->TargetId,
                       srb_ctrl->ControlCode));
    if (srb_ctrl->ControlCode == IOCTL_SCSI_MINIPORT_FIRMWARE) {
        sp_firmware_control(srb, srb_ctrl);

    } else {
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    }
}
