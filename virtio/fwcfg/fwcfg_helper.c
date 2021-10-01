/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2018 Virtuozzo International GmbH
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

static void
fwcfg_read_blob(PVOID ioBase, UINT16 key, PVOID buf, ULONG count)
{
    WRITE_PORT_USHORT((PUSHORT)FW_CFG_CTL(ioBase), key);
    READ_PORT_BUFFER_UCHAR(FW_CFG_DAT(ioBase), (PUCHAR)buf, count);
}

NTSTATUS
fwcfg_check_sig(PVOID ioBase)
{
    UCHAR signature[FW_CFG_SIG_SIZE];

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    fwcfg_read_blob(ioBase, FW_CFG_SIGNATURE, signature, FW_CFG_SIG_SIZE);
    if (memcmp(signature, FW_CFG_QEMU, FW_CFG_SIG_SIZE)) {
        RPRINTK(DPRTL_INIT, ("<-- %s %s: failed memcmp\n",
                             VDEV_DRIVER_NAME, __func__));
        return STATUS_INVALID_SIGNATURE;
    }

    RPRINTK(DPRTL_INIT, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return STATUS_SUCCESS;
}

NTSTATUS
fwcfg_check_features(PVOID ioBase, UINT32 features)
{
    UINT32 f_bitmap;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    fwcfg_read_blob(ioBase, FW_CFG_ID, &f_bitmap, sizeof(f_bitmap));
    if ((f_bitmap & features) != features) {
        RPRINTK(DPRTL_INIT,
            ("<-- %s %s: features %x %x STATUS_DEVICE_CONFIGURATION_ERROR\n",
            VDEV_DRIVER_NAME, __func__, f_bitmap, features));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    RPRINTK(DPRTL_INIT, ("<-- %s %s: features 0x%x\n",
                         VDEV_DRIVER_NAME, __func__, f_bitmap));
    return STATUS_SUCCESS;
}

static UINT64
fwcfg_read_dma_reg(PVOID ioBase)
{
    UINT64 dma_reg;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    ((UINT32 *)&dma_reg)[0] = READ_PORT_ULONG((PULONG)FW_CFG_DMA(ioBase));
    ((UINT32 *)&dma_reg)[1] = READ_PORT_ULONG((PULONG)FW_CFG_DMA(ioBase) + 1);
    RPRINTK(DPRTL_INIT, ("<-- %s %s: dma reg 0x%llx\n",
                         VDEV_DRIVER_NAME, __func__, dma_reg));

    return RtlUlonglongByteSwap(dma_reg);
}

static VOID
fwcfg_write_dma_reg(PVOID ioBase, UINT64 val)
{
    RPRINTK(DPRTL_INIT, ("--> %s %s: val 0x%llx\n",
                         VDEV_DRIVER_NAME, __func__, val));
    val = RtlUlonglongByteSwap(val);
    WRITE_PORT_ULONG((PULONG)FW_CFG_DMA(ioBase), ((PULONG)&val)[0]);
    WRITE_PORT_ULONG((PULONG)FW_CFG_DMA(ioBase) + 1, ((PULONG)&val)[1]);
    RPRINTK(DPRTL_INIT, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
}

NTSTATUS
fwcfg_check_dma(PVOID ioBase)
{
    UINT64 test;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    test = fwcfg_read_dma_reg(ioBase);
    if (test != FW_CFG_QEMU_DMA) {
        RPRINTK(DPRTL_INIT, ("<-- %s %s: test %llx\n",
                             VDEV_DRIVER_NAME, __func__, test));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    RPRINTK(DPRTL_INIT, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return STATUS_SUCCESS;
}

/* At the end of this routine selector points at first file entry */
static UINT32
fwcfg_get_entries_num(PVOID ioBase)
{
    UINT32 num;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    fwcfg_read_blob(ioBase, FW_CFG_FILE_DIR, &num, sizeof(num));
    num = RtlUlongByteSwap(num);
    RPRINTK(DPRTL_INIT, ("<-- %s %s: num %d\n",
                         VDEV_DRIVER_NAME, __func__, num));

    return num;
}

NTSTATUS
fwcfg_find_entry(PVOID ioBase, const char *name,
                 PUSHORT index, ULONG size)
{
    UINT16 i;
    UINT32 total;
    FWCfgFile f;

    RPRINTK(DPRTL_INIT, ("--> %s %s: %s ioBase %x size %x\n",
                         VDEV_DRIVER_NAME, __func__, name, ioBase, size));
    total = fwcfg_get_entries_num(ioBase);
    if (total > MAXUINT16) {
        RPRINTK(DPRTL_INIT, ("<-- %s %s: STATUS_DEVICE_CONFIGURATION_ERROR\n",
                             VDEV_DRIVER_NAME, __func__));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    for (i = 0; i < total; i++) {
        READ_PORT_BUFFER_UCHAR(FW_CFG_DAT(ioBase), (PUCHAR)&f, sizeof(f));
        RPRINTK(DPRTL_INIT, ("    %s %s: i %d f.name %s\n",
                             VDEV_DRIVER_NAME, __func__, i, f.name));
        if (strncmp(f.name, name, FW_CFG_MAX_FILE_PATH) == 0) {
            if (RtlUlongByteSwap(f.size) == size) {
                *index = RtlUshortByteSwap(f.select);
                RPRINTK(DPRTL_INIT,
                        ("<-- %s %s: name %s total %d index %d size %d\n",
                        VDEV_DRIVER_NAME, __func__, name, total, *index, size));
                return STATUS_SUCCESS;
            }
            RPRINTK(DPRTL_INIT, ("<-- %s %s: STATUS_INVALID_PARAMETER\n",
                                 VDEV_DRIVER_NAME, __func__));
            return STATUS_INVALID_PARAMETER;
        }
    }

    RPRINTK(DPRTL_INIT, ("<-- %s %s: STATUS_NOT_FOUND\n",
                         VDEV_DRIVER_NAME, __func__));
    return STATUS_NOT_FOUND;
}

static NTSTATUS
fwcfg_dma_send(PVOID ioBase, LONGLONG data_pa, USHORT index,
               UINT32 size, FWCfgDmaAccess *pDmaAccess, LONGLONG dmaAccess_pa)
{
    UINT16 ctrl = FW_CFG_DMA_CTL_SELECT | FW_CFG_DMA_CTL_WRITE;
    NTSTATUS status;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    pDmaAccess->control = RtlUlongByteSwap(((UINT32)index << 16UL) | ctrl);
    pDmaAccess->length = RtlUlongByteSwap(size);
    pDmaAccess->address = RtlUlonglongByteSwap(data_pa);

    fwcfg_write_dma_reg(ioBase, (UINT64)dmaAccess_pa);

    ctrl = RtlUlongByteSwap(pDmaAccess->control) & MAXUINT16;
    if (!ctrl) {
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_IO_DEVICE_ERROR;
    }

    RPRINTK(DPRTL_INIT, ("<-- %s %s: status %x\n",
                         VDEV_DRIVER_NAME, __func__, status));
    return status;
}

NTSTATUS
fwcfg_get_kdbg(PFDO_DEVICE_EXTENSION fdx)
{
    PUCHAR minidump;
    ULONG32 kdbg_offset;
    ULONG32 kdbg_size;
    CONTEXT context = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    RPRINTK(DPRTL_ON, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    minidump = EX_ALLOC_POOL(VPOOL_NON_PAGED, 0x40000, 'pmdm');
    if (minidump == NULL) {
        RPRINTK(DPRTL_ON, ("<-- %s %s: status %x\n",
                           VDEV_DRIVER_NAME, __func__, status));
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, minidump);

    kdbg_offset = *(PULONG32)(minidump + MINIDUMP_OFFSET_KDBG_OFFSET);
    kdbg_size = *(PULONG32)(minidump + MINIDUMP_OFFSET_KDBG_SIZE);

    fdx->kdbg = EX_ALLOC_POOL(VPOOL_NON_PAGED, kdbg_size, 'gbdk');
    if (fdx->kdbg == NULL) {
        status = STATUS_MEMORY_NOT_ALLOCATED;
    } else {
        memcpy(fdx->kdbg, minidump + kdbg_offset, kdbg_size);
    }

    ExFreePool(minidump);

    RPRINTK(DPRTL_ON, ("<-- %s %s: offset %x size %x status %x\n",
        VDEV_DRIVER_NAME, __func__, kdbg_offset, kdbg_size, status));

    return status;
}

static NTSTATUS
fwcfg_vm_core_info_fill(FDO_DEVICE_EXTENSION *fdx)
{
    NTSTATUS status;
    PUCHAR hdr_buf;
    ULONG bufSizeNeeded;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));

    hdr_buf = (PUCHAR)fdx->vmci_data.pNote
        + FIELD_OFFSET(VMCI_ELF64_NOTE, n_desc);
    status = KeInitializeCrashDumpHeader(DUMP_TYPE_FULL,
                                         0,
                                         hdr_buf,
                                         DUMP_HDR_SIZE,
                                         &bufSizeNeeded);
    if (!NT_SUCCESS(status)) {
        PRINTK(("<-- %s %s: failed to get header, status %x\n",
                VDEV_DRIVER_NAME, __func__, status));
        return status;
    }

    /*
     * Original KDBG pointer was saved in header by system.
     * BugcheckParameter1 field is unused in live system and will be filled by
     * QEMU. So the pointer to decoded KDBG can be stored in this field.
     */
    *(PULONG64)(hdr_buf + DUMP_HDR_OFFSET_BUGCHECK_PARAM1) = (ULONG64)fdx->kdbg;

    RPRINTK(DPRTL_INIT, ("<-- %s %s: status %x\n",
                         VDEV_DRIVER_NAME, __func__, status));
    return status;
}

NTSTATUS
fwcfg_vm_core_info_send(FDO_DEVICE_EXTENSION *fdx)
{
    NTSTATUS status;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    status = fwcfg_dma_send(fdx->ioBase,
                            fdx->vmci_data.vmci_pa,
                            fdx->index,
                            sizeof(VMCOREINFO),
                            fdx->dma_access,
                            fdx->dma_access_pa);
    RPRINTK(DPRTL_INIT, ("<-- %s %s: status %x\n",
                         VDEV_DRIVER_NAME, __func__, status));

    return status;
}

NTSTATUS
fwcfg_evt_device_d0_entry(FDO_DEVICE_EXTENSION *fdx)
{
    NTSTATUS status;
    PVMCI_ELF64_NOTE note = fdx->vmci_data.pNote;
    PVMCOREINFO pVmci = fdx->vmci_data.pVmci;

    RPRINTK(DPRTL_INIT, ("--> %s %s\n", VDEV_DRIVER_NAME, __func__));
    note->n_namesz = sizeof(VMCI_ELF_NOTE_NAME);
    note->n_descsz = DUMP_HDR_SIZE;
    note->n_type = 0;
    memcpy(note->n_name, VMCI_ELF_NOTE_NAME, note->n_namesz);

    pVmci->host_fmt = 0;
    pVmci->guest_fmt = VMCOREINFO_FORMAT_ELF;
    pVmci->paddr = fdx->vmci_data.note_pa;
    pVmci->size = sizeof(VMCI_ELF64_NOTE);

    status = fwcfg_vm_core_info_fill(fdx);
    if (!NT_SUCCESS(status)) {
        RPRINTK(DPRTL_INIT, ("<-- %s %s: fail VMCoreInfoFill\n",
                             VDEV_DRIVER_NAME, __func__));
        return status;
    }

    status = fwcfg_vm_core_info_send(fdx);

    RPRINTK(DPRTL_INIT, ("<-- %s %s\n", VDEV_DRIVER_NAME, __func__));
    return status;
}
