/*-
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

#ifndef _FWCFG_HELPER_H
#define _FWCFG_HELPER_H

#define FW_CFG_CTL_OFFSET       0x00
#define FW_CFG_DAT_OFFSET       0x01
#define FW_CFG_DMA_OFFSET       0x04

#define FW_CFG_CTL(p)           ((PUCHAR)(p) + FW_CFG_CTL_OFFSET)
#define FW_CFG_DAT(p)           ((PUCHAR)(p) + FW_CFG_DAT_OFFSET)
#define FW_CFG_DMA(p)           ((PUCHAR)(p) + FW_CFG_DMA_OFFSET)

#define FW_CFG_SIG_SIZE         4
#define FW_CFG_MAX_FILE_PATH    56

#define FW_CFG_SIGNATURE        0x00
#define FW_CFG_ID               0x01
#define FW_CFG_FILE_DIR         0x19

#define FW_CFG_VERSION          0x01
#define FW_CFG_VERSION_DMA      0x02

#define FW_CFG_DMA_CTL_ERROR    0x01
#define FW_CFG_DMA_CTL_READ     0x02
#define FW_CFG_DMA_CTL_SKIP     0x04
#define FW_CFG_DMA_CTL_SELECT   0x08
#define FW_CFG_DMA_CTL_WRITE    0x10

#define FW_CFG_QEMU             "QEMU"
#define FW_CFG_QEMU_DMA         0x51454d5520434647ULL

#define ENTRY_NAME              "etc/vmcoreinfo"
#define VMCI_ELF_NOTE_NAME      "VMCOREINFO"
#define VMCOREINFO_FORMAT_ELF   0x1
#define DUMP_HDR_SIZE                   (PAGE_SIZE * 2)
#define MINIDUMP_OFFSET_KDBG_OFFSET     (DUMP_HDR_SIZE + 0x70)
#define MINIDUMP_OFFSET_KDBG_SIZE       (DUMP_HDR_SIZE + 0x74)
#define DUMP_HDR_OFFSET_BUGCHECK_PARAM1 0x40
#define ROUND_UP(x, n) (((x) + (n) - 1) & (-(n)))

#pragma pack(push, 1)
typedef struct FWCfgFile {
    UINT32  size;
    UINT16  select;
    UINT16  reserved;
    char    name[FW_CFG_MAX_FILE_PATH];
} FWCfgFile;

typedef struct FWCfgDmaAccess {
    UINT32 control;
    UINT32 length;
    UINT64 address;
} FWCfgDmaAccess;

typedef struct VMCOREINFO {
    UINT16 host_fmt;
    UINT16 guest_fmt;
    UINT32 size;
    UINT64 paddr;
} VMCOREINFO, *PVMCOREINFO;

typedef struct VMCI_ELF64_NOTE {
    UINT32  n_namesz;
    UINT32  n_descsz;
    UINT32  n_type;
    UCHAR   n_name[ROUND_UP(sizeof(VMCI_ELF_NOTE_NAME), 4)];
    UCHAR   n_desc[ROUND_UP(DUMP_HDR_SIZE, 4)];
} VMCI_ELF64_NOTE, *PVMCI_ELF64_NOTE;
#pragma pack(pop)

typedef struct CBUF_DATA {
    VMCI_ELF64_NOTE note;
    VMCOREINFO vmci;
    FWCfgDmaAccess fwcfg_da;
} CBUF_DATA, *PCBUF_DATA;

typedef struct VMCI_DATA {
    PVMCOREINFO         pVmci;
    PVMCI_ELF64_NOTE    pNote;
    LONGLONG            vmci_pa;
    LONGLONG            note_pa;
} VMCI_DATA, *PVMCI_DATA;

ULONG NTAPI KeCapturePersistentThreadState(PCONTEXT Context,
                                           PKTHREAD Thread,
                                           ULONG BugCheckCode,
                                           ULONG BugCheckParameter1,
                                           ULONG BugCheckParameter2,
                                           ULONG BugCheckParameter3,
                                           ULONG BugCheckParameter4,
                                           PVOID VirtualAddress);

#endif
