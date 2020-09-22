/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2016-2020 SUSE LLC
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

#ifndef _VXSB_ENTRY_H
#define _VXSB_ENTRY_H

#include <ntddk.h>
#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <storport.h>

#include <asm/win_compat.h>
#include <asm/win_cpuid.h>
#include <hypervisor_is.h>
#include <win_pvvx.h>
#include <winpv_defs.h>
#include <storport_reg.h>
#ifdef PVVXBLK
#include "vxblk_ver.h"

#define PVVX_LOADING_STR "pvvxblk loading for"
#define PVVX_VIRTIO_DRV_STR "virtio_blk"
#define PVVX_XEN_DRV_STR "xenblk"
#else
#include "vxscsi_ver.h"

#define PVVX_LOADING_STR "pvvxscsi loading for"
#define PVVX_VIRTIO_DRV_STR "virtio_scsi"
#define PVVX_XEN_DRV_STR "xenscsi"
#endif
#include <win_vxprintk.h>

ULONG KvmDriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath);

ULONG XenDriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath);

void virtio_dbg_printk(char *_fmt, ...);

#endif
