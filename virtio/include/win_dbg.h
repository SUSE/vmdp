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

#ifndef _WINPV_DBG_H
#define _WINPV_DBG_H

#define SYSTEM_START_OPTIONS_LEN        256
#define SYSTEM_START_OPTIONS_WSTR       L"SystemStartOptions"
#define SAFE_BOOT_WSTR                  L"SAFEBOOT"
#define NULL_WSTR                       L""

#define PVCTRL_DBG_PRINT_MASK_STR      "dbg_print_mask"
#define PVCTRL_CDBG_PRINT_MASK_STR     "cdbg_print_mask"
#define PVCTRL_CDBG_PRINT_LIMIT_STR    "cdbg_print_limit"
#define PVCTRL_DBG_PRINT_MASK_WSTR      L"dbg_print_mask"
#define XENBUS_PRINTK_PORT              0xe9
#define VIRTIO_DEBUG_PORT               ((PUCHAR)0x3F8)

/* Debug print masks */
#define DPRTL_OFF           0x00000000
#define DPRTL_ON            0x00000001
#define DPRTL_INIT          0x00000002
#define DPRTL_UNEXPD        0x00000004
#define DPRTL_INT           0x00000008
#define DPRTL_PCI           0x00000010
#define DPRTL_RING          0x00000020
#define DPRTL_IO            0x00000040
#define DPRTL_MM            0x00000080
#define DPRTL_CONFIG        0x00000100
#define DPRTL_CHKSUM        0x00000200
#define DPRTL_TRC           0x00000400
#define DPRTL_RX            0x00000800
#define DPRTL_TX            0x00001000
#define DPRTL_PNP           0x00002000
#define DPRTL_PWR           0x00004000
#define DPRTL_EVTCHN        0x00008000
#define DPRTL_WAIT          0x00010000
#define DPRTL_XS            0x00020000
#define DPRTL_PROBE         0x00040000
#define DPRTL_WATCH         0x00080000
#define DPRTL_COND          0x00100000
#define DPRTL_FRNT          0x00200000
#define DPRTL_LSO           0x00400000
#define DPRTL_PRI           0x00800000
#define DPRTL_RXDPC         0x01000000
#define DPRTL_TXDPC         0x02000000
#define DPRTL_DPC           0x03000000
#define DPRTL_RSS           0x04000000
#define DPRTL_UNEXPDTX      0x08000000

#endif
