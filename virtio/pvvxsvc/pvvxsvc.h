/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2008-2012 Novell, Inc.
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

#ifndef _PVVXSVC_H_
#define _PVVXSVC_H_

#ifndef RC_INVOKED
#include <windows.h>
#include <winioctl.h>
#include <tchar.h>
#include <strsafe.h>
#include <shellapi.h>
#include <setupapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <process.h>
#include <initguid.h>
#include <winpv_defs.h>
#include <win_stdint.h>
#include "virtio_balloon_pub.h"
#endif

#define PVVXSVC_NAME                            TEXT("pvvxsvc")
#define PVVXSVC_DISPLAY_NAME                    TEXT("Pvvx Service")
#define PVVXSVC_DESCRIPTION                     \
    TEXT("Monitors Xen shutdown/reboot requests. Launches specified processes.")
#define SYSTEM_CCS_SERVICES_KEY_WSTR            \
    L"SYSTEM\\CurrentControlSet\\Services"

#define XENBLK_SYS "\\xenblk.sys"
#define XENBLK_SETUP "\\xenblk.setup"
#define XENSCSI_SYS "\\xenscsi.sys"
#define XENSCSI_SETUP "\\xenscsi.setup"

#define SYS_ENUM_XENVBD_REG_KEY_WSTR    \
    L"System\\CurrentControlSet\\Enum\\XEN\\Type_vbd"
#define SYS_ENUM_XENVSCSI_REG_KEY_WSTR  \
    L"System\\CurrentControlSet\\Enum\\XEN\\Type_vscsi"

#define MAX_MATCHING_ID_LEN     48
#define MAX_SVC_LEN             80
#define MAX_SVC_IMG_LEN         160
#define MAX_WAIT_LOOPS          300
#define ADDITIONAL_WAIT         10
#define CONFIG_FLAGS_WSTR       L"ConfigFlags"

#define PVVXSVC_TIMEOUT 0
#define XENSVC_INSTALL_SHUTDOWN_TIMEOUT 30
#define PVVXSVC_MEM_STAT_PERIOD_DEFAULT 0

#define MBOX_PVVXSVC_TITLE      4001
#define MBOX_PVVXSVC_USAGE      4002
#define MBOX_PVVXSVC_MSTATS     4003
#define MBOX_PVVXSVC_IS_RUNNING 4004

#ifdef DBG
#define DBG_OUTPUT OutputDebugString
#else
#define DBG_OUTPUT
#endif

#define PVVXSVC_INSTALL_P       "install"
#define PVVXSVC_REMOVE_P        "remove"
#define PVVXSVC_UNINSTALL_P     "uninstall"
#define PVVXSVC_SERVICE_NAME_P  "-s"
#define PVVXSVC_MEMORY_PERIOD_P "-mp"
#define PVVXSVC_MEM_STAT_P      "-m"

#define PVVXSVC_SERVICE_NAME_S  " -s "

#define PVVXSVC_RUN_AS_SERVICE_F    0x0
#define PVVXSVC_INSTALL_F           0x1
#define PVVXSVC_REMOVE_F            0x2
#define PVVXSVC_USAGE_F             0x4
#define PVVXSVC_MEM_PERIOD_F        0x8
#define PVVXSVC_MEM_STAT_F          0x10
#define PVVXSVC_IS_RUNNING_F        0x20

#define MAX_SHUTDOWN_ATTEMPTS       300 /* 1 attempt per second for 5 minutes */
extern SERVICE_STATUS g_pvvxsvc_shutdown_status;
extern SERVICE_STATUS_HANDLE g_pvvxsvc_shutdown_status_handle;
extern HANDLE g_pvvxsvc_shutdown_stop_event_handle;
extern HANDLE g_pvvxsvc_shutdown_wait_handle;
extern HANDLE g_pvvxsvc_h_balloon_evnt;
extern HANDLE g_pvvxsvc_h_balloon_thread;
extern HANDLE g_pvvxsvc_h_balloon_reg_evnt[];
extern HANDLE g_pvvxsvc_h_balloon_reg_thread;
extern TCHAR *reg_bn_sys_dev_key;
extern TCHAR pvvxsvc_name[];

VOID pvvxsvc_report_status(SERVICE_STATUS_HANDLE,
    SERVICE_STATUS *,
    DWORD,
    DWORD,
    DWORD);
VOID pvvxsvc_report_event(LPCWSTR, LPTSTR);
void pvvxsvc_remove(void);
void pvvxsvc_wait_for_status(DWORD status);

/* xensvc_dispatch.c */
VOID WINAPI pvvxsvc_dispatch(DWORD, LPTSTR *);

/* xensvc_shutdown.c */
void pvvxsvc_shutdown_wait_loop(void);
DWORD WINAPI pvvxsvc_shutdown_wait_thread(LPVOID param);

/* xensvc_process.c */
void pvvxsvc_create_process(void);
void pvvxsvc_check_self_removal(void);

/* xensvc_bln.c */
DWORD pvvxsvc_balloon_get_mem_stat_period(DWORD *mp);
DWORD pvvxsvc_balloon_set_mem_stat_period(DWORD mp);
DWORD pvvxsvc_balloon_mem_stats_init(void);
void pvvxsvc_stop_balloon_mem_stats(void);

/* xensvc_utils.c */
HANDLE dev_open(LPGUID dev_guid);
BOOL dev_ioctl(HANDLE h, DWORD ioctl, PVOID ibuf, DWORD in_len,
               PVOID obuf, DWORD *out_len);

/* xensvc_memstats.cpp */
#ifdef __cplusplus
extern "C" {
#endif

BOOL co_init(void);
void co_cleanup(void);
BOOL mem_update(virtio_bln_stat_t *mstat);

#ifdef __cplusplus
}
#endif

#endif  /* _PVVXSVC_H_ */
