/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2014-2026 SUSE LLC
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

#include "pvvxsvc.h"
#include <stdio.h>

HANDLE g_pvvxsvc_h_balloon_evnt;
HANDLE g_pvvxsvc_h_balloon_thread;
HANDLE g_pvvxsvc_h_balloon_reg_evnt[2];
HANDLE g_pvvxsvc_h_balloon_reg_thread;

static DWORD mem_period;
static DWORD pvvxsvc_start_mem_stats_thread(void);
static void pvvxsvc_stop_balloon_mem_thread(void);
static BOOL pvvxsvc_balloon_reg_update(LPVOID lParam);

static BOOL
pvvxsvc_balloon_mem_stats(LPVOID lParam)
{
    virtio_bln_stat_t mstat[VIRTIO_BALLOON_S_NR] = {0};
    HANDLE h;
    HANDLE h_bln_evt;

    h_bln_evt = (HANDLE)lParam;

    if (!co_init()) {
        pvvxsvc_report_event(PVVXSVC_NAME, TEXT("Co services failed to init"));
        return FALSE;
    }
    do {
        mem_update(mstat);
        h = dev_open((LPGUID)&GUID_DEVINTERFACE_VIRTIO_BALLOON);
        if (h != INVALID_HANDLE_VALUE) {
            if (!dev_ioctl(h, IOCTL_REPORT_MEMORY_USAGE,
                           mstat, (DWORD)sizeof(mstat), NULL, NULL)) {
                pvvxsvc_report_event(PVVXSVC_NAME,
                                     TEXT("IOCTL_REPORT_MEMORY_USAGE failed"));
                break;
            }
            CloseHandle(h);
        }
    } while (WaitForSingleObject(h_bln_evt, mem_period) == WAIT_TIMEOUT);
    co_cleanup();
    return TRUE;
}

static BOOL
pvvxsvc_balloon_reg_update(LPVOID lParam)
{
    HKEY hkey;
    DWORD period;
    DWORD exit_code;
    DWORD exit_loop;
    DWORD cc;
    DWORD evnt;

    UNREFERENCED_PARAMETER(lParam);

    cc = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                      PVVXSVC_SYS_CCS_SERVICES_KEY_WSTR,
                      0,
                      KEY_ALL_ACCESS,
                      &hkey);
    if (cc == ERROR_SUCCESS) {
        exit_loop = 0;
        while (!exit_loop) {
            if (RegNotifyChangeKeyValue(hkey,
                                        FALSE,
                                        REG_NOTIFY_CHANGE_LAST_SET,
                                        g_pvvxsvc_h_balloon_reg_evnt[1],
                                        TRUE) == ERROR_SUCCESS) {
                evnt = WaitForMultipleObjects(2,
                                              g_pvvxsvc_h_balloon_reg_evnt,
                                              FALSE,
                                              INFINITE);
                switch (evnt) {
                case WAIT_OBJECT_0 + 0:
                    exit_loop = 1;
                    break;
                case WAIT_OBJECT_0 + 1:
                    cc = pvvxsvc_balloon_get_mem_stat_period(&period);
                    if (cc == ERROR_SUCCESS) {
                        if (g_pvvxsvc_h_balloon_thread == NULL) {
                            exit_code = 0;
                        } else if (!GetExitCodeThread(
                                g_pvvxsvc_h_balloon_thread,
                                &exit_code)) {
                            exit_code = 0;
                        }
                        if (period == 0) {
                            if (exit_code == STILL_ACTIVE) {
                                pvvxsvc_stop_balloon_mem_thread();
                            }
                            mem_period = 0;
                        } else {
                            mem_period = period;
                            if (exit_code != STILL_ACTIVE) {
                                cc = pvvxsvc_start_mem_stats_thread();
                            }
                        }
                    }
                    break;
                default:
                    break;
                }
            } else {
                break;
            }
        }
        RegCloseKey(hkey);
        return TRUE;
    }
    return FALSE;
}

static DWORD
pvvxsvc_balloon_driver_wants_mem_updates(void)
{
    HANDLE h;
    DWORD len;
    DWORD update;

    h = dev_open((LPGUID)&GUID_DEVINTERFACE_VIRTIO_BALLOON);
    if (h == INVALID_HANDLE_VALUE) {
        /* Just return.  We may be on Xen and Xen doesn't care for mem stats. */
        return 0;
    }

    len = (DWORD)sizeof(DWORD);
    update = 0;
    if (!dev_ioctl(h, IOCTL_WANTS_MEMORY_UPDATES, NULL, 0, &update, &len)) {
        pvvxsvc_report_event(PVVXSVC_NAME,
                             TEXT("IOCTL_WANTS_MEMORY_UPDATES failed"));
    }
    CloseHandle(h);
    return update;
}

static DWORD
pvvxsvc_start_mem_stats_thread(void)
{
    DWORD cc = ERROR_GEN_FAILURE;

    g_pvvxsvc_h_balloon_evnt = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (g_pvvxsvc_h_balloon_evnt) {
        g_pvvxsvc_h_balloon_thread = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)pvvxsvc_balloon_mem_stats,
            g_pvvxsvc_h_balloon_evnt, 0, NULL);
        if (g_pvvxsvc_h_balloon_thread) {
            cc = ERROR_SUCCESS;
        } else {
            CloseHandle(g_pvvxsvc_h_balloon_evnt);
            g_pvvxsvc_h_balloon_evnt = NULL;
        }
    }
    return cc;
}

static DWORD
pvvxsvc_start_reg_update_thread(void)
{
    DWORD cc = ERROR_GEN_FAILURE;

    g_pvvxsvc_h_balloon_reg_evnt[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_pvvxsvc_h_balloon_reg_evnt[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (g_pvvxsvc_h_balloon_reg_evnt[0] && g_pvvxsvc_h_balloon_reg_evnt[1]) {
        g_pvvxsvc_h_balloon_reg_thread = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)pvvxsvc_balloon_reg_update,
            g_pvvxsvc_h_balloon_reg_evnt[0], 0, NULL);
        if (g_pvvxsvc_h_balloon_reg_thread) {
            cc = ERROR_SUCCESS;
        } else {
            CloseHandle(g_pvvxsvc_h_balloon_reg_evnt[0]);
            CloseHandle(g_pvvxsvc_h_balloon_reg_evnt[1]);
            g_pvvxsvc_h_balloon_reg_evnt[0] = NULL;
            g_pvvxsvc_h_balloon_reg_evnt[1] = NULL;
        }
    }
    return cc;
}

static void
pvvxsvc_stop_balloon_mem_thread(void)
{
    if (g_pvvxsvc_h_balloon_evnt) {
        SetEvent(g_pvvxsvc_h_balloon_evnt);
        if (g_pvvxsvc_h_balloon_thread) {
            WaitForSingleObject(g_pvvxsvc_h_balloon_thread, 10000);
            CloseHandle(g_pvvxsvc_h_balloon_thread);
            g_pvvxsvc_h_balloon_thread = NULL;
        }
        CloseHandle(g_pvvxsvc_h_balloon_evnt);
        g_pvvxsvc_h_balloon_evnt = NULL;
    }
}

static void
pvvxsvc_stop_balloon_reg_thread(void)
{
    if (g_pvvxsvc_h_balloon_reg_evnt[0]) {
        SetEvent(g_pvvxsvc_h_balloon_reg_evnt[0]);
        if (g_pvvxsvc_h_balloon_reg_thread) {
            WaitForSingleObject(g_pvvxsvc_h_balloon_reg_thread, 10000);
            CloseHandle(g_pvvxsvc_h_balloon_reg_thread);
            g_pvvxsvc_h_balloon_reg_thread = NULL;
        }
        CloseHandle(g_pvvxsvc_h_balloon_reg_evnt[0]);
        g_pvvxsvc_h_balloon_reg_evnt[0] = NULL;
    }
    if (g_pvvxsvc_h_balloon_reg_evnt[1]) {
        CloseHandle(g_pvvxsvc_h_balloon_reg_evnt[1]);
        g_pvvxsvc_h_balloon_reg_evnt[1] = NULL;
    }
}

DWORD
pvvxsvc_balloon_get_mem_stat_period(DWORD *mp)
{
    HKEY hkey;
    DWORD val_len;
    DWORD cc;

    cc = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                      PVVXSVC_SYS_CCS_SERVICES_KEY_WSTR,
                      0,
                      KEY_ALL_ACCESS,
                      &hkey);
    if (cc == ERROR_SUCCESS) {
        val_len = sizeof(DWORD);
        cc = RegQueryValueEx(hkey,
                             TEXT(PVVX_MEM_STAT_PERIOD),
                             NULL,
                             NULL,
                             (LPBYTE)mp,
                             &val_len);
        RegCloseKey(hkey);

        if (cc == ERROR_FILE_NOT_FOUND) {
            *mp = PVVXSVC_MEM_STAT_PERIOD_DEFAULT;
            cc = pvvxsvc_balloon_set_mem_stat_period(*mp);
            if (cc != ERROR_SUCCESS) {
                *mp = 0;
            }
        }

        *mp *= 1000;
    }
    return cc;
}

DWORD
pvvxsvc_balloon_set_mem_stat_period(DWORD mp)
{
    HKEY hkey;
    DWORD cc = 0;

    cc = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                      PVVXSVC_SYS_CCS_SERVICES_KEY_WSTR,
                      0,
                      KEY_ALL_ACCESS,
                      &hkey);
    if (cc == ERROR_SUCCESS) {
        cc = RegSetValueEx(hkey,
                           TEXT(PVVX_MEM_STAT_PERIOD),
                           0,
                           REG_DWORD,
                           (PBYTE)&mp,
                           sizeof(DWORD));
        RegCloseKey(hkey);
    }
    return cc;
}

void
pvvxsvc_stop_balloon_mem_stats(void)
{
    pvvxsvc_stop_balloon_mem_thread();
    pvvxsvc_stop_balloon_reg_thread();
}

DWORD
pvvxsvc_balloon_mem_stats_init(void)
{
    DWORD cc = 0;

    if (!pvvxsvc_balloon_driver_wants_mem_updates()) {
        return ERROR_GEN_FAILURE;
    }

    cc = pvvxsvc_balloon_get_mem_stat_period(&mem_period);
    if (cc != ERROR_SUCCESS) {
        return cc;
    }

    if (mem_period > 0) {
        cc = pvvxsvc_start_mem_stats_thread();
    }
    if (cc == ERROR_SUCCESS) {
        cc = pvvxsvc_start_reg_update_thread();
    }
    return cc;
}
