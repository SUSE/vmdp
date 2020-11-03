/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2014-2020 SUSE LLC
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

SERVICE_STATUS_HANDLE   g_pvvxsvc_shutdown_status_handle;
HANDLE                  g_pvvxsvc_shutdown_stop_event_handle;
HANDLE                  g_pvvxsvc_shutdown_wait_handle;


static VOID pvvxsvc_dispatch_init(DWORD, LPTSTR *);
static VOID WINAPI pvvxsvc_dispatch_ctrl_handler(DWORD);

VOID WINAPI
pvvxsvc_dispatch(DWORD dwArgc, LPTSTR *lpszArgv)
{
    DBG_OUTPUT(TEXT("==> pvvxsvc_dispatch ****\n"));
    g_pvvxsvc_shutdown_status_handle = RegisterServiceCtrlHandler(
        PVVXSVC_NAME,
        pvvxsvc_dispatch_ctrl_handler);

    if (!g_pvvxsvc_shutdown_status_handle) {
        pvvxsvc_report_event(PVVXSVC_NAME,
                             TEXT("RegisterServiceCtrlHandler"));
        return;
    }

    /* These SERVICE_STATUS members remain as set here */
    g_pvvxsvc_shutdown_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_pvvxsvc_shutdown_status.dwServiceSpecificExitCode = 0;

    /* Report initial status to the SCM */
    pvvxsvc_report_status(g_pvvxsvc_shutdown_status_handle,
                          &g_pvvxsvc_shutdown_status,
                          SERVICE_START_PENDING,
                          NO_ERROR,
                          3000);

    /* Perform service-specific initialization and work. */
    pvvxsvc_dispatch_init(dwArgc, lpszArgv);
    DBG_OUTPUT(TEXT("<== pvvxsvc_dispatch ****\n"));
}

static VOID
pvvxsvc_dispatch_init(DWORD dwArgc, LPTSTR *lpszArgv)
{
    /*
     * Be sure to periodically call pvvxsvc_report_status() with
     * SERVICE_START_PENDING. If initialization fails, call
     * pvvxsvc_report_status with SERVICE_STOPPED.
     *
     * Create an event. The control handler function,
     * pvvxsvc_dispatch_ctrl_handler, signals this event when it
     * receives the stop control code.
     */
    DBG_OUTPUT(TEXT("==> pvvxsvc_dispatch_init ****\n"));
    g_pvvxsvc_shutdown_stop_event_handle = CreateEvent(
        NULL,       /* default security attributes */
        TRUE,       /* manual reset event */
        FALSE,      /* not signaled */
        NULL);      /* no name */

    if (g_pvvxsvc_shutdown_stop_event_handle == NULL) {
        pvvxsvc_report_status(g_pvvxsvc_shutdown_status_handle,
                              &g_pvvxsvc_shutdown_status,
                              SERVICE_STOPPED,
                              NO_ERROR,
                              0);
        return;
    }

    /* Report running status when initialization is complete. */
    pvvxsvc_report_status(g_pvvxsvc_shutdown_status_handle,
                          &g_pvvxsvc_shutdown_status,
                          SERVICE_RUNNING,
                          NO_ERROR,
                          0);

    g_pvvxsvc_shutdown_wait_handle = CreateThread(NULL,
                                                  0,
                                                  pvvxsvc_shutdown_wait_thread,
                                                  NULL,
                                                  0,
                                                  NULL);
    if (g_pvvxsvc_shutdown_wait_handle) {
        CloseHandle(g_pvvxsvc_shutdown_wait_handle);
    } else {
        return;
    }

    /* Create any process that is listed in the registry. */
    pvvxsvc_create_process();

    /* Check to see if we are to remove the service. */
    pvvxsvc_check_self_removal();

    pvvxsvc_balloon_mem_stats_init();

    /* Now wait to see if we get a shutdown/reboot request from the host. */
    pvvxsvc_shutdown_wait_loop();

    DBG_OUTPUT(TEXT("<== pvvxsvc_dispatch_init ****\n"));
}

static VOID WINAPI
pvvxsvc_dispatch_ctrl_handler(DWORD dwCtrl)
{
    DBG_OUTPUT(TEXT("==> pvvxsvc_dispatch_ctrl_handler ****\n"));
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        pvvxsvc_report_status(g_pvvxsvc_shutdown_status_handle,
                              &g_pvvxsvc_shutdown_status,
                              SERVICE_STOP_PENDING,
                              NO_ERROR,
                              0);

        /* Signal the service to stop. */
        SetEvent(g_pvvxsvc_shutdown_stop_event_handle);

        /* Stop the balloon mem stats thread if running. */
        pvvxsvc_stop_balloon_mem_stats();
        return;

    case SERVICE_CONTROL_INTERROGATE:
        /* Fall through to send current status. */
        break;
    default:
        break;
    }

    pvvxsvc_report_status(g_pvvxsvc_shutdown_status_handle,
                          &g_pvvxsvc_shutdown_status,
                          g_pvvxsvc_shutdown_status.dwCurrentState,
                          NO_ERROR,
                          0);
    DBG_OUTPUT(TEXT("<== pvvxsvc_dispatch_ctrl_handler ****\n"));
}

#ifdef DBG
static DWORD
pvvxsvc_open_parameter_key(HKEY *pkey)
{
    HKEY hkey;
    HKEY skey;
    DWORD cc;

    cc = 0;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     SYSTEM_CCS_SERVICES_KEY_WSTR,
                     0,
                     KEY_ALL_ACCESS,
                     &hkey) == ERROR_SUCCESS)
    {
        if (RegOpenKeyEx(hkey,
                         pvvxsvc_name,
                         0,
                         KEY_ALL_ACCESS,
                         &skey) == ERROR_SUCCESS)
        {
            if (RegOpenKeyEx(skey,
                             TEXT("Parameters"),
                             0,
                             KEY_ALL_ACCESS,
                             pkey) == ERROR_SUCCESS)
            {
                cc = 1;
            }
            RegCloseKey(skey);
        }
        RegCloseKey(hkey);
    }
    return cc;
}

HKEY pvvxsvc_key;
static DWORD
pvvxsvc_open_pvvxsvc_key(void)
{
    HKEY hkey;
    HKEY skey;
    DWORD cc;

    cc = 0;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     SYSTEM_CCS_SERVICES_KEY_WSTR,
                     0,
                     KEY_ALL_ACCESS,
                     &hkey) == ERROR_SUCCESS)
    {
        if (RegOpenKeyEx(hkey,
                         pvvxsvc_name,
                         0,
                         KEY_ALL_ACCESS,
                         &pvvxsvc_key) == ERROR_SUCCESS)
        {
            cc = 1;
        }
        RegCloseKey(hkey);
    }
    return cc;
}

static void
pvvxsvc_set_pvvxsvc_step(DWORD val)
{
    if (pvvxsvc_key) {
        RegSetValueEx(pvvxsvc_key,
                      TEXT("step"),
                      0,
                      REG_DWORD,
                      (PBYTE)&val,
                      sizeof(DWORD));
    }
}
#endif
