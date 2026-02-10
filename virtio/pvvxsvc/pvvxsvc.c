/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2008-2012 Novell, Inc.
 * Copyright 2012-2026 SUSE LLC
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

SERVICE_STATUS  g_pvvxsvc_shutdown_status;

static TCHAR    g_pvvxsvc_err[MAX_PATH];
TCHAR           pvvxsvc_name[MAX_SVC_LEN] = PVVXSVC_NAME;
TCHAR           pvvxsvc_img_path[MAX_SVC_LEN] = TEXT(PVVXSVC_SERVICE_NAME_S);
TCHAR           *pvvxsvc_img;

static LPCWSTR g_pvvxsvc_name[] = {
    pvvxsvc_name,
};
static DWORD g_pvvxsvc_number = sizeof(g_pvvxsvc_name) / sizeof(LPCWSTR);

static LPCWSTR g_pvvxsvc_display_name[] = {
    pvvxsvc_name,
};

static SERVICE_STATUS *g_pvvxsvc_status[] = {
    &g_pvvxsvc_shutdown_status,
};

static void process_arglist(
    int argc, LPWSTR *wargv, DWORD *cmd, DWORD *mp, DWORD *fb);
static void pvvxsvc_msg_box(UINT id);
static DWORD pvvxsvc_is_running(void);
static VOID pvvxsvc_install(void);
static LPTSTR pvvxsvc_get_last_error_text(LPTSTR lpszBuf, DWORD dwSize);
static DWORD pvvxsvc_finish_first_boot(DWORD cmd);

/*
 * Purpose:
 *   Entry point for the process
 *
 * Parameters:
 *   None
 *
 * Return value:
 *   None
 */
int __cdecl
wmain()
{
    /* Add any additional services for the process to this table. */
    SERVICE_TABLE_ENTRY dispatch_table[] = {
        {PVVXSVC_NAME, (LPSERVICE_MAIN_FUNCTION)pvvxsvc_dispatch},
        {NULL, NULL}
    };
    LPWSTR *wargv;
    DWORD cmd;
    DWORD mp;
    DWORD fb;
    int argc;

    DBG_OUTPUT(TEXT("==> wmain ****\n"));

    wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (NULL == wargv) {
        DBG_OUTPUT(TEXT("    CommandLineToArgvW filed ****\n"));
        return 0;
    }

    process_arglist(argc, wargv, &cmd, &mp, &fb);
    LocalFree(wargv);
    switch (cmd) {
    case PVVXSVC_RUN_AS_SERVICE_F:
        break;
    case PVVXSVC_INSTALL_F:
        pvvxsvc_install();
        return 1;
    case PVVXSVC_REMOVE_F:
        pvvxsvc_finish_first_boot(fb);
        pvvxsvc_remove();
        return 1;
    case PVVXSVC_MEM_STAT_F:
        if (pvvxsvc_balloon_mem_stats_init() == ERROR_SUCCESS) {
            pvvxsvc_msg_box(MBOX_PVVXSVC_MSTATS);
            pvvxsvc_stop_balloon_mem_stats();
        }
        return 1;
    case PVVXSVC_MEM_PERIOD_F:
        pvvxsvc_balloon_set_mem_stat_period(mp);
        return 1;
    case PVVXSVC_IS_RUNNING_F:
        pvvxsvc_msg_box(MBOX_PVVXSVC_IS_RUNNING);
        return 0;
    case PVVXSVC_USAGE_F:
        pvvxsvc_msg_box(MBOX_PVVXSVC_USAGE);
        return 0;
    default:
        pvvxsvc_msg_box(MBOX_PVVXSVC_USAGE);
        return 0;
    }

    /*
     * This call returns when the service has stopped.
     * The process should simply terminate when the call returns.
     */
    DBG_OUTPUT(TEXT("    StartServiceCtrlDispatcher ****\n"));
    if (!StartServiceCtrlDispatcher(dispatch_table)) {
        DBG_OUTPUT(TEXT("    StartServiceCtrlDispatcher failed ****\n"));
        return 0;
    }
    DBG_OUTPUT(TEXT("    wmain CloseHandle ****\n"));
    DBG_OUTPUT(TEXT("<== wmain ****\n"));
    return 1;
}

static void
process_arglist(int argc, LPWSTR *wargv, DWORD *cmd, DWORD *mp, DWORD *fb)
{
    int i;

    *fb = 0;
    *cmd = PVVXSVC_RUN_AS_SERVICE_F;
    for (i = 1; i < argc; i++) {
        if (_wcsicmp(wargv[i], TEXT(PVVXSVC_INSTALL_P)) == 0) {
            DBG_OUTPUT(TEXT("    calling pvvxsvc_install ****\n"));
            *cmd |= PVVXSVC_INSTALL_F;
        } else if (_wcsicmp(wargv[i], TEXT(PVVXSVC_REMOVE_P)) == 0) {
            DBG_OUTPUT(TEXT("    calling pvvxsvc_remove ****\n"));
            *cmd |= PVVXSVC_REMOVE_F;
        } else if (_wcsicmp(wargv[i], TEXT(PVVXSVC_UNINSTALL_P)) == 0) {
            DBG_OUTPUT(TEXT("    calling pvvxsvc_remove ****\n"));
            *cmd |= PVVXSVC_REMOVE_F;
        } else if (_wcsicmp(wargv[i], TEXT(PVVXSVC_MEM_STAT_P)) == 0) {
            if (pvvxsvc_is_running()) {
                *cmd = PVVXSVC_IS_RUNNING_F;
                break;
            }
            *cmd |= PVVXSVC_MEM_STAT_F;
        } else if (_wcsicmp(wargv[i], TEXT(PVVXSVC_SERVICE_NAME_P)) == 0) {
            if (_wcsnicmp(wargv[0],
                          PVVXSVC_FIRSTBOOT_DIR,
                          lstrlen(PVVXSVC_FIRSTBOOT_DIR)) == 0) {
                *fb = PVVXSVC_FIRSTBOOT_F;
            }
            if (i + 1 < argc) {
                i++;
                if (_wcsicmp(wargv[i], TEXT(PVVXSVC_INSTALL_P)) == 0
                        || (_wcsicmp(wargv[i], TEXT(PVVXSVC_REMOVE_P)) == 0)) {
                    *cmd = PVVXSVC_USAGE_F;
                    break;
                } else if (SUCCEEDED(
                        StringCchCopy(pvvxsvc_name, MAX_SVC_LEN, wargv[i]))) {
                    StringCchCat(pvvxsvc_img_path, MAX_SVC_LEN, wargv[i]);
                    pvvxsvc_img = pvvxsvc_img_path;
                } else {
                    *cmd = PVVXSVC_USAGE_F;
                    break;
                }
            } else {
                *cmd = PVVXSVC_USAGE_F;
                break;
            }
        } else if (_wcsicmp(wargv[i], TEXT(PVVXSVC_MEMORY_PERIOD_P)) == 0) {
            if (i + 1 < argc) {
                i++;
                if (swscanf_s(wargv[i], TEXT("%u"), mp) != EOF) {
                    *cmd |= PVVXSVC_MEM_PERIOD_F;
                } else {
                    *cmd = PVVXSVC_USAGE_F;
                    break;
                }
            } else {
                *cmd = PVVXSVC_USAGE_F;
                break;
            }
        }
    }
}

void
static pvvxsvc_msg_box(UINT id)
{
    HINSTANCE hinst;
    TCHAR title[16];
    TCHAR msg[128];

    hinst = GetModuleHandle(NULL);

    LoadString(hinst, MBOX_PVVXSVC_TITLE, title,
        sizeof(title) / sizeof(title[0]) - 1);
    LoadString(hinst, id, msg, sizeof(msg) / sizeof(msg[0]) - 1);

    MessageBox(NULL, msg, title, MB_OK);
}

static DWORD
pvvxsvc_is_running(void)
{
    SERVICE_STATUS svc_status;
    SC_HANDLE sc_svc;
    SC_HANDLE sc_mgr;
    DWORD cc = 0;

    sc_mgr = OpenSCManager(NULL,
                           NULL,
                           SC_MANAGER_ALL_ACCESS);
    if (sc_mgr) {
        sc_svc = OpenService(sc_mgr,
                             PVVXSVC_NAME,
                             SERVICE_ALL_ACCESS);
        if (sc_svc) {
            if (QueryServiceStatus(sc_svc, &svc_status)) {
                if (svc_status.dwCurrentState != SERVICE_STOPPED) {
                    cc = 1;
                }
            }
            CloseServiceHandle(sc_svc);
        }
        CloseServiceHandle(sc_mgr);
    }
    return cc;
}

static VOID
pvvxsvc_install()
{
    SC_HANDLE sc_mgr;
    SC_HANDLE sc_svc;
    TCHAR sz_path[MAX_PATH];
    TCHAR bin_path[MAX_PATH];
    SERVICE_DESCRIPTION desc;
    QUERY_SERVICE_CONFIG *qsc;
    DWORD i;
    DWORD bytes_needed;

    DBG_OUTPUT(TEXT("==> pvvxsvc_install ****\n"));
    if (!GetModuleFileName(NULL, sz_path, MAX_PATH)) {
        DBG_OUTPUT(TEXT("    GetModuleFileName failed ****\n"));
        return;
    }

    /* Get a handle to the SCM database. */
    DBG_OUTPUT(TEXT("    OpenSCManager ****\n"));
    sc_mgr = OpenSCManager(
        NULL,                       /* local computer */
        NULL,                       /* ServicesActive database */
        SC_MANAGER_ALL_ACCESS);     /* full access rights */

    if (NULL == sc_mgr) {
        DBG_OUTPUT(TEXT("    OpenSCManager failed ****\n"));
        return;
    }

    for (i = 0; i < g_pvvxsvc_number; i++) {
        DBG_OUTPUT(TEXT("    CreateService ****\n\t"));
        DBG_OUTPUT(g_pvvxsvc_name[i]);
        sc_svc = CreateService(
            sc_mgr,                     /* SCM database */
            g_pvvxsvc_name[i],          /* name of service */
            g_pvvxsvc_display_name[i],  /* service name to display */
            SERVICE_ALL_ACCESS,         /* desired access */
            SERVICE_WIN32_OWN_PROCESS,  /* service type */
            SERVICE_AUTO_START,         /* start type */
            SERVICE_ERROR_NORMAL,       /* error control type */
            sz_path,                    /* path to service's binary */
            NULL,                       /* no load ordering group */
            NULL,                       /* no tag identifier */
            NULL,                       /* no dependencies */
            NULL,                       /* LocalSystem account */
            NULL);                      /* no password */

        if (sc_svc == NULL) {
            DBG_OUTPUT(TEXT("\n    CreateService failed ****\n"));
        } else {
            DBG_OUTPUT(TEXT("\n    CreateService succeeded ****\n"));
            desc.lpDescription = PVVXSVC_DESCRIPTION;
            ChangeServiceConfig2(sc_svc, SERVICE_CONFIG_DESCRIPTION, &desc);

            /* See if we need to change the ImagePath */
            if (pvvxsvc_img) {
                if (!QueryServiceConfig(
                        sc_svc,
                        NULL,
                        0,
                        &bytes_needed)) {
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        qsc = (LPQUERY_SERVICE_CONFIG) LocalAlloc(
                                LMEM_FIXED, bytes_needed);
                        if (qsc) {
                            if (QueryServiceConfig(
                                    sc_svc,
                                    qsc,
                                    bytes_needed,
                                    &bytes_needed)) {
                                if (SUCCEEDED(StringCchCopy(bin_path,
                                                MAX_PATH,
                                                qsc->lpBinaryPathName))) {
                                    if (SUCCEEDED(StringCchCat(bin_path,
                                                    MAX_PATH,
                                                    pvvxsvc_img))) {
                                        ChangeServiceConfig(
                                            sc_svc,
                                            SERVICE_NO_CHANGE,
                                            SERVICE_NO_CHANGE,
                                            SERVICE_NO_CHANGE,
                                            bin_path,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL);
                                    }
                                }
                            }
                            LocalFree(qsc);
                        }
                    }
                }
            }
            CloseServiceHandle(sc_svc);
        }
    }

    CloseServiceHandle(sc_mgr);
    DBG_OUTPUT(TEXT("<== pvvxsvc_install ****\n"));
}

void
pvvxsvc_remove(void)
{
    SC_HANDLE   sc_svc;
    SC_HANDLE   sc_mgr;
    TCHAR       *reg_bn_sys_dev_key;
    DWORD       i;
    ULONG       notify;
    HKEY        hkey;

    DBG_OUTPUT(TEXT("==> pvvxsvc_remove ****\n"));
    sc_mgr = OpenSCManager(
        NULL,                   /* machine (NULL == local) */
        NULL,                   /* database (NULL == default) */
        SC_MANAGER_CONNECT);    /* access required */

    if (sc_mgr) {
        for (i = 0; i < g_pvvxsvc_number; i++) {
            sc_svc = OpenService(sc_mgr, g_pvvxsvc_name[i],
                DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);

            if (sc_svc) {
                /* try to stop the service */
                if (ControlService(sc_svc, SERVICE_CONTROL_STOP,
                    g_pvvxsvc_status[i])) {
                    DBG_OUTPUT(g_pvvxsvc_name[i]);
                    Sleep(1000);

                    while (QueryServiceStatus(sc_svc, g_pvvxsvc_status[i])) {
                        if (g_pvvxsvc_status[i]->dwCurrentState ==
                                SERVICE_STOP_PENDING){
                            DBG_OUTPUT(TEXT("."));
                            Sleep(1000);
                        } else {
                            break;
                        }
                    }

                    if (g_pvvxsvc_status[i]->dwCurrentState ==
                            SERVICE_STOPPED) {
                        DBG_OUTPUT(TEXT("\n    stopped.\n"));
                    } else {
                        DBG_OUTPUT(TEXT("\n    failed to stop.\n"));
                    }
                }

                /* now remove the service */
                if (DeleteService(sc_svc)) {
                    DBG_OUTPUT(TEXT("    Service deleted.\n"));
                } else {
                    DBG_OUTPUT(TEXT("    DeleteService failed\n"));
                }

                CloseServiceHandle(sc_svc);

                /* Are we running in a pvvx environment or traditional? */
                if (RegOpenKeyEx(
                        HKEY_LOCAL_MACHINE,
                        PVVXBN_SYS_DEVICE_KEY_WSTR,
                        0,
                        KEY_ALL_ACCESS,
                        &hkey) == ERROR_SUCCESS) {
                    RegCloseKey(hkey);
                    reg_bn_sys_dev_key = PVVXBN_SYS_DEVICE_KEY_WSTR;
                } else {
                    reg_bn_sys_dev_key = XENBN_SYS_DEVICE_KEY_WSTR;
                }

                /* We no longer want shutdown notifications. */
                if (ERROR_SUCCESS == RegOpenKeyEx(
                    HKEY_LOCAL_MACHINE,
                    reg_bn_sys_dev_key,
                    0,
                    KEY_ALL_ACCESS,
                    &hkey))
                {
                    notify = XENBUS_NO_SHUTDOWN_NOTIFICATION;
                    RegSetValueEx(
                        hkey,
                        TEXT(XENBUS_SHUTDOWN_NOTIFICATION_STR),
                        0,
                        REG_DWORD,
                        (PBYTE)&notify,
                        sizeof(notify));

                    RegCloseKey(hkey);
                }
            } else {
                DBG_OUTPUT(TEXT("    OpenService failed\n"));
            }
        }

        CloseServiceHandle(sc_mgr);
    } else {
        DBG_OUTPUT(TEXT("OpenSCManager failed\n"));
    }

    DBG_OUTPUT(TEXT("<== pvvxsvc_remove ****\n"));
}

static LPTSTR
pvvxsvc_get_last_error_text(LPTSTR lpszBuf, DWORD dwSize)
{
    DWORD dwRet;
    LPTSTR lpszTemp = NULL;

    DBG_OUTPUT(TEXT("==> pvvxsvc_get_last_error_text ****\n"));
    dwRet = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
        NULL,
        GetLastError(),
        LANG_NEUTRAL,
        (LPTSTR)&lpszTemp,
        0,
        NULL);

    /* supplied buffer is not long enough */
    if (!dwRet || ((long)dwSize < (long)dwRet + 14)) {
        lpszBuf[0] = TEXT('\0');
    } else {
        if (NULL != lpszTemp) {
            /* remove cr and newline character */
            lpszTemp[lstrlen(lpszTemp) - 2] = TEXT('\0');
            _stprintf_s(lpszBuf, dwSize, TEXT("%s (0x%x)"),
                lpszTemp, GetLastError());
        }
    }

    if (NULL != lpszTemp) {
        LocalFree((HLOCAL) lpszTemp);
    }

    DBG_OUTPUT(TEXT("<== pvvxsvc_get_last_error_text ****\n"));
    return lpszBuf;
}

/*
 * Purpose:
 *   Sets the current service status and reports it to the SCM.
 *
 * Parameters:
 *   dwCurrentState - The current state (see SERVICE_STATUS)
 *   dwWin32ExitCode - The system error code
 *   dwWaitHint - Estimated time for pending operation,
 *     in milliseconds
 *
 * Return value:
 *   None
 */
VOID
pvvxsvc_report_status(SERVICE_STATUS_HANDLE ss_handle,
    SERVICE_STATUS *status,
    DWORD dwCurrentState,
    DWORD dwWin32ExitCode,
    DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    DBG_OUTPUT(TEXT("==> pvvxsvc_report_status ****\n"));
    status->dwCurrentState = dwCurrentState;
    status->dwWin32ExitCode = dwWin32ExitCode;
    status->dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING) {
        status->dwControlsAccepted = 0;
    } else {
        status->dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }

    if ((dwCurrentState == SERVICE_RUNNING) ||
        (dwCurrentState == SERVICE_STOPPED)) {
        status->dwCheckPoint = 0;
    } else {
        status->dwCheckPoint = dwCheckPoint++;
    }

    DBG_OUTPUT(TEXT("     SetServiceStatusn"));
    SetServiceStatus(ss_handle, status);
    DBG_OUTPUT(TEXT("<== pvvxsvc_report_status ****\n"));
}

/*
 * Purpose:
 *   Logs messages to the event log
 *
 * Parameters:
 *   szFunction - name of function that failed
 *
 * Return value:
 *   None
 *
 * Remarks:
 *   The service must have an entry in the Application event log.
 */
VOID
pvvxsvc_report_event(LPCWSTR service, LPTSTR szFunction)
{
    HANDLE hEventSource;
    LPCTSTR lpszStrings[1];
    TCHAR Buffer[80];

    DBG_OUTPUT(TEXT("==> pvvxsvc_report_event ****\n"));

    hEventSource = RegisterEventSource(NULL, service);
    if (NULL != hEventSource) {
        StringCchPrintf(Buffer, 80, TEXT("%s: error %d"),
            szFunction, GetLastError());

        lpszStrings[0] = Buffer;

        DBG_OUTPUT(szFunction);

        ReportEvent(hEventSource,   /* event log handle */
            EVENTLOG_ERROR_TYPE,    /* event type */
            0,                      /* event category */
            0,                      /* event identifier */
            NULL,                   /* no security identifier */
            1,                      /* size of lpszStrings array */
            0,                      /* no binary data */
            lpszStrings,            /* array of strings */
            NULL);                  /* no binary data */

        DeregisterEventSource(hEventSource);
    }
    DBG_OUTPUT(TEXT("<== pvvxsvc_report_event ****\n"));
}

void
pvvxsvc_wait_for_status(DWORD status)
{
    SC_HANDLE   sc_svc;
    SC_HANDLE   sc_mgr;
    DWORD       i;
    DWORD       loop_cnt;

    sc_mgr = OpenSCManager(
        NULL,                   /* machine (NULL == local) */
        NULL,                   /* database (NULL == default) */
        SC_MANAGER_CONNECT);    /* access required */

    loop_cnt = 0;
    if (sc_mgr) {
        for (i = 0; i < g_pvvxsvc_number; i++) {
            sc_svc = OpenService(sc_mgr, g_pvvxsvc_name[i],
                DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (sc_svc) {
                while (QueryServiceStatus(sc_svc, g_pvvxsvc_status[i])) {
                    if (g_pvvxsvc_status[i]->dwCurrentState != status) {
                        Sleep(1000); /* 1 second */
                    } else {
                        break;
                    }
                    if (loop_cnt > 10) {
                        break;
                    }
                    loop_cnt++;
                }
                CloseServiceHandle(sc_svc);
            }
        }
        CloseServiceHandle(sc_mgr);
    }
}

static DWORD
pvvxsvc_finish_first_boot(DWORD fb)
{
    WIN32_FIND_DATA fd;
    HANDLE fh;
    HANDLE fv;
    TCHAR startdir[MAX_PATH];
    TCHAR curdir[MAX_PATH];
    TCHAR vexe[MAX_PATH];

    if (!(fb & PVVXSVC_FIRSTBOOT_F)) {
        return 0;
    }

    fh = FindFirstFile(PVVXSVC_FB_SCRIPTS, &fd);
    if (fh != INVALID_HANDLE_VALUE) {
        FindClose(fh);
        return 0;
    }
    fh = FindFirstFile(PVVXSVC_FB_SCRIPTS_DONE, &fd);
    if (fh != INVALID_HANDLE_VALUE) {
        FindClose(fh);
        return 0;
    }

    GetCurrentDirectory(MAX_PATH, startdir);
    if (SetCurrentDirectory(PVVXSVC_FB_SCRIPTS_DONE_DIR)) {
        GetCurrentDirectory(MAX_PATH, curdir);
        fh = FindFirstFile(TEXT("\\vmdp*exe"), &fd);
        if (fh != INVALID_HANDLE_VALUE) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                vexe[0] = 0;
                PathAppend(vexe, TEXT("\\"));
                PathAppend(vexe, fd.cFileName);
                _wspawnl(_P_WAIT,
                         vexe,
                         vexe,
                         TEXT("-y"),
                         NULL);

                fv = FindFirstFile(TEXT("vmdp*"), &fd);
                if (fv != INVALID_HANDLE_VALUE) {
                    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        PathAppend(curdir, fd.cFileName);
                        SetCurrentDirectory(curdir);

                        /* Simple way to indicate that this section of code
                         * was run. The directory is not used for anything
                         * other than to indicate this code was run.
                         */
                        CreateDirectory(TEXT("pvvxsvc_dir"), NULL);

                        _wspawnl(_P_WAIT,
                                 TEXT("setup.exe"),
                                 TEXT("setup.exe"),
                                 TEXT("/eula_accepted"),
                                 TEXT("/no_reboot"),
                                 NULL);
                    }
                    FindClose(fv);
                }
            }
            FindClose(fh);
        }
    }
    SetCurrentDirectory(startdir);
    return 1;
}

