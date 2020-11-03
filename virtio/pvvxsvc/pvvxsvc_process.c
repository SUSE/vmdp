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

void
pvvxsvc_create_process(void)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TCHAR cmd[MAX_PATH];
    TCHAR pwd[MAX_PATH];
    TCHAR *start_dir;
    HKEY pkey;
    DWORD cbdata;
    DWORD run_once;
    DWORD no_desktop;

    if (pvvxsvc_open_parameter_key(&pkey)) {
        cbdata = sizeof(cmd);
        if (RegQueryValueEx(pkey,
                            TEXT("CommandLine"),
                            NULL,
                            NULL,
                            (PBYTE)cmd,
                            &cbdata) == ERROR_SUCCESS) {

            start_dir = NULL;
            cbdata = sizeof(pwd);
            if (RegQueryValueEx(pkey,
                                TEXT("PWD"),
                                NULL,
                                NULL,
                                (PBYTE)pwd,
                                &cbdata) == ERROR_SUCCESS) {
                start_dir = pwd;
            }

            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            cbdata = sizeof(DWORD);
            no_desktop = 0;
            RegQueryValueEx(pkey,
                            TEXT("NoDesktopScreen"),
                            NULL,
                            NULL,
                            (PBYTE)&no_desktop,
                            &cbdata);
            if (no_desktop == 0) {
                si.lpDesktop = TEXT("winsta0\\default");
            }
            ZeroMemory(&pi, sizeof(pi));

            CreateProcess(NULL,     /* No module name (use command line) */
                          cmd,      /* Command line */
                          NULL,     /* Process handle not inheritable */
                          NULL,     /* Thread handle not inheritable */
                          FALSE,    /* Set handle inheritance to FALSE */
                          0,        /* No creation flags */
                          NULL,     /* Use parent's environment block */
                          start_dir,/* Use start_dir if non NULL */
                          &si,      /* Pointer to STARTUPINFO structure */
                          &pi);     /* Pointer to PROCESS_INFORMATION struct */

            cbdata = sizeof(DWORD);
            run_once = 0;
            RegQueryValueEx(pkey,
                            TEXT("RunOnce"),
                            NULL,
                            NULL,
                            (PBYTE)&run_once,
                            &cbdata);
            if (run_once) {
                RegDeleteValue(pkey, TEXT("PWD"));
                RegDeleteValue(pkey, TEXT("CommandLine"));
                RegDeleteValue(pkey, TEXT("RunOnce"));
                RegDeleteValue(pkey, TEXT("UseDesktopScreen"));
            }
        }
        RegCloseKey(pkey);
    }
}

void
pvvxsvc_check_self_removal(void)
{
    HKEY pkey;
    DWORD cbdata;
    DWORD rm;

    if (pvvxsvc_open_parameter_key(&pkey)) {
        cbdata = sizeof(DWORD);
        rm = 0;
        RegQueryValueEx(pkey,
                        TEXT("RemoveService"),
                        NULL,
                        NULL,
                        (PBYTE)&rm,
                        &cbdata);
        if (rm) {
            RegSetValueEx(pkey,
                          TEXT("CommandLine"),
                          0,
                          REG_SZ,
                          (PBYTE)TEXT("pvvxsvc.exe remove"),
                          strlen("pvvxsvc.exe remove") * sizeof(TCHAR) + 2);
            pvvxsvc_create_process();
        }
    }
}
