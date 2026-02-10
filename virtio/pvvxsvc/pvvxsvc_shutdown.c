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

static BOOL pvvxsvc_shutdown_system(LPTSTR lpMsg, DWORD delay, BOOL reboot);
static DWORD pvvxsvc_migrate_restore(void);
static DWORD pvvxsvc_install_reboot(void);
static DWORD pvvxsvc_enum_disk(TCHAR *disk);
static DWORD pvvxsvc_swap_nic_driver(void);

DWORD WINAPI
pvvxsvc_shutdown_wait_thread(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);

    DBG_OUTPUT(TEXT("==> pvvxsvc_shutdown_wait_thread ****\n"));
    WaitForSingleObject(g_pvvxsvc_shutdown_stop_event_handle, INFINITE);
    pvvxsvc_report_status(g_pvvxsvc_shutdown_status_handle,
                          &g_pvvxsvc_shutdown_status,
                          SERVICE_STOPPED,
                          NO_ERROR,
                          0);
    DBG_OUTPUT(TEXT("<== pvvxsvc_shutdown_wait_thread ****\n"));
    return 0;
}

void
pvvxsvc_shutdown_wait_loop(void)
{
    HKEY hkey;
    TCHAR *reg_bn_sys_dev_key;
    ULONG notify;
    DWORD delay;
    DWORD shutdown;
    DWORD cbdata;

    /* Are we running in a pvvx environment or traditional? */
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     PVVXBN_SYS_DEVICE_KEY_WSTR,
                     0,
                     KEY_ALL_ACCESS,
                     &hkey) == ERROR_SUCCESS) {
        RegCloseKey(hkey);
        reg_bn_sys_dev_key = PVVXBN_SYS_DEVICE_KEY_WSTR;
    } else {
        reg_bn_sys_dev_key = XENBN_SYS_DEVICE_KEY_WSTR;
    }

    /*
     * Open the registry and write that we want to be notified
     * when a xm shutdown or reboot is requested.
     */
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    reg_bn_sys_dev_key,
                    0,
                    KEY_ALL_ACCESS,
                    &hkey) == ERROR_SUCCESS) {
        notify = XENBUS_WANTS_SHUTDOWN_NOTIFICATION;
        RegSetValueEx(hkey,
                      TEXT(XENBUS_SHUTDOWN_NOTIFICATION_STR),
                      0,
                      REG_DWORD,
                      (PBYTE)&notify,
                      sizeof(notify));
        RegCloseKey(hkey);
    }

    /* RegisterWaitForSingleObject doesn't work.*/

    DBG_OUTPUT(TEXT("    RegOpenKeyEx ****\n"));
    if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                      reg_bn_sys_dev_key,
                                      0,
                                      KEY_ALL_ACCESS,
                                      &hkey)) {
        /*
         * We need to do something here so that the first
         * RegNotifyChangeKeyValue will catch the first
         * change to the registry.
         */
        shutdown = 0;
        cbdata = sizeof(DWORD);
        if (RegQueryValueEx(hkey,
                            TEXT(XENBUS_SHUTDOWN_STR),
                            NULL,
                            NULL,
                            (PBYTE)&shutdown,
                            &cbdata) == ERROR_SUCCESS) {
            if (shutdown == XENBUS_REG_REBOOT_PROMPT_VALUE) {
                /* MessageBox and SetupPrompReboot don't work. */
                cbdata = sizeof(DWORD);
                if (ERROR_SUCCESS != RegQueryValueEx(hkey,
                                                     XENSVC_INSTALL_DELAY_WSTR,
                                                     NULL,
                                                     NULL,
                                                     (LPBYTE)&delay,
                                                     &cbdata)) {
                    delay = XENSVC_INSTALL_SHUTDOWN_TIMEOUT;
                }
                pvvxsvc_install_reboot();
                pvvxsvc_shutdown_system(TEXT("VMDP requires a system reboot"),
                                        delay, TRUE);
            } else if (shutdown == XENBUS_REG_REBOOT_MIGRATE_VALUE) {
                /* MessageBox and SetupPrompReboot don't work. */
                pvvxsvc_migrate_restore();
                pvvxsvc_shutdown_system(TEXT("vmdp requires a reboot"),
                                        10, TRUE);
            }
        }

        while (1) {
            /* Block until the registry is changed. */
            DBG_OUTPUT(TEXT("    RegNotifyChangeKeyValue ****\n"));
            if (ERROR_SUCCESS == RegNotifyChangeKeyValue(
                    hkey,
                    FALSE,
                    REG_NOTIFY_CHANGE_LAST_SET,
                    NULL,
                    FALSE)) {
                /* Read the value to see if we are to shutdown. */
                DBG_OUTPUT(TEXT("    RegQueryValueEx ****\n"));
                cbdata = sizeof(DWORD);
                if (ERROR_SUCCESS == RegQueryValueEx(hkey,
                                                     TEXT(XENBUS_SHUTDOWN_STR),
                                                     NULL,
                                                     NULL,
                                                     (PBYTE)&shutdown,
                                                     &cbdata)) {
                    cbdata = sizeof(DWORD);
                    if (ERROR_SUCCESS != RegQueryValueEx(
                            hkey,
                            XENSVC_SHUTDOWN_DELAY_WSTR,
                            NULL,
                            NULL,
                            (LPBYTE)&delay,
                            &cbdata)) {
                        delay = PVVXSVC_TIMEOUT;
                    }
                    if (shutdown == XENBUS_REG_SHUTDOWN_VALUE) {
                        DBG_OUTPUT(TEXT("    XENBUS_REG_SHUTDOWN_VALUE ***\n"));
                        pvvxsvc_shutdown_system(TEXT("xm shutdown"),
                                                delay, FALSE);
                    } else if (shutdown == XENBUS_REG_REBOOT_VALUE) {
                        DBG_OUTPUT(TEXT("    XENBUS_REG_REBOOT_VALUE ***\n"));
                        pvvxsvc_shutdown_system(TEXT("xm reboot"), delay, TRUE);
                    } else if (shutdown == XENBUS_REG_REBOOT_PROMPT_VALUE) {
                        /* MessageBox and SetupPrompReboot don't work. */
                        cbdata = sizeof(DWORD);
                        if (ERROR_SUCCESS != RegQueryValueEx(
                                hkey,
                                XENSVC_INSTALL_DELAY_WSTR,
                                NULL,
                                NULL,
                                (LPBYTE)&delay,
                                &cbdata)) {
                            delay = XENSVC_INSTALL_SHUTDOWN_TIMEOUT;
                        }
                        pvvxsvc_install_reboot();
                        pvvxsvc_shutdown_system(
                           TEXT("VMDP needs to reboot the system"),
                           delay,
                           TRUE);
                    } else if (shutdown == XENBUS_REG_REBOOT_MIGRATE_VALUE) {
                        /* MessageBox and SetupPrompReboot don't work. */
                        pvvxsvc_migrate_restore();
                        pvvxsvc_shutdown_system(TEXT("vmdp reboot"), 10, TRUE);
                    }

                    /* Clear the value incase of subsequent cancel. */
                    DBG_OUTPUT(TEXT("    RegSetValueEx ***\n"));
                    shutdown = 0;
                    RegSetValueEx(hkey,
                                  TEXT(XENBUS_SHUTDOWN_STR),
                                  0,
                                  REG_DWORD,
                                  (PBYTE)&shutdown,
                                  sizeof(shutdown));
                }
            } else {
                break;
            }
        }
        RegCloseKey(hkey);
    }
}

static BOOL
pvvxsvc_shutdown_system(LPTSTR lpMsg, DWORD delay, BOOL reboot)
{
    HANDLE tknh;                /* handle to process token */
    TOKEN_PRIVILEGES tknp;      /* pointer to token structure */
    DWORD shutdown_attempts;
    BOOL ss_flag;               /* system shutdown flag */

    /*
     * Get the current process token handle so we can get shutdown
     * privilege.
     */
    DBG_OUTPUT(TEXT("==> pvvxsvc_shutdown_system ****\n"));
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tknh)) {
        pvvxsvc_report_event(PVVXSVC_NAME,
                             TEXT("pvvxsvc failed OpenProcessToken"));
        return FALSE;
    }

    /* Get the LUID for shutdown privilege. */
    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
                         &tknp.Privileges[0].Luid);

    tknp.PrivilegeCount = 1;
    tknp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    /* Get shutdown privilege for this process. */
    AdjustTokenPrivileges(tknh, FALSE, &tknp, 0,
                          (PTOKEN_PRIVILEGES) NULL, 0);

    /* Cannot test the return value of AdjustTokenPrivileges. */

    if (GetLastError() != ERROR_SUCCESS) {
        pvvxsvc_report_event(PVVXSVC_NAME,
                             TEXT("pvvxsvc failed AdjustTokenPrivileges"));
        return FALSE;
    }

    /* Display the shutdown dialog box and start the countdown. */
    shutdown_attempts = 0;
    while ((ss_flag = InitiateSystemShutdownEx(
            NULL,       /* shut down local computer */
            lpMsg,      /* message for user */
            delay,
            TRUE,       /* force apps closed */
            reboot,     /* reboot after shutdown */
            SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER |
                SHTDN_REASON_FLAG_PLANNED)) == 0
            && shutdown_attempts < MAX_SHUTDOWN_ATTEMPTS) {
        shutdown_attempts++;
        Sleep(1000);
    }

    if (!ss_flag) {
        pvvxsvc_report_event(PVVXSVC_NAME,
                             TEXT("pvvxsvc failed InitiateSystemShutdown"));
        return FALSE;
    }

    /* Disable shutdown privilege. */
    tknp.Privileges[0].Attributes = 0;
    AdjustTokenPrivileges(tknh, FALSE, &tknp, 0,
                          (PTOKEN_PRIVILEGES) NULL, 0);

    DBG_OUTPUT(TEXT("<== pvvxsvc_shutdown_system ****\n"));
    return TRUE;
}

static DWORD
pvvxsvc_migrate_restore()
{
    WIN32_FIND_DATA fd;
    TCHAR src[MAX_PATH];
    TCHAR dest[MAX_PATH];
    HANDLE fh;
    size_t slen;

    /* Get the complete path to system32. */
    if (FAILED(SHGetFolderPath(NULL,
                               CSIDL_SYSTEM,
                               NULL,
                               SHGFP_TYPE_CURRENT,
                               src))) {
        return 1;
    }

    wcscat_s(src, MAX_PATH, TEXT("\\drivers"));
    StringCchCopy(dest, MAX_PATH, src);
    StringCchLength(src, MAX_PATH, &slen);
    wcscat_s(src, MAX_PATH, TEXT(XENBLK_SETUP));
    wcscat_s(dest, MAX_PATH, TEXT(XENBLK_SYS));
    fh = FindFirstFile(src, &fd);
    if (fh != INVALID_HANDLE_VALUE) {
        FindClose(fh);
        DeleteFile(dest);
        MoveFile(src, dest);
    }

    src[slen] = '\0';
    dest[slen] = '\0';
    wcscat_s(src, MAX_PATH, TEXT(XENSCSI_SETUP));
    wcscat_s(dest, MAX_PATH, TEXT(XENSCSI_SYS));
    fh = FindFirstFile(src, &fd);
    if (fh != INVALID_HANDLE_VALUE) {
        FindClose(fh);
        DeleteFile(dest);
        MoveFile(src, dest);
    }
    return 1;
}

static DWORD
pvvxsvc_install_reboot(void)
{
    DWORD i;
    DWORD additional_wait;
    DWORD done_vbd;
    DWORD done_vscsi;
    HANDLE hndl = NULL;

    hndl = CreateEvent(NULL,    /* default security attributes */
                       TRUE,    /* manual reset event */
                       FALSE,   /* not signaled */
                       NULL);   /* no name */
    done_vbd = 0;
    done_vscsi = 0;
    additional_wait = 0;
    i = 0;
    while (1) {
        WaitForSingleObject(hndl, 1000);
        if (!done_vbd) {
            done_vbd = pvvxsvc_enum_disk(SYS_ENUM_XENVBD_REG_KEY_WSTR);
        }
        if (!done_vscsi) {
            done_vscsi = pvvxsvc_enum_disk(SYS_ENUM_XENVSCSI_REG_KEY_WSTR);
        }
        i++;
        if (done_vbd && done_vscsi) {
            break;
        }
        if (done_vbd || done_vscsi) {
            additional_wait++;
            if (additional_wait == ADDITIONAL_WAIT) {
                break;
            }
        }
        if (i >= MAX_WAIT_LOOPS) {
            break;
        }
    }
    return ERROR_SUCCESS;
}

static DWORD
pvvxsvc_enum_disk(TCHAR *disk)
{
    DWORD i;
    DWORD len;
    DWORD val_len;
    DWORD found;
    DWORD done;
    DWORD config_flags;
    HKEY hkey;
    HKEY disk_key;
    TCHAR key_name[MAX_MATCHING_ID_LEN];

    config_flags = 0xffff;
    done = 0;
    if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                                      disk,
                                      0,
                                      KEY_ALL_ACCESS,
                                      &hkey)) {
        found = 0;
        len = MAX_MATCHING_ID_LEN;
        i = 0;
        while (RegEnumKeyEx(hkey,
                            i,
                            key_name,
                            &len, NULL,
                            NULL,
                            NULL,
                            NULL) == ERROR_SUCCESS) {
            /* Open the enumerate key. */
            if (RegOpenKeyEx(hkey,
                             key_name,
                             0,
                             KEY_ALL_ACCESS,
                             &disk_key) == ERROR_SUCCESS) {
                val_len = sizeof(DWORD);
                if (RegQueryValueEx(disk_key,
                                    CONFIG_FLAGS_WSTR,
                                    NULL,
                                    NULL,
                                    (LPBYTE)&config_flags,
                                    &val_len) == ERROR_SUCCESS) {
                    if (config_flags == 0) {
                        found++;
                    }
                }
                RegCloseKey(disk_key);
            }
            i++;
            len = MAX_MATCHING_ID_LEN;
        }

        if (i != 0 && i == found) {
            done = 1;
        }

        RegCloseKey(hkey);
    }
    return done;
}
