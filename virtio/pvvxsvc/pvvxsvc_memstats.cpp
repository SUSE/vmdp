/*-
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
#include <stdio.h>
#include <Wbemidl.h>

IWbemLocator *g_locator;
IWbemServices *g_server;

#pragma warning(default : 4201)

void co_cleanup(void)
{
    if (g_locator) {
        g_locator->Release();
        g_locator = NULL;
    }
    if (g_server) {
        g_server->Release();
        g_server = NULL;
    }
    CoUninitialize();
}

BOOL co_init(void)
{
    HRESULT status  = S_OK;
    BOOL initialized;

    status = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(status)) {
        printf("Cannot initialize COM");
        return FALSE;
    }
    initialized = TRUE;

    status = CoInitializeSecurity(NULL,
                                 -1,
                                 NULL,
                                 NULL,
                                 RPC_C_AUTHN_LEVEL_PKT,
                                 RPC_C_IMP_LEVEL_IMPERSONATE,
                                 NULL,
                                 EOAC_NONE,
                                 0);

    if (FAILED(status)) {
        printf("Cannot initialize security\n");
        return FALSE;
    }

    status = CoCreateInstance(CLSID_WbemLocator,
                              NULL,
                              CLSCTX_INPROC_SERVER,
                              IID_IWbemLocator,
                              (LPVOID *)&g_locator);
    if (FAILED(status)) {
        printf("Cannot create instance");
        return FALSE;
    }

    status = g_locator->ConnectServer(L"root\\cimv2",
                                      NULL,
                                      NULL,
                                      0L,
                                      0L,
                                      NULL,
                                      NULL,
                                      &g_server);
    if (FAILED(status)) {
        printf("Cannot connect to wmi server");
        co_cleanup();
        return FALSE;
    }

    status = CoSetProxyBlanket(g_server,
                               RPC_C_AUTHN_WINNT,
                               RPC_C_AUTHZ_NONE,
                               NULL,
                               RPC_C_AUTHN_LEVEL_CALL,
                               RPC_C_IMP_LEVEL_IMPERSONATE,
                               NULL,
                               EOAC_NONE);
    if (FAILED(status)) {
        printf("Cannot set proxy blanket");
        co_cleanup();
        return FALSE;
    }
    return TRUE;
}

BOOL
mem_update(virtio_bln_stat_t *mstat)
{
    MEMORYSTATUSEX statex = {sizeof(statex)};
    IEnumWbemClassObject *enumerator = NULL;
    IWbemClassObject *memory = NULL;
    ULONG retcnt;
    VARIANT var_val = {0};
    HRESULT status  = S_OK;

    status = g_server->ExecQuery(
        L"WQL",
        L"SELECT * FROM Win32_PerfFormattedData_PerfOS_Memory",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &enumerator);

    if (FAILED(status)) {
        printf("Cannot execute query");
        return FALSE;
    }

    while (enumerator) {
        status = enumerator->Next(WBEM_INFINITE,
                                  1L,
                                  &memory,
                                  &retcnt);
        if (retcnt == 0) {
            break;
        }

        status = memory->Get(L"PagesInputPerSec",
                             0,
                             &var_val,
                             NULL,
                             NULL);
        if (FAILED(status) || (var_val.vt == VT_NULL)) {
            printf("Cannot get PagesInputPerSec");
            var_val.vt =  -1;
        }
        mstat[VIRTIO_BALLOON_S_SWAP_IN].tag = VIRTIO_BALLOON_S_SWAP_IN;
        mstat[VIRTIO_BALLOON_S_SWAP_IN].val = var_val.ullVal;

        status = memory->Get(L"PagesOutputPerSec",
                             0,
                             &var_val,
                             NULL,
                             NULL);
        if (FAILED(status) || (var_val.vt == VT_NULL)) {
            printf("Cannot get PagesOutputPerSec");
            var_val.vt =  -1;
        }
        mstat[VIRTIO_BALLOON_S_SWAP_OUT].tag = VIRTIO_BALLOON_S_SWAP_OUT;
        mstat[VIRTIO_BALLOON_S_SWAP_OUT].val = var_val.ullVal;

        status = memory->Get(L"PageReadsPerSec",
                             0,
                             &var_val,
                             NULL,
                             NULL);

        if (FAILED(status) || (var_val.vt == VT_NULL)) {
            printf("Cannot get PageReadsPerSec");
            var_val.vt =  -1;
        }
        mstat[VIRTIO_BALLOON_S_MAJFLT].tag = VIRTIO_BALLOON_S_MAJFLT;
        mstat[VIRTIO_BALLOON_S_MAJFLT].val = var_val.ullVal;

        status = memory->Get(L"PageFaultsPerSec",
                             0,
                             &var_val,
                             NULL,
                             NULL);

        if (FAILED(status) || (var_val.vt == VT_NULL)) {
            printf("Cannot get PageFaultsPerSec");
            var_val.vt =  -1;
        }
        mstat[VIRTIO_BALLOON_S_MINFLT].tag = VIRTIO_BALLOON_S_MINFLT;
        mstat[VIRTIO_BALLOON_S_MINFLT].val = var_val.ullVal;

        if (GlobalMemoryStatusEx(&statex)) {
            mstat[VIRTIO_BALLOON_S_MEMFREE].tag = VIRTIO_BALLOON_S_MEMFREE;
            mstat[VIRTIO_BALLOON_S_MEMFREE].val = statex.ullAvailPhys;

            mstat[VIRTIO_BALLOON_S_MEMTOT].tag = VIRTIO_BALLOON_S_MEMTOT;
            mstat[VIRTIO_BALLOON_S_MEMTOT].val = statex.ullTotalPhys;
        } else {
            mstat[VIRTIO_BALLOON_S_MEMFREE].tag = VIRTIO_BALLOON_S_MEMFREE;
            mstat[VIRTIO_BALLOON_S_MEMFREE].val = -1;

            mstat[VIRTIO_BALLOON_S_MEMTOT].tag = VIRTIO_BALLOON_S_MEMTOT;
            mstat[VIRTIO_BALLOON_S_MEMTOT].val = -1;
        }
        memory->Release();
    }
    enumerator->Release();
    return TRUE;
}
