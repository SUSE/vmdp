/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2015-2023 SUSE LLC
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

#include <string.h>
#include <hypervisor_is.h>
#include <asm/win_cpuid.h>

#ifdef PVVX
/* For kernel drivers. */

#include <ntddk.h>
#include <winpv_defs.h>
#include <asm/win_compat.h>

static LONG
drv_get_reg_val(ULONG path,
                WCHAR *key_name,
                ULONG data_type,
                WCHAR *val_name,
                void *value,
                DWORD *val_len)
{
    RTL_QUERY_REGISTRY_TABLE paramTable[2] = {0};
    UNICODE_STRING str;
    NTSTATUS status;

    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT
                        | RTL_QUERY_REGISTRY_REQUIRED;
    paramTable[0].Name = val_name;

    if (data_type == REG_DWORD) {
        paramTable[0].EntryContext = value;
        paramTable[0].DefaultType = REG_DWORD;
        paramTable[0].DefaultData = value;
        paramTable[0].DefaultLength = *val_len;
    } else if (data_type == REG_SZ) {
        str.Length = 0;
        str.MaximumLength = (USHORT)*val_len;
        str.Buffer = value;
        paramTable[0].EntryContext = &str;
        paramTable[0].DefaultType = REG_NONE;
        paramTable[0].DefaultData = L"";
        paramTable[0].DefaultLength = 0;
    } else {
        return STATUS_INVALID_PARAMETER;
    }
    status = RtlQueryRegistryValues(path,
                                    key_name,
                                    &paramTable[0],
                                    NULL,
                                    NULL);
    return status;
}

static DWORD
get_reg_hypervisor(void)
{
    NTSTATUS status;
    DWORD hypervisor;
    DWORD len;

    hypervisor = HYPERVISOR_UNKNOWN;
    len = sizeof(DWORD);
    drv_get_reg_val(RTL_REGISTRY_SERVICES,
                    VMDP_WSTR,
                    REG_DWORD,
                    HYPERVISOR_VALUE_NAME_WSTR,
                    &hypervisor,
                    &len);
    /* In the driver case, if we can't figure it out, default to KVM. */
    if (hypervisor == HYPERVISOR_UNKNOWN) {
        hypervisor = HYPERVISOR_KVM;
    }

    return hypervisor;
}

#else
/* For user apps. */

#include <winutil.h>

static LONG
usr_get_reg_val(WCHAR *sub_key_name,
                WCHAR *val_name,
                void *value,
                DWORD *val_len)
{
    LONG cc;
    HKEY hkey;

    cc = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        sub_key_name,
        0,
        KEY_ALL_ACCESS,
        &hkey);
    if (cc == ERROR_SUCCESS) {
        cc = RegQueryValueEx(hkey,
                             val_name,
                             NULL,
                             NULL,
                             (LPBYTE)value,
                             val_len);
        RegCloseKey(hkey);
    }
    return cc;
}

static DWORD
get_reg_hypervisor(void)
{
    WCHAR bios[SMALL_VAL_LEN] = {0};
    LONG cc;
    DWORD hypervisor;
    DWORD len;

    hypervisor = HYPERVISOR_UNKNOWN;
    len = sizeof(bios);
    cc = usr_get_reg_val(RKEY_SYSTEM_BIOS_WSTR,
                         SYSTEM_MANUFACTURER_VALUE_NAME_WSTR,
                         bios,
                         &len);
    if (cc == ERROR_SUCCESS) {
        if (wcsstr(bios, BIOS_QEMU_WSTR)) {
            hypervisor = HYPERVISOR_KVM | HYPERVISOR_REG;
        } else if (wcsstr(bios, BIOS_XEN_WSTR)) {
            hypervisor = HYPERVISOR_XEN | HYPERVISOR_REG;
        }
    }
    return hypervisor;
}

#endif

#ifdef ARM64
DWORD
hypervisor_is(void)
{
    return get_reg_hypervisor();
}
#else
DWORD
hypervisor_is(void)
{
    char signature[13];
    DWORD cpuinfo[4] = {0};
    DWORD hypervisor;

    hypervisor = HYPERVISOR_UNKNOWN;
    __cpuid(cpuinfo, 0x40000000);
    signature[12] = 0;
    *(DWORD *)(signature + 0) = cpuinfo[1];
    *(DWORD *)(signature + 4) = cpuinfo[2];
    *(DWORD *)(signature + 8) = cpuinfo[3];

    if (strcmp("XenVMMXenVMM", signature) == 0) {
        hypervisor = HYPERVISOR_XEN;
    } else if (strcmp("KVMKVMKVM", signature) == 0) {
        hypervisor = HYPERVISOR_KVM;
    } else if (strcmp("Microsoft Hv", signature) == 0) {
        __cpuid(cpuinfo, 0x40000100);
        *(DWORD *)(signature + 0) = cpuinfo[1];
        *(DWORD *)(signature + 4) = cpuinfo[2];
        *(DWORD *)(signature + 8) = cpuinfo[3];
        signature[12] = 0;
        if (strcmp("XenVMMXenVMM", signature) == 0) {
            hypervisor = HYPERVISOR_XEN;
        } else if (strcmp("KVMKVMKVM", signature) == 0) {
            hypervisor = HYPERVISOR_KVM;
        } else {
            hypervisor = get_reg_hypervisor();
        }
    } else if (strcmp("NovellShimHv", signature) == 0) {
        hypervisor = HYPERVISOR_XEN;
    }

    return hypervisor;
}
#endif
