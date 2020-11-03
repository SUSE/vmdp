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

#include <windows.h>
#include <stdio.h>

#include "pvvxsvc.h"

static PSP_DEVICE_INTERFACE_DETAIL_DATA
dev_get_interface_detail(LPGUID guid)
{
    SP_DEVICE_INTERFACE_DATA dev_data;
    HDEVINFO hw_dev_info;
    PSP_DEVICE_INTERFACE_DETAIL_DATA dev_detail_data = NULL;
    ULONG len, required_len = 0;
    BOOL cc;

    do {
        hw_dev_info = SetupDiGetClassDevs(guid,
                                          NULL,
                                          NULL,
                                          (DIGCF_PRESENT
                                          | DIGCF_DEVICEINTERFACE));

        if (hw_dev_info == INVALID_HANDLE_VALUE) {
            break;
        }

        dev_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

        cc = SetupDiEnumDeviceInterfaces(hw_dev_info,
                                         0,
                                         guid,
                                         0,
                                         &dev_data);

        if (cc == FALSE) {
            break;
        }

        /* Call first time to get needed alloc size. */
        SetupDiGetDeviceInterfaceDetail(hw_dev_info,
                                        &dev_data,
                                        NULL,
                                        0,
                                        &required_len,
                                        NULL);

        dev_detail_data = (PSP_DEVICE_INTERFACE_DETAIL_DATA)LocalAlloc(
            LMEM_FIXED, required_len);

        if (dev_detail_data == NULL) {
            break;
        }

        dev_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        len = required_len;

        cc = SetupDiGetDeviceInterfaceDetail(hw_dev_info,
                                             &dev_data,
                                             dev_detail_data,
                                             len,
                                             &required_len,
                                             NULL);

        if (cc == FALSE) {
            LocalFree(dev_detail_data);
            dev_detail_data = NULL;
            break;
        }
    } while (0);

    if (hw_dev_info != INVALID_HANDLE_VALUE) {
        SetupDiDestroyDeviceInfoList(hw_dev_info);
    }

    return dev_detail_data;
}

HANDLE
dev_open(LPGUID dev_guid)
{
    PSP_DEVICE_INTERFACE_DETAIL_DATA dev_data = NULL;
    HANDLE h_dev = INVALID_HANDLE_VALUE;

    dev_data = dev_get_interface_detail(dev_guid);
    if (dev_data != NULL) {
        h_dev = CreateFile(dev_data->DevicePath,
                           GENERIC_WRITE | GENERIC_READ,
                           0,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
        LocalFree(dev_data);
    }
    return h_dev;
}

BOOL
dev_ioctl(HANDLE h, DWORD ioctl, PVOID in_buf, DWORD in_len,
          PVOID out_buf, DWORD *out_len)
{
    DWORD   ret_len;
    DWORD   obuf_len;
    DWORD   err;
    BOOL    res;

    ret_len = 0;
    obuf_len = out_len ? *out_len : 0;
    res = DeviceIoControl(h,
                          ioctl,
                          in_buf,
                          in_len,
                          out_buf,
                          obuf_len,
                          &ret_len,
                          NULL);
    if (out_len) {
        *out_len = ret_len;
    }
    return res;
}
