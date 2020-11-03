/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2016-2020 SUSE LLC
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

#include <storport_reg.h>

NTSTATUS
sp_registry_read(void *dev_ext, PUCHAR val_name, DWORD r_type,
                 void *val, ULONG *len)
{
    NTSTATUS status;
    PUCHAR reg_buf;
    BOOLEAN ret;

    reg_buf = StorPortAllocateRegistryBuffer(dev_ext, len);
    if (reg_buf != NULL) {
        ret = StorPortRegistryRead(dev_ext, val_name, 1, r_type, reg_buf, len);
        if (ret) {
            switch (r_type) {
            case REG_DWORD:
                /*
                 * StorPortRegistryRead succeeds even if the reg value does
                 * not exist.  The read value gets set to -1 in this case.
                 */
                if (*(DWORD *)reg_buf != (DWORD)-1) {
                    *(DWORD *)val = *(DWORD *)reg_buf;
                    status = STATUS_SUCCESS;
                } else {
                    status = STATUS_DATA_ERROR;
                    DPRINTK(DPRTL_ON,
                            ("StorPortRegistryRead: value %s not present\n",
                            val_name));
                    DPRINTK(DPRTL_ON,
                            ("  len %d, read 0x%x, using default of 0x%x\n",
                            *len, *(DWORD *)reg_buf, *(DWORD *)val));
                }
                DPRINTK(DPRTL_ON, ("\t%s: 0x%x\n", val_name, *(DWORD *)val));
                break;
            default:
                status = STATUS_INVALID_PARAMETER;
                PRINTK(("StorPortRegistryRead: unknown type %d\n", r_type));
                break;
            }
        } else {
            if (*len == 0) {
                status = STATUS_UNSUCCESSFUL;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            DPRINTK(DPRTL_ON,
                   ("StorPortRegistryRead %s: unsuccessful, len %d\n",
                    val_name, *len));
        }
        StorPortFreeRegistryBuffer(dev_ext, reg_buf);
    } else {
        status = STATUS_NO_MEMORY;
        PRINTK(("StorPortRegistryRead: failed to alloc buffer for value %s\n",
                val_name));
    }
    return status;
}

static NTSTATUS
sp_open_key(PWSTR key_wstr, HANDLE *registryKey, DWORD operation)
{
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;

    RtlInitUnicodeString(&keyName, key_wstr);

    InitializeObjectAttributes(&objectAttributes,
                               &keyName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    if (operation == FILE_OPEN) {
        return ZwOpenKey(registryKey, KEY_ALL_ACCESS, &objectAttributes);
    } else if (operation == FILE_CREATE) {
        return ZwCreateKey(registryKey,
                           KEY_ALL_ACCESS,
                           &objectAttributes,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           NULL);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
sp_get_reg_value(PWSTR key, PWSTR name, DWORD *value)
{
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(DWORD)];
    HANDLE registryKey;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    NTSTATUS status;
    ULONG len;

    DPRINTK(DPRTL_ON, ("%s - IN\n", __func__));

    status = sp_open_key(key, &registryKey, FILE_OPEN);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&valueName, name);
        status = ZwQueryValueKey(registryKey,
                                 &valueName,
                                 KeyValuePartialInformation,
                                 buffer,
                                 sizeof(buffer),
                                 &len);
        if (NT_SUCCESS(status)) {
            *value = *((DWORD *)
                &(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
        }
        ZwClose(registryKey);
    }
    DPRINTK(DPRTL_ON, ("%s - OUT\n", __func__));
    return status;
}

NTSTATUS
sp_set_reg_value(PWSTR key, PWSTR name, DWORD value)
{
    HANDLE registryKey;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    NTSTATUS status;

    DPRINTK(DPRTL_ON, ("%s - IN\n", __func__));

    status = sp_open_key(key, &registryKey, FILE_CREATE);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&valueName, name);
        status = ZwSetValueKey(registryKey,
                               &valueName,
                               0,
                               REG_DWORD,
                               &value,
                               sizeof(DWORD));
        if (!NT_SUCCESS(status)) {
            PRINTK(("Reg set value filed for %ws, %x\n", name, status));
        }
        ZwClose(registryKey);
    } else {
        PRINTK(("Reg open key failed for %ws, %x\n", key, status));
    }
    DPRINTK(DPRTL_ON, ("%s - OUT\n", __func__));
    return status;
}
