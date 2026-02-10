/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2016-2026 SUSE LLC
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

#include "vxsb_entry.h"

#if (NTDDI_VERSION > NTDDI_WIN7)
sp_DRIVER_INITIALIZE DriverEntry;
#else
ULONG DriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath);
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

#ifdef DBG
uint32_t dbg_print_mask = DPRTL_ON | DPRTL_INIT | DPRTL_UNEXPD | DPRTL_COND;
uint32_t conditional_times_printed;
uint32_t conditional_times_to_print_limit = CONDITIONAL_TIMES_TO_PRINT_LIMIT;
#else
uint32_t dbg_print_mask;
#endif

static KSPIN_LOCK vxsb_print_lock;
static UINT_PTR vxsb_print_port;

void (*printk)(char *_fmt, ...);

static void
vxsb_print_str(char *str)
{
    PUCHAR port;
    KLOCK_QUEUE_HANDLE lh;
    char *c;

    /*
     * Spin locks don't protect against irql > 2.  So if we come in at a
     * higl level, just print it and we'll have to maually sort out the
     * the possible mixing of multiple output messages.
     */
    port = (PUCHAR)vxsb_print_port;
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        for (c = str; *c; c++) {
            WRITE_PORT_UCHAR(port, *c);
        }
    } else {
        KeAcquireInStackQueuedSpinLock(&vxsb_print_lock, &lh);
        for (c = str; *c; c++) {
            WRITE_PORT_UCHAR(port, *c);
        }
        KeReleaseInStackQueuedSpinLock(&lh);
    }
}

static void
vxsb_printk(char *_fmt, ...)
{
    va_list ap;
    char buf[256];

    va_start(ap, _fmt);
    RtlStringCbVPrintfA(buf, sizeof(buf), _fmt, ap);
    va_end(ap);
    vxsb_print_str(buf);
}

ULONG
DriverEntry(IN void *DriverObject, IN void *RegistryPath)
{
    UNICODE_STRING xenbus_str;
    PFILE_OBJECT file_obj;
    PDEVICE_OBJECT device_obj;
    NTSTATUS status;
    DWORD use_pv_drivers;
    KIRQL irql;

    KeInitializeSpinLock(&vxsb_print_lock);
    printk = vxsb_printk;
    switch (hypervisor_is()) {
    case HYPERVISOR_KVM:
        vxsb_print_port = (UINT_PTR)VIRTIO_DEBUG_PORT;
        PRINTK(("%s %s.\n", PVVX_LOADING_STR, PVVX_VIRTIO_DRV_STR));
        PRINTK(("  Version %s.\n", VER_FILEVERSION_STR));
        return KvmDriverEntry(DriverObject, RegistryPath);
    case HYPERVISOR_XEN:
        irql = KeGetCurrentIrql();
        vxsb_print_port = XENBUS_PRINTK_PORT;
        if (irql == PASSIVE_LEVEL) {
            /*
             * If we get loaded before xenbus, then we are in a non-normal
             * startup.  In this case we don't want xenblk to continue
             * loading and replace IDE if xenbus comes up later.
             */
            RtlInitUnicodeString(&xenbus_str, XENBUS_DEVICE_NAME_WSTR);
            status = IoGetDeviceObjectPointer(&xenbus_str,
                                              STANDARD_RIGHTS_ALL,
                                              &file_obj,
                                              &device_obj);
            if (!(NT_SUCCESS(status))) {
                /* Let xenbus know that we loaded before xenbus. */
                status = sp_get_reg_value(XENBUS_FULL_DEVICE_KEY_WSTR,
                                          USE_PV_DRIVERS_WSTR,
                                          &use_pv_drivers);
                if (status == STATUS_SUCCESS) {
                    use_pv_drivers |= XENBUS_PROBE_WINDOWS_UPDATE_FLAG;
                    status = sp_set_reg_value(XENBUS_FULL_DEVICE_KEY_WSTR,
                                              USE_PV_DRIVERS_WSTR,
                                              use_pv_drivers);
                }
                PRINTK(("Xenbus not loaded: exiting %x\n", status));
                return STATUS_SUCCESS;
            }
            ObDereferenceObject(file_obj);
        }
        return XenDriverEntry(DriverObject, RegistryPath);
    default:
        break;
    }
    return (ULONG)STATUS_UNSUCCESSFUL;
}
