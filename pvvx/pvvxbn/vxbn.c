/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2013-2020 SUSE LLC
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

#include "vxbn.h"

DRIVER_INITIALIZE DriverEntry;
void (*printk)(char *_fmt, ...);

#ifdef DBG
uint32_t dbg_print_mask = DPRTL_ON | DPRTL_INIT | DPRTL_UNEXPD;
#else
uint32_t dbg_print_mask = DPRTL_OFF;
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

void
xenbus_set_apis(xenbus_apis_t *api)
{
    api->gnttab_grant_foreign_access = gnttab_grant_foreign_access;
    api->gnttab_end_foreign_access_ref = gnttab_end_foreign_access_ref;
    api->gnttab_end_foreign_access = gnttab_end_foreign_access;
    api->gnttab_query_foreign_access = gnttab_query_foreign_access;
    api->gnttab_query_foreign_access_flags = gnttab_query_foreign_access_flags;
    api->gnttab_alloc_grant_references = gnttab_alloc_grant_references;
    api->gnttab_free_grant_reference = gnttab_free_grant_reference;
    api->gnttab_free_grant_references = gnttab_free_grant_references;
    api->gnttab_empty_grant_references = gnttab_empty_grant_references;
    api->gnttab_claim_grant_reference = gnttab_claim_grant_reference;
    api->gnttab_release_grant_reference = gnttab_release_grant_reference;
    api->gnttab_request_free_callback = gnttab_request_free_callback;
    api->gnttab_cancel_free_callback = gnttab_cancel_free_callback;
    api->gnttab_grant_foreign_access_ref = gnttab_grant_foreign_access_ref;
    api->mask_evtchn = mask_evtchn;
    api->unmask_evtchn = unmask_evtchn;
    api->is_evtchn_masked = is_evtchn_masked;
    api->xenbus_get_int_count = xenbus_get_int_count;
    api->notify_remote_via_irq = notify_remote_via_irq;
    api->unbind_evtchn_from_irq = unbind_evtchn_from_irq;
    api->set_callback_irq = set_callback_irq;
    api->register_dpc_to_evtchn = register_dpc_to_evtchn;
    api->unregister_dpc_from_evtchn = unregister_dpc_from_evtchn;
    api->force_evtchn_callback = force_evtchn_callback;
    api->notify_remote_via_evtchn = notify_remote_via_evtchn;
    api->xenbus_directory = xenbus_directory;
    api->xenbus_exists = xenbus_exists;
    api->xenbus_read = xenbus_read;
    api->xenbus_write = xenbus_write;
    api->xenbus_mkdir = xenbus_mkdir;
    api->xenbus_rm = xenbus_rm;
    api->xenbus_transaction_start = xenbus_transaction_start;
    api->xenbus_transaction_end = xenbus_transaction_end;
    api->xenbus_printf = xenbus_printf;
    api->xenbus_free_string = xenbus_free_string;
    api->register_xenbus_watch = register_xenbus_watch;
    api->unregister_xenbus_watch = unregister_xenbus_watch;
    api->xenbus_grant_ring = xenbus_grant_ring;
    api->xenbus_alloc_evtchn = xenbus_alloc_evtchn;
    api->xenbus_bind_evtchn = xenbus_bind_evtchn;
    api->xenbus_free_evtchn = xenbus_free_evtchn;
    api->xenbus_get_nodename_from_pdo = xenbus_get_nodename_from_pdo;
    api->xenbus_get_otherend_from_pdo = xenbus_get_otherend_from_pdo;
    api->xenbus_get_backendid_from_pdo = xenbus_get_backendid_from_pdo;
    api->xenbus_get_nodename_from_dev = xenbus_get_nodename_from_dev;
    api->xenbus_get_otherend_from_dev = xenbus_get_otherend_from_dev;
    api->xenbus_get_backendid_from_dev = xenbus_get_backendid_from_dev;
    api->xenbus_get_pvctrl_param = xenbus_get_pvctrl_param;
    api->xenbus_switch_state = xenbus_switch_state;
    api->xenbus_get_pv_port_options = xenbus_get_pv_port_options;
    api->xenbus_control_pv_devices = xenbus_control_pv_devices;
    api->xenbus_xen_shared_init = xenbus_xen_shared_init;
    api->xenbus_enum_xenblk_info = xenbus_enum_xenblk_info;
    api->xenbus_register_xenblk = xenbus_register_xenblk;
    api->xenbus_register_vscsi = xenbus_register_vscsi;
    api->xenbus_claim_device = xenbus_claim_device;
    api->xenbus_release_device = xenbus_release_device;
    api->xenbus_handle_evtchn_callback = xenbus_handle_evtchn_callback;
    api->xenbus_create_thread = xenbus_create_thread;
    api->xenbus_terminate_thread = xenbus_terminate_thread;
    api->xenbus_print_str = xenbus_print_str;
    api->xenbus_printk = xenbus_printk;
    api->xenbus_console_io = xenbus_console_io;
    api->xenbus_debug_printk = NULL;
    api->xenbus_debug_dump = xenbus_debug_dump;
#ifdef ARCH_x86_64
    api->_cpuid64 = _cpuid64;
#endif
}

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    switch (hypervisor_is()) {
    case HYPERVISOR_KVM:
        printk = virtio_dbg_printk;
        KeInitializeSpinLock(&virtio_print_lock);
        virtio_dbg_printk("pvvxbn loading for virtio_balloon.\n");
        virtio_dbg_printk("  Version %s.\n", VER_FILEVERSION_STR);
        return KvmDriverEntry(DriverObject, RegistryPath);
    case HYPERVISOR_XEN:
        printk = xenbus_printk;
        KeInitializeSpinLock(&xenbus_print_lock);
        xenbus_printk("pvvxbn loading for xenbus.\n");
        xenbus_printk("  Version %s.\n", VER_FILEVERSION_STR);
        status = XenDriverEntry(DriverObject, RegistryPath);
        DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
            XenbusDispatchInternalDeviceControl;
        xenbus_printk("pvvxbn DriverEntrying returned %x\n", status);
        return status;
    default:
        break;
    }
    return STATUS_UNSUCCESSFUL;
}
