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

#include <win_xenbus_apis.h>

int (*gnttab_grant_foreign_access)(domid_t domid, unsigned long frame,
    int readonly);

int (*gnttab_end_foreign_access_ref)(grant_ref_t ref, int readonly);

void (*gnttab_end_foreign_access)(grant_ref_t ref, int readonly);

int (*gnttab_grant_foreign_transfer)(domid_t domid, unsigned long pfn);

unsigned long (*gnttab_end_foreign_transfer_ref)(grant_ref_t ref);
unsigned long (*gnttab_end_foreign_transfer)(grant_ref_t ref);

int (*gnttab_query_foreign_access)(grant_ref_t ref);

uint16_t (*gnttab_query_foreign_access_flags)(grant_ref_t ref);

int (*gnttab_alloc_grant_references)(u16 count,
    grant_ref_t *pprivate_head);

void (*gnttab_free_grant_reference)(grant_ref_t ref);

void (*gnttab_free_grant_references)(grant_ref_t head);

int (*gnttab_empty_grant_references)(const grant_ref_t *pprivate_head);

int (*gnttab_claim_grant_reference)(grant_ref_t *pprivate_head);

void (*gnttab_release_grant_reference)(grant_ref_t *private_head,
    grant_ref_t release);

void (*gnttab_request_free_callback)(
    struct gnttab_free_callback *callback, void (*fn)(void *),
    void *arg, u16 count);

void (*gnttab_cancel_free_callback)(
    struct gnttab_free_callback *callback);

void (*gnttab_grant_foreign_access_ref)(grant_ref_t ref, domid_t domid,
    unsigned long frame, int readonly);

void (*gnttab_grant_foreign_transfer_ref)(grant_ref_t, domid_t domid,
    unsigned long pfn);

void (*mask_evtchn)(int port);

void (*unmask_evtchn)(int port);

uint32_t (*is_evtchn_masked)(int port);

uint64_t (*xenbus_get_int_count)(int port);

void (*notify_remote_via_irq)(int irq);

void (*unbind_evtchn_from_irq)(unsigned int evtchn);

NTSTATUS (*set_callback_irq)(int irq);

NTSTATUS (*register_dpc_to_evtchn)(ULONG evtchn, PKDEFERRED_ROUTINE dpcroutine,
    PVOID dpccontext, void *system1);

void (*unregister_dpc_from_evtchn)(ULONG evtchn);

void (*force_evtchn_callback)(void);

xen_long_t (*notify_remote_via_evtchn)(int port);

char **(*xenbus_directory)(struct xenbus_transaction t,
    const char *dir, const char *node, unsigned int *num);


int (*xenbus_exists)(struct xenbus_transaction t,
    const char *dir, const char *node);


void *(*xenbus_read)(struct xenbus_transaction t,
    const char *dir, const char *node, unsigned int *len);


int (*xenbus_write)(struct xenbus_transaction t,
    const char *dir, const char *node, const char *string);

int (*xenbus_mkdir)(struct xenbus_transaction t,
    const char *dir, const char *node);

int (*xenbus_rm)(struct xenbus_transaction t, const char *dir,
    const char *node);

int (*xenbus_transaction_start)(struct xenbus_transaction *t);

int (*xenbus_transaction_end)(struct xenbus_transaction t, int abort);

int (*xenbus_printf)(struct xenbus_transaction t,
    const char *dir, const char *node, const char *fmt, ...);

void (*xenbus_free_string)(char *str);

int (*register_xenbus_watch)(struct xenbus_watch *watch);

void (*unregister_xenbus_watch)(struct xenbus_watch *watch);

int (*xenbus_grant_ring)(domid_t otherend_id, unsigned long ring_mfn);

int (*xenbus_alloc_evtchn)(domid_t otherend_id, int *port);

int (*xenbus_bind_evtchn)(domid_t otherend_id, int remote_port,
    int *port);

int (*xenbus_free_evtchn)(int port);

char *(*xenbus_get_nodename_from_pdo)(PDEVICE_OBJECT pdo);

char *(*xenbus_get_otherend_from_pdo)(PDEVICE_OBJECT pdo);

char *(*xenbus_get_backendid_from_pdo)(PDEVICE_OBJECT pdo);

char *(*xenbus_get_nodename_from_dev)(void *dev);

char *(*xenbus_get_otherend_from_dev)(void *dev);

char *(*xenbus_get_backendid_from_dev)(void *dev);

NTSTATUS (*xenbus_get_pvctrl_param)(void *mem, uint32_t param,
    uint32_t *value);

int (*xenbus_switch_state)(const char *nodename, enum xenbus_state state);
uint32_t (*xenbus_get_pv_port_options)(xenbus_pv_port_options_t *options);
NTSTATUS (*xenbus_control_pv_devices)(void *port, uint32_t *pv_devices);

NTSTATUS (*xenbus_xen_shared_init)(uint64_t mmio, uint8_t *mem,
    uint32_t mmio_len, uint32_t vector, uint32_t reason);

void *(*xenbus_enum_xenblk_info)(uint32_t *start_idx);

NTSTATUS (*xenbus_register_xenblk)(void *controller,
    uint32_t op_mode,
    void ***info);

NTSTATUS (*xenbus_register_vscsi)(void *controller, uint32_t op_mode,
    void **info);

void (*xenbus_)(void);

NTSTATUS (*xenbus_claim_device)(void *dev, void *controller,
    XENBUS_DEVICE_TYPE type, XENBUS_DEVICE_SUBTYPE subtype,
    uint32_t (*reserved)(void *context, pv_ioctl_t data),
    uint32_t (*ioctl)(void *context, pv_ioctl_t data));

void (*xenbus_release_device)(void *dev, void *controller,
    xenbus_release_device_t release_data);

ULONG (*xenbus_handle_evtchn_callback)(void);

NTSTATUS (*xenbus_create_thread)(PKSTART_ROUTINE callback, void *context);

void (*xenbus_terminate_thread)(void);

void (*xenbus_print_str)(char *str);

void (*xenbus_printk)(char *_fmt, ...);

void (*xenbus_console_io)(char *_fmt, ...);

void (*xenbus_debug_dump)(void);

#ifdef ARCH_x86_64
void (*_cpuid64)(struct cpuid_args *id);
#endif

void
xenbus_fill_apis(xenbus_apis_t *api)
{
    gnttab_grant_foreign_access = api->gnttab_grant_foreign_access;
    gnttab_end_foreign_access_ref = api->gnttab_end_foreign_access_ref;
    gnttab_end_foreign_access = api->gnttab_end_foreign_access;
    gnttab_query_foreign_access = api->gnttab_query_foreign_access;
    gnttab_query_foreign_access_flags = api->gnttab_query_foreign_access_flags;
    gnttab_alloc_grant_references = api->gnttab_alloc_grant_references;
    gnttab_free_grant_reference = api->gnttab_free_grant_reference;
    gnttab_free_grant_references = api->gnttab_free_grant_references;
    gnttab_empty_grant_references = api->gnttab_empty_grant_references;
    gnttab_claim_grant_reference = api->gnttab_claim_grant_reference;
    gnttab_release_grant_reference = api->gnttab_release_grant_reference;
    gnttab_request_free_callback = api->gnttab_request_free_callback;
    gnttab_cancel_free_callback = api->gnttab_cancel_free_callback;
    gnttab_grant_foreign_access_ref = api->gnttab_grant_foreign_access_ref;
    mask_evtchn = api->mask_evtchn;
    unmask_evtchn = api->unmask_evtchn;
    is_evtchn_masked = api->is_evtchn_masked;
    xenbus_get_int_count = api->xenbus_get_int_count;
    notify_remote_via_irq = api->notify_remote_via_irq;
    unbind_evtchn_from_irq = api->unbind_evtchn_from_irq;
    set_callback_irq = api->set_callback_irq;
    register_dpc_to_evtchn = api->register_dpc_to_evtchn;
    unregister_dpc_from_evtchn = api->unregister_dpc_from_evtchn;
    force_evtchn_callback = api->force_evtchn_callback;
    notify_remote_via_evtchn = api->notify_remote_via_evtchn;
    xenbus_directory = api->xenbus_directory;
    xenbus_exists = api->xenbus_exists;
    xenbus_read = api->xenbus_read;
    xenbus_write = api->xenbus_write;
    xenbus_mkdir = api->xenbus_mkdir;
    xenbus_rm = api->xenbus_rm;
    xenbus_transaction_start = api->xenbus_transaction_start;
    xenbus_transaction_end = api->xenbus_transaction_end;
    xenbus_printf = api->xenbus_printf;
    xenbus_free_string = api->xenbus_free_string;
    register_xenbus_watch = api->register_xenbus_watch;
    unregister_xenbus_watch = api->unregister_xenbus_watch;
    xenbus_grant_ring = api->xenbus_grant_ring;
    xenbus_alloc_evtchn = api->xenbus_alloc_evtchn;
    xenbus_bind_evtchn = api->xenbus_bind_evtchn;
    xenbus_free_evtchn = api->xenbus_free_evtchn;
    xenbus_get_nodename_from_pdo = api->xenbus_get_nodename_from_pdo;
    xenbus_get_otherend_from_pdo = api->xenbus_get_otherend_from_pdo;
    xenbus_get_backendid_from_pdo = api->xenbus_get_backendid_from_pdo;
    xenbus_get_nodename_from_dev = api->xenbus_get_nodename_from_dev;
    xenbus_get_otherend_from_dev = api->xenbus_get_otherend_from_dev;
    xenbus_get_backendid_from_dev = api->xenbus_get_backendid_from_dev;
    xenbus_get_pvctrl_param = api->xenbus_get_pvctrl_param;
    xenbus_switch_state = api->xenbus_switch_state;
    xenbus_get_pv_port_options = api->xenbus_get_pv_port_options;
    xenbus_control_pv_devices = api->xenbus_control_pv_devices;
    xenbus_xen_shared_init = api->xenbus_xen_shared_init;
    xenbus_enum_xenblk_info = api->xenbus_enum_xenblk_info;
    xenbus_register_xenblk = api->xenbus_register_xenblk;
    xenbus_register_vscsi = api->xenbus_register_vscsi;
    xenbus_claim_device = api->xenbus_claim_device;
    xenbus_release_device = api->xenbus_release_device;
    xenbus_handle_evtchn_callback = api->xenbus_handle_evtchn_callback;
    xenbus_create_thread = api->xenbus_create_thread;
    xenbus_terminate_thread = api->xenbus_terminate_thread;
    xenbus_print_str = api->xenbus_print_str;
    xenbus_printk = api->xenbus_printk;
    xenbus_console_io = api->xenbus_console_io;
    xenbus_debug_dump = api->xenbus_debug_dump;
#ifdef ARCH_x86_64
    _cpuid64 = api->_cpuid64;
#endif
}

NTSTATUS
xenbus_get_apis(void)
{
    xenbus_apis_t api = {0};
    UNICODE_STRING xenbus_str;
    PFILE_OBJECT file_obj;
    PDEVICE_OBJECT device_obj;
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    KEVENT event;
    PIRP irp;

    RtlInitUnicodeString(&xenbus_str, XENBUS_DEVICE_NAME_WSTR);
    status = IoGetDeviceObjectPointer(&xenbus_str,
        STANDARD_RIGHTS_ALL,
        &file_obj,
        &device_obj);

    if (!(NT_SUCCESS(status))) {
        return status;
    }
    ObDereferenceObject(file_obj);
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoBuildDeviceIoControlRequest(
       IOCTL_XENBUS_GET_APIS,
       device_obj,
       &api,
       sizeof(xenbus_apis_t),
       NULL,
       0,
       TRUE, /* InternalDeviceIoControl */
       &event,
       &io_status);
    if (irp == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = IoCallDriver(device_obj, irp);
    if (status != STATUS_SUCCESS && io_status.Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    xenbus_fill_apis(&api);

    return STATUS_SUCCESS;
}
