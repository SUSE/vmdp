/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2013-2026 SUSE LLC
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

#ifndef _WINXENBUSAPIs_H
#define _WINXENBUSAPIs_H

#include <ntddk.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#define __BUSDRV__
/* #define __XEN_INTERFACE_VERSION__ 0x00030202 */
#include <asm/win_compat.h>
#include <xen/public/win_xen.h>
#include <xen/public/grant_table.h>
#include <win_gnttab.h>
#include <win_xenbus.h>
#include <win_evtchn.h>

#define XENBUS_TAG_API          'IPAX'  /* "XAPI" */

typedef struct _xenbus_apis_s {
    int (*gnttab_grant_foreign_access)(domid_t domid, unsigned long frame,
        int readonly);

    int (*gnttab_end_foreign_access_ref)(grant_ref_t ref, int readonly);

    void (*gnttab_end_foreign_access)(grant_ref_t ref, int readonly);

    int (*gnttab_query_foreign_access)(grant_ref_t ref);

    uint16_t (*gnttab_query_foreign_access_flags)(grant_ref_t ref);

    int (*gnttab_alloc_grant_references)(u16 count, grant_ref_t *pprivate_head);

    void (*gnttab_free_grant_reference)(grant_ref_t ref);

    void (*gnttab_free_grant_references)(grant_ref_t head);

    int (*gnttab_empty_grant_references)(const grant_ref_t *pprivate_head);

    int (*gnttab_claim_grant_reference)(grant_ref_t *pprivate_head);

    void (*gnttab_release_grant_reference)(grant_ref_t *private_head,
        grant_ref_t release);

    void (*gnttab_request_free_callback)(struct gnttab_free_callback *callback,
        void (*fn)(void *), void *arg, u16 count);
    void (*gnttab_cancel_free_callback)(struct gnttab_free_callback *callback);

    void (*gnttab_grant_foreign_access_ref)(grant_ref_t ref, domid_t domid,
        unsigned long frame, int readonly);

    void (*mask_evtchn)(int port);

    void (*unmask_evtchn)(int port);

    uint32_t (*is_evtchn_masked)(int port);

    uint64_t (*xenbus_get_int_count)(int port);

    void (*notify_remote_via_irq)(int irq);

    void (*unbind_evtchn_from_irq)(unsigned int evtchn);

    NTSTATUS (*set_callback_irq)(int irq);

    NTSTATUS (*register_dpc_to_evtchn)(ULONG evtchn,
                                       PKDEFERRED_ROUTINE dpcroutine,
                                       PVOID dpccontext, void *system1);

    VOID (*unregister_dpc_from_evtchn)(ULONG evtchn);

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

    int (*xenbus_bind_evtchn)(domid_t otherend_id, int remote_port, int *port);

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

    void (*xenbus_debug_printk)(uint32_t lvl, char *_fmt, ...);

    void (*xenbus_debug_dump)(void);
#ifdef ARCH_x86_64
    void (*_cpuid64)(struct cpuid_args *id);
#endif
} xenbus_apis_t;

void xenbus_set_apis(xenbus_apis_t *api);
NTSTATUS xenbus_get_apis(void);

#ifdef USE_INDIRECT_XENBUS_APIS
void xenbus_fill_apis(xenbus_apis_t *api);

extern int (*gnttab_grant_foreign_access)(domid_t domid, unsigned long frame,
    int readonly);

extern int (*gnttab_end_foreign_access_ref)(grant_ref_t ref, int readonly);

extern void (*gnttab_end_foreign_access)(grant_ref_t ref, int readonly);

extern int (*gnttab_query_foreign_access)(grant_ref_t ref);

extern uint16_t (*gnttab_query_foreign_access_flags)(grant_ref_t ref);

extern int (*gnttab_alloc_grant_references)(u16 count,
    grant_ref_t *pprivate_head);

extern void (*gnttab_free_grant_reference)(grant_ref_t ref);

extern void (*gnttab_free_grant_references)(grant_ref_t head);

extern int (*gnttab_empty_grant_references)(const grant_ref_t *pprivate_head);

extern int (*gnttab_claim_grant_reference)(grant_ref_t *pprivate_head);

extern void (*gnttab_release_grant_reference)(grant_ref_t *private_head,
    grant_ref_t release);

extern void (*gnttab_request_free_callback)(
    struct gnttab_free_callback *callback, void (*fn)(void *),
    void *arg, u16 count);

extern void (*gnttab_cancel_free_callback)(
    struct gnttab_free_callback *callback);

extern void (*gnttab_grant_foreign_access_ref)(grant_ref_t ref, domid_t domid,
    unsigned long frame, int readonly);

extern void (*mask_evtchn)(int port);

extern void (*unmask_evtchn)(int port);

extern uint32_t (*is_evtchn_masked)(int port);

extern uint64_t (*xenbus_get_int_count)(int port);

extern void (*notify_remote_via_irq)(int irq);

extern void (*unbind_evtchn_from_irq)(unsigned int evtchn);

extern NTSTATUS (*set_callback_irq)(int irq);

extern NTSTATUS (*register_dpc_to_evtchn)(ULONG evtchn,
    PKDEFERRED_ROUTINE dpcroutine,
    PVOID dpccontext, void *system1);

extern VOID (*unregister_dpc_from_evtchn)(ULONG evtchn);

extern void (*force_evtchn_callback)(void);

extern xen_long_t (*notify_remote_via_evtchn)(int port);

extern char **(*xenbus_directory)(struct xenbus_transaction t,
    const char *dir, const char *node, unsigned int *num);


extern int (*xenbus_exists)(struct xenbus_transaction t,
    const char *dir, const char *node);


extern void *(*xenbus_read)(struct xenbus_transaction t,
    const char *dir, const char *node, unsigned int *len);


extern int (*xenbus_write)(struct xenbus_transaction t,
    const char *dir, const char *node, const char *string);

extern int (*xenbus_mkdir)(struct xenbus_transaction t,
    const char *dir, const char *node);

extern int (*xenbus_rm)(struct xenbus_transaction t, const char *dir,
    const char *node);

extern int (*xenbus_transaction_start)(struct xenbus_transaction *t);

extern int (*xenbus_transaction_end)(struct xenbus_transaction t, int abort);

extern int (*xenbus_printf)(struct xenbus_transaction t,
    const char *dir, const char *node, const char *fmt, ...);

extern void (*xenbus_free_string)(char *str);

extern int (*register_xenbus_watch)(struct xenbus_watch *watch);

extern void (*unregister_xenbus_watch)(struct xenbus_watch *watch);

extern int (*xenbus_grant_ring)(domid_t otherend_id, unsigned long ring_mfn);

extern int (*xenbus_alloc_evtchn)(domid_t otherend_id, int *port);

extern int (*xenbus_bind_evtchn)(domid_t otherend_id, int remote_port,
    int *port);

extern int (*xenbus_free_evtchn)(int port);

extern char *(*xenbus_get_nodename_from_pdo)(PDEVICE_OBJECT pdo);

extern char *(*xenbus_get_otherend_from_pdo)(PDEVICE_OBJECT pdo);

extern char *(*xenbus_get_backendid_from_pdo)(PDEVICE_OBJECT pdo);

extern char *(*xenbus_get_nodename_from_dev)(void *dev);

extern char *(*xenbus_get_otherend_from_dev)(void *dev);

extern char *(*xenbus_get_backendid_from_dev)(void *dev);

extern NTSTATUS (*xenbus_get_pvctrl_param)(void *mem, uint32_t param,
    uint32_t *value);

extern int (*xenbus_switch_state)(const char *nodename,
    enum xenbus_state state);
extern uint32_t (*xenbus_get_pv_port_options)(
    xenbus_pv_port_options_t *options);
extern NTSTATUS (*xenbus_control_pv_devices)(void *port, uint32_t *pv_devices);

extern NTSTATUS (*xenbus_xen_shared_init)(uint64_t mmio, uint8_t *mem,
    uint32_t mmio_len, uint32_t vector, uint32_t reason);

extern void *(*xenbus_enum_xenblk_info)(uint32_t *start_idx);

extern NTSTATUS (*xenbus_register_xenblk)(void *controller,
    uint32_t op_mode,
    void ***info);

extern NTSTATUS (*xenbus_register_vscsi)(void *controller, uint32_t op_mode,
    void **info);

extern NTSTATUS (*xenbus_claim_device)(void *dev, void *controller,
    XENBUS_DEVICE_TYPE type, XENBUS_DEVICE_SUBTYPE subtype,
    uint32_t (*reserved)(void *context, pv_ioctl_t data),
    uint32_t (*ioctl)(void *context, pv_ioctl_t data));

extern void (*xenbus_release_device)(void *dev, void *controller,
    xenbus_release_device_t release_data);

extern ULONG (*xenbus_handle_evtchn_callback)(void);

extern NTSTATUS (*xenbus_create_thread)(PKSTART_ROUTINE callback,
    void *context);
extern void (*xenbus_terminate_thread)(void);

extern void (*xenbus_print_str)(char *str);

extern void (*xenbus_printk)(char *_fmt, ...);

extern void (*xenbus_console_io)(char *_fmt, ...);

extern void (*xenbus_debug_dump)(void);
#ifdef ARCH_x86_64
extern void (*_cpuid64)(struct cpuid_args *id);
#endif
#endif

#endif
