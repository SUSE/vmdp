/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2020 SUSE LLC
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

#ifndef _WIN_XENBUS_H
#define _WIN_XENBUS_H

#include <xen/public/win_xen.h>
#include <xen/public/grant_table.h>
#include <xen/public/io/xenbus.h>
#include <winpv_defs.h>
#include <asm/win_plat.h>
#include <win_pvvx.h>

#define EINVAL    22
#define EACCES    13
#define EEXIST    17
#define EISDIR    21
#define ENOENT     2
#define ENOMEM    12
#define ENOSPC    28
#define EIO        5
#define ENOTEMPTY 39
#define ENOSYS    38
#define EROFS     30
#define EBUSY     16
#define EAGAIN    11
#define EISCONN  106
#define ERANGE    34
#define E2BIG      7
#define EPIPE     32
#define EPROTO    71      /* Protocol error */
#define ESHUTDOWN   108
#include <xen/public/io/xs_wire.h>

#define XENBUS_STATE_POWER_OFF          XenbusStateClosed + 100
#define XENBUS_STATE_REBOOT             XenbusStateClosed + 101

#define SHUTDOWN_INVALID    -1
#define SHUTDOWN_POWEROFF   SHUTDOWN_poweroff
#define SHUTDOWN_REBOOT     SHUTDOWN_reboot
#define SHUTDOWN_SUSPEND    SHUTDOWN_suspend
/* Code 3 is SHUTDOWN_CRASH, which we don't use because the domain can only
 * report a crash, not be instructed to crash!
 * HALT is the same as POWEROFF, as far as we're concerned.  The tools use
 * the distinction when we return the reason code to them.
 */
#define SHUTDOWN_HALT       4
#define SHUTDOWN_DEBUG_DUMP 5

#define XENBUS_PRINTK xenbus_printk
#define XENBUS_CONSOLE_IO xenbus_console_io

#define IOCTL_XENBUS_GET_APIS \
   CTL_CODE(FILE_DEVICE_BUS_EXTENDER, 0x811, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct xenbus_pv_port_options_s {
    uint32_t port_offset;
    uint32_t value;
} xenbus_pv_port_options_t;

struct xenbus_watch {
    LIST_ENTRY list;

    /* Path being watched. */
    const char *node;

    /* Callback (executed in a process context with no locks held). */
    void (*callback)(struct xenbus_watch *,
                     const char **vec, unsigned int len);

    /* See XBWF_ definitions below. */
    unsigned long flags;

    void *context;
};

typedef enum _XENBUS_DEVICE_TYPE {
    vnif,
    vbd,
    vscsi,
    vusb,
    unknown
} XENBUS_DEVICE_TYPE;

typedef enum _XENBUS_DEVICE_SUBTYPE {
    disk,
    cdrom,
    none,
    not_specified,
    tape,
    hba,
} XENBUS_DEVICE_SUBTYPE;

typedef enum _PV_IOCTL_CMD {
    PV_SUSPEND,
    PV_RESUME,
    PV_ATTACH,
    PV_DETACH,
} PV_IOCTL_CMD;

typedef enum _XENBUS_RELEASE_ACTION {
    RELEASE_ONLY,
    RELEASE_REMOVE,
} XENBUS_RELEASE_ACTION;

/*
 * Execute callback in its own kthread. Useful if the callback is long
 * running or heavily serialised, to avoid taking out the main xenwatch thread
 * for a long period of time (or even unwittingly causing a deadlock).
 */
#define XBWF_new_thread 1


struct xenbus_transaction {
    u32 id;
};

typedef struct pv_ioctl_s {
    uint16_t cmd;
    uint16_t arg;
} pv_ioctl_t;

typedef struct xenbus_release_device_s {
    uint16_t action;
    uint16_t type;
} xenbus_release_device_t;

typedef struct xenbus_shared_info_t {
    void *gfdo;
    void (*xenbus_set_apis)(void *api);
} xenbus_shared_info_t;

/* Nil transaction ID. */
static struct xenbus_transaction XBT_NIL = {0};


#ifndef USE_INDIRECT_XENBUS_APIS
/* export functions */
DLLEXPORT char **
xenbus_directory(struct xenbus_transaction t,
    const char *dir, const char *node, unsigned int *num);


DLLEXPORT int
xenbus_exists(struct xenbus_transaction t,
    const char *dir, const char *node);


DLLEXPORT void
*xenbus_read(struct xenbus_transaction t,
    const char *dir, const char *node, unsigned int *len);


DLLEXPORT int
xenbus_write(struct xenbus_transaction t,
    const char *dir, const char *node, const char *string);

DLLEXPORT int
xenbus_mkdir(struct xenbus_transaction t,
    const char *dir, const char *node);

DLLEXPORT int
xenbus_rm(struct xenbus_transaction t, const char *dir, const char *node);

DLLEXPORT int
xenbus_transaction_start(struct xenbus_transaction *t);

DLLEXPORT int
xenbus_transaction_end(struct xenbus_transaction t, int abort);

DLLEXPORT int
xenbus_printf(struct xenbus_transaction t,
    const char *dir, const char *node, const char *fmt, ...);

DLLEXPORT void
xenbus_free_string(char *str);

DLLEXPORT int
register_xenbus_watch(struct xenbus_watch *watch);

DLLEXPORT void
unregister_xenbus_watch(struct xenbus_watch *watch);

DLLEXPORT int
xenbus_grant_ring(domid_t otherend_id, unsigned long ring_mfn);

DLLEXPORT int
xenbus_alloc_evtchn(domid_t otherend_id, int *port);

DLLEXPORT int
xenbus_bind_evtchn(domid_t otherend_id, int remote_port, int *port);

DLLEXPORT int
xenbus_free_evtchn(int port);

DLLEXPORT char *
xenbus_get_nodename_from_pdo(PDEVICE_OBJECT pdo);

DLLEXPORT char *
xenbus_get_otherend_from_pdo(PDEVICE_OBJECT pdo);

DLLEXPORT char *
xenbus_get_backendid_from_pdo(PDEVICE_OBJECT pdo);

DLLEXPORT char *
xenbus_get_nodename_from_dev(void *dev);

DLLEXPORT char *
xenbus_get_otherend_from_dev(void *dev);

DLLEXPORT char *
xenbus_get_backendid_from_dev(void *dev);

DLLEXPORT NTSTATUS
xenbus_get_pvctrl_param(void *mem, uint32_t param, uint32_t *value);

DLLEXPORT int
xenbus_switch_state(const char *nodename, enum xenbus_state state);

DLLEXPORT uint32_t
xenbus_get_pv_port_options(xenbus_pv_port_options_t *options);

DLLEXPORT NTSTATUS
xenbus_control_pv_devices(void *in_port, uint32_t *pv_devices);

DLLEXPORT NTSTATUS
xenbus_xen_shared_init(uint64_t mmio, uint8_t *mem, uint32_t mmio_len,
    uint32_t vector, uint32_t reason);

DLLEXPORT void *
xenbus_enum_xenblk_info(uint32_t *start_idx);

DLLEXPORT NTSTATUS
xenbus_register_xenblk(void *controller,
    uint32_t op_mode,
    void ***info);

DLLEXPORT NTSTATUS
xenbus_register_vscsi(void *controller,
    uint32_t op_mode,
    void **info);

DLLEXPORT void
xenbus_external_shutdown(void);

DLLEXPORT NTSTATUS
xenbus_claim_device(void *dev, void *controller,
    XENBUS_DEVICE_TYPE type, XENBUS_DEVICE_SUBTYPE subtype,
    uint32_t (*reserved)(void *context, pv_ioctl_t data),
    uint32_t (*ioctl)(void *context, pv_ioctl_t data));

DLLEXPORT void
xenbus_release_device(void *dev, void *controller,
    xenbus_release_device_t release_data);

DLLEXPORT ULONG
xenbus_handle_evtchn_callback(void);

DLLEXPORT NTSTATUS
xenbus_create_thread(PKSTART_ROUTINE callback, void *context);

DLLEXPORT void
xenbus_terminate_thread(void);

DLLEXPORT void
xenbus_print_str(char *str);

DLLEXPORT void
xenbus_printk(char *_fmt, ...);

DLLEXPORT void
xenbus_console_io(char *_fmt, ...);

DLLEXPORT void
xenbus_debug_dump(void);
#endif

#endif
