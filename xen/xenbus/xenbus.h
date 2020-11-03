/*
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

#ifndef _XENBUSDRV_H
#define _XENBUSDRV_H

#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>
#include "guid.h"
#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#define __XEN_INTERFACE_VERSION__ 0x00030204
#define __BUSDRV__
#include <asm/win_compat.h>
#include <asm/win_hypervisor.h>
#include <win_version.h>
#include <win_xenbus.h>
#include <xen/public/win_xen.h>
#include <xen/public/version.h>
#include <xen/public/memory.h>
#include <win_features.h>
#include <win_gnttab.h>
#include <win_evtchn.h>
#include <win_hvm.h>
#include <win_cmp_strtol.h>
#include <vxbn.h>

#include <win_vxprintk.h>

#define XENBUS_POOL_TAG (ULONG) 'neXp'

/* Used to identify a port optoin request coming from the Xenbus device. */
#define XENBUS_PV_PORT_OPTION_OFFSET_XENB   (DWORD) 'BNEX'
#define XENBUS_PV_PORT_OPTION_VALUE_DEV     (DWORD) 'VED_'

#define XB_EVENT    0x1
#define XS_LIST     0x2
#define XS_REQUEST  0x4

#define X_CMP       0x1
#define X_GNT       0x2
#define X_DPC       0x4
#define X_RPL       0x8
#define X_WAT       0x10
#define X_XSL       0x20
#define X_WEL       0x40

#define SHARED_INFO_NOT_INITIALIZED     0
#define SHARED_INFO_INITIALIZED         1
#define SHARED_INFO_MIGRATING           2

#define GNTTAB_SUSPEND_F                0x001
#define XEN_INFO_CLEANUP_F              0x002
#define XEN_STORE_INTERFACE_NULL_F      0x004
#define XENBUS_RELEASE_DEVICE_F         0x008
#define INITIALIZE_HYPERCALL_PAGE_F     0x010
#define XEN_INFO_INIT_F                 0x020
#define GNTTAB_INIT_F                   0x040
#define EVTCHN_INIT_F                   0x080
#define XEN_FINISH_INIT_F               0x100
#define GNTTAB_FINISH_INIT_F            0x200
#define XS_INIT_F                       0x400
#define XB_COMMS_INIT_F                 0x800
#define READ_REPLY_F                    0x10000
#define XB_WRITE_F                      0x20000
#define EVTCHN_F                        0x40000
#define UNMASK_F                        0x80000

#if defined XENBUG_TRACE_FLAGS || defined DBG
#define XENBUS_INIT_FLAG(_F, _V)        ((_F) = (_V))
#define XENBUS_SET_FLAG(_F, _V)         ((_F) |= (_V))
#define XENBUS_CLEAR_FLAG(_F, _V)       ((_F) &= ~(_V))
#else
#define XENBUS_INIT_FLAG(_F, _V)
#define XENBUS_SET_FLAG(_F, _V)
#define XENBUS_CLEAR_FLAG(_F, _V)
#endif

#define MAX_EVTCHN_PORTS    32
#define NR_RESERVED_ENTRIES 8

#define PRINTF_BUFFER_SIZE 4096

#define DELAYED_RESOURCE_TRY_CNT_DEFAULT 0

#define BALLOON_MAX_RESERVATION 0xffffffffffffffff

#define BOOT_DISK_NODE_NAME "device/vbd/768"

typedef struct _evtchns_s {
    union {
        PKDPC dpc;
        PKDEFERRED_ROUTINE routine;
    } u;
    void *context;
    uint32_t *wants_int_indication;
    int locked;
} evtchns_t;

typedef enum _PNP_STATE {

    NotStarted = 0,         /* Not started yet */
    Started,                /* Device has received the START_DEVICE IRP */
    StopPending,            /* Device has received the QUERY_STOP IRP */
    Stopped,                /* Device has received the STOP_DEVICE IRP */
    RemovePending,          /* Device has received the QUERY_REMOVE IRP */
    SurpriseRemovePending,  /* Device has received the SURPRISE_REMOVE IRP */
    Deleted,                /* Device has received the REMOVE_DEVICE IRP */
    UnKnown                 /* Unknown state */

} PNP_STATE;

typedef struct _COMMON_DEVICE_EXTENSION {
    BOOLEAN IsFdo;
    PDEVICE_OBJECT Self;

    PNP_STATE pnpstate;
    DEVICE_POWER_STATE devpower;
    SYSTEM_POWER_STATE syspower;

} COMMON_DEVICE_EXTENSION, *PCOMMON_DEVICE_EXTENSION;

typedef enum _XENBUS_DEVICE_ORIGIN {
    alloced,
    created,
} XENBUS_DEVICE_ORIGIN;

/* child PDOs device extension */
typedef struct _PDO_DEVICE_EXTENSION {
    COMMON_DEVICE_EXTENSION;

    PDEVICE_OBJECT ParentFdo;

    PCHAR Nodename;
    PCHAR instance_id;

    UNICODE_STRING HardwareIDs;

    XENBUS_DEVICE_TYPE Type;
    XENBUS_DEVICE_SUBTYPE subtype;
    XENBUS_DEVICE_ORIGIN origin;

    PCHAR BackendID;
    PCHAR Otherend;
    void *frontend_dev;
    void *controller;
    uint32_t (*ioctl)(void *, pv_ioctl_t);
    uint32_t shutdown_try_cnt;

    LIST_ENTRY Link;

    BOOLEAN Present;
    BOOLEAN ReportedMissing;
    UCHAR Reserved[2];

    ULONG InterfaceRefCount;
    ULONG PagingPathCount;
    ULONG DumpPathCount;
    ULONG HibernationPathCount;
    KEVENT PathCountEvent;
    PCHAR subnode;
    KDPC shutdown_dpc;
    KTIMER shutdown_timer;

} PDO_DEVICE_EXTENSION, *PPDO_DEVICE_EXTENSION;

/* FDO device extension as function driver */
typedef struct _FDO_DEVICE_EXTENSION {
    COMMON_DEVICE_EXTENSION;

    uint32_t sig;
    PDEVICE_OBJECT Pdo;
    PDEVICE_OBJECT LowerDevice;
    UNICODE_STRING ifname;
    IO_REMOVE_LOCK RemoveLock;
    FAST_MUTEX Mutex;
    SYSTEM_POWER_STATE power_state;
    LIST_ENTRY ListOfPDOs;

    ULONG NumPDOs;
    uint64_t mmio;
    uint8_t *mem;
    uint32_t mmiolen;
    void *xsif;
    grant_ref_t *gnttab_list;
    grant_ref_t *gnttab_free_head;
    int *gnttab_free_count;
    void **info;
    void **sinfo;
    uint32_t max_info_entries;
    uint32_t num_grant_frames;
    LIST_ENTRY shutdown_requests;
    KSPIN_LOCK qlock;
    PIRP irp;
    PIO_WORKITEM item;
    uint32_t initialized;
    uint32_t dirql;
    uint32_t dvector;
    KAFFINITY daffinity;
    uint32_t irql;
    uint32_t vector;
    KAFFINITY affinity;
    PUCHAR PortBase;
    ULONG NumPorts;
    BOOLEAN MappedPort;
    uint32_t dbg_print_mask;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

struct xs_stored_msg {
    LIST_ENTRY list;
    struct xsd_sockmsg hdr;
    union {
        /* Queued replies */
        struct {
            char *body;
        } reply;

        /* Queued watch events */
        struct {
            struct xenbus_watch *handle;
            char **vec;
            unsigned int vec_size;
        } watch;
    } u;
};

extern PKINTERRUPT DriverInterruptObj;

extern PDEVICE_OBJECT gfdo;
extern PFDO_DEVICE_EXTENSION gfdx;
extern shared_info_t *shared_info_area;
extern uint32_t use_pv_drivers;
extern uint32_t delayed_resource_try_cnt;
extern uint32_t pvctrl_flags;
extern uint32_t max_disk_targets;
extern uint32_t g_max_segments_per_request;
extern grant_ref_t *g_gnttab_list;
extern grant_ref_t g_gnttab_free_head;
extern int g_gnttab_free_count;
extern void **ginfo;
extern KSPIN_LOCK xenbus_print_lock;
extern struct xenbus_watch vbd_watch;
extern struct xenbus_watch vif_watch;
extern struct xenbus_watch vscsi_watch;
extern struct xenbus_watch vusb_watch;

extern uint32_t gNR_GRANT_FRAMES;
extern uint32_t gNR_GRANT_ENTRIES;
extern uint32_t gGNTTAB_LIST_END;

extern int xen_store_evtchn;
extern struct xenstore_domain_interface *xen_store_interface;

#if defined XENBUG_TRACE_FLAGS || defined DBG
extern uint32_t rtrace;
extern uint32_t xenbus_locks;
#endif
#ifdef DBG
extern uint32_t evt_print;
extern uint32_t cpu_ints;
extern uint32_t cpu_ints_claimed;
#endif


#define PDX_TO_FDX(_pdx)                        \
    ((PFDO_DEVICE_EXTENSION) (_pdx->ParentFdo->DeviceExtension))

DRIVER_INITIALIZE XenDriverEntry;

KSERVICE_ROUTINE XenbusOnInterrupt;

/* function device subdispatch routines */
NTSTATUS
FDO_Pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS
PDO_Pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
PPDO_DEVICE_EXTENSION
xenbus_find_pdx_from_nodename(PFDO_DEVICE_EXTENSION fdx, char *nodename);

NTSTATUS
XenbusInitializePDO(PDEVICE_OBJECT fdo, char *type,
                    char *nodename, char *subnode);

NTSTATUS
XenbusDestroyPDO(PDEVICE_OBJECT pdo);

VOID
gnttab_suspend(void);

NTSTATUS
gnttab_init(uint32_t reason);

NTSTATUS
gnttab_finish_init(PDEVICE_OBJECT fdo, uint32_t reason);

void
evtchn_remove_queue_dpc(void);

VOID
evtchn_init(uint32_t reason);

KSYNCHRONIZE_ROUTINE EvtchnISR;

KDEFERRED_ROUTINE xenbus_invalidate_relations;

void
xb_read_msg(void);

void
xenbus_watch(IN PDEVICE_OBJECT DeviceObject, PDEVICE_OBJECT fdo);

IO_WORKITEM_ROUTINE xenbus_watch_work;

KDEFERRED_ROUTINE XenbusDpcRoutine;

void
xenbus_copy_fdx(PFDO_DEVICE_EXTENSION dfdx, PFDO_DEVICE_EXTENSION sfdx);

NTSTATUS
xenbus_ioctl(PFDO_DEVICE_EXTENSION fdx, PIRP Irp);

NTSTATUS
xenbus_set_reg_value(PWSTR key, PWSTR name, DWORD value);

NTSTATUS
xenbus_get_reg_value(PWSTR key, PWSTR name, DWORD *value);

NTSTATUS
xenbus_open_key(PWSTR key_wstr, HANDLE *registryKey);

void xenbus_shutdown_setup(uint32_t *shutdown, uint32_t *notify);

void balloon_do_reservation(uint64_t new_target);
void balloon_start(PFDO_DEVICE_EXTENSION fdx, uint32_t reason);
NTSTATUS balloon_init(void);

NTSTATUS xs_finish_init(PDEVICE_OBJECT fdo, uint32_t reason);
NTSTATUS xs_init(struct _FDO_DEVICE_EXTENSION *fdx, uint32_t reason);
VOID xs_cleanup(void);

NTSTATUS xenbus_probe_init(PDEVICE_OBJECT fdo, uint32_t reason);

#endif
