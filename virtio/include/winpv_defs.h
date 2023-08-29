/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2008-2015 Novell, Inc.
 * Copyright 2015-2022 SUSE LLC
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

#ifndef _WINPV_DEFS_H
#define _WINPV_DEFS_H

#define XEN_INT_NOT_XEN 0x0
#define XEN_INT_DISK    0x1
#define XEN_INT_OTHER   0x2
#define XEN_INT_LAN     0x2
#define XEN_INT_XS      0x4

#define MAX_KEY_LEN                     256

#define PVVXBN_DEVICE_NAME_WSTR         \
    L"\\Device\\pvvxbn"
#define PVVXBN_DEVICE_KEY_WSTR          \
    L"pvvxbn\\Parameters\\Device"
#define PVVXBN_SYS_SRVC_KEY_WSTR        \
    L"SYSTEM\\CurrentControlSet\\Services\\pvvxbn"
#define PVVXBN_SYS_DEVICE_KEY_WSTR      \
    L"SYSTEM\\CurrentControlSet\\Services\\pvvxbn\\Parameters\\Device"
#define PVVXBN_FULL_DEVICE_KEY_WSTR     \
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\pvvxbn\\Parameters\\Device"

#define PVVXBLK_SYS_SRVC_KEY_WSTR        \
    L"SYSTEM\\CurrentControlSet\\Services\\pvvxblk"
#define PVVXSCSI_SYS_SRVC_KEY_WSTR       \
    L"SYSTEM\\CurrentControlSet\\Services\\pvvxscsi"
#define PVVXVSERIAL_SYS_SRVC_KEY_WSTR       \
    L"SYSTEM\\CurrentControlSet\\Services\\virtio_serial"

#define XENBN_DEVICE_NAME_WSTR          \
    L"\\Device\\XenBus"
#define XENBN_DEVICE_KEY_WSTR           \
    L"xenbus\\Parameters\\Device"
#define XENBUS_SYS_SRVC_KEY_WSTR        \
    L"SYSTEM\\CurrentControlSet\\Services\\xenbus"
#define XENBN_SYS_DEVICE_KEY_WSTR       \
    L"SYSTEM\\CurrentControlSet\\Services\\xenbus\\Parameters\\Device"
#define XENBN_FULL_DEVICE_KEY_WSTR      \
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\xenbus\\Parameters\\Device"

#define XENBLK_SYS_SRVC_KEY_WSTR        \
    L"SYSTEM\\CurrentControlSet\\Services\\xenblk"
#define XENSCSI_SYS_SRVC_KEY_WSTR       \
    L"SYSTEM\\CurrentControlSet\\Services\\xenscsi"

#define PVVXSVC_SYS_CCS_SERVICES_KEY_WSTR \
    L"SYSTEM\\CurrentControlSet\\Services\\pvvxsvc"
#define PVVX_MEM_STAT_PERIOD            \
    "mem_stat_period"

#define ENUM_PCI_FULL_REG_KEY_WSTR      \
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Enum\\PCI"

#define MISSING_DISK_KEY_WSTR           L"StartOverride"

#define ENUM_PCI_PVVX_WSTR              L"VEN_1AF4&DEV_100"
#define CONFIG_FLAGS_WSTR               L"ConfigFlags"
#ifndef CONFIGFLAG_FINISH_INSTALL
#define CONFIGFLAG_FINISH_INSTALL       0x400
#endif

#define SERVICE_REMOVE                  "remove"
#define SERVICE_INSTALL                 "install"
#define SC_SVC_CREATE                   "create"
#define SC_SVC_DELETE                   "delete"
#define SC_SVC_START                    "start"
#define SC_SVC_STOP                     "stop"
#define USE_PV_DRIVERS_WSTR             L"use_pv_drivers"
#define XENBUS_TIMEOUT_WSTR             L"timeout"
#define XENBUS_PVCTRL_FLAGS_WSTR        L"pvctrl_flags"
#define XENSVC_SHUTDOWN_DELAY_WSTR      L"shutdown_delay"
#define XENSVC_INSTALL_DELAY_WSTR       L"install_shutdown_delay"
#define XENBLK_MAX_DISKS_WSTR           L"max_disks"
#define XENBLK_MAX_SEGS_PER_REQ_WSTR    L"max_segs"
#define XENBUS_HVM_GUEST_PARAM_WSTR     L"hvm_guest_param"
#define XENBUS_PVCTRL_FLAG_BALLOON_WSTR L"balloon"
#define XENBUS_PVCTRL_GRANT_FRAMES_WSTR L"grant_frames"
#define XENBUS_PVCTRL_VM_PAGE_ADJUST_WSTR L"vm_page_adjustment"
#define XENBUS_PVCTRL_DERIVE_OS_MEM_WSTR L"derive_os_memory"
#define XENBUS_NOVELL_PVDRV_KEY_WSTR    L"SOFTWARE\\Novell\\pvdrv"
#define XENBUS_SETUP_RUNNIN_VN          L"setup_running"

#define XENBUS_SHUTDOWN_WSTR                L"shutdown"
#define XENBUS_SHUTDOWN_STR                 "shutdown"
#define XENBUS_SHUTDOWN_NOTIFICATION_WSTR   L"shutdown_notification"
#define XENBUS_SHUTDOWN_NOTIFICATION_STR    "shutdown_notification"

#define PVCTRL_DISK_WSTR                    L"disk"
#define PVCTRL_NO_DISK_WSTR                 L"no_disk"
#define PVCTRL_XVDISK_WSTR                  L"xvdisk"
#define PVCTRL_LAN_WSTR                     L"lan"
#define PVCTRL_NO_LAN_WSTR                  L"no_lan"
#define PVCTRL_NFLAN_WSTR                   L"nflan"
#define PVCTRL_BOOT_VSCSI_WSTR              L"boot_vscsi"
#define PVCTRL_FLAG_INSTANCE_ID_WSTR        L"instanceid"
#define PVCTRL_ON_WSTR                      L"on"
#define PVCTRL_OFF_WSTR                     L"off"
#define PVCTRL_ADD_TCP_SETTINGS_WSTR        L"add_tcp_settings"
#define PVCTRL_REMOVE_TCP_SETTINGS_WSTR     L"remove_tcp_settings"
#define PVCTRL_DEFAULT_SEND_WINDOW_WSTR     L"DefaultSendWindow"
#define PVCTRL_DEFAULT_RECEIVE_WINDOW_WSTR  L"DefaultReceiveWindow"
#define PVCTRL_FAST_SEND_DATAGRAM_THRESHOLD_WSTR    L"FastSendDatagramThreshold"
#define PVCTRL_TCP_WINDOW_SIZE_WSTR         L"TcpWindowSize"
#define PVCTRL_TCP_1323_OPTS_WSTR           L"Tcp1323Opts"
#define PVCTRL_QDEPTH_WSTR                  L"qdepth"
#define PVCTRL_QDEPTH_STR                   "qdepth"
#define PVCTRL_DBG_PRINT_MASK_STR           "dbg_print_mask"
#define PVCTRL_CDBG_PRINT_LIMIT_STR         "cdbg_print_limit"
#define RKEY_AFD_WSTR L"SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters"
#define RKEY_TCP_WSTR L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"

#define PVCTRL_MAX_BLK_QDEPTH               32
#define PVCTRL_DEFAULT_SEND_WINDOW          0x00100000
#define PVCTRL_DEFAULT_RECEIVE_WINDOW       0x00100000
#define PVCTRL_FAST_SEND_DATAGRAM_THRESHOLD 0x00004000
#define PVCTRL_TCP_WINDOW_SIZE              0x00100000
#define PVCTRL_TCP_1323_OPTS                1

#define XENBUS_NO_SHUTDOWN_NOTIFICATION         0
#define XENBUS_WANTS_SHUTDOWN_NOTIFICATION      1
#define XENBUS_UNDEFINED_SHUTDOWN_NOTIFICATION  (uint32_t)(-1)

#define XENBUS_REG_SHUTDOWN_VALUE               1
#define XENBUS_REG_REBOOT_VALUE                 2
#define XENBUS_REG_REBOOT_PROMPT_VALUE          4
#define XENBUS_REG_REBOOT_MIGRATE_VALUE         8

/* use_pv_drivers flags */
#define XENBUS_PROBE_PV_DISK                    0x00000001
#define XENBUS_PROBE_PV_NET                     0x00000002

/* Old defines that need to be converted to XENBUS_PROBE_PV_XVDISK. */
#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_FILE_DISK       0x00000004
#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_ALL_PHY_DISK    0x00000008
#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_ALL_BY_DISK     0x00000010
#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_BY_ID_DISK      0x00000020
#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_BY_NAME_DISK    0x00000040
#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_BY_PATH_DISK    0x00000080
#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_BY_UUID_DISK    0x00000100
#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_IOEMU_DISK      0x00000200

/* Xenblk will only control disks specified as xvd<x> wehere x is >= 'e'. */
#define XENBUS_PROBE_PV_XVDISK                          0x00000400
/* Xenblk will only control vifs specified as with type=netfrong. */
#define XENBUS_PROBE_PV_NFNET                           0x00000800
/* Xenblk can control QEMU SCSI disks. */
#define XENBUS_PROBE_PV_SDVDISK                         0x00001000

#define XENBUS_PROBE_PV_BOOT_VSCSI                      0x00002000

#define XENBUS_PROBE_PV_INSTALL_DISK_FLAG               0x00040000
#define XENBUS_PROBE_PV_INSTALL_NET_FLAG                0x00080000
#define XENBUS_PROBE_PV_NON_XEN_INSTALL_FLAG            0x00100000
#define XENBUS_PROBE_PV_XENBLK_MIGRATED_FLAG            0x00200000
#define XENBUS_PROBE_WINDOWS_UPDATE_FLAG                0x00400000
#define XENBUS_PROBE_PV_MAX_FLAG                        0x08000000

#define XENBUS_LEGACY_PROBE_PV_OVERRIDE_DISK_MASK       \
    (XENBUS_LEGACY_PROBE_PV_OVERRIDE_FILE_DISK          \
    | XENBUS_LEGACY_PROBE_PV_OVERRIDE_ALL_PHY_DISK      \
    | XENBUS_LEGACY_PROBE_PV_OVERRIDE_ALL_BY_DISK       \
    | XENBUS_LEGACY_PROBE_PV_OVERRIDE_BY_ID_DISK        \
    | XENBUS_LEGACY_PROBE_PV_OVERRIDE_BY_NAME_DISK      \
    | XENBUS_LEGACY_PROBE_PV_OVERRIDE_BY_PATH_DISK      \
    | XENBUS_LEGACY_PROBE_PV_OVERRIDE_BY_UUID_DISK      \
    | XENBUS_LEGACY_PROBE_PV_OVERRIDE_IOEMU_DISK)

#define XENBUS_SHOULD_NOT_CREATE_SYMBOLIC_LINK  0x80000000

#define PVCTRL_PARAM_USE_PV_DRIVERS     1
#define PVCTRL_PARAM_TIMEOUT            2
#define PVCTRL_PARAM_FLAGS              3
#define PVCTRL_PARAM_MAX_DISKS          4
#define PVCTRL_PARAM_MAX_VSCSI_DISKS    5
#define PVCTRL_PARAM_MAX_SEGS_PER_REQ   6

#define XENBUS_PV_ALL_PORTOFFSET        4
#define XENBUS_PV_SPECIFIC_PORTOFFSET   8
#define XENBUS_PV_PORTOFFSET_DISK_VALUE 1
#define XENBUS_PV_PORTOFFSET_NET_VALUE  2
#define XENBUS_PV_PORTOFFSET_ALL_VALUE  1

#define XEN_IOPORT_BASE         0x10

#define XEN_IOPORT_PLATFLAGS    (XEN_IOPORT_BASE + 0) /* 1 byte access (R/W) */
#define XEN_IOPORT_MAGIC        (XEN_IOPORT_BASE + 0) /* 2 byte access (R) */
#define XEN_IOPORT_UNPLUG       (XEN_IOPORT_BASE + 0) /* 2 byte access (W) */
#define XEN_IOPORT_DRVVER       (XEN_IOPORT_BASE + 0) /* 4 byte access (W) */

#define XEN_IOPORT_SYSLOG       (XEN_IOPORT_BASE + 2) /* 1 byte access (W) */
#define XEN_IOPORT_PROTOVER     (XEN_IOPORT_BASE + 2) /* 1 byte access (R) */
#define XEN_IOPORT_PRODNUM      (XEN_IOPORT_BASE + 2) /* 2 byte access (W) */

#define XEN_IOPORT_MAGIC_VAL    0x49d2

#define UNPLUG_ALL_IDE_DISKS    1
#define UNPLUG_ALL_NICS         2
#define UNPLUG_AUX_IDE_DISKS    4
#define UNPLUG_ALL              7

#define XENBLK_DEFAULT_TARGETS  32
#define XENBLK_MINIMUM_TARGETS  1
#define XENBLK_MAXIMUM_TARGETS  256

#define XENBLK_DEFAULT_MAX_SEGS 64
#define XENBLK_MIN_SEGS_PER_REQ 11
#define XENBLK_MAX_SEGS_PER_REQ 256

#define MIN_NR_GRANT_FRAMES 4
#define SETUP_DEFAULT_NR_GRANT_FRAMES 7
#define DEFAULT_NR_GRANT_FRAMES 10
#define MAX_NR_GRANT_FRAMES 32

#define XENBUS_MIN_VM_PAGE_ADJUSTMENT 0
#define XENBUS_MAX_VM_PAGE_ADJUSTMENT 0x7fffffff

#define XENBUS_DERIVE_OS_MEM_FROM_OS 1
#define XENBUS_DERIVE_OS_MEM_FROM_XENSTORE 2

#define XENBUS_NORMAL_INIT      1
#define XENBUS_RESUME_INIT      2
#define XENBUS_CRASHDUMP_INIT   4

#define OP_MODE_NORMAL          0x01
#define OP_MODE_HIBERNATE       0x02
#define OP_MODE_CRASHDUMP       0x04
#define OP_MODE_SHUTTING_DOWN   0x08
#define OP_MODE_DISCONNECTED    0x10
#define OP_MODE_RESTARTING      0x20

/* PVCTRL_FLAG flag values. */
#define XENBUS_PVCTRL_USE_INSTANCE_IDS  0x1
#define XENBUS_PVCTRL_ALLOW_STAND_BY    0x2
#define XENBUS_PVCTRL_USE_BALLOONING    0x4
#define XENBUS_PVCTRL_USE_JUST_ONE_CONTROLLER   0x8
#define XENBUS_PVCTRL_USE_VSCSI_SHUTDOWN_TIMER  0x10
#define PVCTRL_DISABLE_MEM_STATS                0x20
#define PVCTRL_DISABLE_FORCED_SHUTDOWN          0x40
#define XENBUS_PVCTRL_NO_MASTER_CONTROLLER      0x80
#define XENBUS_PVCTRL_MIGRATE_DO_INTERRUPTS     0x100

/* Match to xen/public/sched.h */
#define XENBUS_SHUTDOWN     0  /* Domain exited normally. Clean up and kill. */
#define XENBUS_REBOOT       1  /* Clean up, kill, and then restart.          */
#define XENBUS_SUSPEND      2  /* Clean up, save suspend info, kill.         */
#define XENBUS_CRASH        3  /* Tell controller we've crashed.             */
#define XENBUS_HALT         4
#define XENBUS_DEBUG_DUMP   5

#define XENSCSI_FLAGS_VN "flags"
#define XENSCSI_FLAGS_VN_WSTR L"flags"
#define XENSCSI_ALLOW_CONCURRENT_REQUESTS_F 0x1
#define PVCTRL_ALLOW_CONCURRENT_REQUESTS_WSTR L"xscr"
#define PVCTRL_CLEAR_CONCURRENT_REQUESTS_WSTR L"clear_xscr"
#define DEFAULT_XENSCSI_FLAGS 0
#define PVVXSCSI_SYS_DEVICE_KEY_WSTR      \
    L"SYSTEM\\CurrentControlSet\\Services\\pvvxscsi\\Parameters\\Device"

typedef struct xenbus_register_shutdown_event_s {
    LIST_ENTRY list;
    void *irp;
    unsigned long shutdown_type;
} xenbus_register_shutdown_event_t;

#define IOCTL_XENBUS_REGISTER_SHUTDOWN_EVENT \
   CTL_CODE(FILE_DEVICE_VMBUS, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif
