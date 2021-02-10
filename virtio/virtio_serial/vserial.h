/*
 * Copyright (c) 2010-2017 Red Hat, Inc.
 * Copyright 2014-2021 SUSE LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _VSERIAL_H
#define _VSERIAL_H

#include <ntddk.h>
#include <wdmsec.h>
#include <initguid.h>

#define NTSTRSAFE_NO_DEPRECATE
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <win_version.h>
#include <win_mmio_map.h>
#include <virtio_dbg_print.h>
#include <virtio_pci.h>
#include <virtio_pci_wdm.h>
#include <virtio_queue_ops.h>
#include "vsguid.h"
#include "vserial_ver.h"

#define VSERIAL_POOL_TAG (ULONG) 'lrsv'
#define VDEV_DRIVER_NAME "VSerial"

#define PORT_DEVICE_ID L"{6FDE7547-1B65-48ae-B628-80BE62016026}\\VIOSerialPort"
#define VSERIAL_TEXT_LOCATION_NAME_WSTR L"SUSE VSerial Port"
#define VSERIAL_DEVICE_NAME_WSTR    L"\\Device\\vserial"
#define VSERIAL_PORT_DEVICE_NAME_WSTR   L"\\Device\\vserial_port"
#define VSERIAL_REG_PARAM_DEVICE_KEY_WSTR L"virtio_serial\\Parameters\\Device"
#define VSERIAL_PORT_DEVICE_FORMAT_NAME_WSTR    L"%ws_%d"
#define VSERIAL_NUMBER_OF_QUEUES    64
#define VIRTIO_SERIAL_CONTROL_PORT_INDEX 1
#define VIRTIO_SERIAL_MAX_INTS      2
#define WDM_DEVICE_MAX_INTS VIRTIO_SERIAL_MAX_INTS
#define VSERIAL_MAX_NAME_LEN 128

#define VIRTIO_SERIAL_INVALID_INTERRUPT_STATUS 0xFF

#define VIRTIO_CONSOLE_F_SIZE           0
#define VIRTIO_CONSOLE_F_MULTIPORT      1
#define VIRTIO_CONSOLE_BAD_ID           (~(u32)0)


#define VIRTIO_CONSOLE_DEVICE_READY     0
#define VIRTIO_CONSOLE_PORT_ADD         1
#define VIRTIO_CONSOLE_PORT_REMOVE      2
#define VIRTIO_CONSOLE_PORT_READY       3

#define VIRTIO_CONSOLE_CONSOLE_PORT     4
#define VIRTIO_CONSOLE_RESIZE           5
#define VIRTIO_CONSOLE_PORT_OPEN        6
#define VIRTIO_CONSOLE_PORT_NAME        7

#define VSERIAL_PORT_ID_LEN 4
#define RETRY_THRESHOLD                 400
#define TEN_SEC_TIMEOUT                 100000000LL

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

#define IOCTL_GET_INFORMATION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct port_info_s {
    unsigned int id;
    BOOLEAN out_vq_full;
    BOOLEAN host_connected;
    BOOLEAN guest_connected;
    CHAR name[1];
} port_info_t;

typedef struct write_buffer_entry_s {
    SINGLE_LIST_ENTRY ListEntry;
    PVOID Buffer;
} write_buffer_entry_t, *pwrite_buffer_entry_t;

typedef struct port_buffer_s {
    PHYSICAL_ADDRESS    pa_buf;
    PVOID               va_buf;
    size_t              size;
    size_t              len;
    size_t              offset;
} port_buffer_t;

typedef struct port_status_change_s {
    ULONG Version;
    ULONG Reason;
} port_status_change_t;

typedef struct _WORKER_ITEM_CONTEXT {
    PIO_WORKITEM   WorkItem;
    PVOID          Argument1;
    PVOID          Argument2;
} WORKER_ITEM_CONTEXT, *PWORKER_ITEM_CONTEXT;

/* child PDOs device extension */
typedef struct _PDO_DEVICE_EXTENSION {
    COMMON_DEVICE_EXTENSION;
    uint32_t sig;

    PDEVICE_OBJECT ParentFdo;

    char instance_id[VSERIAL_PORT_ID_LEN];

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

    PDEVICE_OBJECT BusDevice;

    port_buffer_t *InBuf;
    KSPIN_LOCK inbuf_lock;
    KSPIN_LOCK ovq_lock;
    ANSI_STRING NameString;
    unsigned int port_id;
    unsigned int device_id;
    BOOLEAN OutVqFull;
    BOOLEAN HostConnected;
    BOOLEAN GuestConnected;

    BOOLEAN Removed;
    PIRP          PendingReadRequest;
    PIRP          PendingWriteRequest;

    /*
     * Hold a list of allocated buffers which were written to the virt queue
     * and was not returned yet.
     */
    SINGLE_LIST_ENTRY   WriteBuffersList;

    UNICODE_STRING ifname;
    KEVENT name_event;
    KEVENT port_opened_event;

} PDO_DEVICE_EXTENSION, *PPDO_DEVICE_EXTENSION;

#pragma pack(push)
#pragma pack(1)
typedef struct _console_config_s {
    uint16_t cols;
    uint16_t rows;
    uint32_t max_nr_ports;
} CONSOLE_CONFIG, *PCONSOLE_CONFIG;
#pragma pack(pop)


#pragma pack(push)
#pragma pack(1)
typedef struct _virtio_console_control_s {
    uint32_t id;
    uint16_t event;
    uint16_t value;
} VIRTIO_CONSOLE_CONTROL, *PVIRTIO_CONSOLE_CONTROL;
#pragma pack(pop)

/* FDO device extension as function driver */
typedef struct _FDO_DEVICE_EXTENSION {
    COMMON_DEVICE_EXTENSION;

    uint32_t sig;
    virtio_device_t vdev;
    virtio_bar_t vbar[PCI_TYPE0_ADDRESSES];
    CONSOLE_CONFIG console_config;
    virtio_queue_t *c_ivq;
    virtio_queue_t *c_ovq;
    virtio_queue_t **in_vqs;
    virtio_queue_t **out_vqs;
    wdm_device_int_info_t int_info[WDM_DEVICE_MAX_INTS];
    ULONG int_cnt;
#ifdef TARGET_OS_GTE_WinLH
    IO_INTERRUPT_MESSAGE_INFO *int_connection_ctx;
#endif

    PDEVICE_OBJECT Pdo;
    PDEVICE_OBJECT LowerDevice;
    UNICODE_STRING ifname;
    KDPC int_dpc;
    IO_REMOVE_LOCK RemoveLock;
    FAST_MUTEX Mutex;
    SYSTEM_POWER_STATE power_state;
        DEVICE_POWER_STATE dpower_state;
    LIST_ENTRY list_of_pdos;

    ULONG NumPDOs;
    KSPIN_LOCK qlock;
    KSPIN_LOCK cvq_lock;
    PIRP irp;
    PIO_WORKITEM item;
    uint32_t port;
    ULONG num_ports;
    INT is_host_multiport;
    uint64_t host_features;
    uint64_t guest_features;
    unsigned int device_id;
    IRP *PendingSIrp;
    LONG msg_int;
    LONG queue_int;
    BOOLEAN mapped_port;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;


extern PKINTERRUPT DriverInterruptObj;

extern PFDO_DEVICE_EXTENSION gfdx;
extern void **ginfo;

#define PDX_TO_FDX(_pdx)                        \
    ((PFDO_DEVICE_EXTENSION) (_pdx->ParentFdo->DeviceExtension))

#ifdef DBG
#define vserial_complete_request(_r, _i)                    \
{                                                           \
    DPRINTK(DPRTL_TRC, ("  %s: Complete request %p\n", __func__, (_r)));   \
    IoCompleteRequest((_r), (_i));                          \
}
#else
#define vserial_complete_request(_r, _i) IoCompleteRequest((_r), (_i))
#endif

DRIVER_ADD_DEVICE vserial_add_device;

/* function device subdispatch routines */

NTSTATUS
FDO_Pnp(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp
  );

NTSTATUS
PDO_Pnp(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp
  );

KDEFERRED_ROUTINE vserial_invalidate_relations;

KDEFERRED_ROUTINE VSerialDpcRoutine;

NTSTATUS
vserial_ioctl(PFDO_DEVICE_EXTENSION fdx, PIRP Irp);

NTSTATUS
vserial_set_reg_value(PWSTR key, PWSTR name, DWORD value);

NTSTATUS
vserial_get_reg_value(PWSTR key, PWSTR name, DWORD *value);

NTSTATUS
vserial_open_key(PWSTR key_wstr, HANDLE *registryKey);

void vserial_shutdown_setup(uint32_t *shutdown, uint32_t *notify);

/******************** vsint.c ****************/
KSERVICE_ROUTINE vserial_isr;

KMESSAGE_SERVICE_ROUTINE vserial_interrupt_message_service;

KDEFERRED_ROUTINE vserial_int_dpc;


/******************** vsbuf.c ****************/
void
vserial_free_buffer(IN port_buffer_t *buf);

size_t
vserial_send_buffers(PPDO_DEVICE_EXTENSION port,
    IN void *buffer,
    IN size_t length);

NTSTATUS
vserial_add_in_buf(IN virtio_queue_t *vq, IN port_buffer_t *buf);

port_buffer_t *
vserial_get_inf_buf(PPDO_DEVICE_EXTENSION port);

NTSTATUS
vserial_fill_queue(IN virtio_queue_t *vq, IN KSPIN_LOCK *lock);

void
vserial_reclaim_consumed_buffers(PPDO_DEVICE_EXTENSION port);

SSIZE_T
vserial_fill_read_buffer_locked(IN PPDO_DEVICE_EXTENSION port,
    IN PVOID outbuf,
    IN SIZE_T count);

/******************** vscontrol.c ****************/

void
vserial_ctrl_msg_get(IN PFDO_DEVICE_EXTENSION fdx);

void
vserial_ctrl_msg_send(
   IN PFDO_DEVICE_EXTENSION fdx,
   IN ULONG id,
   IN USHORT event,
   IN USHORT value);

NTSTATUS
vserial_queue_passive_level_callback(
    __in PFDO_DEVICE_EXTENSION fdx,
    __in PIO_WORKITEM_ROUTINE callback_function,
    __in_opt PVOID context1,
    __in_opt PVOID context2);


/******************** vsport.c ****************/
PPDO_DEVICE_EXTENSION
vserial_find_pdx_from_id(PFDO_DEVICE_EXTENSION fdx, unsigned int id);

IO_WORKITEM_ROUTINE vserial_port_add;

void
vserial_port_remove(PFDO_DEVICE_EXTENSION fdx, PPDO_DEVICE_EXTENSION port);

void
vserial_port_init_console(PPDO_DEVICE_EXTENSION port);

void
vserial_port_create_name(IN PFDO_DEVICE_EXTENSION fdx,
    IN PPDO_DEVICE_EXTENSION port,
    IN port_buffer_t *buf);

NTSTATUS vserial_port_register_interfaces(PPDO_DEVICE_EXTENSION port);
NTSTATUS vserial_port_create(PPDO_DEVICE_EXTENSION pdx);
void vserial_port_close(PPDO_DEVICE_EXTENSION pdx);
void vserial_port_discard_data_locked(PPDO_DEVICE_EXTENSION port);
BOOLEAN vserial_port_has_data_locked(PPDO_DEVICE_EXTENSION port);
void vserial_port_pnp_notify(PPDO_DEVICE_EXTENSION port);
NTSTATUS vserial_port_read(PPDO_DEVICE_EXTENSION port, PIRP request);
NTSTATUS vserial_port_write(PPDO_DEVICE_EXTENSION port, PIRP request);
NTSTATUS vserial_port_device_control(PPDO_DEVICE_EXTENSION port,
                                     IN PIRP request);
NTSTATUS vserial_port_power_on(PPDO_DEVICE_EXTENSION port);
NTSTATUS vserial_port_power_off(PPDO_DEVICE_EXTENSION port);
void vserial_destroy_pdo(PDEVICE_OBJECT pdo);

#endif
