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

#include "xenbus.h"
#include "xen_support.h"

KSPIN_LOCK xenbus_print_lock;

static uint32_t xenbus_thread_count;

int
xenbus_grant_ring(domid_t otherend_id, unsigned long ring_mfn)
{
    int err;
    err = gnttab_grant_foreign_access(otherend_id, ring_mfn, 0);
    if (err < 0) {
        PRINTK(("XENBUS: granting access to ring page fail.\n"));
    }
    return err;
}

int
xenbus_alloc_evtchn(domid_t otherend_id, int *port)
{
    struct evtchn_alloc_unbound alloc_unbound;
    int err;

    alloc_unbound.dom = DOMID_SELF;
    alloc_unbound.remote_dom = otherend_id;

    err = (int)HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
        &alloc_unbound);

    if (err) {
        PRINTK(("XENBUS: allocating event channel fail.\n"));
    } else {
        *port = alloc_unbound.port;
    }

    return err;
}

int
xenbus_bind_evtchn(domid_t otherend_id, int remote_port, int *port)
{
    struct evtchn_bind_interdomain bind_interdomain;
    int err;

    bind_interdomain.remote_dom = otherend_id;
    bind_interdomain.remote_port = remote_port;

    err = (int)HYPERVISOR_event_channel_op(
      EVTCHNOP_bind_interdomain,
      &bind_interdomain);

    if (err) {
        PRINTK(("XENBUS: binding event channel %d from domain %d, fail.\n",
                 remote_port, otherend_id));
    } else {
        *port = bind_interdomain.local_port;
    }

    return err;
}

int
xenbus_free_evtchn(int port)
{
    struct evtchn_close close;
    int err;

    close.port = port;

    err = (int)HYPERVISOR_event_channel_op(
      EVTCHNOP_close, &close);
    if (err) {
        PRINTK(("XENBUS: freeing event channel %d fail.\n", port));
    }

    return err;
}

static BOOLEAN
xenbus_is_valid_pdo(PDEVICE_OBJECT pdo)
{
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;

    if (gfdo) {
        fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
        for (entry = fdx->ListOfPDOs.Flink;
                entry != &fdx->ListOfPDOs;
                entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            if (pdx->Self == pdo) {
                return TRUE;
            }
        }
    } else {
        PRINTK(("xenbus_is_valid_pdo: gfdo is NULL\n"));
    }
    return FALSE;
}

char *
xenbus_get_nodename_from_pdo(PDEVICE_OBJECT pdo)
{
    PPDO_DEVICE_EXTENSION pdx;

    if (xenbus_is_valid_pdo(pdo)) {
        pdx = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

        RPRINTK(DPRTL_ON, ("xenbus_get_nodename_from_pdo %p, %s.\n",
                           pdo, pdx->Nodename));
        return pdx->Nodename;
    }
    return NULL;
}

char *
xenbus_get_otherend_from_pdo(PDEVICE_OBJECT pdo)
{
    PPDO_DEVICE_EXTENSION pdx;

    if (xenbus_is_valid_pdo(pdo)) {
        pdx = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

        RPRINTK(DPRTL_ON, ("xenbus_get_otherend_from_pdo %p, %s.\n",
                           pdo, pdx->Otherend));
        return pdx->Otherend;
    }
    return NULL;
}

char *
xenbus_get_backendid_from_pdo(PDEVICE_OBJECT pdo)
{
    PPDO_DEVICE_EXTENSION pdx;

    if (xenbus_is_valid_pdo(pdo)) {
        pdx = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

        RPRINTK(DPRTL_ON, ("xenbus_get_backendid_from_pdo %p %s\n",
                           pdo, pdx->BackendID));
        return pdx->BackendID;
    }
    return NULL;
}

static PPDO_DEVICE_EXTENSION
xenbus_find_pdx_from_dev(void *dev)
{
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;

    if (gfdo) {
        fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
        for (entry = fdx->ListOfPDOs.Flink;
                entry != &fdx->ListOfPDOs;
                entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            if (pdx->frontend_dev == dev) {
                return pdx;
            }
        }
    } else {
        PRINTK(("xenbus_find_pdx_from_dev: gfdo is NULL\n"));
    }
    return NULL;
}

char *
xenbus_get_nodename_from_dev(void *dev)
{
    PPDO_DEVICE_EXTENSION pdx;

    pdx = xenbus_find_pdx_from_dev(dev);
    if (pdx != NULL) {
        return pdx->Nodename;
    }
    return NULL;
}

char *
xenbus_get_otherend_from_dev(void *dev)
{
    PPDO_DEVICE_EXTENSION pdx;

    pdx = xenbus_find_pdx_from_dev(dev);
    if (pdx != NULL) {
        return pdx->Otherend;
    }
    return NULL;
}

char *
xenbus_get_backendid_from_dev(void *dev)
{
    PPDO_DEVICE_EXTENSION pdx;

    pdx = xenbus_find_pdx_from_dev(dev);
    if (pdx != NULL) {
        return pdx->BackendID;
    }
    return NULL;
}

NTSTATUS
xenbus_get_pvctrl_param(void *mem, uint32_t param, uint32_t *value)
{
    PDEVICE_OBJECT fdo;
    PFDO_DEVICE_EXTENSION fdx;
    NTSTATUS cc;

    if (gfdo)  {
        fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
    } else if (mem) {
        fdo = *(PDEVICE_OBJECT *)(((shared_info_t *)mem) + 1);
        if (fdo)  {
            fdx = (PFDO_DEVICE_EXTENSION)fdo->DeviceExtension;
        } else {
            return STATUS_UNSUCCESSFUL;
        }
    } else  {
        return STATUS_UNSUCCESSFUL;
    }

    cc = STATUS_SUCCESS;
    switch (param) {
    case PVCTRL_PARAM_USE_PV_DRIVERS:
        *value = use_pv_drivers;
        break;
    case PVCTRL_PARAM_TIMEOUT:
        *value = delayed_resource_try_cnt;
        break;
    case PVCTRL_PARAM_FLAGS:
        *value = pvctrl_flags;
        break;
    case PVCTRL_PARAM_MAX_DISKS:
        if (pvctrl_flags & XENBUS_PVCTRL_USE_JUST_ONE_CONTROLLER) {
            *value = fdx->max_info_entries;
        } else {
            *value = 1;
        }
        break;
    case PVCTRL_PARAM_MAX_VSCSI_DISKS:
        *value = fdx->max_info_entries;
        break;
    case PVCTRL_PARAM_MAX_SEGS_PER_REQ:
        *value = g_max_segments_per_request;
        break;
    default:
        cc = STATUS_UNSUCCESSFUL;
        break;
    }
    return cc;
}

int
xenbus_switch_state(const char *nodename, enum xenbus_state state)
{
    int current_state;
    int err;

    if (nodename == NULL) {
        if (state == XENBUS_STATE_POWER_OFF) {
            HYPERVISOR_shutdown(SHUTDOWN_poweroff);
        } else if (state == XENBUS_STATE_REBOOT) {
            HYPERVISOR_shutdown(SHUTDOWN_reboot);
        }
        return 0;
    }
    err = xenbus_printf(XBT_NIL, nodename, "state", "%d", state);
    if (err) {
        return err;
    }

    return 0;
}

/*
 * xenbus_get_pv_port_options remains as a dll export so that older version
 * of xenblk will still load.
 */
uint32_t
xenbus_get_pv_port_options(xenbus_pv_port_options_t *options)
{
    NTSTATUS status;
    uint32_t devices_to_control;
    uint32_t devices_to_unplug;
    uint32_t shutdown_reason;
    uint32_t val;

    /*
     * Need to use the current value of use_pv_drivers since
     * xenbus_determine_pv_driver_usage() may block due to
     * the registry not being available now.
     */

    /* Figure out which devices we will be controlling. */
    devices_to_control = 0;
    if (use_pv_drivers & (XENBUS_PROBE_PV_DISK)) {
        devices_to_control |= XENBUS_PROBE_PV_DISK;
    }

    if (use_pv_drivers & (XENBUS_PROBE_PV_NET)) {
        devices_to_control |= XENBUS_PROBE_PV_NET;
    }

    /* Figure out which qemu devices need to be unplugged. */
    devices_to_unplug = 0;
    if ((use_pv_drivers & (XENBUS_PROBE_PV_DISK))
            && !(use_pv_drivers & (XENBUS_PROBE_PV_XVDISK))
            && !(use_pv_drivers & (XENBUS_PROBE_PV_INSTALL_DISK_FLAG))) {
        devices_to_unplug |= XENBUS_PROBE_PV_DISK;
    }

    if ((use_pv_drivers & (XENBUS_PROBE_PV_NET))
            && !(use_pv_drivers & (XENBUS_PROBE_PV_NFNET))
            && !(use_pv_drivers & (XENBUS_PROBE_PV_INSTALL_NET_FLAG))) {
        devices_to_unplug |= XENBUS_PROBE_PV_NET;
    }

    /* With the devices_to_unplug figured out, decide the options. */
    if (devices_to_unplug == (XENBUS_PROBE_PV_DISK | XENBUS_PROBE_PV_NET)) {
        options->port_offset = XENBUS_PV_ALL_PORTOFFSET;
        options->value = XENBUS_PV_PORTOFFSET_ALL_VALUE;
    } else if (devices_to_unplug == XENBUS_PROBE_PV_DISK) {
        options->port_offset = XENBUS_PV_SPECIFIC_PORTOFFSET;
        options->value = XENBUS_PV_PORTOFFSET_DISK_VALUE;
    } else if (devices_to_unplug == XENBUS_PROBE_PV_NET) {
        options->port_offset = XENBUS_PV_SPECIFIC_PORTOFFSET;
        options->value = XENBUS_PV_PORTOFFSET_NET_VALUE;
    } else {
        options->port_offset = 0;
        options->value = 0;

        PRINTK(("xenbus_get_pv_port_options: no devices to unplug, %x\n",
            use_pv_drivers));
        if (use_pv_drivers & XENBUS_PROBE_PV_NON_XEN_INSTALL_FLAG) {
            shutdown_reason = XENBUS_REG_REBOOT_PROMPT_VALUE;
            PRINTK(("xenbus_get_pv_port_options: shutdown for reboot\n"));
            xenbus_shutdown_setup(&shutdown_reason, NULL);
        } else if (use_pv_drivers & XENBUS_PROBE_PV_XENBLK_MIGRATED_FLAG) {
            shutdown_reason = XENBUS_REG_REBOOT_MIGRATE_VALUE           ;
            PRINTK(("xenbus_get_pv_port_options: shutdown for migrate\n"));
            xenbus_shutdown_setup(&shutdown_reason, NULL);
        }
    }

    /* Mark devices as needing to be installed and clear the install bits */
    if ((use_pv_drivers & (XENBUS_PROBE_PV_INSTALL_DISK_FLAG
                | XENBUS_PROBE_PV_INSTALL_NET_FLAG))) {
        PRINTK(("xenbus_get_pv_port_options: remove install flags.\n"));
        xenbus_set_reg_value(XENBUS_FULL_DEVICE_KEY_WSTR,
            USE_PV_DRIVERS_WSTR,
            use_pv_drivers & (~(XENBUS_PROBE_PV_INSTALL_DISK_FLAG
                | XENBUS_PROBE_PV_INSTALL_NET_FLAG
                | XENBUS_PROBE_PV_NON_XEN_INSTALL_FLAG)));
    }

    RPRINTK(DPRTL_ON,
            ("xb_pv_port_options: use_pv_drivers %x, probe %x, unplug %x\n",
             use_pv_drivers, devices_to_control, devices_to_unplug));
    return devices_to_control;
}

NTSTATUS
xenbus_control_pv_devices(void *in_port, uint32_t *pv_devices)
{
    xenbus_pv_port_options_t opt;
    void *port;
    uint32_t devices;
    uint16_t val;

    devices = xenbus_get_pv_port_options(&opt);
    if (pv_devices)  {
        *pv_devices = devices;
    }
    if (devices) {
        if (opt.value) {
            port = (void *)XEN_IOPORT_BASE;
            if (READ_PORT_USHORT(port) == XEN_IOPORT_MAGIC_VAL) {
                val = 0;
                if (opt.port_offset == XENBUS_PV_ALL_PORTOFFSET) {
                    val = UNPLUG_ALL;
                } else if (opt.value == XENBUS_PV_PORTOFFSET_DISK_VALUE) {
                    val = UNPLUG_ALL_IDE_DISKS | UNPLUG_AUX_IDE_DISKS;
                } else if (opt.value == XENBUS_PV_PORTOFFSET_NET_VALUE) {
                    val = UNPLUG_ALL_NICS;
                }

                port = (void *)XEN_IOPORT_PROTOVER;
                switch (READ_PORT_UCHAR(port)) {
                case 1:
                    port = (void *)XEN_IOPORT_PRODNUM;
                    WRITE_PORT_USHORT(port, PV_PRODUCTVERSION_MJMN);
                    port = (void *)XEN_IOPORT_DRVVER;
                    WRITE_PORT_ULONG(port, PV_PRODUCTVERSION_NUMBER);
                    port = (void *)XEN_IOPORT_BASE;
                    if (READ_PORT_USHORT(port) != XEN_IOPORT_MAGIC_VAL) {
                        PRINTK(("PV drivers not used: blacklisted\n"));
                        return STATUS_UNSUCCESSFUL;
                    }
                    /* Fall through */
                case 0:
                    RPRINTK(DPRTL_ON,
                            ("PV drivers writing to port 0x%x, val 0x%x\n",
                             XEN_IOPORT_UNPLUG, val));
                    port = (void *)XEN_IOPORT_UNPLUG;
                    WRITE_PORT_USHORT(port, val);
                    break;
                default:
                    PRINTK(("PV drivers not used: unknown qemu version\n"));
                    return STATUS_UNSUCCESSFUL;
                }
            } else {
                if (in_port) {
                    /* Fall back to doing it the old way. */
                    RPRINTK(DPRTL_ON,
                            ("xenbus_unplug: port %x, offset %x, val 0x%x.\n",
                             (PULONG)in_port, opt.port_offset, opt.value));
                    WRITE_PORT_ULONG((PVOID)((PUCHAR)in_port + opt.port_offset),
                        opt.value);
                }
            }
            RPRINTK(DPRTL_ON, ("  Done Write to the port io space\n"));
        }
    }
    return STATUS_SUCCESS;
}

void
xenbus_invalidate_relations(PKDPC dpc, PVOID dcontext, PVOID sa1, PVOID sa2)
{
    RPRINTK(DPRTL_ON, ("xenbus_invalidate_relations.\n"));
    if (dcontext) {
        IoInvalidateDeviceRelations((PDEVICE_OBJECT)dcontext, BusRelations);
    }
}

void *
xenbus_enum_xenblk_info(uint32_t *start_idx)
{
    PFDO_DEVICE_EXTENSION fdx;
    uint32_t i;

    if (gfdo) {
        fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
        for (i = *start_idx; i < fdx->max_info_entries; i++) {
            if (fdx->info[i] != NULL) {
                *start_idx = i + 1;
                return fdx->info[i];
            }
        }
    }
    return NULL;
}

NTSTATUS
xenbus_register_xenblk(void *controller,
    uint32_t op_mode,
    void ***info)
{
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;
    NTSTATUS status;
    uint32_t i;

    RPRINTK(DPRTL_ON, ("xenbus_register_xenblk: %p.\n", gfdo));

    status = STATUS_SUCCESS;
    if (gfdo) {
        fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
        if (pvctrl_flags & XENBUS_PVCTRL_USE_JUST_ONE_CONTROLLER) {
            *info = fdx->info;
            return STATUS_SUCCESS;
        } else {
            if (op_mode != OP_MODE_NORMAL) {
                RPRINTK(DPRTL_ON, ("xenbus_register_xenblk: non normal %x.\n",
                        op_mode));
                for (entry = fdx->ListOfPDOs.Flink;
                        entry != &fdx->ListOfPDOs;
                        entry = entry->Flink) {
                    pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
                    if (strcmp(pdx->Nodename, BOOT_DISK_NODE_NAME) == 0) {
                        RPRINTK(DPRTL_ON,
                               ("xenbus_register_xenblk: found boot disk %p.\n",
                                 &pdx->frontend_dev));
                        *info = &pdx->frontend_dev;
                        return STATUS_SUCCESS;
                    }
                }

                /*
                 * We didn't find the BOOT_DISK_NODE_NAME so look for the
                 * first disk in the list.  This still doesn't ensure that
                 * we will find the right disk due to load order but at
                 * least gives us a chance to do the crahsdump.
                 */
                for (entry = fdx->ListOfPDOs.Flink;
                        entry != &fdx->ListOfPDOs;
                        entry = entry->Flink) {
                    pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
                    if (pdx->Type == vbd && pdx->subtype == disk) {
                        RPRINTK(DPRTL_ON,
                                ("xenbus_register_xenblk: found vbd disk %p.\n",
                                 &pdx->frontend_dev));
                        *info = &pdx->frontend_dev;
                        return STATUS_SUCCESS;
                    }
                }
            } else {
                RPRINTK(DPRTL_ON, ("xenbus_register_xenblk: normal.\n"));
                for (i = 0; i < fdx->max_info_entries; i++) {
                    RPRINTK(DPRTL_ON,
                        ("xenbus_register_xenblk: i %d, info %p, &info %p.\n",
                         i, fdx->info[i], &fdx->info[i]));
                    if (fdx->info[i] == NULL) {
                        RPRINTK(DPRTL_ON,
                            ("xenbus_register_xenblk: emtpy entry %d.\n", i));
                        *info = &fdx->info[i];
                        return STATUS_SUCCESS;
                    }
                }
                return STATUS_UNSUCCESSFUL;
            }
        }
    } else {
        PRINTK(("xenbus_register_xenblk: gfdo is NULL\n"));
        status = STATUS_UNSUCCESSFUL;
    }
    RPRINTK(DPRTL_ON, ("xenbus_register_xenblk: OUT\n"));
    return status;
}

NTSTATUS
xenbus_register_vscsi(void *controller,
    uint32_t op_mode,
    void **info)
{
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;
    NTSTATUS status;
    uint32_t i;

    RPRINTK(DPRTL_ON, ("xenbus_register_vscsi: %p.\n", gfdo));

    status = STATUS_SUCCESS;
    if (gfdo) {
        fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
        if (op_mode != OP_MODE_NORMAL) {
            RPRINTK(DPRTL_ON, ("xenbus_register_vscsi: non normal %x.\n",
                               op_mode));
            for (entry = fdx->ListOfPDOs.Flink;
                    entry != &fdx->ListOfPDOs;
                    entry = entry->Flink) {
                pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
                if (pdx->Type == vscsi) {
                    RPRINTK(DPRTL_ON,
                            ("xenbus_register_vscsi: found boot disk %p.\n",
                             &pdx->frontend_dev));
                    *info = &pdx->frontend_dev;
                    return STATUS_SUCCESS;
                }
            }
        } else {
            RPRINTK(DPRTL_ON, ("xenbus_register_vscsi: normal.\n"));
            for (i = 0; i < fdx->max_info_entries; i++) {
                RPRINTK(DPRTL_ON,
                        ("xenbus_register_vscsi: i %d, info %p, &info %p.\n",
                         i, fdx->sinfo[i], &fdx->sinfo[i]));
                if (fdx->sinfo[i] == NULL) {
                    RPRINTK(DPRTL_ON,
                            ("xenbus_register_vscsi: emtpy entry %d.\n", i));
                    *info = &fdx->sinfo[i];
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_UNSUCCESSFUL;
        }
    } else {
        PRINTK(("xenbus_register_vscsi: gfdo is NULL\n"));
        status = STATUS_UNSUCCESSFUL;
    }
    RPRINTK(DPRTL_ON, ("xenbus_register_vscsi: OUT\n"));
    return status;
}

NTSTATUS
xenbus_claim_device(void *dev, void *controller,
    XENBUS_DEVICE_TYPE type, XENBUS_DEVICE_SUBTYPE subtype,
    uint32_t (*reserved)(void *context, pv_ioctl_t data),
    uint32_t (*ioctl)(void *context, pv_ioctl_t data))
{
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;
    NTSTATUS status;
    uint32_t can_claim;

    RPRINTK(DPRTL_ON, ("xenbus_claim_device: %p.\n", gfdo));

    if (!gfdo) {
        PRINTK(("xenbus_claim_device: gfdo is NULL.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;

    if (dev == NULL) {
        RPRINTK(DPRTL_ON, ("xenbus_claim_device: is a claim possible?\n"));
        for (entry = fdx->ListOfPDOs.Flink;
                entry != &fdx->ListOfPDOs;
                entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            RPRINTK(DPRTL_ON,
                    ("xenbus_claim_device: pdx %p: %d, %p, %p: %p %p\n",
                     pdx, pdx->Type, pdx->frontend_dev, pdx->controller,
                     dev, controller));
            if (pdx->Type == type && pdx->subtype == subtype
                    && pdx->frontend_dev == NULL) {
                if ((type == vbd || type == vscsi) &&
                        (use_pv_drivers & XENBUS_PROBE_PV_INSTALL_DISK_FLAG)) {
                    /*
                     * While we are still in the process of installing
                     * so we don't want xenblk to use the device yet.
                     */
                    PRINTK(("xenbus_claim_device: vbd installing.\n"));
                    return STATUS_RESOURCE_IN_USE;
                }
                RPRINTK(DPRTL_ON,
                        ("xenbus_claim_device: it can be claimed.\n"));
                return STATUS_SUCCESS;
            }
        }
        return STATUS_NO_MORE_ENTRIES;
    }

    RPRINTK(DPRTL_ON, ("xenbus_claim_device: start the claim: %p.\n", dev));
    for (entry = fdx->ListOfPDOs.Flink;
        entry != &fdx->ListOfPDOs;
        entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        /* See if it has already been claimed by the dev.*/
        if (pdx->Type == type && pdx->subtype == subtype
                && pdx->frontend_dev == dev) {
            RPRINTK(DPRTL_ON, ("xenbus_claim_device: %p already claimed.\n",
                               dev));
            return STATUS_RESOURCE_IN_USE;
        }
    }

    /* It was not in the list, see if can be added. */
    for (entry = fdx->ListOfPDOs.Flink;
        entry != &fdx->ListOfPDOs;
        entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if (pdx->Type == type && pdx->subtype == subtype
                && pdx->frontend_dev == NULL) {
            pdx->frontend_dev = dev;
            pdx->controller = controller;
            pdx->ioctl = ioctl;
            RPRINTK(DPRTL_ON, ("xenbus_claim_device: pdx %p claimed it %p.\n",
                               pdx, pdx->frontend_dev));
            if ((type == vbd || type == vscsi) &&
                    (use_pv_drivers & XENBUS_PROBE_PV_INSTALL_DISK_FLAG)) {
                use_pv_drivers &= ~XENBUS_PROBE_PV_INSTALL_DISK_FLAG;
                use_pv_drivers |= XENBUS_PROBE_PV_DISK;
                PRINTK(("xenbus_claim_device: use_pv_drivers %x.\n",
                    use_pv_drivers));
                xenbus_set_reg_value(XENBUS_FULL_DEVICE_KEY_WSTR,
                    USE_PV_DRIVERS_WSTR,
                    use_pv_drivers);
            }
            return STATUS_SUCCESS;
        }
    }

    RPRINTK(DPRTL_ON,
            ("xenbus_claim_device: returning STATUS_NO_MORE_ENTRIES.\n"));
    return STATUS_NO_MORE_ENTRIES;
}

void
xenbus_release_device(void *dev, void *controller,
    xenbus_release_device_t release_data)
{
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    PPDO_DEVICE_EXTENSION pdx_hba;
    PLIST_ENTRY entry, pdx_entry;
    NTSTATUS status;
    uint32_t active_vbds;
    uint32_t found_vbds;
    uint32_t vbds_remaining;

    PRINTK(("xenbus_release_device: %p.\n", gfdo));
    XENBUS_SET_FLAG(rtrace, XENBUS_RELEASE_DEVICE_F);

    if (gfdo == NULL) {
        RPRINTK(DPRTL_ON, ("xenbus_release_device: gfdo is NULL\n"));
        return;
    }

    fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
    if (fdx != NULL) {
        RPRINTK(DPRTL_ON, ("  d = %p c = %p t = %d.\n",
                           dev, controller, release_data.type));
        active_vbds = 0;
        found_vbds = 0;
        for (entry = fdx->ListOfPDOs.Flink;
                entry != &fdx->ListOfPDOs;
                entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            RPRINTK(DPRTL_ON,
                    ("xenbus_release_device: pdx %p: %d, %p, %p: %p, %p\n",
                     pdx, pdx->Type, pdx->frontend_dev, pdx->controller,
                     dev, controller));
            if ((pdx->Type == vbd || pdx->Type == vscsi) && pdx->frontend_dev) {
                active_vbds++;
                found_vbds++;
            }
            if (pdx->Type == release_data.type
                    && pdx->frontend_dev == dev) {
                RPRINTK(DPRTL_ON, ("  found match, nulling out fronend_dev\n"));
                if (release_data.action == RELEASE_REMOVE) {
                    PRINTK(("  Mark as reported missing: %s\n  pdx %p pdo %p\n",
                               pdx->Nodename,
                               pdx, pdx->Self->DeviceExtension));
                    pdx->Present = FALSE;
                    pdx->ReportedMissing = TRUE;

                    if (pdx->origin == alloced) {
                        PRINTK(("  XenbusDestroyPDO %s: pdx %p pdo %p\n",
                                   pdx->Nodename,
                                   pdx, pdx->Self->DeviceExtension));
                        fdx->NumPDOs--;
                        RemoveEntryList(&pdx->Link);
                        XenbusDestroyPDO(pdx->Self);
                        ExFreePool(pdx->Self);

                        /*
                         * For vbd disks using one controller, see if we
                         * need to also remove the pdo associated with
                         * the controller
                         */
                        if (fdx && pdx->Type == vbd
                                && (pvctrl_flags &
                                    XENBUS_PVCTRL_USE_JUST_ONE_CONTROLLER)) {
                            vbds_remaining = 0;
                            pdx_hba = NULL;
                            for (pdx_entry = fdx->ListOfPDOs.Flink;
                                    pdx_entry != &fdx->ListOfPDOs;
                                    pdx_entry = pdx_entry->Flink) {
                                pdx = CONTAINING_RECORD(pdx_entry,
                                    PDO_DEVICE_EXTENSION, Link);
                                if (pdx->Type == vbd
                                       && pdx->subtype == hba) {
                                    pdx_hba = pdx;
                                } else if (pdx->Type == vbd) {
                                    vbds_remaining++;
                                }
                            }
                            if (vbds_remaining == 0 && pdx_hba != NULL) {
                                PRINTK(("  Report hba as missing %s: hba %p\n",
                                           pdx_hba->Nodename,
                                           pdx_hba));
                                pdx_hba->Present = FALSE;
                                pdx_hba->ReportedMissing = TRUE;
                            }
                        }
                    }

                    RPRINTK(DPRTL_ON, ("  IoInvalidateDeviceRelations.\n"));
                    IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);
                } else {
                    RPRINTK(DPRTL_ON, ("  pdx %p: nulling %p, %p\n",
                                       pdx, pdx->frontend_dev,
                                       pdx->controller));
                    if ((pdx->Type == vbd || pdx->Type == vscsi)
                            && pdx->frontend_dev) {
                        active_vbds--;
                    }
                    pdx->frontend_dev = NULL;
                    pdx->controller = NULL;
                }

                PRINTK(("xenbus_release_device: match out\n"));
                return;
            }
        }
    } else {
        RPRINTK(DPRTL_ON, ("xenbus_release_device: fdx is NULL\n"));
    }
    PRINTK(("xenbus_release_device: out\n"));
}

ULONG
xenbus_handle_evtchn_callback(void)
{
    return EvtchnISR(NULL);
}

NTSTATUS
xenbus_create_thread(PKSTART_ROUTINE callback, void *context)
{
    HANDLE hthread;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;

    DPRINTK(DPRTL_ON, ("xenbus_create_thread IN.\n"));
    InitializeObjectAttributes(
      &oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    DPRINTK(DPRTL_ON, ("xenbus_create_thread PsCreateSystemThread IN.\n"));
    status = PsCreateSystemThread(
      &hthread,
      THREAD_ALL_ACCESS,
      &oa,
      NULL,
      NULL,
      callback,
      context);
    DPRINTK(DPRTL_ON, ("xenbus_create_thread PsCreateSystemThread OUT.\n"));

    if (NT_SUCCESS(status)) {
        ZwClose(hthread);
    }
    DPRINTK(DPRTL_ON, ("xenbus_create_thread OUT.\n"));
    xenbus_thread_count++;
    return status;
}

void
xenbus_terminate_thread(void)
{
    xenbus_thread_count--;
    PsTerminateSystemThread(STATUS_SUCCESS);
}

void
xenbus_print_str(char *str)
{
    PUCHAR port;
    XEN_LOCK_HANDLE lh;
    char *c;

    /*
     * Spin locks don't protect against irql > 2.  So if we come in at a
     * higl level, just print it and we'll have to maually sort out the
     * the possible mixing of multiple output messages.
     */
    port = (PUCHAR)XENBUS_PRINTK_PORT;
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        for (c = str; *c; c++) {
            WRITE_PORT_UCHAR(port, *c);
        }
    } else {
        XenAcquireSpinLock(&xenbus_print_lock, &lh);
        for (c = str; *c; c++) {
            WRITE_PORT_UCHAR(port, *c);
        }
        XenReleaseSpinLock(&xenbus_print_lock, lh);
    }
}

void
xenbus_printk(char *_fmt, ...)
{
    va_list ap;
    char buf[256];
    char *c;

    va_start(ap, _fmt);
    RtlStringCbVPrintfA(buf, sizeof(buf), _fmt, ap);
    va_end(ap);
    xenbus_print_str(buf);
}

void
xenbus_console_io(char *_fmt, ...)
{
    va_list ap;
    char buf[256];

    va_start(ap, _fmt);
    RtlStringCbVPrintfA(buf, sizeof(buf), _fmt, ap);
    va_end(ap);

    if (!hypercall_page) {
        if (InitializeHypercallPage() != STATUS_SUCCESS) {
            return;
        }
    }
    HYPERVISOR_console_io(0, strlen(buf), buf);
}
