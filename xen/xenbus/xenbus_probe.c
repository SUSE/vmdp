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

static NTSTATUS xenbus_probe_bus(PDEVICE_OBJECT fdo);
static NTSTATUS xenbus_probe_type(PDEVICE_OBJECT fdo, char *type);
static NTSTATUS xenbus_probe_device(PDEVICE_OBJECT fdo, char *type, char *name);
static NTSTATUS xenbus_probe_node(PDEVICE_OBJECT fdo, char *type,
    char *nodename);
static XENBUS_DEVICE_ORIGIN xenbus_determine_creation_type(
    PFDO_DEVICE_EXTENSION fdx,
    XENBUS_DEVICE_TYPE xtype);
static NTSTATUS xenbus_type_to_hwid(PPDO_DEVICE_EXTENSION pdx,
    XENBUS_DEVICE_TYPE xtype);
static NTSTATUS xenbus_type_to_pci_hwid(PPDO_DEVICE_EXTENSION pdx,
    XENBUS_DEVICE_TYPE xtype);


static char *xenbus_nodename_to_hwid(char *nodename);

static NTSTATUS xenbus_init_pdx(PDEVICE_OBJECT fdo, PDEVICE_OBJECT pdo,
                XENBUS_DEVICE_TYPE xtype, XENBUS_DEVICE_SUBTYPE subtype,
                XENBUS_DEVICE_ORIGIN origin, char *nodename,
                char *subnode, ULONG add_pci_during_install);

#define STRLEN_MAX  512
#define ADD_PCI "Add PCI"

NTSTATUS
xenbus_probe_init(PDEVICE_OBJECT fdo, uint32_t reason)
{
    PFDO_DEVICE_EXTENSION fdx;
    uint32_t num_pdos;
    NTSTATUS status;

    if (reason != OP_MODE_NORMAL) {
        return STATUS_SUCCESS;
    }

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;
    num_pdos = fdx->NumPDOs;
    status = xenbus_probe_bus(fdo);
    RPRINTK(DPRTL_PROBE,
            ("xenbus_probe_init: irql %d cpu %x n_pdos %d NPDOs %d\n",
             KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
             num_pdos, fdx->NumPDOs));
#ifdef PVVX
    /* We just want to get the Enum\PCI entry created incase we boot to KVM. */
    if (use_pv_drivers & XENBUS_PROBE_PV_INSTALL_DISK_FLAG) {
        PRINTK(("xenbus_probe_init: Populate PCI reg devices.\n"));
        XenbusInitializePDO(fdo, "vbd", "pvvxblk", ADD_PCI);
        XenbusInitializePDO(fdo, "vscsi", "pvvxscsi", ADD_PCI);
    }
#endif
    return status;
}

/* Called at device start */
static NTSTATUS
xenbus_probe_bus(PDEVICE_OBJECT fdo)
{
    NTSTATUS status;
    char **dir;
    unsigned int i, dir_n;

    RPRINTK(DPRTL_PROBE, ("XENBUS: xenbus_probe_bus().\n"));
    dir = xenbus_directory(XBT_NIL, "device", "", &dir_n);
    RPRINTK(DPRTL_PROBE, ("XENBUS: device/* check finished.\n"));
    if (IS_ERR(dir)) {
        PRINTK(("XENBUS: xs get directory device/ fail.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    status = STATUS_SUCCESS;
    for (i = 0; i < dir_n && status == STATUS_SUCCESS; i++) {
        RPRINTK(DPRTL_PROBE, ("XENBUS: xenbus_probe_bus type %s %x.\n",
                              dir[i], use_pv_drivers));
        if (strcmp(dir[i], "vif") == 0 &&
                !(use_pv_drivers & XENBUS_PROBE_PV_NET)) {
            continue;
        } else if (strcmp(dir[i], "vbd") == 0 &&
                /*
                 * This lets us probe for disk during install even though
                 * XENBUS_PROBE_PV_DISK may not be set.
                 */
                !(use_pv_drivers & XENBUS_PROBE_PV_INSTALL_DISK_FLAG) &&
                !(use_pv_drivers & XENBUS_PROBE_PV_DISK)) {
            continue;
        }
        RPRINTK(DPRTL_PROBE, ("XENBUS: beginning to probe type %s.\n", dir[i]));
        status = xenbus_probe_type(fdo, dir[i]);
    }

    ExFreePool(dir);

    RPRINTK(DPRTL_PROBE, ("XENBUS: xenbus_probe_bus returning %x.\n", status));
    return status;
}

static NTSTATUS
xenbus_probe_type(PDEVICE_OBJECT fdo, char *type)
{
    NTSTATUS status;
    char **dir;
    unsigned int i, dir_n = 0;

    /* type is vbd, vif, vscsi, etc. */
    RPRINTK(DPRTL_PROBE, ("XENBUS: xenbus_probe_type().\n"));
    dir = xenbus_directory(XBT_NIL, "device", type, &dir_n);
    if (IS_ERR((PVOID)dir)) {
        PRINTK(("XENBUS: xs get directory device/%s/ fail.\n", type));
        return STATUS_UNSUCCESSFUL;
    }

    status = STATUS_SUCCESS;
    for (i = 0; i < dir_n && status == STATUS_SUCCESS; i++) {
        status = xenbus_probe_device(fdo, type, dir[i]);
    }

    ExFreePool(dir);

    return status;
}

static NTSTATUS
xenbus_probe_device(PDEVICE_OBJECT fdo, char *type, char *name)
{
    char *nodename;
    NTSTATUS status;
    size_t i, j;

    /* name is 0, 1, 2, etc. */
    RPRINTK(DPRTL_PROBE, ("XENBUS: xenbus_probe_device().\n"));
    i = strlen(type);
    j = strlen(name);
    nodename = kasprintf(i + j + 2 + 6, "%s/%s/%s", "device", type, name);

    if (nodename == NULL) {
        RPRINTK(DPRTL_PROBE,
                ("XENBUS: xenbus_probe_device failed kasprintf.\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = xenbus_probe_node(fdo, type, nodename);

    ExFreePool(nodename);

    return status;
}

/* The following function is called when the bus first enumerates */
static NTSTATUS
xenbus_probe_node(PDEVICE_OBJECT fdo, char *type, char *nodename)
{
    NTSTATUS status = STATUS_SUCCESS;

    /* nodename is device/type/instance e.g. device/vbd/0 */
    status = XenbusInitializePDO(fdo, type, nodename, NULL);
    RPRINTK(DPRTL_PROBE, ("XENBUS: xenbus_probe_node returning %x\n", status));

    return status;
}

static void
xenbus_get_vscsi_info(char *otherend, XENBUS_DEVICE_SUBTYPE *subtype,
    DEVICE_TYPE  *devtype)
{
    *subtype = none;
    *devtype = FILE_DEVICE_CONTROLLER;
}

NTSTATUS
XenbusInitializePDO(PDEVICE_OBJECT fdo, char *type, char *nodename,
    char *subnode)
{
    PFDO_DEVICE_EXTENSION fdx;
    PDEVICE_OBJECT pdo;
    PPDO_DEVICE_EXTENSION pdx;
    NTSTATUS status;
    ANSI_STRING astr;
    char *res;
    char *otherend;
    ULONG len;
    XENBUS_DEVICE_TYPE xtype;
    XENBUS_DEVICE_SUBTYPE subtype;
    XENBUS_DEVICE_ORIGIN origin;
    DEVICE_TYPE dev_type;
    ULONG add_pci_during_install;

    RPRINTK(DPRTL_ON, ("XenbusInitializePDO: new PDO, id: %s, type = %s.\n",
                       nodename, type));

    fdx = (PFDO_DEVICE_EXTENSION)fdo->DeviceExtension;
    otherend = NULL;
    add_pci_during_install = 0;

    if (subnode) {
        if (strcmp(subnode, ADD_PCI) == 0) {
            add_pci_during_install = 1;
            subnode = NULL;
        }
    }

    if (add_pci_during_install) {
        if (strcmp(type, "vbd") == 0) {
            xtype = vbd;
            subtype = disk;
            dev_type = FILE_DEVICE_DISK;
        } else if (strcmp(type, "vscsi") == 0) {
            xtype = vscsi;
            xenbus_get_vscsi_info(otherend, &subtype, &dev_type);
        }
    } else {
        RPRINTK(DPRTL_PROBE, ("XenbusInitializePDO: xenbus_read backend\n"));
        otherend = xenbus_read(XBT_NIL, nodename, "backend", NULL);
        if (otherend == NULL) {
            PRINTK(("XenbusInitializePDO: unable to read backend for\n"));
            PRINTK(("  %s\n", nodename));
            PRINTK(("  Skipping device\n"));
            return STATUS_SUCCESS;
        }
        RPRINTK(DPRTL_ON, ("XenbusInitializePDO: otherend %s.\n",
                           otherend));

        if (strcmp(type, "vif") == 0) {
            xtype = vnif;
            subtype = none;
            dev_type = FILE_DEVICE_NETWORK;
        } else if (strcmp(type, "vbd") == 0) {
            res = xenbus_read(XBT_NIL, nodename, "device-type", NULL);
            if (res) {
                RPRINTK(DPRTL_PROBE,
                        ("XenbusInitializePDO: xenbus_read device-type %s\n",
                         res));
                if (strcmp(res, "disk") != 0) {
                    /* We only control disks. */
                    xenbus_free_string(res);
                    xenbus_free_string(otherend);
                    return STATUS_SUCCESS;
                }
                xenbus_free_string(res);
                xtype = vbd;
                subtype = disk;
                dev_type = FILE_DEVICE_DISK;
            } else {
                RPRINTK(DPRTL_PROBE,
                    ("XenbusInitializePDO: xenbus_read device-type failed\n"));
                xenbus_free_string(otherend);
                return STATUS_SUCCESS;
            }
        } else if (strcmp(type, "vscsi") == 0) {
            xtype = vscsi;
            xenbus_get_vscsi_info(otherend, &subtype, &dev_type);
        } else if (strcmp(type, "vusb") == 0) {
            xtype = vusb;
            xenbus_free_string(otherend);
            /* We currently don't handle vusb devices. */
            return STATUS_SUCCESS;
        } else {
            xenbus_free_string(otherend);
            /* We don't want to create an unknown device. */
            return STATUS_SUCCESS;
        }

        if (xtype == vbd && subtype == disk) {
            /*
             * We already know that we control disks, but check if we only
             * control xvde and greater and no ioemu e.g. hd<x> disks.
             */
            res = xenbus_read(XBT_NIL, otherend, "dev", NULL);
            if (res) {
                if (use_pv_drivers & XENBUS_PROBE_PV_XVDISK) {
                    RPRINTK(DPRTL_PROBE, ("XenbusInitializePDO: dev = %s\n",
                                          res));
                    if ((res[0] == 'h' && res[1] == 'd') ||
                            (res[0] == 'x' && res[1] == 'v' &&
                                res[2] == 'd' && res[3] < 'e')) {
                        RPRINTK(DPRTL_PROBE, ("\tDon't control IOEMU disks\n"));
                        xenbus_free_string(res);
                        xenbus_free_string(otherend);
                        return STATUS_SUCCESS;
                    }
                }

                if (!(use_pv_drivers & XENBUS_PROBE_PV_SDVDISK)) {
                    if (res[0] == 's' && res[1] == 'd') {
                        /*
                         * The disk line was something like: phy:/dev/sdb,sda,w
                         * XENBUS_PROBE_PV_SDVDISK was not set so don't control
                         */
                        RPRINTK(DPRTL_PROBE,
                                ("\tDon't control IOEMU SCSI disks\n"));
                        xenbus_free_string(res);
                        xenbus_free_string(otherend);
                        return STATUS_SUCCESS;
                    }
                }

                xenbus_free_string(res);
            }

            if (use_pv_drivers & XENBUS_PROBE_PV_BOOT_VSCSI) {
                res = xenbus_read(XBT_NIL, otherend, "type", NULL);
                if (res) {
                    if (strcmp(res, "phy") == 0) {
                        /*
                         * There must be a correspoinging vscsi=[] entry
                         * or the disk will not be seen.
                         *
                         * Checking for phy will allow non phy disks to be
                         * controlled by xenblk.  IDE disks are not allowed.
                         */
                        RPRINTK(DPRTL_PROBE,
                                ("\tXenScsi will handle all phy disks.\n"));
                        xenbus_free_string(res);
                        xenbus_free_string(otherend);
                        return STATUS_SUCCESS;
                    }
                    xenbus_free_string(res);
                }
            }
        }

        if (xtype == vnif) {
            /*
             * We already know that we control vifs, but check if we only
             * control the type=netfront or type=vif vifs.
             */
            if (use_pv_drivers & XENBUS_PROBE_PV_NFNET) {
                res = xenbus_read(XBT_NIL, otherend, "type", NULL);
                if (res) {
                    RPRINTK(DPRTL_PROBE,
                            ("XenbusInitializePDO: type = %s\n", res));
                    if (strcmp(res, "netfront") != 0 &&
                            strcmp(res, "vif") != 0) {
                        RPRINTK(DPRTL_PROBE, ("\tDon't control IOEMU vifs\n"));
                        xenbus_free_string(res);
                        xenbus_free_string(otherend);
                        return STATUS_SUCCESS;
                    }
                    xenbus_free_string(res);
                } else {
                    RPRINTK(DPRTL_PROBE,
                        ("\tDon't control IOEMU vifs, not type specified.\n"));
                    xenbus_free_string(otherend);
                    return STATUS_SUCCESS;
                }
            }
        }
    }

    /* If we have already created the pdo, don't do it again. */
    pdx = xenbus_find_pdx_from_nodename(fdx, nodename);
    if (add_pci_during_install || pdx == NULL) {
        origin = xenbus_determine_creation_type(fdx, xtype);
        if (origin == alloced) {
            RPRINTK(DPRTL_PROBE,
                    ("XenbusInitializePDO: allocating PDO, id: %s.\n",
                     nodename));
            pdo = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                sizeof(DEVICE_OBJECT) + sizeof(PDO_DEVICE_EXTENSION),
                XENBUS_POOL_TAG);
            if (pdo) {
                pdo->DeviceExtension = pdo + 1;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_NO_MEMORY;
            }
        } else if (origin == created) {
            RPRINTK(DPRTL_PROBE,
                    ("XenbusInitializePDO: creating PDO, id: %s.\n",
                     nodename));
            status = IoCreateDeviceSecure(
                fdo->DriverObject,
                sizeof(PDO_DEVICE_EXTENSION),
                NULL,
                dev_type,
                FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN,
                FALSE,
                &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                (LPCGUID)&GUID_SD_XENBUS_PDO,
                &pdo);
            if (NT_SUCCESS(status) && xtype == vbd && subtype == disk
                    && (pvctrl_flags & XENBUS_PVCTRL_USE_JUST_ONE_CONTROLLER)
                    && !((pvctrl_flags & XENBUS_PVCTRL_NO_MASTER_CONTROLLER))
                    && add_pci_during_install == 0) {

                /* Allow this created pdo to represent the controller. */
                status = xenbus_init_pdx(fdo, pdo, xtype, hba, origin,
                                         nodename, subnode,
                                         add_pci_during_install);
                if (!NT_SUCCESS(status)) {
                    xenbus_free_string(otherend);
                    IoDeleteDevice(pdo);
                    return status;
                }

                /* Just need this pdx incase the following pdo alloc fails. */
                pdx = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

                /* Now alloc the pdo that will represent this disk. */
                pdo = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                    sizeof(DEVICE_OBJECT) + sizeof(PDO_DEVICE_EXTENSION),
                    XENBUS_POOL_TAG);
                if (pdo) {
                    pdo->DeviceExtension = pdo + 1;
                    status = STATUS_SUCCESS;
                } else {
                    IoDeleteDevice(pdx->Self);
                    xenbus_free_string(otherend);
                    status = STATUS_NO_MEMORY;
                }
                origin = alloced;
            }
        } else {
            RPRINTK(DPRTL_PROBE,
                    ("XenbusInitializePDO: unknown origin for type: %s.\n",
                     nodename));
            xenbus_free_string(otherend);
            return STATUS_SUCCESS;
        }

        if (!NT_SUCCESS(status)) {
            PRINTK(("XENBUS: create pdo device fail for %s.\n", nodename));
            xenbus_free_string(otherend);
            return status;
        }

        status = xenbus_init_pdx(fdo, pdo, xtype, subtype, origin,
                                 nodename, subnode, add_pci_during_install);
        if (!NT_SUCCESS(status)) {
            xenbus_free_string(otherend);
            if (origin == alloced) {
                ExFreePool(pdo);
            } else {
                IoDeleteDevice(pdo);
            }
            return status;
        }
        pdx = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

        if (xtype == vnif && (pvctrl_flags & XENBUS_PVCTRL_USE_INSTANCE_IDS)) {
            pdx->instance_id = xenbus_read(XBT_NIL, nodename, "mac", &len);
        } else {
            pdx->instance_id = NULL;
        }

    }

    /* The backend-id always needs to be updated incase a hibernate happened. */
    RPRINTK(DPRTL_PROBE, ("XenbusInitializePDO: xenbus_read backend-id\n"));
    res = xenbus_read(XBT_NIL, nodename, "backend-id", &len);
    if (res) {
        pdx->BackendID = res;
    } else {
        pdx->BackendID = NULL;
    }

    pdx->Otherend = otherend;

    RPRINTK(DPRTL_ON, ("XenbusInitializePDO: %s. out\n", pdx->Otherend));
    return STATUS_SUCCESS;
}

PPDO_DEVICE_EXTENSION
xenbus_find_pdx_from_nodename(PFDO_DEVICE_EXTENSION fdx, char *nodename)
{
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;

    for (entry = fdx->ListOfPDOs.Flink;
            entry != &fdx->ListOfPDOs;
            entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if (pdx->subtype != hba
                && pdx->Nodename && strcmp(pdx->Nodename, nodename) == 0) {
            return pdx;
        }
    }
    return NULL;
}

static XENBUS_DEVICE_ORIGIN
xenbus_determine_creation_type(PFDO_DEVICE_EXTENSION fdx,
    XENBUS_DEVICE_TYPE xtype)
{
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;

    if (xtype == vnif) {
        return created;
    }
    if (xtype == vbd) {
        if (pvctrl_flags & XENBUS_PVCTRL_USE_JUST_ONE_CONTROLLER) {
            for (entry = fdx->ListOfPDOs.Flink;
                    entry != &fdx->ListOfPDOs;
                    entry = entry->Flink) {
                pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
                if (pdx->Type == xtype && pdx->origin == created) {
                    /*
                     * We found a device already created so we will
                     * allocate this one and any others that come along.
                     */
                    return alloced;
                }
            }
        }
        /* Either each disk gets its own controller or this is the first one. */
        return created;
    }
    if (xtype == vscsi) {
        return created;
    }
    if (xtype == vusb) {
        for (entry = fdx->ListOfPDOs.Flink;
                entry != &fdx->ListOfPDOs;
                entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            if (pdx->Type == xtype && pdx->origin == created) {
                /*
                 * We found a device already created so we will
                 * allocate this one and any others that come along.
                 */
                return alloced;
            }
        }
        /* We didn't find any vscsi devices so we will create this one. */
        return created;
    }
    return origin_unknown;
}

static NTSTATUS
xenbus_type_to_hwid(PPDO_DEVICE_EXTENSION pdx, XENBUS_DEVICE_TYPE xtype)
{
    size_t typelen;
    char *hardware_id;
    ANSI_STRING astr;
    NTSTATUS status;

    /* <type>/<id> --> XEN\TYPE_<type>, typelen+10 */
    typelen = strlen("XEN\\TYPE_xxxxx") + 1;
    hardware_id = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                typelen,
                                XENBUS_POOL_TAG);
    if (hardware_id == NULL) {
        return STATUS_NO_MEMORY;
    }

    switch (xtype) {
    case vnif:
        RtlStringCbCopyA(hardware_id, typelen, "XEN\\TYPE_vif");
        break;
    case vbd:
        RtlStringCbCopyA(hardware_id, typelen, "XEN\\TYPE_vbd");
        break;
    case vscsi:
        RtlStringCbCopyA(hardware_id, typelen, "XEN\\TYPE_vscsi");
        break;
    default:
        ExFreePool(hardware_id);
        return STATUS_INVALID_PARAMETER;
    }

    RPRINTK(DPRTL_ON, ("xenbus_type_to_hwid: type %d, hwid %s, len %d.\n",
                       xtype, hardware_id, typelen));
    RtlInitAnsiString(&astr, hardware_id);
    status = RtlAnsiStringToUnicodeString(&pdx->HardwareIDs, &astr, TRUE);
    ExFreePool(hardware_id);
    return status;
}

static NTSTATUS
xenbus_type_to_pci_hwid(PPDO_DEVICE_EXTENSION pdx, XENBUS_DEVICE_TYPE xtype)
{
    size_t typelen;
    char *hardware_id;
    ANSI_STRING astr;
    NTSTATUS status;

    typelen = strlen("PCI\\VEN_1AF4&DEV_100X&SUBSYS_000X1AF4&REV_00") + 1;
    hardware_id = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                typelen,
                                XENBUS_POOL_TAG);
    if (hardware_id == NULL) {
        return STATUS_NO_MEMORY;
    }
    switch (xtype) {
    case vnif:
        RtlStringCbCopyA(hardware_id, typelen,
            "PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00");
        break;
    case vbd:
        RtlStringCbCopyA(hardware_id, typelen,
            "PCI\\VEN_1AF4&DEV_1001&SUBSYS_00021AF4&REV_00");
        break;
    case vscsi:
        RtlStringCbCopyA(hardware_id, typelen,
            "PCI\\VEN_1AF4&DEV_1004&SUBSYS_00081AF4&REV_00");
        break;
    default:
        ExFreePool(hardware_id);
        return STATUS_INVALID_PARAMETER;
    }
    RPRINTK(DPRTL_ON, ("xenbus_type_to_hwid: type %d, hwid %s, len %d.\n",
                       xtype, hardware_id, typelen));
    RtlInitAnsiString(&astr, hardware_id);
    status = RtlAnsiStringToUnicodeString(&pdx->HardwareIDs, &astr, TRUE);
    ExFreePool(hardware_id);
    return STATUS_SUCCESS;
}

static NTSTATUS
xenbus_init_pdx(PDEVICE_OBJECT fdo, PDEVICE_OBJECT pdo,
                XENBUS_DEVICE_TYPE xtype, XENBUS_DEVICE_SUBTYPE subtype,
                XENBUS_DEVICE_ORIGIN origin, char *nodename,
                char *subnode, ULONG add_pci_during_install)
{
    PFDO_DEVICE_EXTENSION fdx;
    PPDO_DEVICE_EXTENSION pdx;
    ANSI_STRING astr;
    NTSTATUS status;

    fdx = (PFDO_DEVICE_EXTENSION)fdo->DeviceExtension;
    pdx = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;
    memset(pdx, 0, sizeof(PDO_DEVICE_EXTENSION));

    RPRINTK(DPRTL_PROBE, ("xenbus_init_pdx: pdo = %p, pdx = %p, obj = %p\n",
                          pdo, pdx, pdo->DriverObject));

    pdx->Nodename = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                  strlen(nodename) + 1,
                                  XENBUS_POOL_TAG);
    if (pdx->Nodename == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlStringCbCopyA(pdx->Nodename, strlen(nodename) + 1, nodename);

    if (subnode) {
        pdx->subnode = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                     strlen(subnode) + 1,
                                     XENBUS_POOL_TAG);
        if (pdx->subnode == NULL) {
            ExFreePool(pdx->Nodename);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlStringCbCopyA(pdx->subnode, strlen(subnode) + 1, subnode);
    }

    /* Get either a PCI or Xen hardware id. */
    if (add_pci_during_install) {
        RPRINTK(DPRTL_PROBE,
                ("xenbus_init_pdx: xenbus_nodename_to_pci_hwid\n"));
        status = xenbus_type_to_pci_hwid(pdx, xtype);
    } else {
        RPRINTK(DPRTL_PROBE, ("xenbus_init_pdx: xenbus_nodename_to_hwid\n"));
        status = xenbus_type_to_hwid(pdx, xtype);
    }
    if (!NT_SUCCESS(status)) {
        RPRINTK(DPRTL_PROBE,
                ("xenbus_init_pdx: failed xenbus_nodename_to_hwid\n"));
        ExFreePool(pdx->Nodename);
        return status;
    }

    pdo->Flags |= DO_POWER_PAGABLE;
    pdo->Flags &= ~DO_DEVICE_INITIALIZING;
    ExAcquireFastMutex(&fdx->Mutex);
    InsertTailList(&fdx->ListOfPDOs, &pdx->Link);
    fdx->NumPDOs++;
    ExReleaseFastMutex(&fdx->Mutex);
    pdx->IsFdo = FALSE;
    pdx->Self = pdo;
    pdx->ParentFdo = fdo;

    pdx->Type = xtype;
    pdx->subtype = subtype;
    pdx->origin = origin;
    pdx->Present = TRUE;
    pdx->ReportedMissing = FALSE;

    pdx->pnpstate = NotStarted;
    pdx->devpower = PowerDeviceD3;
    pdx->syspower = PowerSystemWorking;

    pdx->InterfaceRefCount = 0;
    pdx->PagingPathCount = 0;
    pdx->DumpPathCount = 0;
    pdx->HibernationPathCount = 0;
    pdx->frontend_dev = NULL;
    pdx->controller = NULL;

    RPRINTK(DPRTL_PROBE, ("xenbus_init_pdx: KeInitializeEvent\n"));
    KeInitializeEvent(&pdx->PathCountEvent, SynchronizationEvent, TRUE);
    return STATUS_SUCCESS;
}

NTSTATUS
XenbusDestroyPDO(PDEVICE_OBJECT pdo)
{
    PPDO_DEVICE_EXTENSION pdx;

    pdx = (PPDO_DEVICE_EXTENSION) pdo->DeviceExtension;

    if (pdx->HardwareIDs.Buffer) {
        RtlFreeUnicodeString(&pdx->HardwareIDs);
        pdx->HardwareIDs.Buffer = NULL;
    }

    if (pdx->BackendID) {
        ExFreePool(pdx->BackendID);
        pdx->BackendID = NULL;
    }

    if (pdx->Otherend) {
        ExFreePool(pdx->Otherend);
        pdx->Otherend = NULL;
    }

    if (pdx->Nodename) {
        RPRINTK(DPRTL_PROBE, ("XenbusDestroyPDO: %s\n", pdx->Nodename));
        ExFreePool(pdx->Nodename);
        pdx->Nodename = NULL;
    }

    if (pdx->subnode) {
        RPRINTK(DPRTL_PROBE, ("XenbusDestroyPDO: %s\n", pdx->subnode));
        ExFreePool(pdx->subnode);
        pdx->subnode = NULL;
    }

    if (pdx->instance_id) {
        RPRINTK(DPRTL_PROBE, ("XenbusDestroyPDO: %s\n", pdx->instance_id));
        ExFreePool(pdx->instance_id);
        pdx->instance_id = NULL;
    }

    if (pdx->origin == created) {
        RPRINTK(DPRTL_ON, ("XenbusDestroyPDO: IoDeleteDevice(pdo) ref cnt %d\n",
                           pdo->ReferenceCount));
        IoDeleteDevice(pdo);
        RPRINTK(DPRTL_PROBE, ("XenbusDestroyPDO: Deleted (pdo)\n"));
    }
    return STATUS_SUCCESS;
}
