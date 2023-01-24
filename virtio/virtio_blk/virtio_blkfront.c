/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2011-2023 SUSE LLC
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

#include "virtio_blk.h"

void
virtio_sp_get_device_config(virtio_sp_dev_ext_t *dev_ext)
{
    dev_ext->features = VIRTIO_DEVICE_GET_FEATURES(&dev_ext->vdev);

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev, 0,
        &dev_ext->info, sizeof(vbif_info_t));

    if (!IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_SIZE_MAX)) {
        dev_ext->info.size_max = PAGE_SIZE;
    }
    if (!IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_SEG_MAX)) {
        dev_ext->info.seg_max = 0;
    }
    if (!IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_GEOMETRY)) {
        dev_ext->info.geometry.cylinders = 0;
        dev_ext->info.geometry.heads = 0;
        dev_ext->info.geometry.sectors = 0;
    }
    if (!IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_BLK_SIZE)) {
        dev_ext->info.blk_size = SECTOR_SIZE;
    }
    if (!IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_TOPOLOGY)) {
        dev_ext->info.physical_block_exp = 0;
        dev_ext->info.alignment_offset = 0;
        dev_ext->info.min_io_size = 0;
        dev_ext->info.opt_io_size = 0;
    }
    if (!IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_MQ)) {
        dev_ext->info.num_queues = 1;
    }

#if (NTDDI_VERSION >= NTDDI_WIN8)
    if (IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_DISCARD)) {
        dev_ext->info.discard_sector_alignment =
        (max(dev_ext->info.discard_sector_alignment,
             MIN_DISCARD_SECTOR_ALIGNMENT)) << SECTOR_SHIFT;

        if (dev_ext->info.max_discard_sectors == 0) {
            dev_ext->info.max_discard_sectors = UINT_MAX;
        }

        if (dev_ext->info.max_discard_seg >= MAX_DISCARD_SEGMENTS) {
            dev_ext->info.max_discard_seg = MAX_DISCARD_SEGMENTS -1;
        }
    }
#endif

    if (dev_ext->info.size_max > 0 && dev_ext->info.seg_max > 0) {
        dev_ext->num_phys_breaks =
            (dev_ext->info.size_max * dev_ext->info.seg_max)
                / (ROUND_TO_PAGES(dev_ext->info.size_max));
        if (dev_ext->num_phys_breaks > MAX_PHYS_SEGMENTS) {
            dev_ext->num_phys_breaks = MAX_PHYS_SEGMENTS;
        }
    } else {
        dev_ext->num_phys_breaks = DEFAULT_MAX_PHYS_SEGS;
    }

    dev_ext->num_queues = dev_ext->info.num_queues;
}

void
virtio_sp_dump_device_config_info(virtio_sp_dev_ext_t *dev_ext,
                                  PPORT_CONFIGURATION_INFORMATION config_info)
{

    PRINTK(("%s: features and configuration:\n", VIRTIO_SP_DRIVER_NAME));
    PRINTK(("\thost features: 0x%llx\n", dev_ext->features));

    if (IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_BARRIER)) {
        PRINTK(("\tVIRTIO_BLK_F_BARRIER\n"));
    }

    if (IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_RO)) {
        PRINTK(("\tVIRTIO_BLK_F_RO\n"));
    }
    PRINTK(("\tVIRTIO_BLK_F_SIZE_MAX: %d\n",
        dev_ext->info.size_max));
    PRINTK(("\tVIRTIO_BLK_F_SEG_MAX: %d\n",
        dev_ext->info.seg_max));


    PRINTK(("\tCalculated phys breaks: %d\n",
        (dev_ext->info.size_max * dev_ext->info.seg_max) /
            ROUND_TO_PAGES(dev_ext->info.size_max)));

    PRINTK(("\tVIRTIO_BLK_F_BLK_SIZE: %d\n",
        dev_ext->info.blk_size));
    PRINTK(("\tVIRTIO_BLK_F_GEOMETRY: cy %d, heads %d, sectrs %d\n",
        dev_ext->info.geometry.cylinders, dev_ext->info.geometry.heads,
        dev_ext->info.geometry.sectors));
    PRINTK(("\tcapacity: %08I64X\n", dev_ext->info.capacity));
    PRINTK(("\tphysical_block_exp: %d\n",
        dev_ext->info.physical_block_exp));
    PRINTK(("\talignment_offset: %d\n",
        dev_ext->info.alignment_offset));
    PRINTK(("\tmin_io_size: %d\n",
        dev_ext->info.min_io_size));
    PRINTK(("\topt_io_size: %d\n",
        dev_ext->info.opt_io_size));
    PRINTK(("\twce %d: %d\n",
        IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_CONFIG_WCE),
        dev_ext->info.wce));
    PRINTK(("\tunused: %d\n",
        dev_ext->info.unused));
    PRINTK(("\tnum_queues %d: %d %d\n",
        IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_MQ),
        dev_ext->info.num_queues,
            dev_ext->num_queues));

#if (NTDDI_VERSION >= NTDDI_WIN8)
    PRINTK(("\tmax_discard_sectors %d: %d\n",
        IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_DISCARD),
        dev_ext->info.max_discard_sectors));
    PRINTK(("\t  max-discard_seg: %d\n",
        dev_ext->info.max_discard_seg));
    PRINTK(("\t  discard_sector_alignment: %d\n",
        dev_ext->info.discard_sector_alignment));

    PRINTK(("\tmax_write_zeroes_sectors %d: %d\n",
        IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_WRITE_ZEROES),
        dev_ext->info.max_write_zeroes_sectors));
    PRINTK(("\t  max_write_zeroes_sectors %d\n",
        dev_ext->info.max_write_zeroes_seg));
    PRINTK(("\t  write_zeros_may_unmap: %d\n",
        dev_ext->info.write_zeroes_may_unmap));
#endif
}

void virtio_sp_enable_features(virtio_sp_dev_ext_t *dev_ext)
{
    uint64_t guest_features;

    guest_features = 0;
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_F_VERSION_1)) {
        virtio_feature_enable(guest_features, VIRTIO_F_VERSION_1);

        if (dev_ext->b_use_packed_rings == TRUE
                && virtio_is_feature_enabled(dev_ext->features,
                                             VIRTIO_F_RING_PACKED)) {
            virtio_feature_enable(guest_features, VIRTIO_F_RING_PACKED);
            RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_F_RING_PACKED\n",
                                 __func__));
        }
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_RING_F_EVENT_IDX)) {
        virtio_feature_enable(guest_features, VIRTIO_RING_F_EVENT_IDX);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_RING_F_EVENT_IDX\n",
                             __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features,
                                  VIRTIO_RING_F_INDIRECT_DESC)) {
        virtio_feature_enable(guest_features, VIRTIO_RING_F_INDIRECT_DESC);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_RING_F_INDIRECT_DESC\n",
                             __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_FLUSH)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_FLUSH);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_FLUSH\n", __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_BARRIER)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_BARRIER);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_BARRIER\n", __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_RO)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_RO);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_RO\n", __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_SIZE_MAX)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_SIZE_MAX);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_SIZE_MAX\n", __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_SEG_MAX)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_SEG_MAX);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_SEG_MAX\n", __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_BLK_SIZE)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_BLK_SIZE);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_BLK_SIZE\n", __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_GEOMETRY)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_GEOMETRY);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_GEOMETRY\n", __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_MQ)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_MQ);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_MQ\n", __func__));
    }
#if (NTDDI_VERSION >= NTDDI_WIN8)
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_BLK_F_DISCARD)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_DISCARD);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_DISCARD\n", __func__));
    }
    if (virtio_is_feature_enabled(dev_ext->features,
                                  VIRTIO_BLK_F_WRITE_ZEROES)) {
        virtio_feature_enable(guest_features, VIRTIO_BLK_F_WRITE_ZEROES);
        RPRINTK(DPRTL_INIT, ("%s: enable VIRTIO_BLK_F_WRITE_ZEROES\n",
                             __func__));
    }
#endif
    PRINTK(("%s: setting guest features 0x%llx\n",
            VIRTIO_SP_DRIVER_NAME, guest_features));
    virtio_device_set_guest_feature_list(&dev_ext->vdev, guest_features);
}

void
virtio_sp_initialize(virtio_sp_dev_ext_t *dev_ext)
{
    uint32_t qdepth;

    qdepth = dev_ext->indirect ? dev_ext->vq[0]->num :
                dev_ext->vq[0]->num / VIRTIO_SP_MAX_SGL_ELEMENTS;
    if (dev_ext->queue_depth > qdepth) {
        dev_ext->queue_depth = qdepth;
        PRINTK(("\tusing default queue depth: %d\n", dev_ext->queue_depth));
    }
#ifdef IS_STORPORT
    sp_init_perfdata(dev_ext);
#endif
}

void
virtio_blk_inquery_data(virtio_sp_dev_ext_t *dev_ext, PSCSI_REQUEST_BLOCK srb)
{
    PINQUIRYDATA inquiryData;
    unsigned int i;

    RPRINTK(DPRTL_CONFIG,
        ("%s %x: SCSIOP_INQUIRY l = %x, isz = %x, srb = %x\n",
         VIRTIO_SP_DRIVER_NAME,
         srb->TargetId,
         srb->DataTransferLength, sizeof(INQUIRYDATA), srb));
    RPRINTK(DPRTL_CONFIG,
            ("    0 %x, 1 %x, 2 %x, 3 %x, 4 %x\n",
             srb->Cdb[0], srb->Cdb[1], srb->Cdb[2],
             srb->Cdb[3], srb->Cdb[4]));

    srb->SrbStatus = SRB_STATUS_SUCCESS;
    if (srb->Cdb[1] == 0) {
        inquiryData = srb->DataBuffer;
        memset(inquiryData, 0, srb->DataTransferLength);

        inquiryData->DeviceType = DIRECT_ACCESS_DEVICE;
        inquiryData->DeviceTypeQualifier = DEVICE_CONNECTED;
        inquiryData->RemovableMedia = 0;
        if (dev_ext->queue_depth) {
            inquiryData->CommandQueue = 1; /* tagged queueing */
        }
        inquiryData->Versions = 4;
        inquiryData->ResponseDataFormat = 2;
        inquiryData->HiSupport = 1;
        inquiryData->Wide32Bit = 1;


        for (i = 0; i < 8; i++) {
            inquiryData->VendorId[i] = ' ';
        }

        inquiryData->VendorId[0] = 'S';
        inquiryData->VendorId[1] = 'U';
        inquiryData->VendorId[2] = 'S';
        inquiryData->VendorId[3] = 'E';

        for (i = 0; i < 16; i++) {
            inquiryData->ProductId[i] = ' ';
        }

        inquiryData->ProductId[0] = 'V';
        inquiryData->ProductId[1] = 'i';
        inquiryData->ProductId[2] = 'r';
        inquiryData->ProductId[3] = 't';
        inquiryData->ProductId[4] = 'I';
        inquiryData->ProductId[5] = 'o';
        inquiryData->ProductId[6] = ' ';
        inquiryData->ProductId[7] = 'B';
        inquiryData->ProductId[8] = 'l';
        inquiryData->ProductId[9] = 'o';
        inquiryData->ProductId[10] = 'c';
        inquiryData->ProductId[11] = 'k';

        inquiryData->ProductRevisionLevel[0] = '0';
        inquiryData->ProductRevisionLevel[1] = '.';
        inquiryData->ProductRevisionLevel[2] = '0';
        inquiryData->ProductRevisionLevel[3] = '1';
    } else if (srb->Cdb[1] & 1) {
        /* The EVPD bit is set.  Check which page to return. */
        switch (srb->Cdb[2]) {
        case VPD_SUPPORTED_PAGES: {
            PVPD_SUPPORTED_PAGES_PAGE spage;

            spage = (PVPD_SUPPORTED_PAGES_PAGE)srb->DataBuffer;

            RPRINTK(DPRTL_CONFIG,
                    ("%x: SCSIOP_INQUIRY page 0.\n",
                     srb->TargetId));
            spage->DeviceType = DIRECT_ACCESS_DEVICE;
            spage->DeviceTypeQualifier = DEVICE_CONNECTED;
            spage->PageCode = VPD_SUPPORTED_PAGES;
            /* spage->Reserved; */
            spage->SupportedPageList[0] = VPD_SUPPORTED_PAGES;
            spage->SupportedPageList[1] = VPD_SERIAL_NUMBER;
            spage->SupportedPageList[2] = VPD_DEVICE_IDENTIFIERS;
#if (NTDDI_VERSION < NTDDI_WIN8)
            spage->PageLength = 3;
#else
            spage->PageLength = 4;
            spage->SupportedPageList[3] = VPD_BLOCK_LIMITS;
            if (IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_DISCARD)) {
                spage->SupportedPageList[4] = VPD_BLOCK_DEVICE_CHARACTERISTICS;
                spage->SupportedPageList[5] = VPD_LOGICAL_BLOCK_PROVISIONING;
                spage->PageLength = 6;
            }
#endif
            break;
        }
        case VPD_DEVICE_IDENTIFIERS: {
            PVPD_IDENTIFICATION_PAGE ipage;

            ipage = (PVPD_IDENTIFICATION_PAGE)srb->DataBuffer;

            RPRINTK(DPRTL_CONFIG,
                    ("%x: SCSIOP_INQUIRY page 83 %s, %d, %d.\n",
                     srb->TargetId,
                     VBIF_DESIGNATOR_STR,
                     strlen(VBIF_DESIGNATOR_STR),
                     sizeof(VPD_IDENTIFICATION_PAGE)));

            ipage->DeviceType = DIRECT_ACCESS_DEVICE;
            ipage->DeviceTypeQualifier = DEVICE_CONNECTED;
            ipage->PageCode = VPD_DEVICE_IDENTIFIERS;
            /* ipage->Reserved; */
            ipage->PageLength =
                sizeof(VPD_IDENTIFICATION_PAGE) +
                (uint8_t)strlen(VBIF_DESIGNATOR_STR);
            ipage->Descriptors[0] = VpdCodeSetAscii;
            ipage->Descriptors[1] = VpdIdentifierTypeSCSINameString;
            /* ipage->Descriptors[2] = reserved; */
            ipage->Descriptors[3] =
                (uint8_t)strlen(VBIF_DESIGNATOR_STR);

            memcpy(&ipage->Descriptors[4],
                VBIF_DESIGNATOR_STR,
                strlen(VBIF_DESIGNATOR_STR));
            break;
        }
        case VPD_SERIAL_NUMBER: {
            if (dev_ext->sn[0] == '\0') {
                if (virtio_blk_do_sn(dev_ext, srb) == TRUE) {
                    srb->SrbStatus = SRB_STATUS_PENDING;
                } else {
                    srb->SrbStatus = SRB_STATUS_ERROR;
                }
            } else {
                virtio_blk_fill_sn(dev_ext, srb);
            }
            break;
        }
#if (NTDDI_VERSION >= NTDDI_WIN8)
        case VPD_BLOCK_LIMITS: {
            PVPD_BLOCK_LIMITS_PAGE lpage;
            ULONG max_io_size;
            USHORT page_len;

            RPRINTK(DPRTL_CONFIG,
                    ("%x: SCSIOP_INQUIRY VPD_BLOCK_LIMITS B0.\n",
                     srb->TargetId));
            max_io_size = dev_ext->max_xfer_len / dev_ext->info.blk_size;
            page_len = 0x10;
            lpage = (PVPD_BLOCK_LIMITS_PAGE)srb->DataBuffer;
            lpage->DeviceType = DIRECT_ACCESS_DEVICE;
            lpage->DeviceTypeQualifier = DEVICE_CONNECTED;
            lpage->PageCode = VPD_BLOCK_LIMITS;
            REVERSE_BYTES_SHORT(&lpage->OptimalTransferLengthGranularity,
                                &dev_ext->info.min_io_size);
            REVERSE_BYTES(&lpage->MaximumTransferLength,
                          &max_io_size);
            REVERSE_BYTES(&lpage->OptimalTransferLength,
                          &dev_ext->info.opt_io_size);
            if (IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_DISCARD) &&
                    (srb->DataTransferLength >= 0x14)) {
                ULONG max_discard_sectors = dev_ext->info.max_discard_sectors;
                ULONG discard_sector_alignment = 0;
                ULONG opt_unmap_granularity =
                    dev_ext->info.discard_sector_alignment
                        / dev_ext->info.blk_size;

                page_len = 0x3c;
                REVERSE_BYTES(&lpage->MaximumUnmapLBACount,
                              &max_discard_sectors);
                REVERSE_BYTES(&lpage->MaximumUnmapBlockDescriptorCount,
                              &dev_ext->info.max_discard_seg);
                REVERSE_BYTES(&lpage->OptimalUnmapGranularity,
                              &opt_unmap_granularity);
                REVERSE_BYTES(&lpage->UnmapGranularityAlignment,
                              &discard_sector_alignment);
                lpage->UGAValid = 1;
            }
            REVERSE_BYTES_SHORT(&lpage->PageLength, &page_len);
            srb->DataTransferLength =
                FIELD_OFFSET(VPD_BLOCK_LIMITS_PAGE, Reserved0) + page_len;
            break;
        }
        case VPD_BLOCK_DEVICE_CHARACTERISTICS: {
            PVPD_BLOCK_DEVICE_CHARACTERISTICS_PAGE cpage;

            RPRINTK(DPRTL_CONFIG,
                   ("%x: SCSIOP_INQUIRY VPD_BLOCK_DEVICE_CHARACTERISTICS B1.\n",
                    srb->TargetId));
            if (srb->DataTransferLength >= 0x8) {
                cpage = (PVPD_BLOCK_DEVICE_CHARACTERISTICS_PAGE)srb->DataBuffer;
                cpage->DeviceType = DIRECT_ACCESS_DEVICE;
                cpage->DeviceTypeQualifier = DEVICE_CONNECTED;
                cpage->PageCode = VPD_BLOCK_DEVICE_CHARACTERISTICS;
                cpage->PageLength = 0x3C;
                cpage->MediumRotationRateMsb = 0;
                cpage->MediumRotationRateLsb = 0;
                cpage->NominalFormFactor = 0;
            } else {
                PRINTK(("%x: VPD_BLOCK_DEVICE_CHARACTERISTICS buf too small.\n",
                         srb->TargetId));
                srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            }
            break;
        }
        case VPD_LOGICAL_BLOCK_PROVISIONING: {
            PVPD_LOGICAL_BLOCK_PROVISIONING_PAGE ppage;
            USHORT pageLen = 0x04;

            RPRINTK(DPRTL_CONFIG,
                    ("%x: SCSIOP_INQUIRY VPD_LOGICAL_BLOCK_PROVISIONING B2.\n",
                     srb->TargetId));
            if (srb->DataTransferLength >= 0x8) {
                ppage = (PVPD_LOGICAL_BLOCK_PROVISIONING_PAGE)srb->DataBuffer;
                ppage->DeviceType = DIRECT_ACCESS_DEVICE;
                ppage->DeviceTypeQualifier = DEVICE_CONNECTED;
                ppage->PageCode = VPD_LOGICAL_BLOCK_PROVISIONING;
                REVERSE_BYTES_SHORT(&ppage->PageLength, &pageLen);

                ppage->DP = 0;
                ppage->LBPRZ = 0;
                ppage->LBPWS10 = 0;
                ppage->LBPWS = 0;
                if (IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_DISCARD)) {
                    ppage->LBPU = 1;
                    ppage->ProvisioningType = PROVISIONING_TYPE_THIN;
                } else {
                    ppage->LBPU = 0;
                    ppage->ProvisioningType = PROVISIONING_TYPE_RESOURCE;
                }
            } else {
                PRINTK(("%x: VPD_LOGICAL_BLOCK_PROVISIONING buf too small.\n",
                         srb->TargetId));
                srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            }
            break;
        }
#endif
        default:
            srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;
        }
    } else {
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    }

    if (dev_ext->queue_depth) {
        SP_SET_QUEUE_DEPTH(dev_ext, srb);
    }
}

UCHAR
virtio_blk_mode_sense(virtio_sp_dev_ext_t *dev_ext, PSCSI_REQUEST_BLOCK srb)
{
    PCDB cdb;
    PMODE_PARAMETER_HEADER header;
    PMODE_CACHING_PAGE cache_page;
    PMODE_PARAMETER_BLOCK param_block;
    ULONG len;

    cdb = (PCDB)&srb->Cdb[0];
    len = srb->DataTransferLength;
    if ((cdb->MODE_SENSE.PageCode == MODE_PAGE_CACHING)
            || (cdb->MODE_SENSE.PageCode == MODE_SENSE_RETURN_ALL)
            || (cdb->MODE_SENSE.PageCode == MODE_PAGE_VENDOR_SPECIFIC)) {
        if (sizeof(MODE_PARAMETER_HEADER) > len) {
            return SRB_STATUS_ERROR;
        }


        header = srb->DataBuffer;
        memset(header, 0, sizeof(MODE_PARAMETER_HEADER));
        header->DeviceSpecificParameter = MODE_DSP_FUA_SUPPORTED;

        if (IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_RO)) {
            header->DeviceSpecificParameter |= MODE_DSP_WRITE_PROTECT;
        }

        len -= sizeof(MODE_PARAMETER_HEADER);

        if (cdb->MODE_SENSE.PageCode == MODE_PAGE_VENDOR_SPECIFIC) {
            if (len >= sizeof(MODE_PARAMETER_BLOCK)) {
                header->BlockDescriptorLength = sizeof(MODE_PARAMETER_BLOCK);
                param_block = (PMODE_PARAMETER_BLOCK)header;
                param_block = (PMODE_PARAMETER_BLOCK)(
                    (unsigned char *)(param_block)
                        + (ULONG)sizeof(MODE_PARAMETER_HEADER));
                memset(param_block, 0, sizeof(MODE_PARAMETER_HEADER));
                srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER) +
                    sizeof(MODE_PARAMETER_BLOCK);
            } else {
                srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER);
            }
        } else {
            if (len >= sizeof(MODE_CACHING_PAGE)) {
                header->ModeDataLength = sizeof(MODE_CACHING_PAGE) + 3;
                cache_page = (PMODE_CACHING_PAGE)header;
                cache_page = (PMODE_CACHING_PAGE)((unsigned char *)(cache_page)
                    + (ULONG)sizeof(MODE_PARAMETER_HEADER));
                memset(cache_page, 0, sizeof(MODE_CACHING_PAGE));
                cache_page->PageCode = MODE_PAGE_CACHING;
                cache_page->PageLength = 10;
                cache_page->WriteCacheEnable =
                    IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_FLUSH) ? 1 : 0;
                srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER) +
                    sizeof(MODE_CACHING_PAGE);

            } else {
                srb->DataTransferLength = sizeof(MODE_PARAMETER_HEADER);
            }
        }
        return SRB_STATUS_SUCCESS;
    }
    return SRB_STATUS_INVALID_REQUEST;
}

uint64_t
virtio_blk_get_lba(virtio_sp_dev_ext_t *dev_ext, PSCSI_REQUEST_BLOCK srb)
{
    PCDB cdb;
    EIGHT_BYTE lba;

    cdb = (PCDB)srb->Cdb;
    lba.AsULongLong = 0;

    switch (cdb->CDB6GENERIC.OperationCode) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
    case SCSIOP_WRITE_VERIFY:
        lba.Byte0 = cdb->CDB10.LogicalBlockByte3;
        lba.Byte1 = cdb->CDB10.LogicalBlockByte2;
        lba.Byte2 = cdb->CDB10.LogicalBlockByte1;
        lba.Byte3 = cdb->CDB10.LogicalBlockByte0;
        break;
    case SCSIOP_READ6:
    case SCSIOP_WRITE6:
        lba.Byte0 = cdb->CDB6READWRITE.LogicalBlockMsb1;
        lba.Byte1 = cdb->CDB6READWRITE.LogicalBlockMsb0;
        lba.Byte2 = cdb->CDB6READWRITE.LogicalBlockLsb;
        break;
    case SCSIOP_READ12:
    case SCSIOP_WRITE12:
    case SCSIOP_WRITE_VERIFY12:
        REVERSE_BYTES(&lba, cdb->CDB12.LogicalBlock);
        break;
    case SCSIOP_READ16:
    case SCSIOP_WRITE16:
    case SCSIOP_WRITE_VERIFY16:
        REVERSE_BYTES_QUAD(&lba, cdb->CDB16.LogicalBlock);
        break;
    default:
        ASSERT(FALSE);
        return (uint64_t)-1;
    }

    return lba.AsULongLong * (dev_ext->info.blk_size / SECTOR_SIZE);
}

BOOLEAN
virtio_blk_do_flush(virtio_sp_dev_ext_t *dev_ext, SCSI_REQUEST_BLOCK *srb)
{
#ifdef IS_STORPORT
    STARTIO_PERFORMANCE_PARAMETERS param;
#endif
    PHYSICAL_ADDRESS pa;
    vbif_srb_ext_t *srb_ext;
    KLOCK_QUEUE_HANDLE lh;
    ULONG len;
    ULONG i;
    ULONG qidx;
    ULONG wait   = 100000;
    ULONG status = SRB_STATUS_ERROR;
    int num_free;

    srb_ext = (vbif_srb_ext_t *)srb->SrbExtension;

    DPRINTK(DPRTL_TRC, ("%s: %s.\n", VIRTIO_SP_DRIVER_NAME, __func__));

#ifdef IS_STORPORT
    if (dev_ext->num_queues > 1) {
        param.Size = sizeof(STARTIO_PERFORMANCE_PARAMETERS);
        status = StorPortGetStartIoPerfParams(dev_ext, srb, &param);
        if (status == STOR_STATUS_SUCCESS && param.MessageNumber != 0) {
            qidx = param.MessageNumber - 1;
        } else {
            qidx = 0;
        }
    } else {
        qidx = 0;
    }
#else
    qidx = 0;
#endif

    srb_ext->vbr.out_hdr.sector = 0;
    srb_ext->vbr.out_hdr.ioprio = 0;
    srb_ext->vbr.req            = srb;
    srb_ext->vbr.out_hdr.type   = VIRTIO_BLK_T_FLUSH;
    srb_ext->out                = 1;
    srb_ext->in                 = 1;

    pa = SP_GET_PHYSICAL_ADDRESS(
        dev_ext, NULL, &srb_ext->vbr.out_hdr, &len);
    srb_ext->sg[0].phys_addr = pa.QuadPart;
    srb_ext->sg[0].len   = sizeof(srb_ext->vbr.out_hdr);

    pa = SP_GET_PHYSICAL_ADDRESS(
        dev_ext, NULL, &srb_ext->vbr.status, &len);
    srb_ext->sg[1].phys_addr = pa.QuadPart;
    srb_ext->sg[1].len   = sizeof(srb_ext->vbr.status);

    KeAcquireInStackQueuedSpinLockAtDpcLevel(&dev_ext->requestq_lock[qidx], &lh);

    DPRINTK(DPRTL_PWR, ("%s: srb %p qidx %d\n", __func__, srb, qidx));

    dev_ext->op_mode |= OP_MODE_FLUSH;
    if (dev_ext->indirect) {
        pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, srb_ext->vr_desc, &len);
        num_free = vq_add_buf_indirect(dev_ext->vq[qidx],
            &srb_ext->sg[0],
            srb_ext->out,
            srb_ext->in,
            &srb_ext->vbr,
            srb_ext->vr_desc,
            pa.QuadPart);
    } else {
        num_free = vq_add_buf(dev_ext->vq[qidx],
            &srb_ext->sg[0],
            srb_ext->out,
            srb_ext->in,
            &srb_ext->vbr);
    }
    if (num_free >= 0) {
        vq_kick(dev_ext->vq[qidx]);

        KeReleaseInStackQueuedSpinLockFromDpcLevel(&lh);

#ifndef IS_STORPORT
        for (i = 0; i < wait; i++) {
            if (!(dev_ext->op_mode & OP_MODE_FLUSH)) {
                status = srb->SrbStatus;
                break;
            }
            SP_STALL_EXECUTION(1000);
            virtio_sp_complete_cmd(dev_ext, 1, 0, FALSE);
        }
        if (status != SRB_STATUS_SUCCESS) {
            PRINTK(("%s %s: [%d] srb %x srbst 0x%x st 0x%x op_mode %x\n",
                     VIRTIO_SP_DRIVER_NAME, __func__, i,
                    srb, srb->SrbStatus, status, dev_ext->op_mode));
            PRINTK(("  type %d fua %d func %x cdb %x\n",
                    srb_ext->vbr.out_hdr.type,
                    srb_ext->force_unit_access,
                    srb->Function,
                    srb->Cdb[0]));
            srb->SrbStatus = SRB_STATUS_ERROR;
            SP_LOG_ERROR(dev_ext, NULL, 0, 0, 0, SP_INTERNAL_ADAPTER_ERROR,
                __LINE__);
        }
#endif
        DPRINTK(DPRTL_TRC, ("%s: %s out.\n", VIRTIO_SP_DRIVER_NAME, __func__));
        return TRUE;
    }

    PRINTK(("Failed to add FLUSH srb: %p.\n", srb));
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lh);
    return FALSE;
}

BOOLEAN
virtio_blk_do_sn(virtio_sp_dev_ext_t *dev_ext, SCSI_REQUEST_BLOCK *srb)
{
#ifdef IS_STORPORT
    STARTIO_PERFORMANCE_PARAMETERS param;
#endif
    vbif_srb_ext_t *srb_ext;
    PHYSICAL_ADDRESS pa;
    KLOCK_QUEUE_HANDLE lh;
    ULONG status;
    ULONG qidx;
    ULONG len = 0UL;
    int num_free;

    srb_ext = (vbif_srb_ext_t *)srb->SrbExtension;

#ifdef IS_STORPORT
    if (dev_ext->num_queues > 1) {
        param.Size = sizeof(STARTIO_PERFORMANCE_PARAMETERS);
        status = StorPortGetStartIoPerfParams(dev_ext, srb, &param);
        if (status == STOR_STATUS_SUCCESS && param.MessageNumber != 0) {
            qidx = param.MessageNumber - 1;
        } else {
            qidx = 0;
        }
    } else {
        qidx = 0;
    }
#else
    qidx = 0;
#endif

    srb_ext->vbr.out_hdr.sector = 0;
    srb_ext->vbr.out_hdr.ioprio = 0;
    srb_ext->vbr.req            = srb;
    srb_ext->vbr.out_hdr.type   = VIRTIO_BLK_T_GET_ID | VIRTIO_BLK_T_IN;
    srb_ext->out                = 1;
    srb_ext->in                 = 2;

    pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, &srb_ext->vbr.out_hdr, &len);
    srb_ext->sg[0].phys_addr = pa.QuadPart;
    srb_ext->sg[0].len   = sizeof(srb_ext->vbr.out_hdr);

    pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, &dev_ext->sn[0], &len);
    srb_ext->sg[1].phys_addr = pa.QuadPart;
    srb_ext->sg[1].len = sizeof(dev_ext->sn);

    pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, &srb_ext->vbr.status, &len);
    srb_ext->sg[2].phys_addr = pa.QuadPart;
    srb_ext->sg[2].len = sizeof(srb_ext->vbr.status);

    KeAcquireInStackQueuedSpinLockAtDpcLevel(&dev_ext->requestq_lock[qidx], &lh);
    if (dev_ext->indirect) {
        pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, srb_ext->vr_desc, &len);
        num_free = vq_add_buf_indirect(dev_ext->vq[qidx],
            &srb_ext->sg[0],
            srb_ext->out,
            srb_ext->in,
            &srb_ext->vbr,
            srb_ext->vr_desc,
            pa.QuadPart);
    } else {
        num_free = vq_add_buf(dev_ext->vq[qidx],
            &srb_ext->sg[0],
            srb_ext->out,
            srb_ext->in,
            &srb_ext->vbr);
    }
    if (num_free >= 0) {
        vq_kick(dev_ext->vq[qidx]);
        KeReleaseInStackQueuedSpinLockFromDpcLevel(&lh);
        DPRINTK(DPRTL_TRC, ("%s: %s out.\n", VIRTIO_SP_DRIVER_NAME, __func__));
        return TRUE;
    }
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lh);

    SP_BUSY(dev_ext, max(dev_ext->queue_depth, 2));
    DPRINTK(DPRTL_UNEXPD, ("%s %s: busy out FALSE\n",
                           VIRTIO_SP_DRIVER_NAME, __func__));
    return FALSE;
}

void
virtio_blk_fill_sn(virtio_sp_dev_ext_t *dev_ext, SCSI_REQUEST_BLOCK *srb)
{
    PVPD_SERIAL_NUMBER_PAGE snpage;
    size_t len;
    ULONG srb_buf_len;

    RPRINTK(DPRTL_CONFIG, ("%s %x\n", __func__, srb->TargetId));

    len = strnlen(dev_ext->sn, sizeof(dev_ext->sn));
    srb_buf_len = srb->DataTransferLength;
    if(srb_buf_len < sizeof(VPD_SERIAL_NUMBER_PAGE) + len) {
        PRINTK(("%s: data len too small %d, %d\n",
                __func__, srb_buf_len, sizeof(VPD_SERIAL_NUMBER_PAGE) + len));
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        return;
    }

    if (len == 0) {
        PRINTK(("%s: No serial number provided.\n", VIRTIO_SP_DRIVER_NAME));
        dev_ext->sn[0] = '0';
        dev_ext->sn[1] = '\0';
        len = 1;
    }

    snpage = (PVPD_SERIAL_NUMBER_PAGE)srb->DataBuffer;
    RtlZeroMemory(snpage, srb_buf_len);
    snpage->DeviceType = DIRECT_ACCESS_DEVICE;
    snpage->DeviceTypeQualifier = DEVICE_CONNECTED;
    snpage->PageCode = VPD_SERIAL_NUMBER;
    /* snpage->Reserved; */
    snpage->PageLength = (UCHAR)len;
    memcpy(&snpage->SerialNumber, &dev_ext->sn, len);
    srb->DataTransferLength = sizeof(VPD_SERIAL_NUMBER_PAGE) + len;
    srb->SrbStatus = SRB_STATUS_SUCCESS;
    srb->ScsiStatus = SCSISTAT_GOOD;
    RPRINTK(DPRTL_CONFIG, ("%s: Setting serial number to %s.\n",
                           VIRTIO_SP_DRIVER_NAME, snpage->SerialNumber));
}

#if (NTDDI_VERSION >= NTDDI_WIN8)
BOOLEAN
virtio_blk_do_unmap(virtio_sp_dev_ext_t *dev_ext, SCSI_REQUEST_BLOCK *srb)
{
    STARTIO_PERFORMANCE_PARAMETERS param;
    vbif_srb_ext_t *srb_ext;
    PUNMAP_LIST_HEADER unmap_list;
    PVOID srb_buf;
    PUNMAP_BLOCK_DESCRIPTOR blk_descrs;
    ULONGLONG blk_start_lba;
    PHYSICAL_ADDRESS pa;
    KLOCK_QUEUE_HANDLE lh;
    ULONG blk_descr_lba_cnt;
    ULONG srb_buf_len;
    ULONG i;
    ULONG len = 0UL;
    ULONG qidx = 0;
    ULONG status;
    int num_free;
    USHORT blk_descr_cnt;
    USHORT blk_desc_data_len;

    srb_ext = (vbif_srb_ext_t *)srb->SrbExtension;
    srb_buf = srb->DataBuffer;
    srb_buf_len = srb->DataTransferLength;

    unmap_list = (PUNMAP_LIST_HEADER)srb_buf;

    if (unmap_list == NULL) {
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        return FALSE;
    }

    REVERSE_BYTES_SHORT(&blk_desc_data_len, unmap_list->BlockDescrDataLength);

    if (!(IS_BIT_SET(dev_ext->features, VIRTIO_BLK_F_DISCARD)) ||
         (srb_buf_len < (ULONG)(blk_desc_data_len + 8)) ) {
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        return FALSE;
    }

    blk_descr_cnt = blk_desc_data_len / sizeof(UNMAP_BLOCK_DESCRIPTOR);
    if (blk_descr_cnt > VIRTIO_BLK_MAX_DISCARD) {
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        return FALSE;
    }

    blk_descrs = (PUNMAP_BLOCK_DESCRIPTOR)((PCHAR)srb_buf + 8);
    for (i = 0; i < blk_descr_cnt; i++) {
        REVERSE_BYTES_QUAD(&blk_start_lba, blk_descrs[i].StartingLba);
        REVERSE_BYTES(&blk_descr_lba_cnt, blk_descrs[i].LbaCount);
        DPRINTK(DPRTL_ON,
            ("[%d] blk_descr_cnt %d blk_start_lba %llu blk_descr_lba_cnt %lu\n",
            i, blk_descr_cnt, blk_start_lba, blk_descr_lba_cnt));
        dev_ext->blk_discard[i].sector =
            blk_start_lba * (dev_ext->info.blk_size / SECTOR_SIZE);
        dev_ext->blk_discard[i].num_sectors =
            blk_descr_lba_cnt * (dev_ext->info.blk_size / SECTOR_SIZE);
        dev_ext->blk_discard[i].flags = 0;
    }

    srb_ext->vbr.out_hdr.sector = 0;
    srb_ext->vbr.out_hdr.ioprio = 0;
    srb_ext->vbr.req            = srb;
    srb_ext->vbr.out_hdr.type   = VIRTIO_BLK_T_DISCARD | VIRTIO_BLK_T_OUT;
    srb_ext->out                = 2;
    srb_ext->in                 = 1;

    pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, &srb_ext->vbr.out_hdr, &len);
    srb_ext->sg[0].phys_addr = pa.QuadPart;
    srb_ext->sg[0].len   = sizeof(srb_ext->vbr.out_hdr);

    pa = MmGetPhysicalAddress(&dev_ext->blk_discard[0]);
    srb_ext->sg[1].phys_addr = pa.QuadPart;
    srb_ext->sg[1].len =
        sizeof(virtio_blk_discard_write_zeroes_t) * blk_descr_cnt;

    pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, &srb_ext->vbr.status, &len);
    srb_ext->sg[2].phys_addr = pa.QuadPart;
    srb_ext->sg[2].len = sizeof(srb_ext->vbr.status);

    if (dev_ext->num_queues > 1) {
        param.Size = sizeof(STARTIO_PERFORMANCE_PARAMETERS);
        status = StorPortGetStartIoPerfParams(dev_ext, srb, &param);
        if (status == STOR_STATUS_SUCCESS && param.MessageNumber != 0) {
            qidx = param.MessageNumber - 1;
        } else {
            qidx = 0;
        }
    } else {
        qidx = 0;
    }

    KeAcquireInStackQueuedSpinLockAtDpcLevel(&dev_ext->requestq_lock[qidx], &lh);
    if (dev_ext->indirect) {
        pa = SP_GET_PHYSICAL_ADDRESS(dev_ext, NULL, srb_ext->vr_desc, &len);
        num_free = vq_add_buf_indirect(dev_ext->vq[qidx],
            &srb_ext->sg[0],
            srb_ext->out,
            srb_ext->in,
            &srb_ext->vbr,
            srb_ext->vr_desc,
            pa.QuadPart);
    } else {
        num_free = vq_add_buf(dev_ext->vq[qidx],
            &srb_ext->sg[0],
            srb_ext->out,
            srb_ext->in,
            &srb_ext->vbr);
    }
    if (num_free >= 0) {
        vq_kick(dev_ext->vq[qidx]);
        KeReleaseInStackQueuedSpinLockFromDpcLevel(&lh);
        DPRINTK(DPRTL_TRC, ("%s: %s out.\n", VIRTIO_SP_DRIVER_NAME, __func__));
        return TRUE;
    }
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lh);

    SP_BUSY(dev_ext, max(dev_ext->queue_depth, 2));
    DPRINTK(DPRTL_UNEXPD, ("%s %s: busy out FALSE\n",
                           VIRTIO_SP_DRIVER_NAME, __func__));
    return FALSE;
}
#endif
