/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2012-2026 SUSE LLC
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

#include "virtio_scsi.h"

void
virtio_sp_get_device_config(virtio_sp_dev_ext_t *dev_ext)
{
    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, seg_max),
        &dev_ext->scsi_config.seg_max,
        sizeof(dev_ext->scsi_config.seg_max));
    RPRINTK(DPRTL_INIT, ("\tseg_max: %d\n",
                         dev_ext->scsi_config.seg_max));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, num_queues),
        &dev_ext->scsi_config.num_queues,
        sizeof(dev_ext->scsi_config.num_queues));
    RPRINTK(DPRTL_INIT, ("\tnum_queues: %d\n",
                         dev_ext->scsi_config.num_queues));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, max_sectors),
        &dev_ext->scsi_config.max_sectors,
        sizeof(dev_ext->scsi_config.max_sectors));
    RPRINTK(DPRTL_INIT, ("\tmax_sectors: %d\n",
                         dev_ext->scsi_config.max_sectors));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, cmd_per_lun),
        &dev_ext->scsi_config.cmd_per_lun,
        sizeof(dev_ext->scsi_config.cmd_per_lun));
    RPRINTK(DPRTL_INIT, ("\tcmd_per_lun: %d\n",
                         dev_ext->scsi_config.cmd_per_lun));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, event_info_size),
        &dev_ext->scsi_config.event_info_size,
         sizeof(dev_ext->scsi_config.event_info_size));
    RPRINTK(DPRTL_INIT, ("\tevent_info_size: %d\n",
                         dev_ext->scsi_config.sense_size));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, sense_size),
        &dev_ext->scsi_config.sense_size,
        sizeof(dev_ext->scsi_config.sense_size));
    RPRINTK(DPRTL_INIT, ("\tsense_size: %d\n",
                         dev_ext->scsi_config.sense_size));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, cdb_size),
        &dev_ext->scsi_config.cdb_size,
        sizeof(dev_ext->scsi_config.cdb_size));
    RPRINTK(DPRTL_INIT, ("\tcdb_size: %d\n",
                         dev_ext->scsi_config.cdb_size));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, max_channel),
        &dev_ext->scsi_config.max_channel,
        sizeof(dev_ext->scsi_config.max_channel));
    RPRINTK(DPRTL_INIT, ("\tmax_channel: %d\n",
                         dev_ext->scsi_config.max_channel));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, max_target),
        &dev_ext->scsi_config.max_target,
        sizeof(dev_ext->scsi_config.max_target));
    RPRINTK(DPRTL_INIT, ("\tmax_target: %d\n",
                         dev_ext->scsi_config.max_target));

    VIRTIO_DEVICE_GET_CONFIG(&dev_ext->vdev,
        FIELD_OFFSET(virtio_scsi_config_t, max_lun),
        &dev_ext->scsi_config.max_lun,
        sizeof(dev_ext->scsi_config.max_lun));
    RPRINTK(DPRTL_INIT, ("\tmax_lun: %d\n",
                         dev_ext->scsi_config.max_lun));

    dev_ext->num_phys_breaks = MAX_PHYS_SEGMENTS;
    dev_ext->num_queues = dev_ext->scsi_config.num_queues;
}

void
virtio_sp_dump_device_config_info(virtio_sp_dev_ext_t *dev_ext)
{

    PRINTK(("%s: features and configuration:\n", VIRTIO_SP_DRIVER_NAME));
    PRINTK(("\thost features: 0x%llx\n", dev_ext->features));
    if (IS_BIT_SET(dev_ext->features, VIRTIO_RING_F_EVENT_IDX)) {
        PRINTK(("\tVIRTIO_RING_F_EVENT_IDX\n"));
    }
    if (IS_BIT_SET(dev_ext->features, VIRTIO_SCSI_F_CHANGE)) {
        PRINTK(("\tVIRTIO_SCSI_F_CHANGE\n"));
    }
    if (IS_BIT_SET(dev_ext->features, VIRTIO_SCSI_F_HOTPLUG)) {
        PRINTK(("\tVIRTIO_SCSI_F_HOTPLUG\n"));
    }
    if (IS_BIT_SET(dev_ext->features, VIRTIO_RING_F_INDIRECT_DESC)) {
        PRINTK(("\tVIRTIO_RING_F_INDIRECT_DESC\n"));
    }
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
        }
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_RING_F_EVENT_IDX)) {
        virtio_feature_enable(guest_features, VIRTIO_RING_F_EVENT_IDX);
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_SCSI_F_CHANGE)) {
        virtio_feature_enable(guest_features, VIRTIO_SCSI_F_CHANGE);
    }
    if (virtio_is_feature_enabled(dev_ext->features, VIRTIO_SCSI_F_HOTPLUG)) {
        virtio_feature_enable(guest_features, VIRTIO_SCSI_F_HOTPLUG);
    }
    if (virtio_is_feature_enabled(dev_ext->features,
                                  VIRTIO_RING_F_INDIRECT_DESC)) {
        virtio_feature_enable(guest_features, VIRTIO_RING_F_INDIRECT_DESC);
    }
    PRINTK(("%s: setting guest features 0x%llx\n",
            VIRTIO_SP_DRIVER_NAME, guest_features));
    virtio_device_set_guest_feature_list(&dev_ext->vdev, guest_features);
}

void
virtio_sp_initialize(virtio_sp_dev_ext_t *dev_ext)
{
    uint32_t i;
    uint32_t qdepth;

    if ((dev_ext->op_mode & OP_MODE_NORMAL)
            && virtio_is_feature_enabled(dev_ext->features,
                                         VIRTIO_SCSI_F_HOTPLUG)) {
        for (i = 0; i < VIRTIO_SCSI_T_EVENTS_IN_QUEUE; i++) {
            if (!virtio_scsi_prime_event_queue(dev_ext,
                                               &dev_ext->event_node[i])) {
                PRINTK(("%s: Can't add to event queue: event %d\n",
                        VIRTIO_SP_DRIVER_NAME, i));
           }
        }
    }

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

BOOLEAN
virtio_scsi_add_event(virtio_sp_dev_ext_t *dev_ext,
    virtio_scsi_event_node_t *event_node)
{
    int num_free;

    num_free = vq_add_buf(dev_ext->vq[VIRTIO_SCSI_QUEUE_EVENT],
                          &event_node->sg,
                          0,
                          1,
                          event_node);
    if (num_free >= 0) {
        vq_kick(dev_ext->vq[VIRTIO_SCSI_QUEUE_EVENT]);
        DPRINTK(DPRTL_TRC, ("%s %s: out TRUE\n",
                            VIRTIO_SP_DRIVER_NAME, __func__));
        return TRUE;
    }

    return FALSE;
}

BOOLEAN
virtio_scsi_prime_event_queue(virtio_sp_dev_ext_t *dev_ext,
    virtio_scsi_event_node_t *event_node)
{
    ULONG len;

    RtlZeroMemory(event_node, sizeof(virtio_scsi_event_node_t));
    event_node->sg.phys_addr = SP_GET_PHYSICAL_ADDRESS(
        dev_ext, NULL, &event_node->event, &len).QuadPart;
    event_node->sg.len = sizeof(virtio_scsi_event_t);
    return virtio_scsi_add_event(dev_ext, event_node);
}

void
virtio_scsi_transport_reset(virtio_sp_dev_ext_t *dev_ext,
                            virtio_scsi_event_t *evt)
{
    switch (evt->reason) {
    case VIRTIO_SCSI_EVT_RESET_RESCAN:
    case VIRTIO_SCSI_EVT_RESET_REMOVED:
        SP_NOTIFICATION(BusChangeDetected, dev_ext, 0);
        break;
    default:
        PRINTK(("%s: Unsupport virtio scsi event reason 0x%x\n",
                VIRTIO_SP_DRIVER_NAME, evt->reason));
        break;
    }
}

void
virtio_scsi_param_change(virtio_sp_dev_ext_t *dev_ext, virtio_scsi_event_t *evt)
{
    uint32_t sense_code = evt->reason & 0xff;
    uint32_t sense_code_qualifier = evt->reason >> 8;

    if (sense_code == SCSI_ADSENSE_PARAMETERS_CHANGED &&
       (sense_code_qualifier == SPC3_SCSI_SENSEQ_PARAMETERS_CHANGED ||
        sense_code_qualifier == SPC3_SCSI_SENSEQ_MODE_PARAMETERS_CHANGED ||
        sense_code_qualifier == SPC3_SCSI_SENSEQ_CAPACITY_DATA_HAS_CHANGED)) {
        SP_NOTIFICATION(BusChangeDetected, dev_ext, 0);
    }
}
