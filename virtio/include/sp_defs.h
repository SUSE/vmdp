/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2011-2015 Novell, Inc.
 * Copyright 2015-2020 SUSE LLC
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

#ifndef _SP_DEFS_H_
#define _SP_DEFS_H_

#ifdef IS_STORPORT
#define sp_sg_element_t STOR_SCATTER_GATHER_ELEMENT
#define sp_sgl_t STOR_SCATTER_GATHER_LIST
#else
typedef PHYSICAL_ADDRESS STOR_PHYSICAL_ADDRESS;
typedef struct _sp_sg_element {
    STOR_PHYSICAL_ADDRESS PhysicalAddress;
    ULONG Length;
    ULONG_PTR Reserved;
} sp_sg_element_t;

typedef struct _sp_sgl_t {
    ULONG NumberOfElements;
    ULONG_PTR Reserved;
    sp_sg_element_t List[VIRTIO_MAX_SG];
} sp_sgl_t;
#endif

#ifndef PCIX_TABLE_POINTER
typedef struct {
  union {
    struct {
      ULONG BaseIndexRegister :3;
      ULONG Reserved          :29;
    };
    ULONG TableOffset;
  };
} PCIX_TABLE_POINTER, *PPCIX_TABLE_POINTER;
#endif

#ifndef PCI_MSIX_CAPABILITY
typedef struct {
  PCI_CAPABILITIES_HEADER Header;
  struct {
    USHORT TableSize      :11;
    USHORT Reserved       :3;
    USHORT FunctionMask   :1;
    USHORT MSIXEnable     :1;
  } MessageControl;
  PCIX_TABLE_POINTER      MessageTable;
  PCIX_TABLE_POINTER      PBATable;
} PCI_MSIX_CAPABILITY, *PPCI_MSIX_CAPABILITY;
#endif

#ifdef IS_STORPORT
/***************************** STOR PORT *******************************/
#define SP_BUILDIO_BOOL FALSE
#define SP_PAUSE StorPortPause
#define SP_RESUME StorPortResume
#define SP_LOCK_HANDLE STOR_LOCK_HANDLE

#define SP_NOTIFICATION StorPortNotification
#define SP_GET_UNCACHED_EXTENSION StorPortGetUncachedExtension
#define SP_LOG_ERROR StorPortLogError
#define SP_STALL_EXECUTION StorPortStallExecution
#define SP_BUSY StorPortBusy
#define SP_NEXT_REQUEST(_next, _dev_ext)
#define SP_GET_PHYSICAL_ADDRESS StorPortGetPhysicalAddress
#define Sp_GET_DEVICE_BASE StorPortGetDeviceBase
#define SP_ISSUE_DPC StorPortIssueDpc
#define SP_SYNCHRONIZE_ACCESS StorPortSynchronizeAccess
#define SP_SHOULD_NOTIFY_NEXT(_dev_ext, _srb, _srb_ext, _num_free)
#define SP_SET_QUEUE_DEPTH(_dev, _srb)                                      \
    StorPortSetDeviceQueueDepth((_dev),                                     \
        (_srb)->PathId,                                                     \
        (_srb)->TargetId,                                                   \
        (_srb)->Lun,                                                        \
        (_dev)->queue_depth)

#define sp_build_sgl StorPortGetScatterGatherList

#define SP_ACQUIRE_SPINLOCK(_dext, _ltype, _mid, _oirql, _ctx, _lh)         \
{                                                                           \
    if ((_dext)->msi_vectors) {                                             \
        StorPortAcquireMSISpinLock ((_dext), (_mid), (_oirql));             \
    } else {                                                                \
        StorPortAcquireSpinLock ((_dext), (_ltype), (_ctx), (_lh));         \
    }                                                                       \
}

#define SP_RELEASE_SPINLOCK(_dev_ext,  _mid, _oirql, _lh)                   \
{                                                                           \
    if ((_dev_ext)->msi_vectors) {                                          \
        StorPortReleaseMSISpinLock ((_dev_ext), (_mid), (_oirql));          \
    } else {                                                                \
        StorPortReleaseSpinLock ((_dev_ext), (_lh));                        \
    }                                                                       \
}

#define SP_COMPLETE_SRB(_dev_ext, _srb)                                     \
    StorPortNotification(RequestComplete, (_dev_ext), (_srb))


#else
/***************************** SCSI MINIPORT *******************************/
#define SP_BUILDIO_BOOL TRUE
#define VBIF_LOCK_HANDLE XEN_LOCK_HANDLE
#define SP_GET_UNCACHED_EXTENSION ScsiPortGetUncachedExtension
#define SP_LOG_ERROR ScsiPortLogError
#define SP_PAUSE(_dev_ext, _pause_val)
#define SP_RESUME(dev_ext)
#define SP_STALL_EXECUTION ScsiPortStallExecution
#define SP_NOTIFICATION ScsiPortNotification
#define SP_busy(_dev_ext, _val)
#define SP_NEXT_REQUEST ScsiPortNotification
#define SP_GET_PHYSICAL_ADDRESS ScsiPortGetPhysicalAddress
#define SP_GET_DEVICE_BASE ScsiPortGetDeviceBase
#define SP_SET_QUEUE_DEPTH(_dev, _srb)
#define SP_ISSUE_DPC(_d, _dpc, _s1, _s2)
#define SP_SYNCHRONIZE_ACCESS(_dev, _func, _arg)                            \
    _func((_dev), (_arg))

#define SP_SHOULD_NOTIFY_NEXT(_dev_ext, _srb, _srb_ext, _num_free)          \
{                                                                           \
    if ((_num_free) < VIRTIO_MAX_SG) {                                      \
        (_srb_ext)->notify_next = TRUE;                                     \
    } else {                                                                \
        (_srb_ext)->notify_next = FALSE;                                    \
        SP_NOTIFICATION(NextLuRequest,                                      \
            (_dev_ext), (_srb)->PathId, (_srb)->TargetId, (_srb)->Lun);     \
    }                                                                       \
}

#define SP_COMPLETE_SRB(_dev_ext, _srb)                                     \
{                                                                           \
    ScsiPortNotification(RequestComplete, (_dev_ext), (_srb));              \
    ScsiPortNotification(NextLuRequest,                                     \
        (_dev_ext), (_srb)->PathId, (_srb)->TargetId, (_srb)->Lun);         \
}

#define StorPortEnablePassiveInitialization(_dev, _foo)

static FORCEINLINE sp_sgl_t *
sp_build_sgl(virtio_sp_dev_ext_t *dev_ext,
    SCSI_REQUEST_BLOCK *srb)
{
    sp_sgl_t      *scsi_sgl;
    uint8_t *data_buf;
    ULONG len;
    ULONG el;
    ULONG bytes_left;

    scsi_sgl = &dev_ext->scsi_sgl;
    bytes_left = srb->DataTransferLength;
    data_buf = (uint8_t *)srb->DataBuffer;

    el = 0;
    while (bytes_left) {
        scsi_sgl->List[el].PhysicalAddress =
            SP_GET_PHYSICAL_ADDRESS(dev_ext, srb, data_buf, &len);
            scsi_sgl->List[el].Length = len;
        bytes_left -= len;
        data_buf += len;
        el++;
    }
    scsi_sgl->NumberOfElements = el;
    if (scsi_sgl->NumberOfElements > VIRTIO_SP_MAX_SGL_ELEMENTS  + 3) {
        PRINTK(("vbif_build_sgl: sgl el %d, len %d.\n",
            scsi_sgl->NumberOfElements, srb->DataTransferLength));
    }
    return scsi_sgl;
}

#endif

#endif  /* _SP_DEFS_H_ */
