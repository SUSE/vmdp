/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2011-2012 Novell, Inc.
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

#include <ntddk.h>
#include <ntstrsafe.h>
#include <virtio_dbg_print.h>

KSPIN_LOCK virtio_print_lock;

static void
virtio_print_str(char *str)
{
    KLOCK_QUEUE_HANDLE lh;
    PVOID port;

    char *c;

    /*
     * Spin locks don't protect against irql > 2.  So if we come in at a
     * higl level, just print it and we'll have to maually sort out the
     * the possible mixing of multiple output messages.
     */
    port = VIRTIO_DEBUG_PORT;
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        for (c = str; *c; c++) {
            WRITE_PORT_UCHAR(port, *c);
        }
    } else {
        KeAcquireInStackQueuedSpinLock(&virtio_print_lock, &lh);
        for (c = str; *c; c++) {
            WRITE_PORT_UCHAR(port, *c);
        }
        KeReleaseInStackQueuedSpinLock(&lh);
    }
}


void
virtio_dbg_printk(char *_fmt, ...)
{
    va_list ap;
    char buf[256];
    char *c;

    va_start(ap, _fmt);
    RtlStringCbVPrintfA(buf, sizeof(buf), _fmt, ap);
    va_end(ap);
    virtio_print_str(buf);
}
