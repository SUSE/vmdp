/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2010-2012 Novell, Inc.
 * Copyright 2012-2021 SUSE LLC
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

#ifndef _VIRTIO_NET_VER_H
#define _VIRTIO_NET_VER_H


#if NDIS_SUPPORT_NDIS6
#if defined ARCH_x86
#define VER_FILEVERSION             2,6,1,03
#define VER_FILEVERSION_STR         "2.6.1.03\0"
#else
#define VER_FILEVERSION             2,6,1,03
#define VER_FILEVERSION_STR         "2.6.1.03\0"
#endif

#define VNIF_MAJOR_DRIVER_VERSION   0x02
#define VNIF_MINOR_DRIVER_VERSION   0x06

#else
#define VER_FILEVERSION             2,6,1,03
#define VER_FILEVERSION_STR         "2.6.1.03\0"

#define VNIF_MAJOR_DRIVER_VERSION   0x02
#define VNIF_MINOR_DRIVER_VERSION   0x06
#endif

#define VNIF_VENDOR_DRIVER_VERSION  ((VNIF_MAJOR_DRIVER_VERSION << 16) | \
                                    VNIF_MINOR_DRIVER_VERSION)

#define VER_LEGALCOPYRIGHT_STR      "Copyright \251 2011-2021 Novell, Inc. SUSE All rights reserved.", "\0"

#endif
