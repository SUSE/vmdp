/*-
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

#ifndef _GUID_H
#define _GUID_H

/* {1133836d-e283-487e-8d6a-2ad3e157439f} */
DEFINE_GUID(GUID_DEVINTERFACE_XENBUS,
    0x1133836d, 0xe283, 0x487e, 0x8d, 0x6a, 0x21, 0xd3, 0xe1, 0x57, 0x43, 0x9f);

/* {449c996d-751d-4ec2-b998-504e559b13f8} */
DEFINE_GUID(GUID_SD_XENBUS_PDO,
    0x449c996d, 0x751d, 0x4ec2, 0xb9, 0x98, 0x50, 0x4e, 0x55, 0x9b, 0x13, 0xf8);

/* {48b81a04-e879-4486-ae88-019845c1114f} */
DEFINE_GUID(GUID_DEVCLASS_XENBUS,
    0x48b81a04, 0xe879, 0x4486, 0xae, 0x88, 0x01, 0x98, 0x45, 0xc1, 0x11, 0x4f);

/*  {49231a0a-e1df-415b-9fd0-91725fea3aaa} */
DEFINE_GUID(GUID_XENBUS_INTERFACE_STANDARD,
    0x49231a0a, 0xe1df, 0x415b, 0x9f, 0xd0, 0x91, 0x72, 0x5f, 0xea, 0x3a, 0xaa);

#endif
