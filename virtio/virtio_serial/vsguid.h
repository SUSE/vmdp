/*
 * Copyright (c) 2010-2017 Red Hat, Inc.
 * Copyright 2014-2020 SUSE LLC
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

#ifndef _VSGUID_H
#define _VSGUID_H

/* {79AAA234-DD0C-436C-8878-D13E6E10BBA5} */
DEFINE_GUID(GUID_DEVINTERFACE_VSERIAL,
    0x79aaa234, 0xdd0c, 0x436c, 0x88, 0x78, 0xd1, 0x3e, 0x6e, 0x10, 0xbb, 0xa5);

/* {1C2DC908-E7A7-4C49-BB70-D8CC7CC8D16D} */
DEFINE_GUID(GUID_DEVCLASS_VSERIAL,
0x1c2dc908, 0xe7a7, 0x4c49, 0xbb, 0x70, 0xd8, 0xcc, 0x7c, 0xc8, 0xd1, 0x6d);

/* {D693FCA3-6D63-4DF7-8E83-EAEEA3D0AEA7} */
DEFINE_GUID(GUID_VSERIAL_INTERFACE_STANDARD,
0xd693fca3, 0x6d63, 0x4df7, 0x8e, 0x83, 0xea, 0xee, 0xa3, 0xd0, 0xae, 0xa7);

/* {527ABA3E-0964-46E9-880F-A736D2381DD1} */
DEFINE_GUID(GUID_SD_VSERIAL_PDO,
0x527aba3e, 0x964, 0x46e9, 0x88, 0xf, 0xa7, 0x36, 0xd2, 0x38, 0x1d, 0xd1);

/****************************************************************************/
DEFINE_GUID(GUID_VIOSERIAL_PORT,
0x6fde7521, 0x1b65, 0x48ae, 0xb6, 0x28, 0x80, 0xbe, 0x62, 0x1, 0x60, 0x26);
/*0x6fde7547, 0x1b65, 0x48ae, 0xb6, 0x28, 0x80, 0xbe, 0x62, 0x1, 0x60, 0x26); */

DEFINE_GUID(GUID_DEVCLASS_PORT_DEVICE,
0x6fde7547, 0x1b65, 0x48ae, 0xb6, 0x28, 0x80, 0xbe, 0x62, 0x1, 0x60, 0x26);
/* {6FDE7547-1B65-48ae-B628-80BE62016026} */

DEFINE_GUID(GUID_VIOSERIAL_PORT_CHANGE_STATUS,
0x2c0f39ac, 0xb156, 0x4237, 0x9c, 0x64, 0x89, 0x91, 0xa1, 0x8b, 0xf3, 0x5c);
/* {2C0F39AC-B156-4237-9C64-8991A18BF35C} */

#endif
