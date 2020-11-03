/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc. All Rights Reserved.
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

#ifndef _EVTCHN_H
#define _EVTCHN_H

#include <xen/public/event_channel.h>

#ifndef USE_INDIRECT_XENBUS_APIS
DLLEXPORT void mask_evtchn(int port);
DLLEXPORT void unmask_evtchn(int port);
DLLEXPORT uint32_t is_evtchn_masked(int port);
DLLEXPORT uint64_t xenbus_get_int_count(int port);
DLLEXPORT void notify_remote_via_irq(int irq);
DLLEXPORT void unbind_evtchn_from_irq(unsigned int evtchn);
DLLEXPORT NTSTATUS set_callback_irq(int irq);

DLLEXPORT NTSTATUS
register_dpc_to_evtchn(
  ULONG evtchn,
  PKDEFERRED_ROUTINE dpcroutine,
  PVOID dpccontext,
  void *system1
  );

DLLEXPORT VOID
unregister_dpc_from_evtchn(ULONG evtchn);

DLLEXPORT void force_evtchn_callback(void);

DLLEXPORT xen_long_t
notify_remote_via_evtchn(int port);

#endif

#endif
