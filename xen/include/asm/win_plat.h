/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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

#ifndef _WIN_PLAT_H
#define _WIN_PLAT_H

#include <asm\win_cpuid.h>

struct kvec {
    void *iov_base; /* and that should *never* hold a userland pointer */
    size_t iov_len;
};

#define IS_ERR_VALUE(x) ((x) > (ULONG_PTR)-1000L)

#define XEN_LOCK_HANDLE KLOCK_QUEUE_HANDLE

#define XenAcquireSpinLock(_lock, _lh)  \
    KeAcquireInStackQueuedSpinLock((_lock), (_lh))

#define XenReleaseSpinLock(_lock, _lh)  \
    KeReleaseInStackQueuedSpinLock(&(_lh))

/*
 * __WIN_RING_SIZE should be the same as __RING_SIZE in ring.h.  However,
 * Windows will not compile correctly without the '&' on the ring.
 */

#define __WIN_RING_SIZE(_s, _sz)                                        \
    (__RD32(((_sz) - (ULONG_PTR)&(_s)->ring + (ULONG_PTR)(_s))          \
        / sizeof((_s)->ring[0])))

#define WIN_FRONT_RING_INIT(_r, _s, __size) do {                        \
    ULONG_PTR ulp;                                                      \
                                                                        \
    (_r)->req_prod_pvt = 0;                                             \
    (_r)->rsp_cons = 0;                                                 \
    ulp = __WIN_RING_SIZE(_s, __size);                                  \
    (_r)->nr_ents = (unsigned int)ulp;                                  \
    (_r)->sring = (_s);                                                 \
} while (0)


static __inline void *ERR_PTR(long error)
{
    return (void *)((ULONG_PTR)error);
}

static __inline LONG_PTR PTR_ERR(const void *ptr)
{
    return (LONG_PTR)ptr;
}

static __inline LONG_PTR IS_ERR(const void *ptr)
{
    return IS_ERR_VALUE((ULONG_PTR)ptr);
}

#ifdef ARCH_x86_64
void _XenbusKeepUsSane(void);
#define XenbusKeepUsSane _XenbusKeepUsSane

struct xen_add_to_physmap_compat {
    uint16_t domid;
    unsigned int space;
    uintptr_t idx;      /* Need to handle the 32/64 bit issue with longs. */
    uintptr_t gpfn;     /* Need to handle the 32/64 bit issue with longs. */
};

#define BitTestCompat BitTest64
#define InterlockedBitTestAndResetCompat InterlockedBitTestAndReset64
#define InterlockedBitTestAndSetCompat InterlockedBitTestAndSet64
#define InterlockedExchangeCompat InterlockedExchange64
#define XbBitScanForwardCompat XbBitScanForward64

#else

#define xen_add_to_physmap_compat xen_add_to_physmap
#define BitTestCompat BitTest
#define InterlockedBitTestAndResetCompat InterlockedBitTestAndReset
#define InterlockedBitTestAndSetCompat InterlockedBitTestAndSet
#define InterlockedExchangeCompat InterlockedExchange
#define XbBitScanForwardCompat XbBitScanForward
#define XenbusKeepUsSane()  \
{                           \
    __asm xor eax, eax      \
    __asm cpuid             \
}

#endif

#ifdef __BUILDMACHINE__ /* is set to WinDDK when using WinDDK sources */
#ifdef ARCH_x86_64
SHORT _InterlockedExchange16(IN OUT SHORT volatile *Target, IN SHORT Value);
#endif
static __inline SHORT
InterlockedExchange16(
  IN OUT SHORT volatile *Target,
  IN SHORT Value)
{
#ifdef ARCH_x86
    __asm {
        mov ax, Value;
        mov ebx, Target;
        lock xchg [ebx], ax;
    }
#else
    return _InterlockedExchange16(Target, Value);
#endif
}
#endif

static __inline LONG
XbBitScanForward(IN LONG volatile *Base)
{
    LONG index;

    if (_BitScanForward(&index, *Base) == 0) {
        index = 0;
    }
    return index;
}

#ifdef ARCH_x86_64
static __inline LONG
XbBitScanForward64(IN INT64 volatile *Base)
{
    LONG index;

    if (_BitScanForward64(&index, *Base) == 0) {
        index = 0;
    }
    return index;
}
#endif

static __inline void
GetCPUID(UINT32 Leaf, UINT32 *resA, UINT32 *resB, UINT32 *resC, UINT32 *resD)
{
    struct cpuid_args cpu_args;

    cpu_args.eax = Leaf;
#ifdef ARCH_x86
    __asm {
        mov eax, cpu_args.eax;
        cpuid;
        mov cpu_args.eax, eax;
        mov cpu_args.ebx, ebx;
        mov cpu_args.ecx, ecx;
        mov cpu_args.edx, edx;
    }
#else
    _cpuid64(&cpu_args);
#endif
    *resA = cpu_args.eax;
    *resB = cpu_args.ebx;
    *resC = cpu_args.ecx;
    *resD = cpu_args.edx;
}

static __inline void
WriteMSR(UINT32 MSR, UINT64 Value)
{
    __writemsr(MSR, Value);
}

#endif
