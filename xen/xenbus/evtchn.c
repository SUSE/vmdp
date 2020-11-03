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

#define cpu_from_evtchn(port) (0)
#define MAX_EVTCHN 256

static KSPIN_LOCK cmpxchg_lock;
static uint32_t active_evtchns;
static uint32_t masked_evtchns;
static uint64_t int_count[MAX_EVTCHN_PORTS] = {0};

/*
 * Interrupt handling:
 * Because only the event_channel has allocate a shared irq
 * for all child devices, child devices cannot set their own
 * ISR. Different from Linux situation, in Windows, we use Dpc
 * instead of irqhandler. Child devices register their customDpc
 * to event channel routines. When event channel routines'
 * ISR runs, it queues the respective device Dpc in its own
 * queue for possible concurrent Dpc handling later.
 */
static evtchns_t evtchns[MAX_EVTCHN] = {0};

struct event_channel {
    int port;
    int in_use;
};

static struct {
    int registered;
    struct event_channel chn[MAX_EVTCHN];
} registered_evtchns;

void
mask_evtchn(int port)
{
    shared_info_t *s = shared_info_area;

    masked_evtchns |= (1 << port);
    InterlockedBitTestAndSetCompat(&s->evtchn_mask[0], port);
}

void
 unmask_evtchn(int port)
{
    evtchn_unmask_t op;

    XENBUS_SET_FLAG(rtrace, UNMASK_F);
    masked_evtchns &= ~(1 << port);
    op.port = port;
    HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &op);
    XENBUS_CLEAR_FLAG(rtrace, UNMASK_F);
}

uint32_t
is_evtchn_masked(int port)
{
    return masked_evtchns & (1 << port);
}

uint64_t
xenbus_get_int_count(int port)
{
    if (port < MAX_EVTCHN_PORTS) {
        return int_count[port];
    }
    return (uint64_t)-1;
}

static int
find_evtchn(int port)
{
    int i;

    for (i = 0; i < MAX_EVTCHN; i++) {
        if (registered_evtchns.chn[i].port == port) {
            return i;
        }
    }
    return MAX_EVTCHN;
}

static int
find_free_evtchn()
{
    int i;

    if (registered_evtchns.registered < MAX_EVTCHN) {
        i = registered_evtchns.registered;
        registered_evtchns.registered++;
        return i;
    }
    for (i = 0; i < MAX_EVTCHN; i++) {
        if (!registered_evtchns.chn[i].in_use) {
            return i;
        }
    }
    return MAX_EVTCHN;
}

/*
 * Registered Dpc routine will receive 3 additional parameters:
 * The first is the 3rd argument dpccontext passed to register_dpc
 * the second is the 4th argument context the caller registered in
 * the register_dpc. The third is the device extension of xenbus,
 * if the dpc is queued from the interrupt service routine.
 */
NTSTATUS
register_dpc_to_evtchn(ULONG evtchn,
    PKDEFERRED_ROUTINE dpcroutine,
    PVOID dpccontext,
    void *system1)
{
    PKDPC dpc;
    XEN_LOCK_HANDLE lh;
    char *buf;
    int channel;

    RPRINTK(DPRTL_ON, ("register_dpc_to_evtchn: evtchn %x\n", evtchn));
    if (evtchn >= MAX_EVTCHN || dpcroutine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * system1 must be non NULL for disks and null for all other devices.
     * Disks do not have dpcs created for them.
     * Disks with a dpcroutine and context just need their routine called.
     * Disks without a dpcroutine have the interrupt and will schedule
     * their own dpc.
     * All non disks need a dpc created.
     */
    if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
        if (system1 != NULL) {
            evtchns[evtchn].u.routine = dpcroutine;
            evtchns[evtchn].context = dpccontext;
        } else {
            dpc = ExAllocatePoolWithTag(NonPagedPoolNx,
                sizeof(KDPC), XENBUS_POOL_TAG);
            if (dpc == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RPRINTK(DPRTL_ON,
                    ("register_dpc_to_evtchn: evtchn %x, d %p, r %p, c %p\n",
                     evtchn, dpc, dpcroutine, dpccontext));
            KeInitializeDpc(dpc, dpcroutine, dpccontext);
            evtchns[evtchn].u.dpc = dpc;
            evtchns[evtchn].context = NULL;
        }
        evtchns[evtchn].wants_int_indication = system1;

        XenAcquireSpinLock(&cmpxchg_lock, &lh);
        XENBUS_SET_FLAG(xenbus_locks, X_CMP);
        channel = find_free_evtchn();
        if (channel < MAX_EVTCHN) {
            registered_evtchns.chn[channel].in_use = 1;
            registered_evtchns.chn[channel].port = (int)evtchn;
            RPRINTK(DPRTL_ON,
                    ("register_dpc ch = %d, reg = %d, evt = %ld\n",
                     channel, registered_evtchns.registered, evtchn));
        } else {
            XENBUS_CLEAR_FLAG(xenbus_locks, X_CMP);
            XenReleaseSpinLock(&cmpxchg_lock, lh);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        XENBUS_CLEAR_FLAG(xenbus_locks, X_CMP);
        XenReleaseSpinLock(&cmpxchg_lock, lh);

        evtchns[evtchn].locked = 0;
        active_evtchns |= (1 << evtchn);
        unmask_evtchn(evtchn);
    }

    RPRINTK(DPRTL_ON, ("register_dpc_to_evtchn: OUT\n"));
    return STATUS_SUCCESS;
}

VOID
unregister_dpc_from_evtchn(ULONG evtchn)
{
    PKDPC dpc;
    void *wants_int_indication;
    XEN_LOCK_HANDLE lh;
    int channel;

    if (evtchn >= MAX_EVTCHN) {
        return;
    }

    RPRINTK(DPRTL_ON, ("unregister_dpc_from_evtchn: mask_evtchn\n"));
    mask_evtchn(evtchn);
    dpc = evtchns[evtchn].u.dpc;
    wants_int_indication = evtchns[evtchn].wants_int_indication;
    evtchns[evtchn].u.dpc = NULL;
    evtchns[evtchn].context = NULL;
    evtchns[evtchn].wants_int_indication = NULL;

    XenAcquireSpinLock(&cmpxchg_lock, &lh);
    XENBUS_SET_FLAG(xenbus_locks, X_CMP);
    RPRINTK(DPRTL_ON, ("unregister_dpc_from_evtchn: find_evtchn\n"));
    channel = find_evtchn((int)evtchn);
    if (channel < MAX_EVTCHN) {
        registered_evtchns.chn[channel].in_use = 0;
        registered_evtchns.chn[channel].port = -1;
    }
    active_evtchns &= ~(1 << evtchn);
    XENBUS_CLEAR_FLAG(xenbus_locks, X_CMP);
    XenReleaseSpinLock(&cmpxchg_lock, lh);

    /* if wants_int_indication is non NULL, we didn't allocate the dpc. */
    if (dpc && wants_int_indication == NULL) {
        RPRINTK(DPRTL_ON, ("unregister_dpc_from_evtchn: evtchn %x, dpc %p\n",
                           evtchn, dpc));
        KeRemoveQueueDpc(dpc);
        ExFreePool(dpc);
    }
}

void
notify_remote_via_irq(int irq)
{
    int evtchn = irq;
    notify_remote_via_evtchn(evtchn);
}

void
unbind_evtchn_from_irq(unsigned int evtchn)
{
    return;
}

#ifdef DBG
uint32_t cpu_ints;
uint32_t cpu_ints_claimed;

#define INC_CPU_INTS() cpu_ints++;
#define INC_CPU_INTS_CLAIMED() cpu_ints_claimed++;
#else
#define INC_CPU_INTS()
#define INC_CPU_INTS_CLAIMED()
#endif

/*
 * We use critical section to do the real ISR thing, so we can
 * ``generate'' our own interrupt
 */

BOOLEAN EvtchnISR(void *context)
{
    shared_info_t *s;
    vcpu_info_t *v;
    evtchns_t *evtchn;
    xen_ulong_t l1, l2, l1i, port;
    ULONG ret_val = XEN_INT_NOT_XEN;

    DPRINTK(DPRTL_EVTCHN, ("EvtchnISR: at level %d\n", KeGetCurrentIrql()));

    if (shared_info_area == NULL) {
        PRINTK(("EvtchnISR: shared_info_area NULL.  Return.\n"));
        return FALSE;
    }

    /* All events are bound to vcpu0, but irq may be redirected. */
    s = shared_info_area;
    v = &s->vcpu_info[0];
    v->evtchn_upcall_pending = 0;
    KeMemoryBarrier();

    l1 = InterlockedExchangeCompat(&v->evtchn_pending_sel, 0);
#ifdef DBG
    if (evt_print) {
        DPRINTK(DPRTL_EVTCHN,
                ("EvtchnISR: irql = %d, cpu = %d, pending_sel %x",
                 KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), l1));
    }
#endif
    while (l1 != 0) {
        l1i = XbBitScanForwardCompat(&l1);
        l1 &= ~(1 << l1i);
        while ((l2 = s->evtchn_pending[l1i] & ~s->evtchn_mask[l1i])) {
            port = (l1i * sizeof(xen_ulong_t) * 8)
                + XbBitScanForwardCompat(&l2);
            DPRINTK(DPRTL_EVTCHN, (", port %x", port));
            InterlockedBitTestAndResetCompat(&s->evtchn_pending[0], port);
            if (port < MAX_EVTCHN_PORTS) {
                int_count[port]++;
            }

            evtchn = &evtchns[port];

            /* Only disk can have a want_int_indication. */
            if (evtchn->wants_int_indication) {
                *(evtchn->wants_int_indication) = 1;

                /*
                 * If the disk registered a dpc, call it.  Otherwise
                 * return and the disk will process at interrupt time.
                 */
                if (evtchn->u.routine) {
                    ((void (*)(void *, void *, void *, void *))
                        evtchn->u.routine)(NULL, evtchn->context, NULL, NULL);
                }
                ret_val |= XEN_INT_DISK;
                INC_CPU_INTS_CLAIMED();
            } else if (evtchn->u.dpc) {
                /* Non disk evtchn has work to do. */
                DPRINTK(DPRTL_EVTCHN, ("EvtchnISR: KeInsertQueueDpc %x\n",
                                       evtchn->u.dpc));
                if (port == xen_store_evtchn) {
                    ret_val |= XEN_INT_XS;
                    XENBUS_SET_FLAG(rtrace, EVTCHN_F);
                } else {
                    ret_val |= XEN_INT_LAN;
                    mask_evtchn((int)port);
                }
                KeInsertQueueDpc(evtchn->u.dpc, NULL, NULL);
                INC_CPU_INTS_CLAIMED();
            }
        }
    }

    DPRINTK(DPRTL_EVTCHN, (", return %d\n", ret_val));
#ifdef DBG
    if (evt_print) {
        DPRINTK(DPRTL_EVTCHN, ("EvtchnISR: OUT evtchn_pending = %x, sel =%x\n",
                               s->evtchn_pending[0], v->evtchn_pending_sel));
        evt_print = 0;
    }
#endif

    return ret_val ? TRUE : FALSE;
}

BOOLEAN
XenbusOnInterrupt(IN PKINTERRUPT InterruptObject, IN PVOID fdx)
{
    DPRINTK(DPRTL_EVTCHN, ("XenbusOnInterrupt.\n"));
    INC_CPU_INTS();
    return EvtchnISR((PFDO_DEVICE_EXTENSION)fdx);
}

void
force_evtchn_callback(void)
{
    DPRINTK(DPRTL_EVTCHN, ("force_evtchn_callback: IN\n"));
    KeSynchronizeExecution(
      DriverInterruptObj,
      EvtchnISR,
      NULL);
    DPRINTK(DPRTL_EVTCHN, ("force_evtchn_callback: OUT\n"));
}

NTSTATUS
set_callback_irq(int irq)
{
    struct xen_hvm_param a;

    RPRINTK(DPRTL_ON, ("set_callback_irq: IN %d\n", irq));
    a.domid = DOMID_SELF;
    a.index = HVM_PARAM_CALLBACK_IRQ;
    a.value = irq;
    RPRINTK(DPRTL_ON, ("set_callback_irq: HVMOP_set_param\n"));
    if (HYPERVISOR_hvm_op(HVMOP_set_param, &a) != 0) {
        PRINTK(("XENBUS: set callback irq fail.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    RPRINTK(DPRTL_ON, ("set_callback_irq: OUT\n"));

    return STATUS_SUCCESS;
}

void
evtchn_remove_queue_dpc(void)
{
    uint32_t i;

    for (i = 0; i < MAX_EVTCHN; i++) {
        if (evtchns[i].u.dpc && evtchns[i].wants_int_indication == NULL) {
            if (KeRemoveQueueDpc(evtchns[i].u.dpc)) {
                RPRINTK(DPRTL_ON,
                        ("evtchn_remove_queue_dpc: removed %d.\n", i));
            }
        }
    }
}

xen_long_t
notify_remote_via_evtchn(int port)
{
    struct evtchn_send send;

    send.port = port;
    return HYPERVISOR_event_channel_op(EVTCHNOP_send, &send);
}

VOID
evtchn_init(uint32_t reason)
{
    int i;

    if (reason == OP_MODE_HIBERNATE || reason == OP_MODE_CRASHDUMP) {
        return;
    }

    KeInitializeSpinLock(&cmpxchg_lock);
    registered_evtchns.registered = 0;
    for (i = 0; i < MAX_EVTCHN; i++) {
        if (evtchns[i].u.dpc) {
            /* Remove any inflight DPCs due to save/restore/migrate. */
            if (evtchns[i].context == NULL) {
                if (KeRemoveQueueDpc(evtchns[i].u.dpc)) {
                    RPRINTK(DPRTL_ON,
                            ("evtchn_init: removed a dpc %p from %d.\n",
                             evtchns[i].u.dpc, i));
                }
                RPRINTK(DPRTL_ON, ("evtchn_init: free dpc %p mem.\n",
                                   evtchns[i].u.dpc));
                ExFreePool(evtchns[i].u.dpc);
            }
            evtchns[i].u.dpc = NULL;
        }
        evtchns[i].locked = 0;
        evtchns[i].wants_int_indication = 0;
        registered_evtchns.chn[i].in_use = 0;
        registered_evtchns.chn[i].port = -1;
    }
    active_evtchns = 0;
    masked_evtchns = 0;
}
