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

#ifndef _ASM_HYPERCALL_H
#define _ASM_HYPERCALL_H

DLLEXPORT extern PUCHAR hypercall_page;

#define HYPERCALL_EVENT_CHANNEL_OP  __HYPERVISOR_event_channel_op*32
#define HYPERCALL_SET_GDT           __HYPERVISOR_set_gdt*32
#define HYPERCALL_STACK_SWITCH      __HYPERVISOR_stack_switch*32
#define HYPERCALL_SCHED_OP          __HYPERVISOR_sched_op*32
#define HYPERCALL_SET_TIMER         __HYPERVISOR_set_timer_op*32
#define HYPERCALL_SET_DEBUGREG      __HYPERVISOR_set_debugreg*32
#define HYPERCALL_MEMORY_OP         __HYPERVISOR_memory_op*32
#define HYPERCALL_MULTICALL         __HYPERVISOR_multicall*32
#define HYPERCALL_ACM               __HYPERVISOR_acm_op*32
#define HYPERCALL_XEN_VERSION       __HYPERVISOR_xen_version*32
#define HYPERCALL_PHYSDEV           __HYPERVISOR_physdev_op*32
#define HYPERCALL_VM_ASSIST         __HYPERVISOR_vm_assist*32
#define HYPERCALL_NMI               __HYPERVISOR_nmi_op*32
#define HYPERCALL_HVM               __HYPERVISOR_hvm_op*32
#define HYPERCALL_CALLBACK          __HYPERVISOR_callback_op*32
#define HYPERCALL_XENOPROF          __HYPERVISOR_xenoprof_op*32
#define HYPERCALL_SET_TRAP_TABLE    __HYPERVISOR_set_trap_table*32
#define HYPERCALL_MMU_UPDATE        __HYPERVISOR_mmu_update*32
#define HYPERCALL_MMUEXT_OP         __HYPERVISOR_mmuext_op*32
#define HYPERCALL_SET_CALLBACKS     __HYPERVISOR_set_callbacks*32
#define HYPERCALL_FPU_TASKSWITCH    __HYPERVISOR_fpu_taskswitch*32
#define HYPERCALL_GET_DEBUGREG      __HYPERVISOR_get_debugreg*32
#define HYPERCALL_UPDATE_DESCRIPTOR __HYPERVISOR_update_descriptor*32
#define HYPERCALL_CONSOLE_IO        __HYPERVISOR_console_io*32
#define HYPERCALL_PHYSDEV_OP_COMPAT __HYPERVISOR_physdev_op_compat*32
#define HYPERVISOR_GRANT_TABLE_OP   __HYPERVISOR_grant_table_op*32
#define HYPERCALL_VCPU_OP           __HYPERVISOR_vcpu_op*32
#define HYPERCALL_SCHED_OP_COMPAT   __HYPERVISOR_sched_op_compat*32
#define HYPERCALL_EVENT_CHANNEL_OP_COMPAT                                   \
                                    __HYPERVISOR_event_channel_op_compat*32
/*
 * We add a local variable to circumvent problems brought by inline assembly.
 * when hypercall_page is imported, the code cl generated for ``__asm add eax,
 * [hypercall_page]'' is indeed ``add eax, [_imp__hypercall_page]'', which is
 * very wrong.
 */

#ifdef ARCH_x86
static __inline void
_hypercall0(PUCHAR hpg, ULONG_PTR op)
{
    __asm {
        mov eax, [hpg]
        add eax, op
        call eax
    }
}

static __inline void
_hypercall1(PUCHAR hpg, ULONG_PTR op, void *a1)
{
    __asm {
        mov ebx, a1
        mov eax, [hpg]
        add eax, op
        call eax
    }
}

static __inline xen_long_t
_hypercall2(PUCHAR hpg, ULONG_PTR op, void *a1, void *a2)
{
    xen_long_t cc;

    __asm {
        mov ebx, a1
        mov ecx, a2
        mov eax, [hpg]
        add eax, op
        call eax
        mov cc, eax
    }
    return cc;
}

static __inline xen_long_t
_hypercall3(PUCHAR hpg, ULONG_PTR op, void *a1, void *a2, void *a3)
{
    xen_long_t cc;

    __asm {
        mov ebx, a1
        mov ecx, a2
        mov edx, a3
        mov eax, [hpg]
        add eax, op
        call eax
        mov cc, eax
    }
    return cc;
}

static __inline void
_hypercall4(PUCHAR hpg, ULONG_PTR op, void *a1, void *a2, void *a3, void *a4)
{
    __asm {
        mov ebx, a1
        mov ecx, a2
        mov edx, a3
        mov esi, a4
        mov eax, [hpg]
        add eax, op
        call eax
    }
}

static __inline void
_hypercall5(PUCHAR hpg, ULONG_PTR op,
    void *a1, void *a2, void *a3, void *a4, void *a5)
{
    __asm {
        mov ebx, a1
        mov ecx, a2
        mov edx, a3
        mov esi, a4
        mov edi, a5
        mov eax, [hpg]
        add eax, op
        call eax
    }
}
#endif

#ifdef ARCH_x86_64
/* Hypercalls declaration */
void _hypercall0(PUCHAR hpg, ULONG_PTR);
void _hypercall1(PUCHAR hpg, ULONG_PTR op, void *a1);
xen_long_t _hypercall2(PUCHAR hpg, ULONG_PTR op, void *a1, void *a2);
xen_long_t _hypercall3(PUCHAR hpg, ULONG_PTR op, void *a1, void *a2,
    void *a3);
void _hypercall4(PUCHAR hpg, ULONG_PTR op, void *a1, void *a2,
    void *a3, void *a4);
void _hypercall5(PUCHAR hpg, ULONG_PTR op, void *a1, void *a2,
    void *a3, void *a4, void *a5);
extern uint8_t hypercall_page_mem[];
#endif

static __inline void
HYPERVISOR_set_trap_table(
  trap_info_t *table)
{
    PUCHAR hpg = hypercall_page;

    _hypercall1(hpg, HYPERCALL_SET_TRAP_TABLE, table);
}

static __inline void
HYPERVISOR_mmu_update(
  mmu_update_t *req, int count, int *success_count, domid_t domid)
{
    PUCHAR hpg = hypercall_page;
    void *_count = (void *)((ULONG_PTR)count);
    void *_domid = (void *)((ULONG_PTR)domid);

    _hypercall4(hpg, HYPERCALL_MMU_UPDATE, req, _count, success_count, _domid);
}

static __inline void
HYPERVISOR_mmuext_op(
  struct mmuext_op *op, int count, int *success_count, domid_t domid)
{
    PUCHAR hpg = hypercall_page;
    void *_count = (void *)((ULONG_PTR)count);
    void *_domid = (void *)((ULONG_PTR)domid);

    _hypercall4(hpg, HYPERCALL_MMUEXT_OP, op, _count, success_count, _domid);
}

static __inline xen_long_t
HYPERVISOR_set_gdt(
  unsigned long *frame_list, int entries)
{
    PUCHAR hpg = hypercall_page;
    void *_entries = (void *)((ULONG_PTR)entries);

    return _hypercall2(hpg, HYPERCALL_SET_GDT, frame_list, _entries);
}

static __inline xen_long_t
HYPERVISOR_stack_switch(
  unsigned long ss, unsigned long esp)
{
    PUCHAR hpg = hypercall_page;
    void * _ss = (void *)((ULONG_PTR)ss);
    void * _esp = (void *)((ULONG_PTR)esp);

    return _hypercall2(hpg, HYPERCALL_STACK_SWITCH, _ss, _esp);
}

static __inline void
HYPERVISOR_set_callbacks(
  unsigned long event_selector, unsigned long event_address,
  unsigned long failsafe_selector, unsigned long failsafe_address)
{
    PUCHAR hpg = hypercall_page;
    void *a1 = (void *)((ULONG_PTR)event_selector);
    void *a2 = (void *)((ULONG_PTR)event_address);
    void *a3 = (void *)((ULONG_PTR)failsafe_selector);
    void *a4 = (void *)((ULONG_PTR)failsafe_address);

    _hypercall4(hpg, HYPERCALL_SET_CALLBACKS, a1, a2, a3, a4);
}

static __inline void
HYPERVISOR_fpu_taskswitch(
  int set)
{
    PUCHAR hpg = hypercall_page;
    void *_set = (void *)((ULONG_PTR)set);

    _hypercall1(hpg, HYPERCALL_FPU_TASKSWITCH, _set);
}

static __inline xen_long_t
HYPERVISOR_sched_op_compat(
  int cmd, unsigned long arg)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);
    void *_arg = (void *)((ULONG_PTR)arg);

    return _hypercall2(hpg, HYPERCALL_SCHED_OP_COMPAT, _cmd, _arg);
}

static __inline xen_long_t
HYPERVISOR_sched_op(
  int cmd, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);

    return _hypercall2(hpg, HYPERCALL_SCHED_OP, _cmd, arg);
}

static __inline xen_long_t
HYPERVISOR_memory_op(
  unsigned int cmd, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);

    return _hypercall2(hpg, HYPERCALL_MEMORY_OP, _cmd, arg);
}

static __inline xen_long_t
HYPERVISOR_multicall(
  void *call_list, int nr_calls)
{
    PUCHAR hpg = hypercall_page;
    void *_nr_calls = (void *)((ULONG_PTR)nr_calls);

    return _hypercall2(hpg, HYPERCALL_MULTICALL, call_list, _nr_calls);
}

static __inline void
HYPERVISOR_update_va_mapping(
  unsigned long va, unsigned long new_val, unsigned long flags)
{
    PUCHAR hpg = hypercall_page;
    unsigned long pte_hi = 0;
}

static __inline xen_long_t
HYPERVISOR_event_channel_op(
  int cmd, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);
    int j;

    return _hypercall2(hpg, HYPERCALL_EVENT_CHANNEL_OP, _cmd, arg);
#if 0
    if (unlikely(rc == -ENOSYS)) {
        struct evtchn_op op;
        op.cmd = cmd;
        memcpy(&op.u, arg, sizeof(op.u));
        rc = _hypercall1(hpg, HYPERCALL_EVENT_CHANNEL_OP_COMPAT, &op);
        memcpy(arg, &op.u, sizeof(op.u));
    }
#endif
}

static __inline xen_long_t
HYPERVISOR_acm_op(
  int cmd, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);

    return _hypercall2(hpg, HYPERCALL_ACM, _cmd, arg);
}

static __inline xen_long_t
HYPERVISOR_xen_version(
  int cmd, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);

    return _hypercall2(hpg, HYPERCALL_XEN_VERSION, _cmd, arg);
}

static __inline xen_long_t
HYPERVISOR_console_io(
  int cmd, int count, char *string)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);
    void *_count = (void *)((ULONG_PTR)count);

    return _hypercall3(hpg, HYPERCALL_CONSOLE_IO, _cmd, _count, string);
}

static __inline xen_long_t
HYPERVISOR_physdev_op(
  int cmd, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);

    return _hypercall2(hpg, HYPERCALL_PHYSDEV, _cmd, arg);
}

static __inline xen_long_t
HYPERVISOR_grant_table_op(
  unsigned int cmd, void *uop, unsigned int count)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);
    void *_count = (void *)((ULONG_PTR)count);

    return _hypercall3(hpg, HYPERVISOR_GRANT_TABLE_OP, _cmd, uop, _count);
}

static __inline void
HYPERVISOR_update_va_mapping_otherdomain(
  unsigned long va, unsigned long new_val, unsigned long flags, domid_t domid)
{
    unsigned long pte_hi = 0;
}

static __inline xen_long_t
HYPERVISOR_vm_assist(
  unsigned int cmd, unsigned int optype)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);
    void *_optype = (void *)((ULONG_PTR)optype);

    return _hypercall2(hpg, HYPERCALL_VM_ASSIST, _cmd, _optype);
}

static __inline xen_long_t
HYPERVISOR_vcpu_op(
  int cmd, int vcpuid, void *extra_args)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);
    void *_vcpuid = (void *)((ULONG_PTR)vcpuid);

    return _hypercall3(hpg, HYPERCALL_VCPU_OP, _cmd, _vcpuid, extra_args);
}

static __inline xen_long_t
HYPERVISOR_shutdown(
  unsigned long reason)
{
    struct sched_shutdown sched_shutdown;
    PUCHAR hpg = hypercall_page;

    sched_shutdown.reason = reason;

    return _hypercall2(hpg, HYPERCALL_SCHED_OP, (void *)SCHEDOP_shutdown,
        &sched_shutdown);
}

static __inline xen_long_t
HYPERVISOR_suspend(
  unsigned long srec)
{
    struct sched_shutdown sched_shutdown;
    PUCHAR hpg = hypercall_page;

    sched_shutdown.reason = SHUTDOWN_suspend;

    return _hypercall3(hpg, HYPERCALL_SCHED_OP, (void *)SCHEDOP_shutdown,
         (void *)&sched_shutdown, (void *)srec);
}

static __inline xen_long_t
HYPERVISOR_nmi_op(
  unsigned long op, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_op = (void *)((ULONG_PTR)op);

    return _hypercall2(hpg, HYPERCALL_NMI, _op, arg);
}

static __inline xen_long_t
HYPERVISOR_hvm_op(
  int op, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_op = (void *)((ULONG_PTR)op);

    return _hypercall2(hpg, HYPERCALL_HVM, _op, arg);
}

static __inline xen_long_t
HYPERVISOR_callback_op(
  int cmd, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_cmd = (void *)((ULONG_PTR)cmd);

    return _hypercall2(hpg, HYPERCALL_CALLBACK, _cmd, arg);
}

static __inline xen_long_t
HYPERVISOR_xenoprof_op(
  int op, void *arg)
{
    PUCHAR hpg = hypercall_page;
    void *_op = (void *)((ULONG_PTR)op);

    return _hypercall2(hpg, HYPERCALL_XENOPROF, _op, arg);
}

#endif
