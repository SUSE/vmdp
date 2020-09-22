;
; SPDX-License-Identifier: BSD-2-Clause
;
; Copyright 2007-2012 Novell, Inc.
; Copyright 2012-2020 SUSE LLC
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions
; are met:
; 1. Redistributions of source code must retain the above copyright
;    notice, this list of conditions and the following disclaimer.
; 2. Redistributions in binary form must reproduce the above copyright
;    notice, this list of conditions and the following disclaimer in the
;    documentation and/or other materials provided with the distribution.
;
; THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
; IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
; OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
; IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
; INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
; NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
; THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;

public _hypercall0
public _hypercall1
public _hypercall2
public _hypercall3
public _hypercall4
public _hypercall5
public _cpuid64
public _InterlockedExchange16
public _XenbusKeepUsSane
public hypercall_page_mem

_STACKRESERVE    equ 64 ; Space to reserve on the stack to save GPRs.

;
;***************************************************************\
;                                                               *
;       Equates.                                                *
;                                                               *
;***************************************************************/
;

PARAM_SIZE  equ 4
PARAM1      equ 5*PARAM_SIZE
PARAM2      equ     PARAM1 + PARAM_SIZE
PARAM3      equ     PARAM2 + PARAM_SIZE
PARAM4      equ     PARAM3 + PARAM_SIZE
PARAM5      equ     PARAM4 + PARAM_SIZE
PARAM6      equ     PARAM5 + PARAM_SIZE
PARAM7      equ     PARAM6 + PARAM_SIZE
PARAM8      equ     PARAM7 + PARAM_SIZE
PARAM9      equ     PARAM8 + PARAM_SIZE
PARAM10     equ     PARAM9 + PARAM_SIZE
PARAM11     equ     PARAM10+ PARAM_SIZE

.DATA

.CODE

hypercall_page_mem db   8192 dup (0)

;
;***************************************************************\
;                                                               *
;       Macros.                                                 *
;                                                               *
;***************************************************************/
;

SaveGPR MACRO

    sub rsp,_STACKRESERVE
    .allocstack _STACKRESERVE
    mov [rsp+56],r15
    .savereg r15,56
    mov [rsp+48],r14
    .savereg r14,48
    mov [rsp+40],r13
    .savereg r13,40
    mov [rsp+32],r12
    .savereg r12,32
    mov [rsp+24],rsi
    .savereg rsi,24
    mov [rsp+16],rdi
    .savereg rdi,16
    mov [rsp+8],rbx
    .savereg rbx,8
    mov [rsp+0],rbp
    .savereg rbp,0
    .endprolog

ENDM

RestoreGPR MACRO

    mov r15,[rsp+56]
    mov r14,[rsp+48]
    mov r13,[rsp+40]
    mov r12,[rsp+32]
    mov rsi,[rsp+24]
    mov rdi,[rsp+16]
    mov rbx,[rsp+8]
    mov rbp,[rsp+0]
    add rsp,_STACKRESERVE

ENDM

align 8
;_hypercall0(hpg, op)
_hypercall0 proc frame

    SaveGPR

        mov rax, rcx
        add rax, rdx
        call rax

    RestoreGPR
    ret

align 8
_hypercall0 endp

align 8
;_hypercall1(hpg, op, a1)
_hypercall1 proc frame

    SaveGPR

        mov rax, rcx
        add rax, rdx
    mov rdi, r8
        call rax

    RestoreGPR
    ret

align 8
_hypercall1 endp

align 8
;_hypercall2(hpg, op, a1, a2)
_hypercall2 proc frame

    SaveGPR

        mov rax, rcx
        add rax, rdx
    mov rdi, r8
    mov rsi, r9
        call rax

    RestoreGPR
    ret

align 8
_hypercall2 endp

align 8
;_hypercall3(hpg, op, a1, a2, a3)
_hypercall3 proc frame

    SaveGPR

        mov rax, rcx
        add rax, rdx
    mov rdi, r8
    mov rsi, r9
    mov rdx, [rsp+40+_STACKRESERVE]
        call rax

    RestoreGPR
    ret

align 8
_hypercall3 endp



align 8
;_hypercall4(hpg, op, a1, a2, a3, a4)
_hypercall4 proc frame

    SaveGPR

        mov rax, rcx
        add rax, rdx
    mov rdi, r8
    mov rsi, r9
    mov rdx, [rsp+40+_STACKRESERVE]
    mov r10, [rsp+48+_STACKRESERVE]
        call rax

    RestoreGPR
    ret

align 8
_hypercall4 endp

align 8
;_hypercall5(hpg, op, a1, a2, a3, a4, a5)
_hypercall5 proc frame

    SaveGPR

        mov rax, rcx
        add rax, rdx
    mov rdi, r8
    mov rsi, r9
    mov rdx, [rsp+40+_STACKRESERVE]
    mov r10, [rsp+48+_STACKRESERVE]
    mov r8, [rsp+56+_STACKRESERVE]
        call rax

    RestoreGPR
    ret

align 8
_hypercall5 endp


align     8
; void _cpuid64(cpuid_args* p);
_cpuid64    proc frame
; rcx <= p
    sub     rsp, 32
    .allocstack 32
    push        rbx
    .pushreg    rbx
    .endprolog

    mov r8, rcx
    mov eax, DWORD PTR [r8+0]
    mov ecx, DWORD PTR [r8+8]
    cpuid
    mov DWORD PTR [r8+0], eax
    mov DWORD PTR [r8+4], ebx
    mov DWORD PTR [r8+8], ecx
    mov DWORD PTR [r8+12], edx

    pop      rbx
    add      rsp, 32

    ret
    align     8
_cpuid64 endp

align 8
;_XenbusKeepUsSane()
_XenbusKeepUsSane proc frame

    SaveGPR

    xor rax, rax
    cpuid
    rdtsc

    RestoreGPR
    ret

align 8
_XenbusKeepUsSane endp

;*************************************************************************
;
; SHORT InterlockedExchange16(SHORT volatile *Target, SHORT Value)
;
;*************************************************************************
;InterlockedExchange16   proc   near
;
;   CPush                           ; save C registers
;   mov eax, [esp+PARAM2]       ; Value
;   mov ebx, [esp+PARAM1]       ; Target
;        lock    xchg [ebx], ax;
;   CPop                            ; restore C registers
;   ret
;
;InterlockedExchange16   endp

align     8
; SHORT _InterlockedExchange16   (SHORT volatile *Target, SHORT Value)
_InterlockedExchange16   proc frame
    ;.allocstack 0
    .endprolog

    xor rax, rax
        mov ax, dx      ;Value
        ;mov rbx, rcx;      Target
        lock xchg [rcx], ax;

    ret
    align     8
_InterlockedExchange16   endp

_TEXT ENDS
    end
