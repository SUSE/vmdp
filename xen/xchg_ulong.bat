@echo off
REM
REM SPDX-License-Identifier: BSD-2-Clause
REM
REM Copyright 2020 SUSE LLC
REM
REM Redistribution and use in source and binary forms, with or without
REM modification, are permitted provided that the following conditions
REM are met:
REM 1. Redistributions of source code must retain the above copyright
REM    notice, this list of conditions and the following disclaimer.
REM 2. Redistributions in binary form must reproduce the above copyright
REM    notice, this list of conditions and the following disclaimer in the
REM    documentation and/or other materials provided with the distribution.
REM
REM THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
REM IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
REM OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
REM IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
REM INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
REM NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
REM DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
REM THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
REM (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
REM THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
REM

REM ************** include\public\xen.h ************************************
sed "s/unsigned long/xen_ulong_t/g" include\xen\public\xen.h > include\xen\public\xen1.tmp

sed "s/xen\.h/win_xen\.h/g" include\xen\public\xen1.tmp > include\xen\public\win_xen.h

del include\xen\public\xen1.tmp

REM ************** include\public\arch-x86\xen.h ***************************
sed "s/unsigned long/xen_ulong_t/g" include\xen\public\arch-x86\xen.h > include\xen\public\arch-x86\xen1.tmp

sed "s/xen-x86_32\.h/win_xen-x86_32\.h/g" include\xen\public\arch-x86\xen1.tmp > include\xen\public\arch-x86\xen2.tmp

sed "s/xen-x86_64\.h/win_xen-x86_64\.h/g" include\xen\public\arch-x86\xen2.tmp > include\xen\public\arch-x86\win_xen.h

del include\xen\public\arch-x86\xen1.tmp
del include\xen\public\arch-x86\xen2.tmp

REM ************** include\public\arch-x86\xen-x86_32.h *******************
sed "s/unsigned long/xen_ulong_t/g" include\xen\public\arch-x86\xen-x86_32.h > include\xen\public\arch-x86\win_xen-x86_32.h

REM ************** include\public\arch-x86\xen-x86_64.h *******************
sed "s/unsigned long/xen_ulong_t/g" include\xen\public\arch-x86\xen-x86_64.h > include\xen\public\arch-x86\win_xen-x86_64.h
@echo on
