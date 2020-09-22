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

set start_dir=%cd%
cd ..
set root_dir=%cd%
cd %start_dir%

if exist build_all.bat del build_all.bat
if exist msb.bat del msb.bat
if exist unsetddk.bat del unsetddk.bat
if exist unsetmsb.bat del unsetmsb.bat

if exist xenblk\storport_reg.c del xenblk\storport_reg.c
if exist xenscsi\storport_reg.c del xenscsi\storport_reg.c

if exist xennet\miniport.c del xennet\miniport.c
if exist xennet\mp_main5.c del xennet\mp_main5.c
if exist xennet\mp_main6.c del xennet\mp_main6.c
if exist xennet\mp_init5.c del xennet\mp_init5.c
if exist xennet\mp_init6.c del xennet\mp_init6.c
if exist xennet\mp_nic5.c del xennet\mp_nic5.c
if exist xennet\mp_nic6.c del xennet\mp_nic6.c
if exist xennet\init.c del xennet\init.c
if exist xennet\oid.c del xennet\oid.c
if exist xennet\mp_utils.c del xennet\mp_utils.c
if exist xennet\mp_rss.c del xennet\mp_rss.c

