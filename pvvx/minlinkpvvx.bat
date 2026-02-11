@echo off
REM
REM SPDX-License-Identifier: BSD-2-Clause
REM
REM Copyright 2020-2021 SUSE LLC
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

rem Must be run from adiminstrator cmd box.

set start_dir=%cd%
cd ..
set root_dir=%cd%
cd %start_dir%

if exist inf\net-start.inf del inf\net-start.inf
mklink inf\net-start.inf %root_dir%\virtio\inf\net-start.inf
if exist inf\net-dev-desc.inf del inf\net-dev-desc.inf
mklink inf\net-dev-desc.inf %root_dir%\virtio\inf\net-dev-desc.inf
if exist inf\net-ndi.inf del inf\net-ndi.inf
mklink inf\net-ndi.inf %root_dir%\virtio\inf\net-ndi.inf
if exist inf\net-reg.inf del inf\net-reg.inf
mklink inf\net-reg.inf %root_dir%\virtio\inf\net-reg.inf
if exist inf\net-reg5.inf del inf\net-reg5.inf
mklink inf\net-reg5.inf %root_dir%\virtio\inf\net-reg5.inf
if exist inf\net-reg6.inf del inf\net-reg6.inf
mklink inf\net-reg6.inf %root_dir%\virtio\inf\net-reg6.inf
if exist inf\net-reg61.inf del inf\net-reg61.inf
mklink inf\net-reg61.inf %root_dir%\virtio\inf\net-reg61.inf
if exist inf\net-reg-msi.inf del inf\net-reg-msi.inf
mklink inf\net-reg-msi.inf %root_dir%\virtio\inf\net-reg-msi.inf
if exist inf\net-reg-poll.inf del inf\net-reg-poll.inf
mklink inf\net-reg-poll.inf %root_dir%\virtio\inf\net-reg-poll.inf
if exist inf\net-service.inf del inf\net-service.inf
mklink inf\net-service.inf %root_dir%\virtio\inf\net-service.inf
if exist inf\net-strings.inf del inf\net-strings.inf
mklink inf\net-strings.inf %root_dir%\virtio\inf\net-strings.inf
if exist inf\net-strings6.inf del inf\net-strings6.inf
mklink inf\net-strings6.inf %root_dir%\virtio\inf\net-strings6.inf
if exist inf\net-strings61.inf del inf\net-strings61.inf
mklink inf\net-strings61.inf %root_dir%\virtio\inf\net-strings61.inf

if exist build_all.bat del build_all.bat
mklink build_all.bat %root_dir%\virtio\build_all.bat
if exist msb.bat del msb.bat
mklink msb.bat %root_dir%\virtio\msb.bat
if exist unsetddk.bat del unsetddk.bat
mklink unsetddk.bat %root_dir%\virtio\unsetddk.bat
if exist unsetmsb.bat del unsetmsb.bat
mklink unsetmsb.bat %root_dir%\virtio\unsetmsb.bat

if exist pvvxbn\pvvxbn_x86.def del pvvxbn\pvvxbn_x86.def
sed "s/NAME xenbus.sys/NAME pvvxbn.sys/g" ..\xen\xenbus\xenbus_x86.def > pvvxbn\pvvxbn_x86.def
if exist pvvxbn\pvvxbn_x64.def del pvvxbn\pvvxbn_x64.def
sed "s/NAME xenbus.sys/NAME pvvxbn.sys/g" ..\xen\xenbus\xenbus_x64.def > pvvxbn\pvvxbn_x64.def

:end
set start_dir=
set root_dir=
