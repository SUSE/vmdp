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

if "%1"=="" goto help

set p2=%2
if "%p2%"=="" set p2=%1

copy dsln%1 virtio.sln
copy dirs-Package\dpkg%1 dirs-Package\dirs-Package.vcxproj

for %%d in (fwcvg  pvcrash_notify pvvxsvc virtio_balloon virtio_blk virtio_net virtio_scsi virtio_serial virtio_rng) do (
    if "%%d%"=="virtio_scsi" (
        copy %%d\vtioscsi_vs%1 %%d\vtioscsi.vcxproj
    ) else if "%%d%"=="virtio_rng" (
        copy %%d\vrng_vs%1 %%d\vrng.vcxproj
        copy %%d\cng\um\viorngum_vs%p2% %%d\cng\um\viorngum.vcxproj
        copy %%d\coinstaller\viorngci_vs%p2% %%d\coinstaller\viorngci.vcxproj
    ) else (
        copy %%d\%%d_vs%1 %%d\%%d.vcxproj
    )
)
goto end

:help
echo Must specify the vs version eg. 15 | 17 | 19

:end
set p2=
