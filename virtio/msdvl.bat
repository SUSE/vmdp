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

REM Must run from the \vmdp\virtio dir

set mstart_dir=%cd%
set p_platform=x64
set cp_platform=x64
set do_full_sdv=no
set dvl_drv=
set config_os=

if "%1"=="" goto build_it

:l_loop
if %1==10 (
    set config_os=%config_os% Win10
) else if %1==81 (
    set config_os=%config_os% Win8.1
) else if %1==8 (
    set config_os=%config_os% Win8
) else if %1==full (
    set do_full_sdv=yes
) else if %1==virtio_balloon (
    set dvl_drv=%dvl_drv% virtio_balloon
) else if %1==virtio_blk (
    set dvl_drv=%dvl_drv% virtio_blk
) else if %1==virtio_net (
    set dvl_drv=%dvl_drv% virtio_net
) else if %1==virtio_scsi (
    set dvl_drv=%dvl_drv% virtio_scsi
) else if %1==virtio_serial (
    set dvl_drv=%dvl_drv% virtio_serial
) else if %1==virtio_rng (
    set dvl_drv=%dvl_drv% virtio_rng
) else if %1==pvcrash (
    set dvl_drv=%dvl_drv% pvcrash_notify
) else if %1==fwcfg (
    set dvl_drv=%dvl_drv% fwcfg
) else if %1==vmdp (
    set dvl_drv=virtio_serial virtio_rng pvcrash_notify fwcfg
) else if %1==all (
    set dvl_drv=virtio_balloon virtio_blk virtio_net virtio_scsi virtio_serial virtio_rng pvcrash_notify fwcfg
) else (
    echo Unknown paramtere: %1
    goto help
)
shift
if not "%1"=="" goto l_loop

if "%dvl_drv%"=="" goto help
if "%config_os%"=="" set config_os=Win10 Win8.1 Win8

:build_it

if not exist dvl mkdir dvl

for %%c in (%config_os%) do (
    if not exist dvl\%%cRelease mkdir dvl\%%cRelease
    if not exist dvl\%%cRelease\%cp_platform% mkdir dvl\%%cRelease\%cp_platform%
    for %%d in (%dvl_drv%) do (
        cd %%d
        title DVL %%d: %%c %p_platform% full=%do_full_sdv% clean
        msbuild /p:Configuration="%%c Release" /p:Platform=%p_platform% /target:clean

        if %do_full_sdv%==yes (
            title DVL %%d: %%c %p_platform% full=%do_full_sdv% sdv clean
            msbuild /p:Configuration="%%c Release" /p:Platform=%p_platform% /target:sdv /p:inputs="/clean"

            title DVL %%d: %%c %p_platform% full=%do_full_sdv% sdv check default.sdv
            msbuild /p:Configuration="%%c Release" /p:Platform=%p_platform% /target:sdv /p:inputs="/check:default.sdv"

            del smvbuild.log
            del smvstats.txt
        )

        title DVL %%d: %%c %p_platform% full=%do_full_sdv% run code analysis once
        msbuild /p:Configuration="%%c Release" /p:Platform=%p_platform% /P:RunCodeAnalysisOnce=True

        title DVL %%d: %%c %p_platform% full=%do_full_sdv% target dvl
        msbuild /p:Configuration="%%c Release" /p:Platform=%p_platform% /target:dvl

        if %%d==virtio_scsi (
            copy vtioscsi.dvl.xml ..\dvl\%%cRelease\%cp_platform%
            del vtioscsi.dvl.xml
        ) else (
            copy %%d.dvl.xml ..\dvl\%%cRelease\%cp_platform%
            del %%d.dvl.xml
        )
        cd ..
    )
)

goto end

:help
echo "msdvl.bat [[10 | 81 | 8] [full] [<driver> | all | vmdp]]"
echo   all - all platroms all drivers non-full
echo   10 - Win10
echo   81 - Win8.1
echo   8 - Win8
echo   "<driver> - [virtio_balloon | virtio_blk | virtio_net | virtio_scsi | virtio_serial | virtio_rng | pvcrash | fwcfg]"
echo   "vmdp - virtio_serial | virtio_rng | pvcrash | fwcfg"
echo   "default: 10 81 8 <driver>"
echo "Must use the full option at least once"

:end
cd %mstart_dir%
set mstart_dir=
set config_os=
set cp_platform=
set p_platform=
set do_full_sdv=
