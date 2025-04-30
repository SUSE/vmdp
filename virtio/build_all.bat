@echo off
REM
REM SPDX-License-Identifier: BSD-2-Clause
REM
REM Copyright 2020-2023 SUSE LLC
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

REM This Batch file builds all of the windows paravirtual drivers for
REM all platforms and architectures

del *.err
del *.wrn
del *.log
set pvbuildoption=
set do_arm_build=
set vxcp_latest=

if "%1"=="13" (
    set vcxp=%1
    set setvcxp_bat=setvcxp.bat
    shift
) else if "%1"=="15" (
    set vcxp=%1
    set setvcxp_bat=setvcxp.bat
    shift
) else if "%1"=="17" (
    set vcxp=%1
    set setvcxp_bat=setvcxp.bat
    shift
) else if "%1"=="19" (
    set vcxp=%1
    set setvcxp_bat=switch_vcxproj.bat
    shift
) else if "%1"=="22" (
    set vcxp=%1
    set setvcxp_bat=switch_vcxproj.bat
    shift
) else (
    set vcxp=19
    set vcxp_latest=22
    set setvcxp_bat=switch_vcxproj.bat
)

echo[
echo Build using VS20%vcxp%

if "%1"=="-cZ" (
    set pvbuildoption=%1
    shift
)

if "%1"=="msb" (
    echo Invalid option: %1
    goto help
)

if "%1"=="xp" (
    set _WXP=WXP
    shift
)

if "%1"=="lh" (
    set _WLH=WLH
    shift
)

if "%1"=="arm" (
    set do_arm_build=%1
    shift
)

if not "%1"=="" goto help

set start_dir=%cd%
set build_dir=%cd%
set start_path=%path%
set start_username=%USERNAME%
set t_rebuild_flag=
if "%pvbuildoption%"=="-cZ" set t_rebuild_flag=c

rem If specifically specified vs2022, only build for 10-2004
if %vcxp%==22 goto biuld_vs_22

rem Build 32 bit
cd %build_dir%
for %%w in (%_WXP% %_WLH% WIN7) do (
    for %%r in (fre chk) do (
        set DDKBUILDENV=
        call \WinDDK\7600.16385.1\bin\setenv.bat \WinDDK\7600.16385.1\ %%w %%r no_oacr
        cd %build_dir%
        call buildpv.bat %pvbuildoption%
        if exist *.err goto builderr
    )
)
set path=%start_path%

rem Build 64 bit
for %%w in (%_WLH% WIN7) do (
    for %%r in (fre chk) do (
        set DDKBUILDENV=
        call \WinDDK\7600.16385.1\bin\setenv.bat \WinDDK\7600.16385.1\ %%w x64 %%r no_oacr
        cd %build_dir%
        call buildpv.bat %pvbuildoption%
        if exist *.err goto builderr
    )
)
set path=%start_path%

:vcxproj-setup
cd %start_dir%
call unsetddk.bat
cd %build_dir%
if %vcxp%==13 (
    call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\VsDevCmd.bat"
) else if %vcxp%==15 (
    call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools\VsDevCmd.bat"
) else if %vcxp%==17 (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat"
) else if %vcxp%==19 (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
) else if %vcxp%==22 (
    goto biuld_vs_22
) else (
    goto help
)

call %setvcxp_bat% %vcxp%

for %%w in (8 8.1 10) do (
    for %%r in (r d) do (
        for %%x in (3 6) do (
            title Windows %%w %%r %%x
            call msb.bat %%w %%r %%x %t_rebuild_flag%
            call msb_err.bat %%w %%r %%x
            if exist *.err goto builderr
        )
    )
)
echo Built using VS20%vcxp%

:biuld_vs_22
set path=%start_path%
cd %start_dir%
call unsetddk.bat
call unsetmsb.bat
cd %build_dir%
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"

set package_to_build=%build_dir%
for %%g in ("%package_to_build%") do set package_to_build=%%~nxg

if "%package_to_build%"=="virtio" (
    set vcxp=x64
) else (
    set vcxp=22
)
call %setvcxp_bat% %vcxp%

for %%w in (10-2004) do (
    for %%r in (r d) do (
        for %%x in (6) do (
            title Windows %%w %%r %%x
            call msb.bat %%w %%r %%x %t_rebuild_flag%
            call msb_err.bat %%w %%r %%x
            if exist *.err goto builderr
        )
    )
)

if not "%do_arm_build%"=="arm" goto end

if "%package_to_build%"=="virtio" (
    call %setvcxp_bat% arm64
    echo "building for virtio - do ARM64 as well"
    for %%w in (10-2004) do (
        for %%r in (r d) do (
            for %%x in (a) do (
                title Windows %%w %%r %%x
                call msb.bat %%w %%r %%x %t_rebuild_flag%
                call msb_err.bat %%w %%r %%x
                if exist *.err goto builderr
            )
        )
    )
    call %setvcxp_bat% x64
) else (
    echo[
    echo Building for ARM64 is not supported on %package_to_build%
)

goto end

:builderr
echo.
echo.
echo.
echo THE BUILD IS BROKEN!!  Please look for an error file in the winpvdrvs directory.
echo.
goto end

:help
echo.
echo build_all.bat builds all of the driver kit files
echo.
echo "syntax: build_all.bat [<13|15|17|19>] [-cZ] [xp] [lh] [arm]"
echo example: build_all
echo.

:end
echo[
echo Built using VS20%vcxp%
cd %start_dir%
call unsetddk.bat
call unsetmsb.bat
set USERNAME=%start_username%
set path=%start_path%
set start_username=
set start_path=
set start_dir=
set build_dir=
set DDKBUILDENV=
color f0
set prompt=$P$G
set t_rebuild_flag=
set pvbuildoption=
set vcxp=
set vcxp_latest=
set _WXP=
set _WLH=
set do_arm_build=
