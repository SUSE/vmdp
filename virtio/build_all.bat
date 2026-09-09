@echo off
REM
REM SPDX-License-Identifier: BSD-2-Clause
REM
REM Copyright 2020-2026 SUSE LLC
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

setlocal EnableDelayedExpansion

del *.err
del *.wrn
del *.log
set pvbuildoption=
set do_arm_build=
set vxcp_latest=
set vcxp=19
set _WXP=
set _WLH=
set _WIN7=
set setvcxp_bat=switch_vcxproj.bat

:parse_params
if "%1"=="" (
    goto after_parse
) else if "%1"=="13" (
    set vcxp=%1
    set setvcxp_bat=setvcxp.bat
) else if "%1"=="15" (
    set vcxp=%1
    set setvcxp_bat=setvcxp.bat
) else if "%1"=="17" (
    set vcxp=%1
    set setvcxp_bat=setvcxp.bat
) else if "%1"=="19" (
    set vcxp=%1
    set setvcxp_bat=switch_vcxproj.bat
) else if "%1"=="22" (
    set vcxp=%1
    set setvcxp_bat=switch_vcxproj.bat
) else if "%1"=="26" (
    set vcxp=%1
    set setvcxp_bat=switch_vcxproj.bat
) else if "%1"=="-cZ" (
    set pvbuildoption=%1
) else if "%1"=="xp" (
    set _WXP=WXP
) else if "%1"=="lh" (
    set _WLH=WLH
) else if "%1"=="win7" (
    set _WIN7=WIN7
) else if "%1"=="arm" (
    set do_arm_build=%1
) else (
    echo Unrecognized parameter: %1
    goto help
)

shift
goto parse_params

:after_parse

echo[
echo Build using VS20%vcxp%

set start_dir=%cd%
set build_dir=%cd%
set start_path=%path%
set t_rebuild_flag=
if "%pvbuildoption%"=="-cZ" set t_rebuild_flag=c

rem If specifically specified vs2022 or greater, only build for 11
if %vcxp%==22 goto setup_vs_gte22
if %vcxp%==26 goto setup_vs_gte22

rem Build 32 bit
cd %build_dir%
for %%w in (%_WXP% %_WLH% %_WIN7%) do (
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
for %%w in (%_WLH% %_WIN7%) do (
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
    goto setup_vs_gte22
) else if %vcxp%==26 (
    goto setup_vs_gte22
) else (
    echo Unknown vs version
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
echo Finished building with VS20%vcxp%
echo[

rem reset vcxp to 26 from 19 because 22 was not specified.
set vcxp=26

rem ********************** Win11 builds ************************
:setup_vs_gte22
set path=%start_path%
set msb_arch=6
cd %start_dir%
call unsetddk.bat
call unsetmsb.bat
cd %build_dir%

set package_to_build=%build_dir%
for %%g in ("%package_to_build%") do set package_to_build=%%~nxg

echo.
if %vcxp%==26 goto build_vs_26

:build_vs_22
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
goto build_vs_gte22

:build_vs_26
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
goto build_vs_gte22

:build_vs_gte22
if "%do_arm_build%"=="arm" (
    if "not %package_to_build%"=="virtio" (
        echo[
        echo Building for ARM64 is not supported on %package_to_build%
        goto end
    )
    set msb_arch=!msb_arch! a
)

for %%x in (!msb_arch!) do (
    echo Build using VS20!vcxp! %%x
    if %%x==6 (
        call %setvcxp_bat% %vcxp%
    ) else (
        call %setvcxp_bat% %vcxp%arm64
    )
    for %%w in (11) do (
        for %%r in (r d) do (
            title Windows %%w %%r %%x
            call msb.bat %%w %%r %%x %t_rebuild_flag%
            call msb_err.bat %%w %%r %%x
            if exist *.err goto builderr
        )
    )
    echo Finished building with VS20!vcxp! %%x
    echo[
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
echo "syntax: build_all.bat [<13|15|17|19|22|26>] [-cZ] [xp] [lh] [win7] [arm]"
echo example: build_all
echo.

:end
echo[
cd %start_dir%
call unsetddk.bat
call unsetmsb.bat
set path=%start_path%
set start_path=
set start_dir=
set build_dir=
set DDKBUILDENV=
color f0
set prompt=$P$G
set t_rebuild_flag=
set pvbuildoption=
set vcxp=
set _WXP=
set _WLH=
set _WIN7=
set do_arm_build=
