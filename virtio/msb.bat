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

set config_os=Win11
set target_os=Win11
set config_rd=Release
set p_platform=x64
set t_rebuild=
set sln=

:parse_params
if "%1"=="" goto build_it

if %1==11 (
    set config_os=Win11
    set target_os=Win11
) else if %1==10 (
    set config_os=Win10
    set target_os=Win10
) else if %1==8.1 (
    set config_os=Win8.1
    set target_os=Win8.1
) else if %1==8 (
    set config_os=Win8
    set target_os=Win8
) else if %1==g (
    set config_os=generic
    set target_os=generic
) else if %1==c (
    set t_rebuild=rebuild
) else if %1==6 (
    set p_platform=x64
) else if %1==3 (
    set p_platform=x86
    rem set p_platform=Win32
) else if %1==a (
    set p_platform=ARM64
) else if %1==r (
    set config_rd=Release
) else if %1==d (
    set config_rd=Debug
) else (
    if "%sln%"=="" (
        rem Anything we don't understand we assume is the solution.
        rem If sln is already set then we saw two things we don't understand.
        set sln=%1
    ) else (
        goto help
    )
)
shift
goto parse_params

:build_it

if "%config_os%"=="generic" (
    set msb_config="%config_rd%"
    set ddk_target_os=
) else (
    set msb_config="%config_os%%config_rd%"
    set ddk_target_os=/p:DDK_TARGET_OS="%target_os%"
)

title VS20%vcxp% msbuild %t_rebuild% %config_os% %p_platform% %config_rd% %cd%
if "%t_rebuild%"=="" goto normal_build
    echo msbuild %sln% /p:Configuration=%msb_config% /p:Platform=%p_platform% /t:%t_rebuild% %ddk_target_os%
    msbuild %sln% /p:Configuration=%msb_config% /p:Platform=%p_platform% /t:%t_rebuild% %ddk_target_os%
goto end

:normal_build
echo msbuild %sln% /p:Configuration=%msb_config% /p:Platform=%p_platform% %ddk_target_os%
msbuild %sln% /p:Configuration=%msb_config% /p:Platform=%p_platform% %ddk_target_os%
goto end

:help
echo "msb.bat [<sln>] [11|10|8.1|8|g] [r|d] [6|3|a] [c]"
echo   11 - Win11
echo   10 - Win10
echo   8.1 - Win8.1
echo   8 - Win8
echo   g - architecture generic build
echo   r - Release
echo   d - Debug
echo   6 - x64
echo   3 - x86
echo   a - ARM64
echo   c - rebuild clean
echo   default: Win11 Release x64

:end
set config_os=
set config_rd=
set p_platform=
set t_rebuild=
set target_os=
set msb_config=
set ddk_target_os=
