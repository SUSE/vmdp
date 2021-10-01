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

REM This Batch file builds all of the windows paravirtual drivers for
REM all platforms and architectures

del *.err
del *.wrn
del *.log
set pvbuildoption=

if "%1"=="13" (
    set vcxp=%1
    call setvcxp %vcxp%
    shift
) else if "%1"=="15" (
    set vcxp=%1
    call setvcxp %vcxp%
    shift
) else if "%1"=="17" (
    set vcxp=%1
    call setvcxp %vcxp%
    shift
) else if "%1"=="19" (
    set vcxp=%1
    call setvcxp %vcxp%
    shift
) else (
    set vcxp=19
)

echo[
echo Build using VS20%vcxp%

if "%1"=="-cZ" (
    set pvbuildoption=%1
    shift
)

if not "%1"=="" goto help

set start_dir=%cd%
set build_dir=%cd%
set start_path=%path%
set start_username=%USERNAME%

rem Build 32 bit
cd %build_dir%
for %%w in (WLH WIN7) do (
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
for %%w in (WLH WIN7) do (
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
) else (
goto help
)
call loadmsbenv.bat
set t_rebuild_flag=
if "%pvbuildoption%"=="-cZ" set t_rebuild_flag=c

for %%w in (8 8.1 10 10-2004) do (
    for %%r in (r d) do (
        for %%x in (3 6) do (
            title Windows %%w %%r %%x
            call msb.bat %%w %%r %%x %t_rebuild_flag%
            call msb_err.bat %%w %%r %%x
            if exist *.err goto builderr
        )
    )
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
echo "syntax: build_all.bat [<13|15|17|19>] [-cZ]"
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
