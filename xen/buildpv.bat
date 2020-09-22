echo off
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

set c_opt=

del build*.log

if "%DDK_TARGET_OS%" == "WinLH"  goto WinLH
if "%DDK_TARGET_OS%" == "Win7"   goto Win7_lable
goto supported_builds

:WinLH
copy dirs_gtxp dirs
set MP_SRC_FILES=src_files6
goto c_option

:Win7_lable
copy dirs_gtxp dirs
set MP_SRC_FILES=src_files6_rss
goto c_option

:c_option
if "%1"=="" goto buildit
if "%1"=="-c" goto set_c_option
if "%1"=="-cZ" goto set_c_option
goto help

:set_c_option
set c_opt=%1
shift

:buildit
build %c_opt%

if exist *.err (
    set errorlevel=
    grep error *.err
    if not errorlevel 1 goto end
    del *err
)

goto end

:supported_builds
echo "buildpv does not support target ddK: %DDK_TARGET_OS%"
echo "To setup a WinDDK environment do something like:"
echo "\WinDDK\7600.16385.1\bin\setenv.bat \WinDDK\7600.16385.1\ Win7 fre no_oacr"
goto end

:help
echo "syntax: buildpv [-cZ | -c]"

:end
set c_opt=
