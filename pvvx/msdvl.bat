@echo off
REM
REM SPDX-License-Identifier: BSD-2-Clause
REM
REM Copyright 2020-2025 SUSE LLC
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

REM Must run from the \vmdp\pvvx dir

set mstart_dir=%cd%
set p_platform=x64
set cp_platform=x64
set do_full_sdv=no
set config_os=
set dvl_drv=

if "%1"=="" goto help

:l_loop
if %1==11 (
    set config_os=%config_os% Win11Release
) else if %1==10 (
    set config_os=%config_os% Win10Release
) else if %1==8.1 (
    set config_os=%config_os% Win8.1Release
) else if %1==8 (
    set config_os=%config_os% Win8Release
) else if %1==full (
    set do_full_sdv=yes
) else if %1==pvvxbn (
    set dvl_drv=%dvl_drv% pvvxbn
) else if %1==pvvxblk (
    set dvl_drv=%dvl_drv% pvvxblk
) else if %1==pvvxnet (
    set dvl_drv=%dvl_drv% pvvxnet
) else if %1==pvvxscsi (
    set dvl_drv=%dvl_drv% pvvxscsi
) else if %1==all (
    if "%dvl_drv%"=="" (
        set dvl_drv=pvvxbn pvvxblk pvvxnet pvvxscsi
    ) else (
        echo "Specify a driver(s) or all but not both."
        goto help
    )
) else (
    echo Unknown paramtere: %1
    goto help
)
shift
if not "%1"=="" goto l_loop

if "%dvl_drv%"=="" goto help
if "%config_os%"=="" set config_os=Win11Release Win10Release Win8.1Release Win8Release

if not exist dvl mkdir dvl

for %%c in (%config_os%) do (
    if %%c==Win11Release (
        if not %switched==22 (
            call switch_vcxproj.bat 22
            set switched=22
        )
    ) else (
        if not %switched==19 (
            call switch_vcxproj.bat 19
            set switched=19
        )
    )
    if not exist dvl\%%c mkdir dvl\%%c
    if not exist dvl\%%c\%cp_platform% mkdir dvl\%%c\%cp_platform%
    for %%d in (%dvl_drv%) do (
        cd %%d
        if not %%d==pvvxbn (
            if not exist pvvxbn\%%c\%cp_platform% mkdir pvvxbn\%%c\%cp_platform%
            copy ..\pvvxbn\%%c\%cp_platform%\pvvxbn.lib pvvxbn\%%c\%cp_platform%
        )

        rmdir /s /q c:\codeql-home\databases\%%d
        del /s c:\codeql-home\databases\%%d.sarif

        title DVL %%d: %%c create database
        c:\codeql-home\codeql\codeql.cmd database create -l=cpp -s=%mstart_dir%\%%d -c "msbuild /t:rebuild "%mstart_dir%\%%d\%%d.vcxproj" /p:Configuration=%%c /p:Platform=x64 /p:UseSharedCompilation=false" "C:\codeql-home\databases\%%d" -j 0

        title DVL %%d: %%c analyze database
        if %%c==Win11Release (
            c:\codeql-home\codeql\codeql.cmd database analyze "C:\codeql-home\databases\%%d" recommended.qls --format=sarifv2.1.0 --output=C:\codeql-home\databases\%%d.sarif -j 0
        ) else (

            c:\codeql-home\codeql\codeql.cmd database analyze "C:\codeql-home\databases\%%d" windows_driver_recommended.qls --format=sarifv2.1.0 --output=C:\codeql-home\databases\%%d.sarif -j 0
        )

        copy /y C:\codeql-home\databases\%%d.sarif

        title DVL %%d: %%c %p_platform% full=%do_full_sdv% clean
        msbuild /p:Configuration=%%c /p:Platform=%p_platform% /target:clean

        if %do_full_sdv%==yes (
            title DVL %%d: %%c %p_platform% full=%do_full_sdv% sdv clean
            msbuild /p:Configuration=%%c /p:Platform=%p_platform% /target:sdv /p:inputs="/clean"

            title DVL %%d: %%c %p_platform% full=%do_full_sdv% sdv check default.sdv
            msbuild /p:Configuration=%%c /p:Platform=%p_platform% /target:sdv /p:inputs="/check:default.sdv"

            del smvbuild.log
            del smvstats.txt
        )

        title DVL %%d: %%c %p_platform% full=%do_full_sdv% run code analysis once
        msbuild /p:Configuration=%%c /p:Platform=%p_platform% /P:RunCodeAnalysisOnce=True

        title DVL %%d: %%c %p_platform% full=%do_full_sdv% target dvl
        msbuild /p:Configuration=%%c /p:Platform=%p_platform% /target:dvl

        copy /y %%d.dvl.xml ..\dvl\%%c\%cp_platform%
        del %%d.dvl.xml
        if not %%d==pvvxbn del pvvxbn\%%c\%cp_platform%\pvvxbn.lib
        cd ..
    )
)

goto end

:help
echo "msdvl.bat [all | [[11 | 10 | 8.1 | 8] [full] <driver>]"
echo   all - all platforms all drivers non-full
echo   10 - Win10
echo   8.1 - Win8.1
echo   8 - Win8
echo   "<driver> - [pvvxbus | pvvxblk | pvvxnet | pvvxscsi]"
echo   "default: 11 10 8.1 8 <driver>"
echo "Must use the full option at least once"

:end
cd %mstart_dir%
set mstart_dir=
set config_os=
set dvl_drv=
set cp_platform=
set p_platform=
set do_full_sdv=
set switched=
