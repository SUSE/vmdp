@echo off

set config_os=
set target_os=
set config_rd=Release
set p_platform=x64
set t_rebuild=
set should_copy=

if "%1"=="" goto build_it
if not "%4"=="" goto setup_4
if not "%3"=="" goto setup_3
if not "%2"=="" goto setup_2
if not "%1"=="" goto setup_1

:setup_4
if not %4==c goto help
set t_rebuild=/t:rebuild

:setup_3
if %3==c goto valid_3
if %3==6 goto valid_3
if %3==3 goto valid_3
goto help

:valid_3
if %3==c set t_rebuild=/t:rebuild
if %3==6 set p_platform=x64
if %3==3 set p_platform=x86

:setup_2
if %2==c goto valid_2
if %2==6 goto valid_2
if %2==3 goto valid_2
if %2==r goto valid_2
if %2==d goto valid_2
goto help

:valid_2
if %2==c set t_rebuild=/t:rebuild
if %2==6 set p_platform=x64
if %2==3 set p_platform=x86
if %2==r set config_rd=Release
if %2==d set config_rd=Debug

:setup_1
if %1==10 goto valid_1
if %1==81 goto valid_1
if %1==8 goto valid_1
if %1==7 goto valid_1
if %1==v goto valid_1
if %1==c goto valid_1
if %1==6 goto valid_1
if %1==3 goto valid_1
if %1==r goto valid_1
if %1==d goto valid_1
goto help

:valid_1
if %1==10 set config_os=Win10
if %1==10 set target_os=/p:DDK_TARGET_OS=Win10
if %1==81 set config_os=Win8.1
if %1==81 set target_os=/p:DDK_TARGET_OS=Win8.1
if %1==8 set config_os=Win8
if %1==8 set target_os=/p:DDK_TARGET_OS=Win8
if %1==7 set config_os=Win7
if %1==7 set target_os=/p:DDK_TARGET_OS=Win7
if %1==v set config_os=Vista
if %1==v set target_os=/p:DDK_TARGET_OS=WinLH
if %1==c set t_rebuild=/t:rebuild
if %1==6 set p_platform=x64
if %1==3 set p_platform=x86
if %1==r set config_rd=Release
if %1==d set config_rd=Debug


:build_it
if "%config_os%"=="" (
    set p_config="%config_rd%"
) else (
    set p_config="%config_os% %config_rd%"
)
msbuild /p:Configuration=%p_config% /p:Platform=%p_platform% %t_rebuild% %target_os%
goto end

:help
echo "msb.bat [10|8.1|8|7|v|r|d|6|3|c] [r|d|6|3|c] [6|3|c] [c]"
echo   10 - Win10
echo   81 - Win8.1
echo   8 - Win8
echo   7 - Win7
echo   v - Vista
echo   r - Release
echo   d - Debug
echo   6 - x64
echo   3 - x86
echo   c - rebuild clean
echo   default: Win8.1 Release x64

:end
set config_os=
set config_rd=
set p_platform=
set t_rebuild=
set target_os=
set should_copy=
