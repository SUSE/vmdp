@echo off

if "%1"=="19" goto start
if "%1"=="22" goto start
goto help

:start
copy pvvx.sln.%1 pvvx.sln
for %%d in (pvvxbn pvvxblk pvvxnet pvvxscsi) do (
    cd %%d
    copy %%d.vcxproj.%1 %%d.vcxproj
    copy %%d.vcxproj.user.%1 %%d.vcxproj.user
    cd ..
)
goto end

:help
echo "usage: %0 <19|22>"

:end
