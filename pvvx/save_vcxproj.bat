@echo off

if "%1"=="19" goto start
if "%1"=="22" goto start
goto help

:start
for %%d in (pvvxbn pvvxblk pvvxnet pvvxscsi) do (
    cd %%d
        copy %%d.vcxproj %%d.vcxproj.%1
        copy %%d.vcxproj.user %%d.vcxproj.user.%1
    cd ..
)
goto end

:help
echo "usage: %0 <19|22>"

:end
