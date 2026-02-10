@echo off

if "%1"=="" goto help
rem if "%1"=="19" goto start
rem if "%1"=="22" goto start
rem goto help

:start
copy pvvx.sln pvvx.sln.%1
for %%d in (pvvxbn pvvxblk pvvxnet pvvxscsi) do (
    cd %%d
    if exist sources.props copy sources.props sources.props.%1
    if exist packages.config copy packages.config packages.config.%1
    if exist %%d.vcxproj.filters copy %%d.vcxproj.filters %%d.vcxproj.filters.%1
    rem if exist %%d.inf copy %%d.inf %%d.inf.%1

    copy %%d.vcxproj %%d.vcxproj.%1
    copy %%d.vcxproj.user %%d.vcxproj.user.%1

    cd ..
)
goto end

:help
echo "usage: %0 <19|22>"

:end
