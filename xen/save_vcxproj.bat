@echo off

if "%1"=="19" goto start
if "%1"=="22" goto start
if "%1"=="26" goto start
goto help

:start
copy xen.sln xen.sln.%1
for %%d in (xenbus xenblk xennet xenscsi) do (
    cd %%d
    if exist sources.props copy sources.props sources.props.%1
    if exist packages.config copy packages.config packages.config.%1
    if exist %%d.vcxproj.filters copy %%d.vcxproj.filters %%d.vcxproj.filters.%1
        copy %%d.vcxproj %%d.vcxproj.%1
        copy %%d.vcxproj.user %%d.vcxproj.user.%1
    cd ..
)
goto end

:help
echo "usage: %0 <19|22>"

:end
