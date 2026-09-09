@echo off

if "%1"=="19" goto start
if "%1"=="22" goto start
if "%1"=="26" goto start
goto help

:start
copy xen.sln.%1 xen.sln
for %%d in (xenbus xenblk xennet xenscsi) do (
    cd %%d
    if exist sources.props del sources.props
    if exist packages.config del packages.config
    if exist %%d.vcxproj.filters del %%d.vcxproj.filters
    rem if exist %%d.inf del %%d.inf

    if exist sources.props.%1 copy sources.props.%1 sources.props
    if exist packages.config.%1 copy packages.config.%1 packages.config
    if exist %%d.vcxproj.filters.%1 copy %%d.vcxproj.filters.%1 %%d.vcxproj.filters
    copy %%d.vcxproj.%1 %%d.vcxproj
    copy %%d.vcxproj.user.%1 %%d.vcxproj.user
    if %%d==xennet (
        copy sources.props.%1 sources.props
    )
    cd ..
)
goto end

:help
echo "usage: %0 <19|22>"

:end
