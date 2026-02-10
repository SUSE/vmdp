@echo off

if "%1"=="19" goto start
if "%1"=="22" goto start
goto help

:start
copy pvvx.sln.%1 pvvx.sln
for %%d in (pvvxbn pvvxblk pvvxnet pvvxscsi) do (
    cd %%d
    if exist sources.props del sources.props
    if exist packages.config del packages.config
    if exist %%d.vcxproj.filters del %%d.vcxproj.filters
    rem if exist %%d.inf del %%d.inf

    if exist sources.props.%1 copy sources.props.%1 sources.props
    if exist packages.config.%1 copy packages.config.%1 packages.config
    if exist %%d.vcxproj.filters.%1 copy %%d.vcxproj.filters.%1 %%d.vcxproj.filters
    rem if exist %%d.inf.%1 copy %%d.inf.%1 %%d.inf

    copy %%d.vcxproj.%1 %%d.vcxproj
    copy %%d.vcxproj.user.%1 %%d.vcxproj.user

    cd ..
)
goto end

:help
echo "usage: %0 <19|22>"

:end
