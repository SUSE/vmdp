@echo off

if "%1"=="19" goto start
if "%1"=="22" goto start
goto help

:start
copy xen.sln.%1 xen.sln
for %%d in (xenbus xenblk xennet xenscsi) do (
    cd %%d
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
