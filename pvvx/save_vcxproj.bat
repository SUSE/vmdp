@echo off

if "%1"=="19" goto start
if "%1"=="22" goto start
goto help

:start
copy pvvx.sln pvvx.sln.%1
for %%d in (pvvxbn pvvxblk pvvxnet pvvxscsi) do (
    cd %%d
    copy %%d.vcxproj %%d.vcxproj.%1
    copy %%d.vcxproj.user %%d.vcxproj.user.%1
    if %%d==pvvxnet (
        copy sources.props sources.props.%1
    )
    if not %1==19 (
        copy packages.config packages.config.%1
    )
    cd ..
)
goto end

:help
echo "usage: %0 <19|22>"

:end
