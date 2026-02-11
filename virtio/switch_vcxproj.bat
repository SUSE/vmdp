@echo off

if "%1"=="" goto help
if "%1"=="19" goto start
if "%1"=="22" goto start
if "%1"=="arm64" goto start
goto help

:start
copy virtio.sln.%1 virtio.sln
for %%d in (fwcfg pvcrash_notify pvvxsvc virtiofs_svc virtio_balloon virtio_blk virtio_fs virtiofs_svc virtio_net virtio_rng virtio_scsi virtio_serial) do (
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

    if "%%d%"=="virtio_rng" (
        if exist cng\um\viorngum.vcxproj.filters del cng\um\viorngum.vcxproj.filters
        if exist cng\um\packages.config del cng\um\packages.config

        if exist cng\um\packages.config.%1 copy /y cng\um\packages.config.%1 cng\um\packages.config
        copy /y cng\um\viorngum.vcxproj.%1 cng\um\viorngum.vcxproj
        copy /y cng\um\viorngum.vcxproj.user.%1 cng\um\viorngum.vcxproj.user
        if exist cng\um\viorngum.vcxproj.filters.%1 copy /y cng\um\viorngum.vcxproj.filters.%1 cng\um\viorngum.vcxproj.filters
    )

    cd ..
)
goto end

:help
echo "usage: %0 <19|22|arm64>"

:end
