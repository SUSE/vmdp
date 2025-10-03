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
    if %%d==virtio_scsi (
        copy vtioscsi.vcxproj.%1 vtioscsi.vcxproj
        copy vtioscsi.vcxproj.user.%1 vtioscsi.vcxproj.user
    ) else (
        copy %%d.vcxproj.%1 %%d.vcxproj
        copy %%d.vcxproj.user.%1 %%d.vcxproj.user
        if %%d==virtio_net (
            copy sources.props.%1 sources.props
        )
        if "%%d%"=="virtio_rng" (
            copy /y cng\um\viorngum.vcxproj.%1 cng\um\viorngum.vcxproj
            copy /y cng\um\viorngum.vcxproj.user.%1 cng\um\viorngum.vcxproj.user
        )
    )
    if not %1==19 (
        copy packages.config.%1 packages.config
    )
    cd ..
)
goto end

:help
echo "usage: %0 <19|22|arm64>"

:end
