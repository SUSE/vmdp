@echo off

if "%1"=="" goto help
rem if "%1"=="19" goto start
rem if "%1"=="22" goto start
rem if "%1"=="arm64" goto start
rem goto help

:start
copy virtio.sln virtio.sln.%1
for %%d in (fwcfg pvcrash_notify pvvxsvc virtiofs_svc virtio_balloon virtio_blk virtio_fs virtiofs_svc virtio_net virtio_rng virtio_scsi virtio_serial) do (
    cd %%d
    if %%d==virtio_scsi (
        copy vtioscsi.vcxproj vtioscsi.vcxproj.%1
        copy vtioscsi.vcxproj.user vtioscsi.vcxproj.user.%1
    ) else (
        copy %%d.vcxproj %%d.vcxproj.%1
        copy %%d.vcxproj.user %%d.vcxproj.user.%1
        if "%%d%"=="virtio_rng" (
            copy /y cng\um\viorngum.vcxproj cng\um\viorngum.vcxproj.%1
            copy /y cng\um\viorngum.vcxproj.user cng\um\viorngum.vcxproj.user.%1
        )
    )
    if not %1==19 (
        copy packages.config packages.config.%1
    )
    cd ..
)
goto end

:help
echo "usage: %0 <19|22|arm64>"

:end
