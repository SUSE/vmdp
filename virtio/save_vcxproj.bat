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
    if exist sources.props copy sources.props sources.props.%1
    if exist packages.config copy packages.config packages.config.%1
    if exist %%d.vcxproj.filters copy %%d.vcxproj.filters %%d.vcxproj.filters.%1
    rem if exist %%d.inf copy %%d.inf %%d.inf.%1

    copy %%d.vcxproj %%d.vcxproj.%1
    copy %%d.vcxproj.user %%d.vcxproj.user.%1
    if "%%d%"=="virtio_rng" (
        copy /y cng\um\viorngum.vcxproj cng\um\viorngum.vcxproj.%1
        copy /y cng\um\viorngum.vcxproj.user cng\um\viorngum.vcxproj.user.%1
        if exist cng\um\viorngum.vcxproj.filters copy /y cng\um\viorngum.vcxproj.filters cng\um\viorngum.vcxproj.filters.%1
    )
    cd ..
)
goto end

:help
echo "usage: %0 <19|22|arm64>"

:end
