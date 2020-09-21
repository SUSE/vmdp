Windows VMDP Virtio Drivers

Run linkvirtio.bat as administrator before building for the first time.

To build the virtio_rng driver you must install the MS crypto package by
installing cpdksetup.exe and placing the files in the correct Kit directory.

To build drivers for Windows 2008 R2/Windows 7 and earlier, use a Window Driver
Kits build environment and run the buildpv.bat command.

To build for Windows 2012/Windows 8 and newer, use a Developer Command Prompt
from Visual Studio and use msb.bat to build.

To build for all supported Windows platforms, from a command prompt run
build_all.bat.

To build dvl files, use a Developer Command Prompt from Visual Studio
and use msdvl.bat.
