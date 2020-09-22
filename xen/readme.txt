Windows VMDP Xen Drivers

The VMDP Xen and Virtio drivers share some common files.  Run the linkxen.bat
as administrator before building the Xen drivers for the first time.

To build drivers for Windows 2008 R2/Windows 7 and earlier, use a Window Driver
Kits build environment and run the buildpv.bat command.

To build drivers for Windows 2012/Windows 8 and newer, use a Developer Command
Prompt from Visual Studio and run msb.bat

To build for all supported Windows platforms, from a command prompt run
build_all.bat.

To build dvl files, use a Developer Command Prompt from Visual Studio and
run msdvl.bat.
