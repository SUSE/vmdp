Windows VMDP Pvvx Drivers

The VMDP pvvx drivers combine the Virtio and Xen code into a single driver.
As such, many of the files are shared between the Virtio and Xen projects.
Run the linkpvvx.bat as administrator before building the pvvx drivers for
the first time.

linkpvvx.bat utilizes sed and must be available on the build machine.

To build drivers for Windows 2008 R2/Windows 7 and earlier, use a Window Driver
Kits build environment and run the buildpv.bat command.

To build drivers for Windows 2012/Windows 8 and newer, use a Developer Command
Prompt from Visual Studio and run msb.bat

To build for all supported Windows platforms, from a command prompt run
build_all.bat.

To build dvl files, use a Developer Command Prompt from Visual Studio and
run msdvl.bat.
