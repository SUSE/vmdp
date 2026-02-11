The vmdp project (Virtual Machine Driver Pack) for Windows provides para-virtual drivers for Windows VMs running on KVM and Xen hypervisors.

Drivers can be built to run on Virtio devices, Xen devices, or built as a combined driver to run on either Virtio or Xen devices.  The combined drivers use the prefix pvvx (para virtual virtio xen).

The provided build scripts allows drivers to be build for Windows Server 2008 through Windows Server 2019.  To build for Windows Server 2008 and Windows Server 2008 R2, the old WinDDK/build is used.  To build Windows Server 2012 through Windows Server 2019, Visual Studio Community/msbuild and the corresponding DDK are used.  These environments will need to be downloaded and installed.

To build the drivers:
- Branch/clone the vmdp repo.
- For pvvx, as administrator, run minlinkpvvx.bat in the pvvx directory.  This gives access to shared files used by pvvx.
- If using the old "sources" and build.exe, in each of the virtio, xen, and pvvx directories, from an administrator command prompt, run linkvirtio.bat, linkxen.bat, and linkpvvx.bat respectively.  Vmdp takes advantage of shared code that is common between virtio and xen.  Linking the files facilitates this sharing.  Files are linked due to the limitation that the old "sources" build file requires all source files to be in the same directory.
- When building with VS2022, install the DDK via NuGet.  This allows building with VS2019 and VS2022 to co-exist.
- The build_all.bat will build all drivers for all supported versions of Windows Server.  build_all.bat is a link in xen and pvvx.

More information for each of virtio, xen, and pvvx can be found in their respective directories readme files.
