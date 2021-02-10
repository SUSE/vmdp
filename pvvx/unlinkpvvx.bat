@echo off
REM
REM SPDX-License-Identifier: BSD-2-Clause
REM
REM Copyright 2020-2021 SUSE LLC
REM
REM Redistribution and use in source and binary forms, with or without
REM modification, are permitted provided that the following conditions
REM are met:
REM 1. Redistributions of source code must retain the above copyright
REM    notice, this list of conditions and the following disclaimer.
REM 2. Redistributions in binary form must reproduce the above copyright
REM    notice, this list of conditions and the following disclaimer in the
REM    documentation and/or other materials provided with the distribution.
REM
REM THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
REM IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
REM OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
REM IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
REM INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
REM NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
REM DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
REM THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
REM (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
REM THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
REM

set start_dir=%cd%
cd ..
set root_dir=%cd%
cd %start_dir%

if exist build_all.bat del build_all.bat
if exist msb.bat del msb.bat
if exist unsetddk.bat del unsetddk.bat
if exist unsetmsb.bat del unsetmsb.bat

if exist pvvxbn\balloon.c del pvvxbn\balloon.c
if exist pvvxbn\evtchn.c del pvvxbn\evtchn.c
if exist pvvxbn\gnttab.c del pvvxbn\gnttab.c
if exist pvvxbn\pdofunc.c del pvvxbn\pdofunc.c
if exist pvvxbn\pnp.c del pvvxbn\pnp.c
if exist pvvxbn\power.c del pvvxbn\power.c
if exist pvvxbn\xenbus.c del pvvxbn\xenbus.c
if exist pvvxbn\xenbus_client.c del pvvxbn\xenbus_client.c
if exist pvvxbn\xenbus_comms.c del pvvxbn\xenbus_comms.c
if exist pvvxbn\xenbus_probe.c del pvvxbn\xenbus_probe.c
if exist pvvxbn\xenbus_xs.c del pvvxbn\xenbus_xs.c
if exist pvvxbn\xen_support.c del pvvxbn\xen_support.c
if exist pvvxbn\xenbus_ioctl.c del pvvxbn\xenbus_ioctl.c
if exist pvvxbn\i386\xenbus_glu32.asm del pvvxbn\i386\xenbus_glu32.asm
if exist pvvxbn\amd64\xenbus_glu64.asm del pvvxbn\amd64\xenbus_glu64.asm
if exist pvvxbn\virtio_balloon.c del pvvxbn\virtio_balloon.c
if exist pvvxbn\virtio_blndrv.c del pvvxbn\virtio_blndrv.c
if exist pvvxbn\virtio_blnpwr.c del pvvxbn\virtio_blnpwr.c
if exist pvvxbn\virtio_pci.c del pvvxbn\virtio_pci.c
if exist pvvxbn\virtio_pci_modern.c del pvvxbn\virtio_pci_modern.c
if exist pvvxbn\virtio_pci_wdm.c del pvvxbn\virtio_pci_wdm.c
if exist pvvxbn\virtio_pci_legacy.c del pvvxbn\virtio_pci_legacy.c
if exist pvvxbn\virtio_ring.c del pvvxbn\virtio_ring.c
if exist pvvxbn\virtio_ring_packed.c del pvvxbn\virtio_ring_packed.c
if exist pvvxbn\virtio_utils.c del pvvxbn\virtio_utils.c
if exist pvvxbn\pvvxbn_x86.def del pvvxbn\pvvxbn_x86.def
if exist pvvxbn\pvvxbn_x64.def del pvvxbn\pvvxbn_x64.def

if exist pvvxblk\xenblk.c del pvvxblk\xenblk.c
if exist pvvxblk\xenblkfront.c del pvvxblk\xenblkfront.c
if exist pvvxblk\virtio_blk.c del pvvxblk\virtio_blk.c
if exist pvvxblk\virtio_blkfront.c del pvvxblk\virtio_blkfront.c
if exist pvvxblk\virtio_pci.c del pvvxblk\virtio_pci.c
if exist pvvxblk\virtio_pci_modern.c del pvvxblk\virtio_pci_modern.c
if exist pvvxblk\virtio_pci_legacy.c del pvvxblk\virtio_pci_legacy.c
if exist pvvxblk\virtio_ring.c del pvvxblk\virtio_ring.c
if exist pvvxblk\virtio_ring_packed.c del pvvxblk\virtio_ring_packed.c
if exist pvvxblk\hypervsr_is.c del pvvxblk\hypervsr_is.c
if exist pvvxblk\xenbus_apis.c del pvvxblk\xenbus_apis.c
if exist pvvxblk\storport_reg.c del pvvxblk\storport_reg.c
if exist pvvxblk\vxsb_entry.c del pvvxblk\vxsb_entry.c
if exist pvvxblk\virtio_sp_common.c del pvvxblk\virtio_sp_common.c

if exist pvvxscsi\xenscsi.c del pvvxscsi\xenscsi.c
if exist pvvxscsi\xenscsi_front.c del pvvxscsi\xenscsi_front.c
if exist pvvxscsi\virtio_scsi.c del pvvxscsi\virtio_scsi.c
if exist pvvxscsi\virtio_scsi_front.c del pvvxscsi\virtio_scsi_front.c
if exist pvvxscsi\virtio_pci.c del pvvxscsi\virtio_pci.c
if exist pvvxscsi\virtio_pci_modern.c del pvvxscsi\virtio_pci_modern.c
if exist pvvxscsi\virtio_pci_legacy.c del pvvxscsi\virtio_pci_legacy.c
if exist pvvxscsi\virtio_ring.c del pvvxscsi\virtio_ring.c
if exist pvvxscsi\virtio_ring_packed.c del pvvxscsi\virtio_ring_packed.c
if exist pvvxscsi\hypervsr_is.c del pvvxscsi\hypervsr_is.c
if exist pvvxscsi\xenbus_apis.c del pvvxscsi\xenbus_apis.c
if exist pvvxscsi\storport_reg.c del pvvxscsi\storport_reg.c
if exist pvvxscsi\vxsb_entry.c del pvvxscsi\vxsb_entry.c
if exist pvvxscsi\virtio_sp_common.c del pvvxscsi\virtio_sp_common.c

if exist pvvxnet\miniport.c del pvvxnet\miniport.c
if exist pvvxnet\mp_main5.c del pvvxnet\mp_main5.c
if exist pvvxnet\mp_main6.c del pvvxnet\mp_main6.c
if exist pvvxnet\mp_init5.c del pvvxnet\mp_init5.c
if exist pvvxnet\mp_init6.c del pvvxnet\mp_init6.c
if exist pvvxnet\mp_nic5.c del pvvxnet\mp_nic5.c
if exist pvvxnet\mp_nic6.c del pvvxnet\mp_nic6.c
if exist pvvxnet\init.c del pvvxnet\init.c
if exist pvvxnet\oid.c del pvvxnet\oid.c
if exist pvvxnet\mp_utils.c del pvvxnet\mp_utils.c
if exist pvvxnet\mp_xutils.c del pvvxnet\mp_xutils.c
if exist pvvxnet\mp_xinterface.c del pvvxnet\mp_xinterface.c
if exist pvvxnet\mp_vnic5.c del pvvxnet\mp_vnic5.c
if exist pvvxnet\mp_vnic6.c del pvvxnet\mp_vnic6.c
if exist pvvxnet\mp_vutils.c del pvvxnet\mp_vutils.c
if exist pvvxnet\mp_vinterface.c del pvvxnet\mp_vinterface.c
if exist pvvxnet\virtio_ring.c del pvvxnet\virtio_ring.c
if exist pvvxnet\virtio_ring_packed.c del pvvxnet\virtio_ring_packed.c
if exist pvvxnet\virtio_pci.c del pvvxnet\virtio_pci.c
if exist pvvxnet\virtio_pci_modern.c del pvvxnet\virtio_pci_modern.c
if exist pvvxnet\virtio_pci_legacy.c del pvvxnet\virtio_pci_legacy.c
if exist pvvxnet\virtio_utils.c del pvvxnet\virtio_utils.c
if exist pvvxnet\xenbus_apis.c del pvvxnet\xenbus_apis.c
if exist pvvxnet\hypervsr_is.c del pvvxnet\hypervsr_is.c
if exist pvvxnet\mp_rss.c del pvvxnet\mp_rss.c
:end
set start_dir=
set root_dir=
