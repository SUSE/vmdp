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

if exist virtio_net\virtio_ring.c del virtio_net\virtio_ring.c
if exist virtio_net\virtio_ring_packed.c del virtio_net\virtio_ring_packed.c
if exist virtio_net\virtio_pci.c del virtio_net\virtio_pci.c
if exist virtio_net\virtio_pci_legacy.c del virtio_net\virtio_pci_legacy.c
if exist virtio_net\virtio_pci_modern.c del virtio_net\virtio_pci_modern.c
if exist virtio_net\virtio_utils.c del virtio_net\virtio_utils.c

if exist virtio_scsi\virtio_ring.c del virtio_scsi\virtio_ring.c
if exist virtio_scsi\virtio_ring_packed.c del virtio_scsi\virtio_ring_packed.c
if exist virtio_scsi\virtio_pci.c del virtio_scsi\virtio_pci.c
if exist virtio_scsi\virtio_pci_legacy.c del virtio_scsi\virtio_pci_legacy.c
if exist virtio_scsi\virtio_pci_modern.c del virtio_scsi\virtio_pci_modern.c
if exist virtio_scsi\virtio_utils.c del virtio_scsi\virtio_utils.c
if exist virtio_scsi\storport_reg.c del virtio_scsi\storport_reg.c
if exist virtio_scsi\virtio_sp_common.c del virtio_scsi\virtio_sp_common.c

if exist virtio_blk\virtio_ring.c del virtio_blk\virtio_ring.c
if exist virtio_blk\virtio_ring_packed.c del virtio_blk\virtio_ring_packed.c
if exist virtio_blk\virtio_pci.c del virtio_blk\virtio_pci.c
if exist virtio_blk\virtio_pci_legacy.c del virtio_blk\virtio_pci_legacy.c
if exist virtio_blk\virtio_pci_modern.c del virtio_blk\virtio_pci_modern.c
if exist virtio_blk\virtio_utils.c del virtio_blk\virtio_utils.c
if exist virtio_blk\virtio_sp_common.c del virtio_blk\virtio_sp_common.c

if exist virtio_balloon\virtio_ring.c del virtio_balloon\virtio_ring.c
if exist virtio_balloon\virtio_ring_packed.c del virtio_balloon\virtio_ring_packed.c
if exist virtio_balloon\virtio_pci.c del virtio_balloon\virtio_pci.c
if exist virtio_balloon\virtio_pci_legacy.c del virtio_balloon\virtio_pci_legacy.c
if exist virtio_balloon\virtio_pci_modern.c del virtio_balloon\virtio_pci_modern.c
if exist virtio_balloon\virtio_pci_wdm.c del virtio_balloon\virtio_pci_wdm.c
if exist virtio_balloon\virtio_utils.c del virtio_balloon\virtio_utils.c

if exist virtio_serial\virtio_ring.c del virtio_serial\virtio_ring.c
if exist virtio_serial\virtio_ring_packed.c del virtio_serial\virtio_ring_packed.c
if exist virtio_serial\virtio_pci.c del virtio_serial\virtio_pci.c
if exist virtio_serial\virtio_pci_legacy.c del virtio_serial\virtio_pci_legacy.c
if exist virtio_serial\virtio_pci_modern.c del virtio_serial\virtio_pci_modern.c
if exist virtio_serial\virtio_pci_wdm.c del virtio_serial\virtio_pci_wdm.c
if exist virtio_serial\virtio_utils.c del virtio_serial\virtio_utils.c

if exist virtio_rng\virtio_ring.c del virtio_rng\virtio_ring.c
if exist virtio_rng\virtio_ring_packed.c del virtio_rng\virtio_ring_packed.c
if exist virtio_rng\virtio_pci.c del virtio_rng\virtio_pci.c
if exist virtio_rng\virtio_pci_legacy.c del virtio_rng\virtio_pci_legacy.c
if exist virtio_rng\virtio_pci_modern.c del virtio_rng\virtio_pci_modern.c
if exist virtio_rng\virtio_pci_wdm.c del virtio_rng\virtio_pci_wdm.c
if exist virtio_rng\virtio_utils.c del virtio_rng\virtio_utils.c

if exist pvcrash_notify\virtio_utils.c del pvcrash_notify\virtio_utils.c

if exist fwcfg\virtio_utils.c del fwcfg\virtio_utils.c


:end
set start_dir=
set start_dir=
