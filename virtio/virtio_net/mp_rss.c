/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2019-2020 SUSE LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ndis.h>
#include "miniport.h"

NDIS_RECEIVE_SCALE_CAPABILITIES *
vnif_rss_set_generall_attributes(PVNIF_ADAPTER adapter,
    NDIS_RECEIVE_SCALE_CAPABILITIES *rss_caps)
{
    if (adapter->b_multi_queue == FALSE || adapter->b_rss_supported == FALSE) {
        return NULL;
    }
#if (NDIS_SUPPORT_NDIS630)
    RPRINTK(DPRTL_ON, ("%s NDIS_SUPPORT_NDIS630\n", __func__));
    rss_caps->Header.Revision = NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_2;
    rss_caps->Header.Size = NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_2;
    rss_caps->NumberOfIndirectionTableEntries =
        NDIS_RSS_INDIRECTION_TABLE_MAX_SIZE_REVISION_2
            / sizeof(PROCESSOR_NUMBER);
#else
    rss_caps->Header.Revision = NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_1;
    rss_caps->Header.Size = NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_1;
#endif

    rss_caps->Header.Type = NDIS_OBJECT_TYPE_RSS_CAPABILITIES;
    rss_caps->CapabilitiesFlags = NDIS_RSS_CAPS_MESSAGE_SIGNALED_INTERRUPTS
        | NDIS_RSS_CAPS_CLASSIFICATION_AT_ISR
        | NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV4
        | NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6
        | NdisHashFunctionToeplitz;
    if (adapter->hw_tasks & VNIF_RSS_TCP_IPV6_EXT_HDRS_SUPPORTED) {
        rss_caps->CapabilitiesFlags |= NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6_EX;
    }
    rss_caps->NumberOfInterruptMessages = adapter->num_hw_queues;

    /* One less for the VNIF_NO_RECEIVE_QUEUE. */
    rss_caps->NumberOfReceiveQueues = adapter->num_rcv_queues - 1;
    return rss_caps;
}

static BOOLEAN
vnif_rss_alloc_cpu_idx_mapping(PVNIF_ADAPTER adapter)
{
    ULONG i;
    ULONG active_proc_cnt;

    active_proc_cnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    if (adapter->rss.cpu_idx_mapping != NULL
            && adapter->rss.cpu_idx_mapping_sz != active_proc_cnt) {
        NdisFreeMemoryWithTagPriority(adapter->AdapterHandle,
                                      adapter->rss.cpu_idx_mapping,
                                      VNIF_POOL_TAG);
        adapter->rss.cpu_idx_mapping = NULL;
        adapter->rss.cpu_idx_mapping_sz = 0;
    }

    if (adapter->rss.cpu_idx_mapping == NULL) {
        adapter->rss.cpu_idx_mapping = (PCHAR)NdisAllocateMemoryWithTagPriority(
            adapter->AdapterHandle,
            sizeof(char) * active_proc_cnt,
            VNIF_POOL_TAG,
            NormalPoolPriority);
        if (adapter->rss.cpu_idx_mapping == NULL) {
            return FALSE;
        }
        adapter->rss.cpu_idx_mapping_sz = active_proc_cnt;
    }



    for(i = 0; i < active_proc_cnt; i++) {
        adapter->rss.cpu_idx_mapping[i] = VNIF_NO_RECEIVE_QUEUE;
    }

    return TRUE;
}


static void
vnif_rss_fill_cpu_mapping(vnif_rss_t *rss, UINT num_receive_queues)
{
    PPROCESSOR_NUMBER proc_num;
    ULONG i;
    ULONG cur_proc_idx;
    CCHAR receive_q = VNIF_FIRST_RSS_RECEIVE_QUEUE;

    rss->first_q_indirection_idx = VNIF_INVALID_INDIRECTION_INDEX;
    RPRINTK(DPRTL_RSS, ("==> %s: indirection table sz %d\n",
                        __func__,
                        rss->indirection_tbl_sz / sizeof(PROCESSOR_NUMBER)));

    for (i = 0;
         i < rss->indirection_tbl_sz / sizeof(PROCESSOR_NUMBER);
         i++) {
        proc_num = &rss->indirection_tbl[i];
        cur_proc_idx = KeGetProcessorIndexFromNumber(proc_num);

        if (cur_proc_idx != INVALID_PROCESSOR_INDEX) {
            if (rss->cpu_idx_mapping[cur_proc_idx] == VNIF_NO_RECEIVE_QUEUE) {
                if (receive_q == VNIF_FIRST_RSS_RECEIVE_QUEUE) {
                    RPRINTK(DPRTL_INIT, ("  FirstQueueIndirectionIndex %d\n",
                                         i));
                    rss->first_q_indirection_idx = i;
                }

                if (receive_q != num_receive_queues) {
                    DPRINTK(DPRTL_RSS, ("  CPUIndexMapping[%d] %d\n",
                                         cur_proc_idx,
                                         receive_q));
                    rss->cpu_idx_mapping[cur_proc_idx] = receive_q++;
                }
            }

            if (i < rss->cpu_idx_mapping_sz) {
              RPRINTK(DPRTL_RSS,
                ("  q_indirection[%d] <- cpu_idx_mapping[%d] = %d pn %d g %d\n",
                i,
                cur_proc_idx,
                rss->cpu_idx_mapping[cur_proc_idx],
                proc_num->Number,
                proc_num->Group));
            }

            rss->q_indirection_tbl[i] = rss->cpu_idx_mapping[cur_proc_idx];

        }
        else {
            rss->cpu_idx_mapping[i] = VNIF_NO_RECEIVE_QUEUE;
        }
    }
    for (i = 0; i < rss->cpu_idx_mapping_sz; i++) {
        RPRINTK(DPRTL_RSS,
            ("  cpu_idx_mapping[%d] == %d\n",
             i,
             rss->cpu_idx_mapping[i]));
    }

    if (rss->first_q_indirection_idx == VNIF_INVALID_INDIRECTION_INDEX) {
        RPRINTK(DPRTL_RSS, ("[%s] CPU queue assignment failed!\n", __func__));
        return;
    }

    RPRINTK(DPRTL_RSS, ("%s: fill out rss->indirection_tbl[]\n", __func__));
    for (i = 0;
         i < rss->indirection_tbl_sz / sizeof(PROCESSOR_NUMBER);
         i++) {
        if (rss->q_indirection_tbl[i] == VNIF_NO_RECEIVE_QUEUE) {
            /* If some hash values remains unassigned after the first pass,
             * either because mapping processor number to index failed or
             * there are not enough queues, reassign the hash values to the
             * first queue
             */
            RPRINTK(DPRTL_RSS,
                    ("  QIndirectionTbl[%d] %d IndirectionTbl[%d] %d\n",
                     i,
                     VNIF_FIRST_RSS_RECEIVE_QUEUE,
                     i,
                     rss->indirection_tbl[rss->first_q_indirection_idx]));

            rss->q_indirection_tbl[i] = VNIF_FIRST_RSS_RECEIVE_QUEUE;
            rss->indirection_tbl[i] = rss->indirection_tbl[
                                        rss->first_q_indirection_idx];
        }
    }

    RPRINTK(DPRTL_RSS, ("<== %s\n", __func__));
}

void
vnif_rss_set_rcv_q_targets(VNIF_ADAPTER *adapter)
{
#if NDIS620_MINIPORT_SUPPORT
    PROCESSOR_NUMBER target_processor;
#endif
    UINT rcvq;
    UINT cpu_idx;

    for (cpu_idx = 0; cpu_idx < adapter->rss.cpu_idx_mapping_sz; cpu_idx++) {
        rcvq = adapter->rss.cpu_idx_mapping[cpu_idx];
        if (rcvq == VNIF_NO_RECEIVE_QUEUE) {
            RPRINTK(DPRTL_RSS,
                    ("%s: no cpu_idx_mapping for cpu_idx %d - use no_rcv_q\n",
                     __func__, cpu_idx));
            rcvq = adapter->num_rcv_queues - 1;
        }
#if NDIS620_MINIPORT_SUPPORT
        KeGetProcessorNumberFromIndex(cpu_idx, &target_processor);
        adapter->rcv_q[rcvq].rcv_processor = target_processor;
        adapter->rcv_q[rcvq].path_id = cpu_idx;
        RPRINTK(DPRTL_RSS,
                ("%s: cpu_idx_mapping[%d] = rcv_q %d on target cpu %d g %d\n",
                 __func__, cpu_idx, rcvq,
                 target_processor.Number,
                 target_processor.Group));
        KeSetTargetProcessorDpcEx(&adapter->rcv_q[rcvq].rcv_q_dpc,
                                  &target_processor);
#else
        KeSetTargetProcessorDpc(&adapter->rcv_q[i].rcv_q_dpc, (uint8_t)i);
#endif
    }
}

static NDIS_STATUS
vnif_rss_setup_q_map(PVNIF_ADAPTER adapter,
                     NDIS_RECEIVE_SCALE_PARAMETERS *rss_params)
{
    PROCESSOR_NUMBER *proc_num;
    ULONG cpu_idx;
    ULONG rss_tbl_sz;
    ULONG active_proc_cnt;
    USHORT rss_idx;
    USHORT path_idx;
    USHORT *cpu_index_tbl;

    rss_idx = 0;
    rss_tbl_sz = rss_params->IndirectionTableSize / sizeof(PROCESSOR_NUMBER);
    active_proc_cnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    RPRINTK(DPRTL_INIT, ("%s: active_proc_cnt %d\n", __func__, active_proc_cnt));

    cpu_index_tbl = (USHORT *)NdisAllocateMemoryWithTagPriority(
        adapter->AdapterHandle,
        active_proc_cnt * sizeof(*cpu_index_tbl),
        VNIF_POOL_TAG,
        NormalPoolPriority);
    if (cpu_index_tbl == NULL) {
        PRINTK(("[%s] cpu index table allocation failed\n", __func__));
        return NDIS_STATUS_RESOURCES;
    }

    for (cpu_idx = 0; cpu_idx < active_proc_cnt; cpu_idx++) {
        cpu_index_tbl[cpu_idx] = (USHORT)INVALID_PROCESSOR_INDEX;
    }

    for (path_idx = 0; path_idx < adapter->num_paths; ++path_idx) {
        cpu_idx = adapter->path[path_idx].cpu_idx;
        if (cpu_idx == INVALID_PROCESSOR_INDEX) {
            PRINTK(("[%s]  Invalid CPU index for path %u\n",
                    __func__, path_idx));
            NdisFreeMemoryWithTagPriority(adapter->AdapterHandle,
                                          cpu_index_tbl,
                                          VNIF_POOL_TAG);
            return NDIS_STATUS_SOFT_ERRORS;
        }
        else if (cpu_idx >= active_proc_cnt) {
            PRINTK(("[%s]  CPU index %lu exceeds CPU range %lu\n",
                    __func__, cpu_idx, active_proc_cnt));
            NdisFreeMemoryWithTagPriority(adapter->AdapterHandle,
                                          cpu_index_tbl,
                                          VNIF_POOL_TAG);
            return NDIS_STATUS_SOFT_ERRORS;
        }
        else {
            RPRINTK(DPRTL_INIT, ("  cpu_index_tbl[cpu_idx %d] = path_idx %d\n",
                cpu_idx, path_idx));
            cpu_index_tbl[cpu_idx] = path_idx;
        }
    }

    for (cpu_idx = 0; cpu_idx < active_proc_cnt; cpu_idx++) {
        if (cpu_index_tbl[cpu_idx] == (USHORT)INVALID_PROCESSOR_INDEX) {
            cpu_index_tbl[cpu_idx] = (USHORT)(cpu_idx % adapter->num_paths);
        }
    }

    if (adapter->rss.rss2_queue_len
            && adapter->rss.rss2_queue_len < rss_tbl_sz) {
        RPRINTK(DPRTL_INIT, ("[%s] Freeing RSS2Queue Map\n", __func__));
        NdisFreeMemoryWithTagPriority(adapter->AdapterHandle,
                                      adapter->rss.rss2_queue_map,
                                      VNIF_POOL_TAG);
        adapter->rss.rss2_queue_len = 0;
    }

    if (adapter->rss.rss2_queue_len == 0) {
        adapter->rss.rss2_queue_len = rss_tbl_sz;
        adapter->rss.rss2_queue_map = (USHORT *)
            NdisAllocateMemoryWithTagPriority(adapter->AdapterHandle,
                rss_tbl_sz * sizeof(*adapter->rss.rss2_queue_map),
                VNIF_POOL_TAG,
                NormalPoolPriority);
        if (adapter->rss.rss2_queue_map == NULL) {
            PRINTK(("[%s] - Allocating RSS to queue mapping failed\n",
                    __func__));
            NdisFreeMemoryWithTagPriority(adapter->AdapterHandle,
                                          cpu_index_tbl,
                                          VNIF_POOL_TAG);
            return NDIS_STATUS_RESOURCES;
        }

        NdisZeroMemory(adapter->rss.rss2_queue_map,
                       sizeof(*adapter->rss.rss2_queue_map)
                        * adapter->rss.rss2_queue_len);
    }

    proc_num = (PROCESSOR_NUMBER *)
        ((char *)rss_params + rss_params->IndirectionTableOffset);
    for (rss_idx = 0; rss_idx < rss_tbl_sz; rss_idx++) {
        cpu_idx = NdisProcessorNumberToIndex(proc_num[rss_idx]);
        adapter->rss.rss2_queue_map[rss_idx] = cpu_index_tbl[cpu_idx];

        DPRINTK(DPRTL_RSS,
                ("  rss2_queue_map[%d] for cpu %d = path %d, p %d/%d a %d/%d\n",
                 rss_idx, cpu_idx, cpu_index_tbl[cpu_idx],
                 proc_num[rss_idx].Number,
                 proc_num[rss_idx].Group,
                 adapter->path[cpu_index_tbl[cpu_idx]].dpc_affinity.Mask,
                 adapter->path[cpu_index_tbl[cpu_idx]].dpc_affinity.Group));
    }

    NdisFreeMemoryWithTagPriority(adapter->AdapterHandle,
                                  cpu_index_tbl,
                                  VNIF_POOL_TAG);
    return NDIS_STATUS_SUCCESS;
}

static BOOLEAN
vnif_rss_is_valid_hash_info(PVNIF_ADAPTER adapter, ULONG hash_info)
{
    ULONG hash_type;
    ULONG hash_func;
    ULONG supported_types;

    if (hash_info == 0) {
        return TRUE;
    }

    hash_type = NDIS_RSS_HASH_TYPE_FROM_HASH_INFO(hash_info);
    hash_func = NDIS_RSS_HASH_FUNC_FROM_HASH_INFO(hash_info);

    supported_types = NDIS_HASH_IPV4
        | NDIS_HASH_TCP_IPV4
        | NDIS_HASH_IPV6
        | NDIS_HASH_TCP_IPV6;

    if (adapter->hw_tasks & VNIF_RSS_TCP_IPV6_EXT_HDRS_SUPPORTED) {
        supported_types |= NDIS_HASH_IPV6_EX
                        |  NDIS_HASH_TCP_IPV6_EX;
    }

    if ((hash_type & supported_types) && !(hash_type & ~supported_types)) {
        return hash_func == NdisHashFunctionToeplitz;
    }

    return FALSE;
}

static void
vnif_rss_move_rx(PVNIF_ADAPTER adapter)
{
    RCB *rcb;
    UINT no_q_idx;
    UINT i;
    UINT j;

    if (adapter->num_rcv_queues == 1) {
        return;
    }
    no_q_idx = adapter->num_rcv_queues - 1;
    NdisAcquireSpinLock(&adapter->rcv_q[no_q_idx].rcv_to_process_lock);
    for (i = 0; i < no_q_idx; i++) {
        NdisAcquireSpinLock(&adapter->rcv_q[i].rcv_to_process_lock);
        j = 0;
        while (!IsListEmpty(&adapter->rcv_q[i].rcv_to_process)) {
            RPRINTK(DPRTL_RSS, ("%s[%d]: %d ==> 0\n", __func__, i, j++));
            rcb = (RCB *) RemoveHeadList(&adapter->rcv_q[i].rcv_to_process);
            InsertTailList(&adapter->rcv_q[no_q_idx].rcv_to_process, &rcb->list);
        }
        NdisReleaseSpinLock(&adapter->rcv_q[i].rcv_to_process_lock);
    }
    NdisReleaseSpinLock(&adapter->rcv_q[no_q_idx].rcv_to_process_lock);

    KeInsertQueueDpc(&adapter->rcv_q[no_q_idx].rcv_q_dpc,
                     (void *)adapter->rcv_q[no_q_idx].path_id,
                     (void *)NDIS_INDICATE_ALL_NBLS);
}

NDIS_STATUS
vnif_rss_oid_gen_receive_scale_params(PVNIF_ADAPTER adapter,
                                      NDIS_RECEIVE_SCALE_PARAMETERS *rss_params,
                                      ULONG rss_params_len,
                                      PULONG bytes_read,
                                      PULONG bytes_needed)
{
    PROCESSOR_NUMBER *proc_num;
    NDIS_STATUS status;
    ULONG proc_mask_size;
    UINT i;
    UINT j;

    if (adapter->b_rss_supported == FALSE) {
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    RPRINTK(DPRTL_INIT, ("%s: %s\n", __func__, adapter->node_name));
    if (rss_params_len < sizeof(NDIS_RECEIVE_SCALE_PARAMETERS)) {
        *bytes_needed = sizeof(NDIS_RECEIVE_SCALE_PARAMETERS);
        RPRINTK(DPRTL_CONFIG, ("\ttoo small %x.\n", rss_params_len));
        return NDIS_STATUS_INVALID_LENGTH;
    }

    if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_HASH_INFO_UNCHANGED)
        && !vnif_rss_is_valid_hash_info(adapter, rss_params->HashInformation)) {
        RPRINTK(DPRTL_CONFIG, ("NDIS_STATUS_INVALID_PARAMETER hash info\n"));
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    *bytes_read = sizeof(NDIS_RECEIVE_SCALE_PARAMETERS);

    if (rss_params->Flags & NDIS_RSS_PARAM_FLAG_DISABLE_RSS
        || (rss_params->HashInformation == 0)) {
        RPRINTK(DPRTL_INIT, ("ApplySettings: disable\n"));
        adapter->rss.rss_mode = VNIF_RSS_DISABLED;
        return NDIS_STATUS_SUCCESS;
    }


    RPRINTK(DPRTL_INIT,
            ("  Oid RSS: IndirectionTableSize %d Entries %d offset %d\n",
             rss_params->IndirectionTableSize,
             rss_params->IndirectionTableSize /
             sizeof(PROCESSOR_NUMBER),
             rss_params->IndirectionTableOffset));
    RPRINTK(DPRTL_INIT, ("  Oid RSS: HashSecretKeySize %d offset %d\n",
                         rss_params->HashSecretKeySize,
                         rss_params->HashSecretKeyOffset));

    RPRINTK(DPRTL_INIT, ("  sizeof(NDIS_RECEIVE_SCALE_PARAMETERS) %d\n",
                         sizeof(NDIS_RECEIVE_SCALE_PARAMETERS)));
    RPRINTK(DPRTL_INIT, ("  rss_params->IndirectionTableSize %d\n",
                         rss_params->IndirectionTableSize));
    RPRINTK(DPRTL_INIT, ("  rss_params->NumberOfProcessorMasks %d size %d\n",
                         rss_params->NumberOfProcessorMasks,
                         rss_params->ProcessorMasksEntrySize));
    RPRINTK(DPRTL_INIT, ("  rss_params->HashSecretKeySize %d\n",
                         rss_params->HashSecretKeySize));

    if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_ITABLE_UNCHANGED)
            && ((rss_params->IndirectionTableSize
             > sizeof(adapter->rss.indirection_tbl))
                || (rss_params_len < (rss_params->IndirectionTableOffset
                                      + rss_params->IndirectionTableSize))
                || !IS_POWER_OF_TWO( rss_params->IndirectionTableSize
                                     / sizeof(PROCESSOR_NUMBER) ))) {
        PRINTK(("[%s] invalid length (2), flags %x\n",
                __func__, rss_params->Flags));
        return NDIS_STATUS_INVALID_LENGTH;
    }

    if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_HASH_KEY_UNCHANGED)
            && ((rss_params->HashSecretKeySize
             > sizeof(adapter->rss.hash_secret_key))
                || (rss_params_len < (rss_params->HashSecretKeyOffset
                                      + rss_params->HashSecretKeySize)))) {
        PRINTK(("[%s] invalid length (3), flags %x\n",
                __func__, rss_params->Flags));
        return NDIS_STATUS_INVALID_LENGTH;
    }

    proc_mask_size = rss_params->NumberOfProcessorMasks
        * rss_params->ProcessorMasksEntrySize;
    if (rss_params_len < rss_params->ProcessorMasksOffset + proc_mask_size) {
        PRINTK(("%s Invalid len rss_params->NumberOfProcessorMasks %d sz %d\n",
              __func__,
                rss_params->NumberOfProcessorMasks,
              rss_params->ProcessorMasksEntrySize));
        PRINTK(("[%s] invalid length (4), flags %x\n",
                __func__, rss_params->Flags));
        return NDIS_STATUS_INVALID_LENGTH;
    }


    if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_ITABLE_UNCHANGED)) {
        if (vnif_rss_alloc_cpu_idx_mapping(adapter) == FALSE) {
            PRINTK(("[%s] vnif_alloc_cpu_idx_mapping failed\n", __func__));
            return NDIS_STATUS_RESOURCES;
        }
        proc_num = (PROCESSOR_NUMBER *)
            ((char *)rss_params + rss_params->IndirectionTableOffset);

        adapter->rss.indirection_tbl_sz = rss_params->IndirectionTableSize;
        NdisMoveMemory(adapter->rss.indirection_tbl,
                       proc_num,
                       adapter->rss.indirection_tbl_sz);
        adapter->rss.hash_mask = (rss_params->IndirectionTableSize
                    / sizeof(PROCESSOR_NUMBER)) - 1;

        *bytes_read += rss_params->IndirectionTableSize
                    + proc_mask_size;
        RPRINTK(DPRTL_INIT, ("  look at rss_params IndirectionTable\n"));
        for (i = 0;
             i < adapter->rss.cpu_idx_mapping_sz &&
                i < rss_params->IndirectionTableSize / sizeof(PROCESSOR_NUMBER);
             i++) {
            RPRINTK(DPRTL_RSS, ("  IndirectionTable[%d] = pn %d g %d cidx %d\n",
                                i, proc_num[i].Number, proc_num[i].Group,
                                KeGetProcessorIndexFromNumber(&proc_num[i])));
        }
        vnif_rss_fill_cpu_mapping(&adapter->rss, adapter->num_rcv_queues - 1);
        vnif_rss_set_rcv_q_targets(adapter);
    }

    if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_HASH_INFO_UNCHANGED)) {
        adapter->rss.hash_info = rss_params->HashInformation;
        RPRINTK(DPRTL_INIT,
                ("HashInformation %x\n", rss_params->HashInformation));
    }

    if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_HASH_KEY_UNCHANGED)) {
        RPRINTK(DPRTL_INIT, ("HashSecretKeySize %d offset %d\n",
              rss_params->HashSecretKeySize,
              rss_params->HashSecretKeyOffset));

        adapter->rss.hash_secret_key_sz = rss_params->HashSecretKeySize;

        NdisMoveMemory(adapter->rss.hash_secret_key,
                       (char*)rss_params + rss_params->HashSecretKeyOffset,
                       rss_params->HashSecretKeySize);

        RPRINTK(DPRTL_RSS, ("Hash Secret Key: sz %d mask %x info %x\n",
                adapter->rss.hash_secret_key_sz,
                adapter->rss.hash_mask,
                adapter->rss.hash_info));
        i = 0;
        while (i < adapter->rss.hash_secret_key_sz) {
            j = 0;
            while (j < 10 && i < adapter->rss.hash_secret_key_sz) {
                DPRINTK(DPRTL_RSS, ("%02x ", (UINT8)adapter->rss.hash_secret_key[i]));
                i++;
                j++;
            }
            DPRINTK(DPRTL_RSS, ("\n"));
        }

        *bytes_read += rss_params->HashSecretKeySize;
    }

    RPRINTK(DPRTL_INIT, ("%s rss_params_len %d, bytes read %d\n",
                         __func__, rss_params_len, *bytes_read));
    vnif_rss_move_rx(adapter);

    status = vnif_rss_setup_q_map(adapter, rss_params);
    if (status != NDIS_STATUS_SUCCESS) {
        PRINTK(("[%s] vnif_setup_rss_q_map failed 0x%x\n", __func__, status));
        return status;
    }

    adapter->rss.rss_mode = VNIF_RSS_FULL;

    RPRINTK(DPRTL_INIT, ("[%s] sucess\n", __func__));
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
vnif_rss_setup_queue_dpc_path(PVNIF_ADAPTER adapter, UINT path_id)
{
#if NDIS620_MINIPORT_SUPPORT
    NDIS_STATUS status;
    PROCESSOR_NUMBER proc_num;
#endif

#if NDIS_SUPPORT_NDIS620
    status = KeGetProcessorNumberFromIndex(path_id, &proc_num);
    if (status != NDIS_STATUS_SUCCESS) {
        PRINTK(("[%s] - KeGetProcessorNumberFromIndex failed idx %d - %d\n",
                __func__, path_id, status));
        return status;
    }

    vnif_set_proc_num_to_group_affinity(proc_num,
        adapter->path[path_id].dpc_affinity);
    RPRINTK(DPRTL_INIT, ("[%s] path[%d] proc_num %d, group %x mask %x\n",
                         __func__, path_id, proc_num.Number,
                         adapter->path[path_id].dpc_affinity.Group,
                         adapter->path[path_id].dpc_affinity.Mask));
    adapter->path[path_id].cpu_idx = proc_num.Number;
#else
    adapter->path[path_id].dpc_target_proc = 1i64 << i;
    adapter->path[path_id].cpu_idx = path_id;
#endif

    return NDIS_STATUS_SUCCESS;
}

UINT
vnif_rss_get_rcv_qidx_for_cur_processor(PVNIF_ADAPTER adapter)
{
    ULONG cur_proc_number;

    cur_proc_number = vnif_get_current_processor(NULL);
    if (adapter->rss.rss_mode != VNIF_RSS_FULL
            || cur_proc_number >= adapter->rss.cpu_idx_mapping_sz) {
        return VNIF_NO_RECEIVE_QUEUE;
    }

    return adapter->rss.cpu_idx_mapping[cur_proc_number];
}

static uint32_t
vnif_rss_toeplitz_hash(hash_sg_entry_t *sg_buf,
                       int sg_entries,
                       uint8_t *full_key)
{

    uint32_t first_key_word;
    uint32_t res;
    UINT byte;
    UINT bit;
    hash_sg_entry_t *sg_entry;
    uint8_t *next_key_byte;

    res = 0;
    next_key_byte = full_key + sizeof(first_key_word);
    first_key_word = RtlUlongByteSwap(*(uint32_t *)full_key);

    for(sg_entry = sg_buf; sg_entry < sg_buf + sg_entries; ++sg_entry) {
        for (byte = 0; byte < sg_entry->chunkLen; ++byte) {
            for (bit = 0; bit <= TOEPLITZ_MAX_BIT_NUM; ++bit) {
                if (TOEPLITZ_BYTE_HAS_BIT(sg_entry->chunkPtr[byte], bit)) {
                    res ^= first_key_word;
                }
                first_key_word = (first_key_word << 1)
                    | TOEPLITZ_BYTE_BIT_STATE(*next_key_byte, bit);
            }
            ++next_key_byte;
        }
    }
    return res;
}


static void
vnif_rss_get_hash_info(PVNIF_ADAPTER adapter,
                       RCB *rcb,
                       ULONG *hash_type,
                       ULONG *hash_value)
{
    hash_sg_entry_t sg_buf[3];
    tcp_hdr_t *tcp_hdr;
    ipv6_header_t *ipv6_hdr;
    uint8_t *ip_hdr;
    uint8_t *pkt_buf;
    ULONG hash_types;
    UINT sg_cnt;

    hash_types = NDIS_RSS_HASH_TYPE_FROM_HASH_INFO(adapter->rss.hash_info);

    DPRINTK(DPRTL_RSS, ("hash_types %x ", hash_types));
    sg_cnt = 0;
    pkt_buf = rcb->page + adapter->buffer_offset;
    ip_hdr = pkt_buf + ETH_HEADER_SIZE;
    tcp_hdr = (tcp_hdr_t *)(ip_hdr + rcb->pkt_info.ip_hdr_len);
    if (rcb->pkt_info.ip_ver == IPV4) {
        if (rcb->pkt_info.protocol == VNIF_PACKET_TYPE_TCP
                && (hash_types & NDIS_HASH_TCP_IPV4)) {
            *hash_type = NDIS_HASH_TCP_IPV4 | (hash_types & NDIS_HASH_IPV4);
            sg_buf[0].chunkPtr = (PCHAR)&((ipv4_header_t *)ip_hdr)->ip_src;
            sg_buf[0].chunkLen = sizeof(((ipv4_header_t *)ip_hdr)->ip_src)
                               + sizeof(((ipv4_header_t *)ip_hdr)->ip_dest);
            sg_buf[1].chunkPtr = (PCHAR)&tcp_hdr->tcp_src;
            sg_buf[1].chunkLen = sizeof(tcp_hdr->tcp_src)
                               + sizeof(tcp_hdr->tcp_dest);
            sg_cnt = 2;
            DPRINTK(DPRTL_RSS, ("NDIS_HASH_TCP_IPV4 "));

        } else if (hash_types & NDIS_HASH_IPV4) {
            *hash_type = NDIS_HASH_IPV4;
            sg_buf[0].chunkPtr = (PCHAR)&((ipv4_header_t *)ip_hdr)->ip_src;
            sg_buf[0].chunkLen = sizeof(((ipv4_header_t *)ip_hdr)->ip_src)
                               + sizeof(((ipv4_header_t *)ip_hdr)->ip_dest);
            sg_cnt = 1;
            DPRINTK(DPRTL_RSS, ("NDIS_HASH_IPV4 "));
        }
    } else if (rcb->pkt_info.ip_ver == IPV6) {
        ipv6_hdr = (ipv6_header_t *)ip_hdr;
        if (rcb->pkt_info.protocol == VNIF_PACKET_TYPE_TCP) {
            if (hash_types & (NDIS_HASH_TCP_IPV6 | NDIS_HASH_TCP_IPV6_EX)) {
                *hash_type = (hash_types & (NDIS_HASH_IPV6
                                            | NDIS_HASH_IPV6_EX
                                            | NDIS_HASH_TCP_IPV6
                                            | NDIS_HASH_TCP_IPV6_EX));
                sg_buf[0].chunkPtr = (PCHAR)&ipv6_hdr->ip6_src_address;
                sg_buf[0].chunkLen = sizeof(ipv6_hdr->ip6_src_address);
                sg_buf[1].chunkPtr = (PCHAR)&ipv6_hdr->ip6_dst_address;
                sg_buf[1].chunkLen = sizeof(ipv6_hdr->ip6_dst_address);

                sg_buf[2].chunkPtr = (PCHAR)&tcp_hdr->tcp_src;
                sg_buf[2].chunkLen = sizeof(tcp_hdr->tcp_src)
                                   + sizeof(tcp_hdr->tcp_dest);
                sg_cnt = 3;
                DPRINTK(DPRTL_RSS,
                        ("NDIS_HASH_TCP_IPV6 | NDIS_HASH_TCP_IPV6_EX "));
            }
        }
        if (sg_cnt == 0 && (hash_types & NDIS_HASH_IPV6_EX)) {
            *hash_type = (hash_types & (NDIS_HASH_IPV6 | NDIS_HASH_IPV6_EX));
            sg_buf[0].chunkPtr = (PCHAR)&ipv6_hdr->ip6_src_address;
            sg_buf[0].chunkLen = sizeof(ipv6_hdr->ip6_src_address);
            sg_buf[1].chunkPtr = (PCHAR)&ipv6_hdr->ip6_dst_address;
            sg_buf[1].chunkLen = sizeof(ipv6_hdr->ip6_dst_address);
            sg_cnt = 2;
            DPRINTK(DPRTL_RSS, ("NDIS_HASH_IPV6 | NDIS_HASH_IPV6_EX) "));
        }

        if (sg_cnt == 0 && (hash_types & NDIS_HASH_IPV6)) {
            *hash_type = NDIS_HASH_IPV6;
            sg_buf[0].chunkPtr = (PCHAR)ipv6_hdr->ip6_src_address;
            sg_buf[0].chunkLen = sizeof(ipv6_hdr->ip6_src_address)
                               + sizeof(ipv6_hdr->ip6_dst_address);
            sg_cnt = 1;
            DPRINTK(DPRTL_RSS, ("NDIS_HASH_IPV6) "));
        }
    }

    if (sg_cnt != 0) {
        *hash_value = vnif_rss_toeplitz_hash(sg_buf,
                                             sg_cnt,
                                             adapter->rss.hash_secret_key);
        rcb->pkt_info.hash_type = *hash_type;
        rcb->pkt_info.hash_value = *hash_value;
        rcb->pkt_info.hash_function = NdisHashFunctionToeplitz;
        DPRINTK(DPRTL_RSS, ("hash_value 0x%x\n", *hash_value));
        return;
    }

    DPRINTK(DPRTL_RSS, ("0\n"));
    rcb->pkt_info.hash_type = 0;
    rcb->pkt_info.hash_value = 0;
    rcb->pkt_info.hash_function = 0;
    *hash_value = 0;
    *hash_type = 0;
}

void
vnif_rss_get_rcb_target_info(PVNIF_ADAPTER adapter,
                             RCB *rcb,
                             UINT *rcv_target_qidx,
                             PROCESSOR_NUMBER *target_processor)
{
    ULONG indirection_idx;
    ULONG hash_type;
    ULONG hash_value;

    if (adapter->rss.rss_mode != VNIF_RSS_FULL
            || adapter->rss.first_q_indirection_idx ==
                    VNIF_INVALID_INDIRECTION_INDEX ) {
        return;
    }

    vnif_rss_get_hash_info(adapter, rcb, &hash_type, &hash_value);

    vnif_rss_dbg_hash_type(adapter,
                           rcb,
                           hash_type,
                           hash_value,
                           target_processor->Number);

    if (hash_type == 0) {
        return;
    } else {
        indirection_idx = hash_value & adapter->rss.hash_mask;

        DPRINTK(DPRTL_RSS, ("RSSHash.Value %x & RSSHashMask %x = %x\n",
                           hash_value,
                           adapter->rss.hash_mask,
                           indirection_idx));
        if (adapter->rss.q_indirection_tbl[indirection_idx] ==
                VNIF_NO_RECEIVE_QUEUE) {
            return;
        }

        *target_processor = adapter->rss.indirection_tbl[indirection_idx];
        *rcv_target_qidx = adapter->rss.q_indirection_tbl[indirection_idx];

#ifdef DBG
        if (adapter->rss.cpu_idx_mapping[
                    KeGetProcessorIndexFromNumber(target_processor)]
                != adapter->rss.q_indirection_tbl[indirection_idx]) {
            PRINTK(("%s: ** rcv_qidx %d does not match q_indrection[%d] %d\n",
                    __func__,
                    adapter->rss.cpu_idx_mapping[
                            KeGetProcessorIndexFromNumber(target_processor)],
                    indirection_idx,
                    adapter->rss.q_indirection_tbl[indirection_idx]));
            PRINTK(("\tfor processor number %d group %d\n",
                    target_processor->Number,
                    target_processor->Group));

        }
#endif
    }
}

void
vnif_rss_free_info(PVNIF_ADAPTER adapter)
{
    if (adapter->rss.cpu_idx_mapping != NULL) {
        RPRINTK(DPRTL_INIT, ("%s: free cpu_idx_mapping\n", __func__));
        NdisFreeMemoryWithTagPriority(adapter->AdapterHandle,
                                      adapter->rss.cpu_idx_mapping,
                                      VNIF_POOL_TAG);
        adapter->rss.cpu_idx_mapping = NULL;
        adapter->rss.cpu_idx_mapping_sz = 0;
    }
    if (adapter->rss.rss2_queue_map != NULL) {
        RPRINTK(DPRTL_INIT, ("%s: free rss2_queue_map\n", __func__));
        NdisFreeMemoryWithTagPriority(adapter->AdapterHandle,
                                      adapter->rss.rss2_queue_map,
                                      VNIF_POOL_TAG);
        adapter->rss.rss2_queue_map = NULL;
        adapter->rss.rss2_queue_len = 0;
    }
}

#ifdef RSS_DEBUG
void
vnif_rss_dbg_seq(PVNIF_ADAPTER adapter,
                 RCB *rcb,
                 UINT path_id,
                 UINT rcv_target_qidx,
                 UINT target_proc_num,
                 UINT rcv_qidx)
{
    rcb->rss_seq = InterlockedIncrement(&adapter->rcv_q[rcv_target_qidx].seq);
    if (adapter->rcv_q[rcv_target_qidx].rcv_processor.Number !=
        target_proc_num) {
        PRINTK(("R** rcv_proc %d != target_proc %d\n",
                adapter->rcv_q[rcv_target_qidx].rcv_processor.Number,
                target_proc_num));
    }
    DPRINTK(DPRTL_RSS,
            ("DPC p %d c %d: ridx %d rpathid %d rqidx %d rtqidx %d tcpu %d\n",
             path_id,
             vnif_get_current_processor(NULL),
             rcb->index, rcb->path_id,
             rcv_qidx, rcv_target_qidx, target_proc_num));
}

void
vnif_rss_test_seq(char *f, RCB *rcb, UINT path_id, UINT rcv_qidx, LONG *seq)
{
    if (rcb->rss_seq < *seq) {
        PRINTK(("%s out of order rcb %d seq %d path id %d cpu %d rcvIdx %d\n",
                f,
                rcb->rss_seq,
                seq,
                path_id,
                vnif_get_current_processor(NULL),
                rcv_qidx));
    }
    *seq = rcb->rss_seq;
}

void
vnif_rss_test_dpc(char *f, PVNIF_ADAPTER adapter)
{
    UINT cpu;
    UINT rcv_qidx;

    cpu = vnif_get_current_processor(NULL);
    rcv_qidx = vnif_rss_get_rcv_qidx_for_cur_cpu(adapter);
    if (rcv_qidx == VNIF_NO_RECEIVE_QUEUE) {
        rcv_qidx = 0;
    }

    if (adapter->maybe_dpc[cpu]) {
        adapter->maybe_dpc[cpu] = 0;
        PRINTK(("%s maybe: rcvq %d proc %d rcv_proc %d\n",
                f, rcv_qidx, cpu,
                adapter->rcv_q[rcv_qidx].rcv_processor.Number));
    }
}

void vnif_rss_dbg_hash_type(PVNIF_ADAPTER adapter,
                            RCB *rcb,
                            ULONG hash_type,
                            ULONG hash_value,
                            ULONG target_proc_num)
{
    ipv4_header_t *ipv4_hdr;
    tcp_hdr_t *tcp_hdr;
    uint8_t *ip_hdr;
    uint8_t *pkt_buf;
    uint8_t *data;
    ULONG indirection_idx;
    ULONG pseq;
    ULONG pktseq;
    ULONG addr;
    USHORT data_offset;

    if (hash_type == 0) {

        if (rcb->pkt_info.ip_ver == IPV4) {
            pkt_buf = rcb->page + adapter->buffer_offset;
            ip_hdr = pkt_buf + ETH_HEADER_SIZE;
            ipv4_hdr = (ipv4_header_t *)ip_hdr;
            tcp_hdr = (tcp_hdr_t *)(ip_hdr + rcb->pkt_info.ip_hdr_len);
            if (rcb->pkt_info.protocol == VNIF_PACKET_TYPE_TCP) {
                if (ipv4_hdr->ip_src >= 0x010001c8
                    && ipv4_hdr->ip_src <= 0x080001c8) {
                    if (tcp_hdr->tcp_src != 0xb) {
                        PRINTK(("TCP src port != 2816 : %d\n",
                                tcp_hdr->tcp_src));
                    }
                }
                switch (ipv4_hdr->ip_src) {
                case 0x010001c8:
                    addr = 1;
                    break;
                case 0x020001c8:
                    addr = 2;
                    break;
                case 0x030001c8:
                    addr= 3;
                    break;
                case 0x040001c8:
                    addr= 4;
                    break;
                case 0x050001c8:
                    addr= 5;
                    break;
                case 0x060001c8:
                    addr= 6;
                    break;
                case 0x070001c8:
                    addr= 7;
                    break;
                case 0x080001c8:
                    addr= 8;
                    break;
                case 0x0501010a:
                default:
                    addr = 0;
                    break;
                }
                if (addr != 0 && rcb->total_len > 0x4b) {
                    adapter->tmap[addr][target_proc_num]++;
                    adapter->ctmap[addr][target_proc_num]++;
                    if (rcb->total_len > 0x4b && tcp_hdr->tcp_src == 0xb) {
                        data_offset = ETH_HEADER_SIZE
                            + rcb->pkt_info.ip_hdr_len
                            + (((tcp_hdr->tcp_flags & 0xf0) >> 4) << 2);

                        pseq = adapter->pseq[addr];
                        pktseq = *((ULONG *)&pkt_buf[data_offset + 0xc]);
                        if (pseq + 1 != pktseq && pktseq != 0) {
                            PRINTK(
                                ("OoO[%d] %x: seq %x pktseq %x, hash_type %x\n",
                                 addr,
                                 (((tcp_hdr->tcp_flags & 0xf0) >> 4) << 2),
                                 pseq + 1, pktseq, hash_type));
                        }
                        adapter->pseq[addr] = pktseq;
                    }
                }
            } else {
                switch (ipv4_hdr->ip_src) {
                case 0x010001c8:
                    adapter->imap[1][target_proc_num]++;
                    adapter->cimap[1][target_proc_num]++;
                    break;
                case 0x020001c8:
                    adapter->imap[2][target_proc_num]++;
                    adapter->cimap[2][target_proc_num]++;
                    break;
                case 0x030001c8:
                    adapter->imap[3][target_proc_num]++;
                    adapter->cimap[3][target_proc_num]++;
                    break;
                case 0x040001c8:
                    adapter->imap[4][target_proc_num]++;
                    adapter->cimap[4][target_proc_num]++;
                    break;
                case 0x050001c8:
                    adapter->imap[5][target_proc_num]++;
                    adapter->cimap[5][target_proc_num]++;
                    break;
                case 0x060001c8:
                    adapter->imap[6][target_proc_num]++;
                    adapter->cimap[6][target_proc_num]++;
                    break;
                case 0x070001c8:
                    adapter->tmap[7][target_proc_num]++;
                    adapter->ctmap[7][target_proc_num]++;
                    break;
                case 0x080001c8:
                    adapter->imap[8][target_proc_num]++;
                    adapter->cimap[8][target_proc_num]++;
                    break;
                case 0x0501010a:
                    adapter->imap[0][target_proc_num]++;
                    adapter->cimap[0][target_proc_num]++;
                    break;
                }
            }
        }
        return;
    } else {
        indirection_idx = hash_value & adapter->rss.hash_mask;

        if (adapter->rss.q_indirection_tbl[indirection_idx] ==
                VNIF_NO_RECEIVE_QUEUE) {
            return;
        }

        target_proc_num = adapter->rss.indirection_tbl[indirection_idx];

        if (rcb->pkt_info.ip_ver == IPV4) {
            pkt_buf = rcb->page + adapter->buffer_offset;
            ip_hdr = pkt_buf + ETH_HEADER_SIZE;
            ipv4_hdr = (ipv4_header_t *)ip_hdr;
            tcp_hdr = (tcp_hdr_t *)(ip_hdr + rcb->pkt_info.ip_hdr_len);
            if (rcb->pkt_info.protocol == VNIF_PACKET_TYPE_TCP) {
                if (ipv4_hdr->ip_src >= 0x010001c8
                    && ipv4_hdr->ip_src <= 0x080001c8
                    && ipv4_hdr->ip_dest == 0x00010164) {
                    if (tcp_hdr->tcp_src != 0xb) {
                        PRINTK(("TCP src port != 2816 : %d hdr len %d\n",
                                tcp_hdr->tcp_src, rcb->pkt_info.ip_hdr_len));
                    }
                }
                switch (ipv4_hdr->ip_src) {
                case 0x010001c8:
                    addr = 1;
                    break;
                case 0x020001c8:
                    addr = 2;
                    break;
                case 0x030001c8:
                    addr= 3;
                    break;
                case 0x040001c8:
                    addr= 4;
                    break;
                case 0x050001c8:
                    addr= 5;
                    break;
                case 0x060001c8:
                    addr= 6;
                    break;
                case 0x070001c8:
                    addr= 7;
                    break;
                case 0x080001c8:
                    addr= 8;
                    break;
                case 0x0501010a:
                default:
                    addr = 0;
                    break;
                }
                if (addr != 0 && rcb->total_len > 0x4b) {
                    adapter->tmap[addr][target_proc_num]++;
                    adapter->ctmap[addr][target_proc_num]++;
                    if (rcb->total_len > 0x4b && tcp_hdr->tcp_src == 0xb) {
                        data_offset = ETH_HEADER_SIZE
                            + rcb->pkt_info.ip_hdr_len
                            + (((tcp_hdr->tcp_flags & 0xf0) >> 4) << 2);

                        pseq = adapter->pseq[addr];
                        pktseq = *((ULONG *)&pkt_buf[data_offset + 0xc]);
                        if (pseq + 1 != pktseq && pktseq != 0) {
                            PRINTK(
                                ("OoO[%d] %x: seq %x pktseq %x, hash_type %x\n",
                                 addr,
                                 (((tcp_hdr->tcp_flags & 0xf0) >> 4) << 2),
                                 pseq + 1, pktseq, hash_type));
                        }
                        adapter->pseq[addr] = pktseq;
                    }
                }
            } else {
                switch (ipv4_hdr->ip_src) {
                case 0x010001c8:
                    adapter->imap[1][target_proc_num]++;
                    adapter->cimap[1][target_proc_num]++;
                    break;
                case 0x020001c8:
                    adapter->imap[2][target_proc_num]++;
                    adapter->cimap[2][target_proc_num]++;
                    break;
                case 0x030001c8:
                    adapter->imap[3][target_proc_num]++;
                    adapter->cimap[3][target_proc_num]++;
                    break;
                case 0x040001c8:
                    adapter->imap[4][target_proc_num]++;
                    adapter->cimap[4][target_proc_num]++;
                    break;
                case 0x050001c8:
                    adapter->imap[5][target_proc_num]++;
                    adapter->cimap[5][target_proc_num]++;
                    break;
                case 0x060001c8:
                    adapter->imap[6][target_proc_num]++;
                    adapter->cimap[6][target_proc_num]++;
                    break;
                case 0x070001c8:
                    adapter->tmap[7][target_proc_num]++;
                    adapter->ctmap[7][target_proc_num]++;
                    break;
                case 0x080001c8:
                    adapter->imap[8][target_proc_num]++;
                    adapter->cimap[8][target_proc_num]++;
                    break;
                case 0x0501010a:
                    adapter->imap[0][target_proc_num]++;
                    adapter->cimap[0][target_proc_num]++;
                    break;
                }
            }
        }
    }
}

void
vnif_rss_dbg_dump_map(PVNIF_ADAPTER adapter)
{
    UINT i;
    UINT j;
    PROCESSOR_NUMBER target_processor;
    UINT cpu_idx;
    UINT maybe = 0;
    UINT rcvq = 0;

    for (j = 0; j < 4; j++) {
        PRINTK((" %7d", adapter->pv_stats->rx_path_cnt[j]));
        adapter->pv_stats->rx_path_cnt[j] = 0;
    }
    PRINTK(("\n"));
    for (i = 0; i < adapter->num_rcv_queues; i++) {
        if (!IsListEmpty(&adapter->rcv_q[i].rcv_to_process)) {
            PRINTK(("Maybe need DPC for rcv q %d on processor %d\n", i,
                    adapter->rcv_q[i].rcv_processor.Number));
            maybe++;
            adapter->maybe_dpc[adapter->rcv_q[i].rcv_processor.Number]++;
        }
    }
    if (maybe) {
        PRINTK(("hash info %x\n", adapter->rss.hash_info));
        for (cpu_idx = 0; cpu_idx < adapter->rss.cpu_idx_mapping_sz; cpu_idx++) {
            rcvq = adapter->rss.cpu_idx_mapping[cpu_idx];
            if (rcvq == VNIF_NO_RECEIVE_QUEUE) {
                rcvq = 0;
            }
    #if NDIS620_MINIPORT_SUPPORT
            KeGetProcessorNumberFromIndex(cpu_idx, &target_processor);
            if (adapter->rcv_q[rcvq].rcv_processor.Number
                    != target_processor.Number) {
                PRINTK(("** rcv_proc %d != target_proc %d\n",
                        adapter->rcv_q[rcvq].rcv_processor.Number,
                        target_processor.Number));
            }
            RPRINTK(DPRTL_RSS,
                    ("%s: cpu_idx_mapping[%d] = rcv_q idx %d on dpc cpu %d\n",
                     __func__, cpu_idx, rcvq, target_processor.Number));
    #endif
        }
    }

    return;




    if (g_running_hypervisor == HYPERVISOR_KVM) {
        for (j = 0; j < adapter->num_paths; j++) {
            PRINTK((" %7x", adapter->path[j].u.vq.rx->vring.avail->flags));
            if(adapter->path[j].u.vq.rx->vring.avail->flags
               && VRING_AVAIL_F_NO_INTERRUPT){
                adapter->path[j].u.vq.rx->vring.avail->flags &=
                    ~VRING_AVAIL_F_NO_INTERRUPT;
                mb();
            }
        }
    }


    PRINTK(("\nIP mapping\n"));
    //for (i = 1; i < 9; i++) {
    for (i = 1; i < 2; i++) {
        PRINTK(("%d:", i));
        for (j = 0; j < 4; j++) {
            PRINTK((" %7d", adapter->imap[i][j]));
            adapter->imap[i][j] = 0;
        }
        PRINTK((" :"));
        for (j = 0; j < 4; j++) {
            PRINTK((" %8d", adapter->cimap[i][j]));
        }
        PRINTK(("\n"));
    }
    PRINTK(("TCP mapping\n"));
    //for (i = 1; i < 9; i++) {
    for (i = 1; i < 2; i++) {
        PRINTK(("%d:", i));
        for (j = 0; j < 4; j++) {
            PRINTK((" %7d", adapter->tmap[i][j]));
            adapter->tmap[i][j] = 0;
        }
        PRINTK((" :"));
        for (j = 0; j < 4; j++) {
            PRINTK((" %8d", adapter->ctmap[i][j]));
        }
        PRINTK(("\n\n"));
    }
}
#endif
