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

#ifndef _MP_RSS_H
#define _MP_RSS_H

#define VNIF_NO_RECEIVE_QUEUE (-2)

typedef enum VNIF_RSS_MODE_s
{
    VNIF_RSS_DISABLED = 0,
    VNIF_RSS_HASHING  = 1,
    VNIF_RSS_FULL     = 2,
} VNIF_RSS_MODE;

#ifdef MP_RSS_SUPPORTED

#define VNIF_FIRST_RSS_RECEIVE_QUEUE    (0)
#define VNIF_RECEIVE_UNCLASSIFIED_PACKET (-1)
#define VNIF_INVALID_INDIRECTION_INDEX (-1)
#define VNIF_MAX_NUM_RSS_QUEUES 16
#define VNIF_DEFAULT_NUM_RSS_QUEUES 8

#define IS_POWER_OF_TWO(_num) (((_num) != 0) && (((_num) & ( (_num) - 1)) == 0))

#define vnif_set_proc_num_to_group_affinity(_proc_num, _affinity)           \
{                                                                           \
    (_affinity).Group = (_proc_num).Group;                                  \
    (_affinity).Mask = 1i64 << (_proc_num).Number;                          \
}

#define vnif_get_current_processor(_null) KeGetCurrentProcessorNumberEx(NULL)

#define TOEPLITZ_MAX_BIT_NUM (7)
#define TOEPLITZ_BYTE_HAS_BIT(byte, bit)                                    \
    ((byte) & (1 << (TOEPLITZ_MAX_BIT_NUM - (bit))))
#define TOEPLITZ_BYTE_BIT_STATE(byte, bit)                                  \
    (((byte) >> (TOEPLITZ_MAX_BIT_NUM - (bit))) & 1)

#define VNIF_GET_RSS_MODE(_adapter) (_adapter)->rss.rss_mode

#define VNIF_RSS_MAX_INDRECTION_TBL_SIZE    \
    NDIS_RSS_INDIRECTION_TABLE_MAX_SIZE_REVISION_2 / sizeof(PROCESSOR_NUMBER)
#define VNIF_RSS_HASH_SECRET_KEY_MAX_SIZE_REVISION                          \
    NDIS_RSS_HASH_SECRET_KEY_MAX_SIZE_REVISION_2

#define VNIF_RSS_2_QUEUE_MAP(_adapter, _nb_list, _path_id)                  \
{                                                                           \
    ULONG           rss_hash_val;                                           \
    ULONG           rss_path_id;                                            \
                                                                            \
    if ((_adapter)->rss.rss2_queue_map) {                                   \
        rss_hash_val = NET_BUFFER_LIST_GET_HASH_VALUE((_nb_list));          \
        if (rss_hash_val) {                                                 \
            rss_path_id = rss_hash_val & (_adapter)->rss.hash_mask;         \
            (_path_id) = (_adapter)->rss.rss2_queue_map[rss_path_id];       \
            DPRINTK(DPRTL_TX,                                               \
                    ("%s: rss_hash_val %x & %x = %d : maps to path %d\n",   \
                     __func__,                                              \
                    rss_hash_val,                                           \
                    (_adapter)->rss.hash_mask,                              \
                    rss_path_id,                                            \
                    (_path_id)));                                           \
        } else {                                                            \
            (_path_id) = 0;                                                 \
        }                                                                   \
    } else {                                                                \
        (_path_id) = 0;                                                     \
    }                                                                       \
}

typedef struct _hash_sg_entry
{
    PCHAR chunkPtr;
    ULONG chunkLen;
} hash_sg_entry_t;

typedef struct _vnif_rss_s {
    PROCESSOR_NUMBER indirection_tbl[VNIF_RSS_MAX_INDRECTION_TBL_SIZE];
    CCHAR q_indirection_tbl[VNIF_RSS_MAX_INDRECTION_TBL_SIZE];
    CCHAR hash_secret_key[VNIF_RSS_HASH_SECRET_KEY_MAX_SIZE_REVISION];
    PCHAR           cpu_idx_mapping;
    #if 0
    void            **rss2_queue_map;
    #endif
    USHORT          *rss2_queue_map;
    ULONG           cpu_idx_mapping_sz;
    ULONG           hash_mask;
    ULONG           hash_info;
    LONG            first_q_indirection_idx;
    VNIF_RSS_MODE   rss_mode;
    UINT            rss2_queue_len;
    USHORT          indirection_tbl_sz;
    USHORT          hash_secret_key_sz;

} vnif_rss_t;

NDIS_RECEIVE_SCALE_CAPABILITIES *
vnif_rss_set_generall_attributes(struct _VNIF_ADAPTER *adapter,
    NDIS_RECEIVE_SCALE_CAPABILITIES *rss_caps);

NDIS_STATUS
vnif_rss_setup_queue_dpc_path(struct _VNIF_ADAPTER *adapter, UINT path_id);

void
vnif_rss_set_rcv_q_targets(struct _VNIF_ADAPTER *adapter);

NDIS_STATUS
vnif_rss_oid_gen_receive_scale_params(struct _VNIF_ADAPTER *adapter,
                                      NDIS_RECEIVE_SCALE_PARAMETERS *rss_params,
                                      ULONG rss_params_len,
                                      PULONG bytes_read,
                                      PULONG bytes_needed);
UINT
vnif_rss_get_rcv_qidx_for_cur_processor(struct _VNIF_ADAPTER *adapter);
#define vnif_rss_get_rcv_qidx_for_cur_cpu(_adapter_)                        \
    vnif_rss_get_rcv_qidx_for_cur_processor((_adapter_));

void
vnif_rss_get_rcb_target_info(struct _VNIF_ADAPTER *adapter,
                             struct _RCB *rcb,
                             UINT *rcv_target_qidx,
                             PROCESSOR_NUMBER *target_processor);

#define vnif_rss_set_nbl_info(_adapter, _nbl, _rcb)                         \
{                                                                           \
    if (VNIF_GET_RSS_MODE((_adapter)) != VNIF_RSS_DISABLED) {               \
        NET_BUFFER_LIST_SET_HASH_TYPE((_nbl), (_rcb)->pkt_info.hash_type);  \
        NET_BUFFER_LIST_SET_HASH_VALUE((_nbl), (_rcb)->pkt_info.hash_value);\
        NET_BUFFER_LIST_SET_HASH_FUNCTION((_nbl),                           \
                                          (_rcb)->pkt_info.hash_function);  \
    }                                                                       \
}

#define vnif_rss_clear_nbl_info(_nbl)                                       \
{                                                                           \
    NET_BUFFER_LIST_SET_HASH_TYPE((_nbl), 0);                               \
    NET_BUFFER_LIST_SET_HASH_VALUE((_nbl), 0);                              \
    NET_BUFFER_LIST_SET_HASH_FUNCTION((_nbl), 0);                           \
}

void vnif_rss_free_info(struct _VNIF_ADAPTER *adapter);

#else
#define vnif_rss_set_generall_attributes(_adapter_, _rss_caps_) NULL
#define vnif_rss_setup_queue_dpc_path(_adapter_, _path_id) NDIS_STATUS_SUCCESS
#define vnif_rss_set_rcv_q_targets(_adapter)
#define vnif_rss_get_rcv_qidx_for_cur_cpu(_adapter_) 0
#define vnif_rss_get_rcb_target_info(_adapter, _rcb, _r_qidx, _t_processor)
#define VNIF_GET_RSS_MODE(_adapter) VNIF_RSS_DISABLED
#define vnif_get_current_processor(_null) KeGetCurrentProcessorNumber()
#define VNIF_RSS_2_QUEUE_MAP(_adapter, _nb_list, _path_id) _path_id = 0;
#define vnif_rss_set_nbl_info(_adapter, _nbl, _rcb)
#define vnif_rss_clear_nbl_info(_nbl)
#define vnif_rss_free_info(_adapter)
#endif

#ifdef RSS_DEBUG
void vnif_rss_dbg_seq(PVNIF_ADAPTER adapter,
                      RCB *rcb,
                      UINT path_id,
                      UINT rcv_target_qidx,
                      UINT target_proc_num,
                      UINT rcv_qidx);

void vnif_rss_test_seq(char *f,
                       RCB *rcb,
                       UINT path_id,
                       UINT rcv_qidx,
                       LONG *seq);

void vnif_rss_test_dpc(char *f, PVNIF_ADAPTER adapter);

void vnif_rss_dbg_hash_type(PVNIF_ADAPTER adapter,
                            RCB *rcb,
                            ULONG hash_type,
                            ULONG hash_value,
                            ULONG target_proc_num);

void vnif_rss_dbg_dump_map(struct _VNIF_ADAPTER *adapter);
#else
#define vnif_rss_dbg_seq(adapter,                                           \
                         rcb, path_id,                                      \
                         rcv_target_qidx,                                   \
                         target_proc_num,                                   \
                         rcv_qidx)

#define vnif_rss_test_seq(f, rcb, path_id, rcv_qidx, seq)

#define vnif_rss_test_dpc(f, adapter)

#define vnif_rss_dbg_hash_type(adapter,                                     \
                               rcb, hash_type,                              \
                               hash_value,                                  \
                               target_proc_num)

#define vnif_rss_dbg_dump_map(adapter)
#endif

#endif
