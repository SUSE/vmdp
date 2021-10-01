/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2006-2012 Novell, Inc.
 * Copyright 2012-2020 SUSE LLC
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

#include "xenbus.h"
#include "xen_support.h"

struct xenstore_domain_interface *xen_store_interface;

int xen_store_evtchn;
struct xenbus_watch vbd_watch = {0};
struct xenbus_watch vif_watch = {0};
struct xenbus_watch vscsi_watch = {0};
struct xenbus_watch vusb_watch = {0};

struct xs_handle {
    LIST_ENTRY reply_list;
    KSPIN_LOCK reply_lock;

    /* we are using event to replace wait queue */
    KEVENT reply_list_notempty;

    KMUTEX request_mutex;

    /* windows ``Resource'' functions for readwritelock */
    ERESOURCE suspend_mutex;
};

static struct xs_handle xs_state = { {0}, (KSPIN_LOCK)0xbad, {0}, {0}, {0} };

static LIST_ENTRY watches;
static KSPIN_LOCK watches_lock = 0xbad;
static KSPIN_LOCK xs_lock = 0xbad;

static KSPIN_LOCK watch_events_lock = 0xbad;
static KEVENT watch_events_notempty;
static LIST_ENTRY watch_events;

#if defined XENBUG_TRACE_FLAGS || defined DBG
static uint32_t xenbus_wait_events;
uint32_t xenbus_locks;
#endif
uint32_t rtrace;
#ifdef DBG
static uint32_t DBG_WAIT;
static uint32_t DBG_XS;
uint32_t evt_print;
#endif

/* system thread related objects */

static KEVENT thread_xenwatch_kill;
static KEVENT thread_xenbus_kill;
static HANDLE xenwatch_tid;
static KSPIN_LOCK xenbus_dpc_lock = 0xbad;
static PIO_WORKITEM xenbus_watch_work_item;
static uint32_t xenbus_watch_work_scheduled;

static KEVENT xb_event;

/* Ignore multiple shutdown requests. */
static int shutting_down = SHUTDOWN_INVALID;
static struct xenbus_watch shutdown_watch = {0};

static void
XenbusDpcRoutine(
    IN PKDPC Dpc,
    IN PVOID DpcContext,
    IN PVOID RegisteredContext,
    IN PVOID DeviceExtension)
{
    XEN_LOCK_HANDLE lh;

    DPRINTK(DPRTL_WAIT,
            ("XenbusDpcRoutine: cpu %x IN\n", KeGetCurrentProcessorNumber()));
    XenAcquireSpinLock(&xenbus_dpc_lock, &lh);
    XENBUS_SET_FLAG(xenbus_locks, X_DPC);
    xb_read_msg();
    XENBUS_CLEAR_FLAG(rtrace, EVTCHN_F);
    DPRINTK(DPRTL_WAIT, ("XenbusDpcRoutine: signaling xb_event\n"));
    KeSetEvent(&xb_event, 0, FALSE);
    if (!IsListEmpty(&watch_events)) {
        if (!xenbus_watch_work_scheduled) {
            xenbus_watch_work_scheduled = 1;
            if (DpcContext == NULL) {
                PRINTK(("XenbusDpcRoutine: DpcContext is NULL\n"));
            } else {
                xenbus_watch_work_item = IoAllocateWorkItem(
                    (PDEVICE_OBJECT)DpcContext);
                if (xenbus_watch_work_item != NULL) {
                    DPRINTK(DPRTL_WAIT,
                            ("XenbusDpcRoutine: IoQueueWorkItem\n"));
                    IoQueueWorkItem(xenbus_watch_work_item,
                        (void (*)(PDEVICE_OBJECT, void *))xenbus_watch_work,
                        DelayedWorkQueue, xenbus_watch_work_item);
                }
            }
        }
    }
    XENBUS_CLEAR_FLAG(xenbus_locks, X_DPC);
    XenReleaseSpinLock(&xenbus_dpc_lock, lh);
    DPRINTK(DPRTL_WAIT, ("XenbusDpcRoutine: cpu %x OUT\n",
                         KeGetCurrentProcessorNumber()));
}


static int
get_error(const char *errorstring)
{
    unsigned int i, len;

    len = (sizeof(xsd_errors) / sizeof(xsd_errors[0]));
    for (i = 0; i < len; i++) {
        if (strcmp(errorstring, xsd_errors[i].errstring) == 0) {
            break;
        }
    }

    if (i == len) {
        PRINTK(("XENBUS: xenstore gives unknown error %s", errorstring));
        return -1;
    }

    return xsd_errors[i].errnum;
}

static void *
xenbus_get_output_chunck(XENSTORE_RING_IDX cons,
    XENSTORE_RING_IDX prod,
    char *buf, uint32_t *len)
{
    *len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);
    if ((XENSTORE_RING_SIZE - (prod - cons)) < *len) {
        *len = XENSTORE_RING_SIZE - (prod - cons);
    }
    return buf + MASK_XENSTORE_IDX(prod);
}

static const void *
xenbus_get_input_chunk(XENSTORE_RING_IDX cons,
    XENSTORE_RING_IDX prod,
    const char *buf, uint32_t *len)
{
    *len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(cons);
    if ((prod - cons) < *len) {
        *len = prod - cons;
    }
    return buf + MASK_XENSTORE_IDX(cons);
}

static int
xenbus_check_indexes(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod)
{
    return ((prod - cons) <= XENSTORE_RING_SIZE);
}

static int
xb_write(const void *buf, unsigned int len)
{
    KDPC dpc = {0};
    struct xenstore_domain_interface *intf;
    XENSTORE_RING_IDX cons, prod;
    int rc;
    PUCHAR data = (PUCHAR) buf;
    LARGE_INTEGER timeout;

    intf = xen_store_interface;
    timeout.QuadPart = 0;

    DPRINTK(DPRTL_WAIT, ("xb_write: In\n"));
    while (len != 0) {
        PUCHAR dst;
        unsigned int avail;
        NTSTATUS status;

        for (;;) {
            if ((intf->req_prod - intf->req_cons) != XENSTORE_RING_SIZE) {
                DPRINTK(DPRTL_WAIT, ("xb_write: break\n"));
                break;
            }

            DPRINTK(DPRTL_WAIT, ("xb_write: KeWaitForSingleObject\n"));
            XENBUS_SET_FLAG(xenbus_wait_events, XB_EVENT);
            status = KeWaitForSingleObject(
                &xb_event,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            if (status != STATUS_SUCCESS) {
                XENBUS_SET_FLAG(rtrace, XB_WRITE_F);
                if (gfdo) {
                    XenbusDpcRoutine(&dpc, gfdo, NULL, NULL);
                } else {
                    DPRINTK(DPRTL_ON, ("xb_write: gfdo is NULL\n"));
                }
                XENBUS_CLEAR_FLAG(rtrace, XB_WRITE_F);
            }
            XENBUS_CLEAR_FLAG(xenbus_wait_events, XB_EVENT);
            DPRINTK(DPRTL_WAIT, ("xb_write: KeWaitForSingleObject done\n"));

            status = KeWaitForSingleObject(
                &thread_xenbus_kill,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            if (status == STATUS_SUCCESS || status == STATUS_ALERTED) {
                DPRINTK(DPRTL_WAIT, ("xb_write: return -1\n"));
                return -1;
            }

            DPRINTK(DPRTL_WAIT, ("xb_write: KeClearEvent\n"));
            KeClearEvent(&xb_event);
        }

        /* Read indexes, then verify. */
        cons = intf->req_cons;
        prod = intf->req_prod;
        KeMemoryBarrier();

        DPRINTK(DPRTL_WAIT, ("xb_write: xenbus_check_indexes\n"));
        if (!xenbus_check_indexes(cons, prod)) {
            intf->req_cons = intf->req_prod = 0;
            DPRINTK(DPRTL_WAIT, ("XENBUS: xenstore ring overflow! reset.\n"));
            return -EIO;
        }

        DPRINTK(DPRTL_WAIT, ("xb_write: xenbus_get_output_chunck\n"));
        dst = xenbus_get_output_chunck(cons, prod, intf->req, &avail);
        if (avail == 0) {
            continue;
        }
        if (avail > len) {
            avail = len;
        }

        RtlCopyMemory(dst, data, avail);
        data += avail;
        len -= avail;

        KeMemoryBarrier();
        intf->req_prod += avail;

        DPRINTK(DPRTL_WAIT, ("xb_write: notify_remote_via_evtchn\n"));
        notify_remote_via_evtchn(xen_store_evtchn);
    }

    DPRINTK(DPRTL_WAIT, ("xb_write: Out\n"));
    return 0;
}


static void *
read_reply(uint32_t *type, unsigned int *len)
{
    KDPC dpc = {0};
    struct xs_stored_msg *msg;
    char *body;
    PLIST_ENTRY ple;
    XEN_LOCK_HANDLE lh;
    LARGE_INTEGER timeout;
    NTSTATUS status;

    timeout.QuadPart = 0;

    XenAcquireSpinLock(&xs_state.reply_lock, &lh);
    XENBUS_SET_FLAG(xenbus_locks, X_RPL);

    XENBUS_SET_FLAG(xenbus_wait_events, XS_LIST);
    while (IsListEmpty(&xs_state.reply_list)) {
        XENBUS_CLEAR_FLAG(xenbus_locks, X_RPL);
        XenReleaseSpinLock(&xs_state.reply_lock, lh);

        status = KeWaitForSingleObject(
            &xs_state.reply_list_notempty,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (status != STATUS_SUCCESS) {
            XENBUS_SET_FLAG(rtrace, READ_REPLY_F);
            if (gfdo) {
                XenbusDpcRoutine(&dpc, gfdo, NULL, NULL);
            } else {
                DPRINTK(DPRTL_ON, ("read_reply: gfdo is NULL\n"));
            }
            XENBUS_CLEAR_FLAG(rtrace, READ_REPLY_F);
        } else {
            if (IsListEmpty(&xs_state.reply_list)) {
                PRINTK(("read_reply: Event is set, but no msg.\n"));
                KeClearEvent(&xs_state.reply_list_notempty);
            }
        }

        XenAcquireSpinLock(&xs_state.reply_lock, &lh);
        XENBUS_SET_FLAG(xenbus_locks, X_RPL);
    }
    XENBUS_CLEAR_FLAG(xenbus_wait_events, XS_LIST);

    ple = RemoveHeadList(&xs_state.reply_list);

    if (IsListEmpty(&xs_state.reply_list)) {
        DPRINTK(DPRTL_WAIT,
                ("read_reply: KeClearEvent xs_state.reply_list_notempty\n"));
        KeClearEvent(&xs_state.reply_list_notempty);
    }

    msg = CONTAINING_RECORD(ple, struct xs_stored_msg, list);

    XENBUS_CLEAR_FLAG(xenbus_locks, X_RPL);
    XenReleaseSpinLock(&xs_state.reply_lock, lh);

    *type = msg->hdr.type;
    if (len) {
        *len = msg->hdr.len;
    }
    body = msg->u.reply.body;

    ExFreePool(msg);

    DPRINTK(DPRTL_XS, ("read_reply: out\n"));
    return body;
}

static void *
xs_talkv(struct xenbus_transaction t,
    enum xsd_sockmsg_type type,
    const struct kvec *iovec,
    unsigned int num_vecs,
    unsigned int *len)
{
    struct xsd_sockmsg msg;
    void *ret = NULL;
    unsigned int i;
    int err;
    LARGE_INTEGER timeout;
    XEN_LOCK_HANDLE lh;

    timeout.QuadPart = 0;

    DPRINTK(DPRTL_XS, ("xs_talkv: XenAcquireSpinLock, irql %x, cpu %x\n",
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));

    msg.tx_id = t.id;
    msg.req_id = 0;
    msg.type = type;
    msg.len = 0;
    for (i = 0; i < num_vecs; i++) {
        msg.len += iovec[i].iov_len;
    }

    XenAcquireSpinLock(&xs_lock, &lh);
    XENBUS_SET_FLAG(xenbus_locks, X_XSL);
    XENBUS_SET_FLAG(xenbus_wait_events, XS_REQUEST);

    DPRINTK(DPRTL_XS, ("xs_talkv: xb_write, irql %x, cpu %x\n",
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    err = xb_write(&msg, sizeof(msg));
    if (err) {
        XENBUS_CLEAR_FLAG(xenbus_wait_events, XS_REQUEST);
        XENBUS_CLEAR_FLAG(xenbus_locks, X_XSL);
        XenReleaseSpinLock(&xs_lock, lh);
        PRINTK(("xs_talkv: xb_write err %x\n", KeGetCurrentProcessorNumber()));
        return ERR_PTR(err);
    }

    for (i = 0; i < num_vecs; i++) {
        DPRINTK(DPRTL_XS, ("xs_talkv: xb_write iovec\n"));
        err = xb_write(iovec[i].iov_base, iovec[i].iov_len);
        if (err) {
            XENBUS_CLEAR_FLAG(xenbus_wait_events, XS_REQUEST);
            XENBUS_CLEAR_FLAG(xenbus_locks, X_XSL);
            XenReleaseSpinLock(&xs_lock, lh);
            PRINTK(("xs_talkv: xb_write err 2, %x\n",
                KeGetCurrentProcessorNumber()));
            return ERR_PTR(err);
        }
    }

    DPRINTK(DPRTL_XS, ("xs_talkv: read_reply, irql %x, cpu %x\n",
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    ret = read_reply(&msg.type, len);

    XENBUS_CLEAR_FLAG(xenbus_wait_events, XS_REQUEST);
    XENBUS_CLEAR_FLAG(xenbus_locks, X_XSL);
    XenReleaseSpinLock(&xs_lock, lh);

    if (IS_ERR(ret)) {
        PRINTK(("xs_talkv: read_reply err %x\n",
                KeGetCurrentProcessorNumber()));
        return ret;
    }

    if (msg.type == XS_ERROR) {
        DPRINTK(DPRTL_XS, ("xs_talkv: msg.type XS_ERROR: %s, cpu %x\n",
                           ret, KeGetCurrentProcessorNumber()));
        err = get_error(ret);
        ExFreePool(ret);
        return ERR_PTR(-err);
    }

    if (msg.type != type) {
        PRINTK(("XENBUS unexpected type %d, expected %d, %x\n",
            msg.type, type, KeGetCurrentProcessorNumber()));
        ExFreePool(ret);
        return ERR_PTR(-EINVAL);
    }
    DPRINTK(DPRTL_XS, ("xs_talkv: out, irql %x, cpu %x\n",
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    return ret;
}

/* Simplified version of xs_talkv: single message. */
static void *
xs_single(struct xenbus_transaction t,
    enum xsd_sockmsg_type type,
    const char *string,
    unsigned int *len)
{
    struct kvec iovec;

    iovec.iov_base = (void *)string;
    iovec.iov_len = strlen(string) + 1;
    DPRINTK(DPRTL_XS, ("xs_single: xs_talkv\n"));
    return xs_talkv(t, type, &iovec, 1, len);
}

/* Many commands only need an ack, don't care what it says. */
static int
xs_error(char *reply)
{
    if (IS_ERR(reply)) {
        return (int)PTR_ERR(reply);
    }

    ExFreePool(reply);
    return 0;
}

static unsigned int
count_strings(const char *strings, unsigned int len)
{
    unsigned int num;
    const char *p;

    for (p = strings, num = 0; p < strings + len; p += strlen(p) + 1) {
        num++;
    }

    return num;
}

/* Simplified asprintf. */
char *
kasprintf(size_t len, const char *fmt, ...)
{
    va_list ap;
    char *p;

    p = EX_ALLOC_POOL(VPOOL_NON_PAGED, len + 1, XENBUS_POOL_TAG);
    if (!p) {
        return NULL;
    }

    va_start(ap, fmt);
    RtlStringCbVPrintfA(p, len + 1, fmt, ap);
    va_end(ap);
    return p;
}

/* Return the path to dir with /name appended. Buffer must be kfree()'ed. */
static char *
join(const char *dir, const char *name)
{
    size_t i, j;
    char *buffer;

    i = strlen(dir);
    j = strlen(name);

    if (j == 0) {
        buffer = kasprintf(i, "%s", dir);
    } else {
        buffer = kasprintf(i + j + 1, "%s/%s", dir, name);
    }
    return (!buffer) ? ERR_PTR(-ENOMEM) : buffer;
}

static char **
split(char *strings, unsigned int len, unsigned int *num)
{
    char *p, **ret;
    unsigned int i;
    unsigned int strcnt;

    if (strings == NULL || len == 0) {
        return ERR_PTR(-ENOMEM);
    }

    /* Count the strings. */
    strcnt = count_strings(strings, len);
    *num = strcnt;

    /* Transfer to one big alloc for easy freeing. */
    ret = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                        strcnt * sizeof(char *) + len,
                        XENBUS_POOL_TAG);

    if (!ret) {
        ExFreePool(strings);
        return ERR_PTR(-ENOMEM);
    }

    RtlCopyMemory(&ret[strcnt], strings, len);
    ExFreePool(strings);

    strings = (char *)&ret[strcnt];
    for (i = 0, p = strings; p < strings + len; i++, p += strlen(p) + 1) {
        ret[i] = p;
    }

    return ret;
}

char **
xenbus_directory(struct xenbus_transaction t,
    const char *dir, const char *node, unsigned int *num)
{
    char *strings, *path;
    unsigned int len;

    path = join(dir, node);
    if (IS_ERR(path)) {
        return (char **)path;
    }

    strings = xs_single(t, XS_DIRECTORY, path, &len);
    ExFreePool(path);
    if (IS_ERR(strings) || len == 0) {
        return (char **)strings;
    }

    return split(strings, len, num);
}

/* Check if a path exists. Return 1 if it does. */
int
xenbus_exists(struct xenbus_transaction t,
    const char *dir, const char *node)
{
    char **d;
    int dir_n;

    d = xenbus_directory(t, dir, node, &dir_n);
    if (IS_ERR(d)) {
        return 0;
    }
    ExFreePool(d);
    return 1;
}

/*
 * Get the value of a single file.
 * Returns a kmalloced value: call free() on it after use.
 * len indicates length in bytes.
 */
void *
xenbus_read(struct xenbus_transaction t,
    const char *dir, const char *node, unsigned int *len)
{
    char *path;
    void *ret;

    path = join(dir, node);
    if (IS_ERR(path)) {
        return (void *)path;
    }

    DPRINTK(DPRTL_XS, ("xenbus_read: xs_single\n"));
    ret = xs_single(t, XS_READ, path, len);
    ExFreePool(path);
    if (IS_ERR(ret)) {
        return NULL;
    } else {
        return ret;
    }
}


/*
 * Write the value of a single file.
 * Returns -err on failure.
 */
int
xenbus_write(struct xenbus_transaction t,
    const char *dir, const char *node, const char *string)
{
    char *path;
    struct kvec iovec[2];
    int ret;

    path = join(dir, node);
    if (IS_ERR(path)) {
        return (int)PTR_ERR(path);
    }

    iovec[0].iov_base = (void *)path;
    iovec[0].iov_len = strlen(path) + 1;
    iovec[1].iov_base = (void *)string;
    iovec[1].iov_len = strlen(string);

    ret = xs_error(xs_talkv(t, XS_WRITE, iovec,
        sizeof(iovec) / sizeof(iovec[0]), NULL));
    ExFreePool(path);
    return ret;
}

/* Create a new directory. */
int
xenbus_mkdir(struct xenbus_transaction t,
    const char *dir, const char *node)
{
    char *path;
    int ret;

    path = join(dir, node);
    if (IS_ERR(path)) {
        return (int)PTR_ERR(path);
    }

    ret = xs_error(xs_single(t, XS_MKDIR, path, NULL));
    ExFreePool(path);
    return ret;
}

/* Destroy a file or directory (directories must be empty). */
int
xenbus_rm(struct xenbus_transaction t, const char *dir, const char *node)
{
    char *path;
    int ret;

    path = join(dir, node);
    if (IS_ERR(path)) {
        return (int)PTR_ERR(path);
    }

    ret = xs_error(xs_single(t, XS_RM, path, NULL));
    ExFreePool(path);
    return ret;
}


/*
 * Start a transaction: changes by others will not be seen during this
 * transaction, and changes will not be visible to others until end.
 */
int
xenbus_transaction_start(struct xenbus_transaction *t)
{
    char *id_str;
    ULONG id;

#ifdef DBG
    DBG_WAIT = 1;
    DBG_XS = 1;
#endif
    DPRINTK(DPRTL_XS, ("xenbus_transaction_start: irql %x, cpu %x IN\n",
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    KeEnterCriticalRegion();
    DPRINTK(DPRTL_XS,
            ("xenbus_transaction_start: ExAcquireResourceSharedLite\n"));
    ExAcquireResourceSharedLite(&xs_state.suspend_mutex, TRUE);

    DPRINTK(DPRTL_XS, ("xenbus_transaction_start: xs_single\n"));
    id_str = xs_single(XBT_NIL, XS_TRANSACTION_START, "", NULL);
    if (IS_ERR(id_str)) {
        DPRINTK(DPRTL_XS,
                ("xenbus_transaction_start: ExReleaseResourceLite\n"));
        ExReleaseResourceLite(&xs_state.suspend_mutex);
        DPRINTK(DPRTL_XS, ("xenbus_transaction_start: KeLeaveCritical\n"));
        KeLeaveCriticalRegion();

        DPRINTK(DPRTL_XS, ("xenbus_transaction_start: OUT\n"));
        return (int)PTR_ERR(id_str);
    }

    id = (ULONG)cmp_strtoul(id_str, NULL, 10);
    t->id = id;
    ExFreePool(id_str);
    DPRINTK(DPRTL_XS, ("xenbus_transaction_start: irql %x, cpu %x OUT\n",
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    return 0;
}

/*
 * End a transaction.
 * If abandon is true, transaction is discarded instead of committed.
 */
int
xenbus_transaction_end(struct xenbus_transaction t, int abort)
{
    char abortstr[2];
    int err;

    if (abort) {
        RtlStringCbCopyA(abortstr, 2, "F");
    } else {
        RtlStringCbCopyA(abortstr, 2, "T");
    }

    DPRINTK(DPRTL_XS, ("xenbus_transaction_end: irql %x, cpu %x OUT\n",
                       KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    err = xs_error(xs_single(t, XS_TRANSACTION_END, abortstr, NULL));

    DPRINTK(DPRTL_XS,
            ("xenbus_transaction_end: ExReleaseResourceLite irql %x, cpu %x\n",
             KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    ExReleaseResourceLite(&xs_state.suspend_mutex);
    DPRINTK(DPRTL_XS,
            ("xenbus_transaction_end: KeLeaveCriticalRegion irql %x, cpu %x\n",
             KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    KeLeaveCriticalRegion();

#ifdef DBG
    DBG_WAIT = 0;
    DBG_XS = 0;
#endif
    return err;
}

/* Single printf and write: returns -errno or 0. */
int
xenbus_printf(struct xenbus_transaction t,
    const char *dir, const char *node, const char *fmt, ...)
{
    va_list ap;
    int ret;
    NTSTATUS status;
    char *printf_buffer;

    printf_buffer = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                                  PRINTF_BUFFER_SIZE,
                                  XENBUS_POOL_TAG);
    if (printf_buffer == NULL) {
        return -ENOMEM;
    }

    va_start(ap, fmt);
    status = RtlStringCbVPrintfA(printf_buffer, PRINTF_BUFFER_SIZE, fmt, ap);
    va_end(ap);

    if (status != STATUS_SUCCESS) {
        return -ENOMEM;
    }

    ret = xenbus_write(t, dir, node, printf_buffer);

    ExFreePool(printf_buffer);

    return ret;
}


/* we have to do this in order to mix xenbus and ndis code */
void
xenbus_free_string(char *str)
{
    if (str) {
        ExFreePool(str);
    }
}

static int
xs_watch(const char *path, const char *token)
{
    struct kvec iov[2];

    iov[0].iov_base = (void *)path;
    iov[0].iov_len = strlen(path) + 1;
    iov[1].iov_base = (void *)token;
    iov[1].iov_len = strlen(token) + 1;

    return xs_error(xs_talkv(XBT_NIL, XS_WATCH, iov,
        sizeof(iov) / sizeof(iov[0]), NULL));
}

static int
xs_unwatch(const char *path, const char *token)
{
    struct kvec iov[2];

    iov[0].iov_base = (char *)path;
    iov[0].iov_len = strlen(path) + 1;
    iov[1].iov_base = (char *)token;
    iov[1].iov_len = strlen(token) + 1;

    return xs_error(xs_talkv(XBT_NIL, XS_UNWATCH, iov,
        sizeof(iov) / sizeof(iov[0]), NULL));
}

static struct xenbus_watch *
find_watch(const char *token)
{
    struct xenbus_watch *i, *cmp;
    PLIST_ENTRY li;

    cmp = (struct xenbus_watch *)cmp_strtoul(token, NULL, 16);

    for (li = watches.Flink; li != &watches; li = li->Flink) {
        i = CONTAINING_RECORD(li, struct xenbus_watch, list);
        if ((*(uintptr_t *)&i) == (*(uintptr_t *)&cmp)) {
            return i;
        }
    }

    return NULL;
}

/* Register callback to watch this node. */
int
register_xenbus_watch(struct xenbus_watch *watch)
{
    /* Pointer in ascii is the token. */
    char token[sizeof(watch) * 2 + 1];
    XEN_LOCK_HANDLE lh;
    int err = 0;

    RtlStringCbPrintfA(token, sizeof(token), "%p", watch);

    RPRINTK(DPRTL_ON, ("register_xenbus_watch: %s\n", watch->node));
    RPRINTK(DPRTL_PNP, ("register_xenbus_watch: callback %p, irql %x, cpu %x\n",
                        watch->callback, KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber()));

    XenAcquireSpinLock(&watches_lock, &lh);
    XENBUS_SET_FLAG(xenbus_locks, X_WAT);
    if (find_watch(token) == NULL) {
        InsertHeadList(&watches, &watch->list);

        XENBUS_CLEAR_FLAG(xenbus_locks, X_WAT);
        XenReleaseSpinLock(&watches_lock, lh);
        err = xs_watch(watch->node, token);

        /* Ignore errors due to multiple registration. */
        if ((err != 0) && (err != -EEXIST)) {
            PRINTK(("register_xenbus_watch: err = 0x%x, %d.\n", err, err));
            XenAcquireSpinLock(&watches_lock, &lh);
            XENBUS_SET_FLAG(xenbus_locks, X_WAT);
            RemoveEntryList(&watch->list);
            XENBUS_CLEAR_FLAG(xenbus_locks, X_WAT);
            XenReleaseSpinLock(&watches_lock, lh);
        }
    } else {
        err = -EEXIST;
        RPRINTK(DPRTL_ON,
                ("register_xenbus_watch: watch already registered.\n"));
        XENBUS_CLEAR_FLAG(xenbus_locks, X_WAT);
        XenReleaseSpinLock(&watches_lock, lh);
    }


    RPRINTK(DPRTL_PNP, ("register_xenbus_watch: irql %x, cpu %x OUT %x\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), err));
    return err;
}

void
unregister_xenbus_watch(struct xenbus_watch *watch)
{
    struct xs_stored_msg *msg, *tmp;
    char token[sizeof(watch) * 2 + 1];
    int err;
    XEN_LOCK_HANDLE lh;
    PLIST_ENTRY li, nli;

    RPRINTK(DPRTL_ON, ("XENBUS: unregister_xenbus_watch IN %p\n",
                       watch));
    RtlStringCbPrintfA(token, sizeof(token), "%p", watch);

    XenAcquireSpinLock(&watches_lock, &lh);
    XENBUS_SET_FLAG(xenbus_locks, X_WAT);
    if (!find_watch(token)) {
        PRINTK(("XENBUS: error! trying to unregister noexist watch\n"));
        XENBUS_CLEAR_FLAG(xenbus_locks, X_WAT);
        XenReleaseSpinLock(&watches_lock, lh);
        return;
    }

    RPRINTK(DPRTL_ON, ("XENBUS: unregister_xenbus_watch removing %p\n",
                       watch->callback));
    RemoveEntryList(&watch->list);
    watch->list.Flink = NULL;
    watch->list.Blink = NULL;
    XENBUS_CLEAR_FLAG(xenbus_locks, X_WAT);
    XenReleaseSpinLock(&watches_lock, lh);

    err = xs_unwatch(watch->node, token);
    if (err) {
        PRINTK(("XENBUS: Failed to release watch %s: %i\n",
            watch->node, err));
    }

    /* Cancel pending watch events. */
    XenAcquireSpinLock(&watch_events_lock, &lh);
    XENBUS_SET_FLAG(xenbus_locks, X_WEL);

    li = watch_events.Flink;

    for (; li != &watch_events; li = nli) {
        nli = li->Flink;
        msg = CONTAINING_RECORD(li, struct xs_stored_msg, list);
        if (msg->u.watch.handle != watch) {
            continue;
        }
        RemoveEntryList(&msg->list);
        if (IsListEmpty(&watch_events)) {
            RPRINTK(DPRTL_WAIT,
              ("unregister_xenbus_watch KeClearEvent watch_events_notempty\n"));
            KeClearEvent(&watch_events_notempty);
        }

        ExFreePool(msg->u.watch.vec);
        ExFreePool(msg);
    }

    watch->callback = NULL;
    XENBUS_CLEAR_FLAG(xenbus_locks, X_WAT);
    XenReleaseSpinLock(&watch_events_lock, lh);

    RPRINTK(DPRTL_ON, ("XENBUS: unregister_xenbus_watch OUT\n"));

}

void
xenbus_watch_work(IN PDEVICE_OBJECT DeviceObject, PVOID work_item)
{
    struct xenbus_watch *i;
    PLIST_ENTRY li;
    struct xs_stored_msg *msg;
    XEN_LOCK_HANDLE lh;
    PLIST_ENTRY ent;
    LARGE_INTEGER timeout;

    DPRINTK(DPRTL_WATCH, ("xenbus_watch_work: irql %x, cpu %x IN\n",
                          KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
#ifdef DBG
    msg = NULL;
#endif

    timeout.QuadPart = 0;

    XenAcquireSpinLock(&watch_events_lock, &lh);
    XENBUS_SET_FLAG(xenbus_locks, X_WEL);
    ent = RemoveHeadList(&watch_events);
    while (ent != &watch_events) {
        if (IsListEmpty(&watch_events)) {
            DPRINTK(DPRTL_WAIT,
                    ("xenwatch_thread: KeClearEvent watch_events_notempty\n"));
            KeClearEvent(&watch_events_notempty);
        }
        msg = CONTAINING_RECORD(ent, struct xs_stored_msg, list);

        for (li = watches.Flink; li != &watches; li = li->Flink) {
            i = CONTAINING_RECORD(li, struct xenbus_watch, list);
            if (i->callback == msg->u.watch.handle->callback) {
                DPRINTK(DPRTL_WAIT, ("xenbus_watch: calling callback\n"));
                XENBUS_CLEAR_FLAG(xenbus_locks, X_WEL);
                XenReleaseSpinLock(&watch_events_lock, lh);

                DPRINTK(DPRTL_WATCH,
                   ("xenbus_watch_work: calling callback %p, irql %x, cpu %x\n",
                    msg->u.watch.handle->callback,
                    KeGetCurrentIrql(),
                    KeGetCurrentProcessorNumber()));
                msg->u.watch.handle->callback(msg->u.watch.handle,
                    (const char **)msg->u.watch.vec,
                    msg->u.watch.vec_size);
                DPRINTK(DPRTL_WATCH,
                 ("xenbus_watch_work: back from callback %p, irql %x, cpu %x\n",
                    msg->u.watch.handle->callback,
                    KeGetCurrentIrql(),
                    KeGetCurrentProcessorNumber()));

                XenAcquireSpinLock(&watch_events_lock, &lh);
                XENBUS_SET_FLAG(xenbus_locks, X_WEL);
                break;
            }
        }



        ExFreePool(msg->u.watch.vec);
        ExFreePool(msg);
        ent = RemoveHeadList(&watch_events);
    }
    if (work_item) {
        IoFreeWorkItem((PIO_WORKITEM)work_item);
    }
    xenbus_watch_work_scheduled = 0;
    XENBUS_CLEAR_FLAG(xenbus_locks, X_WEL);
    XenReleaseSpinLock(&watch_events_lock, lh);
#ifdef DBG
    if (msg == NULL) {
        DPRINTK(DPRTL_WATCH,
                ("xenbus_watch: OUT - no watch events to process\n"));
    }
    DPRINTK(DPRTL_WATCH, ("xenbus_watch_work: irql %x, cpu %x OUT\n",
                          KeGetCurrentIrql(),
                          KeGetCurrentProcessorNumber()));
#endif
}

static int
xb_read_fast(void *buf, uint32_t offset, unsigned int len)
{
    struct xenstore_domain_interface *intf = xen_store_interface;
    XENSTORE_RING_IDX cons, prod;
    int rc;
    PUCHAR data = buf;
    unsigned int avail;
    const char *src;

    /* Read indexes, then verify. */
    cons = intf->rsp_cons + offset;
    prod = intf->rsp_prod;
    KeMemoryBarrier();
    if (!xenbus_check_indexes(cons, prod)) {
        intf->rsp_cons = intf->rsp_prod = 0;
        PRINTK(("XENBUS: xenstore ring overflow! reset.\n"));
        return -EIO;
    }

    while (len != 0) {
        src = xenbus_get_input_chunk(cons, prod, intf->rsp, &avail);
        if (avail == 0) {
            /*
             * This can only happen if (prod - cons) < len and
             * this shouldn't happen if the backend only advances
             * after writing the whole chunk.  But if it does happen
             * just returning will eventually cause a re-read and
             * everything should then be ok.
             */
            PRINTK(("XENBUS: xb_read_fast avail == 0.\n"));
            return ENOMEM;
        }
        if (avail > len) {
            avail = len;
        }

        RtlCopyMemory(data, src, avail);
        data += avail;
        len -= avail;
        cons += avail;
    }

    return 0;
}

void
xb_read_msg(void)
{
    struct xenstore_domain_interface *intf = xen_store_interface;
    struct xs_stored_msg *msg;
    char *body;
    XENSTORE_RING_IDX cons, prod;
    int err;

    XEN_LOCK_HANDLE lh;

    DPRINTK(DPRTL_WAIT, ("xb_read_msg: %x IN\n",
                         KeGetCurrentProcessorNumber()));

    if (xen_store_interface == NULL) {
        /* We have not finished initializing yet. */
        DPRINTK(DPRTL_ON, ("xb_read_msg: xen_store_interface is NULL, %x.\n",
                           rtrace));
        return;
    }
    while (TRUE) {
        DPRINTK(DPRTL_WAIT, ("xb_read_msg: top of while\n"));
        cons = intf->rsp_cons;
        prod = intf->rsp_prod;
        KeMemoryBarrier();
        if (prod - cons < sizeof(struct xsd_sockmsg)) {
            DPRINTK(DPRTL_WAIT, ("xb_read_msg: %x no more work - OUT\n",
                                 KeGetCurrentProcessorNumber()));
            return;
        }

        msg = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                            sizeof(*msg),
                            XENBUS_POOL_TAG);
        if (msg == NULL) {
            DPRINTK(DPRTL_WAIT, ("xb_read_msg: %x mem failure - OUT\n",
                                 KeGetCurrentProcessorNumber()));
            return;
        }

        DPRINTK(DPRTL_WAIT, ("xb_read_msg: xb_read_fast hdr\n"));
        err = xb_read_fast(&msg->hdr, 0, sizeof(msg->hdr));
        if (err) {
            ExFreePool(msg);
            DPRINTK(DPRTL_WAIT, ("xb_read_msg: %x mem failure 2 - OUT\n",
                                 KeGetCurrentProcessorNumber()));
            return;
        }

        KeMemoryBarrier();
        if (intf->rsp_prod - (intf->rsp_cons + sizeof(msg->hdr))
                < msg->hdr.len) {
            DPRINTK(DPRTL_WAIT,
                    ("xb_read_msg: header len too big %x, %x, %x, %x\n",
                     msg->hdr.type, msg->hdr.len, msg->hdr.req_id,
                     msg->hdr.tx_id));
            DPRINTK(DPRTL_WAIT,
                    ("xb_read_msg: rsp_prod %x, rsp_cons %x, hdr %x, rslt %x\n",
                     intf->rsp_prod, intf->rsp_cons, sizeof(msg->hdr),
                     intf->rsp_prod - (intf->rsp_cons + sizeof(msg->hdr))));
            ExFreePool(msg);
            return;
        }
        body = EX_ALLOC_POOL(VPOOL_NON_PAGED,
                             (uintptr_t)msg->hdr.len + 1,
                             XENBUS_POOL_TAG);
        if (body == NULL) {
            ExFreePool(msg);
            DPRINTK(DPRTL_WAIT, ("xb_read_msg: %x mem failure 3 - OUT\n",
                                 KeGetCurrentProcessorNumber()));
            return;
        }

        DPRINTK(DPRTL_WAIT, ("xb_read_msg: xb_read_fast body\n"));
        err = xb_read_fast(body, sizeof(msg->hdr), msg->hdr.len);
        if (err) {
            ExFreePool(body);
            ExFreePool(msg);
            DPRINTK(DPRTL_WAIT,
                    ("xb_read_msg: %x xb_read_fast body failure - OUT\n",
                     KeGetCurrentProcessorNumber()));
            return;
        }
        body[msg->hdr.len] = '\0';

        if (msg->hdr.type == XS_WATCH_EVENT) {
            msg->u.watch.vec = split(body, msg->hdr.len,
                                     &msg->u.watch.vec_size);
            if (IS_ERR(msg->u.watch.vec)) {
                /* split already freed body */
                ExFreePool(msg);
                DPRINTK(DPRTL_WAIT, ("xb_read_msg: %x watch failure - OUT\n",
                                     KeGetCurrentProcessorNumber()));
                return;
            }

            XenAcquireSpinLock(&watches_lock, &lh);
            XENBUS_SET_FLAG(xenbus_locks, X_WAT);
            msg->u.watch.handle = find_watch(
                msg->u.watch.vec[XS_WATCH_TOKEN]);
            XENBUS_CLEAR_FLAG(xenbus_locks, X_WAT);
            XenReleaseSpinLock(&watches_lock, lh);
            if (msg->u.watch.handle != NULL) {
                XenAcquireSpinLock(&watch_events_lock, &lh);
                XENBUS_SET_FLAG(xenbus_locks, X_WEL);
                InsertTailList(&watch_events, &msg->list);
                XENBUS_CLEAR_FLAG(xenbus_locks, X_WEL);
                XenReleaseSpinLock(&watch_events_lock, lh);
                DPRINTK(DPRTL_WAIT,
                        ("xb_read_msg: signaling watch_events_notempty\n"));
                KeSetEvent(&watch_events_notempty, 0, FALSE);
            } else {
                ExFreePool(msg->u.watch.vec);
                ExFreePool(msg);
                msg = NULL;
            }
        } else {
            msg->u.reply.body = body;
            XenAcquireSpinLock(&xs_state.reply_lock, &lh);
            XENBUS_SET_FLAG(xenbus_locks, X_RPL);
            InsertTailList(&xs_state.reply_list, &msg->list);
            XENBUS_CLEAR_FLAG(xenbus_locks, X_RPL);
            XenReleaseSpinLock(&xs_state.reply_lock, lh);
            DPRINTK(DPRTL_WAIT, ("xb_read_msg: signaling xs_state\n"));
            KeSetEvent(&xs_state.reply_list_notempty, 0, FALSE);
        }

        /* Other side must not see free space until we've copied out */
        KeMemoryBarrier();
        if (msg) {
            intf->rsp_cons += sizeof(msg->hdr) + msg->hdr.len;
        }

        /* Implies mb(): they will see new header. */
        notify_remote_via_evtchn(xen_store_evtchn);
    }
    DPRINTK(DPRTL_WAIT, ("xb_read_msg: OUT\n"));
}

static void
xenbus_suspend(PFDO_DEVICE_EXTENSION fdx, uint32_t reason)
{
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;
    pv_ioctl_t ioctl_data;
    LARGE_INTEGER timeout;
    uint32_t waiting_cnt;
    xen_long_t suspend_canceled;

    PRINTK(("xenbus_suspend: irql %d, cpu %d, reason %d.\n",
        KeGetCurrentIrql(), KeGetCurrentProcessorNumber(), reason));

    ioctl_data.cmd = PV_SUSPEND;
    ioctl_data.arg = (uint16_t)reason;
    timeout.QuadPart = -10000000; /* 1 second */

    /* Suspend the vnifs first. */
    for (entry = fdx->ListOfPDOs.Flink;
        entry != &fdx->ListOfPDOs;
        entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if (pdx->Type == vnif && pdx->frontend_dev) {
            PRINTK(("xenbus_suspend: suspending %p, %s.\n",
                pdx->frontend_dev, pdx->Nodename));
            waiting_cnt = 0;
            while (pdx->ioctl(pdx->frontend_dev, ioctl_data)
                    && waiting_cnt < delayed_resource_try_cnt) {
                PRINTK(("xenbus_suspend: suspending %p, %s, cnt %d.\n",
                    pdx->frontend_dev, pdx->Nodename, waiting_cnt));
                KeDelayExecutionThread(KernelMode, FALSE, &timeout);
                waiting_cnt++;
            }
        }
    }

    for (entry = fdx->ListOfPDOs.Flink;
            entry != &fdx->ListOfPDOs;
            entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if ((pdx->Type == vbd || pdx->Type == vscsi || pdx->Type == vusb)
                && pdx->frontend_dev) {
            PRINTK(("xenbus_suspend: suspending %p, %s.\n",
                pdx->frontend_dev, pdx->Nodename));
            pdx->ioctl(pdx->controller, ioctl_data);
        }
    }

    /* Clear out any DPCs that may have been scheduled. */
    evtchn_remove_queue_dpc();

    /* Do the actual suspend. */
    PRINTK(("xenbus_suspend: HYPERVISOR_shutdown/suspend irql %d, reason %d.\n",
               KeGetCurrentIrql(), reason));
    RPRINTK(DPRTL_ON,
            ("xenbus_suspend: mmio %llx mem %p\n\tmmio_len %x shared %p\n",
             fdx->mmio, fdx->mem, fdx->mmiolen, shared_info_area));
    RPRINTK(DPRTL_ON,
        ("\tLowerDevice %p\n", fdx->LowerDevice));

    xenbus_prepare_shared_for_init(fdx, SHARED_INFO_NOT_INITIALIZED);

    if (pvctrl_flags & XENBUS_PVCTRL_MIGRATE_DO_INTERRUPTS) {
        /*
         * Disconnect the interrupt so we won't be called on resume before we
         * can get everything reinitialized.
         */
        PRINTK(("xenbus_suspend: IoDisconnectInterrupt\n"));
        IoDisconnectInterrupt(DriverInterruptObj);
    }

    if (reason == SHUTDOWN_suspend) {
        suspend_canceled = HYPERVISOR_suspend(0);
    } else {
        suspend_canceled = HYPERVISOR_shutdown(reason);
    }

    PRINTK(("xenbus_suspend: resuming irql %d cpu %d reason %d canceled %d\n",
            KeGetCurrentIrql(), KeGetCurrentProcessorNumber(),
            reason, suspend_canceled));
    /* Start things back up again based on suspend_canceled. */
    ioctl_data.cmd = PV_RESUME;
    ioctl_data.arg = (uint16_t)suspend_canceled;


    /* Start up the vbd in reverse order first. */
    RPRINTK(DPRTL_ON,
           ("xenbus_suspend: after mmio %llx mem %p\n\tmmio_len %x shared %p\n",
            fdx->mmio, fdx->mem, fdx->mmiolen, shared_info_area));
    if (suspend_canceled == 0) {
        xenbus_prepare_shared_for_init(fdx, SHARED_INFO_MIGRATING);
        PRINTK(("xenbus_suspend: xenbus_xen_shared_init\n"));
        xenbus_xen_shared_init(fdx->mmio, fdx->mem, fdx->mmiolen,
            fdx->dvector, OP_MODE_NORMAL);
    }


    if (pvctrl_flags & XENBUS_PVCTRL_MIGRATE_DO_INTERRUPTS) {
        /* Structures have been reinitialized.  Reconnect the interrupt. */
        PRINTK(("xenbus_suspend: IoConnectInterrupt v %x i_irql %x d_vec %x\n",
            fdx->vector, fdx->irql, fdx->dvector));
        IoConnectInterrupt(
            &DriverInterruptObj,
            XenbusOnInterrupt,
            (PVOID) fdx,
            NULL,
            fdx->vector,
            (KIRQL)fdx->irql,
            (KIRQL)fdx->irql,
            LevelSensitive,
            TRUE,
            fdx->affinity,
            FALSE);
    }

    PRINTK(("xenbus_suspend: set_callback_irq\n"));
    set_callback_irq(fdx->dvector);

    for (entry = fdx->ListOfPDOs.Blink;
            entry != &fdx->ListOfPDOs;
            entry = entry->Blink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        RPRINTK(DPRTL_ON,
                ("xenbus_suspend: checking %s type %d fdev %p irql %d.\n",
                 pdx->Nodename, pdx->Type, pdx->frontend_dev,
                 KeGetCurrentIrql()));
        if ((pdx->Type == vbd || pdx->Type == vscsi || pdx->Type == vusb)
                && pdx->frontend_dev) {
            RPRINTK(DPRTL_ON, ("xenbus_suspend: %p, srt [0] %p, [1] %p\n",
                               fdx, fdx->info[0], fdx->info[1]));
            PRINTK(("xenbus_suspend: resuming %p, %s with %x, irql %d.\n",
                pdx->frontend_dev, pdx->Nodename, ioctl_data.arg,
                KeGetCurrentIrql()));
            pdx->ioctl(pdx->controller, ioctl_data);
            RPRINTK(DPRTL_ON, ("xenbus_suspend: back %p, srt [0] %p, [1] %p\n",
                               fdx, fdx->info[0], fdx->info[1]));
        }
    }

    PRINTK(("xenbus_suspend: all disks resumed: irql %d, reason %d.\n",
            KeGetCurrentIrql(), reason));

    /* Start up all the vnifs. */
    for (entry = fdx->ListOfPDOs.Flink;
        entry != &fdx->ListOfPDOs;
        entry = entry->Flink) {
        pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
        if (pdx->Type == vnif && pdx->frontend_dev) {
            PRINTK(("xenbus_suspend: resuming %p, %s with %x, irql %d.\n",
                    pdx->frontend_dev, pdx->Nodename, ioctl_data.arg,
                    KeGetCurrentIrql()));
            pdx->ioctl(pdx->frontend_dev, ioctl_data);
        }
    }
    PRINTK(("xenbus_suspend: completed - irql %d.\n", KeGetCurrentIrql()));
    RPRINTK(DPRTL_ON, ("xenbus_suspend: done %p, srt [0] %p, [1] %p\n",
                       fdx, fdx->info[0], fdx->info[1]));
}

static void
xenbus_shutdown(PFDO_DEVICE_EXTENSION fdx, uint32_t reason)
{
    XEN_LOCK_HANDLE lh;
    xenbus_register_shutdown_event_t *ioctl;
    PIRP irp;
    PLIST_ENTRY ent;
    HANDLE registryKey;
    UNICODE_STRING valueName;
    NTSTATUS status;
    NTSTATUS open_key_status;
    uint32_t resultLength;
    uint32_t notify;
    uint32_t shutdown;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(uint32_t)];

    RPRINTK(DPRTL_ON, ("==> xenbus_shutdown: irql %x\n",
                       KeGetCurrentIrql()));

    /*
     * Check the registry to see if anyone expects to be notified of a
     * shutdown via the registry.
     */
    notify = XENBUS_UNDEFINED_SHUTDOWN_NOTIFICATION;
    open_key_status = xenbus_open_key(XENBUS_FULL_DEVICE_KEY_WSTR,
        &registryKey);
    if (NT_SUCCESS(open_key_status)) {
        RtlInitUnicodeString(&valueName, XENBUS_SHUTDOWN_NOTIFICATION_WSTR);

        status = ZwQueryValueKey(registryKey,
            &valueName,
            KeyValuePartialInformation,
            buffer,
            sizeof(buffer),
            &resultLength);

        if (NT_SUCCESS(status)) {
            notify = *((PULONG)
                &(((PKEY_VALUE_PARTIAL_INFORMATION) buffer)->Data));
        }
    }

    if (IsListEmpty(&fdx->shutdown_requests)
        && (notify == XENBUS_UNDEFINED_SHUTDOWN_NOTIFICATION
            || notify == XENBUS_NO_SHUTDOWN_NOTIFICATION)) {
        /* No one is listening for this shutdown.  Do the best we can.*/
        RPRINTK(DPRTL_ON, ("    xenbus_shutdown calling xenbus_suspend\n"));

        if (NT_SUCCESS(open_key_status)) {
            ZwClose(registryKey);
        }
        xenbus_suspend(fdx, reason);
        return;
    }

#ifdef XENBUS_HAS_IOCTLS
    XenAcquireSpinLock(&fdx->qlock, &lh);
    while (!IsListEmpty(&fdx->shutdown_requests)) {
        ent = RemoveHeadList(&fdx->shutdown_requests);
        ioctl = CONTAINING_RECORD(ent, xenbus_register_shutdown_event_t, list);
        irp = ioctl->irp;
        if (irp != NULL) {
            if (IoSetCancelRoutine(irp, NULL) != NULL) {
                ioctl->shutdown_type = reason;
                RPRINTK(DPRTL_ON,
                        ("    xenbus_shutdown in shutdown_type = %x\n",
                         ioctl->shutdown_type));
                irp->Tail.Overlay.DriverContext[3] = NULL;
                irp->IoStatus.Status = STATUS_SUCCESS;
                irp->IoStatus.Information =
                    sizeof(xenbus_register_shutdown_event_t);
                XenReleaseSpinLock(&fdx->qlock, lh);
                IoCompleteRequest(irp, IO_NO_INCREMENT);
                XenAcquireSpinLock(&fdx->qlock, &lh);
            } else {
                /*
                 * Cancel routine will run as soon as we release the lock.
                 * So let it complete the request and free the record.
                 */
                RPRINTK(DPRTL_ON,
                        ("    xenbus_shutdown: IoSetCancelRoutine failed\n"));
                InitializeListHead(&ioctl->list);
            }
        }
    }
    XenReleaseSpinLock(&fdx->qlock, lh);
#endif

    if (notify == XENBUS_WANTS_SHUTDOWN_NOTIFICATION) {
        reason++;
        RPRINTK(DPRTL_ON,
                ("    xenbus_shutdown: writing reg shutdown reason %x\n",
                 reason));
        xenbus_shutdown_setup(&reason, NULL);
    }
    if (NT_SUCCESS(open_key_status)) {
        ZwClose(registryKey);
    }

    RPRINTK(DPRTL_ON, ("<== xenbus_shutdown\n"));
    return;
}

static NTSTATUS
hotplug_handler(PFDO_DEVICE_EXTENSION fdx, char *device, char *node,
    char *subnode)
{
    LARGE_INTEGER timeout;
    PPDO_DEVICE_EXTENSION pdx;
    char *buf;
    uint32_t backend_state;
    uint32_t len;
    uint32_t i;
    uint32_t start;

    RPRINTK(DPRTL_PNP, ("hotplug_handler called: %s.\n", node));

    if (gfdo == NULL) {
        PRINTK(("hotplug_handler: %s, gfdo is NULL\n", node));
        return STATUS_UNSUCCESSFUL;
    }

    if (device[1] == 's') {
        start = 13; /* device/vscsi */
    } else if (device[1] == 'u') {
        start = 12; /* device/vusb */
    } else {
        start = 11; /* device/vbd or device/vif */
    }

    len = strlen(node);
    for (i = start; i < len && node[i] != '/'; i++) {
        ;
    }

    node[i] = '\0';
    if (xenbus_find_pdx_from_nodename(fdx, node)) {
        RPRINTK(DPRTL_PNP, ("hotplug_handler: %s already exists.\n",
                            node));
        return STATUS_UNSUCCESSFUL;
    }

    RPRINTK(DPRTL_PNP, ("hotplug_handler: %s is new, node %s.\n",
                        node, &node[i + 1]));
    if (strcmp(&node[i + 1], "backend") != 0) {
        return STATUS_UNSUCCESSFUL;
    }

    RPRINTK(DPRTL_PNP, ("hotplug_handler: %s is ready.\n", node));
    if (XenbusInitializePDO(gfdo, device, node, subnode) != STATUS_SUCCESS) {
        PRINTK(("hotplug_handler: Failed to initialized %s.\n", node));
        return STATUS_UNSUCCESSFUL;
    }

    pdx = xenbus_find_pdx_from_nodename(fdx, node);
    if (pdx == NULL) {
        PRINTK(("hotplug_handler: %s could not find pdx.\n", node));
        return STATUS_UNSUCCESSFUL;
    }

    timeout.QuadPart = -1000000; /* .1 second */
    for (i = 0; i < 50; i++) {
        buf = xenbus_read(XBT_NIL, pdx->Otherend, "state", NULL);
        if (buf) {
            backend_state = (enum xenbus_state)cmp_strtoul(buf, NULL, 10);
            xenbus_free_string(buf);
            if (backend_state == XenbusStateInitWait) {
                RPRINTK(DPRTL_PNP, ("hotplug_handler: %s ready.\n",
                                    node));
                return STATUS_SUCCESS;
            }
        }
        PRINTK(("hotplug_handler: %s waiting to become ready.\n",
            node));
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }
    return STATUS_UNSUCCESSFUL;
}

static void
vbd_handler(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)watch->context;
    PPDO_DEVICE_EXTENSION pdx;
    PLIST_ENTRY entry;
    pv_ioctl_t ioctl_data;
    int found;

    RPRINTK(DPRTL_ON, ("vbd_handler: %s\n", (char *)vec[0]));
    if (hotplug_handler(fdx, "vbd", (char *)vec[0], NULL) == STATUS_SUCCESS) {
        if (!(pvctrl_flags & XENBUS_PVCTRL_USE_JUST_ONE_CONTROLLER)) {
            RPRINTK(DPRTL_ON,
                    ("vbd_handler: calling IoInvalidateDeviceRelations\n"));
            RPRINTK(DPRTL_ON, ("  %s\n", (char *)vec[0]));
            IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);
        } else {
            for (found = 0, entry = fdx->ListOfPDOs.Flink;
                    entry != &fdx->ListOfPDOs;
                    entry = entry->Flink) {
                pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
                if (pdx->Type == vbd && pdx->frontend_dev
                        && pdx->ioctl && pdx->controller) {
                    ioctl_data.cmd = PV_ATTACH;
                    ioctl_data.arg = 0;
                    RPRINTK(DPRTL_ON, ("vbd_handler: calling pdx->ioctl\n"));
                    pdx->ioctl(pdx->controller, ioctl_data);
                    found++;
                    break;
                }
            }
            if (!found) {
                /* Must be the first one. */
                RPRINTK(DPRTL_ON,
                        ("vbd_handler: calling IoInvalidateDeviceRelations\n"));
                IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);
            }
        }
    }
}

static void
vscsi_handler(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)watch->context;
    PPDO_DEVICE_EXTENSION pdx;
    pv_ioctl_t ioctl_data;

    if (hotplug_handler(fdx, "vscsi", (char *)vec[0], NULL) == STATUS_SUCCESS) {
        RPRINTK(DPRTL_ON, ("vscsi_handler: IoInvalidateDeviceRelations\n"));
        IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);

        pdx = xenbus_find_pdx_from_nodename(fdx, (char *)vec[0]);
        if (pdx) {
            if (pdx->ioctl && pdx->controller) {
                ioctl_data.cmd = PV_ATTACH;
                ioctl_data.arg = 0;
                RPRINTK(DPRTL_ON, ("vscsi_handler: calling pdx->ioctl\n"));
                pdx->ioctl(pdx->controller, ioctl_data);
            }
        }
    }
}

static void
vusb_handler(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)watch->context;
    PPDO_DEVICE_EXTENSION pdx;
    pv_ioctl_t ioctl_data;

    if (hotplug_handler(fdx, "vusb", (char *)vec[0], NULL) == STATUS_SUCCESS) {
        PRINTK(("vusb_handler: IoInvalidateDeviceRelations\n"));
        IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);

        pdx = xenbus_find_pdx_from_nodename(fdx, (char *)vec[0]);
        if (pdx) {
            if (pdx->ioctl && pdx->controller) {
                ioctl_data.cmd = PV_ATTACH;
                ioctl_data.arg = 0;
                PRINTK(("vusb_handler: calling pdx->ioctl\n"));
                pdx->ioctl(pdx->controller, ioctl_data);
            }
        }
    }
}

static void
vif_handler(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)watch->context;

    if (hotplug_handler(fdx, "vif", (char *)vec[0], NULL) == STATUS_SUCCESS) {
        IoInvalidateDeviceRelations(fdx->Pdo, BusRelations);
    }
}

static void
shutdown_handler(struct xenbus_watch *watch,
    const char **vec, unsigned int len)
{
    PFDO_DEVICE_EXTENSION fdx = (PFDO_DEVICE_EXTENSION)watch->context;
    xenbus_pv_port_options_t options;
    char *str;
    NTSTATUS status;
    struct xenbus_transaction xbt;
    int err;

    if (shutting_down != SHUTDOWN_INVALID) {
        RPRINTK(DPRTL_ON,
                ("shutdown_handler called while shutting_down = %x.\n",
                 shutting_down));
        return;
    }

 again:
    err = xenbus_transaction_start(&xbt);
    if (err) {
        RPRINTK(DPRTL_ON,
                ("shutdown_handler xenbus_transaction_start failed %x\n", err));
        return;
    }

    str = (char *)xenbus_read(xbt, "control", "shutdown", NULL);
    /* Ignore read errors and empty reads. */
    if (IS_ERR(str) || str == NULL) {
        xenbus_transaction_end(xbt, 1);
        RPRINTK(DPRTL_ON,
                ("shutdown_handler %p: empty or NULL irql = %d, cpu = %d.\n",
                 shutdown_handler, KeGetCurrentIrql(),
                 KeGetCurrentProcessorNumber()));
        return;
    }

    if (str[0] != '\0') {
        /*
         * By writing to the control, the watch will fire again.
         * Don't write the null string if it is already NULL.
         */
        xenbus_write(xbt, "control", "shutdown", "");
    }

    err = xenbus_transaction_end(xbt, 0);
    if (err == -EAGAIN) {
        xenbus_free_string(str);
        goto again;
    }

    PRINTK(("shutdown_handler: shutdown request is: %s\n", str));
    if (strcmp(str, "poweroff") == 0) {
        shutting_down = SHUTDOWN_poweroff;
        xenbus_shutdown(fdx, shutting_down);
    } else if (strcmp(str, "halt") == 0) {
        shutting_down = SHUTDOWN_poweroff;
        xenbus_shutdown(fdx, shutting_down);
    } else if (strcmp(str, "reboot") == 0) {
        shutting_down = SHUTDOWN_reboot;
        xenbus_shutdown(fdx, shutting_down);
    } else if (strcmp(str, "suspend") == 0) {
        shutting_down = SHUTDOWN_suspend;
        xenbus_suspend(fdx, shutting_down);
    } else {
        RPRINTK(DPRTL_ON, ("shutdown_handler: Ignoring shutdown request: %s\n",
                           str));
        shutting_down = SHUTDOWN_INVALID;
    }

    xenbus_free_string(str);

    /* Reset so we can do another flavor of shutdiown. */
    shutting_down = SHUTDOWN_INVALID;
}

NTSTATUS xs_finish_init(PDEVICE_OBJECT fdo, uint32_t reason)
{
    PFDO_DEVICE_EXTENSION fdx;
    NTSTATUS status;

    if (reason != OP_MODE_NORMAL) {
        return STATUS_SUCCESS;
    }

    fdx = (PFDO_DEVICE_EXTENSION) fdo->DeviceExtension;
    shutdown_watch.callback = shutdown_handler;
    shutdown_watch.node = "control/shutdown";
    shutdown_watch.flags = XBWF_new_thread;
    shutdown_watch.context = fdx;
    register_xenbus_watch(&shutdown_watch);

    vbd_watch.callback = vbd_handler;
    vbd_watch.node = "device/vbd";
    vbd_watch.flags = XBWF_new_thread;
    vbd_watch.context = fdx;
    register_xenbus_watch(&vbd_watch);

    vif_watch.callback = vif_handler;
    vif_watch.node = "device/vif";
    vif_watch.flags = XBWF_new_thread;
    vif_watch.context = fdx;
    register_xenbus_watch(&vif_watch);

    vscsi_watch.callback = vscsi_handler;
    vscsi_watch.node = "device/vscsi";
    vscsi_watch.flags = XBWF_new_thread;
    vscsi_watch.context = fdx;
    register_xenbus_watch(&vscsi_watch);

    vusb_watch.callback = vusb_handler;
    vusb_watch.node = "device/vusb";
    vusb_watch.flags = XBWF_new_thread;
    vusb_watch.context = fdx;
    register_xenbus_watch(&vusb_watch);

    RPRINTK(DPRTL_ON, ("xs_finish_init: register_dpc_to_evtchn %x.\n",
        xen_store_evtchn));
    status = register_dpc_to_evtchn(xen_store_evtchn,
        XenbusDpcRoutine, fdo, NULL);

    if (!NT_SUCCESS(status)) {
        PRINTK(("XENBUS: request Dpc failed.\n"));
    }
    return status;
}

NTSTATUS xs_init(FDO_DEVICE_EXTENSION *fdx, uint32_t reason)
{
    PHYSICAL_ADDRESS store_addr;
    unsigned long xen_store_mfn;

    RPRINTK(DPRTL_ON, ("xs_init: fdx %p, reason %x.\n",
        fdx, reason));
    if (reason == OP_MODE_CRASHDUMP) {
        xen_store_interface = NULL;
        return STATUS_SUCCESS;
    }
    if (reason == OP_MODE_HIBERNATE) {
        xen_store_interface = fdx->xsif;
    } else { /* reason == OP_MODE_NORMAL */
        xen_store_mfn = (unsigned long)hvm_get_parameter(HVM_PARAM_STORE_PFN);
        store_addr.QuadPart = (UINT64) xen_store_mfn << PAGE_SHIFT;
        RPRINTK(DPRTL_ON, ("\txen_store_mfn %lx\n",
            xen_store_mfn));

        if (xen_store_interface) {
            RPRINTK(DPRTL_ON, ("\tunmapping xen_store_interface: %p.\n",
                               xen_store_interface));
            MmUnmapIoSpace(xen_store_interface, PAGE_SIZE);
        }
        xen_store_interface = mm_map_io_space(store_addr,
                                              PAGE_SIZE,
                                              MmNonCached);
        if (xen_store_interface == NULL) {
            PRINTK(("XENBUS: failed to map xenstore page, pfn: %x!\n",
                xen_store_mfn));
                return STATUS_NO_MEMORY;
        }
        RPRINTK(DPRTL_ON, ("\txen_store_interface %p\n", xen_store_interface));
        fdx->xsif = xen_store_interface;
    }

    xen_store_evtchn = (int)hvm_get_parameter(HVM_PARAM_STORE_EVTCHN);
    RPRINTK(DPRTL_ON, ("\txen_store_evtchn = %x\n", xen_store_evtchn));

    InitializeListHead(&watches);
    InitializeListHead(&watch_events);
    InitializeListHead(&xs_state.reply_list);

    /* Reinitializing a lock may cause a deadlock. */
    if (xs_state.reply_lock == 0xbad) {
        ExReinitializeResourceLite(&xs_state.suspend_mutex);
        KeInitializeMutex(&xs_state.request_mutex, 0);
        KeInitializeSpinLock(&xs_state.reply_lock);
        KeInitializeSpinLock(&watches_lock);
        KeInitializeSpinLock(&watch_events_lock);
        KeInitializeSpinLock(&xs_lock);
        KeInitializeSpinLock(&xenbus_dpc_lock);

        KeInitializeEvent(&xs_state.reply_list_notempty,
                          NotificationEvent,    FALSE);
        KeInitializeEvent(&thread_xenwatch_kill, NotificationEvent, FALSE);
        KeInitializeEvent(&thread_xenbus_kill, NotificationEvent, FALSE);
        KeInitializeEvent(&watch_events_notempty, NotificationEvent, FALSE);
        KeInitializeEvent(&xb_event, NotificationEvent, FALSE);
    }

    KeClearEvent(&xs_state.reply_list_notempty);
    KeClearEvent(&thread_xenwatch_kill);
    KeClearEvent(&thread_xenbus_kill);
    KeClearEvent(&watch_events_notempty);
    KeClearEvent(&xb_event);

    xenbus_watch_work_scheduled = 0;

    RPRINTK(DPRTL_ON, ("xs_init: suspend_mutex %p OUT\n",
                       &xs_state.suspend_mutex));
    return STATUS_SUCCESS;
}

VOID xs_cleanup(void)
{
    unregister_xenbus_watch(&vbd_watch);
    vbd_watch.node = NULL;

    unregister_xenbus_watch(&vif_watch);
    vif_watch.node = NULL;

    unregister_xenbus_watch(&shutdown_watch);
    shutdown_watch.node = NULL;

    unregister_xenbus_watch(&vscsi_watch);
    vscsi_watch.node = NULL;

    unregister_xenbus_watch(&vusb_watch);
    vusb_watch.node = NULL;

    if (xen_store_evtchn) {
        RPRINTK(DPRTL_ON, ("xs_cleanup: unregister_dpc_from_evtchn %d.\n",
                           xen_store_evtchn));
        unregister_dpc_from_evtchn(xen_store_evtchn);
    }
    KeSetEvent(&xb_event, 0, FALSE);
}

void
xenbus_debug_dump(void)
{
    FDO_DEVICE_EXTENSION *fdx;
    PLIST_ENTRY entry;
    PPDO_DEVICE_EXTENSION pdx;
    pv_ioctl_t ioctl_data;

    shared_info_t *s;
    vcpu_info_t *v;
    struct xenstore_domain_interface *intf;

    s = shared_info_area;
    if (!s) {
        PRINTK(("\n*** xenbus state dump: shard_info_area not setup.\n"));
        return;
    }
    v = &s->vcpu_info[0];
    if (!v) {
        PRINTK(("\n*** xenbus state dump: vcpu_info not setup.\n"));
        return;
    }
    v->evtchn_upcall_pending = 0;
    intf = xen_store_interface;

    PRINTK(("*** xenbus state dump: irql %d, cpu %d\n",
            KeGetCurrentIrql(), KeGetCurrentProcessorNumber()));
    PRINTK(("\tshared_info: evtchn_mask %x, evtchn_pending %x\n",
            s->evtchn_mask[0], s->evtchn_pending[0]));

    PRINTK(("\tvcpu: pending_sel %x, upcall_mask %x, upcall_pending %x\n",
            v->evtchn_pending_sel, v->evtchn_upcall_mask,
            v->evtchn_upcall_pending));
    if (intf) {
        PRINTK(("\tinterface: req_cons %x, req_prod %x\n",
                intf->req_cons, intf->req_prod));
        PRINTK(("\tinterface: rsp_cons %x, rsp_prod %x\n",
                intf->rsp_cons, intf->rsp_prod));
    }
    PRINTK(("\tIsListEmpty: watch_events %x, xs_state %x\n",
            IsListEmpty(&watch_events), IsListEmpty(&xs_state.reply_list)));
#ifdef DBG
    PRINTK(("\tints %d, ints clained %d\n", cpu_ints, cpu_ints_claimed));
    PRINTK(("\trtrace flags %x\n", rtrace));
    PRINTK(("\twe %x ws %x wl %x gfdo %p***\n",
            xenbus_wait_events, xenbus_watch_work_scheduled,
            xenbus_locks, gfdo));
    if (s->evtchn_pending[0] || v->evtchn_pending_sel) {
        PRINTK(("\tSetting evt_print to 1\n"));
        evt_print = 1;
    }

    if (gfdo) {
        fdx = (PFDO_DEVICE_EXTENSION) gfdo->DeviceExtension;
        ioctl_data.arg = (uint16_t)SHUTDOWN_reboot;
        ioctl_data.cmd = PV_ATTACH;
        for (entry = fdx->ListOfPDOs.Flink;
                entry != &fdx->ListOfPDOs;
                entry = entry->Flink) {
            pdx = CONTAINING_RECORD(entry, PDO_DEVICE_EXTENSION, Link);
            PRINTK(("\t pdx: %s, type = %d, fdev = %p\n",
                pdx->Nodename, pdx->Type, pdx->frontend_dev));
            if (pdx->Type == vnif && pdx->frontend_dev) {
                PRINTK(("\t call xennet to do an arp: %s\n", pdx->Nodename));
                pdx->ioctl(pdx->frontend_dev, ioctl_data);
            }
        }
    }
#endif
}
