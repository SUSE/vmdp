/*
 * Virtio PCI driver
 *
 * This module allows virtio devices to be used over a virtual PCI device.
 * This can be used with QEMU based VMMs like KVM or Xen.
 *
 * Copyright IBM Corp. 2007
 *
 * Authors:
 *  Anthony Liguori  <aliguori@us.ibm.com>
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 */

#ifndef _LINUX_VIRTIO_PCI_H
#define _LINUX_VIRTIO_PCI_H

#include <virtio_config.h>
#include <virtio_ring.h>

/* A 32-bit r/o bitmask of the features supported by the host */
#define VIRTIO_PCI_HOST_FEATURES    0

/* A 32-bit r/w bitmask of features activated by the guest */
#define VIRTIO_PCI_GUEST_FEATURES   4

/* A 32-bit r/w PFN for the currently selected queue */
#define VIRTIO_PCI_QUEUE_PFN        8

/* A 16-bit r/o queue size for the currently selected queue */
#define VIRTIO_PCI_QUEUE_NUM        12

/* A 16-bit r/w queue selector */
#define VIRTIO_PCI_QUEUE_SEL        14

/* A 16-bit r/w queue notifier */
#define VIRTIO_PCI_QUEUE_NOTIFY     16

/* An 8-bit device status register.  */
#define VIRTIO_PCI_STATUS       18

/*
 * An 8-bit r/o interrupt status register.  Reading the value will return the
 * current contents of the ISR and will also clear it.  This is effectively
 * a read-and-acknowledge.
 */
#define VIRTIO_PCI_ISR          19

/* The bit of the ISR which indicates a device configuration change. */
#define VIRTIO_PCI_ISR_CONFIG       0x2

/* MSI-X registers: only enabled if MSI-X is enabled. */
/* A 16-bit vector for configuration changes. */
#define VIRTIO_MSI_CONFIG_VECTOR        20
/* A 16-bit vector for selected queue notifications. */
#define VIRTIO_MSI_QUEUE_VECTOR         22
/* Vector value used to disable MSI for queue */
#define VIRTIO_MSI_NO_VECTOR            0xffff

/* The remaining space is defined by each driver as the per-driver */
/* configuration space */
#define VIRTIO_PCI_CONFIG 20
#define VIRTIO_PCI_CONFIG_MSI_OFFSET 4

/* Virtio ABI version, this must match exactly */
#define VIRTIO_PCI_ABI_VERSION      0

/* How many bits to shift physical queue address written to QUEUE_PFN. */
/* 12 is historical, and due to x86 page size. */
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT 12

/* The alignment to use between consumer and producer parts of vring. */
/* x86 pagesize again. */
#define VIRTIO_PCI_VRING_ALIGN      PAGE_SIZE

#define LEGACY_VRING_ALIGN PAGE_SIZE
#define MODERN_VRING_ALIGN 64

#define SMP_CACHE_BYTES 64
#define CACHE_LINE_SIZE 64
#define ROUND_TO_CACHE_LINES(Size)  (((ULONG_PTR)(Size) + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1))
#define ROUND_TO_VIRTIO_ALIGN(_v, _s)                                       \
    (((ULONG_PTR)                                                           \
        (_s) + ((_v)->addr ? LEGACY_VRING_ALIGN : MODERN_VRING_ALIGN) - 1)  \
    & ~(((_v)->addr ? LEGACY_VRING_ALIGN : MODERN_VRING_ALIGN) - 1))

#define IS_BIT_SET(_value, _bit) (((_value) & (1 << (_bit))) != 0)

/* IDs for different capabilities.  Must all exist. */

/* Common configuration */
#define VIRTIO_PCI_CAP_COMMON_CFG   1
/* Notifications */
#define VIRTIO_PCI_CAP_NOTIFY_CFG   2
/* ISR access */
#define VIRTIO_PCI_CAP_ISR_CFG      3
/* Device specific configuration */
#define VIRTIO_PCI_CAP_DEVICE_CFG   4
/* PCI configuration access */
#define VIRTIO_PCI_CAP_PCI_CFG      5

#define MAX_QUEUES_PER_DEVICE_DEFAULT   8
#define PORT_MASK 0xFFFF

#define VIRTIO_BLK_MSIX_CONFIG_VECTOR   0

/* This is the PCI capability header: */
typedef struct virtio_pci_cap_s {
    uint8_t cap_vndr;      /* PCI field: PCI_CAPABILITY_ID_VENDOR_SPECIFIC */
    uint8_t cap_next;      /* Generic PCI field: next ptr. */
    uint8_t cap_len;       /* Generic PCI field: capability length */
    uint8_t cfg_type;      /* Identifies the structure. */
    uint8_t bar;           /* Where to find it. */
    uint8_t padding[3];    /* Pad to full dword. */
    uint32_t offset;      /* Offset within bar. */
    uint32_t length;      /* Length of the structure, in bytes. */
} virtio_pci_cap_t;

typedef struct virtio_pci_notify_cap_s {
    virtio_pci_cap_t cap;
    uint32_t notify_off_multiplier;   /* Multiplier for queue_notify_off. */
} virtio_pci_notify_cap_t;

/* Fields in VIRTIO_PCI_CAP_COMMON_CFG: */
typedef struct virtio_pci_common_cfg_s {
    /* About the whole device. */
    uint32_t device_feature_select;   /* read-write */
    uint32_t device_feature;          /* read-only */
    uint32_t guest_feature_select;    /* read-write */
    uint32_t guest_feature;           /* read-write */
    uint16_t msix_config;             /* read-write */
    uint16_t num_queues;              /* read-only */
    uint8_t device_status;             /* read-write */
    uint8_t config_generation;         /* read-only */

    /* About a specific virtqueue. */
    uint16_t queue_select;            /* read-write */
    uint16_t queue_size;              /* read-write, power of 2. */
    uint16_t queue_msix_vector;       /* read-write */
    uint16_t queue_enable;            /* read-write */
    uint16_t queue_notify_off;        /* read-only */
    uint32_t queue_desc_lo;           /* read-write */
    uint32_t queue_desc_hi;           /* read-write */
    uint32_t queue_avail_lo;          /* read-write */
    uint32_t queue_avail_hi;          /* read-write */
    uint32_t queue_used_lo;           /* read-write */
    uint32_t queue_used_hi;           /* read-write */
} virtio_pci_common_cfg_t;

typedef struct virtio_bar_s {
    PHYSICAL_ADDRESS  pa;
    PVOID             va;
    ULONG             len;
    BOOLEAN           bPortSpace;
} virtio_bar_t;

typedef struct virtio_per_queue_info_s {
    /* the actual virtqueue */
    struct virtqueue *vq;
    /* the number of entries in the queue */
    int num;
    /* the index of the queue */
    int queue_index;
    /* the virtual address of the ring queue */
    void *queue;
    /* physical address of the ring queue */
    PHYSICAL_ADDRESS phys;
    /* owner per-queue context */
    void *pOwnerContext;
} virtio_per_queue_info_t;

typedef struct virtio_device_s {
    const struct virtio_device_ops_s *dev_op;
    virtio_bar_t bar[PCI_TYPE0_ADDRESSES];
    ULONG_PTR addr;
    ULONG msix_used_offset;

    /* the ISR status field, reading causes the device to de-assert an */
    /* interrupt */
    volatile uint8_t *isr;

    /* modern virtio device capabilities and related state */
    volatile virtio_pci_common_cfg_t *common;
    volatile unsigned char *config;
    volatile unsigned char *notify_base;
    void *notification_addr;
    int notify_map_cap;
    uint32_t notify_offset_multiplier;

    size_t config_len;
    size_t notify_len;

    ULONG maxQueues;
    char *drv_name;
    /* virtio_per_queue_info_t info[MAX_QUEUES_PER_DEVICE_DEFAULT]; */
    /* do not add any members after info struct, it is extensible */
} virtio_device_t;

typedef struct virtio_device_ops_s {
    /* read/write device config and read config generation counter */
    void (*get_config)(virtio_device_t *vdev,
                       unsigned offset, void *buf, unsigned len);
    void (*set_config)(virtio_device_t *vdev,
                       unsigned offset, const void *buf, unsigned len);
    uint32_t (*get_config_generation)(virtio_device_t *vdev);

    /* read/write device status byte and reset the device */
    uint8_t (*get_status)(virtio_device_t *vdev);
    void (*set_status)(virtio_device_t *vdev, uint8_t status);
    void (*reset)(virtio_device_t *vdev);

    /* get/set device feature bits */
    uint64_t (*get_features)(virtio_device_t *vdev);
    NTSTATUS (*set_features)(virtio_device_t *vdev, uint64_t features);

    /* set config/queue MSI interrupt vector, returns the new vector */
    uint16_t (*set_config_vector)(virtio_device_t *vdev, uint16_t vector);
    uint16_t (*set_queue_vector)(virtio_device_t *vdev,
        uint16_t qidx,
        uint16_t vector);

    /* query virtual queue size and memory requirements */
    NTSTATUS (*query_queue_alloc)(virtio_device_t *vdev,
        unsigned qidx, uint16_t *pnum_entries,
        unsigned long *pring_size,
        unsigned long *pheapS_sze);

    /* allocate and initialize a queue */
    virtio_queue_t *(*setup_queue)(virtio_device_t *vdev,
                                   uint16_t qidx,
                                   virtio_queue_t *vq,
                                   void *vring_mem,
                                   uint16_t num,
                                   uint16_t msi_vector,
                                   BOOLEAN use_event_idx);

    /* tear down and deallocate a queue */
    void (*delete_queue)(virtio_queue_t *vq, uint32_t free_mem);

    NTSTATUS (*activate_queue)(virtio_device_t *vdev,
                              virtio_queue_t *vq,
                              uint16_t msi_vector);
} virtio_device_ops_t;

#define VIRTIO_DEVICE_GET_CONFIG(_vdev, _offset, _buf, _len)               \
    (_vdev)->dev_op->get_config((_vdev), (_offset), (_buf), (_len))

#define VIRTIO_DEVICE_SET_CONFIG(_vdev, _offset, _buf, _len)               \
    (_vdev)->dev_op->set_config((_vdev), (_offset), (_buf), (_len))

#define VIRTIO_DEVICE_GET_CONFIG_GENERATION(_vdev)                         \
    (_vdev)->dev_op->get_config_generation((_vdev))

#define VIRTIO_DEVICE_GET_STATUS(_vdev)                                    \
    (_vdev)->dev_op->get_status((_vdev))

#define VIRTIO_DEVICE_SET_STATUS(_vdev, _status)                           \
    (_vdev)->dev_op->set_status((_vdev), (_status))

#define VIRTIO_DEVICE_RESET(_vdev)                                         \
    (_vdev)->dev_op->reset((_vdev))

#define VIRTIO_DEVICE_GET_FEATURES(_vdev)                                  \
    (_vdev)->dev_op->get_features((_vdev))

#define VIRTIO_DEVICE_SET_FEATURES(_vdev, _features)                       \
    (_vdev)->dev_op->set_features((_vdev), (_features))

#define VIRTIO_DEVICE_SET_CONFIG_VECTOR(_vdev, _vector)                    \
    (_vdev)->dev_op->set_config_vector((_vdev), (_vector))

#define VIRTIO_DEVICE_SET_QUEUE_VECTOR(_vdev, _qidx, _vector)              \
    (_vdev)->dev_op->set_queue_vector((_vdev), (_qidx), (_vector))

#define VIRTIO_DEVICE_QUERY_QUEUE_ALLOC(_vdev, _qidx, _num, _rsize, _hsize) \
    (_vdev)->dev_op->query_queue_alloc((_vdev), (_qidx), (_num),            \
                                       (_rsize), (_hsize))

#define VIRTIO_DEVICE_QUEUE_SETUP(_vdev, _qidx, _vq, _vring_mem, _num,  \
                                  _msi_vector, _use_event_idx)          \
    (_vdev)->dev_op->setup_queue((_vdev), (_qidx), (_vq), (_vring_mem), \
                                 (_num), (_msi_vector), (_use_event_idx))

#define VIRTIO_DEVICE_QUEUE_DELETE(_vdev, _vq, _free_mem)               \
    (_vdev)->dev_op->delete_queue((_vq), (_free_mem))

#define VIRTIO_DEVICE_QUEUE_ACTIVATE(_vdev, _vq, _msi_vector)           \
    (_vdev)->dev_op->activate_queue((_vdev), (_vq), (_msi_vector))

#define VIRTIO_IOWRITE64_LOHI(val, lo_addr, hi_addr)                    \
    virtio_iowrite32((ULONG_PTR)(lo_addr), (uint32_t)(val));            \
    virtio_iowrite32((ULONG_PTR)(hi_addr), (val) >> 32)

/***********************************************/
#define PCI_READ_CONFIG_BYTE(_pci_config_buf, _offset, _bval)           \
    (_bval) = (_pci_config_buf)[(_offset)];

#define PCI_READ_CONFIG_WORD(_pci_config_buf, _offset, _wval)           \
    (_wval) = *(uint16_t *)&(_pci_config_buf)[(_offset)];

#define PCI_READ_CONFIG_DWORD(_pci_config_buf, _offset, _dval)          \
    (_dval) = *(uint32_t *)&(_pci_config_buf)[(_offset)];

/*
 * shall be used only if virtio_device_t device storage is allocated
 * dynamically to provide support for more than 8
 * (MAX_QUEUES_PER_DEVICE_DEFAULT) queues.
 * return size in bytes to allocate for virtio_device_t structure.
 */
ULONG __inline virtio_dev_size_required(USHORT max_number_of_queues)
{
    ULONG size = sizeof(virtio_device_t);

    if (max_number_of_queues > MAX_QUEUES_PER_DEVICE_DEFAULT) {
        size += sizeof(virtio_per_queue_info_t)
            * (max_number_of_queues - MAX_QUEUES_PER_DEVICE_DEFAULT);
    }
    return size;
}

#define virtio_is_feature_enabled(features_list, feature)   \
    (!!((features_list) & (1ULL << (feature))))
#define virtio_feature_enable(features_list, feature) \
    ((features_list) |= (1ULL << (feature)))
#define virtio_feature_disable(features_list, feature) \
    ((features_list) &= ~(1ULL << (feature)))

uint8_t virtio_ioread8(ULONG_PTR ulRegister);
uint16_t virtio_ioread16(ULONG_PTR ulRegister);
uint32_t virtio_ioread32(ULONG_PTR ulRegister);
void virtio_iowrite8(ULONG_PTR ulRegister, uint8_t val);
void virtio_iowrite16(ULONG_PTR ulRegister, uint16_t val);
void virtio_iowrite32(ULONG_PTR ulRegister, uint32_t val);

BOOLEAN virtio_device_has_host_feature(virtio_device_t *vdev, uint64_t feature);
NTSTATUS virtio_device_set_guest_feature_list(virtio_device_t *vdev,
                                              uint64_t list);
void virtio_device_reset_features(virtio_device_t *vdev);
void virtio_device_add_status(virtio_device_t *vdev, uint8_t status);
void virtio_device_remove_status(virtio_device_t *vdev, uint8_t status);
ULONG virtio_device_read_isr_status(virtio_device_t *vdev);
int virtio_get_bar_index(PPCI_COMMON_HEADER p_header, PHYSICAL_ADDRESS pa);

NTSTATUS virtio_get_pci_config_space(PDEVICE_OBJECT device_object,
                                     uint8_t *pci_config_space,
                                     ULONG len);
void virtio_sleep(unsigned int msecs);

NTSTATUS virtio_device_init(virtio_device_t *vdev,
                            virtio_bar_t *vbar,
                            PUCHAR pci_config_buf,
                            char *drv_name,
                            BOOLEAN msi_enabled);

NTSTATUS virtio_dev_legacy_init(virtio_device_t *vdev,
                            virtio_bar_t *vbar,
                            PUCHAR pci_config_buf);

NTSTATUS virtio_dev_modern_init(virtio_device_t *vdev,
                                virtio_bar_t *vbar,
                                PUCHAR pci_config_buf);
#endif
