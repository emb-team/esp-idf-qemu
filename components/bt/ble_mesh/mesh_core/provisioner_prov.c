// Copyright 2017-2018 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>
#include <errno.h>

#include "stack/bt_types.h"
#include "sdkconfig.h"
#include "osi/allocator.h"

#include "mesh_main.h"
#include "mesh_trace.h"

#include "crypto.h"
#include "adv.h"
#include "mesh.h"
#include "provisioner_prov.h"
#include "provisioner_proxy.h"
#include "provisioner_main.h"

#if CONFIG_BLE_MESH_PROVISIONER

#define CONFIG_BT_MAX_CONN      CONFIG_BT_ACL_CONNECTIONS

/* Service data length has minus 1 type length & 2 uuid length*/
#define BLE_MESH_PROV_SRV_DATA_LEN       0x12
#define BLE_MESH_PROXY_SRV_DATA_LEN1     0x09
#define BLE_MESH_PROXY_SRV_DATA_LEN2     0x11

/* 3 transmissions, 20ms interval */
#define PROV_XMIT_COUNT        2
#define PROV_XMIT_INT          20

#define AUTH_METHOD_NO_OOB     0x00
#define AUTH_METHOD_STATIC     0x01
#define AUTH_METHOD_OUTPUT     0x02
#define AUTH_METHOD_INPUT      0x03

#define OUTPUT_OOB_BLINK       0x00
#define OUTPUT_OOB_BEEP        0x01
#define OUTPUT_OOB_VIBRATE     0x02
#define OUTPUT_OOB_NUMBER      0x03
#define OUTPUT_OOB_STRING      0x04

#define INPUT_OOB_PUSH         0x00
#define INPUT_OOB_TWIST        0x01
#define INPUT_OOB_NUMBER       0x02
#define INPUT_OOB_STRING       0x03

#define PROV_ERR_NONE          0x00
#define PROV_ERR_NVAL_PDU      0x01
#define PROV_ERR_NVAL_FMT      0x02
#define PROV_ERR_UNEXP_PDU     0x03
#define PROV_ERR_CFM_FAILED    0x04
#define PROV_ERR_RESOURCES     0x05
#define PROV_ERR_DECRYPT       0x06
#define PROV_ERR_UNEXP_ERR     0x07
#define PROV_ERR_ADDR          0x08

#define PROV_INVITE            0x00
#define PROV_CAPABILITIES      0x01
#define PROV_START             0x02
#define PROV_PUB_KEY           0x03
#define PROV_INPUT_COMPLETE    0x04
#define PROV_CONFIRM           0x05
#define PROV_RANDOM            0x06
#define PROV_DATA              0x07
#define PROV_COMPLETE          0x08
#define PROV_FAILED            0x09

#define PROV_ALG_P256          0x00

#define GPCF(gpc)              (gpc & 0x03)
#define GPC_START(last_seg)    (((last_seg) << 2) | 0x00)
#define GPC_ACK                0x01
#define GPC_CONT(seg_id)       (((seg_id) << 2) | 0x02)
#define GPC_CTL(op)            (((op) << 2) | 0x03)

#define START_PAYLOAD_MAX      20
#define CONT_PAYLOAD_MAX       23

#define START_LAST_SEG(gpc)    (gpc >> 2)
#define CONT_SEG_INDEX(gpc)    (gpc >> 2)

#define BEARER_CTL(gpc)        (gpc >> 2)
#define LINK_OPEN              0x00
#define LINK_ACK               0x01
#define LINK_CLOSE             0x02

#define CLOSE_REASON_SUCCESS   0x00
#define CLOSE_REASON_TIMEOUT   0x01
#define CLOSE_REASON_FAILED    0x02

#define PROV_AUTH_VAL_SIZE     0x10
#define PROV_CONF_SALT_SIZE    0x10
#define PROV_CONF_KEY_SIZE     0x10
#define PROV_DH_KEY_SIZE       0x20
#define PROV_CONFIRM_SIZE      0x10
#define PROV_PROV_SALT_SIZE    0x10
#define PROV_CONF_INPUTS_SIZE  0x91

static inline int prov_get_pb_index(void);

#define XACT_SEG_DATA(_seg) (&link[prov_get_pb_index()].rx.buf->data[20 + ((_seg - 1) * 23)])
#define XACT_SEG_RECV(_seg) (link[prov_get_pb_index()].rx.seg &= ~(1 << (_seg)))

#define XACT_NVAL              0xff

enum {
    REMOTE_PUB_KEY,        /* Remote key has been received */
    LOCAL_PUB_KEY,         /* Local public key is available */
    LINK_ACTIVE,           /* Link has been opened */
    WAIT_GEN_DHKEY,        /* Waiting for remote public key to generate DHKey */
    HAVE_DHKEY,            /* DHKey has been calcualted */
    SEND_CONFIRM,          /* Waiting to send Confirm value */
    WAIT_NUMBER,           /* Waiting for number input from user */
    WAIT_STRING,           /* Waiting for string input from user */
    TIMEOUT_START,         /* Provision timeout timer has started */
    NUM_FLAGS,
};

/** Provisioner link structure allocation
 * |--------------------------------------------------------|
 * |            Link(PB-ADV)            |   Link(PB-GATT)   |
 * |--------------------------------------------------------|
 * |<----------------------Total Link---------------------->|
 */
struct prov_link {
    BLE_MESH_ATOMIC_DEFINE(flags, NUM_FLAGS);
    u8_t  uuid[16];          /* check if device is being provisioned*/
    u16_t oob_info;          /* oob info of this device */
    u8_t  element_num;       /* element num of device */
    u8_t  ki_flags;          /* Key refresh flag and iv update flag */
    u32_t iv_index;          /* IV Index */
    u8_t  auth_method;       /* choosed authentication method */
    u8_t  auth_action;       /* choosed authentication action */
    u8_t  auth_size;         /* choosed authentication size */
    u16_t unicast_addr;      /* unicast address assigned for device */
    bt_mesh_addr_t addr;       /* Device address */
#if defined(CONFIG_BLE_MESH_PB_GATT)
    bool   connecting;       /* start connecting with device */
    struct bt_mesh_conn *conn; /* GATT connection */
#endif
    u8_t  expect;            /* Next expected PDU */

    u8_t *dhkey;             /* Calculated DHKey */
    u8_t *auth;              /* Authentication Value */

    u8_t *conf_salt;         /* ConfirmationSalt */
    u8_t *conf_key;          /* ConfirmationKey */
    u8_t *conf_inputs;       /* ConfirmationInputs */

    u8_t *rand;              /* Local Random */
    u8_t *conf;              /* Remote Confirmation */

    u8_t *prov_salt;         /* Provisioning Salt */

#if defined(CONFIG_BLE_MESH_PB_ADV)
    bool  linking;           /* Linking is being establishing */
    u16_t link_close;        /* Link close been sent flag */
    u32_t link_id;           /* Link ID */
    u8_t  pending_ack;       /* Decide which transaction id ack is pending */
    u8_t  expect_ack_for;    /* Transaction ACK expected for provisioning pdu */

    struct {
        u8_t  trans_id;      /* Transaction ID */
        u8_t  prev_id;       /* Previous Transaction ID */
        u8_t  seg;           /* Bit-field of unreceived segments */
        u8_t  last_seg;      /* Last segment (to check length) */
        u8_t  fcs;           /* Expected FCS value */
        u8_t  adv_buf_id;    /* index of buf allocated in adv_buf_data */
        struct net_buf_simple *buf;
    } rx;

    struct {
        /* Start timestamp of the transaction */
        s64_t start;

        /* Transaction id*/
        u8_t trans_id;

        /* Pending outgoing buffer(s) */
        struct net_buf *buf[3];

        /* Retransmit timer */
        struct k_delayed_work retransmit;
    } tx;
#endif
    /** Provision timeout timer. Spec P259 says: The provisioning protocol
     *  shall have a minimum timeout of 60 seconds that is reset each time
     *  a provisioning protocol PDU is sent or received.
     */
    struct k_delayed_work timeout;
};

struct prov_rx {
    u32_t link_id;
    u8_t  xact_id;
    u8_t  gpc;
};

#define BLE_MESH_ALREADY_PROV_NUM  (CONFIG_BLE_MESH_MAX_PROV_NODES + 10)

struct prov_ctx_t {
    /* If provisioning random have been generated, set BIT0 to 1 */
    u8_t  rand_gen_done;

    /* Provisioner random */
    u8_t  random[16];

    /* Number of provisioned devices */
    u16_t node_count;

    /* Current number of PB-ADV provisioned devices simultaneously */
    u8_t  pba_count;

    /* Current number of PB-GATT provisioned devices simultaneously */
    u8_t  pbg_count;

    /* Current index of device being provisioned using PB-GATT or PB-ADV */
    int   pb_index;

    /* Current unicast address going to assigned */
    u16_t current_addr;

    /* Current net_idx going to be used in provisioning data */
    u16_t curr_net_idx;

    /* Current flags going to be used in provisioning data */
    u16_t curr_flags;

    /* Current iv_index going to be used in provisioning data */
    u16_t curr_iv_index;

    /* Offset of the device uuid to be matched, based on zero */
    u8_t  match_offset;

    /* Length of the device uuid to be matched (start from the match_offset) */
    u8_t  match_length;

    /* Value of the device uuid to be matched */
    u8_t *match_value;

    /* Indicate when received uuid_match adv_pkts, can provision it at once */
    bool prov_after_match;

    /** This structure is used to store the information of the device which
     *  provisioner has successfully sent provisioning data to. In this
     *  structure, we don't care if the device is currently in the mesh
     *  network, or has been removed, or failed to send provisioning
     *  complete pdu after receiving the provisioning data pdu.
     */
    struct already_prov_info {
        u8_t  uuid[16];     /* device uuid */
        u8_t  element_num;  /* element number of the deleted node */
        u16_t unicast_addr; /* Primary unicast address of the deleted node */
    } already_prov[BLE_MESH_ALREADY_PROV_NUM];
};

struct prov_node_info {
    bool  provisioned;      /* device provisioned flag */
    bt_mesh_addr_t addr;      /* device address */
    u8_t  uuid[16];         /* node uuid */
    u16_t oob_info;         /* oob info contained in adv pkt */
    u8_t  element_num;      /* element contained in this node */
    u16_t unicast_addr;     /* primary unicast address of this node */
    u16_t net_idx;          /* Netkey index got during provisioning */
    u8_t  flags;            /* Key refresh flag and iv update flag */
    u32_t iv_index;         /* IV Index */
};

struct unprov_dev_queue {
    bt_mesh_addr_t addr;
    u8_t         uuid[16];
    u16_t        oob_info;
    u8_t         bearer;
    u8_t         flags;
} __packed unprov_dev[CONFIG_BLE_MESH_WAIT_FOR_PROV_MAX_DEV_NUM] = {
    [0 ... (CONFIG_BLE_MESH_WAIT_FOR_PROV_MAX_DEV_NUM - 1)] = {
        .addr.type = 0xff,
        .bearer    = 0,
        .flags     = false,
    },
};

static unprov_adv_pkt_cb_t notify_unprov_adv_pkt_cb;

#define RETRANSMIT_TIMEOUT   K_MSEC(500)
#define BUF_TIMEOUT          K_MSEC(400)
#if defined(CONFIG_BLE_MESH_FAST_PROV)
#define TRANSACTION_TIMEOUT  K_SECONDS(3)
#define PROVISION_TIMEOUT    K_SECONDS(6)
#else
#define TRANSACTION_TIMEOUT  K_SECONDS(30)
#define PROVISION_TIMEOUT    K_SECONDS(60)
#endif /* CONFIG_BLE_MESH_FAST_PROV */

#if defined(CONFIG_BLE_MESH_PB_GATT)
#define PROV_BUF_HEADROOM 5
#else
#define PROV_BUF_HEADROOM 0
#endif

#define PROV_BUF(len) NET_BUF_SIMPLE(PROV_BUF_HEADROOM + len)

/* Number of devices can be provisioned at the same time using PB-GATT + PB-ADV */
#define BLE_MESH_PROV_SAME_TIME (CONFIG_BLE_MESH_PBA_SAME_TIME + CONFIG_BLE_MESH_PBG_SAME_TIME)

static struct prov_link link[BLE_MESH_PROV_SAME_TIME];

static const struct bt_mesh_prov *prov;

static struct prov_ctx_t prov_ctx;

static struct prov_node_info prov_nodes[CONFIG_BLE_MESH_MAX_PROV_NODES];

#if defined(CONFIG_BLE_MESH_PB_ADV)
static void send_link_open(void);
#endif

static void prov_gen_dh_key(int i);

static void send_pub_key(u8_t oob);

static void close_link(int i, u8_t reason);

#if defined(CONFIG_BLE_MESH_PB_ADV)
#define ADV_BUF_SIZE  65
static struct adv_buf_t {
    struct net_buf_simple buf;
    u8_t                  adv_buf_data[ADV_BUF_SIZE];
} adv_buf[CONFIG_BLE_MESH_PBA_SAME_TIME];
#endif

#define PROV_FREE_MEM(id, member)   \
{                                   \
    if (link[id].member) {          \
        osi_free(link[id].member);  \
    }                               \
}

/* Fast provisioning uses this structure for provisioning data */
struct bt_mesh_fast_prov {
    u16_t net_idx;
    const u8_t *net_key;
    u8_t  flags;
    u32_t iv_index;
    u16_t unicast_addr_min;
    u16_t unicast_addr_max;
};
static struct bt_mesh_fast_prov fast_prov;
static bool fast_prov_flag;
#define FAST_PROV_FLAG_GET() fast_prov_flag

static inline int prov_get_pb_index(void)
{
    return prov_ctx.pb_index;
}

static void prov_set_pb_index(int i)
{
    prov_ctx.pb_index = i;
}

void provisioner_pbg_count_dec(void)
{
    if (prov_ctx.pbg_count) {
        prov_ctx.pbg_count--;
    }
}

void provisioner_pbg_count_inc(void)
{
    prov_ctx.pbg_count++;
}

void provisioner_clear_link_conn_info(u8_t addr[6])
{
#if defined(CONFIG_BLE_MESH_PB_GATT)
    if (!addr) {
        BT_ERR("%s, Invalid parameter", __func__);
        return;
    }

    BT_DBG("%s, Clear device %s info", __func__, bt_hex(addr, BLE_MESH_ADDR_LEN));

    for (int i = CONFIG_BLE_MESH_PBA_SAME_TIME; i < BLE_MESH_PROV_SAME_TIME; i++) {
        if (!memcmp(link[i].addr.val, addr, BLE_MESH_ADDR_LEN)) {
            link[i].connecting = false;
            link[i].conn = NULL;
            link[i].oob_info = 0x0;
            memset(link[i].uuid, 0, 16);
            memset(&link[i].addr, 0, sizeof(bt_mesh_addr_t));
            bt_mesh_atomic_test_and_clear_bit(link[i].flags, LINK_ACTIVE);
            if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
                k_delayed_work_cancel(&link[i].timeout);
            }
            return;
        }
    }

    BT_WARN("%s, Address %s is not found", __func__, bt_hex(addr, BLE_MESH_ADDR_LEN));
    return;
#endif
}

const struct bt_mesh_prov *provisioner_get_prov_info(void)
{
    return prov;
}

int provisioner_prov_reset_all_nodes(void)
{
    int i;

    BT_DBG("%s", __func__);

    for (i = 0; i < ARRAY_SIZE(prov_nodes); i++) {
        if (prov_nodes[i].provisioned) {
            memset(&prov_nodes[i], 0, sizeof(struct prov_node_info));
        }
    }

    prov_ctx.node_count = 0;

    return 0;
}

static int provisioner_dev_find(const bt_mesh_addr_t *addr, const u8_t uuid[16], int *index)
{
    bool uuid_match = false;
    bool addr_match = false;
    u8_t zero[16] = {0};
    int i = 0, j = 0, comp = 0;

    if (addr) {
        comp = memcmp(addr->val, zero, BLE_MESH_ADDR_LEN);
    }

    if ((!uuid && (!addr || (comp == 0) || (addr->type > BLE_ADDR_RANDOM))) || !index) {
        return -EINVAL;
    }

    /** Note: user may add a device into two unprov_dev array elements,
     *        one with device address, address type and another only
     *        with device UUID. We need to take this into consideration.
     */
    if (uuid && memcmp(uuid, zero, 16)) {
        for (i = 0; i < ARRAY_SIZE(unprov_dev); i++) {
            if (!memcmp(unprov_dev[i].uuid, uuid, 16)) {
                uuid_match = true;
                break;
            }
        }
    }

    if (addr && comp && (addr->type <= BLE_ADDR_RANDOM)) {
        for (j = 0; j < ARRAY_SIZE(unprov_dev); j++) {
            if (!memcmp(unprov_dev[j].addr.val, addr->val, BLE_MESH_ADDR_LEN) &&
                    unprov_dev[j].addr.type == addr->type) {
                addr_match = true;
                break;
            }
        }
    }

    if (!uuid_match && !addr_match) {
        BT_DBG("%s, Device does not exist in queue", __func__);
        return -ENODEV;
    }

    if (uuid_match && addr_match && (i != j)) {
        /** In this situation, copy address & type into device
         *  uuid array element, reset another element, rm_flag
         *  will be decided by uuid element.
         */
        unprov_dev[i].addr.type = unprov_dev[j].addr.type;
        memcpy(unprov_dev[i].addr.val, unprov_dev[j].addr.val, BLE_MESH_ADDR_LEN);
        unprov_dev[i].bearer |= unprov_dev[j].bearer;
        memset(&unprov_dev[j], 0x0, sizeof(struct unprov_dev_queue));
    }

    *index = uuid_match ? i : j;
    return 0;
}

static int provisioner_dev_uuid_match(const u8_t uuid[16])
{
    if (!uuid) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    if (prov_ctx.match_length && prov_ctx.match_value) {
        if (memcmp(uuid + prov_ctx.match_offset,
                   prov_ctx.match_value, prov_ctx.match_length)) {
            return -EAGAIN;
        }
    }

    return 0;
}

static int provisioner_check_device_uuid(const u8_t uuid[16])
{
    int i;

    if (!uuid) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    /* Check if this device is currently being provisioned.
     * According to Zephyr's device code, if we connect with
     * one device and start to provision it, we may still can
     * receive the connectable prov adv pkt from this device.
     * Here we check both PB-GATT and PB-ADV link status.
     */
    for (i = 0; i < BLE_MESH_PROV_SAME_TIME; i++) {
#if defined(CONFIG_BLE_MESH_PB_GATT)
        if (link[i].connecting || bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE)) {
#else
        if (link[i].linking || bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE)) {
#endif
            if (!memcmp(link[i].uuid, uuid, 16)) {
                BT_DBG("%s, Device is being provisioned", __func__);
                return -EALREADY;
            }
        }
    }

    /* Check if the device uuid matches configured value */
    if (provisioner_dev_uuid_match(uuid)) {
        BT_DBG("%s, Device uuid failed to match", __func__);
        return -EIO;
    }

    /* Check if the device has already been provisioned */
    for (i = 0; i < ARRAY_SIZE(prov_nodes); i++) {
        if (prov_nodes[i].provisioned) {
            if (!memcmp(prov_nodes[i].uuid, uuid, 16)) {
                BT_WARN("Provisioned before, start to provision again");
                provisioner_node_reset(i);
                memset(&prov_nodes[i], 0, sizeof(struct prov_node_info));
                if (prov_ctx.node_count) {
                    prov_ctx.node_count--;
                }
                return 0;
            }
        }
    }

    /* Check if the prov_nodes queue is full */
    if (prov_ctx.node_count == ARRAY_SIZE(prov_nodes)) {
        BT_WARN("Current provisioned devices reach max limit");
        return -ENOMEM;
    }

    return 0;
}

static int provisioner_start_prov_device(bt_mesh_prov_bearer_t bearer, const u8_t uuid[16],
                const bt_mesh_addr_t *addr, u16_t oob_info)
{
    u8_t zero[6] = {0};
    int addr_cmp, i;

    if ((bearer != BLE_MESH_PROV_ADV && bearer != BLE_MESH_PROV_GATT) || !uuid || !addr) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    addr_cmp = memcmp(addr->val, zero, BLE_MESH_ADDR_LEN);

    if (bearer == BLE_MESH_PROV_ADV) {
#if defined(CONFIG_BLE_MESH_PB_ADV)
        for (i = 0; i < CONFIG_BLE_MESH_PBA_SAME_TIME; i++) {
            if (!bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE) && !link[i].linking) {
                memcpy(link[i].uuid, uuid, 16);
                link[i].oob_info = oob_info;
                if (addr_cmp && (addr->type <= BLE_ADDR_RANDOM)) {
                    link[i].addr.type = addr->type;
                    memcpy(link[i].addr.val, addr->val, BLE_MESH_ADDR_LEN);
                }
                prov_set_pb_index(i);
                send_link_open();
                /* If Provisioner sets LINK_ACTIVE flag once Link Open is sent, here
                 * we may not need to use linking flag (like PB-GATT connecting) to
                 * prevent the stored device info (UUID, oob_info) being replaced by
                 * other received unprovisioned device beacons.
                 * But if Provisioner sets LINK_ACTIVE flag after Link ACK is received,
                 * we need to use linking flag to prevent device info being replaced.
                 * Currently we set LINK_ACTIVE flag after sending Link Open.
                 */
                link[i].linking = true;
                if (prov->prov_link_open) {
                    prov->prov_link_open(BLE_MESH_PROV_ADV);
                }
                return 0;
            }
        }
#endif
    } else {
#if defined(CONFIG_BLE_MESH_PB_GATT)
        for (i = CONFIG_BLE_MESH_PBA_SAME_TIME; i < BLE_MESH_PROV_SAME_TIME; i++) {
            if (!bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE) && !link[i].connecting) {
                memcpy(link[i].uuid, uuid, 16);
                link[i].oob_info = oob_info;
                if (addr_cmp && (addr->type <= BLE_ADDR_RANDOM)) {
                    link[i].addr.type = addr->type;
                    memcpy(link[i].addr.val, addr->val, BLE_MESH_ADDR_LEN);
                }
                if (bt_mesh_gattc_conn_create(&link[i].addr, BLE_MESH_UUID_MESH_PROV_VAL)) {
                    memset(link[i].uuid, 0, 16);
                    link[i].oob_info = 0x0;
                    memset(&link[i].addr, 0, sizeof(bt_mesh_addr_t));
                    return -EIO;
                }
                /* If creating connection successfully, set connecting flag to 1 */
                link[i].connecting = true;
                return 0;
            }
        }
#endif
    }

    BT_ERR("%s, No link is available", __func__);
    return -ENOMEM;
}

int bt_mesh_provisioner_add_unprov_dev(struct bt_mesh_unprov_dev_add *add_dev, u8_t flags)
{
    bt_mesh_addr_t add_addr = {0};
    u8_t zero[16] = {0};
    int addr_cmp = 0, uuid_cmp = 0;
    int i, err = 0;

    if (!add_dev) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    addr_cmp = memcmp(add_dev->addr, zero, BLE_MESH_ADDR_LEN);
    uuid_cmp = memcmp(add_dev->uuid, zero, 16);

    if (add_dev->bearer == 0x0 || ((uuid_cmp == 0) &&
            ((addr_cmp == 0) || add_dev->addr_type > BLE_ADDR_RANDOM))) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    if ((add_dev->bearer & BLE_MESH_PROV_ADV) && (add_dev->bearer & BLE_MESH_PROV_GATT) &&
            (flags & START_PROV_NOW)) {
        BT_ERR("%s, Can not start PB-ADV & PB-GATT simultaneouly", __func__);
        return -EINVAL;
    }

    if ((uuid_cmp == 0) && (flags & START_PROV_NOW)) {
        BT_ERR("%s, Can not start provisioning with zero uuid", __func__);
        return -EINVAL;
    }

    if ((add_dev->bearer & BLE_MESH_PROV_GATT) && (flags & START_PROV_NOW) &&
            ((addr_cmp == 0) || add_dev->addr_type > BLE_ADDR_RANDOM)) {
        BT_ERR("%s, Invalid device address for PB-GATT", __func__);
        return -EINVAL;
    }

    if (add_dev->bearer & BLE_MESH_PROV_GATT) {
#if !CONFIG_BLE_MESH_PB_GATT
        BT_ERR("%s, Not support PB-GATT", __func__);
        return -EINVAL;
#endif
    }

    if (add_dev->bearer & BLE_MESH_PROV_ADV) {
#if !CONFIG_BLE_MESH_PB_ADV
        BT_ERR("%s, Not support PB-ADV", __func__);
        return -EINVAL;
#endif
    }

    add_addr.type = add_dev->addr_type;
    memcpy(add_addr.val, add_dev->addr, BLE_MESH_ADDR_LEN);

    err = provisioner_dev_find(&add_addr, add_dev->uuid, &i);
    if (err == -EINVAL) {
        BT_ERR("%s, Invalid parameter", __func__);
        return err;
    } else if (err == 0) {
        if (!(add_dev->bearer & unprov_dev[i].bearer)) {
            BT_WARN("%s, Add device with only bearer updated", __func__);
            unprov_dev[i].bearer |= add_dev->bearer;
        } else {
            BT_WARN("%s, Device already exists", __func__);
        }
        goto start;
    }

    for (i = 0; i < ARRAY_SIZE(unprov_dev); i++) {
        if (unprov_dev[i].bearer) {
            continue;
        }
        if (addr_cmp && (add_dev->addr_type <= BLE_ADDR_RANDOM)) {
            unprov_dev[i].addr.type = add_dev->addr_type;
            memcpy(unprov_dev[i].addr.val, add_dev->addr, BLE_MESH_ADDR_LEN);
        }
        if (uuid_cmp) {
            memcpy(unprov_dev[i].uuid, add_dev->uuid, 16);
        }
        unprov_dev[i].bearer = add_dev->bearer & BIT_MASK(2);
        unprov_dev[i].flags  = flags & BIT_MASK(3);
        goto start;
    }

    /* If queue is full, find flushable device and replace it */
    for (i = 0; i < ARRAY_SIZE(unprov_dev); i++) {
        if (unprov_dev[i].flags & FLUSHABLE_DEV) {
            memset(&unprov_dev[i], 0, sizeof(struct unprov_dev_queue));
            if (addr_cmp && (add_dev->addr_type <= BLE_ADDR_RANDOM)) {
                unprov_dev[i].addr.type = add_dev->addr_type;
                memcpy(unprov_dev[i].addr.val, add_dev->addr, BLE_MESH_ADDR_LEN);
            }
            if (uuid_cmp) {
                memcpy(unprov_dev[i].uuid, add_dev->uuid, 16);
            }
            unprov_dev[i].bearer = add_dev->bearer & BIT_MASK(2);
            unprov_dev[i].flags  = flags & BIT_MASK(3);
            goto start;
        }
    }

    BT_ERR("%s, Unprovisioned device queue is full", __func__);
    return -ENOMEM;

start:
    if (!(flags & START_PROV_NOW)) {
        return 0;
    }

    /* Check if current provisioned node count + active link reach max limit */
    if (prov_ctx.node_count + prov_ctx.pba_count + \
        prov_ctx.pbg_count >= ARRAY_SIZE(prov_nodes)) {
        BT_WARN("%s, Node count + active link count reach max limit", __func__);
        return -EIO;
    }

    if ((err = provisioner_check_device_uuid(add_dev->uuid))) {
        return err;
    }

    if (add_dev->bearer & BLE_MESH_PROV_ADV) {
#if defined(CONFIG_BLE_MESH_PB_ADV)
        if (prov_ctx.pba_count == CONFIG_BLE_MESH_PBA_SAME_TIME) {
            BT_WARN("%s, Current PB-ADV links reach max limit", __func__);
            return -EIO;
        }
        if ((err = provisioner_start_prov_device(BLE_MESH_PROV_ADV,
                add_dev->uuid, &add_addr, add_dev->oob_info))) {
            return err;
        }
#endif
    } else if (add_dev->bearer & BLE_MESH_PROV_GATT) {
#if defined(CONFIG_BLE_MESH_PB_GATT)
        if (prov_ctx.pbg_count == CONFIG_BLE_MESH_PBG_SAME_TIME) {
            BT_WARN("%s, Current PB-GATT links reach max limit", __func__);
            return -EIO;
        }
        if ((err = provisioner_start_prov_device(BLE_MESH_PROV_GATT,
                add_dev->uuid, &add_addr, add_dev->oob_info))) {
            return err;
        }
#endif
    }

    return 0;
}

int bt_mesh_provisioner_delete_device(struct bt_mesh_device_delete *del_dev)
{
    /**
     * Three Situations:
     * 1. device is not being/been provisioned, just remove from device queue.
     * 2. device is being provisioned, need to close link & remove from device queue.
     * 3. device is been provisioned, need to send config_node_reset and may need to
     *    remove from device queue. config _node_reset can be added in function
     *    provisioner_node_reset() in provisioner_main.c.
     */
    bt_mesh_addr_t del_addr = {0};
    u8_t zero[16] = {0};
    int addr_cmp = 0, uuid_cmp = 0;
    bool addr_match = false;
    bool uuid_match = false;
    int i, err = 0;

    if (!del_dev) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    addr_cmp = memcmp(del_dev->addr, zero, BLE_MESH_ADDR_LEN);
    uuid_cmp = memcmp(del_dev->uuid, zero, 16);

    if ((uuid_cmp == 0) && ((addr_cmp == 0) || del_dev->addr_type > BLE_ADDR_RANDOM)) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    del_addr.type = del_dev->addr_type;
    memcpy(del_addr.val, del_dev->addr, BLE_MESH_ADDR_LEN);

    /* First: find if the device is in the device queue */
    err = provisioner_dev_find(&del_addr, del_dev->uuid, &i);
    if (err) {
        BT_DBG("%s, Device is not in the queue", __func__);
    } else {
        memset(&unprov_dev[i], 0x0, sizeof(struct unprov_dev_queue));
    }

    /* Second: find if the device is being provisioned */
    for (i = 0; i < ARRAY_SIZE(link); i++) {
        if (addr_cmp && (del_dev->addr_type <= BLE_ADDR_RANDOM)) {
            if (!memcmp(link[i].addr.val, del_dev->addr, BLE_MESH_ADDR_LEN) &&
                    link[i].addr.type == del_dev->addr_type) {
                addr_match = true;
            }
        }
        if (uuid_cmp) {
            if (!memcmp(link[i].uuid, del_dev->uuid, 16)) {
                uuid_match = true;
            }
        }
        if (addr_match || uuid_match) {
            close_link(i, CLOSE_REASON_FAILED);
            break;
        }
    }

    /* Third: find if the device is been provisioned */
    for (i = 0; i < ARRAY_SIZE(prov_nodes); i++) {
        if (addr_cmp && (del_dev->addr_type <= BLE_ADDR_RANDOM)) {
            if (!memcmp(prov_nodes[i].addr.val, del_dev->addr, BLE_MESH_ADDR_LEN) &&
                    prov_nodes[i].addr.type == del_dev->addr_type) {
                addr_match = true;
            }
        }
        if (uuid_cmp) {
            if (!memcmp(prov_nodes[i].uuid, del_dev->uuid, 16)) {
                uuid_match = true;
            }
        }
        if (addr_match || uuid_match) {
            memset(&prov_nodes[i], 0, sizeof(struct prov_node_info));
            provisioner_node_reset(i);
            if (prov_ctx.node_count) {
                prov_ctx.node_count--;
            }
            break;
        }
    }

    return 0;
}

int bt_mesh_provisioner_set_dev_uuid_match(u8_t offset, u8_t length,
        const u8_t *match, bool prov_flag)
{
    if (length && (!match || (offset + length > 16))) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    if (length && !prov_ctx.match_value) {
        prov_ctx.match_value = osi_calloc(16);
        if (!prov_ctx.match_value) {
            BT_ERR("%s, Failed to allocate memory", __func__);
            return -ENOMEM;
        }
    }

    prov_ctx.match_offset = offset;
    prov_ctx.match_length = length;
    if (length) {
        memcpy(prov_ctx.match_value, match, length);
    }
    prov_ctx.prov_after_match = prov_flag;

    return 0;
}

int bt_mesh_prov_adv_pkt_cb_register(unprov_adv_pkt_cb_t cb)
{
    if (!cb) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    notify_unprov_adv_pkt_cb = cb;
    return 0;
}

int bt_mesh_provisioner_set_prov_data_info(struct bt_mesh_prov_data_info *info)
{
    const u8_t *key = NULL;

    if (!info || info->flag == 0) {
        return -EINVAL;
    }

    if (info->flag & NET_IDX_FLAG) {
        key = provisioner_net_key_get(info->net_idx);
        if (!key) {
            BT_ERR("%s, Failed to get NetKey", __func__);
            return -EINVAL;
        }
        prov_ctx.curr_net_idx = info->net_idx;
    } else if (info->flag & FLAGS_FLAG) {
        prov_ctx.curr_flags = info->flags;
    } else if (info->flag & IV_INDEX_FLAG) {
        prov_ctx.curr_iv_index = info->iv_index;
    }

    return 0;
}

/* The following APIs are for fast provisioning */

void provisioner_set_fast_prov_flag(bool flag)
{
    fast_prov_flag = flag;
}

u8_t provisioner_set_fast_prov_net_idx(const u8_t *net_key, u16_t net_idx)
{
    fast_prov.net_idx = net_idx;
    fast_prov.net_key = net_key;

    if (!net_key) {
        BT_WARN("%s, Wait for NetKey for fast provisioning", __func__);
        return 0x01; /*status: wait for net_key */
    }

    return 0x0; /* status: success */
}

u16_t provisioner_get_fast_prov_net_idx(void)
{
    return fast_prov.net_idx;
}

u8_t bt_mesh_set_fast_prov_unicast_addr_range(u16_t min, u16_t max)
{
    if (!BLE_MESH_ADDR_IS_UNICAST(min) || !BLE_MESH_ADDR_IS_UNICAST(max)) {
        BT_ERR("%s, Not a unicast address", __func__);
        return 0x01; /* status: not a unicast address */
    }

    if (min > max) {
        BT_ERR("%s, Min bigger than max", __func__);
        return 0x02; /* status: min is bigger than max */
    }

    if (min <= fast_prov.unicast_addr_max) {
        BT_ERR("%s, Address overlap", __func__);
        return 0x03; /* status: address overlaps with current value */
    }

    fast_prov.unicast_addr_min = min;
    fast_prov.unicast_addr_max = max;

    prov_ctx.current_addr = fast_prov.unicast_addr_min;

    return 0x0; /* status: success */
}

void bt_mesh_set_fast_prov_flags_iv_index(u8_t flags, u32_t iv_index)
{
    /* BIT0: Key Refreash flag, BIT1: IV Update flag */
    fast_prov.flags = flags & BIT_MASK(2);
    fast_prov.iv_index = iv_index;
}

#if defined(CONFIG_BLE_MESH_PB_ADV)
static struct net_buf_simple *bt_mesh_pba_get_buf(int id)
{
    struct net_buf_simple *buf = &(adv_buf[id].buf);

    net_buf_simple_init(buf, 0);

    return buf;
}
#endif /* CONFIG_BLE_MESH_PB_ADV */

static void prov_memory_free(int i)
{
    PROV_FREE_MEM(i, dhkey);
    PROV_FREE_MEM(i, auth);
    PROV_FREE_MEM(i, conf);
    PROV_FREE_MEM(i, conf_salt);
    PROV_FREE_MEM(i, conf_key);
    PROV_FREE_MEM(i, conf_inputs);
    PROV_FREE_MEM(i, prov_salt);
}

#if defined(CONFIG_BLE_MESH_PB_ADV)
static void buf_sent(int err, void *user_data)
{
    int i = (int)user_data;

    if (!link[i].tx.buf[0]) {
        return;
    }

    k_delayed_work_submit(&link[i].tx.retransmit, RETRANSMIT_TIMEOUT);
}

static struct bt_mesh_send_cb buf_sent_cb = {
    .end = buf_sent,
};

static void free_segments(int id)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(link[id].tx.buf); i++) {
        struct net_buf *buf = link[id].tx.buf[i];

        if (!buf) {
            break;
        }

        link[id].tx.buf[i] = NULL;
        /* Mark as canceled */
        BLE_MESH_ADV(buf)->busy = 0;
        /** Change by Espressif. Add this to avoid buf->ref is 2 which will
         *  cause lack of buf.
         */
        if (buf->ref > 1) {
            buf->ref = 1;
        }
        net_buf_unref(buf);
    }
}

static void prov_clear_tx(int i)
{
    BT_DBG("%s", __func__);

    k_delayed_work_cancel(&link[i].tx.retransmit);

    free_segments(i);
}

static void reset_link(int i, u8_t reason)
{
    prov_clear_tx(i);

    if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_cancel(&link[i].timeout);
    }

    if (prov->prov_link_close) {
        prov->prov_link_close(BLE_MESH_PROV_ADV, reason);
    }

    prov_memory_free(i);

#if defined(CONFIG_BLE_MESH_USE_DUPLICATE_SCAN)
    /* Remove the link id from exceptional list */
    bt_mesh_update_exceptional_list(BLE_MESH_EXCEP_LIST_REMOVE,
        BLE_MESH_EXCEP_INFO_MESH_LINK_ID, &link[i].link_id);
#endif

    /* Clear everything except the retransmit delayed work config */
    memset(&link[i], 0, offsetof(struct prov_link, tx.retransmit));

    link[i].pending_ack = XACT_NVAL;
    link[i].rx.prev_id  = XACT_NVAL;

    if (bt_mesh_pub_key_get()) {
        bt_mesh_atomic_set_bit(link[i].flags, LOCAL_PUB_KEY);
    }

    link[i].rx.buf = bt_mesh_pba_get_buf(i);

    if (prov_ctx.pba_count) {
        prov_ctx.pba_count--;
    }
}

static struct net_buf *adv_buf_create(void)
{
    struct net_buf *buf;

    buf = bt_mesh_adv_create(BLE_MESH_ADV_PROV, PROV_XMIT_COUNT,
                             PROV_XMIT_INT, BUF_TIMEOUT);
    if (!buf) {
        BT_ERR("Out of provisioning buffers");
        return NULL;
    }

    return buf;
}

static void ack_complete(u16_t duration, int err, void *user_data)
{
    int i = (int)user_data;

    BT_DBG("xact %u complete", (u8_t)link[i].pending_ack);

    link[i].pending_ack = XACT_NVAL;
}

static void gen_prov_ack_send(u8_t xact_id)
{
    static const struct bt_mesh_send_cb cb = {
        .start = ack_complete,
    };
    const struct bt_mesh_send_cb *complete;
    struct net_buf *buf;
    int i = prov_get_pb_index();

    BT_DBG("xact_id %u", xact_id);

    if (link[i].pending_ack == xact_id) {
        BT_DBG("Not sending duplicate ack");
        return;
    }

    buf = adv_buf_create();
    if (!buf) {
        return;
    }

    if (link[i].pending_ack == XACT_NVAL) {
        link[i].pending_ack = xact_id;
        complete = &cb;
    } else {
        complete = NULL;
    }

    net_buf_add_be32(buf, link[i].link_id);
    net_buf_add_u8(buf, xact_id);
    net_buf_add_u8(buf, GPC_ACK);

    bt_mesh_adv_send(buf, complete, (void *)i);
    net_buf_unref(buf);
}

static void send_reliable(int id)
{
    link[id].tx.start = k_uptime_get();

    for (int i = 0; i < ARRAY_SIZE(link[id].tx.buf); i++) {
        struct net_buf *buf = link[id].tx.buf[i];

        if (!buf) {
            break;
        }

        if (i + 1 < ARRAY_SIZE(link[id].tx.buf) && link[id].tx.buf[i + 1]) {
            bt_mesh_adv_send(buf, NULL, NULL);
        } else {
            bt_mesh_adv_send(buf, &buf_sent_cb, (void *)id);
        }
    }
}

static int bearer_ctl_send(int i, u8_t op, void *data, u8_t data_len)
{
    struct net_buf *buf;

    BT_DBG("op 0x%02x data_len %u", op, data_len);

    prov_clear_tx(i);

    buf = adv_buf_create();
    if (!buf) {
        return -ENOBUFS;
    }

    net_buf_add_be32(buf, link[i].link_id);
    /* Transaction ID, always 0 for Bearer messages */
    net_buf_add_u8(buf, 0x00);
    net_buf_add_u8(buf, GPC_CTL(op));
    net_buf_add_mem(buf, data, data_len);

    link[i].tx.buf[0] = buf;
    send_reliable(i);

    /** We can also use buf->ref and a flag to decide that
     *  link close has been sent 3 times.
     *  Here we use another way: use retransmit timer and need
     *  to make sure the timer is not cancelled during sending
     *  link close pdu, so we add link[i].tx.id = 0
     */
    if (op == LINK_CLOSE) {
        u8_t reason = *(u8_t *)data;
        link[i].link_close = (reason << 8 | BIT(0));
        link[i].tx.trans_id = 0;
    }

    return 0;
}

static void send_link_open(void)
{
    int i = prov_get_pb_index(), j;

    /** Generate link ID, and may need to check if this id is
     *  currently being used, which may will not happen ever.
     */
    bt_mesh_rand(&link[i].link_id, sizeof(u32_t));
    while (1) {
        for (j = 0; j < CONFIG_BLE_MESH_PBA_SAME_TIME; j++) {
            if (bt_mesh_atomic_test_bit(link[j].flags, LINK_ACTIVE) || link[j].linking) {
                if (link[i].link_id == link[j].link_id) {
                    bt_mesh_rand(&link[i].link_id, sizeof(u32_t));
                    break;
                }
            }
        }
        if (j == CONFIG_BLE_MESH_PBA_SAME_TIME) {
            break;
        }
    }

#if defined(CONFIG_BLE_MESH_USE_DUPLICATE_SCAN)
    /* Add the link id into exceptional list */
    bt_mesh_update_exceptional_list(BLE_MESH_EXCEP_LIST_ADD,
        BLE_MESH_EXCEP_INFO_MESH_LINK_ID, &link[i].link_id);
#endif

    bearer_ctl_send(i, LINK_OPEN, link[i].uuid, 16);

    /* Set LINK_ACTIVE just to be in compatibility with  current Zephyr code */
    bt_mesh_atomic_set_bit(link[i].flags, LINK_ACTIVE);

    prov_ctx.pba_count++;
}

static u8_t last_seg(u8_t len)
{
    if (len <= START_PAYLOAD_MAX) {
        return 0;
    }

    len -= START_PAYLOAD_MAX;

    return 1 + (len / CONT_PAYLOAD_MAX);
}

static inline u8_t next_transaction_id(void)
{
    int i = prov_get_pb_index();

    if (link[i].tx.trans_id < 0x7F) {
        return link[i].tx.trans_id++;
    }

    return 0x0;
}

static int prov_send_adv(struct net_buf_simple *msg)
{
    struct net_buf *start, *buf;
    u8_t seg_len, seg_id;
    u8_t xact_id;
    int i = prov_get_pb_index();

    BT_DBG("%s, len %u: %s", __func__, msg->len, bt_hex(msg->data, msg->len));

    prov_clear_tx(i);

    start = adv_buf_create();
    if (!start) {
        return -ENOBUFS;
    }

    xact_id = next_transaction_id();
    net_buf_add_be32(start, link[i].link_id);
    net_buf_add_u8(start, xact_id);

    net_buf_add_u8(start, GPC_START(last_seg(msg->len)));
    net_buf_add_be16(start, msg->len);
    net_buf_add_u8(start, bt_mesh_fcs_calc(msg->data, msg->len));

    link[i].tx.buf[0] = start;

    seg_len = MIN(msg->len, START_PAYLOAD_MAX);
    BT_DBG("seg 0 len %u: %s", seg_len, bt_hex(msg->data, seg_len));
    net_buf_add_mem(start, msg->data, seg_len);
    net_buf_simple_pull(msg, seg_len);

    buf = start;
    for (seg_id = 1; msg->len > 0; seg_id++) {
        if (seg_id >= ARRAY_SIZE(link[i].tx.buf)) {
            BT_ERR("%s, Too big message", __func__);
            free_segments(i);
            return -E2BIG;
        }

        buf = adv_buf_create();
        if (!buf) {
            free_segments(i);
            return -ENOBUFS;
        }

        link[i].tx.buf[seg_id] = buf;

        seg_len = MIN(msg->len, CONT_PAYLOAD_MAX);

        BT_DBG("seg_id %u len %u: %s", seg_id, seg_len,
               bt_hex(msg->data, seg_len));

        net_buf_add_be32(buf, link[i].link_id);
        net_buf_add_u8(buf, xact_id);
        net_buf_add_u8(buf, GPC_CONT(seg_id));
        net_buf_add_mem(buf, msg->data, seg_len);
        net_buf_simple_pull(msg, seg_len);
    }

    send_reliable(i);

    if (!bt_mesh_atomic_test_and_set_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_submit(&link[i].timeout, PROVISION_TIMEOUT);
    }

    return 0;
}
#endif /* CONFIG_BLE_MESH_PB_ADV */

#if defined(CONFIG_BLE_MESH_PB_GATT)
static int prov_send_gatt(struct net_buf_simple *msg)
{
    int i = prov_get_pb_index();
    int err;

    if (!link[i].conn) {
        return -ENOTCONN;
    }

    err = provisioner_proxy_send(link[i].conn, BLE_MESH_PROXY_PROV, msg);
    if (err) {
        BT_ERR("%s, Failed to send PB-GATT pdu", __func__);
        return err;
    }

    if (!bt_mesh_atomic_test_and_set_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_submit(&link[i].timeout, PROVISION_TIMEOUT);
    }

    return 0;
}
#endif /* CONFIG_BLE_MESH_PB_GATT */

static inline int prov_send(struct net_buf_simple *buf)
{
    int i = prov_get_pb_index();

    if (i < CONFIG_BLE_MESH_PBA_SAME_TIME) {
#if defined(CONFIG_BLE_MESH_PB_ADV)
        return prov_send_adv(buf);
#else
        return -EINVAL;
#endif
    } else if (i >= CONFIG_BLE_MESH_PBA_SAME_TIME &&
               i < BLE_MESH_PROV_SAME_TIME) {
#if defined(CONFIG_BLE_MESH_PB_GATT)
        return prov_send_gatt(buf);
#else
        return -EINVAL;
#endif
    } else {
        BT_ERR("%s, Link index exceeding upper limit", __func__);
        return -EINVAL;
    }
}

static void prov_buf_init(struct net_buf_simple *buf, u8_t type)
{
    net_buf_simple_init(buf, PROV_BUF_HEADROOM);
    net_buf_simple_add_u8(buf, type);
}

static void prov_invite(const u8_t *data)
{
    BT_DBG("%s", __func__);
}

static void prov_start(const u8_t *data)
{
    BT_DBG("%s", __func__);
}

static void prov_data(const u8_t *data)
{
    BT_DBG("%s", __func__);
}

static void send_invite(void)
{
    struct net_buf_simple *buf = PROV_BUF(2);
    int i = prov_get_pb_index();

    prov_buf_init(buf, PROV_INVITE);

    net_buf_simple_add_u8(buf, prov->prov_attention);

    link[i].conf_inputs[0] = prov->prov_attention;

    if (prov_send(buf)) {
        BT_ERR("%s, Failed to send Provisioning Invite", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    link[i].expect = PROV_CAPABILITIES;
}

static void prov_capabilities(const u8_t *data)
{
    struct net_buf_simple *buf = PROV_BUF(6);
    u16_t algorithms, output_action, input_action;
    u8_t  element_num, pub_key_oob, static_oob,
          output_size, input_size;
    u8_t  auth_method, auth_action, auth_size;
    int i = prov_get_pb_index();

    element_num = data[0];
    BT_DBG("Elements: %u", element_num);
    if (!element_num) {
        BT_ERR("%s, Invalid element number", __func__);
        goto fail;
    }
    link[i].element_num = element_num;

    algorithms = sys_get_be16(&data[1]);
    BT_DBG("Algorithms:        %u", algorithms);
    if (algorithms != BIT(PROV_ALG_P256)) {
        BT_ERR("%s, Invalid algorithms", __func__);
        goto fail;
    }

    pub_key_oob = data[3];
    BT_DBG("Public Key Type:   0x%02x", pub_key_oob);
    if (pub_key_oob > 0x01) {
        BT_ERR("%s, Invalid public key type", __func__);
        goto fail;
    }
    pub_key_oob = ((prov->prov_pub_key_oob &&
                    prov->prov_pub_key_oob_cb) ? pub_key_oob : 0x00);

    static_oob = data[4];
    BT_DBG("Static OOB Type:   0x%02x", static_oob);
    if (static_oob > 0x01) {
        BT_ERR("%s, Invalid Static OOB type", __func__);
        goto fail;
    }
    static_oob = (prov->prov_static_oob_val ? static_oob : 0x00);

    output_size = data[5];
    BT_DBG("Output OOB Size:   %u", output_size);
    if (output_size > 0x08) {
        BT_ERR("%s, Invalid Output OOB size", __func__);
        goto fail;
    }

    output_action = sys_get_be16(&data[6]);
    BT_DBG("Output OOB Action: 0x%04x", output_action);
    if (output_action > 0x1f) {
        BT_ERR("%s, Invalid Output OOB action", __func__);
        goto fail;
    }

    /* Provisioner select output action */
    if (prov->prov_input_num && output_size) {
        output_action = __builtin_ctz(output_action);
    } else {
        output_size = 0x0;
        output_action = 0x0;
    }

    input_size = data[8];
    BT_DBG("Input OOB Size: %u", input_size);
    if (input_size > 0x08) {
        BT_ERR("%s, Invalid Input OOB size", __func__);
        goto fail;
    }

    input_action = sys_get_be16(&data[9]);
    BT_DBG("Input OOB Action: 0x%04x", input_action);
    if (input_action > 0x0f) {
        BT_ERR("%s, Invalid Input OOB action", __func__);
        goto fail;
    }

    /* Make sure received pdu is ok and cancel the timeout timer */
    if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_cancel(&link[i].timeout);
    }

    /* Provisioner select input action */
    if (prov->prov_output_num && input_size) {
        input_action = __builtin_ctz(input_action);
    } else {
        input_size = 0x0;
        input_action = 0x0;
    }

    if (static_oob) {
        /* if static oob is valid, just use static oob */
        auth_method = AUTH_METHOD_STATIC;
        auth_action = 0x00;
        auth_size   = 0x00;
    } else {
        if (!output_size && !input_size) {
            auth_method = AUTH_METHOD_NO_OOB;
            auth_action = 0x00;
            auth_size   = 0x00;
        } else if (!output_size && input_size) {
            auth_method = AUTH_METHOD_INPUT;
            auth_action = (u8_t)input_action;
            auth_size   = input_size;
        } else {
            auth_method = AUTH_METHOD_OUTPUT;
            auth_action = (u8_t)output_action;
            auth_size   = output_size;
        }
    }

    /* Store provisioning capbilities value in conf_inputs */
    memcpy(&link[i].conf_inputs[1], data, 11);

    prov_buf_init(buf, PROV_START);
    net_buf_simple_add_u8(buf, prov->prov_algorithm);
    net_buf_simple_add_u8(buf, pub_key_oob);
    net_buf_simple_add_u8(buf, auth_method);
    net_buf_simple_add_u8(buf, auth_action);
    net_buf_simple_add_u8(buf, auth_size);

    memcpy(&link[i].conf_inputs[12], &buf->data[1], 5);

    if (prov_send(buf)) {
        BT_ERR("%s, Failed to send Provisioning Start", __func__);
        goto fail;
    }

    link[i].auth_method = auth_method;
    link[i].auth_action = auth_action;
    link[i].auth_size   = auth_size;

    /** After prov start sent, use OOB to get remote public key.
     *  And we just follow the procedure in Figure 5.15 of Section
     *  5.4.2.3 of Mesh Profile Spec.
     */
    if (pub_key_oob) {
        if (prov->prov_pub_key_oob_cb(i)) {
            BT_ERR("%s, Failed to notify input OOB Public Key", __func__);
            goto fail;
        }
    }

    /** If using PB-ADV, need to listen for transaction ack,
     *  after ack is received, provisioner can send public key.
     */
#if defined(CONFIG_BLE_MESH_PB_ADV)
    if (i < CONFIG_BLE_MESH_PBA_SAME_TIME) {
        link[i].expect_ack_for = PROV_START;
        return;
    }
#endif /* CONFIG_BLE_MESH_PB_ADV */

    send_pub_key(pub_key_oob);
    return;

fail:
    close_link(i, CLOSE_REASON_FAILED);
    return;
}

static bt_mesh_output_action_t output_action(u8_t action)
{
    switch (action) {
    case OUTPUT_OOB_BLINK:
        return BLE_MESH_BLINK;
    case OUTPUT_OOB_BEEP:
        return BLE_MESH_BEEP;
    case OUTPUT_OOB_VIBRATE:
        return BLE_MESH_VIBRATE;
    case OUTPUT_OOB_NUMBER:
        return BLE_MESH_DISPLAY_NUMBER;
    case OUTPUT_OOB_STRING:
        return BLE_MESH_DISPLAY_STRING;
    default:
        return BLE_MESH_NO_OUTPUT;
    }
}

static bt_mesh_input_action_t input_action(u8_t action)
{
    switch (action) {
    case INPUT_OOB_PUSH:
        return BLE_MESH_PUSH;
    case INPUT_OOB_TWIST:
        return BLE_MESH_TWIST;
    case INPUT_OOB_NUMBER:
        return BLE_MESH_ENTER_NUMBER;
    case INPUT_OOB_STRING:
        return BLE_MESH_ENTER_STRING;
    default:
        return BLE_MESH_NO_INPUT;
    }
}

static int prov_auth(u8_t method, u8_t action, u8_t size)
{
    bt_mesh_output_action_t output;
    bt_mesh_input_action_t input;
    int i = prov_get_pb_index();

    link[i].auth = (u8_t *)osi_calloc(PROV_AUTH_VAL_SIZE);
    if (!link[i].auth) {
        BT_ERR("%s, Failed to allocate memory", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return -ENOMEM;
    }

    switch (method) {
    case AUTH_METHOD_NO_OOB:
        if (action || size) {
            return -EINVAL;
        }
        memset(link[i].auth, 0, 16);
        return 0;

    case AUTH_METHOD_STATIC:
        if (action || size) {
            return -EINVAL;
        }
        memcpy(link[i].auth + 16 - prov->prov_static_oob_len,
               prov->prov_static_oob_val, prov->prov_static_oob_len);
        memset(link[i].auth, 0, 16 - prov->prov_static_oob_len);
        return 0;

    case AUTH_METHOD_OUTPUT:
        /* Use auth_action to get device output action */
        output = output_action(action);
        if (!output) {
            return -EINVAL;
        }
        return prov->prov_input_num(AUTH_METHOD_OUTPUT, output, size, i);

    case AUTH_METHOD_INPUT:
        /* Use auth_action to get device input action */
        input = input_action(action);
        if (!input) {
            return -EINVAL;
        }

        /* Provisioner ouputs number/string and wait for device's Provisioning Input Complete PDU */
        link[i].expect = PROV_INPUT_COMPLETE;

        if (input == BLE_MESH_ENTER_STRING) {
            unsigned char str[9];
            u8_t j;

            bt_mesh_rand(str, size);
            /* Normalize to '0' .. '9' & 'A' .. 'Z' */
            for (j = 0; j < size; j++) {
                str[j] %= 36;
                if (str[j] < 10) {
                    str[j] += '0';
                } else {
                    str[j] += 'A' - 10;
                }
            }
            str[size] = '\0';

            memcpy(link[i].auth, str, size);
            memset(link[i].auth + size, 0, sizeof(link[i].auth) - size);

            return prov->prov_output_num(AUTH_METHOD_INPUT, input, str, size, i);
        } else {
            u32_t div[8] = { 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
            u32_t num;

            bt_mesh_rand(&num, sizeof(num));
            num %= div[size - 1];

            sys_put_be32(num, &link[i].auth[12]);
            memset(link[i].auth, 0, 12);

            return prov->prov_output_num(AUTH_METHOD_INPUT, input, &num, size, i);
        }

    default:
        return -EINVAL;
    }
}

static void send_confirm(void)
{
    struct net_buf_simple *buf = PROV_BUF(17);
    int i = prov_get_pb_index();

    BT_DBG("ConfInputs[0]   %s", bt_hex(link[i].conf_inputs, 64));
    BT_DBG("ConfInputs[64]  %s", bt_hex(link[i].conf_inputs + 64, 64));
    BT_DBG("ConfInputs[128] %s", bt_hex(link[i].conf_inputs + 128, 17));

    link[i].conf_salt = (u8_t *)osi_calloc(PROV_CONF_SALT_SIZE);
    if (!link[i].conf_salt) {
        BT_ERR("%s, Failed to allocate memory", __func__);
        goto fail;
    }

    link[i].conf_key = (u8_t *)osi_calloc(PROV_CONF_KEY_SIZE);
    if (!link[i].conf_key) {
        BT_ERR("%s, Failed to allocate memory", __func__);
        goto fail;
    }

    if (bt_mesh_prov_conf_salt(link[i].conf_inputs, link[i].conf_salt)) {
        BT_ERR("%s, Failed to generate confirmation salt", __func__);
        goto fail;
    }

    BT_DBG("ConfirmationSalt: %s", bt_hex(link[i].conf_salt, 16));

    if (bt_mesh_prov_conf_key(link[i].dhkey, link[i].conf_salt, link[i].conf_key)) {
        BT_ERR("%s, Failed to generate confirmation key", __func__);
        goto fail;
    }

    BT_DBG("ConfirmationKey: %s", bt_hex(link[i].conf_key, 16));

    /** Provisioner use the same random number for each provisioning
     *  device, if different random need to be used, here provisioner
     *  should allocate memory for rand and call bt_mesh_rand() every time.
     */
    if (!(prov_ctx.rand_gen_done & BIT(0))) {
        if (bt_mesh_rand(prov_ctx.random, 16)) {
            BT_ERR("%s, Failed to generate random number", __func__);
            goto fail;
        }
        link[i].rand = prov_ctx.random;
        prov_ctx.rand_gen_done |= BIT(0);
    } else {
        /* Provisioner random has already been generated. */
        link[i].rand = prov_ctx.random;
    }

    BT_DBG("LocalRandom: %s", bt_hex(link[i].rand, 16));

    prov_buf_init(buf, PROV_CONFIRM);

    if (bt_mesh_prov_conf(link[i].conf_key, link[i].rand, link[i].auth,
                          net_buf_simple_add(buf, 16))) {
        BT_ERR("%s, Failed to generate confirmation value", __func__);
        goto fail;
    }

    if (prov_send(buf)) {
        BT_ERR("%s, Failed to send Provisioning Confirm", __func__);
        goto fail;
    }

    link[i].expect = PROV_CONFIRM;
    return;

fail:
    close_link(i, CLOSE_REASON_FAILED);
    return;
}

int bt_mesh_prov_set_oob_input_data(u8_t *val, u8_t link_idx, bool num_flag)
{
    /** This function should be called in the prov_input_num
     *  callback, after the data output by device has been
     *  input by provisioner.
     *  Paramter size is used to indicate the length of data
     *  indicated by Pointer val, for example, if device output
     *  data is 12345678(decimal), the data in auth value will
     *  be 0xBC614E.
     *  Parameter num_flag is used to indicate whether the value
     *  input by provisioner is number or string.
     */
    if (!link[link_idx].auth) {
        BT_ERR("%s, Link auth is NULL", __func__);
        return -EINVAL;
    }

    memset(link[link_idx].auth, 0, 16);
    if (num_flag) {
        /* Provisioner inputs number */
        memcpy(link[link_idx].auth + 12, val, sizeof(u32_t));
    } else {
        /* Provisioner inputs string */
        memcpy(link[link_idx].auth, val, link[link_idx].auth_size);
    }

    prov_set_pb_index(link_idx);
    send_confirm();

    return 0;
}

// int bt_mesh_prov_set_oob_output_data(u8_t *num, u8_t size, bool num_flag, u8_t link_idx)
// {
//     /** This function should be called in the prov_output_num
//      *  callback, after the data has been output by provisioner.
//      *  Parameter size is used to indicate the length of data
//      *  indicated by Pointer num, for example, if provisioner
//      *  output data is 12345678(decimal), the data in auth value
//      *  will be 0xBC614E.
//      *  Parameter num_flag is used to indicate whether the value
//      *  output by provisioner is number or string.
//      */
//     if (!link[link_idx].auth) {
//         BT_ERR("%s, link auth is NULL", __func__);
//         return -EINVAL;
//     }

//     if (num_flag) {
//         /* Provisioner output number */
//         memset(link[link_idx].auth, 0, 16);
//         memcpy(link[link_idx].auth + 16 - size, num, size);
//     } else {
//         /* Provisioner output string */
//         memset(link[link_idx].auth, 0, 16);
//         memcpy(link[link_idx].auth, num, size);
//     }

//     link[link_idx].expect = PROV_INPUT_COMPLETE;

//     return 0;
// }

int bt_mesh_prov_read_oob_pub_key(u8_t link_idx, u8_t pub_key_x[32], u8_t pub_key_y[32])
{
    if (!link[link_idx].conf_inputs) {
        BT_ERR("%s, Link conf_inputs is NULL", __func__);
        return -EINVAL;
    }

    /* Swap X and Y halves independently to big-endian */
    sys_memcpy_swap(&link[link_idx].conf_inputs[81], pub_key_x, 32);
    sys_memcpy_swap(&link[link_idx].conf_inputs[81] + 32, pub_key_y, 32);

    bt_mesh_atomic_set_bit(link[link_idx].flags, REMOTE_PUB_KEY);

    if (bt_mesh_atomic_test_and_clear_bit(link[link_idx].flags, WAIT_GEN_DHKEY)) {
        prov_gen_dh_key(link_idx);
    }

    return 0;
}

static void prov_dh_key_cb(const u8_t key[32])
{
    int i = prov_get_pb_index();

    BT_DBG("%p", key);

    if (!key) {
        BT_ERR("%s, Failed to generate DHKey", __func__);
        goto fail;
    }

    link[i].dhkey = (u8_t *)osi_calloc(PROV_DH_KEY_SIZE);
    if (!link[i].dhkey) {
        BT_ERR("%s, Failed to allocate memory", __func__);
        goto fail;
    }
    sys_memcpy_swap(link[i].dhkey, key, 32);

    BT_DBG("DHkey: %s", bt_hex(link[i].dhkey, 32));

    bt_mesh_atomic_set_bit(link[i].flags, HAVE_DHKEY);

    /** After dhkey is generated, if auth_method is No OOB or
     *  Static OOB, provisioner can start to send confirmation.
     *  If output OOB is used by the device, provisioner need
     *  to watch out the output number and input it as auth_val.
     *  If input OOB is used by the device, provisioner need
     *  to output a value, and wait for prov input complete pdu.
     */
    if (prov_auth(link[i].auth_method,
                  link[i].auth_action, link[i].auth_size) < 0) {
        BT_ERR("%s, Failed to authenticate", __func__);
        goto fail;
    }
    if (link[i].auth_method == AUTH_METHOD_OUTPUT ||
        link[i].auth_method == AUTH_METHOD_INPUT) {
        return;
    }

    if (link[i].expect != PROV_INPUT_COMPLETE) {
        send_confirm();
    }
    return;

fail:
    close_link(i, CLOSE_REASON_FAILED);
    return;
}

static void prov_gen_dh_key(int i)
{
    u8_t pub_key[64];

    /* Copy device public key in little-endian for bt_mesh_dh_key_gen().
     * X and Y halves are swapped independently.
     */
    sys_memcpy_swap(&pub_key[0], &link[i].conf_inputs[81], 32);
    sys_memcpy_swap(&pub_key[32], &link[i].conf_inputs[113], 32);

    if (bt_mesh_dh_key_gen(pub_key, prov_dh_key_cb)) {
        BT_ERR("%s, Failed to generate DHKey", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }
}

static void send_pub_key(u8_t oob)
{
    struct net_buf_simple *buf = PROV_BUF(65);
    const u8_t *key = NULL;
    int i = prov_get_pb_index();

    key = bt_mesh_pub_key_get();
    if (!key) {
        BT_ERR("%s, No public key available", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    BT_DBG("Local Public Key: %s", bt_hex(key, 64));

    bt_mesh_atomic_set_bit(link[i].flags, LOCAL_PUB_KEY);

    prov_buf_init(buf, PROV_PUB_KEY);

    /* Swap X and Y halves independently to big-endian */
    sys_memcpy_swap(net_buf_simple_add(buf, 32), key, 32);
    sys_memcpy_swap(net_buf_simple_add(buf, 32), &key[32], 32);

    /* Store provisioner public key value in conf_inputs */
    memcpy(&link[i].conf_inputs[17], &buf->data[1], 64);

    if (prov_send(buf)) {
        BT_ERR("%s, Failed to send Provisioning Public Key", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    if (!oob) {
        link[i].expect = PROV_PUB_KEY;
    } else {
        /** Have already got device public key. If next is to
         *  send confirm(not wait for input complete), need to
         *  wait for transactiona ack for public key then send
         *  provisioning confirm pdu.
         */
#if defined(CONFIG_BLE_MESH_PB_ADV)
        if (i < CONFIG_BLE_MESH_PBA_SAME_TIME) {
            link[i].expect_ack_for = PROV_PUB_KEY;
            return;
        }
#endif /* CONFIG_BLE_MESH_PB_ADV */

        /* If remote public key has been read, then start to generate DHkey,
         * otherwise wait for device oob public key.
         */
        if (bt_mesh_atomic_test_bit(link[i].flags, REMOTE_PUB_KEY)) {
            prov_gen_dh_key(i);
        } else {
            bt_mesh_atomic_set_bit(link[i].flags, WAIT_GEN_DHKEY);
        }
    }
}

static void prov_pub_key(const u8_t *data)
{
    int i = prov_get_pb_index();

    BT_DBG("Remote Public Key: %s", bt_hex(data, 64));

    /* Make sure received pdu is ok and cancel the timeout timer */
    if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_cancel(&link[i].timeout);
    }

    memcpy(&link[i].conf_inputs[81], data, 64);

    if (!bt_mesh_atomic_test_bit(link[i].flags, LOCAL_PUB_KEY)) {
        /* Clear retransmit timer */
#if defined(CONFIG_BLE_MESH_PB_ADV)
        prov_clear_tx(i);
#endif
        bt_mesh_atomic_set_bit(link[i].flags, REMOTE_PUB_KEY);
        BT_WARN("%s, Waiting for local public key", __func__);
        return;
    }

    prov_gen_dh_key(i);
}

static void prov_input_complete(const u8_t *data)
{
    int i = prov_get_pb_index();

    /* Make sure received pdu is ok and cancel the timeout timer */
    if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_cancel(&link[i].timeout);
    }

    /* Provisioner receives input complete and send confirm */
    send_confirm();
}

static void prov_confirm(const u8_t *data)
{
    /** Here Zephyr uses PROV_BUF(16). Currently test with PROV_BUF(16)
     *  and PROV_BUF(17) on branch feature/btdm_ble_mesh_debug both
     *  work fine.
     */
    struct net_buf_simple *buf = PROV_BUF(17);
    int i = prov_get_pb_index();

    BT_DBG("Remote Confirm: %s", bt_hex(data, 16));

    /* Make sure received pdu is ok and cancel the timeout timer */
    if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_cancel(&link[i].timeout);
    }

    link[i].conf = (u8_t *)osi_calloc(PROV_CONFIRM_SIZE);
    if (!link[i].conf) {
        BT_ERR("%s, Failed to allocate memory", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    memcpy(link[i].conf, data, 16);

    if (!bt_mesh_atomic_test_bit(link[i].flags, HAVE_DHKEY)) {
#if defined(CONFIG_BLE_MESH_PB_ADV)
        prov_clear_tx(i);
#endif
        bt_mesh_atomic_set_bit(link[i].flags, SEND_CONFIRM);
    }

    prov_buf_init(buf, PROV_RANDOM);

    net_buf_simple_add_mem(buf, link[i].rand, 16);

    if (prov_send(buf)) {
        BT_ERR("%s, Failed to send Provisioning Random", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    link[i].expect = PROV_RANDOM;
}

static void send_prov_data(void)
{
    struct net_buf_simple *buf = PROV_BUF(34);
    const u8_t *netkey = NULL;
    int   i = prov_get_pb_index();
    int   j, err;
    bool  already_flag = false;
    u8_t  session_key[16];
    u8_t  nonce[13];
    u8_t  pdu[25];
    u16_t max_addr;

    err = bt_mesh_session_key(link[i].dhkey, link[i].prov_salt, session_key);
    if (err) {
        BT_ERR("%s, Failed to generate session key", __func__);
        goto fail;
    }
    BT_DBG("SessionKey: %s", bt_hex(session_key, 16));

    err = bt_mesh_prov_nonce(link[i].dhkey, link[i].prov_salt, nonce);
    if (err) {
        BT_ERR("%s, Failed to generate session nonce", __func__);
        goto fail;
    }
    BT_DBG("Nonce: %s", bt_hex(nonce, 13));

    /* Assign provisioning data for the device. Currently all provisioned devices
     * will be added to the primary subnet, and may add an API to choose to which
     * subnet will the device be provisioned later.
     */
    if (FAST_PROV_FLAG_GET()) {
        netkey = fast_prov.net_key;
        if (!netkey) {
            BT_ERR("%s, Failed to get NetKey for fast provisioning", __func__);
            goto fail;
        }
        memcpy(pdu, netkey, 16);
        sys_put_be16(fast_prov.net_idx, &pdu[16]);
        pdu[18] = fast_prov.flags;
        sys_put_be32(fast_prov.iv_index, &pdu[19]);
    } else {
        netkey = provisioner_net_key_get(prov_ctx.curr_net_idx);
        if (!netkey) {
            BT_ERR("%s, Failed to get NetKey for provisioning data", __func__);
            goto fail;
        }
        memcpy(pdu, netkey, 16);
        sys_put_be16(prov_ctx.curr_net_idx, &pdu[16]);
        pdu[18] = prov_ctx.curr_flags;
        sys_put_be32(prov_ctx.curr_iv_index, &pdu[19]);
    }

    /* 1. The Provisioner must not reuse unicast addresses that have been
     *    allocated to a device and sent in a Provisioning Data PDU until
     *    the Provisioner receives an Unprovisioned Device beacon or
     *    Service Data for the Mesh Provisioning Service from that same
     *    device, identified using the Device UUID of the device.
     * 2. Once the provisioning data for the device has been sent, we will
     *    add the data sent to this device into the already_prov_info.
     * 3. Another situation here is:
     *    If the device is a re-provisioned one, but the element num has
     *    changed and is larger than the previous number, here we will
     *    assign new address for the device.
     */

    /* Check if this device is a re-provisioned device */
    for (j = 0; j < BLE_MESH_ALREADY_PROV_NUM; j++) {
        if (!memcmp(link[i].uuid, prov_ctx.already_prov[j].uuid, 16)) {
            if (link[i].element_num <= prov_ctx.already_prov[j].element_num) {
                already_flag = true;
                sys_put_be16(prov_ctx.already_prov[j].unicast_addr, &pdu[23]);
                link[i].unicast_addr = prov_ctx.already_prov[j].unicast_addr;
                break;
            } else {
                /* TODO: If the device has a larger element number during the
                 * second provisioning, then if the device is provisioned the
                 * third time later, already_prov struct will have two elements
                 * containing the same device UUID but with different element
                 * number. So we may add a flag to indicate the unicast address
                 * in the smaller element can be reused by other devices when
                 * unicast address is exhausted.
                 */
            }
        }
    }

    max_addr = FAST_PROV_FLAG_GET() ? fast_prov.unicast_addr_max : 0x7FFF;

    if (!already_flag) {
        /* If this device to be provisioned is a new device */
        if (!prov_ctx.current_addr) {
            BT_ERR("%s, No unicast address can be assigned", __func__);
            goto fail;
        }

        if (prov_ctx.current_addr + link[i].element_num - 1 > max_addr) {
            BT_ERR("%s, Not enough unicast address for the device", __func__);
            goto fail;
        }

        sys_put_be16(prov_ctx.current_addr, &pdu[23]);
        link[i].unicast_addr = prov_ctx.current_addr;
    }

    prov_buf_init(buf, PROV_DATA);

    err = bt_mesh_prov_encrypt(session_key, nonce, pdu, net_buf_simple_add(buf, 33));
    if (err) {
        BT_ERR("%s, Failed to encrypt provisioning data", __func__);
        goto fail;
    }

    if (prov_send(buf)) {
        BT_ERR("%s, Failed to send Provisioning Data", __func__);
        goto fail;
    }

    /* If provisioning data is sent successfully, add the assigned information
     * into the already_prov_info struct if this device is a new one. And if
     * sent successfully, update the current_addr in prov_ctx struct.
     */
    if (!already_flag) {
        for (j = 0; j < BLE_MESH_ALREADY_PROV_NUM; j++) {
            if (!prov_ctx.already_prov[j].element_num) {
                memcpy(prov_ctx.already_prov[j].uuid, link[i].uuid, 16);
                prov_ctx.already_prov[j].element_num  = link[i].element_num;
                prov_ctx.already_prov[j].unicast_addr = link[i].unicast_addr;
                break;
            }
        }

        /* We update the next unicast address to be assigned here because
         * if provisioner is provisioning two devices at the same time, we
         * need to assign the unicast address for them correctly. Hence we
         * should not update the prov_ctx.current_addr after the proper
         * provisioning complete pdu is received.
         */
        prov_ctx.current_addr += link[i].element_num;
        if (prov_ctx.current_addr > max_addr) {
            /* No unicast address will be used for further provisioning */
            prov_ctx.current_addr = 0x0000;
        }
    }

    if (FAST_PROV_FLAG_GET()) {
        link[i].ki_flags = fast_prov.flags;
        link[i].iv_index = fast_prov.iv_index;
    } else {
        link[i].ki_flags = prov_ctx.curr_flags;
        link[i].iv_index = prov_ctx.curr_iv_index;
    }

    link[i].expect = PROV_COMPLETE;
    return;

fail:
    close_link(i, CLOSE_REASON_FAILED);
    return;
}

static void prov_random(const u8_t *data)
{
    u8_t conf_verify[16];
    int i = prov_get_pb_index();

    BT_DBG("Remote Random: %s", bt_hex(data, 16));

    if (bt_mesh_prov_conf(link[i].conf_key, data, link[i].auth, conf_verify)) {
        BT_ERR("%s, Failed to calculate confirmation verification", __func__);
        goto fail;
    }

    if (memcmp(conf_verify, link[i].conf, 16)) {
        BT_ERR("%s, Invalid confirmation value", __func__);
        BT_DBG("Received:   %s", bt_hex(link[i].conf, 16));
        BT_DBG("Calculated: %s",  bt_hex(conf_verify, 16));
        goto fail;
    }

    /*Verify received confirm is ok and cancel the timeout timer */
    if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_cancel(&link[i].timeout);
    }

    /** After provisioner receives provisioning random from device,
     *  and successfully check the confirmation, the following
     *  should be done:
     *  1. osi_calloc memory for prov_salt
     *  2. calculate prov_salt
     *  3. prepare provisioning data and send
     */
    link[i].prov_salt = (u8_t *)osi_calloc(PROV_PROV_SALT_SIZE);
    if (!link[i].prov_salt) {
        BT_ERR("%s, Failed to allocate memory", __func__);
        goto fail;
    }

    if (bt_mesh_prov_salt(link[i].conf_salt, link[i].rand, data,
                          link[i].prov_salt)) {
        BT_ERR("%s, Failed to generate ProvisioningSalt", __func__);
        goto fail;
    }

    BT_DBG("ProvisioningSalt: %s", bt_hex(link[i].prov_salt, 16));

    send_prov_data();
    return;

fail:
    close_link(i, CLOSE_REASON_FAILED);
    return;
}

static void prov_complete(const u8_t *data)
{
    u8_t device_key[16];
    int i = prov_get_pb_index(), j;
    int err, rm = 0;

    /* Make sure received pdu is ok and cancel the timeout timer */
    if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_cancel(&link[i].timeout);
    }

    /* If provisioning complete is received, the provisioning device
     * will be stored into the prov_node_info structure and become a
     * node within the mesh network
     */
    err = bt_mesh_dev_key(link[i].dhkey, link[i].prov_salt, device_key);
    if (err) {
        BT_ERR("%s, Failed to generate device key", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    for (j = 0; j < ARRAY_SIZE(prov_nodes); j++) {
        if (!prov_nodes[j].provisioned) {
            prov_nodes[j].provisioned = true;
            prov_nodes[j].oob_info = link[i].oob_info;
            prov_nodes[j].element_num = link[i].element_num;
            prov_nodes[j].unicast_addr = link[i].unicast_addr;
            if (FAST_PROV_FLAG_GET()) {
                prov_nodes[j].net_idx = fast_prov.net_idx;
            } else {
                prov_nodes[j].net_idx = prov_ctx.curr_net_idx;
            }
            prov_nodes[j].flags = link[i].ki_flags;
            prov_nodes[j].iv_index = link[i].iv_index;
            prov_nodes[j].addr.type = link[i].addr.type;
            memcpy(prov_nodes[j].addr.val, link[i].addr.val, BLE_MESH_ADDR_LEN);
            memcpy(prov_nodes[j].uuid, link[i].uuid, 16);
            break;
        }
    }

    if (j == ARRAY_SIZE(prov_nodes)) {
        BT_ERR("%s, Provisioned node queue is full", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    prov_ctx.node_count++;

    err = provisioner_node_provision(j, prov_nodes[j].uuid, prov_nodes[j].oob_info,
                prov_nodes[j].unicast_addr, prov_nodes[j].element_num,
                prov_nodes[j].net_idx, prov_nodes[j].flags,
                prov_nodes[j].iv_index, device_key);
    if (err) {
        BT_ERR("%s, Failed to store node info", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    if (prov->prov_complete) {
        prov->prov_complete(j, prov_nodes[j].uuid, prov_nodes[j].unicast_addr,
                            prov_nodes[j].element_num, prov_nodes[j].net_idx);
    }

    err = provisioner_dev_find(&link[i].addr, link[i].uuid, &rm);
    if (!err) {
        if (unprov_dev[rm].flags & RM_AFTER_PROV) {
            memset(&unprov_dev[rm], 0, sizeof(struct unprov_dev_queue));
        }
    } else if (err == -ENODEV) {
        BT_DBG("%s, Device is not found in queue", __func__);
    } else {
        BT_WARN("%s, Failed to remove device from queue", __func__);
    }

    close_link(i, CLOSE_REASON_SUCCESS);
}

static void prov_failed(const u8_t *data)
{
    int i = prov_get_pb_index();

    BT_WARN("%s, Error 0x%02x", __func__, data[0]);

    close_link(i, CLOSE_REASON_FAILED);
}

static const struct {
    void (*func)(const u8_t *data);
    u16_t len;
} prov_handlers[] = {
    { prov_invite,         1  },
    { prov_capabilities,   11 },
    { prov_start,          5  },
    { prov_pub_key,        64 },
    { prov_input_complete, 0  },
    { prov_confirm,        16 },
    { prov_random,         16 },
    { prov_data,           33 },
    { prov_complete,       0  },
    { prov_failed,         1  },
};

static void close_link(int i, u8_t reason)
{
    if (i < CONFIG_BLE_MESH_PBA_SAME_TIME) {
#if defined(CONFIG_BLE_MESH_PB_ADV)
        bearer_ctl_send(i, LINK_CLOSE, &reason, sizeof(reason));
#endif
    } else if (i >= CONFIG_BLE_MESH_PBA_SAME_TIME &&
               i < BLE_MESH_PROV_SAME_TIME) {
#if defined(CONFIG_BLE_MESH_PB_GATT)
        if (link[i].conn) {
            bt_mesh_gattc_disconnect(link[i].conn);
        }
#endif
    } else {
        BT_ERR("%s, Invalid link index %d", __func__, i);
    }
}

static void prov_timeout(struct k_work *work)
{
    int i = work->index;

    BT_DBG("%s", __func__);

    close_link(i, CLOSE_REASON_TIMEOUT);
}

#if defined(CONFIG_BLE_MESH_PB_ADV)
static void prov_retransmit(struct k_work *work)
{
    int id = work->index;

    BT_DBG("%s", __func__);

    if (!bt_mesh_atomic_test_bit(link[id].flags, LINK_ACTIVE)) {
        BT_WARN("%s, Link is not active", __func__);
        return;
    }

    if (k_uptime_get() - link[id].tx.start > TRANSACTION_TIMEOUT) {
        BT_WARN("%s, Timeout, giving up transaction", __func__);
        close_link(id, CLOSE_REASON_TIMEOUT);
        return;
    }

    if (link[id].link_close & BIT(0)) {
        if (link[id].link_close >> 1 & 0x02) {
            reset_link(id, link[id].link_close >> 8);
            return;
        }
        link[id].link_close += BIT(1);
    }

    for (int i = 0; i < ARRAY_SIZE(link[id].tx.buf); i++) {
        struct net_buf *buf = link[id].tx.buf[i];

        if (!buf) {
            break;
        }

        if (BLE_MESH_ADV(buf)->busy) {
            continue;
        }

        BT_DBG("%u bytes: %s", buf->len, bt_hex(buf->data, buf->len));

        if (i + 1 < ARRAY_SIZE(link[id].tx.buf) && link[id].tx.buf[i + 1]) {
            bt_mesh_adv_send(buf, NULL, NULL);
        } else {
            bt_mesh_adv_send(buf, &buf_sent_cb, (void *)id);
        }
    }
}

static void link_ack(struct prov_rx *rx, struct net_buf_simple *buf)
{
    int i = prov_get_pb_index();

    BT_DBG("len %u", buf->len);

    if (buf->len) {
        BT_ERR("%s, Invalid Link ACK length", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    if (link[i].expect == PROV_CAPABILITIES) {
        BT_WARN("%s, Link ACK is already received", __func__);
        return;
    }

    link[i].conf_inputs = (u8_t *)osi_calloc(PROV_CONF_INPUTS_SIZE);
    if (!link[i].conf_inputs) {
        BT_ERR("%s, Failed to allocate memory", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    /** After received link_ack, we don't call prov_clear_tx() to
     *  cancel retransmit timer, because retransmit timer will be
     *  cancelled after we send the provisioning invite pdu.
     */
    send_invite();
}

static void link_close(struct prov_rx *rx, struct net_buf_simple *buf)
{
    u8_t reason;
    int i = prov_get_pb_index();

    BT_DBG("len %u", buf->len);

    reason = net_buf_simple_pull_u8(buf);

    reset_link(i, reason);
}

static void gen_prov_ctl(struct prov_rx *rx, struct net_buf_simple *buf)
{
    int i = prov_get_pb_index();

    BT_DBG("op 0x%02x len %u", BEARER_CTL(rx->gpc), buf->len);

    switch (BEARER_CTL(rx->gpc)) {
    case LINK_OPEN:
        break;

    case LINK_ACK:
        if (!bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE)) {
            return;
        }
        link_ack(rx, buf);
        break;

    case LINK_CLOSE:
        if (!bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE)) {
            return;
        }
        link_close(rx, buf);
        break;

    default:
        BT_ERR("%s, Unknown bearer opcode 0x%02x", __func__, BEARER_CTL(rx->gpc));
        return;
    }
}

static void prov_msg_recv(void)
{
    int i = prov_get_pb_index();

    u8_t type = link[i].rx.buf->data[0];

    BT_DBG("type 0x%02x len %u", type, link[i].rx.buf->len);

    /** Provisioner first checks information of the received
     *  provisioing pdu, and once succeed, check the fcs
     */
    if (type != PROV_FAILED && type != link[i].expect) {
        BT_ERR("%s, Unexpected msg 0x%02x != 0x%02x", __func__, type, link[i].expect);
        goto fail;
    }

    if (type >= 0x0A) {
        BT_ERR("%s, Unknown provisioning PDU type 0x%02x", __func__, type);
        goto fail;
    }

    if (1 + prov_handlers[type].len != link[i].rx.buf->len) {
        BT_ERR("%s, Invalid length %u for type 0x%02x", __func__, link[i].rx.buf->len, type);
        goto fail;
    }

    if (!bt_mesh_fcs_check(link[i].rx.buf, link[i].rx.fcs)) {
        BT_ERR("%s, Incorrect FCS", __func__);
        goto fail;
    }

    gen_prov_ack_send(link[i].rx.trans_id);
    link[i].rx.prev_id = link[i].rx.trans_id;
    link[i].rx.trans_id = 0;

    prov_handlers[type].func(&link[i].rx.buf->data[1]);
    return;

fail:
    close_link(i, CLOSE_REASON_FAILED);
    return;
}

static void gen_prov_cont(struct prov_rx *rx, struct net_buf_simple *buf)
{
    u8_t seg = CONT_SEG_INDEX(rx->gpc);
    int i = prov_get_pb_index();

    BT_DBG("len %u, seg_index %u", buf->len, seg);

    if (!link[i].rx.seg && link[i].rx.prev_id == rx->xact_id) {
        BT_WARN("%s, Resending ack", __func__);
        gen_prov_ack_send(rx->xact_id);
        return;
    }

    if (rx->xact_id != link[i].rx.trans_id) {
        BT_WARN("%s, Data for unknown transaction (%u != %u)",
            __func__, rx->xact_id, link[i].rx.trans_id);
        /* If Provisioner receives a Provisioning PDU with a mismatch
         * transaction number, it just ignore the PDU.
         */
        return;
    }

    if (seg > link[i].rx.last_seg) {
        BT_ERR("%s, Invalid segment index %u", __func__, seg);
        goto fail;
    } else if (seg == link[i].rx.last_seg) {
        u8_t expect_len;

        expect_len = (link[i].rx.buf->len - 20 -
                      (23 * (link[i].rx.last_seg - 1)));
        if (expect_len != buf->len) {
            BT_ERR("%s, Incorrect last seg len: %u != %u",
                __func__, expect_len, buf->len);
            goto fail;
        }
    }

    if (!(link[i].rx.seg & BIT(seg))) {
        BT_WARN("%s, Ignore already received segment", __func__);
        return;
    }

    memcpy(XACT_SEG_DATA(seg), buf->data, buf->len);
    XACT_SEG_RECV(seg);

    if (!link[i].rx.seg) {
        prov_msg_recv();
    }
    return;

fail:
    close_link(i, CLOSE_REASON_FAILED);
    return;
}

static void gen_prov_ack(struct prov_rx *rx, struct net_buf_simple *buf)
{
    int i = prov_get_pb_index();
    u8_t ack_type, pub_key_oob;

    BT_DBG("len %u", buf->len);

    if (!link[i].tx.buf[0]) {
        return;
    }

    if (!link[i].tx.trans_id) {
        return;
    }

    if (rx->xact_id == (link[i].tx.trans_id - 1)) {
        prov_clear_tx(i);

        ack_type = link[i].expect_ack_for;
        switch (ack_type) {
        case PROV_START:
            pub_key_oob = link[i].conf_inputs[13];
            send_pub_key(pub_key_oob);
            break;
        case PROV_PUB_KEY:
            prov_gen_dh_key(i);
            break;
        default:
            break;
        }
        link[i].expect_ack_for = 0x00;
    }
}

static void gen_prov_start(struct prov_rx *rx, struct net_buf_simple *buf)
{
    int i = prov_get_pb_index();

    if (link[i].rx.seg) {
        BT_WARN("%s, Get Start while there are unreceived segments", __func__);
        return;
    }

    if (link[i].rx.prev_id == rx->xact_id) {
        BT_WARN("%s, Resending ack", __func__);
        gen_prov_ack_send(rx->xact_id);
        return;
    }

    link[i].rx.buf->len = net_buf_simple_pull_be16(buf);
    link[i].rx.trans_id = rx->xact_id;
    link[i].rx.fcs = net_buf_simple_pull_u8(buf);

    BT_DBG("len %u last_seg %u total_len %u fcs 0x%02x", buf->len,
           START_LAST_SEG(rx->gpc), link[i].rx.buf->len, link[i].rx.fcs);

    /* Provisioner can not receive zero-length provisioning pdu */
    if (link[i].rx.buf->len < 1) {
        BT_ERR("%s, Ignoring zero-length provisioning PDU", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    if (link[i].rx.buf->len > link[i].rx.buf->size) {
        BT_ERR("%s, Too large provisioning PDU (%u bytes)", __func__, link[i].rx.buf->len);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    if (START_LAST_SEG(rx->gpc) > 0 && link[i].rx.buf->len <= 20) {
        BT_ERR("%s, Too small total length for multi-segment PDU", __func__);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    link[i].rx.seg = (1 << (START_LAST_SEG(rx->gpc) + 1)) - 1;
    link[i].rx.last_seg = START_LAST_SEG(rx->gpc);
    memcpy(link[i].rx.buf->data, buf->data, buf->len);
    XACT_SEG_RECV(0);

    if (!link[i].rx.seg) {
        prov_msg_recv();
    }
}

static const struct {
    void (*const func)(struct prov_rx *rx, struct net_buf_simple *buf);
    const u8_t require_link;
    const u8_t min_len;
} gen_prov[] = {
    { gen_prov_start, true,  3 },
    { gen_prov_ack,   true,  0 },
    { gen_prov_cont,  true,  0 },
    { gen_prov_ctl,   true,  0 },
};

static void gen_prov_recv(struct prov_rx *rx, struct net_buf_simple *buf)
{
    int i = prov_get_pb_index();

    if (buf->len < gen_prov[GPCF(rx->gpc)].min_len) {
        BT_ERR("%s, Too short GPC message type %u", __func__, GPCF(rx->gpc));
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    /** require_link flag can be used combined with link[].linking flag
     *  to set LINK_ACTIVE status after link_ack pdu is received.
     *  And if so, we shall not check LINK_ACTIVE status in the
     *  function find_link().
     */
    if (!bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE) &&
            gen_prov[GPCF(rx->gpc)].require_link) {
        BT_DBG("Ignoring message that requires active link");
        return;
    }

    gen_prov[GPCF(rx->gpc)].func(rx, buf);
}

static int find_link(u32_t link_id, bool set)
{
    int i;

    /* link for PB-ADV is from 0 to CONFIG_BLE_MESH_PBA_SAME_TIME */
    for (i = 0; i < CONFIG_BLE_MESH_PBA_SAME_TIME; i++) {
        if (bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE)) {
            if (link[i].link_id == link_id) {
                if (set) {
                    prov_set_pb_index(i);
                }
                return 0;
            }
        }
    }

    return -1;
}

void provisioner_pb_adv_recv(struct net_buf_simple *buf)
{
    struct prov_rx rx;
    int i;

    rx.link_id = net_buf_simple_pull_be32(buf);
    if (find_link(rx.link_id, true) < 0) {
        BT_DBG("%s, Data for unexpected link", __func__);
        return;
    }

    i = prov_get_pb_index();

    if (buf->len < 2) {
        BT_ERR("%s, Too short provisioning packet (len %u)", __func__, buf->len);
        close_link(i, CLOSE_REASON_FAILED);
        return;
    }

    rx.xact_id = net_buf_simple_pull_u8(buf);
    rx.gpc = net_buf_simple_pull_u8(buf);

    BT_DBG("link_id 0x%08x xact_id %u", rx.link_id, rx.xact_id);

    gen_prov_recv(&rx, buf);
}
#endif /* CONFIG_BLE_MESH_PB_ADV */

#if defined(CONFIG_BLE_MESH_PB_GATT)
static struct bt_mesh_conn *find_conn(struct bt_mesh_conn *conn, bool set)
{
    int i;

    /* link for PB-GATT is from CONFIG_BLE_MESH_PBA_SAME_TIME to BLE_MESH_PROV_SAME_TIME */
    for (i = CONFIG_BLE_MESH_PBA_SAME_TIME; i < BLE_MESH_PROV_SAME_TIME; i++) {
        if (bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE)) {
            if (link[i].conn == conn) {
                if (set) {
                    prov_set_pb_index(i);
                }
                return conn;
            }
        }
    }

    return NULL;
}

int provisioner_pb_gatt_recv(struct bt_mesh_conn *conn, struct net_buf_simple *buf)
{
    u8_t type;
    int i;

    BT_DBG("%u bytes: %s", buf->len, bt_hex(buf->data, buf->len));

    if (!find_conn(conn, true)) {
        BT_ERR("%s, Data for unexpected connection", __func__);
        return -ENOTCONN;
    }

    i = prov_get_pb_index();

    if (buf->len < 1) {
        BT_ERR("%s, Too short provisioning packet (len %u)", __func__, buf->len);
        goto fail;
    }

    type = net_buf_simple_pull_u8(buf);
    if (type != PROV_FAILED && type != link[i].expect) {
        BT_ERR("%s, Unexpected msg 0x%02x != 0x%02x", __func__, type, link[i].expect);
        goto fail;
    }

    if (type >= 0x0A) {
        BT_ERR("%s, Unknown provisioning PDU type 0x%02x", __func__, type);
        goto fail;
    }

    if (prov_handlers[type].len != buf->len) {
        BT_ERR("%s, Invalid length %u for type 0x%02x", __func__, buf->len, type);
        goto fail;
    }

    prov_handlers[type].func(buf->data);

    return 0;

fail:
    /* Mesh Spec Section 5.4.4 Provisioning errors */
    close_link(i, CLOSE_REASON_FAILED);
    return -EINVAL;
}

int provisioner_set_prov_conn(const u8_t addr[6], struct bt_mesh_conn *conn)
{
    if (!addr || !conn) {
        BT_ERR("%s, Invalid parameter", __func__);
        return -EINVAL;
    }

    for (int i = CONFIG_BLE_MESH_PBA_SAME_TIME; i < BLE_MESH_PROV_SAME_TIME; i++) {
        if (!memcmp(link[i].addr.val, addr, BLE_MESH_ADDR_LEN)) {
            link[i].conn = bt_mesh_conn_ref(conn);
            return 0;
        }
    }

    BT_ERR("%s, Address %s is not found", __func__, bt_hex(addr, BLE_MESH_ADDR_LEN));
    return -ENOMEM;
}

int provisioner_pb_gatt_open(struct bt_mesh_conn *conn, u8_t *addr)
{
    int i, id = 0;

    BT_DBG("conn %p", conn);

    /** Double check if the device is currently being provisioned
     *  using PB-ADV.
     *  Provisioner binds conn with proper device when
     *  proxy_prov_connected() is invoked, and here after proper GATT
     *  procedures are completed, we just check if this conn already
     *  exists in the proxy servers array.
     */
    for (i = CONFIG_BLE_MESH_PBA_SAME_TIME; i < BLE_MESH_PROV_SAME_TIME; i++) {
        if (link[i].conn == conn) {
            id = i;
            break;
        }
    }

    if (i == BLE_MESH_PROV_SAME_TIME) {
        BT_ERR("%s, Link is not found", __func__);
        return -ENOTCONN;
    }

    prov_set_pb_index(id);

    for (i = 0; i < CONFIG_BLE_MESH_PBA_SAME_TIME; i++) {
        if (bt_mesh_atomic_test_bit(link[i].flags, LINK_ACTIVE)) {
            if (!memcmp(link[i].uuid, link[id].uuid, 16)) {
                BT_WARN("%s, Provision using PB-GATT & PB-ADV same time", __func__);
                close_link(id, CLOSE_REASON_FAILED);
                return -EALREADY;
            }
        }
    }

    bt_mesh_atomic_set_bit(link[id].flags, LINK_ACTIVE);
    link[id].conn = bt_mesh_conn_ref(conn);

    /* May use lcd to indicate starting provisioning each device */
    if (prov->prov_link_open) {
        prov->prov_link_open(BLE_MESH_PROV_GATT);
    }

    link[id].conf_inputs = (u8_t *)osi_calloc(PROV_CONF_INPUTS_SIZE);
    if (!link[id].conf_inputs) {
        /* Disconnect this connection, clear corresponding informations */
        BT_ERR("%s, Failed to allocate memory", __func__);
        close_link(id, CLOSE_REASON_FAILED);
        return -ENOMEM;
    }

    send_invite();

    return 0;
}

int provisioner_pb_gatt_close(struct bt_mesh_conn *conn, u8_t reason)
{
    int i;

    BT_DBG("conn %p", conn);

    if (!find_conn(conn, true)) {
        BT_ERR("%s, Conn %p is not found", __func__, conn);
        return -ENOTCONN;
    }

    i = prov_get_pb_index();

    if (bt_mesh_atomic_test_and_clear_bit(link[i].flags, TIMEOUT_START)) {
        k_delayed_work_cancel(&link[i].timeout);
    }

    if (prov->prov_link_close) {
        prov->prov_link_close(BLE_MESH_PROV_GATT, reason);
    }

    prov_memory_free(i);

    memset(&link[i], 0, offsetof(struct prov_link, timeout));

    if (bt_mesh_pub_key_get()) {
        bt_mesh_atomic_set_bit(link[i].flags, LOCAL_PUB_KEY);
    }

    return 0;
}
#endif /* CONFIG_BLE_MESH_PB_GATT */

int provisioner_prov_init(const struct bt_mesh_prov *prov_info)
{
    const u8_t *key = NULL;
    int i;

    if (!prov_info) {
        BT_ERR("%s, No provisioning context provided", __func__);
        return -EINVAL;
    }

    if (CONFIG_BLE_MESH_PBG_SAME_TIME > CONFIG_BT_MAX_CONN) {
        BT_ERR("%s, PB-GATT same time exceeds max connection", __func__);
        return -EINVAL;
    }

    key = bt_mesh_pub_key_get();
    if (!key) {
        BT_ERR("%s, Failed to generate Public Key", __func__);
        return -EIO;
    }

    prov = prov_info;

#if defined(CONFIG_BLE_MESH_PB_ADV)
    for (i = 0; i < CONFIG_BLE_MESH_PBA_SAME_TIME; i++) {
        adv_buf[i].buf.size = ADV_BUF_SIZE;
        link[i].pending_ack = XACT_NVAL;
        k_delayed_work_init(&link[i].tx.retransmit, prov_retransmit);
        link[i].tx.retransmit.work.index = i;
        link[i].rx.prev_id = XACT_NVAL;
        link[i].rx.buf = bt_mesh_pba_get_buf(i);
    }
#endif

    for (i = 0; i < BLE_MESH_PROV_SAME_TIME; i++) {
        k_delayed_work_init(&link[i].timeout, prov_timeout);
        link[i].timeout.work.index = i;
    }

    /* for PB-GATT, use servers[] array in proxy_provisioner.c */

    prov_ctx.current_addr = prov->prov_start_address;
    prov_ctx.curr_net_idx = BLE_MESH_KEY_PRIMARY;
    prov_ctx.curr_flags = prov->flags;
    prov_ctx.curr_iv_index = prov->iv_index;

    return 0;
}

static int provisioner_notify_unprov_adv_pkt(bt_mesh_prov_bearer_t bearer, const u8_t uuid[16],
                const bt_mesh_addr_t *addr, u16_t oob_info)
{
    u8_t adv_type;
    int index;

    if ((bearer != BLE_MESH_PROV_ADV && bearer != BLE_MESH_PROV_GATT) || !uuid || !addr) {
        BT_ERR("%s, invalid parameter", __func__);
        return -EINVAL;
    }

    adv_type = (bearer == BLE_MESH_PROV_ADV) ? BLE_MESH_ADV_NONCONN_IND : BLE_MESH_ADV_IND;

    if (prov_ctx.prov_after_match == false) {
        if (provisioner_dev_find(addr, uuid, &index)) {
            BT_DBG("%s, Device is not found, notify to upper layer", __func__);
            if (notify_unprov_adv_pkt_cb) {
                notify_unprov_adv_pkt_cb(addr->val, addr->type, adv_type, uuid, oob_info, bearer);
            }
            return -EALREADY;
        }

        if (!(unprov_dev[index].bearer & bearer)) {
            BT_DBG("%s, Not support PB-%s", __func__, (bearer == BLE_MESH_PROV_ADV) ? "ADV" : "GATT");
            return -EIO;
        }
    }

    return 0;
}

void provisioner_unprov_beacon_recv(struct net_buf_simple *buf)
{
#if defined(CONFIG_BLE_MESH_PB_ADV)
    const bt_mesh_addr_t *addr = NULL;
    u8_t *uuid = NULL;
    u16_t oob_info;

    if (buf->len != 0x12 && buf->len != 0x16) {
        BT_ERR("%s, Invalid Unprovisioned Device Beacon length", __func__);
        return;
    }

    if (prov_ctx.pba_count == CONFIG_BLE_MESH_PBA_SAME_TIME) {
        BT_DBG("Current PB-ADV devices reach max limit");
        return;
    }

    addr = bt_mesh_pba_get_addr();
    uuid = buf->data;
    net_buf_simple_pull(buf, 16);
    /* Mesh beacon uses big-endian to send beacon data */
    oob_info = net_buf_simple_pull_be16(buf);

    if (provisioner_check_device_uuid(uuid)) {
        return;
    }

    if (provisioner_notify_unprov_adv_pkt(
            BLE_MESH_PROV_ADV, uuid, addr, oob_info)) {
        return;
    }

    provisioner_start_prov_device(BLE_MESH_PROV_ADV, uuid, addr, oob_info);
#endif /* CONFIG_BLE_MESH_PB_ADV */
}

bool provisioner_flags_match(struct net_buf_simple *buf)
{
    u8_t flags;

    if (buf->len != 1) {
        BT_DBG("%s, Unexpected flags length", __func__);
        return false;
    }

    flags = net_buf_simple_pull_u8(buf);

    BT_DBG("Received adv pkt with flags: 0x%02x", flags);

    /* Flags context will not be checked curently */

    return true;
}

u16_t provisioner_srv_uuid_recv(struct net_buf_simple *buf)
{
    u16_t uuid = 0;

    if (buf->len != 2) {
        BT_DBG("Length not match mesh service uuid");
        return false;
    }

    uuid = net_buf_simple_pull_le16(buf);

    BT_DBG("Received adv pkt with service UUID: %d", uuid);

    if ((uuid != BLE_MESH_UUID_MESH_PROV_VAL) && (uuid != BLE_MESH_UUID_MESH_PROXY_VAL)) {
        return false;
    }

    return uuid;
}

static void provisioner_prov_srv_data_recv(struct net_buf_simple *buf, const bt_mesh_addr_t *addr);

void provisioner_srv_data_recv(struct net_buf_simple *buf, const bt_mesh_addr_t *addr, u16_t uuid)
{
    u16_t uuid_type;

    if (!buf || !addr) {
        BT_ERR("%s, Invalid parameter", __func__);
        return;
    }

    uuid_type = net_buf_simple_pull_le16(buf);
    if (uuid_type != uuid) {
        BT_DBG("%s, Invalid Mesh Service Data UUID 0x%04x", __func__, uuid_type);
        return;
    }

    switch (uuid) {
    case BLE_MESH_UUID_MESH_PROV_VAL:
        if (buf->len != BLE_MESH_PROV_SRV_DATA_LEN) {
            BT_WARN("%s, Invalid Mesh Prov Service Data length %d", __func__, buf->len);
            return;
        }
        BT_DBG("Start to deal with Mesh Prov Service Data");
        provisioner_prov_srv_data_recv(buf, addr);
        break;
    case BLE_MESH_UUID_MESH_PROXY_VAL:
        if (buf->len != BLE_MESH_PROXY_SRV_DATA_LEN1 &&
                buf->len != BLE_MESH_PROXY_SRV_DATA_LEN2) {
            BT_ERR("%s, Invalid Mesh Proxy Service Data length %d", __func__, buf->len);
            return;
        }
        BT_DBG("Start to deal with Mesh Proxy Service Data");
        provisioner_proxy_srv_data_recv(buf);
        break;
    default:
        break;
    }
}

static void provisioner_prov_srv_data_recv(struct net_buf_simple *buf, const bt_mesh_addr_t *addr)
{
#if defined(CONFIG_BLE_MESH_PB_GATT)
    u8_t *uuid = NULL;
    u16_t oob_info;

    if (prov_ctx.pbg_count == CONFIG_BLE_MESH_PBG_SAME_TIME) {
        BT_DBG("Current PB-GATT devices reach max limit");
        return;
    }

    uuid = buf->data;
    net_buf_simple_pull(buf, 16);
    /* Mesh beacon uses big-endian to send beacon data */
    oob_info = net_buf_simple_pull_be16(buf);

    if (provisioner_check_device_uuid(uuid)) {
        return;
    }

    if (provisioner_notify_unprov_adv_pkt(
            BLE_MESH_PROV_GATT, uuid, addr, oob_info)) {
        return;
    }

    /* Provisioner will copy the device uuid, oob info, etc. into an unused link
     * struct, and at this moment the link has not been activated. Even if we
     * receive an Unprovisioned Device Beacon and a Connectable Provisioning adv
     * pkt from the same device, and store the device info received within each
     * adv pkt into two link structs which will has no impact on the provisioning
     * of this device, because no matter which link among PB-GATT and PB-ADV is
     * activated first, the other one will be dropped finally and the link struct
     * occupied by the dropped link will be used by other devices (because the link
     * is not activated).
     * Use connecting flag to prevent if two devices's adv pkts are both received,
     * the previous one info will be replaced by the second one.
     */
    provisioner_start_prov_device(BLE_MESH_PROV_GATT, uuid, addr, oob_info);
#endif /* CONFIG_BLE_MESH_PB_GATT */
}

#endif /* CONFIG_BLE_MESH_PROVISIONER */
