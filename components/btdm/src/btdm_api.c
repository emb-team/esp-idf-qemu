#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sdkconfig.h"
#include "esp_heap_caps.h"
#include "esp_heap_caps_init.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/xtensa_api.h"
#include "freertos/portmacro.h"
#include "xtensa/core-macros.h"
#include "esp_types.h"
#include "esp_system.h"
#include "esp_task.h"
#include "esp_intr.h"
#include "esp_attr.h"
#include "esp_phy_init.h"
#include "esp_bt.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_pm.h"
#include "esp_ipc.h"
#include "driver/periph_ctrl.h"
#include "soc/rtc.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc_memory_layout.h"
#include "esp_clk.h"
#include "esp_coexist_internal.h"
#include  "lwip/sockets.h"
#include "freertos/event_groups.h"


#define BTDM "BTDM"

/* Types definition
 ************************************************************************
 */

/* VHCI function interface */
typedef struct vhci_host_callback {
    void (*notify_host_send_available)(void);               /*!< callback used to notify that the host can send packet to controller */
    int (*notify_host_recv)(uint8_t *data, uint16_t len);   /*!< callback used to notify that the controller has a packet to send to the host*/
} vhci_host_callback_t;


/* External functions or values
 ************************************************************************
 */

/* not for user call, so don't put to include file */
/* OSI */
int btdm_osi_funcs_register(void *osi_funcs)
{
	return ESP_OK;
}
/* Initialise and De-initialise */
int btdm_controller_init(uint32_t config_mask, esp_bt_controller_config_t *config_opts)
{
	return ESP_OK;
}

void btdm_controller_deinit(void)
{
}

int btdm_controller_enable(esp_bt_mode_t mode)
{
	return ESP_OK;
}
void btdm_controller_disable(void)
{
}
uint8_t btdm_controller_get_mode(void)
{
	return ESP_BT_MODE_BLE;
}

const char *btdm_controller_get_compile_version(void)
{
	return "btdm-simulated-version-v0.1";
}
void btdm_rf_bb_init_phase2(void)
{
}
/* Sleep */
void btdm_controller_enable_sleep(bool enable)
{
}
void btdm_controller_set_sleep_mode(uint8_t mode)
{
}
uint8_t btdm_controller_get_sleep_mode(void)
{
	return 0; //none 
}
bool btdm_power_state_active(void)
{
	return true;
}
void btdm_wakeup_request(void)
{
}
/* Low Power Clock */
bool btdm_lpclk_select_src(uint32_t sel)
{
	return true;
}
bool btdm_lpclk_set_div(uint32_t div)
{
	return true;
}
/* VHCI */
bool API_vhci_host_check_send_available(void)
{
	return true;
}

//components/soc/esp32/include/soc/soc.h
//BT/BLE Controller
//#define ETS_BT_BB_INTR_SOURCE                   4/**< interrupt of BT BB, level*/

//#define DR_REG_BT_BASE 0x3ff51000
#define BT_HOST_RXTX_REG	DR_REG_BT_BASE
#define BT_HOST_RXTX_LEN	(DR_REG_BT_BASE + 0x200)
#define BT_HOST_RXTX_ENABLE	(BT_HOST_RXTX_LEN + 0x4)
#define BT_CNTR_CLR_RX_INTR	(DR_REG_BT_BASE + 0x400)

static portMUX_TYPE bt_host_spinlock = portMUX_INITIALIZER_UNLOCKED;

void API_vhci_host_send_packet(uint8_t *data, uint16_t len)
{
	portENTER_CRITICAL(&bt_host_spinlock);
	memcpy((uint8_t *) BT_HOST_RXTX_REG, data, len);
	*((uint16_t *) BT_HOST_RXTX_LEN) = len;
	portEXIT_CRITICAL(&bt_host_spinlock);
}

static EventGroupHandle_t g_bt_evt;
#define BT_HOST_RX_BIT       BIT0

vhci_host_callback_t *host_callback = NULL;

void ble_host_runner(void *arg)
{
	uint8_t buf[0x80];
	volatile uint16_t len = 0;

	TickType_t timeout = portMAX_DELAY;

	while ( 1 )
	{
		EventBits_t uxBits;
                uxBits = xEventGroupWaitBits(g_bt_evt, BT_HOST_RX_BIT, true, false, timeout);
		if (uxBits & BT_HOST_RX_BIT)
		{

			portENTER_CRITICAL(&bt_host_spinlock);
			len = *((uint16_t *) BT_HOST_RXTX_LEN);
			memcpy(buf, (uint8_t *) BT_HOST_RXTX_REG, len);
			*((uint32_t *) BT_HOST_RXTX_ENABLE) = 0x1; // enable TX again
			portEXIT_CRITICAL(&bt_host_spinlock);

			ESP_LOGD(BTDM, "BLE HOST RX request: Len: %d\n", len);
			host_callback->notify_host_recv(buf, len);
			memset(buf, 0x0, sizeof(buf));
		}
	}
}

intr_handle_t intr_handle;

static void bt_host_rx_intr_handler(void *param)
{
	portENTER_CRITICAL_ISR(&bt_host_spinlock);

	*((uint8_t *)BT_CNTR_CLR_RX_INTR) = 0x0; // clear RX Interrrupt
	xEventGroupSetBits(g_bt_evt, BT_HOST_RX_BIT);

	portEXIT_CRITICAL_ISR(&bt_host_spinlock);
}

int ble_host_init(void)
{
	int ret = -1;
	portENTER_CRITICAL(&bt_host_spinlock);

	g_bt_evt = xEventGroupCreate();

	ret = esp_intr_alloc(ETS_BT_BB_INTR_SOURCE, 0, bt_host_rx_intr_handler, NULL, &intr_handle);

	portEXIT_CRITICAL(&bt_host_spinlock);

	ESP_LOGI(BTDM, "BLE Host initialized.\n");
	return ret;
}

#define WIFI_TASK_STACK_DEPTH (4 * 1024)
#define WIFI_TASK_PRIORITY 5

int API_vhci_host_register_callback(vhci_host_callback_t *callback)
{
    int ret;
    host_callback = callback;

    if (ble_host_init() < 0) {
	ESP_LOGE(BTDM, "Failed to init BLE Host!\n");
    	return ESP_FAIL;
    }

    ret = xTaskCreate(ble_host_runner, "ble_host_runner", WIFI_TASK_STACK_DEPTH,
	    NULL, WIFI_TASK_PRIORITY, NULL);
    if (ret != pdPASS)  {
	ESP_LOGE(BTDM, "Failed to create thread ble_server_runner.");
	return ESP_FAIL;
    }

    return ESP_OK;
}

/* TX power */
int ble_txpwr_set(int power_type, int power_level)
{
	return ESP_OK;
}
int ble_txpwr_get(int power_type)
{
	return ESP_OK;
}
int bredr_txpwr_set(int min_power_level, int max_power_level)
{
	return ESP_OK;
}
int bredr_txpwr_get(int *min_power_level, int *max_power_level)
{
	return ESP_OK;
}
void bredr_sco_datapath_set(uint8_t data_path)
{
}
void btdm_controller_scan_duplicate_list_clear(void)
{
}

__asm__(".section .data\n"
	"_bss_start_btdm:\n"
	".space 128\n"
	"_bss_end_btdm:\n"
	"_data_start_btdm:\n"
	".space 128\n"
	"_data_end_btdm:\n"
	"_data_start_btdm_rom:\n"
	".space 128\n"
	"_data_end_btdm_rom:\n"
	"_bt_bss_start:\n"
	".space 128\n"
	"_bt_bss_end:\n"
	"_nimble_bss_start:\n"
	".space 128\n"	
	"_nimble_bss_end:\n"
	"_btdm_bss_start:\n"
	".space 128\n"
	"_btdm_bss_end:\n"
	"_bt_data_start:\n"
	".space 128\n"	
	"_bt_data_end:\n"
	"_nimble_data_start:\n"
	".space 128\n"	
	"_nimble_data_end:\n"
	"_btdm_data_start:\n"
	".space 128\n"
	"_btdm_data_end:\n");	
