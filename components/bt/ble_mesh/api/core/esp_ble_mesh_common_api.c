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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "btc/btc_task.h"
#include "btc/btc_manage.h"
#include "osi/allocator.h"

#include "esp_bt_defs.h"
#include "esp_err.h"
#include "esp_bt_main.h"
#include "sdkconfig.h"

#include "btc_ble_mesh_prov.h"

#include "mesh.h"
#include "mesh_buf.h"
#include "transport.h"
#include "esp_ble_mesh_common_api.h"

#if CONFIG_BT_MESH

esp_err_t esp_ble_mesh_init(esp_ble_mesh_prov_t *prov, esp_ble_mesh_comp_t *comp)
{
    btc_msg_t msg;
    btc_ble_mesh_prov_args_t arg = {0};
    xSemaphoreHandle semaphore = NULL;

    ESP_BLUEDROID_STATUS_CHECK(ESP_BLUEDROID_STATUS_ENABLED);

    // Create a semaphore
    if ((semaphore = xSemaphoreCreateCounting(1, 0)) == NULL) {
        LOG_ERROR("%s, unable to allocate memory for the semaphore.", __func__);
        return ESP_ERR_NO_MEM;
    }

    msg.sig = BTC_SIG_API_CALL;
    msg.pid = BTC_PID_PROV;
    msg.act = BTC_BLE_MESH_ACT_APP_REGISTER;
    arg.mesh_reg.prov = prov;
    arg.mesh_reg.comp = comp;
    // semaphore pointer transport to BTC layer, we will give the semaphore in the BTC task.
    arg.mesh_reg.semaphore = semaphore;

    if (btc_transfer_context(&msg, &arg, sizeof(btc_ble_mesh_prov_args_t), NULL) != BT_STATUS_SUCCESS) {
        vSemaphoreDelete(semaphore);
        LOG_ERROR("BLE Mesh initialise failed");
        return ESP_FAIL;
    }

    // Take the Semaphore, wait to BLE Mesh init finish.
    xSemaphoreTake(semaphore, portMAX_DELAY);
    // Don't forget to delete the semaphore at the end.
    vSemaphoreDelete(semaphore);
    return ESP_OK;
}

#endif /* #if CONFIG_BT_MESH */

