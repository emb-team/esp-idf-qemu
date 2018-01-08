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

#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "driver/gpio.h"

#include "board.h"
#include "esp_fast_prov_server_model.h"

#define TAG "BOARD"

extern example_fast_prov_server_t fast_prov_server;

struct _led_state led_state[3] = {
    { LED_OFF, LED_OFF, LED_R, "red"   },
    { LED_OFF, LED_OFF, LED_G, "green" },
    { LED_OFF, LED_OFF, LED_B, "blue"  },
};

static xQueueHandle led_action_queue;

void board_output_number(esp_ble_mesh_output_action_t action, uint32_t number)
{
    ESP_LOGI(TAG, "Board output number %d", number);
}

void board_prov_complete(void)
{
    board_led_operation(LED_B, LED_OFF);
}

void board_led_operation(uint8_t pin, uint8_t onoff)
{
    for (int i = 0; i < 3; i++) {
        if (led_state[i].pin != pin) {
            continue;
        }
        if (onoff == led_state[i].previous) {
            ESP_LOGW(TAG, "led %s is already %s",
                     led_state[i].name, (onoff ? "on" : "off"));
            return;
        }
        gpio_set_level(pin, onoff);
        led_state[i].previous = onoff;
        return;
    }

    ESP_LOGE(TAG, "LED is not found!");
}

static void board_led_init(void)
{
    for (int i = 0; i < 3; i++) {
        gpio_pad_select_gpio(led_state[i].pin);
        gpio_set_direction(led_state[i].pin, GPIO_MODE_OUTPUT);
        gpio_set_level(led_state[i].pin, LED_OFF);
        led_state[i].previous = LED_OFF;
    }
}

static void led_action_thread(void *arg)
{
    struct _led_state led = {0};

    while (1) {
        if (xQueueReceive(led_action_queue, &led, (portTickType)portMAX_DELAY)) {
            ESP_LOGI(TAG, "%s: pin 0x%04x onoff 0x%02x", __func__, led.pin, led.current);
            /* If the node is controlled by phone, add a delay when turn on/off led */
            if (fast_prov_server.primary_role == true) {
                vTaskDelay(50 / portTICK_PERIOD_MS);
            }
            gpio_set_level(led.pin, led.current);
        }
    }
}

esp_err_t led_action_task_post(struct _led_state *msg, uint32_t timeout)
{
    if (xQueueSend(led_action_queue, msg, timeout) != pdTRUE) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t board_init(void)
{
    BaseType_t ret;

    board_led_init();

    led_action_queue = xQueueCreate(60, sizeof(struct _led_state));
    if (!led_action_queue) {
        ESP_LOGE(TAG, "%s: Failed to create led action queue", __func__);
        return ESP_FAIL;
    }

    ret = xTaskCreate(led_action_thread, "led_action_thread", 4096, NULL, 5, NULL);
    if (ret == pdFAIL) {
        ESP_LOGE(TAG, "%s: Failed to create led_action_thread", __func__);
        vQueueDelete(led_action_queue);
        return ESP_FAIL;
    }

    return ESP_OK;
}
