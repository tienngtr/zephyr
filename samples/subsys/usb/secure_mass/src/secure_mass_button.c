/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(CONFIG_APP_SECURE_MASS_USER_BUTTON_UNLOCK)

#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "secure_mass_priv.h"

LOG_MODULE_DECLARE(secure_mass, LOG_LEVEL_INF);

static const struct gpio_dt_spec unlock_button =
	GPIO_DT_SPEC_GET_OR(DT_ALIAS(sw0), gpios, {0});
static struct gpio_callback unlock_button_cb_data;

static void secure_mass_button_work_handler(struct k_work *work);
static void secure_mass_button_pressed(const struct device *port,
				       struct gpio_callback *cb,
				       gpio_port_pins_t pins);

static K_WORK_DEFINE(unlock_button_work, secure_mass_button_work_handler);

static void secure_mass_button_work_handler(struct k_work *work)
{
	int ret;

	ARG_UNUSED(work);

	ret = secure_mass_request_unlock();
	if (ret == 0) {
		LOG_INF("Unlock requested by user button");
	} else if (ret != -EBUSY && ret != -EALREADY) {
		LOG_WRN("Button unlock request failed (%d)", ret);
	}
}

static void secure_mass_button_pressed(const struct device *port,
				       struct gpio_callback *cb,
				       gpio_port_pins_t pins)
{
	ARG_UNUSED(port);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);

	k_work_submit(&unlock_button_work);
}

int secure_mass_button_init(void)
{
	int ret;

	if (!unlock_button.port) {
		return 0;
	}

	if (!gpio_is_ready_dt(&unlock_button)) {
		LOG_ERR("Button device %s is not ready", unlock_button.port->name);
		return -ENODEV;
	}

	ret = gpio_pin_configure_dt(&unlock_button, GPIO_INPUT);
	if (ret != 0) {
		LOG_ERR("Failed to configure unlock button (%d)", ret);
		return ret;
	}

	ret = gpio_pin_interrupt_configure_dt(&unlock_button,
					      GPIO_INT_EDGE_TO_ACTIVE);
	if (ret != 0) {
		LOG_ERR("Failed to enable unlock button interrupt (%d)", ret);
		return ret;
	}

	gpio_init_callback(&unlock_button_cb_data, secure_mass_button_pressed,
			   BIT(unlock_button.pin));
	ret = gpio_add_callback(unlock_button.port, &unlock_button_cb_data);
	if (ret != 0) {
		LOG_ERR("Failed to register unlock button callback (%d)", ret);
		return ret;
	}

	return 0;
}

#else

#include "secure_mass_priv.h"

int secure_mass_button_init(void)
{
	return 0;
}

#endif
