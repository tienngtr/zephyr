/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>

#include "secure_mass_priv.h"

LOG_MODULE_DECLARE(secure_mass, LOG_LEVEL_INF);

static const struct gpio_dt_spec unlock_led =
	GPIO_DT_SPEC_GET_OR(DT_ALIAS(led0), gpios, {0});
static const struct gpio_dt_spec lock_led =
	GPIO_DT_SPEC_GET_OR(DT_ALIAS(led2), gpios, {0});

static int configure_indicator_led(const struct gpio_dt_spec *led)
{
	if (!led->port) {
		return 0;
	}

	if (!gpio_is_ready_dt(led)) {
		LOG_ERR("LED device %s is not ready", led->port->name);
		return -ENODEV;
	}

	return gpio_pin_configure_dt(led, GPIO_OUTPUT_INACTIVE);
}

static void set_indicator_led(const struct gpio_dt_spec *led, int value)
{
	if (!led->port) {
		return;
	}

	(void)gpio_pin_set_dt(led, value);
}

int secure_mass_indicator_init(void)
{
	int ret;

	ret = configure_indicator_led(&unlock_led);
	if (ret != 0) {
		return ret;
	}

	ret = configure_indicator_led(&lock_led);
	if (ret != 0) {
		return ret;
	}

	secure_mass_indicator_update(SECURE_STATE_LOCKED);
	return 0;
}

void secure_mass_indicator_update(enum secure_state state)
{
	switch (state) {
	case SECURE_STATE_UNLOCKED:
		set_indicator_led(&lock_led, 0);
		set_indicator_led(&unlock_led, 1);
		break;
	case SECURE_STATE_LOCKED:
		set_indicator_led(&unlock_led, 0);
		set_indicator_led(&lock_led, 1);
		break;
	default:
		break;
	}
}
