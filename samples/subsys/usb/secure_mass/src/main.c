/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>

#include "secure_mass_priv.h"

LOG_MODULE_REGISTER(secure_mass, LOG_LEVEL_INF);

int main(void)
{
	int ret;

	ret = secure_msc_init();
	if (ret != 0) {
		return ret;
	}

	ret = secure_mass_button_init();
	if (ret != 0) {
		return ret;
	}

	ret = secure_mass_usb_init_locked();
	if (ret != 0) {
		return ret;
	}

	LOG_INF("secure_mass ready");

	secure_hid_process_loop();
	return 0;
}
