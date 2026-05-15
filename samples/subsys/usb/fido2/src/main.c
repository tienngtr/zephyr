/*
 * Copyright (c) 2026 Siratul Islam <email@sirat.me>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/authentication/fido2/fido2.h>
#include <zephyr/fs/fs.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/usb_device.h>

#if defined(CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD)
#include <ff.h>

static FATFS fido2_sd_fs;
static struct fs_mount_t fido2_sd_mount = {
	.type = FS_FATFS,
	.mnt_point = CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD_MOUNT_POINT,
	.fs_data = &fido2_sd_fs,
};
#endif /* CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD */

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

static void status_cb(enum usb_dc_status_code status, const uint8_t *param)
{
	ARG_UNUSED(param);

	switch (status) {
	case USB_DC_RESET:
		LOG_INF("USB reset");
		break;
	case USB_DC_CONFIGURED:
		LOG_INF("USB configured");
		break;
	default:
		break;
	}
}

#if defined(CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD)
static int fido2_mount_sd_card(void)
{
	int ret;

	ret = fs_mount(&fido2_sd_mount);
	if (ret) {
		LOG_ERR("Failed to mount FIDO2 SD card storage at %s: %d",
			CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD_MOUNT_POINT, ret);
		return ret;
	}

	LOG_INF("FIDO2 SD card storage mounted at %s",
		CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD_MOUNT_POINT);
	return 0;
}
#endif /* CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD */

int main(void)
{
	int ret;

#if defined(CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD)
	ret = fido2_mount_sd_card();
	if (ret) {
		return ret;
	}
#endif /* CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD */

	ret = fido2_init();
	if (ret) {
		LOG_ERR("Failed to initialize FIDO2 subsystem: %d", ret);
		return ret;
	}

	ret = fido2_start();
	if (ret) {
		LOG_ERR("Failed to start FIDO2 authenticator: %d", ret);
		return ret;
	}

	ret = usb_enable(status_cb);
	if (ret) {
		LOG_ERR("Failed to enable USB device support: %d", ret);
		return ret;
	}

	LOG_INF("FIDO2 USB HID sample is ready");

	while (true) {
		k_sleep(K_SECONDS(1));
	}

	return 0;
}
