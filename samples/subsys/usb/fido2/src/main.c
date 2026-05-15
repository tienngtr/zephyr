/*
 * Copyright (c) 2026 Siratul Islam <email@sirat.me>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sample_usbd.h>

#include <zephyr/authentication/fido2/fido2.h>
#include <zephyr/fs/fs.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/usb/usbd.h>

#if defined(CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD)
#include <ff.h>

#define FIDO2_SD_MOUNT_POINT "/SD:"

static FATFS fido2_sd_fs;
static struct fs_mount_t fido2_sd_mount = {
	.type = FS_FATFS,
	.mnt_point = FIDO2_SD_MOUNT_POINT,
	.fs_data = &fido2_sd_fs,
};
#endif /* CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD */

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

static void msg_cb(struct usbd_context *const usbd_ctx, const struct usbd_msg *const msg)
{
	LOG_INF("USBD message: %s", usbd_msg_type_string(msg->type));

	if (msg->type == USBD_MSG_CONFIGURATION) {
		LOG_INF("Configuration value %d", msg->status);
	}

	if (usbd_can_detect_vbus(usbd_ctx)) {
		if (msg->type == USBD_MSG_VBUS_READY) {
			if (usbd_enable(usbd_ctx)) {
				LOG_ERR("Failed to enable USB device support");
			}
		}

		if (msg->type == USBD_MSG_VBUS_REMOVED) {
			if (usbd_disable(usbd_ctx)) {
				LOG_ERR("Failed to disable USB device support");
			}
		}
	}
}

#if defined(CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD)
static int fido2_mount_sd_card(void)
{
	int ret;

	ret = fs_mount(&fido2_sd_mount);
	if (ret) {
		LOG_ERR("Failed to mount FIDO2 SD card storage at %s: %d",
			FIDO2_SD_MOUNT_POINT, ret);
		return ret;
	}

	LOG_INF("FIDO2 SD card storage mounted at %s", FIDO2_SD_MOUNT_POINT);
	return 0;
}
#endif /* CONFIG_FIDO2_SAMPLE_STORAGE_SD_CARD */

int main(void)
{
	struct usbd_context *sample_usbd;
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

	sample_usbd = sample_usbd_init_device(msg_cb);
	if (sample_usbd == NULL) {
		LOG_ERR("Failed to initialize USB device");
		return -ENODEV;
	}

	if (!usbd_can_detect_vbus(sample_usbd)) {
		ret = usbd_enable(sample_usbd);
		if (ret) {
			LOG_ERR("Failed to enable USB device support: %d", ret);
			return ret;
		}
	}

	ret = fido2_start();
	if (ret) {
		LOG_ERR("Failed to start FIDO2 authenticator: %d", ret);
		return ret;
	}

	LOG_INF("FIDO2 USB HID sample is ready");

	while (true) {
		k_sleep(K_SECONDS(1));
	}

	return 0;
}
