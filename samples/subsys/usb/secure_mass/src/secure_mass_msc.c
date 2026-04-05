/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>

#include <zephyr/usb/class/msc_bot.h>
#include "secure_mass_priv.h"

LOG_MODULE_DECLARE(secure_mass, LOG_LEVEL_INF);

static const struct msc_bot_inquiry_data secure_msc_inquiry_rsp = {
	.head = { 0x00, 0x80, 0x00, 0x01, 36 - 4, 0x80, 0x00, 0x00 },
	.t10_vid = "Zephyr  ",
	.product_id = "Secure RAM Disk ",
	.revision = "1.00",
};

static struct msc_bot_ctx secure_msc_ctx;
static uint8_t __aligned(4)
	secure_msc_page[SECURE_MSC_BLOCK_SIZE + SECURE_MSC_EP_MPS];

K_KERNEL_STACK_DEFINE(secure_msc_thread_stack, SECURE_MSC_STACK_SIZE);

static void secure_msc_bulk_out(uint8_t ep,
				enum usb_dc_ep_cb_status_code ep_status);
static void secure_msc_bulk_in(uint8_t ep,
			       enum usb_dc_ep_cb_status_code ep_status);

static void secure_msc_on_eject(struct msc_bot_ctx *ctx, void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(user_data);

	secure_mass_request_relock();
}

static const struct msc_bot_ops secure_msc_ops = {
	.on_eject = secure_msc_on_eject,
};

static const struct msc_bot_cfg secure_msc_cfg = {
	.disk_name = SECURE_RAMDISK_NAME,
	.in_ep_addr = SECURE_MSC_IN_EP_ADDR,
	.out_ep_addr = SECURE_MSC_OUT_EP_ADDR,
	.block_size = SECURE_MSC_BLOCK_SIZE,
	.packet_size = SECURE_MSC_EP_MPS,
	.inquiry = &secure_msc_inquiry_rsp,
	.medium_policy = MSC_BOT_MEDIUM_POLICY_TRACKED,
	.reset_on_disconnect = true,
	.default_sense_key = MSC_BOT_SCSI_SENSE_NONE,
	.default_sense_asc = 0x00,
	.default_sense_ascq = 0x00,
	.ops = &secure_msc_ops,
};

struct usb_ep_cfg_data secure_msc_ep_data[SECURE_MSC_NUM_ENDPOINTS] = {
	{
		.ep_cb = secure_msc_bulk_out,
		.ep_addr = SECURE_MSC_OUT_EP_ADDR,
	},
	{
		.ep_cb = secure_msc_bulk_in,
		.ep_addr = SECURE_MSC_IN_EP_ADDR,
	},
};

static void secure_msc_bulk_out(uint8_t ep,
				enum usb_dc_ep_cb_status_code ep_status)
{
	ARG_UNUSED(ep_status);

	msc_bot_bulk_out(&secure_msc_ctx, ep);
}

static void secure_msc_bulk_in(uint8_t ep,
			       enum usb_dc_ep_cb_status_code ep_status)
{
	ARG_UNUSED(ep);
	ARG_UNUSED(ep_status);

	msc_bot_bulk_in(&secure_msc_ctx);
}

void secure_msc_status_cb(struct usb_cfg_data *cfg,
			  enum usb_dc_status_code status,
			  const uint8_t *param)
{
	ARG_UNUSED(cfg);
	ARG_UNUSED(param);

	msc_bot_usb_status(&secure_msc_ctx, status);
}

int secure_msc_class_handle_req(struct usb_setup_packet *setup,
				int32_t *len, uint8_t **data)
{
	return msc_bot_class_handle_req(&secure_msc_ctx,
					secure_mass_get_active_msc_interface_number(),
					setup, len, data);
}

int secure_msc_init(void)
{
	int rc;

	rc = msc_bot_init(&secure_msc_ctx, &secure_msc_cfg, secure_msc_page,
			  sizeof(secure_msc_page));
	if (rc != 0) {
		LOG_ERR("secure MSC init failed (%d)", rc);
		return rc;
	}

	rc = msc_bot_start_thread(&secure_msc_ctx, secure_msc_thread_stack,
				  K_KERNEL_STACK_SIZEOF(secure_msc_thread_stack),
				  SECURE_MSC_THREAD_PRIO, "secure_msc");
	if (rc != 0) {
		LOG_ERR("secure MSC thread start failed (%d)", rc);
		return rc;
	}

	secure_msc_set_active(false);
	return 0;
}

void secure_msc_set_active(bool active)
{
	msc_bot_set_medium_state(&secure_msc_ctx, active, active);
	msc_bot_reset_protocol(&secure_msc_ctx);
}
