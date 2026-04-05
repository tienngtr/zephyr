/*
 * The Mass Storage protocol state machine in this file is based on mbed's
 * implementation. We augment it by adding Zephyr's USB transport and Storage
 * APIs.
 *
 * Copyright (c) 2010-2011 mbed.org, MIT License
 * Copyright (c) 2016 Intel Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file
 * @brief Mass Storage device class driver
 *
 * Driver for USB Mass Storage device class driver
 */

#include <zephyr/init.h>
#include <zephyr/sys/byteorder.h>

#include <zephyr/logging/log.h>

#include <usb_descriptor.h>

#include <zephyr/usb/class/msc_bot.h>

LOG_MODULE_REGISTER(usb_msc, CONFIG_USB_MASS_STORAGE_LOG_LEVEL);

#define SCSI_TRANSPARENT_SUBCLASS	0x06
#define BULK_ONLY_TRANSPORT_PROTOCOL	0x50

#define MAX_PACKET			CONFIG_MASS_STORAGE_BULK_EP_MPS
#define BLOCK_SIZE			512
#define DISK_THREAD_PRIO		-5

#define MASS_STORAGE_IN_EP_ADDR		0x82
#define MASS_STORAGE_OUT_EP_ADDR	0x01

BUILD_ASSERT(MAX_PACKET <= BLOCK_SIZE);

struct usb_mass_config {
	struct usb_if_descriptor if0;
	struct usb_ep_descriptor if0_in_ep;
	struct usb_ep_descriptor if0_out_ep;
} __packed;

USBD_CLASS_DESCR_DEFINE(primary, 0) struct usb_mass_config mass_cfg = {
	.if0 = {
		.bLength = sizeof(struct usb_if_descriptor),
		.bDescriptorType = USB_DESC_INTERFACE,
		.bInterfaceNumber = 0,
		.bAlternateSetting = 0,
		.bNumEndpoints = 2,
		.bInterfaceClass = USB_BCC_MASS_STORAGE,
		.bInterfaceSubClass = SCSI_TRANSPARENT_SUBCLASS,
		.bInterfaceProtocol = BULK_ONLY_TRANSPORT_PROTOCOL,
		.iInterface = 0,
	},
	.if0_in_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = MASS_STORAGE_IN_EP_ADDR,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize =
			sys_cpu_to_le16(CONFIG_MASS_STORAGE_BULK_EP_MPS),
		.bInterval = 0x00,
	},
	.if0_out_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = MASS_STORAGE_OUT_EP_ADDR,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize =
			sys_cpu_to_le16(CONFIG_MASS_STORAGE_BULK_EP_MPS),
		.bInterval = 0x00,
	},
};

#define INQ_VENDOR_ID_LEN	8
#define INQ_PRODUCT_ID_LEN	16
#define INQ_REVISION_LEN	4

static const struct msc_bot_inquiry_data inq_rsp = {
	.head = { 0x00, 0x80, 0x00, 0x01, 36 - 4, 0x80, 0x00, 0x00 },
	.t10_vid = CONFIG_MASS_STORAGE_INQ_VENDOR_ID,
	.product_id = CONFIG_MASS_STORAGE_INQ_PRODUCT_ID,
	.revision = CONFIG_MASS_STORAGE_INQ_REVISION,
};

BUILD_ASSERT(sizeof(CONFIG_MASS_STORAGE_INQ_VENDOR_ID) == (INQ_VENDOR_ID_LEN + 1),
	"CONFIG_MASS_STORAGE_INQ_VENDOR_ID must be 8 characters (pad with spaces)");
BUILD_ASSERT(sizeof(CONFIG_MASS_STORAGE_INQ_PRODUCT_ID) == (INQ_PRODUCT_ID_LEN + 1),
	"CONFIG_MASS_STORAGE_INQ_PRODUCT_ID must be 16 characters (pad with spaces)");
BUILD_ASSERT(sizeof(CONFIG_MASS_STORAGE_INQ_REVISION) == (INQ_REVISION_LEN + 1),
	"CONFIG_MASS_STORAGE_INQ_REVISION must be 4 characters (pad with spaces)");

static struct msc_bot_ctx mass_bot_ctx;
static uint8_t __aligned(4) mass_page[BLOCK_SIZE + MAX_PACKET];

K_KERNEL_STACK_DEFINE(mass_thread_stack, CONFIG_MASS_STORAGE_STACK_SIZE);

static const struct msc_bot_cfg mass_bot_cfg = {
	.disk_name = CONFIG_MASS_STORAGE_DISK_NAME,
	.in_ep_addr = MASS_STORAGE_IN_EP_ADDR,
	.out_ep_addr = MASS_STORAGE_OUT_EP_ADDR,
	.block_size = BLOCK_SIZE,
	.packet_size = MAX_PACKET,
	.inquiry = &inq_rsp,
	.medium_policy = MSC_BOT_MEDIUM_POLICY_ALWAYS_READY,
	.reset_on_disconnect = false,
	.default_sense_key = MSC_BOT_SCSI_SENSE_ILLEGAL_REQUEST,
	.default_sense_asc = 0x30,
	.default_sense_ascq = 0x01,
};

static void mass_storage_bulk_out(uint8_t ep,
				  enum usb_dc_ep_cb_status_code ep_status);
static void mass_storage_bulk_in(uint8_t ep,
				 enum usb_dc_ep_cb_status_code ep_status);

static struct usb_ep_cfg_data mass_ep_data[] = {
	{
		.ep_cb = mass_storage_bulk_out,
		.ep_addr = MASS_STORAGE_OUT_EP_ADDR,
	},
	{
		.ep_cb = mass_storage_bulk_in,
		.ep_addr = MASS_STORAGE_IN_EP_ADDR,
	},
};

static void mass_storage_bulk_out(uint8_t ep,
				  enum usb_dc_ep_cb_status_code ep_status)
{
	ARG_UNUSED(ep_status);

	msc_bot_bulk_out(&mass_bot_ctx, ep);
}

static void mass_storage_bulk_in(uint8_t ep,
				 enum usb_dc_ep_cb_status_code ep_status)
{
	ARG_UNUSED(ep);
	ARG_UNUSED(ep_status);

	msc_bot_bulk_in(&mass_bot_ctx);
}

static int mass_storage_class_handle_req(struct usb_setup_packet *setup,
					 int32_t *len, uint8_t **data)
{
	return msc_bot_class_handle_req(&mass_bot_ctx,
					mass_cfg.if0.bInterfaceNumber,
					setup, len, data);
}

static void mass_storage_status_cb(struct usb_cfg_data *cfg,
				   enum usb_dc_status_code status,
				   const uint8_t *param)
{
	ARG_UNUSED(cfg);
	ARG_UNUSED(param);

	msc_bot_usb_status(&mass_bot_ctx, status);
}

static void mass_interface_config(struct usb_desc_header *head,
				  uint8_t bInterfaceNumber)
{
	ARG_UNUSED(head);

	mass_cfg.if0.bInterfaceNumber = bInterfaceNumber;
}

USBD_DEFINE_CFG_DATA(mass_storage_config) = {
	.usb_device_description = NULL,
	.interface_config = mass_interface_config,
	.interface_descriptor = &mass_cfg.if0,
	.cb_usb_status = mass_storage_status_cb,
	.interface = {
		.class_handler = mass_storage_class_handle_req,
		.custom_handler = NULL,
	},
	.num_endpoints = ARRAY_SIZE(mass_ep_data),
	.endpoint = mass_ep_data,
};

static int mass_storage_init(void)
{
	int rc;

	rc = msc_bot_init(&mass_bot_ctx, &mass_bot_cfg, mass_page,
			  sizeof(mass_page));
	if (rc != 0) {
		LOG_ERR("Storage init failed (%d)", rc);
		return 0;
	}

	LOG_INF("Sect Count %u", mass_bot_ctx.block_count);
	LOG_INF("Memory Size %llu",
		(uint64_t)mass_bot_ctx.block_count * BLOCK_SIZE);

	rc = msc_bot_start_thread(&mass_bot_ctx, mass_thread_stack,
				  K_KERNEL_STACK_SIZEOF(mass_thread_stack),
				  DISK_THREAD_PRIO, "usb_mass");
	if (rc != 0) {
		LOG_ERR("MSC thread start failed (%d)", rc);
	}

	return 0;
}

SYS_INIT(mass_storage_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);
