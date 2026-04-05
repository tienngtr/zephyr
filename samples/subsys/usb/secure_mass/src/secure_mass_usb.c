/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/linker/section_tags.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/reboot.h>

#include "secure_mass_priv.h"

LOG_MODULE_DECLARE(secure_mass, LOG_LEVEL_INF);

struct secure_boot_mode_state {
	uint32_t magic;
	uint8_t next_mode;
	uint8_t reserved[3];
};

static __noinit struct secure_boot_mode_state secure_boot_mode_state;

struct secure_mass_runtime secure_mass_runtime = {
	.state = SECURE_STATE_LOCKED,
	.usb_mode = SECURE_USB_MODE_LOCKED,
	.pending_usb_mode = SECURE_USB_MODE_LOCKED,
	.hid_protocol = HID_PROTOCOL_REPORT,
	.current_password = "12345678",
	.current_password_len = 8U,
};

static struct secure_locked_descriptor_set locked_desc = {
	.dev = {
		.bLength = sizeof(struct usb_device_descriptor),
		.bDescriptorType = USB_DESC_DEVICE,
		.bcdUSB = sys_cpu_to_le16(USB_SRN_2_0),
		.bDeviceClass = 0,
		.bDeviceSubClass = 0,
		.bDeviceProtocol = 0,
		.bMaxPacketSize0 = USB_MAX_CTRL_MPS,
		.idVendor = sys_cpu_to_le16(CONFIG_USB_DEVICE_VID),
		.idProduct = sys_cpu_to_le16(CONFIG_USB_DEVICE_PID),
		.bcdDevice = sys_cpu_to_le16(USB_BCD_DRN),
		.iManufacturer = 1,
		.iProduct = 2,
		.iSerialNumber = 3,
		.bNumConfigurations = 1,
	},
	.cfg = {
		.bLength = sizeof(struct usb_cfg_descriptor),
		.bDescriptorType = USB_DESC_CONFIGURATION,
		.wTotalLength = sys_cpu_to_le16(sizeof(struct usb_cfg_descriptor) +
						sizeof(struct secure_hid_interface_desc)),
		.bNumInterfaces = 1,
		.bConfigurationValue = 1,
		.iConfiguration = 0,
		.bmAttributes = USB_SCD_RESERVED,
		.bMaxPower = CONFIG_USB_MAX_POWER,
	},
	.hid = {
		.if0 = {
			.bLength = sizeof(struct usb_if_descriptor),
			.bDescriptorType = USB_DESC_INTERFACE,
			.bInterfaceNumber = 0,
			.bAlternateSetting = 0,
			.bNumEndpoints = 2,
			.bInterfaceClass = USB_BCC_HID,
			.bInterfaceSubClass = 0,
			.bInterfaceProtocol = 0,
			.iInterface = 0,
		},
		.if0_hid = {
			.bLength = sizeof(struct secure_hid_descriptor),
			.bDescriptorType = USB_DESC_HID,
			.bcdHID = sys_cpu_to_le16(USB_HID_VERSION),
			.bCountryCode = 0,
			.bNumDescriptors = 1,
			.subdesc = {
				{
					.bDescriptorType = USB_DESC_HID_REPORT,
					.wDescriptorLength = 0,
				},
			},
		},
		.if0_in_ep = {
			.bLength = sizeof(struct usb_ep_descriptor),
			.bDescriptorType = USB_DESC_ENDPOINT,
			.bEndpointAddress = SECURE_HID_IN_EP_ADDR,
			.bmAttributes = USB_DC_EP_INTERRUPT,
			.wMaxPacketSize = sys_cpu_to_le16(SECURE_HID_EP_MPS),
			.bInterval = SECURE_HID_INTERVAL_MS,
		},
		.if0_out_ep = {
			.bLength = sizeof(struct usb_ep_descriptor),
			.bDescriptorType = USB_DESC_ENDPOINT,
			.bEndpointAddress = SECURE_HID_OUT_EP_ADDR,
			.bmAttributes = USB_DC_EP_INTERRUPT,
			.wMaxPacketSize = sys_cpu_to_le16(SECURE_HID_EP_MPS),
			.bInterval = SECURE_HID_INTERVAL_MS,
		},
	},
	.strings = {
		.lang_descr = {
			.bLength = sizeof(struct usb_string_descriptor),
			.bDescriptorType = USB_DESC_STRING,
			.bString = sys_cpu_to_le16(0x0409),
		},
		.mfr = {
			.bLength = USB_STRING_DESCRIPTOR_LENGTH(SECURE_USB_MANUFACTURER),
			.bDescriptorType = USB_DESC_STRING,
			.bString = SECURE_USB_MANUFACTURER,
		},
		.product = {
			.bLength = USB_STRING_DESCRIPTOR_LENGTH(SECURE_USB_PRODUCT),
			.bDescriptorType = USB_DESC_STRING,
			.bString = SECURE_USB_PRODUCT,
		},
		.sn = {
			.bLength = USB_STRING_DESCRIPTOR_LENGTH(SECURE_USB_SN),
			.bDescriptorType = USB_DESC_STRING,
			.bString = SECURE_USB_SN,
		},
	},
	.term = {
		.bLength = 0,
		.bDescriptorType = 0,
	},
};

static struct secure_unlocked_descriptor_set unlocked_desc = {
	.dev = {
		.bLength = sizeof(struct usb_device_descriptor),
		.bDescriptorType = USB_DESC_DEVICE,
		.bcdUSB = sys_cpu_to_le16(USB_SRN_2_0),
		.bDeviceClass = 0,
		.bDeviceSubClass = 0,
		.bDeviceProtocol = 0,
		.bMaxPacketSize0 = USB_MAX_CTRL_MPS,
		.idVendor = sys_cpu_to_le16(CONFIG_USB_DEVICE_VID),
		.idProduct = sys_cpu_to_le16(CONFIG_USB_DEVICE_PID),
		.bcdDevice = sys_cpu_to_le16(USB_BCD_DRN),
		.iManufacturer = 1,
		.iProduct = 2,
		.iSerialNumber = 3,
		.bNumConfigurations = 1,
	},
	.cfg = {
		.bLength = sizeof(struct usb_cfg_descriptor),
		.bDescriptorType = USB_DESC_CONFIGURATION,
		.wTotalLength = sys_cpu_to_le16(sizeof(struct usb_cfg_descriptor) +
						sizeof(struct secure_hid_interface_desc) +
						sizeof(struct secure_msc_interface_desc)),
		.bNumInterfaces = 2,
		.bConfigurationValue = 1,
		.iConfiguration = 0,
		.bmAttributes = USB_SCD_RESERVED,
		.bMaxPower = CONFIG_USB_MAX_POWER,
	},
	.hid = {
		.if0 = {
			.bLength = sizeof(struct usb_if_descriptor),
			.bDescriptorType = USB_DESC_INTERFACE,
			.bInterfaceNumber = 0,
			.bAlternateSetting = 0,
			.bNumEndpoints = 2,
			.bInterfaceClass = USB_BCC_HID,
			.bInterfaceSubClass = 0,
			.bInterfaceProtocol = 0,
			.iInterface = 0,
		},
		.if0_hid = {
			.bLength = sizeof(struct secure_hid_descriptor),
			.bDescriptorType = USB_DESC_HID,
			.bcdHID = sys_cpu_to_le16(USB_HID_VERSION),
			.bCountryCode = 0,
			.bNumDescriptors = 1,
			.subdesc = {
				{
					.bDescriptorType = USB_DESC_HID_REPORT,
					.wDescriptorLength = 0,
				},
			},
		},
		.if0_in_ep = {
			.bLength = sizeof(struct usb_ep_descriptor),
			.bDescriptorType = USB_DESC_ENDPOINT,
			.bEndpointAddress = SECURE_HID_IN_EP_ADDR,
			.bmAttributes = USB_DC_EP_INTERRUPT,
			.wMaxPacketSize = sys_cpu_to_le16(SECURE_HID_EP_MPS),
			.bInterval = SECURE_HID_INTERVAL_MS,
		},
		.if0_out_ep = {
			.bLength = sizeof(struct usb_ep_descriptor),
			.bDescriptorType = USB_DESC_ENDPOINT,
			.bEndpointAddress = SECURE_HID_OUT_EP_ADDR,
			.bmAttributes = USB_DC_EP_INTERRUPT,
			.wMaxPacketSize = sys_cpu_to_le16(SECURE_HID_EP_MPS),
			.bInterval = SECURE_HID_INTERVAL_MS,
		},
	},
	.msc = {
		.if0 = {
			.bLength = sizeof(struct usb_if_descriptor),
			.bDescriptorType = USB_DESC_INTERFACE,
			.bInterfaceNumber = 1,
			.bAlternateSetting = 0,
			.bNumEndpoints = 2,
			.bInterfaceClass = USB_BCC_MASS_STORAGE,
			.bInterfaceSubClass = 0x06,
			.bInterfaceProtocol = 0x50,
			.iInterface = 0,
		},
		.if0_in_ep = {
			.bLength = sizeof(struct usb_ep_descriptor),
			.bDescriptorType = USB_DESC_ENDPOINT,
			.bEndpointAddress = SECURE_MSC_IN_EP_ADDR,
			.bmAttributes = USB_DC_EP_BULK,
			.wMaxPacketSize = sys_cpu_to_le16(SECURE_MSC_EP_MPS),
			.bInterval = 0,
		},
		.if0_out_ep = {
			.bLength = sizeof(struct usb_ep_descriptor),
			.bDescriptorType = USB_DESC_ENDPOINT,
			.bEndpointAddress = SECURE_MSC_OUT_EP_ADDR,
			.bmAttributes = USB_DC_EP_BULK,
			.wMaxPacketSize = sys_cpu_to_le16(SECURE_MSC_EP_MPS),
			.bInterval = 0,
		},
	},
	.strings = {
		.lang_descr = {
			.bLength = sizeof(struct usb_string_descriptor),
			.bDescriptorType = USB_DESC_STRING,
			.bString = sys_cpu_to_le16(0x0409),
		},
		.mfr = {
			.bLength = USB_STRING_DESCRIPTOR_LENGTH(SECURE_USB_MANUFACTURER),
			.bDescriptorType = USB_DESC_STRING,
			.bString = SECURE_USB_MANUFACTURER,
		},
		.product = {
			.bLength = USB_STRING_DESCRIPTOR_LENGTH(SECURE_USB_PRODUCT),
			.bDescriptorType = USB_DESC_STRING,
			.bString = SECURE_USB_PRODUCT,
		},
		.sn = {
			.bLength = USB_STRING_DESCRIPTOR_LENGTH(SECURE_USB_SN),
			.bDescriptorType = USB_DESC_STRING,
			.bString = SECURE_USB_SN,
		},
	},
	.term = {
		.bLength = 0,
		.bDescriptorType = 0,
	},
};

USBD_DEFINE_CFG_DATA(secure_hid_config) = {
	.usb_device_description = NULL,
	.interface_config = NULL,
	.interface_descriptor = NULL,
	.cb_usb_status = secure_hid_status_cb,
	.interface = {
		.class_handler = secure_hid_class_handle_req,
		.custom_handler = secure_hid_custom_handle_req,
	},
	.num_endpoints = SECURE_HID_NUM_ENDPOINTS,
	.endpoint = secure_hid_ep_data,
};

USBD_DEFINE_CFG_DATA(secure_msc_config) = {
	.usb_device_description = NULL,
	.interface_config = NULL,
	.interface_descriptor = NULL,
	.cb_usb_status = secure_msc_status_cb,
	.interface = {
		.class_handler = secure_msc_class_handle_req,
		.custom_handler = NULL,
	},
	.num_endpoints = SECURE_MSC_NUM_ENDPOINTS,
	.endpoint = secure_msc_ep_data,
};

static void ascii7_to_utf16le(void *descriptor)
{
	struct usb_string_descriptor *str = descriptor;
	int idx_max = str->bLength - 3;
	int ascii_idx_max = str->bLength / 2 - 2;
	uint8_t *buf = (uint8_t *)&str->bString;

	for (int i = idx_max; i >= 0; i -= 2) {
		buf[i] = 0U;
		buf[i - 1] = buf[ascii_idx_max--];
	}
}

static void prepare_string_descriptors(struct secure_usb_strings *strings)
{
	ascii7_to_utf16le(&strings->mfr);
	ascii7_to_utf16le(&strings->product);
	ascii7_to_utf16le(&strings->sn);
}

static void prepare_descriptors_once(void)
{
	if (secure_mass_runtime.descriptors_ready) {
		return;
	}

	prepare_string_descriptors(&locked_desc.strings);
	prepare_string_descriptors(&unlocked_desc.strings);
	locked_desc.hid.if0_hid.subdesc[0].wDescriptorLength =
		sys_cpu_to_le16(SECURE_HID_REPORT_DESC_SIZE);
	unlocked_desc.hid.if0_hid.subdesc[0].wDescriptorLength =
		sys_cpu_to_le16(SECURE_HID_REPORT_DESC_SIZE);
	secure_mass_runtime.descriptors_ready = true;
}

static enum secure_usb_mode secure_mass_load_boot_mode(void)
{
	enum secure_usb_mode mode = SECURE_USB_MODE_LOCKED;

	if (secure_boot_mode_state.magic == SECURE_BOOT_MODE_MAGIC &&
	    secure_boot_mode_state.next_mode <= SECURE_USB_MODE_UNLOCKED) {
		mode = (enum secure_usb_mode)secure_boot_mode_state.next_mode;
	}

	secure_boot_mode_state.magic = 0U;
	secure_boot_mode_state.next_mode = SECURE_USB_MODE_LOCKED;

	return mode;
}

static void secure_mass_store_boot_mode(enum secure_usb_mode mode)
{
	secure_boot_mode_state.magic = SECURE_BOOT_MODE_MAGIC;
	secure_boot_mode_state.next_mode = (uint8_t)mode;
}

static const uint8_t *get_active_descriptor(enum secure_usb_mode mode)
{
	if (mode == SECURE_USB_MODE_LOCKED) {
		return (const uint8_t *)&locked_desc;
	}

	return (const uint8_t *)&unlocked_desc;
}

static void configure_cfg_data_for_mode(enum secure_usb_mode mode)
{
	if (mode == SECURE_USB_MODE_LOCKED) {
		secure_hid_config.interface_descriptor = &locked_desc.hid.if0;
		secure_msc_config.interface_descriptor = NULL;
		secure_msc_set_active(false);
	} else {
		secure_hid_config.interface_descriptor = &unlocked_desc.hid.if0;
		secure_msc_config.interface_descriptor = &unlocked_desc.msc.if0;
		secure_msc_set_active(true);
	}
}

const struct secure_hid_descriptor *secure_mass_get_active_hid_descriptor(void)
{
	if (secure_mass_runtime.usb_mode == SECURE_USB_MODE_LOCKED) {
		return &locked_desc.hid.if0_hid;
	}

	return &unlocked_desc.hid.if0_hid;
}

static void secure_usb_status_cb(enum usb_dc_status_code status,
				 const uint8_t *param)
{
	ARG_UNUSED(param);

	if (secure_mass_runtime.usb_switch_in_progress) {
		return;
	}

	if (secure_mass_runtime.usb_mode != SECURE_USB_MODE_UNLOCKED) {
		return;
	}

	switch (status) {
	case USB_DC_CONFIGURED:
		secure_mass_runtime.unlocked_configured_once = true;
		break;
	case USB_DC_DISCONNECTED:
		if (secure_mass_runtime.unlocked_configured_once) {
			secure_mass_runtime.unlocked_configured_once = false;
			secure_mass_schedule_mode_switch(SECURE_USB_MODE_LOCKED,
							 K_MSEC(SECURE_DISCONNECT_DELAY_MS));
		}
		break;
	default:
		break;
	}
}

static int apply_usb_mode(enum secure_usb_mode mode)
{
	int ret;

	configure_cfg_data_for_mode(mode);

	ret = usb_set_config(get_active_descriptor(mode));
	if (ret != 0) {
		LOG_ERR("usb_set_config failed (%d)", ret);
		return ret;
	}

	ret = usb_enable(secure_usb_status_cb);
	if (ret != 0) {
		LOG_ERR("usb_enable failed (%d)", ret);
		return ret;
	}

	secure_mass_runtime.usb_mode = mode;
	secure_mass_runtime.pending_usb_mode = mode;
	secure_mass_runtime.unlocked_configured_once = false;
	secure_mass_runtime.state = (mode == SECURE_USB_MODE_LOCKED) ?
		SECURE_STATE_LOCKED : SECURE_STATE_UNLOCKED;
	secure_mass_runtime.usb_switch_in_progress = false;
	secure_mass_indicator_update(secure_mass_runtime.state);

	LOG_INF("USB mode is now %s",
		mode == SECURE_USB_MODE_LOCKED ? "locked (HID)" :
		"unlocked (HID + MSC)");

	return 0;
}

static void usb_switch_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	secure_mass_runtime.usb_switch_in_progress = true;
	secure_mass_store_boot_mode(secure_mass_runtime.pending_usb_mode);

	LOG_INF("Rebooting into %s mode",
		secure_mass_runtime.pending_usb_mode == SECURE_USB_MODE_LOCKED ?
		"locked" : "unlocked");

	sys_reboot(SYS_REBOOT_WARM);
}

void secure_mass_schedule_mode_switch(enum secure_usb_mode mode,
				      k_timeout_t delay)
{
	secure_mass_runtime.pending_usb_mode = mode;
	secure_mass_runtime.state = SECURE_STATE_TRANSITION;
	k_work_reschedule(&secure_mass_runtime.usb_switch_work, delay);
}

void secure_mass_request_relock(void)
{
	if (secure_mass_runtime.state == SECURE_STATE_UNLOCKED &&
	    !secure_mass_runtime.usb_switch_in_progress) {
		secure_mass_schedule_mode_switch(SECURE_USB_MODE_LOCKED,
						 K_MSEC(SECURE_RELOCK_DELAY_MS));
	}
}

int secure_mass_request_unlock(void)
{
	if (secure_mass_runtime.usb_switch_in_progress ||
	    secure_mass_is_transition_state()) {
		return -EBUSY;
	}

	if (secure_mass_runtime.state != SECURE_STATE_LOCKED) {
		return -EALREADY;
	}

	secure_mass_schedule_mode_switch(SECURE_USB_MODE_UNLOCKED,
					 K_MSEC(SECURE_UNLOCK_DELAY_MS));
	return 0;
}

int secure_mass_usb_init(void)
{
	int ret;
	enum secure_usb_mode boot_mode;

	k_work_init_delayable(&secure_mass_runtime.usb_switch_work,
			      usb_switch_work_handler);
	prepare_descriptors_once();
	boot_mode = secure_mass_load_boot_mode();

	ret = apply_usb_mode(boot_mode);
	if (ret != 0) {
		LOG_ERR("Initial USB enable failed (%d)", ret);
		return ret;
	}

	return 0;
}
