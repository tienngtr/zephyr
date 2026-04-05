/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <zephyr/usb/class/hid.h>
#include <zephyr/usb/class/usb_hid.h>
#include <zephyr/usb/usb_device.h>

void usb_hid_set_report_size(struct usb_hid_descriptor *desc, uint16_t size)
{
	sys_put_le16(size, (uint8_t *)&desc->subdesc[0].wDescriptorLength);
}

static int call_req_handler(usb_hid_req_handler_t handler, void *context,
			    struct usb_setup_packet *setup,
			    int32_t *len, uint8_t **data)
{
	if (handler == NULL) {
		return -ENOTSUP;
	}

	return handler(context, setup, len, data);
}

int usb_hid_handle_class_request(uint8_t iface_num,
				 const struct usb_hid_req_handlers *handlers,
				 void *context,
				 struct usb_setup_packet *setup,
				 int32_t *len, uint8_t **data)
{
	if ((setup->wIndex & 0xFF) != iface_num || handlers == NULL) {
		return -ENOTSUP;
	}

	if (usb_reqtype_is_to_host(setup)) {
		switch (setup->bRequest) {
		case USB_HID_GET_IDLE:
			return call_req_handler(handlers->get_idle, context,
						 setup, len, data);
		case USB_HID_GET_REPORT:
			return call_req_handler(handlers->get_report, context,
						 setup, len, data);
		case USB_HID_GET_PROTOCOL:
			return call_req_handler(handlers->get_protocol, context,
						 setup, len, data);
		default:
			return -ENOTSUP;
		}
	}

	switch (setup->bRequest) {
	case USB_HID_SET_IDLE:
		return call_req_handler(handlers->set_idle, context,
					 setup, len, data);
	case USB_HID_SET_REPORT:
		return call_req_handler(handlers->set_report, context,
					 setup, len, data);
	case USB_HID_SET_PROTOCOL:
		return call_req_handler(handlers->set_protocol, context,
					 setup, len, data);
	default:
		return -ENOTSUP;
	}
}

int usb_hid_handle_descriptor_request(uint8_t iface_num,
				      const struct usb_hid_descriptor *hid_desc,
				      const uint8_t *report_desc,
				      size_t report_size,
				      struct usb_setup_packet *setup,
				      int32_t *len, uint8_t **data)
{
	uint8_t value;

	if (!usb_reqtype_is_to_host(setup) ||
	    setup->RequestType.recipient != USB_REQTYPE_RECIPIENT_INTERFACE ||
	    setup->bRequest != USB_SREQ_GET_DESCRIPTOR ||
	    (setup->wIndex & 0xFF) != iface_num) {
		return -EINVAL;
	}

	value = (uint8_t)(setup->wValue >> 8);

	switch (value) {
	case USB_DESC_HID:
		if (hid_desc == NULL) {
			return -ENOTSUP;
		}

		*len = MIN(setup->wLength, hid_desc->bLength);
		*data = (uint8_t *)hid_desc;
		return 0;
	case USB_DESC_HID_REPORT:
		if (report_desc == NULL) {
			return -ENOTSUP;
		}

		*len = MIN(setup->wLength, report_size);
		*data = (uint8_t *)report_desc;
		return 0;
	default:
		return -ENOTSUP;
	}
}
