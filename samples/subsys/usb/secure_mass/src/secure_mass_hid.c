/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/logging/log.h>

#include "secure_mass_priv.h"

LOG_MODULE_DECLARE(secure_mass, LOG_LEVEL_INF);

static const uint8_t secure_hid_report_desc[] = {
	0x06, 0x00, 0xFF,
	0x09, 0x01,
	0xA1, 0x01,
	0x09, 0x02,
	0x15, 0x00,
	0x26, 0xFF, 0x00,
	0x75, 0x08,
	0x95, SECURE_HID_PKT_LEN,
	0x81, 0x02,
	0x09, 0x03,
	0x15, 0x00,
	0x26, 0xFF, 0x00,
	0x75, 0x08,
	0x95, SECURE_HID_PKT_LEN,
	0x91, 0x02,
	0xC0,
};

BUILD_ASSERT(sizeof(secure_hid_report_desc) == SECURE_HID_REPORT_DESC_SIZE,
	     "secure HID report descriptor size changed");

K_MSGQ_DEFINE(hid_rx_msgq, sizeof(struct hid_rx_msg), 8, 4);

static void queue_hid_packet(const uint8_t *buf, size_t len);
static int secure_hid_send_packet(const struct hid_pkt_v1 *pkt);
static void send_hid_response(uint8_t cmd, uint8_t seq, uint8_t status,
			      const uint8_t *payload, size_t len);
static uint8_t get_info_flags(void);
static void handle_get_info(const struct hid_pkt_v1 *req);
static void handle_unlock(const struct hid_pkt_v1 *req);
static void handle_change_password(const struct hid_pkt_v1 *req);
static void handle_hid_request(const struct hid_pkt_v1 *req);
static void secure_hid_int_in(uint8_t ep,
			      enum usb_dc_ep_cb_status_code ep_status);
static void secure_hid_int_out(uint8_t ep,
			       enum usb_dc_ep_cb_status_code ep_status);

struct usb_ep_cfg_data secure_hid_ep_data[SECURE_HID_NUM_ENDPOINTS] = {
	{
		.ep_cb = secure_hid_int_in,
		.ep_addr = SECURE_HID_IN_EP_ADDR,
	},
	{
		.ep_cb = secure_hid_int_out,
		.ep_addr = SECURE_HID_OUT_EP_ADDR,
	},
};

static void queue_hid_packet(const uint8_t *buf, size_t len)
{
	struct hid_rx_msg msg;

	if (len > SECURE_HID_PKT_LEN) {
		return;
	}

	memset(&msg, 0, sizeof(msg));
	msg.len = len;
	memcpy(msg.data, buf, len);

	if (k_msgq_put(&hid_rx_msgq, &msg, K_NO_WAIT) != 0) {
		LOG_WRN("Dropping HID packet: queue full");
	}
}

static int secure_hid_send_packet(const struct hid_pkt_v1 *pkt)
{
	int ret;

	if (!secure_mass_runtime.hid_configured) {
		return -EAGAIN;
	}

	if (atomic_test_and_set_bit(secure_mass_runtime.hid_flags, HID_EP_BUSY_FLAG)) {
		return -EBUSY;
	}

	ret = usb_write(SECURE_HID_IN_EP_ADDR, (const uint8_t *)pkt,
			sizeof(*pkt), NULL);
	if (ret != 0) {
		atomic_clear_bit(secure_mass_runtime.hid_flags, HID_EP_BUSY_FLAG);
	}

	return ret;
}

static void send_hid_response(uint8_t cmd, uint8_t seq, uint8_t status,
			      const uint8_t *payload, size_t len)
{
	struct hid_pkt_v1 rsp;
	int ret;

	memset(&rsp, 0, sizeof(rsp));
	rsp.version = 1;
	rsp.cmd = cmd | BIT(7);
	rsp.seq = seq;
	rsp.status = status;
	rsp.len = MIN(len, sizeof(rsp.data));
	if (payload != NULL && rsp.len > 0) {
		memcpy(rsp.data, payload, rsp.len);
	}

	ret = secure_hid_send_packet(&rsp);
	if (ret != 0) {
		LOG_WRN("Failed to send HID response (%d)", ret);
	}
}

static uint8_t get_info_flags(void)
{
	uint8_t flags = 0U;

	if (secure_mass_runtime.current_password_len > 0U) {
		flags |= BIT(0);
	}
	if (secure_mass_runtime.state == SECURE_STATE_UNLOCKED) {
		flags |= BIT(1);
		flags |= BIT(2);
	}

	return flags;
}

static void handle_get_info(const struct hid_pkt_v1 *req)
{
	uint8_t payload[5];

	payload[0] = secure_mass_runtime.state;
	payload[1] = SECURE_PASSWORD_MAX_LEN;
	payload[2] = get_info_flags();
	payload[3] = 0xFF;
	payload[4] = 0;

	send_hid_response(req->cmd, req->seq, SECURE_STATUS_OK,
			  payload, sizeof(payload));
}

static void handle_unlock(const struct hid_pkt_v1 *req)
{
	size_t password_len;

	if (secure_mass_is_transition_state()) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_BUSY, NULL, 0);
		return;
	}

	if (secure_mass_runtime.state != SECURE_STATE_LOCKED) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_INVALID_STATE,
				  NULL, 0);
		return;
	}

	if (req->len < 1U) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_BAD_LENGTH,
				  NULL, 0);
		return;
	}

	password_len = req->data[0];
	if (password_len > SECURE_PASSWORD_MAX_LEN ||
	    req->len != (password_len + 1U)) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_BAD_LENGTH,
				  NULL, 0);
		return;
	}

	if (password_len != secure_mass_runtime.current_password_len ||
	    memcmp(&req->data[1], secure_mass_runtime.current_password,
		   password_len) != 0) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_BAD_PASSWORD,
				  NULL, 0);
		return;
	}

	if (secure_mass_request_unlock() != 0) {
		send_hid_response(req->cmd, req->seq,
				  SECURE_STATUS_INTERNAL_ERROR, NULL, 0);
		return;
	}

	send_hid_response(req->cmd, req->seq, SECURE_STATUS_OK, NULL, 0);
}

static void handle_change_password(const struct hid_pkt_v1 *req)
{
	size_t new_len;

	if (secure_mass_is_transition_state()) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_BUSY, NULL, 0);
		return;
	}

	if (secure_mass_runtime.state != SECURE_STATE_UNLOCKED) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_INVALID_STATE,
				  NULL, 0);
		return;
	}

	if (req->len < 1U) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_BAD_LENGTH,
				  NULL, 0);
		return;
	}

	new_len = req->data[0];
	if (new_len > SECURE_PASSWORD_MAX_LEN ||
	    req->len != (new_len + 1U)) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_BAD_LENGTH,
				  NULL, 0);
		return;
	}

	memset(secure_mass_runtime.current_password, 0,
	       sizeof(secure_mass_runtime.current_password));
	memcpy(secure_mass_runtime.current_password, &req->data[1], new_len);
	secure_mass_runtime.current_password_len = new_len;

	send_hid_response(req->cmd, req->seq, SECURE_STATUS_OK, NULL, 0);
}

static void handle_hid_request(const struct hid_pkt_v1 *req)
{
	if (req->version != 1U || req->len > sizeof(req->data)) {
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_BAD_LENGTH,
				  NULL, 0);
		return;
	}

	switch (req->cmd) {
	case SECURE_CMD_GET_INFO:
		if (req->len != 0U) {
			send_hid_response(req->cmd, req->seq, SECURE_STATUS_BAD_LENGTH,
					  NULL, 0);
			return;
		}
		handle_get_info(req);
		break;
	case SECURE_CMD_UNLOCK:
		handle_unlock(req);
		break;
	case SECURE_CMD_CHANGE_PASSWORD:
		handle_change_password(req);
		break;
	default:
		send_hid_response(req->cmd, req->seq, SECURE_STATUS_NOT_SUPPORTED,
				  NULL, 0);
		break;
	}
}

static void secure_hid_int_in(uint8_t ep,
			      enum usb_dc_ep_cb_status_code ep_status)
{
	ARG_UNUSED(ep);

	if (ep_status == USB_DC_EP_DATA_IN) {
		atomic_clear_bit(secure_mass_runtime.hid_flags, HID_EP_BUSY_FLAG);
	}
}

static void secure_hid_int_out(uint8_t ep,
			       enum usb_dc_ep_cb_status_code ep_status)
{
	uint8_t buf[SECURE_HID_PKT_LEN];
	uint32_t bytes_read = 0U;

	if (ep_status != USB_DC_EP_DATA_OUT) {
		return;
	}

	if (usb_ep_read_wait(ep, buf, sizeof(buf), &bytes_read) == 0 &&
	    bytes_read > 0U) {
		queue_hid_packet(buf, bytes_read);
	}

	usb_ep_read_continue(ep);
}

void secure_hid_status_cb(struct usb_cfg_data *cfg,
			  enum usb_dc_status_code status,
			  const uint8_t *param)
{
	ARG_UNUSED(cfg);
	ARG_UNUSED(param);

	switch (status) {
	case USB_DC_RESET:
	case USB_DC_DISCONNECTED:
		secure_mass_runtime.hid_configured = false;
		atomic_clear_bit(secure_mass_runtime.hid_flags, HID_EP_BUSY_FLAG);
		break;
	case USB_DC_CONFIGURED:
		secure_mass_runtime.hid_configured = true;
		atomic_clear_bit(secure_mass_runtime.hid_flags, HID_EP_BUSY_FLAG);
		break;
	default:
		break;
	}
}

int secure_hid_class_handle_req(struct usb_setup_packet *setup,
				int32_t *len, uint8_t **data)
{
	static uint8_t zero_report[SECURE_HID_PKT_LEN];

	if ((setup->wIndex & 0xFF) != 0U) {
		return -ENOTSUP;
	}

	if (usb_reqtype_is_to_host(setup)) {
		switch (setup->bRequest) {
		case USB_HID_GET_IDLE:
			*data = &secure_mass_runtime.hid_idle_rate;
			*len = 1;
			return 0;
		case USB_HID_GET_PROTOCOL:
			*data = &secure_mass_runtime.hid_protocol;
			*len = 1;
			return 0;
		case USB_HID_GET_REPORT:
			*data = zero_report;
			*len = MIN(setup->wLength, sizeof(zero_report));
			return 0;
		default:
			return -ENOTSUP;
		}
	}

	switch (setup->bRequest) {
	case USB_HID_SET_IDLE:
		secure_mass_runtime.hid_idle_rate = (uint8_t)(setup->wValue >> 8);
		return 0;
	case USB_HID_SET_PROTOCOL:
		secure_mass_runtime.hid_protocol = (uint8_t)setup->wValue;
		return 0;
	case USB_HID_SET_REPORT:
		if (*len > SECURE_HID_PKT_LEN) {
			return -EINVAL;
		}
		queue_hid_packet(*data, *len);
		return 0;
	default:
		return -ENOTSUP;
	}
}

int secure_hid_custom_handle_req(struct usb_setup_packet *setup,
				 int32_t *len, uint8_t **data)
{
	uint8_t value;

	if (!usb_reqtype_is_to_host(setup) ||
	    setup->RequestType.recipient != USB_REQTYPE_RECIPIENT_INTERFACE ||
	    setup->bRequest != USB_SREQ_GET_DESCRIPTOR ||
	    (setup->wIndex & 0xFF) != 0U) {
		return -EINVAL;
	}

	value = (uint8_t)(setup->wValue >> 8);

	switch (value) {
	case USB_DESC_HID:
		*data = (uint8_t *)secure_mass_get_active_hid_descriptor();
		*len = MIN(setup->wLength,
			   ((struct secure_hid_descriptor *)*data)->bLength);
		return 0;
	case USB_DESC_HID_REPORT:
		*data = (uint8_t *)secure_hid_report_desc;
		*len = MIN(setup->wLength, sizeof(secure_hid_report_desc));
		return 0;
	default:
		return -ENOTSUP;
	}
}

void secure_hid_process_loop(void)
{
	while (true) {
		struct hid_rx_msg msg;

		k_msgq_get(&hid_rx_msgq, &msg, K_FOREVER);
		if (msg.len != sizeof(struct hid_pkt_v1)) {
			LOG_WRN("Ignoring HID packet of %u bytes", msg.len);
			continue;
		}

		handle_hid_request((const struct hid_pkt_v1 *)msg.data);
	}
}
