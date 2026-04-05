/*
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2018,2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief USB HID Class device API header
 */

#ifndef ZEPHYR_INCLUDE_USB_HID_CLASS_DEVICE_H_
#define ZEPHYR_INCLUDE_USB_HID_CLASS_DEVICE_H_

#include <zephyr/usb/class/hid.h>
#include <zephyr/usb/usb_ch9.h>

#ifdef __cplusplus
extern "C" {
#endif

struct device;

/**
 * @brief usb_hid.h API
 * @defgroup usb_hid_class USB HID class API
 * @ingroup usb
 * @{
 */

/**
 * @defgroup usb_hid_device_api HID class USB specific definitions
 * @{
 */

struct usb_hid_class_subdescriptor {
	uint8_t bDescriptorType;
	uint16_t wDescriptorLength;
} __packed;

struct usb_hid_descriptor {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint16_t bcdHID;
	uint8_t bCountryCode;
	uint8_t bNumDescriptors;
	struct usb_hid_class_subdescriptor subdesc[1];
} __packed;

typedef int (*hid_cb_t)(const struct device *dev,
			struct usb_setup_packet *setup, int32_t *len,
			uint8_t **data);
typedef void (*hid_int_ready_callback)(const struct device *dev);
typedef void (*hid_protocol_cb_t)(const struct device *dev, uint8_t protocol);
typedef void (*hid_idle_cb_t)(const struct device *dev, uint16_t report_id);
typedef int (*usb_hid_req_handler_t)(void *context,
				     struct usb_setup_packet *setup,
				     int32_t *len, uint8_t **data);

struct usb_hid_req_handlers {
	usb_hid_req_handler_t get_idle;
	usb_hid_req_handler_t get_report;
	usb_hid_req_handler_t get_protocol;
	usb_hid_req_handler_t set_idle;
	usb_hid_req_handler_t set_report;
	usb_hid_req_handler_t set_protocol;
};

/**
 * @brief USB HID device interface
 */
struct hid_ops {
	hid_cb_t get_report;
	hid_cb_t set_report;
	hid_protocol_cb_t protocol_change;
	hid_idle_cb_t on_idle;
	/*
	 * int_in_ready is an optional callback that is called when
	 * the current interrupt IN transfer has completed.  This can
	 * be used to wait for the endpoint to go idle or to trigger
	 * the next transfer.
	 */
	hid_int_ready_callback int_in_ready;
	hid_int_ready_callback int_out_ready;
};

/**
 * @brief Register HID device
 *
 * @param[in]  dev          Pointer to USB HID device
 * @param[in]  desc         Pointer to HID report descriptor
 * @param[in]  size         Size of HID report descriptor
 * @param[in]  op           Pointer to USB HID device interrupt struct
 */
void usb_hid_register_device(const struct device *dev,
			     const uint8_t *desc,
			     size_t size,
			     const struct hid_ops *op);

/**
 * @brief Write to USB HID interrupt endpoint buffer
 *
 * @param[in]  dev          Pointer to USB HID device
 * @param[in]  data         Pointer to data buffer
 * @param[in]  data_len     Length of data to copy
 * @param[out] bytes_ret    Bytes written to the EP buffer.
 *
 * @return 0 on success, negative errno code on fail.
 */
int hid_int_ep_write(const struct device *dev,
		     const uint8_t *data,
		     uint32_t data_len,
		     uint32_t *bytes_ret);

/**
 * @brief Read from USB HID interrupt endpoint buffer
 *
 * @param[in]  dev          Pointer to USB HID device
 * @param[in]  data         Pointer to data buffer
 * @param[in]  max_data_len Max length of data to copy
 * @param[out] ret_bytes    Number of bytes to copy.  If data is NULL and
 *                          max_data_len is 0 the number of bytes
 *                          available in the buffer will be returned.
 *
 * @return 0 on success, negative errno code on fail.
 */
int hid_int_ep_read(const struct device *dev,
		    uint8_t *data,
		    uint32_t max_data_len,
		    uint32_t *ret_bytes);

/**
 * @brief Set USB HID class Protocol Code
 *
 * @details Should be called before usb_hid_init().
 *
 * @param[in]  dev          Pointer to USB HID device
 * @param[in]  proto_code   Protocol Code to be used for bInterfaceProtocol
 *
 * @return 0 on success, negative errno code on fail.
 */
int usb_hid_set_proto_code(const struct device *dev, uint8_t proto_code);

/**
 * @brief Initialize USB HID class support
 *
 * @param[in]  dev          Pointer to USB HID device
 *
 * @return 0 on success, negative errno code on fail.
 */
int usb_hid_init(const struct device *dev);

/**
 * @brief Set HID report descriptor length in a HID descriptor.
 *
 * @param[in,out] desc      Pointer to HID descriptor.
 * @param[in]     size      HID report descriptor size in bytes.
 */
void usb_hid_set_report_size(struct usb_hid_descriptor *desc, uint16_t size);

/**
 * @brief Dispatch a HID class request using caller-provided handlers.
 *
 * @param[in]     iface_num Expected interface number.
 * @param[in]     handlers  Request handlers for the supported operations.
 * @param[in]     context   Opaque context passed to handlers.
 * @param[in]     setup     Setup packet.
 * @param[in,out] len       Transfer length.
 * @param[in,out] data      Transfer data buffer pointer.
 *
 * @return 0 on success, negative errno code on failure.
 */
int usb_hid_handle_class_request(uint8_t iface_num,
				 const struct usb_hid_req_handlers *handlers,
				 void *context,
				 struct usb_setup_packet *setup,
				 int32_t *len, uint8_t **data);

/**
 * @brief Handle HID and HID report descriptor GET_DESCRIPTOR requests.
 *
 * @param[in]     iface_num    Expected interface number.
 * @param[in]     hid_desc     HID descriptor to return for USB_DESC_HID.
 * @param[in]     report_desc  HID report descriptor to return for
 *                             USB_DESC_HID_REPORT.
 * @param[in]     report_size  HID report descriptor size in bytes.
 * @param[in]     setup        Setup packet.
 * @param[in,out] len          Transfer length.
 * @param[in,out] data         Transfer data buffer pointer.
 *
 * @return 0 on success, negative errno code on failure.
 */
int usb_hid_handle_descriptor_request(uint8_t iface_num,
				      const struct usb_hid_descriptor *hid_desc,
				      const uint8_t *report_desc,
				      size_t report_size,
				      struct usb_setup_packet *setup,
				      int32_t *len, uint8_t **data);

/**
 * @}
 */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_USB_HID_CLASS_DEVICE_H_ */
