/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_SAMPLES_SUBSYS_USB_SECURE_MASS_PRIV_H_
#define ZEPHYR_SAMPLES_SUBSYS_USB_SECURE_MASS_PRIV_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <zephyr/usb/class/hid.h>
#include <zephyr/usb/usb_device.h>

#include <usb_descriptor.h>

#define SECURE_USB_MANUFACTURER		"Zephyr"
#define SECURE_USB_PRODUCT		"Secure USB Mass"
#define SECURE_USB_SN			"0011223344556677"

#define SECURE_PASSWORD_MAX_LEN		48
#define SECURE_HID_PKT_LEN		64
#define SECURE_HID_REPORT_DESC_SIZE	34

#define SECURE_HID_IN_EP_ADDR		0x81
#define SECURE_HID_OUT_EP_ADDR		0x01
#define SECURE_MSC_IN_EP_ADDR		0x82
#define SECURE_MSC_OUT_EP_ADDR		0x02

#define SECURE_HID_EP_MPS		64
#define SECURE_MSC_EP_MPS		64
#define SECURE_HID_INTERVAL_MS		10

#define SECURE_HID_NUM_ENDPOINTS	2
#define SECURE_MSC_NUM_ENDPOINTS	2

#define SECURE_MSC_BLOCK_SIZE		512
#define SECURE_MSC_THREAD_PRIO		-5
#define SECURE_MSC_STACK_SIZE		1536

#define SECURE_RAMDISK_NAME		"RAM"

#define SECURE_UNLOCK_DELAY_MS		300
#define SECURE_RELOCK_DELAY_MS		300
#define SECURE_DISCONNECT_DELAY_MS	10

#define HID_EP_BUSY_FLAG		0

#define MSC_CBW_SIGNATURE		0x43425355
#define MSC_CSW_SIGNATURE		0x53425355

#define MSC_CBW_DIRECTION_DATA_IN	0x80

#define MSC_CSW_STATUS_PASSED		0x00
#define MSC_CSW_STATUS_FAILED		0x01
#define MSC_CSW_STATUS_PHASE_ERROR	0x02

#define SCSI_TEST_UNIT_READY		0x00
#define SCSI_REQUEST_SENSE		0x03
#define SCSI_INQUIRY			0x12
#define SCSI_MODE_SENSE6		0x1A
#define SCSI_START_STOP_UNIT		0x1B
#define SCSI_MEDIA_REMOVAL		0x1E
#define SCSI_READ_FORMAT_CAPACITIES	0x23
#define SCSI_READ_CAPACITY		0x25
#define SCSI_READ10			0x28
#define SCSI_WRITE10			0x2A
#define SCSI_VERIFY10			0x2F
#define SCSI_READ12			0xA8
#define SCSI_WRITE12			0xAA

#define MSC_REQUEST_GET_MAX_LUN		0xFE
#define MSC_REQUEST_RESET		0xFF

#define SCSI_SENSE_NONE			0x00
#define SCSI_SENSE_NOT_READY		0x02
#define SCSI_SENSE_ILLEGAL_REQUEST	0x05

#define SCSI_ASC_MEDIA_NOT_PRESENT	0x3A
#define SCSI_ASC_INVALID_COMMAND	0x20

#define THREAD_OP_NONE			0
#define THREAD_OP_READ_QUEUED		1
#define THREAD_OP_WRITE_QUEUED		2
#define THREAD_OP_WRITE_DONE		3

enum secure_cmd {
	SECURE_CMD_GET_INFO = 0x01,
	SECURE_CMD_UNLOCK = 0x02,
	SECURE_CMD_CHANGE_PASSWORD = 0x03,
};

enum secure_status {
	SECURE_STATUS_OK = 0x00,
	SECURE_STATUS_BAD_PASSWORD = 0x01,
	SECURE_STATUS_INVALID_STATE = 0x02,
	SECURE_STATUS_BAD_LENGTH = 0x03,
	SECURE_STATUS_BUSY = 0x04,
	SECURE_STATUS_NOT_SUPPORTED = 0x05,
	SECURE_STATUS_INTERNAL_ERROR = 0x06,
	SECURE_STATUS_PASSWORD_POLICY = 0x07,
};

enum secure_state {
	SECURE_STATE_LOCKED = 0,
	SECURE_STATE_UNLOCKED = 1,
	SECURE_STATE_TRANSITION = 2,
};

enum secure_usb_mode {
	SECURE_USB_MODE_LOCKED = 0,
	SECURE_USB_MODE_UNLOCKED = 1,
};

enum secure_msc_stage {
	MSC_STAGE_READ_CBW,
	MSC_STAGE_ERROR,
	MSC_STAGE_PROCESS_CBW,
	MSC_STAGE_SEND_CSW,
	MSC_STAGE_WAIT_CSW,
};

struct hid_pkt_v1 {
	uint8_t version;
	uint8_t cmd;
	uint8_t seq;
	uint8_t status;
	uint8_t len;
	uint8_t data[59];
} __packed;

BUILD_ASSERT(sizeof(struct hid_pkt_v1) == SECURE_HID_PKT_LEN,
	     "secure HID packet must stay 64 bytes");

struct hid_rx_msg {
	uint8_t len;
	uint8_t data[SECURE_HID_PKT_LEN];
};

struct usb_hid_class_subdescriptor {
	uint8_t bDescriptorType;
	uint16_t wDescriptorLength;
} __packed;

struct secure_hid_descriptor {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint16_t bcdHID;
	uint8_t bCountryCode;
	uint8_t bNumDescriptors;
	struct usb_hid_class_subdescriptor subdesc[1];
} __packed;

struct secure_hid_interface_desc {
	struct usb_if_descriptor if0;
	struct secure_hid_descriptor if0_hid;
	struct usb_ep_descriptor if0_in_ep;
	struct usb_ep_descriptor if0_out_ep;
} __packed;

struct secure_msc_interface_desc {
	struct usb_if_descriptor if0;
	struct usb_ep_descriptor if0_in_ep;
	struct usb_ep_descriptor if0_out_ep;
} __packed;

#define DECLARE_ASCII_STRING_DESC(type_name, literal)				\
	struct type_name {							\
		uint8_t bLength;						\
		uint8_t bDescriptorType;					\
		uint8_t bString[USB_BSTRING_LENGTH(literal)];			\
	} __packed

DECLARE_ASCII_STRING_DESC(secure_mfr_str_desc, SECURE_USB_MANUFACTURER);
DECLARE_ASCII_STRING_DESC(secure_product_str_desc, SECURE_USB_PRODUCT);
DECLARE_ASCII_STRING_DESC(secure_sn_str_desc, SECURE_USB_SN);

struct secure_usb_strings {
	struct usb_string_descriptor lang_descr;
	struct secure_mfr_str_desc mfr;
	struct secure_product_str_desc product;
	struct secure_sn_str_desc sn;
} __packed;

struct secure_locked_descriptor_set {
	struct usb_device_descriptor dev;
	struct usb_cfg_descriptor cfg;
	struct secure_hid_interface_desc hid;
	struct secure_usb_strings strings;
	struct usb_desc_header term;
} __packed;

struct secure_unlocked_descriptor_set {
	struct usb_device_descriptor dev;
	struct usb_cfg_descriptor cfg;
	struct secure_hid_interface_desc hid;
	struct secure_msc_interface_desc msc;
	struct secure_usb_strings strings;
	struct usb_desc_header term;
} __packed;

struct msc_cbw {
	uint32_t signature;
	uint32_t tag;
	uint32_t data_length;
	uint8_t flags;
	uint8_t lun;
	uint8_t cb_length;
	uint8_t cb[16];
} __packed;

struct msc_csw {
	uint32_t signature;
	uint32_t tag;
	uint32_t data_residue;
	uint8_t status;
} __packed;

struct msc_inquiry_data {
	uint8_t head[8];
	uint8_t t10_vid[8];
	uint8_t product_id[16];
	uint8_t revision[4];
} __packed;

struct secure_mass_runtime {
	enum secure_state state;
	enum secure_usb_mode usb_mode;
	enum secure_usb_mode pending_usb_mode;
	bool descriptors_ready;
	bool usb_switch_in_progress;
	bool hid_configured;
	uint8_t hid_idle_rate;
	uint8_t hid_protocol;
	atomic_t hid_flags[1];
	char current_password[SECURE_PASSWORD_MAX_LEN + 1];
	size_t current_password_len;
	struct k_work_delayable usb_switch_work;
};

extern struct secure_mass_runtime secure_mass_runtime;

extern struct usb_ep_cfg_data secure_hid_ep_data[SECURE_HID_NUM_ENDPOINTS];
extern struct usb_ep_cfg_data secure_msc_ep_data[SECURE_MSC_NUM_ENDPOINTS];

static inline bool secure_mass_is_transition_state(void)
{
	return secure_mass_runtime.state == SECURE_STATE_TRANSITION;
}

int secure_hid_class_handle_req(struct usb_setup_packet *setup,
				int32_t *len, uint8_t **data);
int secure_hid_custom_handle_req(struct usb_setup_packet *setup,
				 int32_t *len, uint8_t **data);
void secure_hid_status_cb(struct usb_cfg_data *cfg,
			  enum usb_dc_status_code status,
			  const uint8_t *param);
void secure_hid_process_loop(void);

int secure_msc_class_handle_req(struct usb_setup_packet *setup,
				int32_t *len, uint8_t **data);
void secure_msc_status_cb(struct usb_cfg_data *cfg,
			  enum usb_dc_status_code status,
			  const uint8_t *param);
int secure_msc_init(void);
void secure_msc_set_active(bool active);

int secure_mass_usb_init_locked(void);
void secure_mass_schedule_mode_switch(enum secure_usb_mode mode,
				      k_timeout_t delay);
void secure_mass_request_relock(void);
const struct secure_hid_descriptor *secure_mass_get_active_hid_descriptor(void);

#endif /* ZEPHYR_SAMPLES_SUBSYS_USB_SECURE_MASS_PRIV_H_ */
