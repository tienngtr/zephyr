/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_USB_CLASS_MSC_BOT_H_
#define ZEPHYR_INCLUDE_USB_CLASS_MSC_BOT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/usb/usb_device.h>

#define MSC_BOT_REQUEST_GET_MAX_LUN		0xFE
#define MSC_BOT_REQUEST_RESET			0xFF

#define MSC_BOT_CBW_SIGNATURE			0x43425355
#define MSC_BOT_CSW_SIGNATURE			0x53425355

#define MSC_BOT_CBW_DIRECTION_DATA_IN		0x80

#define MSC_BOT_CSW_STATUS_PASSED		0x00
#define MSC_BOT_CSW_STATUS_FAILED		0x01
#define MSC_BOT_CSW_STATUS_PHASE_ERROR		0x02

#define MSC_BOT_SCSI_TEST_UNIT_READY		0x00
#define MSC_BOT_SCSI_REQUEST_SENSE		0x03
#define MSC_BOT_SCSI_INQUIRY			0x12
#define MSC_BOT_SCSI_MODE_SENSE6		0x1A
#define MSC_BOT_SCSI_START_STOP_UNIT		0x1B
#define MSC_BOT_SCSI_MEDIA_REMOVAL		0x1E
#define MSC_BOT_SCSI_READ_FORMAT_CAPACITIES	0x23
#define MSC_BOT_SCSI_READ_CAPACITY		0x25
#define MSC_BOT_SCSI_READ10			0x28
#define MSC_BOT_SCSI_WRITE10			0x2A
#define MSC_BOT_SCSI_VERIFY10			0x2F
#define MSC_BOT_SCSI_READ12			0xA8
#define MSC_BOT_SCSI_WRITE12			0xAA

#define MSC_BOT_SCSI_SENSE_NONE			0x00
#define MSC_BOT_SCSI_SENSE_NOT_READY		0x02
#define MSC_BOT_SCSI_SENSE_ILLEGAL_REQUEST	0x05

#define MSC_BOT_SCSI_ASC_MEDIA_NOT_PRESENT	0x3A
#define MSC_BOT_SCSI_ASC_INVALID_COMMAND	0x20

enum msc_bot_stage {
	MSC_BOT_STAGE_READ_CBW,
	MSC_BOT_STAGE_ERROR,
	MSC_BOT_STAGE_PROCESS_CBW,
	MSC_BOT_STAGE_SEND_CSW,
	MSC_BOT_STAGE_WAIT_CSW,
};

enum msc_bot_thread_op {
	MSC_BOT_THREAD_OP_NONE,
	MSC_BOT_THREAD_OP_READ_QUEUED,
	MSC_BOT_THREAD_OP_WRITE_QUEUED,
	MSC_BOT_THREAD_OP_WRITE_DONE,
};

enum msc_bot_medium_policy {
	MSC_BOT_MEDIUM_POLICY_ALWAYS_READY,
	MSC_BOT_MEDIUM_POLICY_TRACKED,
};

struct msc_bot_cbw {
	uint32_t signature;
	uint32_t tag;
	uint32_t data_length;
	uint8_t flags;
	uint8_t lun;
	uint8_t cb_length;
	uint8_t cb[16];
} __packed;

struct msc_bot_csw {
	uint32_t signature;
	uint32_t tag;
	uint32_t data_residue;
	uint8_t status;
} __packed;

struct msc_bot_inquiry_data {
	uint8_t head[8];
	uint8_t t10_vid[8];
	uint8_t product_id[16];
	uint8_t revision[4];
} __packed;

struct msc_bot_ctx;

struct msc_bot_ops {
	void (*on_eject)(struct msc_bot_ctx *ctx, void *user_data);
};

struct msc_bot_cfg {
	const char *disk_name;
	uint8_t in_ep_addr;
	uint8_t out_ep_addr;
	uint16_t block_size;
	uint16_t packet_size;
	const struct msc_bot_inquiry_data *inquiry;
	enum msc_bot_medium_policy medium_policy;
	bool reset_on_disconnect;
	uint8_t default_sense_key;
	uint8_t default_sense_asc;
	uint8_t default_sense_ascq;
	const struct msc_bot_ops *ops;
	void *user_data;
};

struct msc_bot_ctx {
	const struct msc_bot_cfg *cfg;
	struct msc_bot_cbw cbw;
	struct msc_bot_csw csw;
	enum msc_bot_stage stage;
	uint32_t block_count;
	uint32_t curr_lba;
	uint32_t length;
	uint16_t curr_offset;
	volatile int thread_op;
	volatile uint32_t deferred_wr_sz;
	bool mem_ok;
	bool prevent_removal;
	bool medium_loaded;
	bool io_allowed;
	bool thread_started;
	uint8_t sense_key;
	uint8_t sense_asc;
	uint8_t sense_ascq;
	struct k_thread thread;
	struct k_sem disk_wait_sem;
	uint8_t *page;
	size_t page_len;
};

int msc_bot_init(struct msc_bot_ctx *ctx, const struct msc_bot_cfg *cfg,
		 uint8_t *page, size_t page_len);
int msc_bot_start_thread(struct msc_bot_ctx *ctx, k_thread_stack_t *stack,
			 size_t stack_size, int prio, const char *name);
void msc_bot_reset_protocol(struct msc_bot_ctx *ctx);
void msc_bot_set_medium_state(struct msc_bot_ctx *ctx, bool loaded,
			      bool io_allowed);
void msc_bot_bulk_out(struct msc_bot_ctx *ctx, uint8_t ep);
void msc_bot_bulk_in(struct msc_bot_ctx *ctx);
void msc_bot_usb_status(struct msc_bot_ctx *ctx,
			enum usb_dc_status_code status);
int msc_bot_class_handle_req(struct msc_bot_ctx *ctx, uint8_t interface_number,
			     struct usb_setup_packet *setup, int32_t *len,
			     uint8_t **data);
void msc_bot_thread_main(void *arg1, void *arg2, void *arg3);

#endif /* ZEPHYR_INCLUDE_USB_CLASS_MSC_BOT_H_ */
