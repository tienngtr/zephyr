/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/storage/disk_access.h>

#include "secure_mass_priv.h"

LOG_MODULE_DECLARE(secure_mass, LOG_LEVEL_INF);

struct secure_msc_context {
	struct msc_cbw cbw;
	struct msc_csw csw;
	enum secure_msc_stage stage;
	uint32_t block_count;
	uint32_t curr_lba;
	uint32_t length;
	uint16_t curr_offset;
	volatile int thread_op;
	volatile uint32_t deferred_wr_sz;
	bool medium_loaded;
	bool prevent_removal;
	bool io_allowed;
	bool thread_started;
	bool mem_ok;
	uint8_t sense_key;
	uint8_t sense_asc;
	uint8_t sense_ascq;
	struct k_thread thread;
	struct k_sem disk_wait_sem;
	uint8_t __aligned(4) page[SECURE_MSC_BLOCK_SIZE + SECURE_MSC_EP_MPS];
};

static const struct msc_inquiry_data msc_inquiry_rsp = {
	.head = { 0x00, 0x80, 0x00, 0x01, 36 - 4, 0x80, 0x00, 0x00 },
	.t10_vid = "Zephyr  ",
	.product_id = "Secure RAM Disk ",
	.revision = "1.00",
};

static struct secure_msc_context msc;

K_KERNEL_STACK_DEFINE(msc_thread_stack, SECURE_MSC_STACK_SIZE);

static void secure_msc_bulk_out(uint8_t ep,
				enum usb_dc_ep_cb_status_code ep_status);
static void secure_msc_bulk_in(uint8_t ep,
			       enum usb_dc_ep_cb_status_code ep_status);
static void msc_thread_main(void *arg1, void *arg2, void *arg3);
static void secure_msc_set_sense(uint8_t key, uint8_t asc, uint8_t ascq);
static void secure_msc_clear_sense(void);
static void secure_msc_reset_protocol(void);
static void msc_send_csw(void);
static void msc_fail_command(void);
static bool msc_write_to_host(uint8_t *buf, uint16_t size);
static bool msc_check_medium_ready(void);
static bool msc_check_cbw_data_length(void);
static void msc_test_unit_ready(void);
static bool msc_request_sense(void);
static bool msc_inquiry_request(void);
static bool msc_mode_sense6(void);
static bool msc_read_format_capacity(void);
static bool msc_read_capacity(void);
static void msc_thread_memory_read_done(void);
static void msc_memory_read(void);
static bool msc_info_transfer(void);
static void msc_memory_verify(uint8_t *buf, uint16_t size);
static void msc_memory_write(uint8_t *buf, uint16_t size);
static void msc_thread_memory_write_done(void);
static void msc_decode_cbw(uint8_t *buf, uint16_t size);

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

static void secure_msc_set_sense(uint8_t key, uint8_t asc, uint8_t ascq)
{
	msc.sense_key = key;
	msc.sense_asc = asc;
	msc.sense_ascq = ascq;
}

static void secure_msc_clear_sense(void)
{
	secure_msc_set_sense(SCSI_SENSE_NONE, 0, 0);
}

static void secure_msc_reset_protocol(void)
{
	memset(&msc.cbw, 0, sizeof(msc.cbw));
	memset(&msc.csw, 0, sizeof(msc.csw));
	memset(msc.page, 0, sizeof(msc.page));

	msc.curr_lba = 0U;
	msc.length = 0U;
	msc.curr_offset = 0U;
	msc.stage = MSC_STAGE_READ_CBW;
	msc.prevent_removal = false;
	msc.mem_ok = true;
	secure_msc_clear_sense();
}

void secure_msc_set_active(bool active)
{
	msc.medium_loaded = active;
	msc.io_allowed = active;
	secure_msc_reset_protocol();
}

static void msc_send_csw(void)
{
	msc.csw.signature = MSC_CSW_SIGNATURE;
	if (usb_write(SECURE_MSC_IN_EP_ADDR, (uint8_t *)&msc.csw,
		      sizeof(msc.csw), NULL) != 0) {
		LOG_ERR("Failed to send MSC CSW");
	}
	msc.stage = MSC_STAGE_WAIT_CSW;
}

static void msc_fail_command(void)
{
	if (msc.cbw.data_length != 0U) {
		if (msc.cbw.flags & MSC_CBW_DIRECTION_DATA_IN) {
			usb_ep_set_stall(SECURE_MSC_IN_EP_ADDR);
		} else {
			usb_ep_set_stall(SECURE_MSC_OUT_EP_ADDR);
		}
	}

	msc.csw.status = MSC_CSW_STATUS_FAILED;
	msc_send_csw();
}

static bool msc_write_to_host(uint8_t *buf, uint16_t size)
{
	if (size >= msc.cbw.data_length) {
		size = msc.cbw.data_length;
	}

	msc.stage = MSC_STAGE_SEND_CSW;

	if (usb_write(SECURE_MSC_IN_EP_ADDR, buf, size, NULL) != 0) {
		LOG_ERR("Failed to write MSC payload");
		return false;
	}

	msc.csw.data_residue -= size;
	msc.csw.status = MSC_CSW_STATUS_PASSED;
	return true;
}

static bool msc_check_medium_ready(void)
{
	if (!msc.medium_loaded || !msc.io_allowed) {
		secure_msc_set_sense(SCSI_SENSE_NOT_READY,
				     SCSI_ASC_MEDIA_NOT_PRESENT, 0x00);
		msc.csw.status = MSC_CSW_STATUS_FAILED;
		msc_send_csw();
		return false;
	}

	return true;
}

static bool msc_check_cbw_data_length(void)
{
	if (msc.cbw.data_length == 0U) {
		msc.csw.status = MSC_CSW_STATUS_FAILED;
		msc_send_csw();
		return false;
	}

	return true;
}

static void msc_test_unit_ready(void)
{
	if (!msc_check_medium_ready()) {
		return;
	}

	if (msc.cbw.data_length != 0U) {
		if (msc.cbw.flags & MSC_CBW_DIRECTION_DATA_IN) {
			usb_ep_set_stall(SECURE_MSC_IN_EP_ADDR);
		} else {
			usb_ep_set_stall(SECURE_MSC_OUT_EP_ADDR);
		}
	}

	msc.csw.status = MSC_CSW_STATUS_PASSED;
	msc_send_csw();
}

static bool msc_request_sense(void)
{
	uint8_t request_sense[] = {
		0x70, 0x00, msc.sense_key, 0x00, 0x00, 0x00, 0x00, 0x0A,
		0x00, 0x00, 0x00, 0x00, msc.sense_asc, msc.sense_ascq,
		0x00, 0x00, 0x00, 0x00,
	};

	secure_msc_clear_sense();
	return msc_write_to_host(request_sense, sizeof(request_sense));
}

static bool msc_inquiry_request(void)
{
	return msc_write_to_host((uint8_t *)&msc_inquiry_rsp,
				 sizeof(msc_inquiry_rsp));
}

static bool msc_mode_sense6(void)
{
	uint8_t sense6[] = { 0x03, 0x00, 0x00, 0x00 };

	return msc_write_to_host(sense6, sizeof(sense6));
}

static bool msc_read_format_capacity(void)
{
	uint8_t capacity[] = {
		0x00, 0x00, 0x00, 0x08,
		(uint8_t)((msc.block_count >> 24) & 0xff),
		(uint8_t)((msc.block_count >> 16) & 0xff),
		(uint8_t)((msc.block_count >> 8) & 0xff),
		(uint8_t)(msc.block_count & 0xff),
		0x02,
		(uint8_t)((SECURE_MSC_BLOCK_SIZE >> 16) & 0xff),
		(uint8_t)((SECURE_MSC_BLOCK_SIZE >> 8) & 0xff),
		(uint8_t)(SECURE_MSC_BLOCK_SIZE & 0xff),
	};

	if (!msc_check_medium_ready()) {
		return false;
	}

	return msc_write_to_host(capacity, sizeof(capacity));
}

static bool msc_read_capacity(void)
{
	uint8_t capacity[8];

	if (!msc_check_medium_ready()) {
		return false;
	}

	sys_put_be32(msc.block_count - 1U, &capacity[0]);
	sys_put_be32(SECURE_MSC_BLOCK_SIZE, &capacity[4]);

	return msc_write_to_host(capacity, sizeof(capacity));
}

static void msc_thread_memory_read_done(void)
{
	uint32_t n = msc.length;

	if (n > SECURE_MSC_EP_MPS) {
		n = SECURE_MSC_EP_MPS;
	}
	if (n > SECURE_MSC_BLOCK_SIZE - msc.curr_offset) {
		n = SECURE_MSC_BLOCK_SIZE - msc.curr_offset;
	}

	if (usb_write(SECURE_MSC_IN_EP_ADDR, &msc.page[msc.curr_offset], n,
		      NULL) != 0) {
		LOG_ERR("Failed to write MSC read data");
	}

	msc.curr_offset += n;
	if (msc.curr_offset >= SECURE_MSC_BLOCK_SIZE) {
		msc.curr_offset -= SECURE_MSC_BLOCK_SIZE;
		msc.curr_lba += 1U;
	}
	msc.length -= n;
	msc.csw.data_residue -= n;

	if (!msc.length || msc.stage != MSC_STAGE_PROCESS_CBW) {
		msc.csw.status = (msc.stage == MSC_STAGE_PROCESS_CBW) ?
			MSC_CSW_STATUS_PASSED : MSC_CSW_STATUS_FAILED;
		msc.stage = (msc.stage == MSC_STAGE_PROCESS_CBW) ?
			MSC_STAGE_SEND_CSW : msc.stage;
	}
}

static void msc_memory_read(void)
{
	if (msc.curr_lba >= msc.block_count) {
		msc_fail_command();
		return;
	}

	if (!msc_check_medium_ready()) {
		return;
	}

	if (!msc.curr_offset) {
		msc.thread_op = THREAD_OP_READ_QUEUED;
		k_sem_give(&msc.disk_wait_sem);
	} else {
		msc_thread_memory_read_done();
	}
}

static bool msc_info_transfer(void)
{
	uint32_t n;

	if (!msc_check_medium_ready() || !msc_check_cbw_data_length()) {
		return false;
	}

	n = sys_get_be32(&msc.cbw.cb[2]);
	if (n >= msc.block_count) {
		msc_fail_command();
		return false;
	}

	msc.curr_lba = n;
	msc.curr_offset = 0U;

	switch (msc.cbw.cb[0]) {
	case SCSI_READ10:
	case SCSI_WRITE10:
	case SCSI_VERIFY10:
		n = sys_get_be16(&msc.cbw.cb[7]);
		break;
	case SCSI_READ12:
	case SCSI_WRITE12:
		n = sys_get_be32(&msc.cbw.cb[6]);
		break;
	default:
		n = 0U;
		break;
	}

	msc.length = n * SECURE_MSC_BLOCK_SIZE;

	if (msc.cbw.data_length != msc.length) {
		msc_fail_command();
		return false;
	}

	return true;
}

static void msc_memory_verify(uint8_t *buf, uint16_t size)
{
	uint32_t n;

	if (msc.curr_lba >= msc.block_count) {
		msc_fail_command();
		return;
	}

	if (!msc_check_medium_ready()) {
		return;
	}

	if (!msc.curr_offset) {
		if (disk_access_read(SECURE_RAMDISK_NAME, msc.page,
				     msc.curr_lba, 1) != 0) {
			LOG_ERR("MSC verify read failed");
			msc_fail_command();
			return;
		}
	}

	for (n = 0U; n < size; n++) {
		if (msc.page[msc.curr_offset + n] != buf[n]) {
			msc.mem_ok = false;
			break;
		}
	}

	msc.curr_offset += n;
	if (msc.curr_offset >= SECURE_MSC_BLOCK_SIZE) {
		msc.curr_offset -= SECURE_MSC_BLOCK_SIZE;
		msc.curr_lba += 1U;
	}
	msc.length -= size;
	msc.csw.data_residue -= size;

	if (!msc.length || msc.stage != MSC_STAGE_PROCESS_CBW) {
		msc.csw.status = (msc.mem_ok && msc.stage == MSC_STAGE_PROCESS_CBW) ?
			MSC_CSW_STATUS_PASSED : MSC_CSW_STATUS_FAILED;
		msc_send_csw();
	}
}

static void msc_memory_write(uint8_t *buf, uint16_t size)
{
	if (msc.curr_lba >= msc.block_count) {
		msc_fail_command();
		return;
	}

	if (!msc_check_medium_ready()) {
		return;
	}

	for (uint16_t i = 0; i < size; i++) {
		msc.page[msc.curr_offset + i] = buf[i];
	}

	if (msc.curr_offset + size >= SECURE_MSC_BLOCK_SIZE) {
		msc.thread_op = THREAD_OP_WRITE_QUEUED;
		msc.deferred_wr_sz = size;
		k_sem_give(&msc.disk_wait_sem);
		return;
	}

	msc.curr_offset += size;
	msc.length -= size;
	msc.csw.data_residue -= size;

	if (!msc.length || msc.stage != MSC_STAGE_PROCESS_CBW) {
		msc.csw.status = (msc.stage == MSC_STAGE_ERROR) ?
			MSC_CSW_STATUS_FAILED : MSC_CSW_STATUS_PASSED;
		msc_send_csw();
	}
}

static void msc_thread_memory_write_done(void)
{
	uint32_t size = msc.deferred_wr_sz;
	size_t overflowed_len = (msc.curr_offset + size) - SECURE_MSC_BLOCK_SIZE;

	if (SECURE_MSC_BLOCK_SIZE > (msc.curr_offset + size)) {
		overflowed_len = 0;
	}

	if (overflowed_len > 0U) {
		memmove(msc.page, &msc.page[SECURE_MSC_BLOCK_SIZE], overflowed_len);
	}

	msc.curr_offset = overflowed_len;
	msc.curr_lba += 1U;
	msc.length -= size;
	msc.csw.data_residue -= size;

	if (!msc.length) {
		if (disk_access_ioctl(SECURE_RAMDISK_NAME, DISK_IOCTL_CTRL_SYNC,
				      NULL) != 0) {
			LOG_WRN("MSC sync failed");
		}
	}

	if (!msc.length || msc.stage != MSC_STAGE_PROCESS_CBW) {
		msc.csw.status = (msc.stage == MSC_STAGE_ERROR) ?
			MSC_CSW_STATUS_FAILED : MSC_CSW_STATUS_PASSED;
		msc_send_csw();
	}

	msc.thread_op = THREAD_OP_WRITE_DONE;
	usb_ep_read_continue(SECURE_MSC_OUT_EP_ADDR);
}

static void msc_decode_cbw(uint8_t *buf, uint16_t size)
{
	if (size != sizeof(msc.cbw)) {
		LOG_WRN("Unexpected CBW size %u", size);
		return;
	}

	memcpy(&msc.cbw, buf, size);
	if (msc.cbw.signature != MSC_CBW_SIGNATURE) {
		LOG_WRN("Invalid MSC CBW signature");
		return;
	}

	msc.csw.tag = msc.cbw.tag;
	msc.csw.data_residue = msc.cbw.data_length;

	if (msc.cbw.cb_length < 1U || msc.cbw.cb_length > 16U ||
	    msc.cbw.lun != 0U) {
		msc_fail_command();
		return;
	}

	switch (msc.cbw.cb[0]) {
	case SCSI_TEST_UNIT_READY:
		msc_test_unit_ready();
		break;
	case SCSI_REQUEST_SENSE:
		if (msc_check_cbw_data_length()) {
			msc_request_sense();
		}
		break;
	case SCSI_INQUIRY:
		if (msc_check_cbw_data_length()) {
			msc_inquiry_request();
		}
		break;
	case SCSI_MODE_SENSE6:
		if (msc_check_cbw_data_length()) {
			msc_mode_sense6();
		}
		break;
	case SCSI_READ_FORMAT_CAPACITIES:
		if (msc_check_cbw_data_length()) {
			msc_read_format_capacity();
		}
		break;
	case SCSI_READ_CAPACITY:
		if (msc_check_cbw_data_length()) {
			msc_read_capacity();
		}
		break;
	case SCSI_READ10:
	case SCSI_READ12:
		if (msc_info_transfer()) {
			if (msc.cbw.flags & MSC_CBW_DIRECTION_DATA_IN) {
				msc.stage = MSC_STAGE_PROCESS_CBW;
				msc_memory_read();
			} else {
				usb_ep_set_stall(SECURE_MSC_OUT_EP_ADDR);
				msc.csw.status = MSC_CSW_STATUS_PHASE_ERROR;
				msc_send_csw();
			}
		}
		break;
	case SCSI_WRITE10:
	case SCSI_WRITE12:
		if (msc_info_transfer()) {
			if (!(msc.cbw.flags & MSC_CBW_DIRECTION_DATA_IN)) {
				msc.stage = MSC_STAGE_PROCESS_CBW;
			} else {
				usb_ep_set_stall(SECURE_MSC_IN_EP_ADDR);
				msc.csw.status = MSC_CSW_STATUS_PHASE_ERROR;
				msc_send_csw();
			}
		}
		break;
	case SCSI_VERIFY10:
		if (!(msc.cbw.cb[1] & 0x02U)) {
			msc.csw.status = MSC_CSW_STATUS_PASSED;
			msc_send_csw();
			break;
		}
		if (msc_info_transfer()) {
			if (!(msc.cbw.flags & MSC_CBW_DIRECTION_DATA_IN)) {
				msc.stage = MSC_STAGE_PROCESS_CBW;
				msc.mem_ok = true;
			} else {
				usb_ep_set_stall(SECURE_MSC_IN_EP_ADDR);
				msc.csw.status = MSC_CSW_STATUS_PHASE_ERROR;
				msc_send_csw();
			}
		}
		break;
	case SCSI_MEDIA_REMOVAL:
		msc.prevent_removal = (msc.cbw.cb[4] & 0x01U) != 0U;
		msc.csw.status = MSC_CSW_STATUS_PASSED;
		msc_send_csw();
		break;
	case SCSI_START_STOP_UNIT: {
		bool loej = (msc.cbw.cb[4] & 0x02U) != 0U;
		bool start = (msc.cbw.cb[4] & 0x01U) != 0U;

		if (loej && !start) {
			if (msc.prevent_removal) {
				secure_msc_set_sense(SCSI_SENSE_ILLEGAL_REQUEST,
						     SCSI_ASC_INVALID_COMMAND, 0x00);
				msc_fail_command();
				break;
			}

			msc.medium_loaded = false;
			msc.io_allowed = false;
			secure_msc_set_sense(SCSI_SENSE_NOT_READY,
					     SCSI_ASC_MEDIA_NOT_PRESENT, 0x00);
			msc.csw.status = MSC_CSW_STATUS_PASSED;
			msc_send_csw();
			secure_mass_request_relock();
			break;
		}

		if (loej && start) {
			msc.medium_loaded = true;
			msc.io_allowed = true;
		}

		msc.csw.status = MSC_CSW_STATUS_PASSED;
		msc_send_csw();
		break;
	}
	default:
		secure_msc_set_sense(SCSI_SENSE_ILLEGAL_REQUEST,
				     SCSI_ASC_INVALID_COMMAND, 0x00);
		msc_fail_command();
		break;
	}
}

static void secure_msc_bulk_out(uint8_t ep,
				enum usb_dc_ep_cb_status_code ep_status)
{
	uint8_t buf[SECURE_MSC_EP_MPS];
	uint32_t bytes_read = 0U;

	ARG_UNUSED(ep_status);

	if (usb_ep_read_wait(ep, buf, sizeof(buf), &bytes_read) != 0) {
		return;
	}

	switch (msc.stage) {
	case MSC_STAGE_READ_CBW:
		msc_decode_cbw(buf, bytes_read);
		break;
	case MSC_STAGE_PROCESS_CBW:
		switch (msc.cbw.cb[0]) {
		case SCSI_WRITE10:
		case SCSI_WRITE12:
			msc_memory_write(buf, bytes_read);
			break;
		case SCSI_VERIFY10:
			msc_memory_verify(buf, bytes_read);
			break;
		default:
			msc.stage = MSC_STAGE_ERROR;
			msc_fail_command();
			break;
		}
		break;
	default:
		usb_ep_set_stall(ep);
		msc.csw.status = MSC_CSW_STATUS_PHASE_ERROR;
		msc_send_csw();
		break;
	}

	if (msc.thread_op != THREAD_OP_WRITE_QUEUED) {
		usb_ep_read_continue(ep);
	}
}

static void secure_msc_bulk_in(uint8_t ep,
			       enum usb_dc_ep_cb_status_code ep_status)
{
	ARG_UNUSED(ep);
	ARG_UNUSED(ep_status);

	switch (msc.stage) {
	case MSC_STAGE_PROCESS_CBW:
		switch (msc.cbw.cb[0]) {
		case SCSI_READ10:
		case SCSI_READ12:
			msc_memory_read();
			break;
		default:
			msc.stage = MSC_STAGE_ERROR;
			msc_fail_command();
			break;
		}
		break;
	case MSC_STAGE_SEND_CSW:
		msc_send_csw();
		break;
	case MSC_STAGE_WAIT_CSW:
		msc.stage = MSC_STAGE_READ_CBW;
		break;
	default:
		usb_ep_set_stall(SECURE_MSC_IN_EP_ADDR);
		msc_send_csw();
		break;
	}
}

void secure_msc_status_cb(struct usb_cfg_data *cfg,
			  enum usb_dc_status_code status,
			  const uint8_t *param)
{
	ARG_UNUSED(cfg);
	ARG_UNUSED(param);

	switch (status) {
	case USB_DC_RESET:
	case USB_DC_DISCONNECTED:
		secure_msc_reset_protocol();
		break;
	default:
		break;
	}
}

int secure_msc_class_handle_req(struct usb_setup_packet *setup,
				int32_t *len, uint8_t **data)
{
	static uint8_t max_lun_count;

	ARG_UNUSED(data);

	if ((setup->wIndex & 0xFF) != 1U || setup->wValue != 0U) {
		return -EINVAL;
	}

	if (usb_reqtype_is_to_device(setup)) {
		if (setup->bRequest == MSC_REQUEST_RESET && setup->wLength == 0U) {
			secure_msc_reset_protocol();
			return 0;
		}
	} else {
		if (setup->bRequest == MSC_REQUEST_GET_MAX_LUN &&
		    setup->wLength == 1U) {
			max_lun_count = 0U;
			*data = &max_lun_count;
			*len = 1;
			return 0;
		}
	}

	return -ENOTSUP;
}

static void msc_thread_main(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	while (true) {
		k_sem_take(&msc.disk_wait_sem, K_FOREVER);

		switch (msc.thread_op) {
		case THREAD_OP_READ_QUEUED:
			if (disk_access_read(SECURE_RAMDISK_NAME, msc.page,
					     msc.curr_lba, 1) != 0) {
				LOG_ERR("MSC disk read failed");
			}
			msc_thread_memory_read_done();
			break;
		case THREAD_OP_WRITE_QUEUED:
			if (disk_access_write(SECURE_RAMDISK_NAME, msc.page,
					      msc.curr_lba, 1) != 0) {
				LOG_ERR("MSC disk write failed");
			}
			msc_thread_memory_write_done();
			break;
		default:
			break;
		}
	}
}

int secure_msc_init(void)
{
	uint32_t block_size = 0U;
	int rc;

	rc = disk_access_init(SECURE_RAMDISK_NAME);
	if (rc != 0) {
		LOG_ERR("disk_access_init failed (%d)", rc);
		return rc;
	}

	rc = disk_access_ioctl(SECURE_RAMDISK_NAME, DISK_IOCTL_GET_SECTOR_COUNT,
			       &msc.block_count);
	if (rc != 0) {
		LOG_ERR("Failed to query sector count (%d)", rc);
		return rc;
	}

	rc = disk_access_ioctl(SECURE_RAMDISK_NAME, DISK_IOCTL_GET_SECTOR_SIZE,
			       &block_size);
	if (rc != 0) {
		LOG_ERR("Failed to query sector size (%d)", rc);
		return rc;
	}

	if (block_size != SECURE_MSC_BLOCK_SIZE) {
		LOG_ERR("Unsupported sector size %u", block_size);
		return -EINVAL;
	}

	k_sem_init(&msc.disk_wait_sem, 0, 1);
	secure_msc_set_active(false);

	if (!msc.thread_started) {
		k_thread_create(&msc.thread, msc_thread_stack,
				SECURE_MSC_STACK_SIZE, msc_thread_main,
				NULL, NULL, NULL, SECURE_MSC_THREAD_PRIO,
				0, K_NO_WAIT);
		msc.thread_started = true;
	}

	return 0;
}
