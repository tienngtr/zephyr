/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/usb/class/msc_bot.h>

#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/storage/disk_access.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(usb_msc_bot, CONFIG_LOG_DEFAULT_LEVEL);

static uint8_t *msc_bot_packet_buf(struct msc_bot_ctx *ctx)
{
	return &ctx->page[ctx->cfg->block_size];
}

static bool msc_bot_medium_tracked(const struct msc_bot_ctx *ctx)
{
	return ctx->cfg->medium_policy == MSC_BOT_MEDIUM_POLICY_TRACKED;
}

static void msc_bot_set_sense(struct msc_bot_ctx *ctx, uint8_t key,
			      uint8_t asc, uint8_t ascq)
{
	ctx->sense_key = key;
	ctx->sense_asc = asc;
	ctx->sense_ascq = ascq;
}

static void msc_bot_clear_sense(struct msc_bot_ctx *ctx)
{
	msc_bot_set_sense(ctx, ctx->cfg->default_sense_key,
			  ctx->cfg->default_sense_asc,
			  ctx->cfg->default_sense_ascq);
}

void msc_bot_set_medium_state(struct msc_bot_ctx *ctx, bool loaded,
			      bool io_allowed)
{
	ctx->medium_loaded = loaded;
	ctx->io_allowed = io_allowed;
}

void msc_bot_reset_protocol(struct msc_bot_ctx *ctx)
{
	memset(&ctx->cbw, 0, sizeof(ctx->cbw));
	memset(&ctx->csw, 0, sizeof(ctx->csw));
	memset(ctx->page, 0, ctx->page_len);

	ctx->curr_lba = 0U;
	ctx->length = 0U;
	ctx->curr_offset = 0U;
	ctx->stage = MSC_BOT_STAGE_READ_CBW;
	ctx->thread_op = MSC_BOT_THREAD_OP_NONE;
	ctx->deferred_wr_sz = 0U;
	ctx->prevent_removal = false;
	ctx->mem_ok = true;
	msc_bot_clear_sense(ctx);
}

static void msc_bot_send_csw(struct msc_bot_ctx *ctx)
{
	ctx->csw.signature = MSC_BOT_CSW_SIGNATURE;
	if (usb_write(ctx->cfg->in_ep_addr, (uint8_t *)&ctx->csw,
		      sizeof(ctx->csw), NULL) != 0) {
		LOG_ERR("Failed to send MSC CSW");
	}

	ctx->stage = MSC_BOT_STAGE_WAIT_CSW;
}

static void msc_bot_fail_command(struct msc_bot_ctx *ctx)
{
	if (ctx->cbw.data_length != 0U) {
		if ((ctx->cbw.flags & MSC_BOT_CBW_DIRECTION_DATA_IN) != 0U) {
			usb_ep_set_stall(ctx->cfg->in_ep_addr);
		} else {
			usb_ep_set_stall(ctx->cfg->out_ep_addr);
		}
	}

	ctx->csw.status = MSC_BOT_CSW_STATUS_FAILED;
	msc_bot_send_csw(ctx);
}

static bool msc_bot_write_to_host(struct msc_bot_ctx *ctx, uint8_t *buf,
				  uint16_t size)
{
	if (size >= ctx->cbw.data_length) {
		size = ctx->cbw.data_length;
	}

	ctx->stage = MSC_BOT_STAGE_SEND_CSW;

	if (usb_write(ctx->cfg->in_ep_addr, buf, size, NULL) != 0) {
		LOG_ERR("Failed to write MSC payload");
		return false;
	}

	ctx->csw.data_residue -= size;
	ctx->csw.status = MSC_BOT_CSW_STATUS_PASSED;
	return true;
}

static bool msc_bot_check_medium_ready(struct msc_bot_ctx *ctx)
{
	if (!msc_bot_medium_tracked(ctx)) {
		return true;
	}

	if (!ctx->medium_loaded || !ctx->io_allowed) {
		msc_bot_set_sense(ctx, MSC_BOT_SCSI_SENSE_NOT_READY,
				  MSC_BOT_SCSI_ASC_MEDIA_NOT_PRESENT, 0x00);
		ctx->csw.status = MSC_BOT_CSW_STATUS_FAILED;
		msc_bot_send_csw(ctx);
		return false;
	}

	return true;
}

static bool msc_bot_check_cbw_data_length(struct msc_bot_ctx *ctx)
{
	if (ctx->cbw.data_length == 0U) {
		ctx->csw.status = MSC_BOT_CSW_STATUS_FAILED;
		msc_bot_send_csw(ctx);
		return false;
	}

	return true;
}

static void msc_bot_test_unit_ready(struct msc_bot_ctx *ctx)
{
	if (!msc_bot_check_medium_ready(ctx)) {
		return;
	}

	if (ctx->cbw.data_length != 0U) {
		if ((ctx->cbw.flags & MSC_BOT_CBW_DIRECTION_DATA_IN) != 0U) {
			usb_ep_set_stall(ctx->cfg->in_ep_addr);
		} else {
			usb_ep_set_stall(ctx->cfg->out_ep_addr);
		}
	}

	ctx->csw.status = MSC_BOT_CSW_STATUS_PASSED;
	msc_bot_send_csw(ctx);
}

static bool msc_bot_request_sense(struct msc_bot_ctx *ctx)
{
	uint8_t request_sense[] = {
		0x70, 0x00, ctx->sense_key, 0x00, 0x00, 0x00, 0x00, 0x0A,
		0x00, 0x00, 0x00, 0x00, ctx->sense_asc, ctx->sense_ascq,
		0x00, 0x00, 0x00, 0x00,
	};

	msc_bot_clear_sense(ctx);
	return msc_bot_write_to_host(ctx, request_sense, sizeof(request_sense));
}

static bool msc_bot_inquiry_request(struct msc_bot_ctx *ctx)
{
	return msc_bot_write_to_host(ctx, (uint8_t *)ctx->cfg->inquiry,
				     sizeof(*ctx->cfg->inquiry));
}

static bool msc_bot_mode_sense6(struct msc_bot_ctx *ctx)
{
	uint8_t sense6[] = { 0x03, 0x00, 0x00, 0x00 };

	return msc_bot_write_to_host(ctx, sense6, sizeof(sense6));
}

static bool msc_bot_read_format_capacity(struct msc_bot_ctx *ctx)
{
	uint8_t capacity[] = {
		0x00, 0x00, 0x00, 0x08,
		(uint8_t)((ctx->block_count >> 24) & 0xff),
		(uint8_t)((ctx->block_count >> 16) & 0xff),
		(uint8_t)((ctx->block_count >> 8) & 0xff),
		(uint8_t)(ctx->block_count & 0xff),
		0x02,
		(uint8_t)((ctx->cfg->block_size >> 16) & 0xff),
		(uint8_t)((ctx->cfg->block_size >> 8) & 0xff),
		(uint8_t)(ctx->cfg->block_size & 0xff),
	};

	if (!msc_bot_check_medium_ready(ctx)) {
		return false;
	}

	return msc_bot_write_to_host(ctx, capacity, sizeof(capacity));
}

static bool msc_bot_read_capacity(struct msc_bot_ctx *ctx)
{
	uint8_t capacity[8];

	if (!msc_bot_check_medium_ready(ctx)) {
		return false;
	}

	sys_put_be32(ctx->block_count - 1U, &capacity[0]);
	sys_put_be32(ctx->cfg->block_size, &capacity[4]);

	return msc_bot_write_to_host(ctx, capacity, sizeof(capacity));
}

static void msc_bot_thread_memory_read_done(struct msc_bot_ctx *ctx)
{
	uint32_t n = ctx->length;

	if (n > ctx->cfg->packet_size) {
		n = ctx->cfg->packet_size;
	}
	if (n > ctx->cfg->block_size - ctx->curr_offset) {
		n = ctx->cfg->block_size - ctx->curr_offset;
	}

	if (usb_write(ctx->cfg->in_ep_addr, &ctx->page[ctx->curr_offset], n,
		      NULL) != 0) {
		LOG_ERR("Failed to write MSC read data");
	}

	ctx->curr_offset += n;
	if (ctx->curr_offset >= ctx->cfg->block_size) {
		ctx->curr_offset -= ctx->cfg->block_size;
		ctx->curr_lba += 1U;
	}
	ctx->length -= n;
	ctx->csw.data_residue -= n;

	if (!ctx->length || ctx->stage != MSC_BOT_STAGE_PROCESS_CBW) {
		ctx->csw.status = (ctx->stage == MSC_BOT_STAGE_PROCESS_CBW) ?
			MSC_BOT_CSW_STATUS_PASSED :
			MSC_BOT_CSW_STATUS_FAILED;
		ctx->stage = (ctx->stage == MSC_BOT_STAGE_PROCESS_CBW) ?
			MSC_BOT_STAGE_SEND_CSW : ctx->stage;
	}
}

static void msc_bot_memory_read(struct msc_bot_ctx *ctx)
{
	if (ctx->curr_lba >= ctx->block_count) {
		msc_bot_fail_command(ctx);
		return;
	}

	if (!msc_bot_check_medium_ready(ctx)) {
		return;
	}

	if (ctx->curr_offset == 0U) {
		ctx->thread_op = MSC_BOT_THREAD_OP_READ_QUEUED;
		k_sem_give(&ctx->disk_wait_sem);
	} else {
		msc_bot_thread_memory_read_done(ctx);
	}
}

static bool msc_bot_info_transfer(struct msc_bot_ctx *ctx)
{
	uint32_t n;

	if (!msc_bot_check_medium_ready(ctx) ||
	    !msc_bot_check_cbw_data_length(ctx)) {
		return false;
	}

	n = sys_get_be32(&ctx->cbw.cb[2]);
	if (n >= ctx->block_count) {
		msc_bot_fail_command(ctx);
		return false;
	}

	ctx->curr_lba = n;
	ctx->curr_offset = 0U;

	switch (ctx->cbw.cb[0]) {
	case MSC_BOT_SCSI_READ10:
	case MSC_BOT_SCSI_WRITE10:
	case MSC_BOT_SCSI_VERIFY10:
		n = sys_get_be16(&ctx->cbw.cb[7]);
		break;
	case MSC_BOT_SCSI_READ12:
	case MSC_BOT_SCSI_WRITE12:
		n = sys_get_be32(&ctx->cbw.cb[6]);
		break;
	default:
		n = 0U;
		break;
	}

	ctx->length = n * ctx->cfg->block_size;

	if (ctx->cbw.data_length != ctx->length) {
		msc_bot_fail_command(ctx);
		return false;
	}

	return true;
}

static void msc_bot_memory_verify(struct msc_bot_ctx *ctx, uint8_t *buf,
				  uint16_t size)
{
	uint32_t n;

	if (ctx->curr_lba >= ctx->block_count) {
		msc_bot_fail_command(ctx);
		return;
	}

	if (!msc_bot_check_medium_ready(ctx)) {
		return;
	}

	if (ctx->curr_offset == 0U) {
		if (disk_access_read(ctx->cfg->disk_name, ctx->page,
				     ctx->curr_lba, 1) != 0) {
			LOG_ERR("MSC verify read failed");
			msc_bot_fail_command(ctx);
			return;
		}
	}

	for (n = 0U; n < size; n++) {
		if (ctx->page[ctx->curr_offset + n] != buf[n]) {
			ctx->mem_ok = false;
			break;
		}
	}

	ctx->curr_offset += n;
	if (ctx->curr_offset >= ctx->cfg->block_size) {
		ctx->curr_offset -= ctx->cfg->block_size;
		ctx->curr_lba += 1U;
	}
	ctx->length -= size;
	ctx->csw.data_residue -= size;

	if (!ctx->length || ctx->stage != MSC_BOT_STAGE_PROCESS_CBW) {
		ctx->csw.status = (ctx->mem_ok &&
				   ctx->stage == MSC_BOT_STAGE_PROCESS_CBW) ?
			MSC_BOT_CSW_STATUS_PASSED :
			MSC_BOT_CSW_STATUS_FAILED;
		msc_bot_send_csw(ctx);
	}
}

static void msc_bot_memory_write(struct msc_bot_ctx *ctx, uint8_t *buf,
				 uint16_t size)
{
	for (uint16_t i = 0; i < size; i++) {
		ctx->page[ctx->curr_offset + i] = buf[i];
	}

	if (ctx->curr_lba >= ctx->block_count) {
		msc_bot_fail_command(ctx);
		return;
	}

	if (!msc_bot_check_medium_ready(ctx)) {
		return;
	}

	if (ctx->curr_offset + size >= ctx->cfg->block_size) {
		if ((disk_access_status(ctx->cfg->disk_name) &
		     DISK_STATUS_WR_PROTECT) == 0) {
			ctx->thread_op = MSC_BOT_THREAD_OP_WRITE_QUEUED;
			ctx->deferred_wr_sz = size;
			k_sem_give(&ctx->disk_wait_sem);
			return;
		}
	}

	ctx->curr_offset += size;
	ctx->length -= size;
	ctx->csw.data_residue -= size;

	if (!ctx->length || ctx->stage != MSC_BOT_STAGE_PROCESS_CBW) {
		ctx->csw.status = (ctx->stage == MSC_BOT_STAGE_ERROR) ?
			MSC_BOT_CSW_STATUS_FAILED :
			MSC_BOT_CSW_STATUS_PASSED;
		msc_bot_send_csw(ctx);
	}
}

static void msc_bot_thread_memory_write_done(struct msc_bot_ctx *ctx)
{
	uint32_t size = ctx->deferred_wr_sz;
	size_t overflowed_len = (ctx->curr_offset + size) - ctx->cfg->block_size;

	if (ctx->cfg->block_size > (ctx->curr_offset + size)) {
		overflowed_len = 0U;
	}

	if (overflowed_len > 0U) {
		memmove(ctx->page, &ctx->page[ctx->cfg->block_size],
			overflowed_len);
	}

	ctx->curr_offset = overflowed_len;
	ctx->curr_lba += 1U;
	ctx->length -= size;
	ctx->csw.data_residue -= size;

	if (!ctx->length) {
		if (disk_access_ioctl(ctx->cfg->disk_name, DISK_IOCTL_CTRL_SYNC,
				      NULL) != 0) {
			LOG_WRN("MSC sync failed");
		}
	}

	if (!ctx->length || ctx->stage != MSC_BOT_STAGE_PROCESS_CBW) {
		ctx->csw.status = (ctx->stage == MSC_BOT_STAGE_ERROR) ?
			MSC_BOT_CSW_STATUS_FAILED :
			MSC_BOT_CSW_STATUS_PASSED;
		msc_bot_send_csw(ctx);
	}

	ctx->thread_op = MSC_BOT_THREAD_OP_WRITE_DONE;
	usb_ep_read_continue(ctx->cfg->out_ep_addr);
}

static void msc_bot_decode_cbw(struct msc_bot_ctx *ctx, uint8_t *buf,
			       uint16_t size)
{
	bool loej;
	bool start;

	if (size != sizeof(ctx->cbw)) {
		LOG_WRN("Unexpected CBW size %u", size);
		return;
	}

	memcpy(&ctx->cbw, buf, size);
	if (ctx->cbw.signature != MSC_BOT_CBW_SIGNATURE) {
		LOG_WRN("Invalid MSC CBW signature");
		return;
	}

	ctx->csw.tag = ctx->cbw.tag;
	ctx->csw.data_residue = ctx->cbw.data_length;

	if (ctx->cbw.cb_length < 1U || ctx->cbw.cb_length > 16U ||
	    ctx->cbw.lun != 0U) {
		msc_bot_fail_command(ctx);
		return;
	}

	switch (ctx->cbw.cb[0]) {
	case MSC_BOT_SCSI_TEST_UNIT_READY:
		msc_bot_test_unit_ready(ctx);
		break;
	case MSC_BOT_SCSI_REQUEST_SENSE:
		if (msc_bot_check_cbw_data_length(ctx)) {
			msc_bot_request_sense(ctx);
		}
		break;
	case MSC_BOT_SCSI_INQUIRY:
		if (msc_bot_check_cbw_data_length(ctx)) {
			msc_bot_inquiry_request(ctx);
		}
		break;
	case MSC_BOT_SCSI_MODE_SENSE6:
		if (msc_bot_check_cbw_data_length(ctx)) {
			msc_bot_mode_sense6(ctx);
		}
		break;
	case MSC_BOT_SCSI_READ_FORMAT_CAPACITIES:
		if (msc_bot_check_cbw_data_length(ctx)) {
			msc_bot_read_format_capacity(ctx);
		}
		break;
	case MSC_BOT_SCSI_READ_CAPACITY:
		if (msc_bot_check_cbw_data_length(ctx)) {
			msc_bot_read_capacity(ctx);
		}
		break;
	case MSC_BOT_SCSI_READ10:
	case MSC_BOT_SCSI_READ12:
		if (msc_bot_info_transfer(ctx)) {
			if ((ctx->cbw.flags & MSC_BOT_CBW_DIRECTION_DATA_IN) !=
			    0U) {
				ctx->stage = MSC_BOT_STAGE_PROCESS_CBW;
				msc_bot_memory_read(ctx);
			} else {
				usb_ep_set_stall(ctx->cfg->out_ep_addr);
				ctx->csw.status = MSC_BOT_CSW_STATUS_PHASE_ERROR;
				msc_bot_send_csw(ctx);
			}
		}
		break;
	case MSC_BOT_SCSI_WRITE10:
	case MSC_BOT_SCSI_WRITE12:
		if (msc_bot_info_transfer(ctx)) {
			if ((ctx->cbw.flags & MSC_BOT_CBW_DIRECTION_DATA_IN) ==
			    0U) {
				ctx->stage = MSC_BOT_STAGE_PROCESS_CBW;
			} else {
				usb_ep_set_stall(ctx->cfg->in_ep_addr);
				ctx->csw.status = MSC_BOT_CSW_STATUS_PHASE_ERROR;
				msc_bot_send_csw(ctx);
			}
		}
		break;
	case MSC_BOT_SCSI_VERIFY10:
		if ((ctx->cbw.cb[1] & 0x02U) == 0U) {
			ctx->csw.status = MSC_BOT_CSW_STATUS_PASSED;
			msc_bot_send_csw(ctx);
			break;
		}
		if (msc_bot_info_transfer(ctx)) {
			if ((ctx->cbw.flags & MSC_BOT_CBW_DIRECTION_DATA_IN) ==
			    0U) {
				ctx->stage = MSC_BOT_STAGE_PROCESS_CBW;
				ctx->mem_ok = true;
			} else {
				usb_ep_set_stall(ctx->cfg->in_ep_addr);
				ctx->csw.status = MSC_BOT_CSW_STATUS_PHASE_ERROR;
				msc_bot_send_csw(ctx);
			}
		}
		break;
	case MSC_BOT_SCSI_MEDIA_REMOVAL:
		if (msc_bot_medium_tracked(ctx)) {
			ctx->prevent_removal = (ctx->cbw.cb[4] & 0x01U) != 0U;
		}
		ctx->csw.status = MSC_BOT_CSW_STATUS_PASSED;
		msc_bot_send_csw(ctx);
		break;
	case MSC_BOT_SCSI_START_STOP_UNIT:
		if (!msc_bot_medium_tracked(ctx)) {
			ctx->csw.status = MSC_BOT_CSW_STATUS_PASSED;
			msc_bot_send_csw(ctx);
			break;
		}

		loej = (ctx->cbw.cb[4] & 0x02U) != 0U;
		start = (ctx->cbw.cb[4] & 0x01U) != 0U;

		if (loej && !start) {
			if (ctx->prevent_removal) {
				msc_bot_set_sense(ctx,
						  MSC_BOT_SCSI_SENSE_ILLEGAL_REQUEST,
						  MSC_BOT_SCSI_ASC_INVALID_COMMAND,
						  0x00);
				msc_bot_fail_command(ctx);
				break;
			}

			msc_bot_set_medium_state(ctx, false, false);
			msc_bot_set_sense(ctx, MSC_BOT_SCSI_SENSE_NOT_READY,
					  MSC_BOT_SCSI_ASC_MEDIA_NOT_PRESENT,
					  0x00);
			ctx->csw.status = MSC_BOT_CSW_STATUS_PASSED;
			msc_bot_send_csw(ctx);
			if (ctx->cfg->ops != NULL &&
			    ctx->cfg->ops->on_eject != NULL) {
				ctx->cfg->ops->on_eject(ctx,
							ctx->cfg->user_data);
			}
			break;
		}

		if (loej && start) {
			msc_bot_set_medium_state(ctx, true, true);
		}

		ctx->csw.status = MSC_BOT_CSW_STATUS_PASSED;
		msc_bot_send_csw(ctx);
		break;
	default:
		if (msc_bot_medium_tracked(ctx)) {
			msc_bot_set_sense(ctx,
					  MSC_BOT_SCSI_SENSE_ILLEGAL_REQUEST,
					  MSC_BOT_SCSI_ASC_INVALID_COMMAND,
					  0x00);
		}
		msc_bot_fail_command(ctx);
		break;
	}
}

void msc_bot_bulk_out(struct msc_bot_ctx *ctx, uint8_t ep)
{
	uint8_t *buf = msc_bot_packet_buf(ctx);
	uint32_t bytes_read = 0U;

	if (usb_ep_read_wait(ep, buf, ctx->cfg->packet_size, &bytes_read) != 0) {
		return;
	}

	switch (ctx->stage) {
	case MSC_BOT_STAGE_READ_CBW:
		msc_bot_decode_cbw(ctx, buf, bytes_read);
		break;
	case MSC_BOT_STAGE_PROCESS_CBW:
		switch (ctx->cbw.cb[0]) {
		case MSC_BOT_SCSI_WRITE10:
		case MSC_BOT_SCSI_WRITE12:
			msc_bot_memory_write(ctx, buf, bytes_read);
			break;
		case MSC_BOT_SCSI_VERIFY10:
			msc_bot_memory_verify(ctx, buf, bytes_read);
			break;
		default:
			ctx->stage = MSC_BOT_STAGE_ERROR;
			msc_bot_fail_command(ctx);
			break;
		}
		break;
	default:
		usb_ep_set_stall(ep);
		ctx->csw.status = MSC_BOT_CSW_STATUS_PHASE_ERROR;
		msc_bot_send_csw(ctx);
		break;
	}

	if (ctx->thread_op != MSC_BOT_THREAD_OP_WRITE_QUEUED) {
		usb_ep_read_continue(ep);
	}
}

void msc_bot_bulk_in(struct msc_bot_ctx *ctx)
{
	switch (ctx->stage) {
	case MSC_BOT_STAGE_PROCESS_CBW:
		switch (ctx->cbw.cb[0]) {
		case MSC_BOT_SCSI_READ10:
		case MSC_BOT_SCSI_READ12:
			msc_bot_memory_read(ctx);
			break;
		default:
			ctx->stage = MSC_BOT_STAGE_ERROR;
			msc_bot_fail_command(ctx);
			break;
		}
		break;
	case MSC_BOT_STAGE_SEND_CSW:
		msc_bot_send_csw(ctx);
		break;
	case MSC_BOT_STAGE_WAIT_CSW:
		ctx->stage = MSC_BOT_STAGE_READ_CBW;
		break;
	default:
		usb_ep_set_stall(ctx->cfg->in_ep_addr);
		msc_bot_send_csw(ctx);
		break;
	}
}

void msc_bot_usb_status(struct msc_bot_ctx *ctx,
			enum usb_dc_status_code status)
{
	switch (status) {
	case USB_DC_RESET:
		msc_bot_reset_protocol(ctx);
		break;
	case USB_DC_DISCONNECTED:
		if (ctx->cfg->reset_on_disconnect) {
			msc_bot_reset_protocol(ctx);
		}
		break;
	default:
		break;
	}
}

int msc_bot_class_handle_req(struct msc_bot_ctx *ctx, uint8_t interface_number,
			     struct usb_setup_packet *setup, int32_t *len,
			     uint8_t **data)
{
	static uint8_t max_lun_count;

	ARG_UNUSED(ctx);

	if ((setup->wIndex & 0xFFU) != interface_number || setup->wValue != 0U) {
		return -EINVAL;
	}

	if (usb_reqtype_is_to_device(setup)) {
		if (setup->bRequest == MSC_BOT_REQUEST_RESET &&
		    setup->wLength == 0U) {
			msc_bot_reset_protocol(ctx);
			return 0;
		}
	} else {
		if (setup->bRequest == MSC_BOT_REQUEST_GET_MAX_LUN &&
		    setup->wLength == 1U) {
			max_lun_count = 0U;
			*data = &max_lun_count;
			*len = 1;
			return 0;
		}
	}

	return -ENOTSUP;
}

void msc_bot_thread_main(void *arg1, void *arg2, void *arg3)
{
	struct msc_bot_ctx *ctx = arg1;

	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	while (true) {
		k_sem_take(&ctx->disk_wait_sem, K_FOREVER);

		switch (ctx->thread_op) {
		case MSC_BOT_THREAD_OP_READ_QUEUED:
			if (disk_access_read(ctx->cfg->disk_name, ctx->page,
					     ctx->curr_lba, 1) != 0) {
				LOG_ERR("MSC disk read failed");
			}
			msc_bot_thread_memory_read_done(ctx);
			break;
		case MSC_BOT_THREAD_OP_WRITE_QUEUED:
			if (disk_access_write(ctx->cfg->disk_name, ctx->page,
					      ctx->curr_lba, 1) != 0) {
				LOG_ERR("MSC disk write failed");
			}
			msc_bot_thread_memory_write_done(ctx);
			break;
		default:
			break;
		}
	}
}

int msc_bot_init(struct msc_bot_ctx *ctx, const struct msc_bot_cfg *cfg,
		 uint8_t *page, size_t page_len)
{
	uint32_t block_size = 0U;
	int rc;

	if (ctx == NULL || cfg == NULL || page == NULL ||
	    page_len < (size_t)cfg->block_size + cfg->packet_size) {
		return -EINVAL;
	}

	ctx->cfg = cfg;
	ctx->page = page;
	ctx->page_len = page_len;

	rc = disk_access_init(cfg->disk_name);
	if (rc != 0) {
		return rc;
	}

	rc = disk_access_ioctl(cfg->disk_name, DISK_IOCTL_GET_SECTOR_COUNT,
			       &ctx->block_count);
	if (rc != 0) {
		return rc;
	}

	rc = disk_access_ioctl(cfg->disk_name, DISK_IOCTL_GET_SECTOR_SIZE,
			       &block_size);
	if (rc != 0) {
		return rc;
	}

	if (block_size != cfg->block_size) {
		return -EINVAL;
	}

	k_sem_init(&ctx->disk_wait_sem, 0, 1);

	if (cfg->medium_policy == MSC_BOT_MEDIUM_POLICY_ALWAYS_READY) {
		msc_bot_set_medium_state(ctx, true, true);
	} else {
		msc_bot_set_medium_state(ctx, false, false);
	}

	msc_bot_reset_protocol(ctx);
	return 0;
}

int msc_bot_start_thread(struct msc_bot_ctx *ctx, k_thread_stack_t *stack,
			 size_t stack_size, int prio, const char *name)
{
	if (ctx->thread_started) {
		return 0;
	}

	k_thread_create(&ctx->thread, stack, stack_size, msc_bot_thread_main,
			ctx, NULL, NULL, prio, 0, K_NO_WAIT);
	ctx->thread_started = true;

	if (name != NULL) {
		k_thread_name_set(&ctx->thread, name);
	}

	return 0;
}
