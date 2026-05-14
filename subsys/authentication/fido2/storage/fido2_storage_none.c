/*
 * Copyright (c) 2026 Siratul Islam <email@sirat.me>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>
#include <zephyr/authentication/fido2/fido2_storage.h>

static struct fido2_credential credentials[CONFIG_FIDO2_MAX_CREDENTIALS];
static bool credential_used[CONFIG_FIDO2_MAX_CREDENTIALS];

static int cred_slot_get(const uint8_t *cred_id, size_t cred_id_len)
{
	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		if (!credential_used[i]) {
			continue;
		}

		if (credentials[i].id_len == cred_id_len &&
		    memcmp(credentials[i].id, cred_id, cred_id_len) == 0) {
			return i;
		}
	}

	return -ENOENT;
}

static int none_backend_init(void)
{
	return 0;
}

static int none_backend_store(const struct fido2_credential *cred)
{
	int idx;

	idx = cred_slot_get(cred->id, cred->id_len);
	if (idx >= 0) {
		memcpy(&credentials[idx], cred, sizeof(*cred));
		return 0;
	}

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		if (credential_used[i]) {
			continue;
		}

		memcpy(&credentials[i], cred, sizeof(*cred));
		credential_used[i] = true;
		return 0;
	}

	return -ENOSPC;
}

static int none_backend_load(const uint8_t *cred_id, size_t cred_id_len,
			     struct fido2_credential *cred)
{
	int idx;

	idx = cred_slot_get(cred_id, cred_id_len);
	if (idx < 0) {
		return idx;
	}

	memcpy(cred, &credentials[idx], sizeof(*cred));

	return 0;
}

static int none_backend_remove(const uint8_t *cred_id, size_t cred_id_len,
			       struct fido2_credential *cred)
{
	int idx;

	idx = cred_slot_get(cred_id, cred_id_len);
	if (idx < 0) {
		return idx;
	}

	if (cred != NULL) {
		memcpy(cred, &credentials[idx], sizeof(*cred));
	}

	memset(&credentials[idx], 0, sizeof(credentials[idx]));
	credential_used[idx] = false;

	return 0;
}

static int none_backend_find_by_rp(const uint8_t rp_id_hash[FIDO2_SHA256_SIZE],
				   struct fido2_credential *creds, size_t max_creds,
				   size_t *count)
{
	*count = 0;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		if (!credential_used[i]) {
			continue;
		}

		if (memcmp(credentials[i].rp_id_hash, rp_id_hash, FIDO2_SHA256_SIZE) != 0) {
			continue;
		}

		if (*count < max_creds) {
			memcpy(creds + *count, &credentials[i], sizeof(*creds));
		}
		(*count)++;
	}

	return 0;
}

static int none_backend_enumerate_rps(size_t offset, struct fido2_credential *creds,
				      size_t max_creds, size_t *count)
{
	size_t unique = 0;

	*count = 0;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		bool seen = false;

		if (!credential_used[i]) {
			continue;
		}

		for (int j = 0; j < i; ++j) {
			if (!credential_used[j]) {
				continue;
			}

			if (memcmp(credentials[j].rp_id_hash, credentials[i].rp_id_hash,
				   FIDO2_SHA256_SIZE) == 0) {
				seen = true;
				break;
			}
		}

		if (seen) {
			continue;
		}

		if (unique++ < offset) {
			continue;
		}

		if (*count < max_creds) {
			memcpy(creds + *count, &credentials[i], sizeof(*creds));
		}
		(*count)++;
	}

	return 0;
}

static int none_backend_iterate(fido2_storage_iterate_cb_t cb, void *user_data)
{
	int ret;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		if (!credential_used[i]) {
			continue;
		}

		ret = cb(&credentials[i], user_data);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

static int none_backend_sign_count_increment(const uint8_t *cred_id, size_t cred_id_len,
					     uint32_t *new_count)
{
	int idx;

	idx = cred_slot_get(cred_id, cred_id_len);
	if (idx < 0) {
		return idx;
	}

	credentials[idx].sign_count++;
	*new_count = credentials[idx].sign_count;

	return 0;
}

static int none_backend_update_user_info(const uint8_t *cred_id, size_t cred_id_len,
					 const char *user_name, const char *user_display_name)
{
	int idx;

	idx = cred_slot_get(cred_id, cred_id_len);
	if (idx < 0) {
		return idx;
	}

	if (user_name != NULL) {
		strncpy(credentials[idx].user_name, user_name,
			sizeof(credentials[idx].user_name) - 1);
		credentials[idx].user_name[sizeof(credentials[idx].user_name) - 1] = '\0';
	}

	if (user_display_name != NULL) {
		strncpy(credentials[idx].user_display_name, user_display_name,
			sizeof(credentials[idx].user_display_name) - 1);
		credentials[idx].user_display_name[sizeof(credentials[idx].user_display_name) - 1] =
			'\0';
	}

	return 0;
}

static int none_backend_credential_count(size_t *count)
{
	*count = 0;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		if (credential_used[i]) {
			(*count)++;
		}
	}

	return 0;
}

static int none_backend_wipe_all(void)
{
	memset(credentials, 0, sizeof(credentials));
	memset(credential_used, 0, sizeof(credential_used));

	return 0;
}

static int none_backend_pin_set(const uint8_t pin_hash[FIDO2_PIN_HASH_SIZE])
{
	ARG_UNUSED(pin_hash);

	return -ENOTSUP;
}

static int none_backend_pin_get(uint8_t pin_hash[FIDO2_PIN_HASH_SIZE])
{
	ARG_UNUSED(pin_hash);

	return -ENOENT;
}

static int none_backend_pin_retries_get(uint8_t *retries)
{
	*retries = 0;

	return 0;
}

static int none_backend_pin_retries_decrement(void)
{
	return -ENOTSUP;
}

static int none_backend_pin_retries_reset(void)
{
	return 0;
}

const struct fido2_storage_api fido2_storage_backend = {
	.init = none_backend_init,
	.store = none_backend_store,
	.load = none_backend_load,
	.remove = none_backend_remove,
	.find_by_rp = none_backend_find_by_rp,
	.enumerate_rps = none_backend_enumerate_rps,
	.iterate = none_backend_iterate,
	.sign_count_increment = none_backend_sign_count_increment,
	.update_user_info = none_backend_update_user_info,
	.credential_count = none_backend_credential_count,
	.wipe_all = none_backend_wipe_all,
	.pin_set = none_backend_pin_set,
	.pin_get = none_backend_pin_get,
	.pin_retries_get = none_backend_pin_retries_get,
	.pin_retries_decrement = none_backend_pin_retries_decrement,
	.pin_retries_reset = none_backend_pin_retries_reset,
};
