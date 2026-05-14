/*
 * Copyright (c) 2026 Siratul Islam <email@sirat.me>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#include <zephyr/authentication/fido2/fido2_types.h>
#include <zephyr/authentication/fido2/fido2_storage.h>
#include <psa/crypto.h>

LOG_MODULE_DECLARE(fido2, CONFIG_FIDO2_LOG_LEVEL);

static int destroy_credential_key(uint32_t key_id)
{
	psa_status_t status;

	status = psa_destroy_key(key_id);
	if (status == PSA_SUCCESS || status == PSA_ERROR_DOES_NOT_EXIST ||
	    status == PSA_ERROR_INVALID_HANDLE) {
		return 0;
	}

	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to destroy credential key 0x%08x: %d", (unsigned int)key_id,
			status);
	}

	return status;
}

static int destroy_stored_credential_key(const struct fido2_credential *cred, void *user_data)
{
	ARG_UNUSED(user_data);

	(void)destroy_credential_key(cred->key_id);

	return 0;
}

int fido2_storage_init(void)
{
	return fido2_storage_backend.init();
}

int fido2_storage_store(const struct fido2_credential *cred)
{
	return fido2_storage_backend.store(cred);
}

int fido2_storage_load(const uint8_t *cred_id, size_t cred_id_len, struct fido2_credential *cred)
{
	return fido2_storage_backend.load(cred_id, cred_id_len, cred);
}

int fido2_storage_remove(const uint8_t *cred_id, size_t cred_id_len)
{
	struct fido2_credential cred;
	int ret;

	ret = fido2_storage_backend.remove(cred_id, cred_id_len, &cred);
	if (ret) {
		return ret;
	}

	ret = destroy_credential_key(cred.key_id);

	return ret;
}

int fido2_storage_find_by_rp(const uint8_t rp_id_hash[FIDO2_SHA256_SIZE],
			     struct fido2_credential *creds, size_t max_creds, size_t *count)
{
	return fido2_storage_backend.find_by_rp(rp_id_hash, creds, max_creds, count);
}

int fido2_storage_enumerate_rps(size_t offset, struct fido2_credential *creds, size_t max_creds,
				size_t *count)
{
	return fido2_storage_backend.enumerate_rps(offset, creds, max_creds, count);
}

int fido2_storage_iterate(fido2_storage_iterate_cb_t cb, void *user_data)
{
	return fido2_storage_backend.iterate(cb, user_data);
}

int fido2_storage_sign_count_increment(const uint8_t *cred_id, size_t cred_id_len,
				       uint32_t *new_count)
{
	return fido2_storage_backend.sign_count_increment(cred_id, cred_id_len, new_count);
}

int fido2_storage_update_user_info(const uint8_t *cred_id, size_t cred_id_len,
				   const char *user_name, const char *user_display_name)
{
	return fido2_storage_backend.update_user_info(cred_id, cred_id_len, user_name,
						     user_display_name);
}

int fido2_storage_credential_count(size_t *count)
{
	return fido2_storage_backend.credential_count(count);
}

int fido2_storage_wipe_all(void)
{
	(void)fido2_storage_iterate(destroy_stored_credential_key, NULL);

	return fido2_storage_backend.wipe_all();
}

int fido2_storage_pin_set(const uint8_t pin_hash[FIDO2_PIN_HASH_SIZE])
{
	return fido2_storage_backend.pin_set(pin_hash);
}

int fido2_storage_pin_get(uint8_t pin_hash[FIDO2_PIN_HASH_SIZE])
{
	return fido2_storage_backend.pin_get(pin_hash);
}

int fido2_storage_pin_retries_get(uint8_t *retries)
{
	return fido2_storage_backend.pin_retries_get(retries);
}

int fido2_storage_pin_retries_decrement(void)
{
	return fido2_storage_backend.pin_retries_decrement();
}

int fido2_storage_pin_retries_reset(void)
{
	return fido2_storage_backend.pin_retries_reset();
}
