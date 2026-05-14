/*
 * Copyright (c) 2026 Siratul Islam <email@sirat.me>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/authentication/fido2/fido2_types.h>
#include <zephyr/authentication/fido2/fido2_storage.h>
#include <errno.h>
#include <string.h>

LOG_MODULE_DECLARE(fido2, CONFIG_FIDO2_LOG_LEVEL);

#define FIDO2_SETTINGS_BASE        "fido2"
#define FIDO2_SETTINGS_CRED_PREFIX FIDO2_SETTINGS_BASE "/cred"
#define FIDO2_SETTINGS_PIN_HASH    FIDO2_SETTINGS_BASE "/pin_hash"
#define FIDO2_SETTINGS_PIN_RETRIES FIDO2_SETTINGS_BASE "/pin_retries"
#define FIDO2_SETTINGS_KEY_MAX     20

#ifndef CONFIG_FIDO2_PIN_MAX_RETRIES
#define CONFIG_FIDO2_PIN_MAX_RETRIES 8
#endif

static void build_key(char *buf, size_t size, int idx)
{
	snprintk(buf, size, FIDO2_SETTINGS_CRED_PREFIX "/%d", idx);
}

static int cred_slot_get(const uint8_t *cred_id, size_t cred_id_len, struct fido2_credential *out)
{
	struct fido2_credential cred;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		char key[FIDO2_SETTINGS_KEY_MAX];

		build_key(key, sizeof(key), i);
		if (settings_load_one(key, &cred, sizeof(cred)) != sizeof(cred)) {
			continue;
		}
		if (cred.id_len == cred_id_len && memcmp(cred.id, cred_id, cred_id_len) == 0) {
			if (out != NULL) {
				memcpy(out, &cred, sizeof(cred));
			}
			return i;
		}
	}

	return -ENOENT;
}

static int settings_backend_init(void)
{
	int ret;

	ret = settings_subsys_init();
	if (ret) {
		LOG_ERR("Settings init failed: %d", ret);
		return ret;
	}

	LOG_INF("Credential storage: settings");
	return 0;
}

static int settings_backend_store(const struct fido2_credential *cred)
{
	struct fido2_credential temp;
	int idx;

	idx = cred_slot_get(cred->id, cred->id_len, NULL);
	if (idx >= 0) {
		char key[FIDO2_SETTINGS_KEY_MAX];

		build_key(key, sizeof(key), idx);
		return settings_save_one(key, cred, sizeof(*cred));
	}

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		char key[FIDO2_SETTINGS_KEY_MAX];

		build_key(key, sizeof(key), i);
		if (settings_load_one(key, &temp, sizeof(temp)) == sizeof(temp)) {
			continue; /* slot occupied */
		}

		return settings_save_one(key, cred, sizeof(*cred));
	}

	return -ENOSPC;
}

static int settings_backend_load(const uint8_t *cred_id, size_t cred_id_len,
				 struct fido2_credential *cred)
{
	int idx;

	idx = cred_slot_get(cred_id, cred_id_len, cred);
	if (idx < 0) {
		return idx;
	}

	return 0;
}

static int settings_backend_remove(const uint8_t *cred_id, size_t cred_id_len,
				   struct fido2_credential *cred)
{
	int idx;
	char key[FIDO2_SETTINGS_KEY_MAX];

	idx = cred_slot_get(cred_id, cred_id_len, cred);
	if (idx < 0) {
		return idx;
	}

	build_key(key, sizeof(key), idx);

	return settings_delete(key);
}

static int settings_backend_find_by_rp(const uint8_t rp_id_hash[FIDO2_SHA256_SIZE],
				       struct fido2_credential *creds, size_t max_creds,
				       size_t *count)
{
	struct fido2_credential cred;

	*count = 0;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		char key[FIDO2_SETTINGS_KEY_MAX];

		build_key(key, sizeof(key), i);
		if (settings_load_one(key, &cred, sizeof(cred)) != sizeof(cred)) {
			continue;
		}
		if (memcmp(cred.rp_id_hash, rp_id_hash, FIDO2_SHA256_SIZE) == 0) {
			if (*count < max_creds) {
				memcpy(creds + *count, &cred, sizeof(cred));
			}
			(*count)++;
		}
	}

	return 0;
}

static int settings_backend_enumerate_rps(size_t offset, struct fido2_credential *creds,
					  size_t max_creds, size_t *count)
{
	struct fido2_credential cred;
	size_t unique = 0;

	*count = 0;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		char key[FIDO2_SETTINGS_KEY_MAX];
		bool seen = false;

		build_key(key, sizeof(key), i);
		if (settings_load_one(key, &cred, sizeof(cred)) != sizeof(cred)) {
			continue;
		}

		for (int j = 0; j < i; ++j) {
			struct fido2_credential prev;
			char prev_key[FIDO2_SETTINGS_KEY_MAX];

			build_key(prev_key, sizeof(prev_key), j);
			if (settings_load_one(prev_key, &prev, sizeof(prev)) != sizeof(prev)) {
				continue;
			}

			if (memcmp(prev.rp_id_hash, cred.rp_id_hash, FIDO2_SHA256_SIZE) == 0) {
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
			memcpy(creds + *count, &cred, sizeof(cred));
		}
		(*count)++;
	}

	return 0;
}

static int settings_backend_iterate(fido2_storage_iterate_cb_t cb, void *user_data)
{
	struct fido2_credential cred;
	int ret;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		char key[FIDO2_SETTINGS_KEY_MAX];

		build_key(key, sizeof(key), i);
		if (settings_load_one(key, &cred, sizeof(cred)) != sizeof(cred)) {
			continue;
		}

		ret = cb(&cred, user_data);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

static int settings_backend_sign_count_increment(const uint8_t *cred_id, size_t cred_id_len,
						 uint32_t *new_count)
{
	struct fido2_credential cred;
	char key[FIDO2_SETTINGS_KEY_MAX];
	int idx;

	idx = cred_slot_get(cred_id, cred_id_len, &cred);
	if (idx < 0) {
		return idx;
	}

	cred.sign_count++;
	*new_count = cred.sign_count;
	build_key(key, sizeof(key), idx);

	return settings_save_one(key, &cred, sizeof(cred));
}

static int settings_backend_update_user_info(const uint8_t *cred_id, size_t cred_id_len,
					     const char *user_name,
					     const char *user_display_name)
{
	struct fido2_credential cred;
	char key[FIDO2_SETTINGS_KEY_MAX];
	int idx;

	idx = cred_slot_get(cred_id, cred_id_len, &cred);
	if (idx < 0) {
		return idx;
	}

	if (user_name != NULL) {
		strncpy(cred.user_name, user_name, sizeof(cred.user_name) - 1);
		cred.user_name[sizeof(cred.user_name) - 1] = '\0';
	}

	if (user_display_name != NULL) {
		strncpy(cred.user_display_name, user_display_name,
			sizeof(cred.user_display_name) - 1);
		cred.user_display_name[sizeof(cred.user_display_name) - 1] = '\0';
	}

	build_key(key, sizeof(key), idx);

	return settings_save_one(key, &cred, sizeof(cred));
}

static int settings_backend_credential_count(size_t *count)
{
	struct fido2_credential cred;

	*count = 0;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		char key[FIDO2_SETTINGS_KEY_MAX];

		build_key(key, sizeof(key), i);
		if (settings_load_one(key, &cred, sizeof(cred)) == sizeof(cred)) {
			(*count)++;
		}
	}

	return 0;
}

static int settings_backend_wipe_all(void)
{
	int ret;

	for (int i = 0; i < CONFIG_FIDO2_MAX_CREDENTIALS; ++i) {
		char key[FIDO2_SETTINGS_KEY_MAX];

		build_key(key, sizeof(key), i);
		ret = settings_delete(key);
		if (ret && ret != -ENOENT) {
			return ret;
		}
	}

	ret = settings_delete(FIDO2_SETTINGS_PIN_HASH);
	if (ret && ret != -ENOENT) {
		return ret;
	}

	ret = settings_delete(FIDO2_SETTINGS_PIN_RETRIES);
	if (ret && ret != -ENOENT) {
		return ret;
	}

	return 0;
}

static int settings_backend_pin_set(const uint8_t pin_hash[FIDO2_PIN_HASH_SIZE])
{
	uint8_t retries = CONFIG_FIDO2_PIN_MAX_RETRIES;
	int ret;

	ret = settings_save_one(FIDO2_SETTINGS_PIN_HASH, pin_hash, FIDO2_PIN_HASH_SIZE);
	if (ret) {
		return ret;
	}

	return settings_save_one(FIDO2_SETTINGS_PIN_RETRIES, &retries, sizeof(retries));
}

static int settings_backend_pin_get(uint8_t pin_hash[FIDO2_PIN_HASH_SIZE])
{
	int ret;

	ret = settings_load_one(FIDO2_SETTINGS_PIN_HASH, pin_hash, FIDO2_PIN_HASH_SIZE);
	if (ret == FIDO2_PIN_HASH_SIZE) {
		return 0;
	}

	return ret < 0 ? ret : -ENOENT;
}

static int settings_backend_pin_retries_get(uint8_t *retries)
{
	int ret;

	ret = settings_load_one(FIDO2_SETTINGS_PIN_RETRIES, retries, sizeof(*retries));
	if (ret == sizeof(*retries)) {
		return 0;
	}

	*retries = CONFIG_FIDO2_PIN_MAX_RETRIES;

	return ret < 0 && ret != -ENOENT ? ret : 0;
}

static int settings_backend_pin_retries_decrement(void)
{
	uint8_t retries;
	int ret;

	ret = settings_backend_pin_retries_get(&retries);
	if (ret) {
		return ret;
	}

	if (retries > 0) {
		retries--;
	}

	return settings_save_one(FIDO2_SETTINGS_PIN_RETRIES, &retries, sizeof(retries));
}

static int settings_backend_pin_retries_reset(void)
{
	uint8_t retries = CONFIG_FIDO2_PIN_MAX_RETRIES;

	return settings_save_one(FIDO2_SETTINGS_PIN_RETRIES, &retries, sizeof(retries));
}

static const struct fido2_storage_api settings_api = {.init = settings_backend_init,
						      .store = settings_backend_store,
						      .load = settings_backend_load,
						      .remove = settings_backend_remove,
						      .find_by_rp = settings_backend_find_by_rp,
						      .enumerate_rps = settings_backend_enumerate_rps,
						      .iterate = settings_backend_iterate,
						      .sign_count_increment =
							      settings_backend_sign_count_increment,
						      .update_user_info =
							      settings_backend_update_user_info,
						      .credential_count =
							      settings_backend_credential_count,
						      .wipe_all = settings_backend_wipe_all,
						      .pin_set = settings_backend_pin_set,
						      .pin_get = settings_backend_pin_get,
						      .pin_retries_get =
							      settings_backend_pin_retries_get,
						      .pin_retries_decrement =
							      settings_backend_pin_retries_decrement,
						      .pin_retries_reset =
							      settings_backend_pin_retries_reset};

const struct fido2_storage_api fido2_storage_backend = settings_api;
