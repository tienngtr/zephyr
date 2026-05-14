/*
 * Copyright (c) 2026 Siratul Islam <email@sirat.me>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#include <zephyr/authentication/fido2/fido2.h>
#include <zephyr/authentication/fido2/fido2_types.h>
#include <zephyr/authentication/fido2/fido2_storage.h>
#include <zephyr/authentication/fido2/fido2_transport.h>
#include <zephyr/authentication/fido2/fido2_attestation.h>

#include "fido2_cbor.h"
#include "fido2_crypto.h"

LOG_MODULE_REGISTER(fido2, CONFIG_FIDO2_LOG_LEVEL);

struct fido2_msg {
	const struct fido2_transport *transport;
	uint32_t cid;
	size_t len;
	uint8_t data[CONFIG_FIDO2_CBOR_MAX_SIZE + 1];
};

/*
 * The transport callback may run on the system workqueue where stack can
 * be tight. Keep the queue item out.
 */
static struct k_spinlock rx_enqueue_lock;
static struct fido2_msg rx_enqueue_msg;
/* Reused to minimize thread stack usage. */
static struct fido2_msg rx_dequeue_msg;

K_MSGQ_DEFINE(fido2_msgq, sizeof(struct fido2_msg), 2, 4);

static K_THREAD_STACK_DEFINE(fido2_stack, CONFIG_FIDO2_THREAD_STACK_SIZE);
static struct k_thread fido2_thread;

/* Kept these out to keep thread stack light */
static struct fido2_make_credential_params mc_params;
static struct fido2_get_assertion_params ga_params;
static struct fido2_credential mc_credential;
static struct fido2_credential ga_credentials[CONFIG_FIDO2_MAX_CREDENTIALS];
static struct {
	bool active;
	size_t next_index;
	size_t count;
	uint8_t client_data_hash[FIDO2_SHA256_SIZE];
	uint8_t flags;
} ga_next;

static uint8_t ctap_tx_frame[CONFIG_FIDO2_CBOR_MAX_SIZE];

static atomic_t fido2_running;

static int64_t reset_deadline;

static int mc_populate_credential(void)
{
	int ret;

	ret = fido2_crypto_sha256((const uint8_t *)mc_params.rp_id, strlen(mc_params.rp_id),
				  mc_credential.rp_id_hash);
	if (ret) {
		LOG_ERR("RP ID hash failed: %d", ret);
		return ret;
	}

	strncpy(mc_credential.rp_id, mc_params.rp_id, sizeof(mc_credential.rp_id) - 2);
	strncpy(mc_credential.rp_name, mc_params.rp_name, sizeof(mc_credential.rp_name) - 2);
	memcpy(mc_credential.user_id, mc_params.user_id, mc_params.user_id_len);
	mc_credential.user_id_len = mc_params.user_id_len;
	strncpy(mc_credential.user_name, mc_params.user_name, sizeof(mc_credential.user_name) - 1);
	strncpy(mc_credential.user_display_name, mc_params.user_display_name,
		sizeof(mc_credential.user_display_name) - 1);
	mc_credential.sign_count = 0;
	mc_credential.algorithm = FIDO2_COSE_ES256;
	mc_credential.discoverable = mc_params.resident_key;

#if defined(CONFIG_FIDO2_EXT_CRED_PROTECT)
	mc_credential.cred_protect = mc_params.ext_cred_protect_level;
#endif
#if defined(CONFIG_FIDO2_EXT_HMAC_SECRET)
	if (mc_params.ext_hmac_secret) {
		mc_credential.extensions |= FIDO2_EXT_HMAC_SECRET;
	}
#endif

	mc_credential.id_len = FIDO2_DISCOVERABLE_CRED_ID_SIZE;
	ret = sys_csrand_get(mc_credential.id, mc_credential.id_len);
	if (ret) {
		LOG_ERR("Credential ID csrand failed: %d", ret);
		return ret;
	}

	return 0;
}

static int mc_store_credential(void)
{
	size_t creds_found;
	int ret;

	if (mc_credential.discoverable &&
	    fido2_storage_find_by_rp(mc_credential.rp_id_hash, ga_credentials,
				     CONFIG_FIDO2_MAX_CREDENTIALS, &creds_found) == 0) {
		for (int i = 0; i < creds_found; ++i) {
			if (mc_credential.user_id_len == ga_credentials[i].user_id_len &&
			    memcmp(mc_credential.user_id, ga_credentials[i].user_id,
				   mc_credential.user_id_len) == 0) {
				fido2_storage_remove(ga_credentials[i].id,
						     ga_credentials[i].id_len);
				break;
			}
		}
	}

	ret = fido2_storage_store(&mc_credential);

	if (ret) {
		LOG_ERR("Credential store failed: %d", ret);
		return ret;
	}

	return 0;
}

static int ga_build_auth_data(const uint8_t rp_id_hash[FIDO2_SHA256_SIZE], uint32_t sign_count,
			      uint8_t flags, uint8_t *auth_data, size_t auth_data_size,
			      size_t *auth_data_len)
{
	size_t offset = 0;

	if (auth_data_size < FIDO2_AUTH_DATA_HEADER_SIZE) {
		return -ENOMEM;
	}

	memcpy(auth_data + offset, rp_id_hash, FIDO2_SHA256_SIZE);
	offset += FIDO2_SHA256_SIZE;

	auth_data[offset] = flags;
	offset += sizeof(uint8_t);

	sys_put_be32(sign_count, auth_data + offset);
	offset += sizeof(uint32_t);

	*auth_data_len = offset;

	return 0;
}

static enum fido2_status ga_encode_credential_assertion(const struct fido2_credential *credential,
							const uint8_t client_data_hash[FIDO2_SHA256_SIZE],
							uint8_t flags, bool include_user,
							size_t num_credentials,
							uint8_t *cbor_out, size_t cbor_out_cap,
							size_t *cbor_out_len)
{
	uint8_t auth_data[FIDO2_AUTH_DATA_HEADER_SIZE];
	uint8_t signed_hash[FIDO2_SHA256_SIZE];
	uint8_t sig[80];
	size_t auth_data_len;
	size_t sig_len;
	uint32_t sign_count;
	int ret;

	ret = fido2_storage_sign_count_increment(credential->id, credential->id_len, &sign_count);
	if (ret) {
		return FIDO2_ERR_OTHER;
	}

	ret = ga_build_auth_data(credential->rp_id_hash, sign_count, flags, auth_data,
				 sizeof(auth_data), &auth_data_len);
	if (ret) {
		return FIDO2_ERR_OTHER;
	}

	ret = fido2_crypto_hash_authdata(auth_data, auth_data_len, client_data_hash, signed_hash);
	if (ret) {
		return FIDO2_ERR_OTHER;
	}

	ret = fido2_crypto_sign(credential->key_id, signed_hash, sig, sizeof(sig), &sig_len);
	if (ret) {
		return FIDO2_ERR_OTHER;
	}

	ret = fido2_cbor_encode_get_assertion_resp(credential, auth_data, auth_data_len, sig,
						   sig_len, include_user, num_credentials,
						   cbor_out, cbor_out_cap, cbor_out_len);
	if (ret) {
		return FIDO2_ERR_OTHER;
	}

	return FIDO2_OK;
}

static size_t ga_filter_discoverable_credentials(size_t count)
{
	size_t out = 0;

	for (size_t i = 0; i < count && i < ARRAY_SIZE(ga_credentials); ++i) {
		if (!ga_credentials[i].discoverable) {
			continue;
		}

		if (out != i) {
			memcpy(&ga_credentials[out], &ga_credentials[i], sizeof(ga_credentials[out]));
		}
		out++;
	}

	return out;
}

static int mc_build_auth_data(const uint8_t rp_id_hash[FIDO2_SHA256_SIZE], const uint8_t *cred_id,
			      size_t cred_id_len, const uint8_t *pub_key, size_t pub_key_len,
			      uint32_t sign_count, uint8_t flags, uint8_t *auth_data,
			      size_t auth_data_size, size_t *auth_data_len)
{
	uint8_t cose_key[FIDO2_COSE_KEY_MAX_SIZE];
	size_t cose_key_len;
	size_t total;
	size_t offset = 0;
	size_t written;
	int ret;

	ret = fido2_cbor_encode_cose_key(pub_key, pub_key_len, cose_key, sizeof(cose_key),
					 &cose_key_len);
	if (ret) {
		return ret;
	}

	total = FIDO2_AUTH_DATA_HEADER_SIZE + FIDO2_AAGUID_SIZE + 2 + cred_id_len + cose_key_len;

	if (total > auth_data_size) {
		return -ENOMEM;
	}

	memcpy(auth_data + offset, rp_id_hash, FIDO2_SHA256_SIZE);
	offset += FIDO2_SHA256_SIZE;

	auth_data[offset] = flags;
	offset += sizeof(uint8_t);

	sys_put_be32(sign_count, auth_data + offset);
	offset += sizeof(uint32_t);

	written = hex2bin(CONFIG_FIDO2_AAGUID, strlen(CONFIG_FIDO2_AAGUID), auth_data + offset,
			  FIDO2_AAGUID_SIZE);
	if (written != FIDO2_AAGUID_SIZE) {
		LOG_ERR("AAGUID parse failed, check CONFIG_FIDO2_AAGUID");
		return -EINVAL;
	}
	offset += FIDO2_AAGUID_SIZE;

	sys_put_be16(cred_id_len, auth_data + offset);
	offset += sizeof(uint16_t);

	memcpy(auth_data + offset, cred_id, cred_id_len);
	offset += cred_id_len;

	memcpy(auth_data + offset, cose_key, cose_key_len);
	offset += cose_key_len;

	*auth_data_len = offset;

	return 0;
}

static enum fido2_status
handle_make_credential(uint8_t *cbor_in, size_t cbor_in_len, uint8_t *cbor_out, size_t cbor_out_cap,
		       size_t *cbor_out_len, const struct fido2_transport *transport, uint32_t cid)
{
	bool supported_alg = false;
	uint8_t pub_key[FIDO2_P256_UNCOMPRESSED_KEY_SIZE];
	size_t pub_key_len;
	uint8_t auth_data[FIDO2_AUTH_DATA_MAX_SIZE];
	size_t auth_data_len;
	bool user_verified = false;
	uint8_t flags;
	struct fido2_attestation_result att_result;
	int ret;

	memset(&mc_credential, 0, sizeof(mc_credential));

	ret = fido2_cbor_decode_make_credential(cbor_in, cbor_in_len, &mc_params);
	if (ret) {
		LOG_WRN("MakeCredential CBOR decode failed: %d (len=%zu)", ret, cbor_in_len);
		return FIDO2_ERR_INVALID_CBOR;
	}

	/* UP must not be false. */
	if (mc_params.has_up_option && !mc_params.up) {
		LOG_WRN("Rejected MakeCredential: options.up cannot be false");
		return FIDO2_ERR_INVALID_OPTION;
	}

	/* pinUvAuthParam and uv are mutually exclusive, pinUvAuthParam takes precedence. */
	if (mc_params.has_pin_uv_auth_param) {
		mc_params.uv = false;
	}

	/* "Gracefully" reject unsupprted feature */
	if (mc_params.has_enterprise_attestation) {
		LOG_WRN("Rejected MakeCredential: enterprise attestation not supported");
		return FIDO2_ERR_INVALID_PARAMETER;
	}

	/* Only ES256 (COSE algorithm -7) is supported */
	for (int i = 0; i < mc_params.num_algorithms; ++i) {
		if (mc_params.algorithms[i] == FIDO2_COSE_ES256) {
			supported_alg = true;
			break;
		}
	}
	if (!supported_alg) {
		LOG_WRN("No supported algorithm in pubKeyCredParams");
		return FIDO2_ERR_UNSUPPORTED_ALGORITHM;
	}

	ret = fido2_crypto_generate_keypair(&mc_credential.key_id);
	if (ret) {
		LOG_ERR("Keypair generation failed: %d", ret);
		return FIDO2_ERR_OTHER;
	}

	ret = fido2_crypto_export_pubkey(mc_credential.key_id, pub_key, sizeof(pub_key),
					 &pub_key_len);
	if (ret) {
		LOG_ERR("Public key export failed: %d", ret);
		fido2_crypto_destroy_key(mc_credential.key_id);
		return FIDO2_ERR_OTHER;
	}

	if (pub_key_len != FIDO2_P256_UNCOMPRESSED_KEY_SIZE ||
	    pub_key[0] != FIDO2_EC_POINT_UNCOMPRESSED) {
		LOG_ERR("Unsupported public key format len=%zu first=0x%02x", pub_key_len,
			pub_key_len > 0 ? pub_key[0] : 0);
		fido2_crypto_destroy_key(mc_credential.key_id);
		return FIDO2_ERR_OTHER;
	}

	ret = mc_populate_credential();
	if (ret) {
		fido2_crypto_destroy_key(mc_credential.key_id);
		return FIDO2_ERR_OTHER;
	}

	flags = AUTH_DATA_FLAG_AT | AUTH_DATA_FLAG_UP;

	if (user_verified) {
		flags |= AUTH_DATA_FLAG_UV;
	}

	ret = mc_build_auth_data(mc_credential.rp_id_hash, mc_credential.id, mc_credential.id_len,
				 pub_key, pub_key_len, 0, flags, auth_data, sizeof(auth_data),
				 &auth_data_len);
	if (ret) {
		LOG_ERR("authData build failed: %d", ret);
		fido2_crypto_destroy_key(mc_credential.key_id);
		return FIDO2_ERR_OTHER;
	}

	ret = fido2_attestation_sign(auth_data, auth_data_len, mc_params.client_data_hash,
				     mc_credential.key_id, &att_result);
	if (ret) {
		fido2_crypto_destroy_key(mc_credential.key_id);
		return FIDO2_ERR_OTHER;
	}

	ret = fido2_cbor_encode_make_credential_resp(auth_data, auth_data_len, &att_result,
						     cbor_out, cbor_out_cap, cbor_out_len);
	if (ret) {
		LOG_ERR("MakeCredential response encode failed: %d", ret);
		fido2_crypto_destroy_key(mc_credential.key_id);
		return FIDO2_ERR_OTHER;
	}

	ret = mc_store_credential();
	if (ret) {
		fido2_crypto_destroy_key(mc_credential.key_id);
		return (ret == -ENOSPC) ? FIDO2_ERR_KEY_STORE_FULL : FIDO2_ERR_OTHER;
	}

	LOG_INF("MakeCredential succeeded for RP: %s", mc_params.rp_id);

	return FIDO2_OK;
}

static enum fido2_status handle_get_assertion(uint8_t *cbor_in, size_t cbor_in_len,
					      uint8_t *cbor_out, size_t cbor_out_cap,
					      size_t *cbor_out_len)
{
	struct fido2_credential credential = {0};
	uint8_t rp_id_hash[FIDO2_SHA256_SIZE];
	size_t count = 0;
	uint8_t flags;
	int ret;

	ga_next.active = false;

	ret = fido2_cbor_decode_get_assertion(cbor_in, cbor_in_len, &ga_params);
	if (ret) {
		LOG_WRN("GetAssertion CBOR decode failed: %d (len=%zu)", ret, cbor_in_len);
		return FIDO2_ERR_INVALID_CBOR;
	}

	if (ga_params.has_pin_uv_auth_param) {
		ga_params.uv = false;
	}

	if (ga_params.uv) {
		return FIDO2_ERR_UNSUPPORTED_OPTION;
	}

	ret = fido2_crypto_sha256((const uint8_t *)ga_params.rp_id, strlen(ga_params.rp_id),
				  rp_id_hash);
	if (ret) {
		return FIDO2_ERR_OTHER;
	}

	if (ga_params.num_allow > 0) {
		for (int i = 0; i < ga_params.num_allow; ++i) {
			ret = fido2_storage_load(ga_params.allow_ids[i], ga_params.allow_id_lens[i],
						 &credential);
			if (ret == 0) {
				break;
			}
		}
		if (ret) {
			return FIDO2_ERR_NO_CREDENTIALS;
		}
	} else {
		ret = fido2_storage_find_by_rp(rp_id_hash, ga_credentials,
					       ARRAY_SIZE(ga_credentials), &count);
		if (ret || count == 0) {
			return FIDO2_ERR_NO_CREDENTIALS;
		}
		count = ga_filter_discoverable_credentials(count);
		if (count == 0) {
			return FIDO2_ERR_NO_CREDENTIALS;
		}
		memcpy(&credential, &ga_credentials[0], sizeof(credential));
	}

	if (memcmp(credential.rp_id_hash, rp_id_hash, FIDO2_SHA256_SIZE) != 0) {
		return FIDO2_ERR_NO_CREDENTIALS;
	}

	flags = ga_params.up ? AUTH_DATA_FLAG_UP : 0;

	if (ga_params.num_allow == 0 && count > 1) {
		memcpy(ga_next.client_data_hash, ga_params.client_data_hash,
		       sizeof(ga_next.client_data_hash));
		ga_next.flags = flags;
		ga_next.count = count;
		ga_next.next_index = 1;
		ga_next.active = true;
	}

	ret = ga_encode_credential_assertion(&credential, ga_params.client_data_hash, flags,
					     ga_params.num_allow == 0, count, cbor_out,
					     cbor_out_cap, cbor_out_len);
	if (ret != FIDO2_OK) {
		ga_next.active = false;
		return ret;
	}

	LOG_INF("GetAssertion succeeded for RP: %s (%zu credential%s)", ga_params.rp_id,
		count > 0 ? count : 1, count == 1 ? "" : "s");

	return FIDO2_OK;
}

static enum fido2_status handle_get_next_assertion(uint8_t *cbor_out, size_t cbor_out_cap,
						   size_t *cbor_out_len)
{
	const struct fido2_credential *credential;
	enum fido2_status status;

	if (!ga_next.active || ga_next.next_index >= ga_next.count) {
		ga_next.active = false;
		return FIDO2_ERR_NOT_ALLOWED;
	}

	credential = &ga_credentials[ga_next.next_index++];
	if (ga_next.next_index >= ga_next.count) {
		ga_next.active = false;
	}

	status = ga_encode_credential_assertion(credential, ga_next.client_data_hash,
					       ga_next.flags, true, 0, cbor_out,
					       cbor_out_cap, cbor_out_len);
	if (status != FIDO2_OK) {
		ga_next.active = false;
		return status;
	}

	LOG_INF("GetNextAssertion succeeded (%zu/%zu)", ga_next.next_index, ga_next.count);

	return FIDO2_OK;
}

static enum fido2_status handle_get_info(uint8_t *cbor_out, size_t cbor_out_cap,
					 size_t *cbor_out_len)
{
	struct fido2_device_info info = {0};
	int ret;

	info.versions[0] = "FIDO_2_0";
	info.versions[1] = "FIDO_2_1";
	info.num_versions = 2;
	info.num_pin_uv_auth_protocols = 0;
	info.max_credential_count = CONFIG_FIDO2_MAX_CREDENTIALS;
	info.max_msg_size = CONFIG_FIDO2_CBOR_MAX_SIZE;
	info.max_credential_id_length = FIDO2_CREDENTIAL_ID_MAX_SIZE;
	info.transports = 0;

	info.firmware_version = 0x00010000;

	if (IS_ENABLED(CONFIG_FIDO2_TRANSPORT_USB_HID)) {
		info.transports |= FIDO2_TRANSPORT_USB;
	}
	if (IS_ENABLED(CONFIG_FIDO2_TRANSPORT_BLE)) {
		info.transports |= FIDO2_TRANSPORT_BLE;
	}
	if (IS_ENABLED(CONFIG_FIDO2_TRANSPORT_NFC)) {
		info.transports |= FIDO2_TRANSPORT_NFC;
	}

	info.options.rk = true;
	info.options.up = true;
	info.options.plat = false;
	/* These will depend on config */
	info.options.uv = false;
	/* Allow non-UV non-discoverable credential creation */
	info.options.make_cred_uv_not_rqd = !IS_ENABLED(CONFIG_FIDO2_ALWAYS_UV);
	/* Force UV even when RP sets userVerification=discouraged */
	info.options.always_uv = IS_ENABLED(CONFIG_FIDO2_ALWAYS_UV);
	info.options.no_mc_ga_permissions_with_client_pin = false;

#if defined(CONFIG_FIDO2_CREDENTIAL_MANAGEMENT)
	info.options.cred_mgmt = true;
#endif
#if defined(CONFIG_FIDO2_EXT_CRED_PROTECT)
	info.extensions[info.num_extensions++] = "credProtect";
#endif
#if defined(CONFIG_FIDO2_EXT_HMAC_SECRET)
	info.extensions[info.num_extensions++] = "hmac-secret";
#endif
#if defined(CONFIG_FIDO2_EXT_LARGE_BLOB_KEY)
	info.extensions[info.num_extensions++] = "largeBlobKey";
#endif
#if defined(CONFIG_FIDO2_EXT_CRED_BLOB)
	info.extensions[info.num_extensions++] = "credBlob";
#endif
#if defined(CONFIG_FIDO2_EXT_THIRD_PARTY_PAYMENT)
	info.extensions[info.num_extensions++] = "thirdPartyPayment";
#endif

	/* Convert HEX AAGUID to binary and load it in info */
	size_t written = hex2bin(CONFIG_FIDO2_AAGUID, strlen(CONFIG_FIDO2_AAGUID), info.aaguid,
				 FIDO2_AAGUID_SIZE);
	if (written != FIDO2_AAGUID_SIZE) {
		memset(info.aaguid, 0, FIDO2_AAGUID_SIZE);
	}

	ret = fido2_cbor_encode_get_info(&info, cbor_out, cbor_out_cap, cbor_out_len);
	if (ret) {
		return FIDO2_ERR_OTHER;
	}

	return FIDO2_OK;
}

static enum fido2_status handle_reset(uint8_t *cbor_in, size_t cbor_in_len,
				      uint8_t *cbor_out, size_t cbor_out_cap,
				      size_t *cbor_out_len)
{
	int ret;

	ARG_UNUSED(cbor_in);
	ARG_UNUSED(cbor_out);
	ARG_UNUSED(cbor_out_cap);

	*cbor_out_len = 0;

	if (cbor_in_len != 0) {
		return FIDO2_ERR_INVALID_LENGTH;
	}

	ret = fido2_reset();
	if (ret == -EACCES) {
		LOG_WRN("Rejected Reset: outside power-up reset window");
		return FIDO2_ERR_NOT_ALLOWED;
	}

	if (ret) {
		LOG_ERR("Reset failed: %d", ret);
		return FIDO2_ERR_OTHER;
	}

	ga_next.active = false;
	memset(&mc_credential, 0, sizeof(mc_credential));
	memset(ga_credentials, 0, sizeof(ga_credentials));

	LOG_INF("Reset succeeded; credentials and PIN state wiped");

	return FIDO2_OK;
}

static enum fido2_status process_command(uint8_t cmd, uint8_t *cbor_in, size_t cbor_in_len,
					 uint8_t *cbor_out, size_t cbor_out_cap,
					 size_t *cbor_out_len,
					 const struct fido2_transport *transport, uint32_t cid)
{
	if (cmd != FIDO2_CMD_GET_NEXT_ASSERTION && cmd != FIDO2_CMD_GET_ASSERTION) {
		ga_next.active = false;
	}

	switch (cmd) {
	case FIDO2_CMD_GET_INFO:
		return handle_get_info(cbor_out, cbor_out_cap, cbor_out_len);
	case FIDO2_CMD_MAKE_CREDENTIAL:
		return handle_make_credential(cbor_in, cbor_in_len, cbor_out, cbor_out_cap,
					      cbor_out_len, transport, cid);
	case FIDO2_CMD_GET_ASSERTION:
		return handle_get_assertion(cbor_in, cbor_in_len, cbor_out, cbor_out_cap,
					    cbor_out_len);
	case FIDO2_CMD_GET_NEXT_ASSERTION:
		return handle_get_next_assertion(cbor_out, cbor_out_cap, cbor_out_len);
	case FIDO2_CMD_RESET:
		return handle_reset(cbor_in, cbor_in_len, cbor_out, cbor_out_cap, cbor_out_len);
	default:
		*cbor_out_len = 0;
		return FIDO2_ERR_INVALID_COMMAND;
	}
}

static void transport_recv_cb(const struct fido2_transport *transport, uint32_t cid,
			      const uint8_t *buf, size_t len, void *user_data)
{
	k_spinlock_key_t key;
	int ret;

	ARG_UNUSED(user_data);

	if (len > sizeof(rx_enqueue_msg.data)) {
		LOG_WRN("Message too large, dropping");
		return;
	}

	key = k_spin_lock(&rx_enqueue_lock);

	rx_enqueue_msg.transport = transport;
	rx_enqueue_msg.cid = cid;
	rx_enqueue_msg.len = len;
	memcpy(rx_enqueue_msg.data, buf, len);

	ret = k_msgq_put(&fido2_msgq, &rx_enqueue_msg, K_NO_WAIT);

	k_spin_unlock(&rx_enqueue_lock, key);

	if (ret) {
		LOG_WRN("Message queue full, dropping cid=0x%08x", cid);
	}
}

static void fido2_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (atomic_get(&fido2_running)) {
		if (k_msgq_get(&fido2_msgq, &rx_dequeue_msg, K_MSEC(100)) != 0) {
			continue;
		}

		if (rx_dequeue_msg.len < 1) {
			continue;
		}

		uint8_t cmd = rx_dequeue_msg.data[0];
		size_t cbor_out_len = 0;
		enum fido2_status status;
		int ret;

		status =
			process_command(cmd, rx_dequeue_msg.data + 1, rx_dequeue_msg.len - 1,
					ctap_tx_frame + 1, sizeof(ctap_tx_frame) - 1, &cbor_out_len,
					rx_dequeue_msg.transport, rx_dequeue_msg.cid);
		ctap_tx_frame[0] = (uint8_t)status;

		if (rx_dequeue_msg.transport && rx_dequeue_msg.transport->api) {
			ret = rx_dequeue_msg.transport->api->send(rx_dequeue_msg.cid, ctap_tx_frame,
								  cbor_out_len + 1);
		} else {
			LOG_ERR("No send path for cid=0x%08x", rx_dequeue_msg.cid);
			ret = -ENODEV;
		}

		if (ret) {
			LOG_WRN("Response send failed: %d", ret);
		} else {
			LOG_INF("CTAP cmd=0x%02x status=0x%02x wire_len=%zu cid=0x%08x", cmd,
				ctap_tx_frame[0], cbor_out_len + 1, rx_dequeue_msg.cid);
		}
	}
}

int fido2_init(void)
{
	int ret;

	reset_deadline = k_uptime_get() + 10000; /* Reset allowed for 10s post-boot */

	ret = fido2_storage_init();
	if (ret) {
		LOG_ERR("Storage init failed");
		return ret;
	}

	ret = fido2_crypto_init();
	if (ret) {
		LOG_ERR("Crypto init failed");
		return ret;
	}

	ret = fido2_transport_init_all(transport_recv_cb, NULL);
	if (ret) {
		LOG_ERR("Transport init failed");
		return ret;
	}

	LOG_INF("FIDO2 subsystem initialized");

	return 0;
}

int fido2_start(void)
{
	if (atomic_get(&fido2_running)) {
		LOG_ERR("FIDO2 authenticator already started");
		return -EALREADY;
	}

	atomic_set(&fido2_running, 1);

	k_thread_create(&fido2_thread, fido2_stack, K_THREAD_STACK_SIZEOF(fido2_stack),
			fido2_thread_fn, NULL, NULL, NULL, CONFIG_FIDO2_THREAD_PRIORITY, 0,
			K_NO_WAIT);
	k_thread_name_set(&fido2_thread, "fido2");

	LOG_INF("FIDO2 authenticator started");
	return 0;
}

int fido2_stop(void)
{
	if (!atomic_get(&fido2_running)) {
		LOG_ERR("FIDO2 authenticator already stopped");
		return -EALREADY;
	}

	atomic_set(&fido2_running, 0);

	k_thread_join(&fido2_thread, K_SECONDS(5));

	fido2_transport_shutdown_all();

	LOG_INF("FIDO2 authenticator stopped");
	return 0;
}

int fido2_reset(void)
{
	if (k_uptime_get() > reset_deadline) {
		return -EACCES;
	}

	return fido2_storage_wipe_all();
}
