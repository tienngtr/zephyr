/*
 * Copyright (c) 2026 Siratul Islam <email@sirat.me>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FIDO2_CRYPTO_H_
#define FIDO2_CRYPTO_H_

#include <zephyr/authentication/fido2/fido2_types.h>

/**
 * Initialize the crypto module.
 * @return PSA_SUCCESS on success, PSA error code on failure
 */
int fido2_crypto_init(void);

/**
 * Generate a new P-256 key pair and return the PSA key ID.
 *
 * @param key_id Output: assigned PSA key ID
 * @return PSA_SUCCESS on success, PSA error code on failure
 */
int fido2_crypto_generate_keypair(uint32_t *key_id);

/**
 * Sign data using ECDSA-SHA256 with the given key.
 *
 * @param key_id PSA key ID
 * @param hash 32-byte hash to sign
 * @param sig Output signature buffer
 * @param sig_size Size of signature buffer
 * @param sig_len Actual signature length written
 * @return PSA_SUCCESS on success, PSA error code on failure
 */
int fido2_crypto_sign(uint32_t key_id, const uint8_t hash[FIDO2_SHA256_SIZE], uint8_t *sig,
		      size_t sig_size, size_t *sig_len);

/**
 * Export the public key for a key pair.
 *
 * @param key_id PSA key ID
 * @param pub_key Output: uncompressed public key (65 bytes for P-256)
 * @param pub_key_size Buffer size
 * @param pub_key_len Actual bytes written
 * @return PSA_SUCCESS on success, PSA error code on failure
 */
int fido2_crypto_export_pubkey(uint32_t key_id, uint8_t *pub_key, size_t pub_key_size,
			       size_t *pub_key_len);

/**
 * Compute SHA-256 hash.
 *
 * @param data Input data
 * @param len Input length
 * @param hash Output: 32-byte hash
 * @return PSA_SUCCESS on success, PSA error code on failure
 */
int fido2_crypto_sha256(const uint8_t *data, size_t len, uint8_t hash[FIDO2_SHA256_SIZE]);

/**
 * Compute SHA-256(authData || clientDataHash).
 *
 * @param auth_data Raw authenticatorData bytes
 * @param auth_data_len Length of auth_data
 * @param client_data_hash 32-byte clientDataHash
 * @param out Output: 32-byte hash
 * @return PSA_SUCCESS on success, PSA error code on failure
 */
int fido2_crypto_hash_authdata(const uint8_t *auth_data, size_t auth_data_len,
			       const uint8_t client_data_hash[FIDO2_SHA256_SIZE],
			       uint8_t out[FIDO2_SHA256_SIZE]);

/**
 * Destroy a key.
 *
 * @param key_id PSA key ID to destroy
 * @return PSA_SUCCESS on success, PSA error code on failure
 */
int fido2_crypto_destroy_key(uint32_t key_id);

#endif /* FIDO2_CRYPTO_H_ */
