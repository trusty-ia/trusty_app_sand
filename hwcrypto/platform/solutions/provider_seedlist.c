/*
 * Copyright (C) 2018 The Android Open Source Project
 * Copyright (C) 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <uapi/err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <trusty_std.h>
#include <interface/hwkey/hwkey.h>
#include <openssl/cipher.h>
#include <openssl/aes.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include "common.h"
#include "hwkey_srv_priv.h"
#include "hwrng_srv_priv.h"
#include "trusty_key_migration.h"

#include "trusty_device_info.h"
#include "trusty_syscalls_x86.h"

#define LOCAL_TRACE  1
#define LOG_TAG      "provider_seedlist"

extern struct crypto_context g_crypto_ctx;
extern const struct aad trk_aad;
extern const uuid_t crypto_uuid;
extern const struct aad ssek_aad;

uint32_t get_ssek(uint8_t *ssek, size_t *ssek_len)
{
	uint8_t aes_gcm_key[32] = {0};
	int rc = -1;

	assert(ssek && ssek_len);

	/* always use seed[0] derivative to decrypt ssek and trk */
	rc = get_aes_gcm_key(0, aes_gcm_key, sizeof(aes_gcm_key));
	if (rc != NO_ERROR) {
		*ssek_len = 0;
		TLOGE("get_ssek failed (%d) to get_aes_gcm_key.\n", rc);
		goto out;
	}

	rc = aes_256_gcm_decrypt((const struct key *)aes_gcm_key,
				(const struct iv *)g_crypto_ctx.ssek_iv, &ssek_aad,
				(const void *)g_crypto_ctx.ssek_cipher, sizeof(g_crypto_ctx.ssek_cipher),
				ssek, ssek_len);
	if (rc || *ssek_len != sizeof(struct key)) {
		TLOGE("get_ssek failed to decrypt ssek, rc is %d. *ssek_len is %zu.\n", rc, *ssek_len);
		*ssek_len = 0;
		secure_memzero(ssek, sizeof(struct key));
		goto out;
	}

	rc = HWKEY_NO_ERROR;
out:
	secure_memzero(aes_gcm_key, sizeof(aes_gcm_key));
	return rc;
}


/*
 * Derive key V1 - HMAC SHA256 based Key derivation function
 */
uint32_t derive_key_v1(const uuid_t *uuid,
			const uint8_t *ikm_data, size_t ikm_len,
			uint8_t *key_buf, size_t *key_len)
{

	struct key trk;
	size_t out_size = 0;
	uint8_t aes_gcm_key[32] = {0};
	int rc = -1;

	assert(ikm_data && key_buf && key_len);

	if (!ikm_len) {
		*key_len = 0;
		return HWKEY_ERR_BAD_LEN;
	}

	/* always use seed 0 derivative to decrypt ssek and trk */
	rc = get_aes_gcm_key(0, aes_gcm_key, sizeof(aes_gcm_key));
	if (rc != NO_ERROR) {
		TLOGE("failed (%d) to get device HUK\n", rc);
		goto out;
	}

	rc = aes_256_gcm_decrypt((const struct key *)aes_gcm_key,
				(const struct iv *)g_crypto_ctx.trk_iv, &trk_aad,
				(const void *)g_crypto_ctx.trk_cipher, sizeof(g_crypto_ctx.trk_cipher),
				&trk, &out_size);
	if (rc || out_size != sizeof(trk)) {
		TLOGE("aes_256_gcm_decrypt failed to rot key, rc is %d. out_size is %zu.\n", rc, out_size);
		*key_len = 0;
		secure_memzero(key_buf, ikm_len);
		goto out;
        }

	if (!HKDF(key_buf, ikm_len, EVP_sha256(),
		(const uint8_t *)&trk, sizeof(trk),
		(const uint8_t *)uuid, sizeof(uuid_t),
		ikm_data, ikm_len)) {
		TLOGE(" derive_key_v1 HDKF failed 0x%x.\n", ERR_get_error());
		*key_len = 0;
		secure_memzero(key_buf, ikm_len);
		goto out;
	}

	*key_len = ikm_len;
	rc = HWKEY_NO_ERROR;

out:
	secure_memzero(aes_gcm_key, sizeof(aes_gcm_key));
	secure_memzero(&trk, sizeof(trk));

	return rc;
}

/*
 * Generate RPMB Secure Storage Authentication key from seed[index]
 */
static uint32_t get_rpmb_ss_auth_key_with_index(uint8_t index,
				uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	uint8_t rpmb_key[RPMB_SS_AUTH_KEY_SIZE] = {0};
	trusty_device_info_t dev_info;
	int ret = HWKEY_ERR_GENERIC;
	uint8_t serial[MMC_PROD_NAME_WITH_PSN_LEN] = {0};

	assert(kbuf);
	assert(klen);

	if (NO_ERROR != get_device_info(&dev_info)) {
		TLOGE("failed to get device infomation\n");
		goto out;
	}

	if (index < dev_info.sec_info.num_seeds) {
		/* Clear Byte 2 and 0 for CID[6] PRV and CID[0] CRC for eMMC Field Firmware Updates
		 * serial[0] = cid[0];  -- CRC
		 * serial[2] = cid[6];  -- PRV
		 */
		memcpy_s(serial, sizeof(serial), dev_info.sec_info.serial, sizeof(dev_info.sec_info.serial));
		serial[0] ^= serial[0];
		serial[2] ^= serial[2];

		if (!HKDF(rpmb_key, sizeof(rpmb_key), EVP_sha256(),
			  (const uint8_t *)dev_info.sec_info.dseed_list[index].seed, 32,
			  (const uint8_t *)&crypto_uuid, sizeof(uuid_t),
			  (const uint8_t *)serial, sizeof(serial))) {
			TLOGE("HDKF failed 0x%x\n", ERR_get_error());
			goto out;
		}
		memcpy_s(kbuf, RPMB_SS_AUTH_KEY_SIZE, rpmb_key, RPMB_SS_AUTH_KEY_SIZE);
	}
	*klen = RPMB_SS_AUTH_KEY_SIZE;

	ret = HWKEY_NO_ERROR;
out:
	secure_memzero(rpmb_key, sizeof(rpmb_key));
	secure_memzero(&dev_info, sizeof(dev_info));

	return ret;
}

/*
 * Generate RPMB Secure Storage Authentication keys for all seeds
 */
uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot *slot,
				     uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	int rc = 0;
	uint32_t i;
	trusty_device_info_t dev_info;
	size_t klen_for_once = 0;

	assert(kbuf);
	assert(klen);

	*klen = 0;

	rc = get_device_info(&dev_info);
	if (NO_ERROR != rc) {
		TLOGE("%s:failed to get device infomation\n", __func__);
		rc = HWKEY_ERR_GENERIC;
		goto clear_dev_info;
	}

	for (i = 0; i < dev_info.sec_info.num_seeds; i++) {
		if (HWKEY_NO_ERROR != get_rpmb_ss_auth_key_with_index(
				i, kbuf + i * RPMB_SS_AUTH_KEY_SIZE, kbuf_len, &klen_for_once)) {
			secure_memzero(kbuf, kbuf_len);
			rc = HWKEY_ERR_GENERIC;
			goto clear_dev_info;
		}
		*klen += klen_for_once;
	}
clear_dev_info:
	secure_memzero(&dev_info, sizeof(trusty_device_info_t));
	return rc;
}
