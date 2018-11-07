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
#include "trusty_key_crypt.h"

#include "trusty_device_info.h"
#include "trusty_syscalls_x86.h"

#define LOCAL_TRACE  1
#define LOG_TAG      "provider_fixed_seed"

extern struct crypto_context g_crypto_ctx;
extern const uint8_t trk_aad[16];
extern const uuid_t crypto_uuid;
extern const uint8_t ssek_aad[16];

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

	rc = aes_256_gcm_decrypt((const struct gcm_key *)aes_gcm_key,
				(const void *)g_crypto_ctx.ssek_iv, sizeof(g_crypto_ctx.ssek_iv),
				(const void *)ssek_aad, sizeof(ssek_aad),
				(const void *)g_crypto_ctx.ssek_cipher, sizeof(g_crypto_ctx.ssek_cipher),
				ssek, ssek_len);
	if (rc || *ssek_len != sizeof(struct gcm_key)) {
		TLOGE("get_ssek failed to decrypt ssek, rc is %d. *ssek_len is %zu.\n", rc, *ssek_len);
		*ssek_len = 0;
		secure_memzero(ssek, sizeof(struct gcm_key));
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

	struct gcm_key trk;
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

	rc = aes_256_gcm_decrypt((const struct gcm_key *)aes_gcm_key,
				(const void *)g_crypto_ctx.trk_iv, sizeof(g_crypto_ctx.trk_iv),
				(const void *)trk_aad, sizeof(trk_aad),
				(const void *)g_crypto_ctx.trk_cipher, sizeof(g_crypto_ctx.trk_cipher),
				&trk, &out_size);
	if (rc || out_size != sizeof(trk)) {
		TLOGE("aes_256_gcm_decrypt failed to decrypt rot key, rc is %d. out_size is %zu.\n", rc, out_size);
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
 * Generate RPMB Secure Storage Authentication keys for all seeds
 */
uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot *slot,
				     uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	int rc = 0;
	trusty_device_info_t dev_info;
	uint8_t invalid_key[64] = {0};

	assert(kbuf);
	assert(klen);

	*klen = 0;

	rc = get_device_info(&dev_info);
	if (NO_ERROR != rc) {
		TLOGE("%s:failed to get device infomation\n", __func__);
		rc = HWKEY_ERR_GENERIC;
		goto clear_dev_info;
	}

	if (!CRYPTO_memcmp(dev_info.sec_info.rpmb_key[0], invalid_key, sizeof(invalid_key)))
	{
			TLOGE("%s: the RPMB key is unavailable.\n", __func__);
			rc = HWKEY_ERR_GENERIC;
			goto clear_dev_info;
	}

	memcpy_s(kbuf, RPMB_SS_AUTH_KEY_SIZE, dev_info.sec_info.rpmb_key[0], RPMB_SS_AUTH_KEY_SIZE);
	*klen = RPMB_SS_AUTH_KEY_SIZE;

clear_dev_info:
	secure_memzero(&dev_info, sizeof(trusty_device_info_t));
	return rc;
}
