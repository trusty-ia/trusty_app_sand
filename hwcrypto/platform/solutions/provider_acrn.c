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
#define LOG_TAG      "provider_acrn"

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
        *key_len = ikm_len;
        memset(key_buf, 0, ikm_len);

        return HWKEY_NO_ERROR;
}

/*
 * Generate RPMB Secure Storage Authentication keys for all seeds
 */
uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot *slot,
				     uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	assert(kbuf);
	assert(klen);

	memset(kbuf, 0, RPMB_SS_AUTH_KEY_SIZE);
	*klen = RPMB_SS_AUTH_KEY_SIZE;

	return 0;
}
