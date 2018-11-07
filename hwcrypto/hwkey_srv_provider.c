/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2016 Intel Corporation
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
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/evp.h>

#include "common.h"
#include "hwkey_srv_priv.h"
#include "hwrng_srv_priv.h"
#include "trusty_key_migration.h"
#include "trusty_key_crypt.h"

#include "trusty_device_info.h"
#include "trusty_syscalls_x86.h"

#define LOCAL_TRACE  1
#define LOG_TAG      "hwkey_srv_provider"

#define CRYPTO_CTX_INITIAL_VALUE(crypto_ctx) {0, {0}, {0}, {0}, {0}, 0, {0}}

struct crypto_context g_crypto_ctx = CRYPTO_CTX_INITIAL_VALUE(g_crypto_ctx);

const uint8_t trk_aad[16] = {
		0xf3, 0x56, 0x5b, 0xd9, 0xc4, 0xe7, 0xd4, 0x1e,
		0xbb, 0xb4, 0x14, 0x15, 0x20, 0xe7, 0x09, 0xcf,
};

const uint8_t ssek_aad[16] = {
		0x8d, 0x46, 0x2b, 0xd1, 0xb3, 0xde, 0x0f, 0x5c,
		0xc1, 0x6d, 0x56, 0xcc, 0x2e, 0x53, 0x05, 0x54,
};
/* Secure storage service app uuid */
const uuid_t ss_uuid = SECURE_STORAGE_SERVER_APP_UUID;
const uuid_t crypto_uuid = HWCRYPTO_SRV_APP_UUID;

static const uint8_t gcm_info[] = {0xc7, 0x87, 0xaf, 0xe7, 0x3b, 0xca, 0x44, 0x63,
				   0x35, 0x16, 0x0b, 0x94, 0x52, 0x53, 0x4d, 0xa3};

#if LK_DEBUGLEVEL > 1

/* This input vector is taken from RFC 5869 (Extract-and-Expand HKDF) */
static const uint8_t IKM[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

static const uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c };

static const uint8_t info[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

/* Expected Output Key */
static const uint8_t exp_OKM[42]= { 0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
				    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
				    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
				    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
				    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
				    0x58, 0x65 };

static bool hkdf_self_test(void)
{
	int res;
	uint8_t OKM[sizeof(exp_OKM)];

	TLOGI("hkdf self test\n");

	/* Check if OKM is OK */
	memset(OKM, 0x55, sizeof(OKM));

	res = HKDF(OKM, sizeof(OKM), EVP_sha256(),
		   IKM, sizeof(IKM), salt, sizeof(salt), info, sizeof(info));
	if (!res) {
		TLOGE("hkdf: failed 0x%x\n", ERR_get_error());
		return false;
	}

	res = memcmp(OKM, exp_OKM, sizeof(OKM));
	if (res) {
		TLOGE("hkdf: %s data mismatch\n", __func__);
		return false;
	}

	TLOGI("hkdf self test: PASSED\n");
	return true;
}

/*
 *  Run Self test
 */
static bool hwkey_self_test(void)
{
	TLOGI("hwkey self test\n");

	if (!hkdf_self_test())
		return false;

	TLOGI("hwkey self test: PASSED\n");
	return true;
}
#endif

static int get_device_seed_by_index(uint8_t index, uint8_t *seed, uint32_t seed_len)
{
	int rc = 0;
	trusty_device_info_t dev_info;

	if (index >= CSE_SEED_MAX_ENTRIES)
		return HWKEY_ERR_NOT_VALID;

	if(!seed) {
		TLOGE("the input param is NULL\n");
		return ERR_IO;
	}

	/* get device info */
	rc = get_device_info(&dev_info);
	if (rc != NO_ERROR ) {
		TLOGE("failed (%d) to get device infomation\n", rc);
		rc = ERR_IO;
		goto clear_sensitive_data;
	}

	if (dev_info.sec_info.size_of_this_struct != sizeof(device_sec_info_t)){
		TLOGE("trusty_device_info_t size is mismatched\n");
		rc = ERR_BAD_LEN;
		goto clear_sensitive_data;
	}

	/*
	 * Since seed_list is sorted by svn in descending order, so dseed_list[0] will contain the
	 * current seed and highest svn. dseed_list[0].seed, only lower 32 bytes
	 * will be used for now by Trusty. But keep higher 32 bytes for future extension.
	 */

	rc = memcpy_s(seed, seed_len, dev_info.sec_info.dseed_list[index].seed, seed_len);

clear_sensitive_data:
	secure_memzero(&dev_info, sizeof(trusty_device_info_t));
	return rc;
}

static int get_seed_count(uint32_t *num)
{
	int rc;
	trusty_device_info_t dev_info;

	/* get device info */
	rc = get_device_info(&dev_info);
	if (rc != NO_ERROR ) {
		TLOGE("failed (%d) to get device infomation.\n", rc);
		secure_memzero(&dev_info, sizeof(trusty_device_info_t));
		return HWKEY_ERR_GENERIC;
	}

	// this log will be removed after all platforms are fully enabled.
	TLOGE("The sec info platform is (%d)\n", dev_info.sec_info.platform);
	fprintf(stderr, "\r\n");

	*num = dev_info.sec_info.num_seeds;
	secure_memzero(&dev_info, sizeof(trusty_device_info_t));

	assert(*num > 0 && *num <= CSE_SEED_MAX_ENTRIES);

	return HWKEY_NO_ERROR;
}

static uint8_t get_svn_by_index(uint8_t index)
{
	trusty_device_info_t dev_info;
	uint8_t svn;

	assert(index < CSE_SEED_MAX_ENTRIES);

	/* get device info for svn*/
	if (NO_ERROR != get_device_info(&dev_info)) {
		TLOGE("failed to get device infomation.\n");
		secure_memzero(&dev_info, sizeof(dev_info));
		assert(0);
	}

	svn = dev_info.sec_info.dseed_list[index].cse_svn;
	secure_memzero(&dev_info, sizeof(dev_info));

	return svn;
}

/* aes gcm key for crypto is derived from seed[index] */
uint32_t get_aes_gcm_key(uint8_t index, uint8_t *aes_gcm_key, size_t key_len)
{
	int rc = -1;
	uint8_t hw_device_key[32] = {0};

	assert(aes_gcm_key);

	if (get_device_seed_by_index(index, hw_device_key, sizeof(hw_device_key))) {
		TLOGE("failed (%d) to get device HUK.\n", rc);
		goto out;
	}

	if (!HKDF(aes_gcm_key, key_len, EVP_sha256(),
		(const uint8_t *)hw_device_key, 32,
		(const uint8_t *)&crypto_uuid, sizeof(uuid_t),
		gcm_info, sizeof(gcm_info))) {
		TLOGE("get_aes_gcm_key HDKF failed 0x%x.\n", ERR_get_error());
		goto out;
	}

	rc = NO_ERROR;

out:
	secure_memzero(hw_device_key, sizeof(hw_device_key));

	return rc;
}


/* wrap_crypto_context with seed 0 and random iv.
 * save g_crypto_ctx to trusty memory.
 */
static uint32_t wrap_crypto_context(const struct gcm_key ssek, const struct gcm_key trk,
					struct crypto_context *crypto_ctx)
{
	int rc = -1;
	uint8_t aes_gcm_key[32] = {0};
	size_t out_size = 0;

	assert(crypto_ctx);

	if (NO_ERROR != hwrng_dev_get_rng_data(crypto_ctx->trk_iv, sizeof(crypto_ctx->trk_iv))) {
		TLOGE("fail to genarate random trk iv.\n");
		goto out;
	}

	if (NO_ERROR != hwrng_dev_get_rng_data(crypto_ctx->ssek_iv, sizeof(crypto_ctx->ssek_iv))) {
		TLOGE("fail to genarate random ssek iv.\n");
		goto out;
	}

	rc = get_aes_gcm_key(0, aes_gcm_key, sizeof(aes_gcm_key));
	if (rc != NO_ERROR) {
		TLOGE("failed (%d) to get aes_gcm_key.\n", rc);
		goto out;
	}

	rc = aes_256_gcm_encrypt((const struct gcm_key *)aes_gcm_key,
				(const void *)crypto_ctx->ssek_iv, sizeof(crypto_ctx->ssek_iv),
				(const void *)ssek_aad, sizeof(ssek_aad),
				(const void *)&ssek, sizeof(ssek),
				crypto_ctx->ssek_cipher, &out_size);
	if (AES_GCM_NO_ERROR != rc || out_size != sizeof(crypto_ctx->ssek_cipher)) {
		TLOGE("failed to encrypt ssek: rc is %d. out_size is %zu.\n", rc, out_size);
		goto out;
	}

	rc = aes_256_gcm_encrypt((const struct gcm_key *)aes_gcm_key,
				(const void *)crypto_ctx->trk_iv, sizeof(crypto_ctx->trk_iv),
				(const void *)trk_aad, sizeof(trk_aad),
				(const void *)&trk, sizeof(trk),
				crypto_ctx->trk_cipher, &out_size);
	if (AES_GCM_NO_ERROR != rc || out_size != sizeof(crypto_ctx->trk_cipher)) {
		TLOGE("failed to encrypt trk: rc is %d. out_size is %zu.\n", rc, out_size);
		goto out;
	}

	crypto_ctx->svn = get_svn_by_index(0);
	crypto_ctx->magic = CRYPTO_CONTEXT_MAGIC_DATA;

	/* save g_crypto_ctx to trusty memory only if the previous operations are successful.*/
	memcpy_s(&g_crypto_ctx, sizeof(struct crypto_context), crypto_ctx, sizeof(struct crypto_context));

	rc = HWKEY_NO_ERROR;

out:
	secure_memzero(aes_gcm_key, sizeof(aes_gcm_key));
	if (rc)
		secure_memzero(crypto_ctx, sizeof(struct crypto_context));
	return rc;
}

uint32_t generate_crypto_context(uint8_t *data, size_t *data_len)
{
	struct gcm_key ssek, trk;
	int rc = -1;
	struct crypto_context crypto_ctx = CRYPTO_CTX_INITIAL_VALUE(crypto_ctx);

	assert(data && data_len);

	if (*data_len < sizeof(struct crypto_context)) {
		TLOGE("generate_crypto_context data len is too small!\n");
		goto out;
	}

	if (NO_ERROR != hwrng_dev_get_rng_data((uint8_t *)&trk, sizeof(trk))) {
		TLOGE("fail to genarate random trk.\n");
		goto out;;
	}

	if (NO_ERROR != hwrng_dev_get_rng_data((uint8_t *)&ssek, sizeof(ssek))) {
		TLOGE("fail to genarate random ssek.\n");
		goto out;
	}

	rc = wrap_crypto_context(ssek, trk, &crypto_ctx);
	if (rc != HWKEY_NO_ERROR) {
		TLOGE("generate_crypto_context failed to wrap_crypto_context: %d.\n", rc);
		goto out;
	}

	*data_len = sizeof(struct crypto_context);
	memcpy_s(data, *data_len, &crypto_ctx, sizeof(struct crypto_context));

out:
	secure_memzero(&ssek, sizeof(ssek));
	secure_memzero(&trk, sizeof(trk));
	secure_memzero(&crypto_ctx, sizeof(struct crypto_context));

	return rc;
}

uint32_t exchange_crypto_context(const uint8_t *src, size_t src_len,
				    uint8_t *dst, size_t *dst_len)
{
	uint32_t seed_count, i;
	uint32_t index = -1;
	struct gcm_key ssek, trk;
	size_t out_size;
	int rc = -1;
	uint8_t aes_gcm_key[32] = {0};
	struct crypto_context updated_crypto_ctx = CRYPTO_CTX_INITIAL_VALUE(updated_crypto_ctx);
	struct crypto_context crypto_ctx = CRYPTO_CTX_INITIAL_VALUE(crypto_ctx);
	uint8_t svn;

	assert(dst && dst_len && src && (src_len == sizeof(struct crypto_context)));

	memcpy_s(&crypto_ctx, sizeof(struct crypto_context), src, src_len);
	// get crypto_context from SS
	svn = get_svn_by_index(0);
	if (crypto_ctx.svn == svn) {
		memcpy_s(&g_crypto_ctx, sizeof(struct crypto_context), &crypto_ctx, sizeof(struct crypto_context));

		//use IN crypto_context as OUT;
		*dst_len = src_len;
		memcpy_s(dst, *dst_len, src, src_len);
		secure_memzero(&crypto_ctx, sizeof(struct crypto_context));

		return 0;
	}

	if (svn < crypto_ctx.svn) {
		TLOGE("SVN0 is untrusted! %u < %u.\n", svn, crypto_ctx.svn);
		goto out;
	}

	TLOGE("Seed Changed!!!\n");
	*dst_len = 0;

	if (get_seed_count(&seed_count))
		return HWKEY_ERR_GENERIC;

	/* lookup the seed index matched with svn from seed[1] */
	for (i=1; i<seed_count; i++) {
		svn = get_svn_by_index(i);
		if (svn == crypto_ctx.svn) {
			index = i;
			TLOGI("seed changed to index %u. seed_count is %u.\n", index, seed_count);
			break;
		}
	}

	if (i >= seed_count) {
		TLOGE("FATAL ERROR! seed changed but not found!!! i is %u, seed_count is %u.\n", i, seed_count);
		goto out;
	}

	rc = get_aes_gcm_key(index, aes_gcm_key, sizeof(aes_gcm_key));
	if (rc != NO_ERROR) {
		TLOGE("failed (%d) to get aes_gcm_key.\n", rc);
		goto out;
	}

	rc = aes_256_gcm_decrypt((const struct gcm_key *) aes_gcm_key,
				(const void *)crypto_ctx.ssek_iv, sizeof(crypto_ctx.ssek_iv),
				(const void *)ssek_aad, sizeof(ssek_aad),
				(const void *)crypto_ctx.ssek_cipher, sizeof(crypto_ctx.ssek_cipher),
				&ssek, &out_size);
	if (rc != AES_GCM_NO_ERROR || out_size != sizeof(ssek)) {
		TLOGE("failed to decrypt ssek rc is %d, out_size is %zu.\n", rc, out_size);
		goto out;
	}

	rc = aes_256_gcm_decrypt((const struct gcm_key *) aes_gcm_key,
				(const void *)crypto_ctx.trk_iv, sizeof(crypto_ctx.trk_iv),
				(const void *)trk_aad, sizeof(trk_aad),
				(const void *)crypto_ctx.trk_cipher, sizeof(crypto_ctx.trk_cipher),
				&trk, &out_size);
	if (rc != AES_GCM_NO_ERROR || out_size != sizeof(trk)) {
		TLOGE("failed to decrypt trk rc is %d, out_size is %zu.\n", rc, out_size);
		goto out;
	}

	rc = wrap_crypto_context(ssek, trk, &updated_crypto_ctx);
	if (rc != HWKEY_NO_ERROR) {
		TLOGE("exchange_crypto_context failed to wrap_crypto_context: %d.\n", rc);
		goto out;
	}

	*dst_len = sizeof(updated_crypto_ctx);
	memcpy_s(dst, *dst_len, &updated_crypto_ctx, sizeof(updated_crypto_ctx));

out:
	secure_memzero(&trk, sizeof(trk));
	secure_memzero(&ssek, sizeof(ssek));
	secure_memzero(aes_gcm_key, sizeof(aes_gcm_key));
	secure_memzero(&crypto_ctx, sizeof(struct crypto_context));
	secure_memzero(&updated_crypto_ctx, sizeof(updated_crypto_ctx));

	return rc;
}

/*
 *  List of keys slots that hwkey service supports
 */
static const struct hwkey_keyslot _keys[] = {
	{
		.uuid = &ss_uuid,
		.key_id = RPMB_SS_AUTH_KEY_ID,
		.handler = get_rpmb_ss_auth_key,
	},
};

/*
 *  Initialize Fake HWKEY service provider
 */
void hwkey_init_srv_provider(void)
{
	int rc;
	uint32_t seed_count, i;

	TLOGI("Init hwkey service provider\n");

#if LK_DEBUGLEVEL > 1
	/* run self test */
	if (!hwkey_self_test()) {
		TLOGE("hwkey_self_test failed\n");
		abort();
	}
#endif

	/* install key handlers */
	hwkey_install_keys(_keys, countof(_keys));

	/* start service */
	rc = hwkey_start_service();
	if (rc != NO_ERROR ) {
		TLOGE("failed (%d) to start HWKEY service\n", rc);
		abort();
	}

	if (get_seed_count(&seed_count))
		abort();

	for (i=1; i<seed_count; i++) {
		if (get_svn_by_index(i-1) <= get_svn_by_index(i)) {
			TLOGE("SVN(%u) and SVN(%u) are untrusted! %u <= %u.\n",
			i-1, i, get_svn_by_index(i-1), get_svn_by_index(i));
			abort();
		}
	}
}

