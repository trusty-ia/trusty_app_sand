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
#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <trusty_key_migration.h>
#include <trusty_std.h>
#include <interface/hwkey/hwkey.h>
#include <openssl/cipher.h>
#include <openssl/aes.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>
#include <openssl/evp.h>

#include "common.h"
#include "hwkey_srv_priv.h"
#include "hwrng_srv_priv.h"

#define LOCAL_TRACE  1
#define LOG_TAG      "hwkey_srv"

static struct crypto_context g_crypto_ctx = {0};

struct key {
	uint8_t byte[32];
};

struct iv {
	uint8_t byte[12];
};

struct aad {
	uint8_t byte[16];
};

struct tag {
	uint8_t byte[16];
};

#define AES_GCM_NO_ERROR           0
#define AES_GCM_ERR_GENERIC        -1
#define AES_GCM_ERR_AUTH_FAILED    -2

static const struct aad trk_aad = {
	.byte = {
		0xf3, 0x56, 0x5b, 0xd9, 0xc4, 0xe7, 0xd4, 0x1e,
		0xbb, 0xb4, 0x14, 0x15, 0x20, 0xe7, 0x09, 0xcf,
	}
};

static const struct aad ssek_aad = {
	.byte = {
		0x8d, 0x46, 0x2b, 0xd1, 0xb3, 0xde, 0x0f, 0x5c,
		0xc1, 0x6d, 0x56, 0xcc, 0x2e, 0x53, 0x05, 0x54,
	}
};

static const uint8_t gcm_info[] = {0xc7, 0x87, 0xaf, 0xe7, 0x3b, 0xca, 0x44, 0x63,
				   0x35, 0x16, 0x0b, 0x94, 0x52, 0x53, 0x4d, 0xa3};

/* RPMB Key support */
#define RPMB_SS_AUTH_KEY_SIZE    32
#define RPMB_SS_AUTH_KEY_ID      "com.android.trusty.storage_auth.rpmb"

/* Secure storage service app uuid */
static const uuid_t ss_uuid = SECURE_STORAGE_SERVER_APP_UUID;
static const uuid_t crypto_uuid = HWCRYPTO_SRV_APP_UUID;

#if LK_DEBUGLEVEL > 1

/* This input vector is taken from RFC 5869 (Extract-and-Expand HKDF) */
static const uint8_t IKM[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

static const uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c };

static const uint8_t info[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

/* Expected pseudorandom key */
static const uint8_t exp_PRK[] = { 0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
				   0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
				   0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
				   0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5 };

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
		TLOGE("hkdf: data mismatch\n", __func__);
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

/**
 * aes_256_gcm_encrypt - Helper function for encrypt.
 * @key:          Key object.
 * @iv:           Initialization vector to use for Cipher Block Chaining.
 * @aad:          AAD to use for infomation.
 * @plain:        Data to encrypt, it is only plaintext.
 * @plain_size:   Number of bytes in @plain.
 * @out:          Data out, it contains ciphertext and tag.
 * @out_size:     Number of bytes out @out.
 *
 * Return: 0 on success, < 0 if an error was detected.
 */
static int aes_256_gcm_encrypt(const struct key *key,
			const struct iv *iv, const struct aad *aad,
			const void *plain, size_t plain_size,
			void *out, size_t *out_size)
{
	int rc = AES_GCM_ERR_GENERIC;
	EVP_CIPHER_CTX *ctx;
	int out_len, cur_len, data_len;
	uint8_t out_buf[32] = {0};
	uint8_t gcm_data[48] = {0};
	uint8_t *tag;

	if ((key ==  NULL) ||  (iv ==  NULL) || (plain ==  NULL) ||
		(plain_size > 32) ||  (out ==  NULL) || (out_size ==  NULL)) {
		TLOGE("invalid args!\n");
		return AES_GCM_ERR_GENERIC;
	}

	/*creat cipher ctx*/
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		TLOGE("fail to create CTX....\n");
		goto exit;
	}

	/* Set cipher, key and iv */
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
					(unsigned char *)key, (unsigned char *)iv)) {
		TLOGE("CipherInit fail\n");
		goto exit;
	}

	/* set iv length.*/
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(struct iv), NULL)) {
		TLOGE("set iv length fail\n");
		goto exit;
	}

	/* set to aad info.*/
	if (NULL != aad) {
		if (!EVP_EncryptUpdate(ctx, NULL, &out_len, (uint8_t *)aad, sizeof(struct aad))) {
			TLOGE("set aad info fail\n");
			goto exit;
		}
	}

	/* Encrypt plaintext */
	data_len = plain_size;
	if (!EVP_EncryptUpdate(ctx, out_buf, &out_len, plain, data_len)) {
		TLOGE("Encrypt plain text fail.\n");
		goto exit;
	}

	if (memcpy_s(gcm_data, sizeof(gcm_data), out_buf, out_len)) {
		TLOGE("fail to copy encrypt data.\n");
		goto exit;
	}

	cur_len = out_len;
	tag = gcm_data + cur_len;
	/* get no output for GCM */
	if (!EVP_EncryptFinal_ex(ctx, out_buf, &out_len)) {
		TLOGE("EncryptFinal fail.\n");
		goto exit;
	}

	/*get TAG*/
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(struct tag), out_buf)) {
		TLOGE("get TAG fail.\n");
		rc = AES_GCM_ERR_AUTH_FAILED;
		goto exit;
	}

	if (memcpy_s(tag, sizeof(gcm_data) - cur_len, out_buf, sizeof(struct tag))) {
		TLOGE("fail to copy encrypt tag.\n");
		goto exit;
	}
	cur_len += sizeof(struct tag);

	/*set data of out*/
	if (memcpy_s(out, cur_len, gcm_data, cur_len)) {
		TLOGE("fail to copy out data.\n");
		goto exit;
	}
	*out_size = cur_len;

	rc = AES_GCM_NO_ERROR;

exit:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	secure_memzero(&gcm_data, sizeof(gcm_data));
	secure_memzero(&out_buf, sizeof(out_buf));

	return rc;
}

/**
 * aes_256_gcm_decrypt - Helper function for decrypt.
 * @key:          Key object.
 * @iv:           Initialization vector to use for Cipher Block Chaining.
 * @aad:          AAD to use for infomation.
 * @cipher:       Data in to decrypt, it contains ciphertext and tag.
 * @cipher_size:  Number of bytes in @cipher.
 * @out:          Data out, it is only plaintext.
 * @out_size:     Number of bytes out @out.
 *
 * Return: 0 on success, < 0 if an error was detected.
 */
static int aes_256_gcm_decrypt(const struct key *key,
			const struct iv *iv, const struct aad *aad,
			const void *cipher, size_t cipher_size,
			void *out, size_t *out_size)
{
	int rc = AES_GCM_ERR_GENERIC;
	EVP_CIPHER_CTX *ctx;
	int out_len, cur_len, data_len;
	uint8_t out_buf[32] = {0};
	uint8_t gcm_data[32] = {0};
	uint8_t *tag;

	if ((key ==  NULL) ||  (iv ==  NULL) || (cipher ==  NULL) ||
		(cipher_size < 48) ||  (out ==  NULL) || (out_size ==  NULL)) {
		TLOGE("invalid args!\n");
		return AES_GCM_ERR_GENERIC;
	}

	/*creat cipher ctx*/
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		TLOGE("fail to create CTX....\n");
		goto exit;
	}

	/* Set cipher, key and iv */
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
					(unsigned char *)key, (unsigned char *)iv)) {
		TLOGE("CipherInit fail\n");
		goto exit;
	}

	/* set iv length.*/
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(struct iv), NULL)) {
		TLOGE("set iv length fail\n");
		goto exit;
	}

	/* set to aad info.*/
	if (NULL != aad) {
		if (!EVP_EncryptUpdate(ctx, NULL, &out_len, (uint8_t *)aad, sizeof(struct aad))) {
			TLOGE("set aad info fail\n");
			goto exit;
		}
	}

	/* Decrypt plaintext */
	data_len = cipher_size - sizeof(struct tag);
	if (!EVP_DecryptUpdate(ctx, out_buf, &out_len, cipher, data_len)) {
		TLOGE("Decrypt cipher text fail.\n");
		goto exit;
	}

	if (memcpy_s(gcm_data, sizeof(gcm_data), out_buf, out_len)) {
		TLOGE("fail to copy decrypt data.\n");
		goto exit;
	}
	cur_len = out_len;
	tag = cipher + data_len;

	/*set TAG*/
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(struct tag), tag)) {
		TLOGE("set TAG fail.\n");
		goto exit;
	}

	/* Check TAG */
	if (!EVP_DecryptFinal_ex(ctx, out_buf, &out_len)) {
		TLOGE("fail to check TAG.\n");
		rc = AES_GCM_ERR_AUTH_FAILED;
		goto exit;
	}

	/*set data of out*/
	if (memcpy_s(out, cur_len, gcm_data, cur_len)) {
		TLOGE("fail to copy out data.\n");
		goto exit;
	}
	*out_size = cur_len;

	rc = AES_GCM_NO_ERROR;

exit:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	secure_memzero(&gcm_data, sizeof(gcm_data));
	secure_memzero(&out_buf, sizeof(out_buf));

	return rc;
}

static int get_device_index_huk(uint8_t index, uint8_t *huk, uint32_t huk_len)
{
	int rc = 0;
	trusty_device_info_t dev_info;

	if (index >= CSE_SEED_MAX_ENTRIES)
		return HWKEY_ERR_NOT_VALID;

	if(!huk) {
		TLOGE("the input param is NULL\n");
		return ERR_IO;
	}

	/* get device info */
	rc = get_device_info(&dev_info, GET_SEED);
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

	rc = memcpy_s(huk, huk_len, dev_info.sec_info.dseed_list[index].seed, huk_len);

clear_sensitive_data:
	secure_memzero(&dev_info, sizeof(trusty_device_info_t));
	return rc;
}

static int get_seed_count(uint32_t *num)
{
	int rc;
	trusty_device_info_t dev_info;

	/* get device info */
	rc = get_device_info(&dev_info, GET_NONE);
	if (rc != NO_ERROR ) {
		TLOGE("failed (%d) to get device infomation.\n", rc);
		return rc;
	}

	// this log will be removed after all platforms are fully enabled.
	TLOGE("%s: The sec info platform is (%d)\n", __func__, dev_info.sec_info.platform);

	assert(dev_info.sec_info.num_seeds > 0 &&
		dev_info.sec_info.num_seeds <= CSE_SEED_MAX_ENTRIES);

	*num = dev_info.sec_info.num_seeds;
	return HWKEY_NO_ERROR;
}

static uint8_t get_svn_by_index(uint8_t index)
{
	trusty_device_info_t dev_info;
	uint8_t svn;

	assert(index < CSE_SEED_MAX_ENTRIES);

	/* get device info for svn*/
	if (NO_ERROR != get_device_info(&dev_info, GET_SEED)) {
		TLOGE("failed to get device infomation.\n");
		secure_memzero(&dev_info, sizeof(dev_info));
		assert(0);
	}

	svn = dev_info.sec_info.dseed_list[index].cse_svn;
	secure_memzero(&dev_info, sizeof(dev_info));

	return svn;
}

/* aes gcm key for crypto is derived from seed[index] */
static uint32_t get_aes_gcm_key(uint8_t index, uint8_t *aes_gcm_key, size_t key_len)
{
	int rc = -1;
	uint8_t hw_device_key[32] = {0};

	assert(aes_gcm_key);

	if (get_device_index_huk(index, hw_device_key, sizeof(hw_device_key))) {
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
static uint32_t wrap_crypto_context(const struct key ssek, const struct key trk,
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

	rc = aes_256_gcm_encrypt((const struct key *)aes_gcm_key,
				(const struct iv *)crypto_ctx->ssek_iv, &ssek_aad,
				(const void *)&ssek, sizeof(ssek),
				crypto_ctx->ssek_cipher, &out_size);
	if (AES_GCM_NO_ERROR != rc || out_size != sizeof(crypto_ctx->ssek_cipher)) {
		TLOGE("failed to encrypt ssek: rc is %d. out_size is %zu.\n", rc, out_size);
		goto out;
	}

	rc = aes_256_gcm_encrypt((const struct key *)aes_gcm_key,
				(const struct iv *)crypto_ctx->trk_iv, &trk_aad,
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
	struct key ssek, trk;
	int rc = -1;
	struct crypto_context crypto_ctx = {0};

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
	struct key ssek, trk;
	size_t out_size;
	int rc = -1;
	uint8_t aes_gcm_key[32] = {0};
	struct crypto_context updated_crypto_ctx = {0};
	struct crypto_context crypto_ctx = {0};
	uint8_t svn;

	assert(dst && dst_len && src && (src_len == sizeof(struct crypto_context)));

	memcpy_s(&crypto_ctx, sizeof(struct crypto_context), src, src_len);
	// get crypto_context from SS
	svn = get_svn_by_index(0);
	if (crypto_ctx.svn == svn) {
		TLOGE("seed is not changed, copy src to dst.\n");
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

	TLOGI("Seed Changed!!!\n");
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

	rc = aes_256_gcm_decrypt((const struct key *) aes_gcm_key,
				(const struct iv *) crypto_ctx.ssek_iv, &ssek_aad,
				(const void *) crypto_ctx.ssek_cipher, sizeof(crypto_ctx.ssek_cipher),
				&ssek, &out_size);
	if (rc != AES_GCM_NO_ERROR || out_size != sizeof(ssek)) {
		TLOGE("failed to decrypt ssek rc is %d, out_size is %zu.\n", rc, out_size);
		goto out;
	}

	rc = aes_256_gcm_decrypt((const struct key *) aes_gcm_key,
					(const struct iv *) crypto_ctx.trk_iv, &trk_aad,
					(const void *) crypto_ctx.trk_cipher, sizeof(crypto_ctx.trk_cipher),
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
#ifdef TARGET_PRODUCE_ICL
uint32_t derive_key_v1(const uuid_t *uuid,
			const uint8_t *ikm_data, size_t ikm_len,
			uint8_t *key_buf, size_t *key_len)
{
	*key_len = ikm_len;
	memset(key_buf, 0, ikm_len);

	return HWKEY_NO_ERROR;
}
#else
uint32_t derive_key_v1(const uuid_t *uuid,
			const uint8_t *ikm_data, size_t ikm_len,
			uint8_t *key_buf, size_t *key_len)
{

	struct key trk;
	size_t out_size = 0;
	uint8_t aes_gcm_key[32] = {0};
	int rc = -1;

	assert(ikm_data && key_buf && key_buf);

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
		TLOGE("aes_256_gcm_decrypt failed to decrypt ssek, rc is %d. out_size is %zu.\n", rc, out_size);
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
#endif

static int get_device_huk(uint8_t *huk, uint32_t huk_len)
{
	return get_device_index_huk(0, huk, huk_len);
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

	if (NO_ERROR != get_device_info(&dev_info, GET_SEED)) {
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
static uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot *slot,
				     uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	uint32_t i;
	trusty_device_info_t dev_info;
	size_t klen_for_once = 0;

	assert(kbuf);
	assert(klen);

	*klen = 0;

	if (NO_ERROR != get_device_info(&dev_info, GET_NONE)) {
		TLOGE("%s:failed to get device infomation\n", __func__);
		return HWKEY_ERR_GENERIC;
	}

	if (dev_info.sec_info.platform == APL_PLATFORM) {
		for (i = 0; i < dev_info.sec_info.num_seeds; i++) {
			if (HWKEY_NO_ERROR != get_rpmb_ss_auth_key_with_index(
						i, kbuf + i * RPMB_SS_AUTH_KEY_SIZE, kbuf_len, &klen_for_once)) {
				secure_memzero(kbuf, kbuf_len);
				return HWKEY_ERR_GENERIC;
			}
			*klen += klen_for_once;
		}
	} else {
		//TODO: ICL and CWP rpmb key.
		TLOGE("%s: platform is not APL!\n", __func__);
		assert(0);
	}

	return HWKEY_NO_ERROR;
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
#ifndef TARGET_PRODUCE_ICL
	uint32_t seed_count, i;
#endif

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

#ifndef TARGET_PRODUCE_ICL
	if (get_seed_count(&seed_count))
		abort();

	for (i=1; i<seed_count; i++) {
		if (get_svn_by_index(i-1) <= get_svn_by_index(i)) {
			TLOGE("SVN(%u) and SVN(%u) are untrusted! %u <= %u.\n",
			i-1, i, get_svn_by_index(i-1), get_svn_by_index(i));
			abort();
		}
	}
#endif
}

