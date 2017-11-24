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

#include <trusty_std.h>
#include <interface/hwkey/hwkey.h>
#include <openssl/cipher.h>
#include <openssl/aes.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>

#include "common.h"
#include "hwkey_srv_priv.h"

#define LOCAL_TRACE  1
#define LOG_TAG      "hwkey_srv"

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

static int get_device_index_huk(uint8_t index, uint8_t *huk, uint32_t huk_len)
{
	int rc = 0;
	trusty_device_info_t dev_info = {0};

	if (index >= BOOTLOADER_SEED_MAX_ENTRIES)
		return HWKEY_ERR_NOT_VALID;

	if(!huk) {
		TLOGE("the input param is NULL\n", 0);
		return ERR_IO;
	}

	/* get device info */
	rc = get_device_info(&dev_info, GET_SEED);
	if (rc != NO_ERROR ) {
		TLOGE("failed (%d) to get device infomation\n", rc);
		rc = ERR_IO;
		goto clear_sensitive_data;
	}

	if (dev_info.size != sizeof(trusty_device_info_t)){
		TLOGE("trusty_device_info_t size is mismatched\n");
		rc = ERR_BAD_LEN;
		goto clear_sensitive_data;
	}

	/*
	 * Since seed_list is sorted by svn in descending order, so seed_list[0] will contain the
	 * current seed and highest svn.
	 */

	rc = memcpy_s(huk, huk_len, dev_info.seed_list[index].seed, huk_len);

clear_sensitive_data:
	memset(&dev_info, 0, sizeof(trusty_device_info_t));
	return rc;

}

static int get_seed_number(uint32_t *num)
{
	int rc;
	trusty_device_info_t dev_info = {0};

	/* get device info */
	rc = get_device_info(&dev_info, false);
	if (rc != NO_ERROR ) {
		TLOGE("failed (%d) to get device infomation.\n", rc);
		return rc;
	}
	assert(dev_info.num_seeds > 0 &&
		dev_info.num_seeds <= BOOTLOADER_SEED_MAX_ENTRIES);

	*num = dev_info.num_seeds;
	return HWKEY_NO_ERROR;
}

/*
 * Derive key with Index - HMAC SHA256 based Key derivation function with Seed[index]
 */
uint32_t derive_key_with_index(const uint32_t index, const uuid_t *uuid,
				const uint8_t *ikm_data, size_t ikm_len,
				uint8_t *key_buf, size_t *key_len)
{
	int rc = 0;
	uint8_t hw_device_key[BUP_MKHI_BOOTLOADER_SEED_LEN] = {0};
	uint32_t seed_num = 0;

	if (index >= BOOTLOADER_SEED_MAX_ENTRIES) {
		return HWKEY_ERR_NOT_VALID;
	}

	if (!ikm_len || get_seed_number(&seed_num)) {
		*key_len = 0;
		return HWKEY_ERR_BAD_LEN;
	}

	if (index < seed_num) {
		/* update the hw_device_key */
		rc = get_device_index_huk(index, hw_device_key, sizeof(hw_device_key));
		if (rc != NO_ERROR) {
			TLOGE("failed (%d) to get device HUK\n", rc);
			return rc;
		}

		if (!HKDF(key_buf, ikm_len, EVP_sha256(),
			  (const uint8_t *)hw_device_key, sizeof(hw_device_key),
			  (const uint8_t *)uuid, sizeof(uuid_t),
			  ikm_data, ikm_len)) {
			TLOGE("HDKF failed 0x%x\n", ERR_get_error());
			*key_len = 0;
			/* clear the sensitive data */
			memset(hw_device_key, 0, sizeof(hw_device_key));
			memset(key_buf, 0, ikm_len);
			return HWKEY_ERR_GENERIC;
		}
		memset(hw_device_key, 0, sizeof(hw_device_key));
	}

	*key_len = ikm_len;

	return HWKEY_NO_ERROR;
 }

/*
 * Derive key V1 - HMAC SHA256 based Key derivation function
 */
uint32_t derive_key_v1(const uuid_t *uuid,
			const uint8_t *ikm_data, size_t ikm_len,
			uint8_t *key_buf, size_t *key_len)
{
	return derive_key_with_index(0, uuid, ikm_data, ikm_len, key_buf, key_len);
}

static int get_device_huk(uint8_t *huk, uint32_t huk_len)
{
	return get_device_index_huk(0, huk, huk_len);
}

/*
 *  RPMB Key support
 */
#define RPMB_SS_AUTH_KEY_SIZE    32
#define RPMB_SS_AUTH_KEY_ID      "com.android.trusty.storage_auth.rpmb"

/* Secure storage service app uuid */
static const uuid_t ss_uuid = SECURE_STORAGE_SERVER_APP_UUID;

static const uuid_t crypto_uuid = HWCRYPTO_SRV_APP_UUID;

/*
 * Generate RPMB Secure Storage Authentication key from seed[index]
 */
static uint32_t get_rpmb_ss_auth_key_with_index(uint8_t index,
				uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	uint8_t rpmb_key[RPMB_SS_AUTH_KEY_SIZE] = {0};
	trusty_device_info_t dev_info = {0};
	int ret = HWKEY_ERR_GENERIC;
	uint8_t serial[MMC_PROD_NAME_WITH_PSN_LEN] = {0};

	assert(kbuf);
	assert(klen);

	if (NO_ERROR != get_device_info(&dev_info, true)) {
		TLOGE("failed to get device infomation\n");
		goto out;
	}

	if (index < dev_info.num_seeds) {
		/* Clear Byte 2 and 0 for CID[6] PRV and CID[0] CRC for eMMC Field Firmware Updates
		 * serial[0] = cid[0];  -- CRC
		 * serial[2] = cid[6];  -- PRV
		 */
		memcpy_s(serial, sizeof(serial), dev_info.serial, sizeof(dev_info.serial));
		serial[0] ^= serial[0];
		serial[2] ^= serial[2];

		if (!HKDF(rpmb_key, sizeof(rpmb_key), EVP_sha256(),
			  (const uint8_t *)dev_info.seed_list[index].seed, BUP_MKHI_BOOTLOADER_SEED_LEN,
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
	memset(rpmb_key, 0, sizeof(rpmb_key));
	memset(&dev_info, 0, sizeof(dev_info));

	return ret;
}

/*
 * Generate RPMB Secure Storage Authentication keys for all seeds
 */
static uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot *slot,
				     uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	uint32_t i;
	size_t klen_for_once = 0;

	assert(kbuf);
	assert(klen);

	*klen = 0;

	for (i = 0; i < BOOTLOADER_SEED_MAX_ENTRIES; i++) {
		if (HWKEY_NO_ERROR != get_rpmb_ss_auth_key_with_index(
					i, kbuf + i * RPMB_SS_AUTH_KEY_SIZE, kbuf_len, &klen_for_once)) {
			memset(kbuf, 0, kbuf_len);
			return HWKEY_ERR_GENERIC;
		}
		*klen += klen_for_once;
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
}

