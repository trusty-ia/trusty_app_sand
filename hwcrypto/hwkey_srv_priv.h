/*
 * Copyright (C) 2016 The Android Open Source Project
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
#pragma once

#include <lk/compiler.h>
#include <sys/types.h>
#include <trusty_uuid.h>

struct hwkey_keyslot {
	const char *key_id;
	const uuid_t *uuid;
	const void *priv;
	uint32_t (*handler)(const struct hwkey_keyslot *slot,
			    uint8_t *kbuf, size_t kbuf_len, size_t *klen);
};

__BEGIN_CDECLS

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

/* RPMB Key support */
#define RPMB_SS_AUTH_KEY_SIZE    32
#define RPMB_SS_AUTH_KEY_ID      "com.android.trusty.storage_auth.rpmb"

void hwkey_init_srv_provider(void);

void hwkey_install_keys(const struct hwkey_keyslot *keys, uint kcnt);

int  hwkey_start_service(void);

uint32_t generate_crypto_context(uint8_t *data, size_t *data_len);

uint32_t exchange_crypto_context(const uint8_t *src, size_t src_len,
		uint8_t *dst, size_t *dst_len);


int aes_256_gcm_encrypt(const struct key *key,
		const struct iv *iv, const struct aad *aad,
		const void *plain, size_t plain_size,
		void *out, size_t *out_size);

int aes_256_gcm_decrypt(const struct key *key,
		const struct iv *iv, const struct aad *aad,
		const void *cipher, size_t cipher_size,
		void *out, size_t *out_size);

uint32_t get_aes_gcm_key(uint8_t index, uint8_t *aes_gcm_key, size_t key_len);

uint32_t get_ssek(uint8_t *ssek, size_t *ssek_len);

uint32_t derive_key_v1(const uuid_t *uuid,
		const uint8_t *ikm_data, size_t ikm_len,
		uint8_t *key_data, size_t *key_len);

uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot *slot,
		uint8_t *kbuf, size_t kbuf_len, size_t *klen);

__END_CDECLS


