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
#define LOG_TAG      "hwkey_srv_kgf"

extern struct crypto_context g_crypto_ctx;
extern const uint8_t trk_aad[16];
extern const uuid_t crypto_uuid;
extern const uint8_t ssek_aad[16];

uint32_t get_ssek(uint8_t *ssek, size_t *ssek_len)
{
	return HWKEY_ERR_NOT_IMPLEMENTED;
}

/*
 * Derive key V1 - HMAC SHA256 based Key derivation function
 */
uint32_t derive_key_v1(const uuid_t *uuid,
			const uint8_t *ikm_data, size_t ikm_len,
			uint8_t *key_buf, size_t *key_len)
{
	return HWKEY_ERR_NOT_IMPLEMENTED;
}

/*
 * Generate RPMB Secure Storage Authentication keys for all seeds
 */
uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot *slot,
				     uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	return HWKEY_ERR_NOT_IMPLEMENTED;
}
