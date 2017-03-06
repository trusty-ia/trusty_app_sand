
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "hwrng_srv_priv.h"

#define LOCAL_TRACE  1
#define LOG_TAG      "hwrng_srv"

#define DRNG_MAX_TRIES 3
#define DRNG_HAS_RDRAND 0X1
#define DRNG_HAS_RDSEED  0X2

static uint32_t g_drng_feature = 0;

void __cpuid(uint64_t cpu_info[4], uint64_t leaf, uint64_t subleaf)
{
	__asm__ __volatile__ (
			"pushq %%rbx;" /* save the ebx */
			"cpuid;"
			"mov %%rbx, %1;" /* save what cpuid just put in ebx */
			"popq %%rbx;" /* restore the old ebx */
			: "=a" (cpu_info[0]),
			"=r" (cpu_info[1]),
			"=c" (cpu_info[2]),
			"=d" (cpu_info[3])
			: "a" (leaf), "c" (subleaf)
			: "cc"
			);
}

static void get_drng_support(void)
{
	uint64_t info[4];

	/* CPUID: input in rax = 1. */
	__cpuid(info, 1, 0);

	/* CPUID: ECX.RDRAND[bit30] = 1? */
	if ((info[2] & 0x40000000) == 0x40000000)
		g_drng_feature |= DRNG_HAS_RDRAND;

	/* CPUID: input in rax = 7. rcx=0 */
	__cpuid(info, 7, 0);

	/* CPUID: EBX.RDREED[bit18] = 1? */
	if ((info[1] & 0x40000) == 0x40000)
		g_drng_feature |= DRNG_HAS_RDSEED;
}

static int rdseed32(uint32_t *out)
{
	uint8_t ret;
	int i;

	for (i=0; i<DRNG_MAX_TRIES; i++) {
		__asm__ __volatile__ (
				"RDSEED %0;"
				"setc %1;"
				: "=r"(*out), "=qm"(ret)
				);
		if(ret)
			return NO_ERROR;
	}
	return ERR_IO;
}

static int rdseed64(uint64_t *out)
{
	uint8_t ret;
	int i;

	for (i=0; i<DRNG_MAX_TRIES; i++) {
		__asm__ __volatile__ (
				"RDSEED %0;"
				"setc %1;"
				: "=r"(*out), "=qm"(ret)
				);
		if(ret)
			return NO_ERROR;
	}
	return ERR_IO;
}

static int rdrand32(uint32_t *out)
{
	uint8_t ret;
	int i;

	for (i=0; i<DRNG_MAX_TRIES; i++) {
		__asm__ __volatile__ (
				"RDRAND %0;"
				"setc %1;"
				: "=r"(*out), "=qm"(ret)
				);
		if(ret)
			return NO_ERROR;
	}
	return ERR_IO;
}

static int rdrand64(uint64_t *out)
{
	uint8_t ret;
	int i;

	for (i=0; i<DRNG_MAX_TRIES; i++) {
		__asm__ __volatile__ (
				"RDRAND %0;"
				"setc %1;"
				: "=r"(*out), "=qm"(ret)
				);
		if(ret)
			return NO_ERROR;
	}
	return ERR_IO;
}

static int drng_rand32(uint32_t *out)
{
	if (g_drng_feature & DRNG_HAS_RDSEED) {
		if (NO_ERROR != rdseed32(out)) {
			TLOGE("failed with rdseed32\n");
			return ERR_IO;
		}
	} else if (g_drng_feature & DRNG_HAS_RDRAND) {
		if (NO_ERROR != rdrand32(out)) {
			TLOGE("failed with rdrand32\n");
			return ERR_IO;
		}
	} else {
		TLOGE("DRNG_NO_SUPPORT!\n");
		return ERR_NOT_FOUND;
	}
	return NO_ERROR;
}

static int drng_rand_multiple4_buf(uint8_t *buf, size_t len)
{
	int i;

	if (len%4) {
		TLOGE("the len isn't multiple of 4bytes\n");
		return ERR_IO;
	}

	for (i=0; i<len; i+=4) {
		uint32_t tmp_buf=0;
		if (NO_ERROR != drng_rand32(&tmp_buf)) {
			TLOGE("failed with rdseed32\n");
			return ERR_IO;
		}
		memcpy(buf+i, &tmp_buf, sizeof(tmp_buf));
	}
	return NO_ERROR;
}

int hwrng_dev_get_rng_data(uint8_t *buf, size_t len)
{
	TLOGI("try to generate a random with len=%d\n", len);
	if (len <= 4) {
		uint32_t tmp_buf;
		if (NO_ERROR != drng_rand32(&tmp_buf)) {
			TLOGE("failed with drng_rand32\n");
			return ERR_IO;
		}
		memcpy(buf, &tmp_buf, len);
		return NO_ERROR;
	}

	const size_t len_multiple4 = len & ~3;
	if (NO_ERROR != drng_rand_multiple4_buf(buf, len_multiple4)) {
		TLOGE("failed with drng_rand_multiple4_buf\n");
		return ERR_IO;
	}
	len -= len_multiple4;
	if (len != 0) {
		assert(len <  4);

		uint32_t tmp_buf;
		if (NO_ERROR != drng_rand32(&tmp_buf)) {
			TLOGE("failed with drng_rand32\n");
			return ERR_IO;
		}
		memcpy(buf + len_multiple4, &tmp_buf, len);
	}
	return NO_ERROR;
}

void hwrng_init_srv_provider(void)
{
	int rc;

	TLOGI("Init hwrng service provider\n");

	/* Nothing to initialize here, just start service */
	rc = hwrng_start_service();
	if (rc != NO_ERROR) {
		TLOGE("failed (%d) to start HWRNG service\n", rc);
		abort();
	}

	/* get the drng feature support */
	get_drng_support();
}

