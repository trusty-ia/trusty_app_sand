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

#include <stddef.h>
#include <stdio.h>
#include <trusty_app_manifest.h>

//58a31eee-eab0-45d2-8b87-733555d12ba4
#define BENCHMARK_TEST_APP_UUID \
        { 0x58a31eee, 0xeab0, 0x45d2, \
            { 0x8b, 0x87, 0x73, 0x35, 0x55, 0xd1, 0x2b, 0xa4 }}

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
	.uuid = BENCHMARK_TEST_APP_UUID,

	.config_options =
	/* optional configuration options here */
	{
		/* openssl need a larger heap */
		TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(64*4096),

		/* openssl need a larger stack */
		TRUSTY_APP_CONFIG_MIN_STACK_SIZE(16*4096),
	},
};
