/*
 * Copyright (C) 2015 Intel Corporation
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

#include <trusty_app_manifest.h>
#include <stddef.h>
#include <stdio.h>


/* HWKEY Server App UUID: 	   {fdc03e8b-a9cf-4ace-b00d-5478c193c787} */
#define HWKEY_SRV_APP_UUID \
    { 0xfdc03e8b, 0xa9cf, 0x4ace, \
        { 0xb0, 0x0d, 0x54, 0x78, 0xc1, 0x93, 0xc7, 0x87 } }

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
    .uuid = HWKEY_SRV_APP_UUID,

    /* optional configuration options here */
    {
        /* four pages for heap */
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(4 * 4096),

        /* 2 pages for stack */
        TRUSTY_APP_CONFIG_MIN_STACK_SIZE(2 * 4096),
    },
};

