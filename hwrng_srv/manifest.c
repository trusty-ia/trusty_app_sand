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


/* HWRNG Server App UUID: 	   {9e0c759f-9b97-4442-8bdf-cf6c30b99f63} */
#define HWRNG_SRV_APP_UUID \
    { 0x9e0c759f, 0x9b97, 0x4442, \
        { 0x8b, 0xdf, 0xcf, 0x6c, 0x30, 0xb9, 0x9f, 0x63 } }

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
    .uuid = HWRNG_SRV_APP_UUID,

    /* optional configuration options here */
    {
        /* 2 pages for heap */
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(8 * 4096),

        /* 1 pages for stack */
        TRUSTY_APP_CONFIG_MIN_STACK_SIZE(4 * 4096),
    },
};

