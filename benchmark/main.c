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


#include <assert.h>
#include <uapi/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <app/tests.h>

#if !defined(BUILD_FOR_ANDROID)
#include <trusty_std.h>
#endif

#define LOCAL_TRACE  1
#define LOG_TAG      "benchmark-main"

uint64_t rdtsc_start(void)
{
    unsigned int low, high;
    __asm__ volatile(
        "cpuid;"
        "rdtsc;"
        "mov %%edx, %0;"
        "mov %%eax, %1;"
        : "=r"(high), "=r"(low)
        ::"%rax", "%rbx", "%rcx", "%rdx");
    return (low | ((uint64_t)high) << 32);
}

uint64_t rdtsc_end(void)
{
    unsigned int low, high;
    __asm__ volatile(
        "rdtscp;"
        "mov %%edx, %0;"
        "mov %%eax, %1;"
        "cpuid;"
        : "=r"(high), "=r"(low)
        ::"%rax", "%rbx", "%rcx", "%rdx");
    return (low | ((uint64_t)high) << 32);
}

int main(void)
{
    int rc = 0;
    TLOGI("======benchmark test start:=======\n");

    benchmarks();
    rsa_test();

    TLOGI("======benchmark test end=======\n");
    return rc;
}
