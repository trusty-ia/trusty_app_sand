/*
 * Copyright (c) 2008-2012 Travis Geiselbrecht
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <assert.h>
#include <uapi/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <app/tests.h>

#define LOG_TAG      "benchmark"

const size_t BUFSIZE = (1024*4);
const uint ITER = 1024;
static int g_count = 0;

static void bench_asm(void)
{
    uint64_t count = rdtsc_start();

    for(uint i = 0; i < ITER*ITER; i++) {
        __asm__ volatile(
            "pushq %%rax;"
            "pushq %%rcx;"
            "xor %%rcx, %%rax;"
            "popq %%rcx;"
            "popq %%rax;;"
            :::"%rax", "%rcx"
            );
        }
    count = rdtsc_end() - count;

    TLOGI("%s took %llu cycles\n", __FUNCTION__, count);
}


static void bench_set_overhead(void)
{
    uint32_t *buf = malloc(BUFSIZE);
    if (!buf) {
        TLOGI("alloc buf with size %zd has failed\n", BUFSIZE);
        return;
    }

    uint64_t count = rdtsc_start();
    for (uint i = 0; i < ITER; i++) {
        __asm__ volatile("");
    }
    count = rdtsc_end() - count;

    TLOGI("%s took %llu cycles\n", __FUNCTION__, count);

    free(buf);
}

static void bench_memset(void)
{
    void *buf = malloc(BUFSIZE);
    if (!buf) {
        TLOGI("alloc buf with size %zd has failed\n", BUFSIZE);
        return;
    }

    uint64_t count = rdtsc_start();
    for (uint i = 0; i < ITER; i++) {
        memset(buf, 0, BUFSIZE);
    }
    count = rdtsc_end() - count;

    TLOGI("%s took %llu cycles\n", __FUNCTION__, count);

    free(buf);
}

static void bench_malloc(void)
{
    void *buf;

    uint64_t count = rdtsc_start();
    for (uint i = 0; i < ITER; i++) {
        buf = malloc(BUFSIZE+1024*i);
        if (!buf) {
            TLOGI("alloc buf with size %zd has failed\n", BUFSIZE+1024*i);
            break;
        }
        memset(buf, 0, BUFSIZE);

        free(buf);
    }
    count = rdtsc_end() - count;

    TLOGI("%s took %llu cycles\n", __FUNCTION__, count);
}


#define bench_cset(type) \
static void bench_cset_##type(void) \
{ \
    type *buf = malloc(BUFSIZE); \
    if (!buf) { \
        TLOGI("alloc buf with size %zd has failed\n", BUFSIZE); \
        return; \
    } \
\
    uint64_t count = rdtsc_start(); \
    for (uint i = 0; i < ITER; i++) { \
        for (uint j = 0; j < BUFSIZE / sizeof(*buf); j++) { \
            buf[j] = 0; \
        } \
    } \
    count = rdtsc_end() - count; \
 \
    TLOGI("%s took %llu cycles\n", __FUNCTION__, count); \
 \
    free(buf); \
}

bench_cset(uint8_t)
bench_cset(uint16_t)
bench_cset(uint32_t)
bench_cset(uint64_t)

static void bench_cset_wide(void)
{
    uint32_t *buf = malloc(BUFSIZE);
    if (!buf) {
        TLOGI("alloc buf with size %zd has failed\n", BUFSIZE);
        return;
    }

    uint64_t count = rdtsc_start();
    for (uint i = 0; i < ITER; i++) {
        for (uint j = 0; j < BUFSIZE / sizeof(*buf) / 8; j++) {
            buf[j*8] = 0;
            buf[j*8+1] = 0;
            buf[j*8+2] = 0;
            buf[j*8+3] = 0;
            buf[j*8+4] = 0;
            buf[j*8+5] = 0;
            buf[j*8+6] = 0;
            buf[j*8+7] = 0;
        }
    }
    count = rdtsc_end() - count;

    TLOGI("%s took %llu cycles\n", __FUNCTION__, count);

    free(buf);
}

static void bench_memcpy(void)
{
    uint8_t *buf = malloc(BUFSIZE);
    if (!buf) {
        TLOGI("alloc buf with size %zd has failed\n", BUFSIZE);
        return;
    }

    uint64_t count = rdtsc_start();
    for (uint i = 0; i < ITER; i++) {
        memcpy(buf, buf + BUFSIZE / 2, BUFSIZE / 2);
    }
    count = rdtsc_end() - count;

    TLOGI("%s took %llu cycles\n", __FUNCTION__, count);

    free(buf);
}

#if ARCH_ARM
static void arm_bench_cset_stm(void)
{
    uint32_t *buf = malloc(BUFSIZE);
    if (!buf) {
        TLOGI("alloc buf with size %zd has failed\n", BUFSIZE);
        return;
    }

    uint64_t count = rdtsc_start();
    for (uint i = 0; i < ITER; i++) {
        for (uint j = 0; j < BUFSIZE / sizeof(*buf) / 8; j++) {
            __asm__ volatile(
                "stm    %0, {r0-r7};"
                :: "r" (&buf[j*8])
            );
        }
    }
    count = rdtsc_end() - count;

    TLOGI("%s took %llu cycles\n", __FUNCTION__, count);

    free(buf);
}

static void arm_bench_multi_issue(void)
{
    uint32_t cycles;
    uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0;

#define ITER 1000000
    uint64_t count = ITER;
    cycles = rdtsc();
    while (count--) {
        asm volatile ("");
        asm volatile ("add %0, %0, %0" : "=r" (a) : "r" (a));
        asm volatile ("add %0, %0, %0" : "=r" (b) : "r" (b));
        asm volatile ("and %0, %0, %0" : "=r" (c) : "r" (c));
        asm volatile ("mov %0, %0" : "=r" (d) : "r" (d));
        asm volatile ("orr %0, %0, %0" : "=r" (e) : "r" (e));
        asm volatile ("add %0, %0, %0" : "=r" (f) : "r" (f));
        asm volatile ("and %0, %0, %0" : "=r" (g) : "r" (g));
        asm volatile ("mov %0, %0" : "=r" (h) : "r" (h));
    }
    cycles = rdtsc() - cycles;

    TLOGI("%s took %llu cycles\n", __FUNCTION__, count);
#undef ITER
}
#endif // ARCH_ARM

#if WITH_LIB_LIBM
#include <math.h>

static void bench_sincos(void)
{
    TLOGI("touching the floating point unit\n");
    __UNUSED volatile double _hole = sin(0);

    uint64_t count = rdtsc_start();
    __UNUSED double a = sin(2.0);
    count = rdtsc_end() - count;
    TLOGI("took %llu cycles for sin()\n", count);

    count = rdtsc_start();
    a = cos(2.0);
    count = rdtsc_end() - count;
    TLOGI("took %llu cycles for cos()\n", count);

    count = rdtsc_start();
    a = sinf(2.0);
    count = rdtsc_end() - count;
    TLOGI("took %llu cycles for sinf()\n", count);

    count = rdtsc_start();
    a = cosf(2.0);
    count = rdtsc_end() - count;
    TLOGI("took %llu cycles for cosf()\n", count);

    count = rdtsc_start();
    a = sqrt(1234567.0);
    count = rdtsc_end() - count;
    TLOGI("took %llu cycles for sqrt()\n", count);

    count = rdtsc_start();
    a = sqrtf(1234567.0f);
    count = rdtsc_end() - count;
    TLOGI("took %llu cycles for sqrtf()\n", count);
}

#endif // WITH_LIB_LIBM

void benchmarks(void)
{
    bench_asm();
    bench_set_overhead();
    bench_memset();
    bench_memcpy();
    bench_malloc();

    bench_cset_uint8_t();
    bench_cset_uint16_t();
    bench_cset_uint32_t();
    bench_cset_uint64_t();
    bench_cset_wide();

#if ARCH_ARM
    arm_bench_cset_stm();

    arm_bench_multi_issue();
#endif
#if WITH_LIB_LIBM
    bench_sincos();
#endif
}

