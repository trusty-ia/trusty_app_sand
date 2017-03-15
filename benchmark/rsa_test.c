#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <app/tests.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/obj.h>

#define LOG_TAG      "rsa_test"

#define NUM2 1
#define RSA_3 0x3
#define RSA_F4  0x10001

static int test_mod_exp_mont_consttime()
{
    int ret = 0;
    int i;
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();

    uint64_t start, end;

    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        TLOGI("ctx init has failed\n");
    }

    if (!a || !b || !c || !d || !e ||
    !BN_rand(c, 30, 0, 1)) {  // must be odd for montgomery
        TLOGI("failed to init BigNum\n");
        return 1;
    }

    for (i=0; i<NUM2; i++) {
        ret = BN_rand(a, 20 + i * 5, 0, 0);
        if (!ret) {
            TLOGI("failed to generate rand of a\n");
            return 2;
        }
        ret = BN_rand(b, 2 + i, 0, 0);
        if (!ret) {
            TLOGI("failed to generate rand of b\n");
            return 3;
        }

        start = rdtsc_start();
        ret = BN_mod_exp_mont_consttime(d, a, b, c, ctx, NULL);
        end = rdtsc_end();

        TLOGI("SW: BN_mod_exp_mont_consttime cost %lld\n", end-start);
        if (!ret) {
            TLOGI("failed to test BN_mod_exp_mont_consttime\n");
            return 4;
        }
    }

    return 0;
}

static int test_large_key()
{
    int ret = 0;
    BIGNUM e_f0;
    RSA* pre_key_2k;
    RSA* pre_key_3k;
    RSA* pre_key_4k;
    uint64_t start, end;
    int i = 0;

    pre_key_2k = RSA_new();
    pre_key_3k = RSA_new();
    pre_key_4k = RSA_new();

    BN_init(&e_f0);
    BN_set_word(&e_f0, RSA_3);

    TLOGI("soft: start to generate pre_key_2k:\n");
    start = rdtsc_start();
    for (i=0; i<NUM2; i++) {
        if (!RSA_generate_key_ex(pre_key_3k, 2048, &e_f0, NULL)) {
            TLOGI("RSA_generate_key_ex failed.\n");
            ret = -1;
        }
    }
    end = rdtsc_end();
    TLOGI("generate pre_key_2k cost %lld ms\n", (end-start)/TSC_TO_MS/NUM2);

    TLOGI("start to generate pre_key_3k:\n");
    start = rdtsc_start();
    for (i=0; i<NUM2; i++) {
        if (!RSA_generate_key_ex(pre_key_3k, 3072, &e_f0, NULL)) {
            TLOGI("RSA_generate_key_ex failed.\n");
            ret = -1;
        }
    }
    end = rdtsc_end();
    TLOGI("generate pre_key_3k cost %lld ms\n", (end-start)/TSC_TO_MS/NUM2);

    TLOGI("start to generate pre_key_4k:\n");
    start = rdtsc_start();
    for (i=0; i<NUM2; i++) {
        if (!RSA_generate_key_ex(pre_key_4k, 4096, &e_f0, NULL)) {
            TLOGI("RSA_generate_key_ex failed.\n");
            ret = -2;
        }
    }
    end = rdtsc_end();
    TLOGI("generate pre_key_4k cost %lld ms\n", (end-start)/TSC_TO_MS/NUM2);

    BN_free(&e_f0);

    if(pre_key_2k)
        RSA_free(pre_key_2k);
    if(pre_key_3k)
        RSA_free(pre_key_3k);
    if(pre_key_4k)
        RSA_free(pre_key_4k);
    return ret;
}

void rsa_test(void)
{
    test_large_key();
    test_mod_exp_mont_consttime();
}

