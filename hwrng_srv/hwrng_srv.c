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

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_std.h>
#include <err.h>
#include <interface/hwrng/hwrng.h>

#define LOG_TAG "hwrng-srv"

#define TLOGI(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)


#define DRNG_MAX_TRIES 3
#define DRNG_HAS_RDRAND 0X1
#define DRNG_HAS_RDSEED  0X2

void __cpuid(uint32_t cpu_info[4], uint32_t leaf, uint32_t subleaf)
{
    __asm__ __volatile__ (
            "cpuid"
            : "=a" (cpu_info[0]),
            "=b" (cpu_info[1]),
            "=c" (cpu_info[2]),
            "=d" (cpu_info[3])
            : "a" (leaf), "c" (subleaf)
            );
}

static int get_drng_support(void)
{
    uint32_t drng_feature = 0;
    uint32_t info[4];

    /* CPUID: input in rax = 1. */
    __cpuid(info, 1, 0);

    /* CPUID: ECX.RDRAND[bit30] = 1? */
    if ((info[2] & 0x40000000) == 0x40000000)
        drng_feature |= DRNG_HAS_RDRAND;

    /* CPUID: input in rax = 7. rcx=0 */
    __cpuid(info, 7, 0);

    /* CPUID: EBX.RDREED[bit18] = 1? */
    if ((info[1] & 0x40000) == 0x40000)
        drng_feature |= DRNG_HAS_RDSEED;

    return drng_feature;
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
    uint32_t drng_feature = 0;
    drng_feature = get_drng_support();

    if (drng_feature & DRNG_HAS_RDSEED) {
        if (NO_ERROR != rdseed32(out)) {
            TLOGI("failed with rdseed32\n");
            return ERR_IO;
        }
    } else if (drng_feature & DRNG_HAS_RDRAND) {
        if (NO_ERROR != rdrand32(out)) {
            TLOGI("failed with rdrand32\n");
            return ERR_IO;
        }
    } else {
        TLOGI("DRNG_NO_SUPPORT!\n");
        return ERR_NOT_FOUND;
    }
    return NO_ERROR;
}

static int drng_rand_multiple4_buf(uint8_t *buf, size_t len)
{
    int i;

    if (len%4) {
        TLOGI("the len isn't multiple of 4bytes\n");
        return ERR_IO;
    }

    for (i=0; i<len; i+=4) {
        uint32_t tmp_buf=0;
        if (NO_ERROR != drng_rand32(&tmp_buf)) {
            TLOGI("failed with rdseed32\n");
            return ERR_IO;
        }
        memcpy(buf+i, &tmp_buf, sizeof(tmp_buf));
    }
    return NO_ERROR;
}

static int hw_get_random(uint8_t *buf, size_t len)
{
    TLOGI("try to generate a random with len=%d\n", len);
    if (len <= 4) {
        uint32_t tmp_buf;
        if (NO_ERROR != drng_rand32(&tmp_buf)) {
            TLOGI("failed with drng_rand32\n");
            return ERR_IO;
        }
        memcpy(buf, &tmp_buf, len);
        return NO_ERROR;
    }

    const size_t len_multiple4 = len & ~3;
    if (NO_ERROR != drng_rand_multiple4_buf(buf, len_multiple4)) {
        TLOGI("failed with drng_rand_multiple4_buf\n");
        return ERR_IO;
    }
    len -= len_multiple4;
    if (len != 0) {
        assert(len <  4);

        uint32_t tmp_buf;
        if (NO_ERROR != drng_rand32(&tmp_buf)) {
            TLOGI("failed with drng_rand32\n");
            return ERR_IO;
        }
        memcpy(buf + len_multiple4, &tmp_buf, len);
    }
    return NO_ERROR;
}

static long send_response(handle_t chan, uint8_t *resp_buf, uint32_t resp_size)
{
    iovec_t tx_iov = {
        .base = resp_buf,
        .len = resp_size,
    };
    ipc_msg_t tx_msg = {
        .num_iov = 1,
        .iov = &tx_iov,
    };

    long rc = send_msg(chan, &tx_msg);
    if (rc < 0) {
        TLOGI("failed to send_msg to chan\n");
        return rc;
    }

    if(((size_t) rc) != resp_size) {
        TLOGI("invalid resp msg size for (%d)\n", chan);
        return ERR_IO;
    }
    return NO_ERROR;
}

static long handle_msg(handle_t chan)
{
    int rc = 0;
    struct hwrng_req req_msg = {0};
    uint8_t *hwrng_buf;

    hwrng_buf = (uint8_t *)malloc(HWRNG_MAX_BUFFER_LENGTH);
    if (hwrng_buf == NULL) {
        TLOGI("failed to allocate mem for hwrng_buf\n");
        goto out;
    }
    memset(hwrng_buf, 0, HWRNG_MAX_BUFFER_LENGTH);

    ipc_msg_info_t msg_info;

    rc = get_msg(chan, &msg_info);
    if (rc == ERR_NO_MSG)
        goto out;/* no new messges */

    if (rc != NO_ERROR) {
        TLOGI("failed(%d) to get msg form chan (%d)\n", rc,chan);
        goto out;
    }

    iovec_t rx_iov = {
        .base = &req_msg,
        .len = sizeof(struct hwrng_req),
    };
    ipc_msg_t rx_msg = {
        .num_iov = 1,
        .iov = &rx_iov,
    };

    rc = read_msg(chan, msg_info.id, 0, &rx_msg);
    if (rc < 0) {
        TLOGI("failed (%d) to read msg from chan (%d)\n", rc, chan);
        goto out;
    }

    if ((size_t)rc != msg_info.len) {
        TLOGI("invalid msg size (%d)\n", rc);
        goto out;
    }

    if (req_msg.len > HWRNG_MAX_BUFFER_LENGTH || req_msg.len == 0) {
        TLOGI("invalid length(%d) of request random\n", req_msg.len);
        goto out;
    }
    rc = hw_get_random(hwrng_buf, req_msg.len);
    if (rc != NO_ERROR) {
        TLOGI("failed to get hw random\n");
        goto out;
    }

    /* send the response to the client TA */
    rc = send_response(chan, hwrng_buf, req_msg.len);
    if (rc < 0) {
        TLOGI("failed (%d) to send_response for chan (%d)\n", rc, chan);
        goto out;
    }

    /* retire original message */
    rc = put_msg(chan, msg_info.id);
    if (rc != NO_ERROR) {
        TLOGI("failed (%d) to put_msg from chan (%d)\n", rc, chan);
        goto out;
    }
    rc = NO_ERROR;

out:
    if (hwrng_buf)
        free(hwrng_buf);
    return rc;
}


static void hwrng_chan_handler(const uevent_t *ev)
{
    if (ev->event & IPC_HANDLE_POLL_MSG) {
        long rc = handle_msg(ev->handle);
        if (rc != NO_ERROR) {
            /* report an error and close channel */
            TLOGI("failed handle event on channel\n");
            close(ev->handle);
        }
        return;
    }

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        /* closed by peer. */
        close(ev->handle);
        return;
    }
}

static void hwrng_port_handler(const uevent_t *ev)
{
    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
            (ev->event & IPC_HANDLE_POLL_HUP) ||
            (ev->event & IPC_HANDLE_POLL_MSG) ||
            (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        /* should never happen with port handles */
        TLOGI("error event (0x%x) for port (%d)\n", ev->event, ev->handle);
        abort();
    }

    if (ev->event & IPC_HANDLE_POLL_READY) {
        uuid_t peer_uuid;

        /* incomming connection: accept it */
        int rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            TLOGI("failed (%d) to accept on port %d\n", rc, ev->handle);
            return;
        }
    }
}

/*
 *  Main entry point of service task
 */
int main(void)
{
    int rc;
    handle_t port;


    TLOGI("Initializing hwrng-srv:\n");

    /* create port */
    rc = port_create(HWRNG_PORT,1,
            HWRNG_MAX_BUFFER_LENGTH,
            IPC_PORT_ALLOW_TA_CONNECT);
    if (rc < 0) {
        TLOGI("Failed (%d) to create port %s\n", rc, HWRNG_PORT);
        abort();
    }
    port = (handle_t)rc;

    /* enter main event loop */
    while (true) {
        uevent_t event;

        event.handle = INVALID_IPC_HANDLE;
        event.event = 0;
        event.cookie = NULL;

        rc = wait_any(&event, -1);

        if (rc == NO_ERROR) {
            /* got an event */
            if (event.handle == port) {
                hwrng_port_handler(&event);
            } else {
                hwrng_chan_handler(&event);
            }
        } else {
            TLOGI("wait_any failed (%d)\n", rc);
            abort();
        }
    }

    return 0;
}

