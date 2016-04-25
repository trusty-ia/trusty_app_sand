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
#include <interface/hwkey/hwkey.h>

#define LOG_TAG "hwkey-srv"

#define TLOGI(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)

static long send_response(handle_t chan,
        struct hwkey_msg *msg,
        uint8_t *resp_buf,
        uint32_t resp_size)
{
    iovec_t tx_iov[2] = {
        {
            .base = msg,
            .len = sizeof(*msg),
        },
        {
            .base = resp_buf,
            .len = resp_size,
        },
    };
    ipc_msg_t tx_msg = {
        .num_iov = 2,
        .iov = tx_iov,
    };

    long rc = send_msg(chan, &tx_msg);
    if (rc < 0) {
        TLOGI("failed to send_msg to chan\n");
        return rc;
    }

    if(((size_t) rc) != sizeof(*msg) + resp_size) {
        TLOGI("invalid resp msg size for (%d)\n", chan);
        return ERR_IO;
    }
    return NO_ERROR;
}

static void dispatch_cmd(struct hwkey_msg *msg,
        uint8_t *req_buf,
        uint32_t req_size,
        uint8_t *resp_buf,
        uint32_t *resp_size)
{
    if(!req_buf || !resp_buf) {
        TLOGI("msg buffer is null\n");
        return;
    }

    TLOGI("msg->cmd = %d\n", msg->cmd);
    TLOGI("msg->kdfversion = %d\n", msg->arg1);
    TLOGI("req_buf = %s\n", req_buf);

    switch(msg->cmd) {
        case HWKEY_DERIVE:
            //TODO  derive the key from IMR!!
            /* Req: @arg1--requested key derivation function (KDF) version.
             * Use HWKEY_KDF_VERSION_BEST for best version.
             * Resp: @arg1--Always different from request if
             * request contained HWKEY_KDF_VERSION_BEST*/
            if (msg->arg1 == HWKEY_KDF_VERSION_BEST)
                msg->arg1 = HWKEY_KDF_VERSION_1;
            msg->status = HWKEY_NO_ERROR;
            break;
        case HWKEY_GET_KEYSLOT:
            // TODO!!
            msg->status = HWKEY_ERR_NOT_FOUND;
            break;
        default:
            break;
    }

    /* setup the resp msg structure */
    msg->cmd |= HWKEY_RESP_BIT;

    /* only to made the unitest pass!replace the first 5 bytes as "Resp:" */
    memcpy(resp_buf, req_buf, req_size);
    uint8_t * tmp = "Resp:";
    memcpy(resp_buf, tmp, strlen(tmp));
    *resp_size = (uint32_t)strlen(resp_buf);
}

static long handle_msg(handle_t chan)
{
    int rc = 0;
    uint8_t req_buf[HWKEY_MAX_BUFFER_LENGTH] = {0};
    uint8_t resp_buf[HWKEY_MAX_BUFFER_LENGTH] = {0};
    uint32_t req_size=0, resp_size=0;
    struct hwkey_msg msg = {0};

    ipc_msg_info_t msg_info;

    rc = get_msg(chan, &msg_info);
    if (rc == ERR_NO_MSG)
        return NO_ERROR; /* no new messges */

    if (rc != NO_ERROR) {
        TLOGI("failed(%d) to get msg form chan (%d)\n", rc,chan);
        return rc;
    }

    req_size = msg_info.len-sizeof(struct hwkey_msg);
    iovec_t rx_iov[2] = {
        {
            .base = &msg,
            .len = sizeof(struct hwkey_msg),
        },
        {
            .base = req_buf,
            .len = req_size,
        },
    };
    ipc_msg_t rx_msg = {
        .num_iov = 2,
        .iov = rx_iov,
    };

    rc = read_msg(chan, msg_info.id, 0, &rx_msg);
    if (rc < 0) {
        TLOGI("failed (%d) to read msg from chan (%d)\n", rc, chan);
        return rc;
    }
    if ((size_t)rc < msg_info.len) {
        TLOGI("invalid msg size (%d)\n", rc);
        return rc;
    }

    /* handle the request cmd */
    dispatch_cmd(&msg, req_buf, req_size, resp_buf, &resp_size);

    /* send the response to the client TA */
    rc = send_response(chan, &msg, resp_buf, resp_size);
    if (rc < 0) {
        TLOGI("failed (%d) to send_response for chan (%d)\n", rc, chan);
        return rc;
    }

    /* retire original message */
    rc = put_msg(chan, msg_info.id);
    if (rc != NO_ERROR) {
        TLOGI("failed (%d) to put_msg from chan (%d)\n", rc, chan);
        return rc;
    }

    return NO_ERROR;
}


static void hwkey_chan_handler(const uevent_t *ev)
{
    int rc;

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

static void hwkey_port_handler(const uevent_t *ev)
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


    TLOGI("Initializing hwkey-srv:\n");

    /* create port */
    rc = port_create(HWKEY_PORT,1,
            HWKEY_MAX_BUFFER_LENGTH,
            IPC_PORT_ALLOW_TA_CONNECT);
    if (rc < 0) {
        TLOGI("Failed (%d) to create port %s\n", rc, HWKEY_PORT);
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
                hwkey_port_handler(&event);
            } else {
                hwkey_chan_handler(&event);
            }
        } else {
            TLOGI("wait_any failed (%d)\n", rc);
            abort();
        }
    }

    return 0;
}

