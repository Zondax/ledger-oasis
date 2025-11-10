/*******************************************************************************
 *   (c) 2016 Ledger
 *   (c) 2019 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "actions.h"

#include <os_io_seproxyhal.h>

#include "apdu_codes.h"
#include "coin.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "parser_impl.h"
#include "sha512.h"
#include "stdbool.h"
#include "tx.h"

uint16_t action_addrResponseLen;

void app_sign_ed25519() {
    uint8_t *signature = G_io_apdu_buffer;
    uint16_t replyLen = 0;

    uint8_t messageDigest[CX_SHA512_SIZE] = {0};
    crypto_getBytesToSign(messageDigest, sizeof(messageDigest));

    const zxerr_t err = crypto_signEd25519(signature, IO_APDU_BUFFER_SIZE - 3, messageDigest, CX_SHA256_SIZE, &replyLen);

    if (err != zxerr_ok || replyLen == 0) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
    }
}

void app_sign_secp256k1() {
    uint8_t *signature = G_io_apdu_buffer;
    uint16_t replyLen = 0;

    uint8_t messageDigest[CX_SHA512_SIZE] = {0};
    crypto_getBytesToSign(messageDigest, sizeof(messageDigest));

    zxerr_t err = crypto_signSecp256k1(signature, IO_APDU_BUFFER_SIZE - 3, messageDigest, CX_SHA256_SIZE, &replyLen);

    if (err != zxerr_ok || replyLen == 0) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
    }
}

void app_sign_sr25519() {
    uint8_t *signature = G_io_apdu_buffer;
    uint8_t messageDigest[CX_SHA512_SIZE] = {0};
    size_t ctx_len = 0;
    uint16_t replyLen = 0;

    const uint8_t *context = crypto_getSr25519BytesToSign(messageDigest, sizeof(messageDigest), &ctx_len);

    zxerr_t err =
        crypto_sign_sr25519(signature, IO_APDU_BUFFER_SIZE - 3, messageDigest, CX_SHA256_SIZE, context, ctx_len, &replyLen);

    if (err != zxerr_ok || replyLen == 0) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
    }
}

void app_reject() {
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

zxerr_t app_fill_address(address_kind_e kind) {
    zemu_log("app_fill_address\n");
    // Put data directly in the apdu buffer
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    action_addrResponseLen = 0;

    zxerr_t err = crypto_fillAddress(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, &action_addrResponseLen, kind);

    if (err != zxerr_ok || action_addrResponseLen == 0) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    return zxerr_ok;
}

void app_sign_eth() {
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();
    uint16_t replyLen = 0;

    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    zxerr_t err = crypto_sign_eth(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength, &replyLen);

    if (err != zxerr_ok || replyLen == 0) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_SIGN_VERIFY_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
    }
}

void app_reply_address() {
    if (action_addrResponseLen == 0) {
        THROW(APDU_CODE_DATA_INVALID);
    }
    set_code(G_io_apdu_buffer, action_addrResponseLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addrResponseLen + 2);
}

void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}
