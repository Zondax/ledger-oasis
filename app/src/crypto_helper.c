/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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
#include "crypto.h"
#include "tx.h"
#include "apdu_codes.h"
#include <os_io_seproxyhal.h>
#include "coin.h"
#include "parser_impl.h"
#include "sha512.h"

zxerr_t crypto_getBytesToSign(uint8_t *toSign, size_t toSignLen) {
#if defined(APP_CONSUMER)
    if (toSign == NULL || toSignLen < CX_SHA512_SIZE) {
        return zxerr_encoding_failed;
    }
    MEMZERO(toSign, toSignLen);

    uint8_t *message = tx_get_buffer() + CRYPTO_BLOB_SKIP_BYTES;
    uint16_t messageLength = tx_get_buffer_length() - CRYPTO_BLOB_SKIP_BYTES;
    SHA512_256(message, messageLength, toSign);

    if (parser_tx_obj.type == runtimeType) {
        message = tx_get_buffer() + parser_tx_obj.oasis.runtime.metaLen;
        messageLength = tx_get_buffer_length() - parser_tx_obj.oasis.runtime.metaLen;
        SHA512_256_with_context(parser_tx_obj.context.ptr, parser_tx_obj.context.len,
                                 message, messageLength, toSign);
    }
#endif
    return zxerr_ok;
}

const uint8_t *crypto_getSr25519BytesToSign(uint8_t *msgDigest, size_t msgDigestLen, size_t *ctxLen) {
#if defined(APP_CONSUMER)
    if (msgDigest == NULL || msgDigestLen < SR25519_BLAKE_HASH_LEN) {
        return NULL;
    }
    uint8_t *message = tx_get_buffer() + parser_tx_obj.oasis.runtime.metaLen;
    size_t messageLen= tx_get_buffer_length() - parser_tx_obj.oasis.runtime.metaLen;
    cx_hash_sha256(message, messageLen, msgDigest, msgDigestLen);
    *ctxLen = (size_t)parser_tx_obj.context.len;
    return parser_tx_obj.context.ptr;
#endif
    return NULL;
}
