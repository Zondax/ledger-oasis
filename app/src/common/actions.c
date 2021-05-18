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
#include "crypto.h"
#include "tx.h"
#include "apdu_codes.h"
#include <os_io_seproxyhal.h>
#include "coin.h"
#include "stdbool.h"

#ifdef APP_VALIDATOR
#include "validator/vote.h"
#include "validator/vote_fsm.h"
#include "parser_impl.h"
#endif

uint16_t action_addrResponseLen;

void app_sign() {

#ifdef APP_VALIDATOR
    if(parser_tx_obj.type == consensusType) {
        //If vote_state is not initialized, set new valid vote
        if(!vote_state.isInitialized) {
            vote_state.vote = vote;
            vote_state.isInitialized = true;
            set_code(G_io_apdu_buffer, 0, APDU_CODE_CONDITIONS_NOT_SATISFIED);
            io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
            return;
        }

        if (!try_state_transition()) {
            //Return current vote_state along with the conflicting vote data
            // [vote_state][vote][error]
            MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
            G_io_apdu_buffer[0] = vote.Type;
            uint16_t offset = 1;
            memcpy(&G_io_apdu_buffer[offset], &vote.Height, sizeof(vote.Height));
            offset += sizeof(vote.Height);
            memcpy(&G_io_apdu_buffer[offset], &vote.Round, sizeof(vote.Round));
            offset += sizeof(vote.Round);
            G_io_apdu_buffer[offset] = vote_state.vote.Type;
            offset += 1;
            memcpy(&G_io_apdu_buffer[offset], &vote_state.vote.Height, sizeof(vote.Height));
            offset += sizeof(vote.Height);
            memcpy(&G_io_apdu_buffer[offset], &vote_state.vote.Round, sizeof(vote.Round));
            offset += sizeof(vote.Round);
            set_code(G_io_apdu_buffer, offset, APDU_CODE_COMMAND_NOT_ALLOWED);
            io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, offset + 2);
            return;
        }
}
#endif

    uint8_t *signature = G_io_apdu_buffer;

    const uint8_t *message = tx_get_buffer() + CRYPTO_BLOB_SKIP_BYTES;
    const uint16_t messageLength = tx_get_buffer_length() - CRYPTO_BLOB_SKIP_BYTES;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_sign(signature, IO_APDU_BUFFER_SIZE - 3, message, messageLength, &replyLen);

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

zxerr_t app_fill_address() {
    // Put data directly in the apdu buffer
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    action_addrResponseLen = 0;

    zxerr_t err = crypto_fillAddress(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, &action_addrResponseLen);

    if (err != zxerr_ok || action_addrResponseLen == 0) {
        THROW(APDU_CODE_EXECUTION_ERROR);
    }

    return zxerr_ok;
}

void app_reply_address() {
    zxerr_t zxerr = app_fill_address();
    set_code(G_io_apdu_buffer, action_addrResponseLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addrResponseLen + 2);
}

void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}
