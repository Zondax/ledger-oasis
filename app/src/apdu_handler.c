/*******************************************************************************
*   (c) 2018, 2019 Zondax GmbH
*   (c) 2016 Ledger
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

#include "zxmacros.h"
#include <string.h>
#include <os_io_seproxyhal.h>
#include <os.h>
#include <ux.h>

#include "view.h"
#include "view_custom.h"
#include "view_internal.h"
#include "actions.h"
#include "tx.h"
#include "addr.h"
#include "crypto.h"
#include "coin.h"
#include "app_main.h"
#include "app_mode.h"

#include "parser_txdef.h"
#include "parser_impl.h"

#include "eth_addr.h"
#include "eth_utils.h"

static bool tx_initialized = false;

static const char *msg_error1 = "Expert Mode";
static const char *msg_error2 = "Required";

void extractHDPath(uint32_t rx, uint32_t offset) {
    MEMZERO(hdPath,sizeof(hdPath));
    if ((rx - offset) == sizeof(uint32_t) * HDPATH_LEN_ADR0008) {
        hdPathLen = HDPATH_LEN_ADR0008;
    } else if ((rx - offset) == sizeof(uint32_t) * HDPATH_LEN_DEFAULT) {
        hdPathLen = HDPATH_LEN_DEFAULT;
    } else {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    char buffer[15];
    snprintf(buffer, sizeof(buffer), "Path len: %d", hdPathLen);
    zemu_log_stack(buffer);

    MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * hdPathLen);

    const bool mainnet = (hdPath[0] == HDPATH_0_DEFAULT &&
                         hdPath[1] == HDPATH_1_DEFAULT) ||
                         (hdPath[0] == HDPATH_0_DEFAULT &&
                         hdPath[1] == HDPATH_1_ALTERNATIVE) ||
                         (hdPath[0] == HDPATH_0_DEFAULT &&
                         hdPath[1] == HDPATH_1_ALTERNATIVE2);

    if (!mainnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    if(hdPathLen == HDPATH_LEN_ADR0008 && hdPath[2] < 0x80000000){
        THROW(APDU_CODE_DATA_INVALID);
    }
}

void extract_eth_path(uint32_t rx, uint32_t offset)
{
    tx_initialized = false;

    uint32_t path_len = *(G_io_apdu_buffer + offset);

    if (path_len > MAX_BIP32_PATH || path_len < 1)
        THROW(APDU_CODE_WRONG_LENGTH);

    if ((rx - offset - 1) < sizeof(uint32_t) * path_len) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    // first byte at OFFSET_DATA is the path len, so we skip this
    uint8_t *path_data = G_io_apdu_buffer + offset + 1;

    // hw-app-eth serializes path as BE numbers
    for (uint8_t i = 0; i < path_len; i++) {
        hdPath[i] = U4BE(path_data, 0);
        path_data += sizeof(uint32_t);
    }

    const bool mainnet =
      hdPath[0] == HDPATH_ETH_0_DEFAULT && hdPath[1] == HDPATH_ETH_1_DEFAULT;


    if (!mainnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    // set the hdPath len
    hdPathLen = path_len;
}

bool process_chunk(volatile uint32_t *tx, uint32_t rx) {
    UNUSED(tx);

    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (payloadType) {
        case 0:
            tx_initialize_oasis();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            tx_initialized = true;
            return false;
        case 1:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case 2:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return true;
    }
    tx_initialized = false;
    THROW(APDU_CODE_INVALIDP1P2);
}

bool
process_chunk_eth(__Z_UNUSED volatile uint32_t *tx, uint32_t rx)
{
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        THROW(APDU_CODE_INVALIDP1P2);
    }

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint64_t read = 0;
    uint64_t to_read = 0;
    uint64_t max_len = 0;

    uint8_t *data = &(G_io_apdu_buffer[OFFSET_DATA]);
    uint32_t len = rx - OFFSET_DATA;

    uint64_t added;
    switch (payloadType) {
        case P1_ETH_FIRST:
            tx_initialize_eth();
            tx_reset();
            extract_eth_path(rx, OFFSET_DATA);
            // there is not warranties that the first chunk
            // contains the serialized path only;
            // so we need to offset the data to point to the first transaction
            // byte
            uint32_t path_len = sizeof(uint32_t) * hdPathLen;

            // plus the first offset data containing the path len
            data += path_len + 1;
            if (len < path_len) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            // now process the chunk
            len -= path_len + 1;
            if (get_tx_rlp_len(data, len, &read, &to_read) != rlp_ok) {
                THROW(APDU_CODE_DATA_INVALID);
            }

            // get remaining data len
            max_len = saturating_add(read, to_read);
            max_len = MIN(max_len, len);

            added = tx_append(data, max_len);
            if (added != max_len) {
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }

            tx_initialized = true;

            // if the number of bytes read and the number of bytes to read
            //  is the same as what we read...
            if ((saturating_add(read, to_read) - len) == 0) {
                return true;
            }
            return false;
        case P1_ETH_MORE:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }

            uint64_t buff_len = tx_get_buffer_length();
            uint8_t *buff_data = tx_get_buffer();

            if (get_tx_rlp_len(buff_data, buff_len, &read, &to_read) !=
                rlp_ok) {
                THROW(APDU_CODE_DATA_INVALID);
            }

            uint64_t rlp_read = buff_len - read;

            // either the entire buffer of the remaining bytes we expect
            uint64_t missing = to_read - rlp_read;
            max_len = len;

            if (missing < len)
                max_len = missing;

            added = tx_append(data, max_len);

            if (added != max_len) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }

            // check if this chunk was the last one
            if (missing - len == 0) {
                tx_initialized = false;
                return true;
            }

            return false;
    }
    THROW(APDU_CODE_INVALIDP1P2);
}

__Z_INLINE void handle_getversion(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    UNUSED(flags);
    UNUSED(rx);
#ifdef DEBUG
    G_io_apdu_buffer[0] = 0xFF;
#else
    G_io_apdu_buffer[0] = 0;
#endif
    G_io_apdu_buffer[1] = LEDGER_MAJOR_VERSION;
    G_io_apdu_buffer[2] = LEDGER_MINOR_VERSION;
    G_io_apdu_buffer[3] = LEDGER_PATCH_VERSION;
    G_io_apdu_buffer[4] = 0;

    G_io_apdu_buffer[5] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[6] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[7] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[8] = (TARGET_ID >> 0) & 0xFF;

    *tx += 9;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx, address_kind_e kind) {
    zemu_log("handleGetAddr\n");
    extractHDPath(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zxerr_t zxerr = app_fill_address(kind);
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        switch (kind) {
            case addr_ed25519:
                view_review_init(addr_getItem_ed25519, addr_getNumItems, app_reply_address);
                break;
            case addr_secp256k1:
                view_review_init(addr_getItem_secp256k1, addr_getNumItems, app_reply_address);
                break;
            case addr_sr25519:
                view_review_init(addr_getItem_sr25519, addr_getNumItems, app_reply_address);
                break;
            default:
                zemu_log("No match for address kind!\n");
                THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
                break;
        }
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = action_addrResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void
handleGetEthAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx)
{
    extract_eth_path(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    uint8_t with_code = G_io_apdu_buffer[OFFSET_P2];

    if (with_code != P2_CHAINCODE && with_code != P2_NO_CHAINCODE)
        THROW(APDU_CODE_INVALIDP1P2);

    chain_code = with_code;

    zxerr_t zxerr = app_fill_address(addr_eth);
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(eth_addr_getItem, eth_addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = action_addrResponseLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignSecp256k1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    uint8_t parser_err;
    const char *error_msg = tx_parse(&parser_err);
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        if (parser_err == parser_required_expert_mode) {
            *flags |= IO_ASYNCH_REPLY;
            view_custom_error_show(PIC(msg_error1),PIC(msg_error2));
        }
        THROW(APDU_CODE_DATA_INVALID);
    }
#if defined(APP_CONSUMER)
    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign_secp256k1);
#if !defined(TARGET_STAX) && !defined(TARGET_FLEX)
    view_inspect_init(tx_getInnerItem, tx_getNumInnerItems, tx_canInspectItem);
#endif
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
#endif
}

__Z_INLINE void handleSignEd25519(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    uint8_t parser_err;
    const char *error_msg = tx_parse(&parser_err);
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        if (parser_err == parser_required_expert_mode) {
            *flags |= IO_ASYNCH_REPLY;
            view_custom_error_show(PIC(msg_error1),PIC(msg_error2));
        }
        THROW(APDU_CODE_DATA_INVALID);
    }
#if defined(APP_CONSUMER)
    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign_ed25519);
#if !defined(TARGET_STAX) && !defined(TARGET_FLEX)
    view_inspect_init(tx_getInnerItem, tx_getNumInnerItems, tx_canInspectItem);
#endif
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
#elif defined(APP_VALIDATOR)
    switch(parser_tx_obj.type) {
                        case consensusType:
                        {
                            if(vote_state.isInitialized) {
                                app_sign_ed25519();
                                view_status_show();
                            } else {
                                CHECK_APP_CANARY()
                                view_review_init(tx_getItem, tx_getNumItems, app_sign_ed25519);
                                view_review_show(REVIEW_TXN);
                                *flags |= IO_ASYNCH_REPLY;
                            }
                        }
                        	break;
                        case nodeType:
                            app_sign_ed25519();
                            break;
                        default:
                            THROW(APDU_CODE_BAD_KEY_HANDLE);
                    }

#else
#error "APP MODE IS NOT SUPPORTED"
#endif
}

__Z_INLINE void
handleSignEth(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx)
{
    if (!process_chunk_eth(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    CHECK_APP_CANARY()

    uint8_t parser_err;
    const char *error_msg = tx_parse(&parser_err);
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }
#if defined(APP_CONSUMER)
    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign_eth);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
#endif
}

__Z_INLINE void handleSignSr25519(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()
    uint8_t parser_err;
    const char *error_msg = tx_parse(&parser_err);
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        if (parser_err == parser_required_expert_mode) {
            *flags |= IO_ASYNCH_REPLY;
            view_custom_error_show(PIC(msg_error1),PIC(msg_error2));
        }
        THROW(APDU_CODE_DATA_INVALID);
    }

#if defined(APP_CONSUMER)
    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign_sr25519);
#if !defined(TARGET_STAX) && !defined(TARGET_FLEX)
    view_inspect_init(tx_getInnerItem, tx_getNumInnerItems, tx_canInspectItem);
#endif
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
#endif
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint16_t sw = 0;

    BEGIN_TRY
    {
        TRY
        {
            uint8_t cla = G_io_apdu_buffer[OFFSET_CLA];
            if ((cla != CLA) && (cla != CLA_ETH)) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }
            uint8_t instruction = G_io_apdu_buffer[OFFSET_INS];

            // Handle this case as ins number
            if (instruction == INS_GET_ADDR_ETH && cla == CLA_ETH)
                 handleGetEthAddr(flags, tx, rx);

            switch (instruction) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_ED25519: {
                    zemu_log("INS_GET_ADDR_ED25519\n");
                    CHECK_PIN_VALIDATED()
                    handleGetAddr(flags, tx, rx, addr_ed25519);
                    break;
                }

                case INS_SIGN_ED25519: {
                    CHECK_PIN_VALIDATED()
                    handleSignEd25519(flags, tx, rx);
                    break;
                }

                case INS_SIGN_RT_ED25519: {
                    CHECK_PIN_VALIDATED()
                    handleSignEd25519(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    if (cla != CLA_ETH) {
                        zemu_log("INS_GET_ADDR_SECP256K1\n");
                        CHECK_PIN_VALIDATED()
                        handleGetAddr(flags, tx, rx, addr_secp256k1);
                    } else {
                        zemu_log("Sign Eth\n");
                        handleSignEth(flags, tx, rx);
                    }
                    break;
                }

                case INS_SIGN_RT_SECP256K1: {
                    CHECK_PIN_VALIDATED()
                    handleSignSecp256k1(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SR25519: {
                    zemu_log("INS_GET_ADDR_SR25519\n");
                    CHECK_PIN_VALIDATED()
                    handleGetAddr(flags, tx, rx, addr_sr25519);
                    break;
                }

                case INS_SIGN_RT_SR25519: {
                    zemu_log("INS_SIGN_RT_SR25519\n");
                    CHECK_PIN_VALIDATED()
                    handleSignSr25519(flags, tx, rx);
                    break;
                }

                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET)
        {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e)
        {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY
        {
        }
    }
    END_TRY;
}
