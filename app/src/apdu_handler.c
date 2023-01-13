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

#include "parser_txdef.h"
#include "parser_impl.h"

static bool tx_initialized = false;

void extractHDPath(uint32_t rx, uint32_t offset) {
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
                         hdPath[1] == HDPATH_1_ALTERNATIVE);

    if (!mainnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    if(hdPathLen == HDPATH_LEN_ADR0008 && hdPath[2] < 0x80000000){
        THROW(APDU_CODE_DATA_INVALID);
    }
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
            tx_initialize();
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
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
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

    const char *error_msg = tx_parse();
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign_secp256k1);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSignEd25519(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    CHECK_APP_CANARY()

    const char *error_msg = tx_parse();
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

#if defined(APP_CONSUMER)
    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign_ed25519);
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

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint16_t sw = 0;

    BEGIN_TRY
    {
        TRY
        {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
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

                case INS_SIGN_PT_ED25519: {
                    CHECK_PIN_VALIDATED()
                    handleSignEd25519(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    zemu_log("INS_GET_ADDR_SECP256K1\n");
                    CHECK_PIN_VALIDATED()
                    handleGetAddr(flags, tx, rx, addr_secp256k1);
                    break;
                }

                case INS_SIGN_PT_SECP256K1: {
                    CHECK_PIN_VALIDATED()
                    handleSignSecp256k1(flags, tx, rx);
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
