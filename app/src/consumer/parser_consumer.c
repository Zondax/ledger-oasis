/*******************************************************************************
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

#if defined(APP_CONSUMER)

#include <stdio.h>
#include <zxmacros.h>
#include <zxerror.h>
#include <bech32.h>
#include "parser_impl_con.h"
#include "bignum.h"
#include "parser.h"
#include "parser_txdef_con.h"
#include "coin.h"

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    CHECK_PARSER_ERR(_readContext(ctx, &parser_tx_obj))
    CHECK_PARSER_ERR(_read(ctx, &parser_tx_obj));
    CHECK_PARSER_ERR(_extractContextSuffix(&parser_tx_obj))
    return parser_ok;
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validateTx(ctx, &parser_tx_obj))

    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
        CHECK_APP_CANARY()
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, &parser_tx_obj);
    if (parser_tx_obj.context.suffixLen > 0) {
        (*num_items)++;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t parser_getType(const parser_context_t *ctx, char *outVal, uint16_t outValLen) {
    switch (parser_tx_obj.oasis.tx.method) {
        case stakingTransfer:
            snprintf(outVal, outValLen, "Transfer");
            return parser_ok;
        case stakingBurn:
            snprintf(outVal, outValLen, "Burn");
            return parser_ok;
        case stakingWithdraw:
            snprintf(outVal, outValLen, "Withdraw");
            return parser_ok;
        case stakingAllow:
            snprintf(outVal, outValLen, "Allow");
            return parser_ok;
        case stakingEscrow:
            snprintf(outVal, outValLen, "Add escrow");
            return parser_ok;
        case stakingReclaimEscrow:
            snprintf(outVal, outValLen, "Reclaim escrow");
            return parser_ok;
        case stakingAmendCommissionSchedule:
#if defined(TARGET_NANOS)
            snprintf(outVal, outValLen, "Amend commission  schedule");
#else
            snprintf(outVal, outValLen, "Amend commission schedule");
#endif
            return parser_ok;
        case registryDeregisterEntity:
            snprintf(outVal, outValLen, "Deregister Entity");
            return parser_ok;
        case registryUnfreezeNode:
            snprintf(outVal, outValLen, "Unfreeze Node");
            return parser_ok;
        case registryRegisterEntity:
            snprintf(outVal, outValLen, "Register Entity");
            return parser_ok;
        case unknownMethod:
        default:
            break;
    }
    return parser_unexpected_method;
}

#define LESS_THAN_64_DIGIT(num_digit) if (num_digit > 64) return parser_value_out_of_range;

__Z_INLINE bool format_quantity(const quantity_t *q,
                                uint8_t *bcd, uint16_t bcdSize,
                                char *bignum, uint16_t bignumSize) {

    bignumBigEndian_to_bcd(bcd, bcdSize, q->buffer, q->len);
    return bignumBigEndian_bcdprint(bignum, bignumSize, bcd, bcdSize);
}

__Z_INLINE parser_error_t parser_printQuantity(const quantity_t *q,
                                               char *outVal, uint16_t outValLen,
                                               uint8_t pageIdx, uint8_t *pageCount) {
    // upperbound 2**(64*8)
    // results in 155 decimal digits => max 78 bcd bytes

    // Too many digits, we cannot format this
    LESS_THAN_64_DIGIT(q->len)

    // TODO: Change depending on Mainnet / Testnet
    snprintf(outVal, outValLen, "%s ", COIN_DENOM);
    outVal += strlen(COIN_DENOM) + 1;
    outValLen -= strlen(COIN_DENOM) + 1;

    char bignum[160];
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(overlapped.bcd, sizeof(overlapped.bcd));
    MEMZERO(bignum, sizeof(bignum));

    if (!format_quantity(q, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    fpstr_to_str(overlapped.output, sizeof(overlapped.output), bignum, COIN_AMOUNT_DECIMAL_PLACES);
    number_inplace_trimming(overlapped.output);
    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);
    return parser_ok;
}


__Z_INLINE parser_error_t parser_printQuantityWithSign(const quantity_t *q, bool is_negative,
                                                       char *outVal, uint16_t outValLen,
                                                       uint8_t pageIdx, uint8_t *pageCount) {
    // upperbound 2**(64*8)
    // results in 155 decimal digits => max 78 bcd bytes

    // Too many digits, we cannot format this
    LESS_THAN_64_DIGIT(q->len)

    // TODO: Change depending on Mainnet / Testnet
    if(is_negative){
        snprintf(outVal, outValLen, "%s -", COIN_DENOM);
    } else {
        snprintf(outVal, outValLen, "%s +", COIN_DENOM);
    }
    outVal += strlen(COIN_DENOM) + 2;
    outValLen -= strlen(COIN_DENOM) + 2;

    char bignum[160];
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(overlapped.bcd, sizeof(overlapped.bcd));
    MEMZERO(bignum, sizeof(bignum));

    if (!format_quantity(q, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    fpstr_to_str(overlapped.output, sizeof(overlapped.output), bignum, COIN_AMOUNT_DECIMAL_PLACES);
    number_inplace_trimming(overlapped.output);
    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_printShares(const quantity_t *q,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    // upperbound 2**(64*8)
    // results in 155 decimal digits => max 78 bcd bytes

    // Too many digits, we cannot format this
    LESS_THAN_64_DIGIT(q->len)

    char bignum[160];
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(overlapped.bcd, sizeof(overlapped.bcd));
    MEMZERO(bignum, sizeof(bignum));

    if (!format_quantity(q, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    fpstr_to_str(overlapped.output, sizeof(overlapped.output), bignum, 0);
    number_inplace_trimming(overlapped.output);
    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_printRate(const quantity_t *q,
                                           char *outVal, uint16_t outValLen,
                                           uint8_t pageIdx, uint8_t *pageCount) {

    // Too many digits, we cannot format this
    LESS_THAN_64_DIGIT(q->len)

    char bignum[160];
    union {
        // overlapping arrays to avoid excessive stack usage. Do not use at the same time
        uint8_t bcd[80];
        char output[160];
    } overlapped;

    MEMZERO(overlapped.bcd, sizeof(overlapped.bcd));
    MEMZERO(bignum, sizeof(bignum));

    if (!format_quantity(q, overlapped.bcd, sizeof(overlapped.bcd), bignum, sizeof(bignum))) {
        return parser_unexpected_value;
    }

    fpstr_to_str(overlapped.output, sizeof(overlapped.output), bignum, COIN_RATE_DECIMAL_PLACES - 2);
    overlapped.output[strlen(overlapped.output)] = '%';
    pageString(outVal, outValLen, overlapped.output, pageIdx, pageCount);

    return parser_ok;
}

__Z_INLINE parser_error_t parser_printAddress(const address_raw_t *addressRaw,
                                              char *outVal, uint16_t outValLen,
                                              uint8_t pageIdx, uint8_t *pageCount) {
    char outBuffer[128];
    MEMZERO(outBuffer, sizeof(outBuffer));

    //  and encode as bech32
    const zxerr_t err = bech32EncodeFromBytes(
            outBuffer, sizeof(outBuffer),
            COIN_HRP,
            (uint8_t *) addressRaw, sizeof(address_raw_t), 1);

    if (err != zxerr_ok) {
        return parser_invalid_address;
    }

    pageString(outVal, outValLen, outBuffer, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_printPublicKey(const publickey_t *pk,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {
    char outBuffer[128];
    MEMZERO(outBuffer, sizeof(outBuffer));

    if (array_to_hexstr(outBuffer, sizeof(outBuffer), (uint8_t *) pk, 32) != 64) {
        return parser_unexpected_value;
    }

    pageString(outVal, outValLen, outBuffer, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_printSignature(raw_signature_t *s,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {

    // 64 * 2 + 1 (one more for the zero termination)
    char outBuffer[2 * sizeof(raw_signature_t) + 1];
    MEMZERO(outBuffer, sizeof(outBuffer));

    array_to_hexstr(outBuffer, sizeof(outBuffer), (const uint8_t *) s, sizeof(raw_signature_t));
    pageString(outVal, outValLen, outBuffer, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_getItemEntity(const oasis_entity_t *entity,
                                               int8_t displayIdx,
                                               char *outKey, uint16_t outKeyLen,
                                               char *outVal, uint16_t outValLen,
                                               uint8_t pageIdx, uint8_t *pageCount) {
#define ENTITY_DYNAMIC_OFFSET 3

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Descr. Ver");
        uint64_to_str(outVal, outValLen, entity->obj.descriptor_version);
        *pageCount = 1;
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "ID");
        return parser_printPublicKey(&entity->obj.id,
                                     outVal, outValLen, pageIdx, pageCount);
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Allowed");
        if (entity->obj.allow_entity_signed_nodes) {
            snprintf(outVal, outValLen, "True");
        } else {
            snprintf(outVal, outValLen, "False");
        }
        return parser_ok;
    }

    if (displayIdx - ENTITY_DYNAMIC_OFFSET < (int) entity->obj.nodes_length) {
        const int8_t index = displayIdx - ENTITY_DYNAMIC_OFFSET;

        snprintf(outKey, outKeyLen, "Node [%i]", index + 1);

        publickey_t node;
        CHECK_PARSER_ERR(_getEntityNodesIdAtIndex(entity, &node, index))
        return parser_printPublicKey(&node, outVal, outValLen, pageIdx, pageCount);
    }

    return parser_no_data;
}

__Z_INLINE parser_error_t parser_getItemTx(const parser_context_t *ctx,
                                           int8_t displayIdx,
                                           char *outKey, uint16_t outKeyLen,
                                           char *outVal, uint16_t outValLen,
                                           uint8_t pageIdx, uint8_t *pageCount) {
    // Variable items
    switch (parser_tx_obj.oasis.tx.method) {
        case stakingTransfer:
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "Amount");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.body.stakingTransfer.amount,
                                                outVal, outValLen, pageIdx, pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 3: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
                case 4: {
                    snprintf(outKey, outKeyLen, "Address");
                    return parser_printAddress(&parser_tx_obj.oasis.tx.body.stakingTransfer.to,
                                               outVal, outValLen, pageIdx, pageCount);
                }
            }
            break;
        case stakingBurn:
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "Amount");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.body.stakingBurn.amount,
                                                outVal, outValLen, pageIdx, pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 3: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
            }
            break;
        case stakingWithdraw:
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "From");
                    return parser_printAddress(&parser_tx_obj.oasis.tx.body.stakingWithdraw.from,
                                               outVal, outValLen, pageIdx, pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Amount");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.body.stakingWithdraw.amount,
                                                outVal, outValLen, pageIdx, pageCount);
                }
                case 3: {
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 4: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
            }
            break;
        case stakingAllow:
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "Beneficiary");
                    return parser_printAddress(&parser_tx_obj.oasis.tx.body.stakingAllow.beneficiary,
                                               outVal, outValLen, pageIdx, pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Amount change");
                    return parser_printQuantityWithSign(&parser_tx_obj.oasis.tx.body.stakingAllow.amount_change,
                                                        parser_tx_obj.oasis.tx.body.stakingAllow.negative,
                                                        outVal, outValLen, pageIdx, pageCount);
                }
                case 3: {
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 4: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
            }
            break;
        case stakingEscrow:
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "Amount");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.body.stakingEscrow.amount,
                                                outVal, outValLen, pageIdx, pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 3: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
                case 4: {
                    snprintf(outKey, outKeyLen, "Address");
                    return parser_printAddress(&parser_tx_obj.oasis.tx.body.stakingEscrow.account,
                                               outVal, outValLen, pageIdx, pageCount);
                }
            }
            break;
        case stakingReclaimEscrow:
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "Shares");
                    return parser_printShares(&parser_tx_obj.oasis.tx.body.stakingReclaimEscrow.shares,
                                              outVal, outValLen, pageIdx, pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 3: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
                case 4: {
                    snprintf(outKey, outKeyLen, "Address");
                    return parser_printAddress(&parser_tx_obj.oasis.tx.body.stakingReclaimEscrow.account,
                                               outVal, outValLen, pageIdx, pageCount);
                }
            }
            break;
        case stakingAmendCommissionSchedule: {
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
            }
            uint8_t dynDisplayIdx = displayIdx - 3;
            if (dynDisplayIdx / 2 < (int) parser_tx_obj.oasis.tx.body.stakingAmendCommissionSchedule.rates_length) {
                const int8_t index = dynDisplayIdx / 2;
                commissionRateStep_t rate;

                CHECK_PARSER_ERR(_getCommissionRateStepAtIndex(ctx, &rate, index))

                switch (dynDisplayIdx % 2) {
                    case 0: {
                        snprintf(outKey, outKeyLen, "Rates (%d): start", index + 1);
                        uint64_to_str(outVal, outValLen, rate.start);
                        *pageCount = 1;
                        return parser_ok;
                    }
                    case 1: {
                        snprintf(outKey, outKeyLen, "Rates (%d): rate", index + 1);
                        return parser_printRate(&rate.rate, outVal, outValLen, pageIdx, pageCount);
                    }
                }
            } else {
                const int8_t index = (dynDisplayIdx -
                                      parser_tx_obj.oasis.tx.body.stakingAmendCommissionSchedule.rates_length * 2) / 3;

                // Only keeping one amendment in body at the time
                commissionRateBoundStep_t bound;
                CHECK_PARSER_ERR(_getCommissionBoundStepAtIndex(ctx, &bound, index))

                switch ((dynDisplayIdx -
                         parser_tx_obj.oasis.tx.body.stakingAmendCommissionSchedule.rates_length * 2) % 3) {
                    case 0: {
                        snprintf(outKey, outKeyLen, "Bounds (%d): start", index + 1);
                        uint64_to_str(outVal, outValLen, bound.start);
                        *pageCount = 1;
                        return parser_ok;
                    }
                    case 1: {
                        snprintf(outKey, outKeyLen, "Bounds (%d): min", index + 1);
                        return parser_printRate(&bound.rate_min, outVal, outValLen, pageIdx, pageCount);
                    }
                    case 2: {
                        snprintf(outKey, outKeyLen, "Bounds (%d): max", index + 1);
                        return parser_printRate(&bound.rate_max, outVal, outValLen, pageIdx, pageCount);
                    }
                }
            }
            break;
        }
        case registryDeregisterEntity:
            *pageCount = 0;
            return parser_no_data;

        case registryUnfreezeNode: {
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
                case 3:
                    snprintf(outKey, outKeyLen, "Node ID");
                    return parser_printPublicKey(
                            &parser_tx_obj.oasis.tx.body.registryUnfreezeNode.node_id,
                            outVal, outValLen, pageIdx, pageCount);
            }
        }
        case registryRegisterEntity: {
            switch (displayIdx) {
                case 0: {
                    snprintf(outKey, outKeyLen, "Type");
                    *pageCount = 1;
                    return parser_getType(ctx, outVal, outValLen);
                }
                case 1: {
                    // ??? displayIdx == 1 && parser_tx_obj.oasis.tx.has_fee
                    snprintf(outKey, outKeyLen, "Fee");
                    return parser_printQuantity(&parser_tx_obj.oasis.tx.fee_amount, outVal, outValLen, pageIdx,
                                                pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "Gas limit");
                    uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.tx.fee_gas);
                    *pageCount = 1;
                    return parser_ok;
                }
                case 3:
                    snprintf(outKey, outKeyLen, "Public key");
                    return parser_printPublicKey(
                            &parser_tx_obj.oasis.tx.body.registryRegisterEntity.signature.public_key,
                            outVal, outValLen, pageIdx, pageCount);
                case 4:
                    snprintf(outKey, outKeyLen, "Signature");
                    return parser_printSignature(
                            &parser_tx_obj.oasis.tx.body.registryRegisterEntity.signature.raw_signature,
                            outVal, outValLen, pageIdx, pageCount);
                default:
                    return parser_getItemEntity(
                            &parser_tx_obj.oasis.tx.body.registryRegisterEntity.entity,
                            displayIdx - 5,
                            outKey, outKeyLen, outVal, outValLen,
                            pageIdx, pageCount);
            }
        }
        case unknownMethod:
        default:
            break;
    }

    *pageCount = 0;
    return parser_no_data;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint16_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
    *pageCount = 0;

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (numItems == 0) {
        return parser_unexpected_number_items;
    }

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    parser_error_t err = parser_ok;

    if (parser_tx_obj.context.suffixLen > 0 && displayIdx + 1 == numItems /*last*/) {
        // Display context
        snprintf(outKey, outKeyLen, "Genesis hash");
        pageStringExt(outVal, outValLen,
                      (const char *) parser_tx_obj.context.suffixPtr, parser_tx_obj.context.suffixLen,
                      pageIdx, pageCount);
    } else {
        switch (parser_tx_obj.type) {
            case txType: {
                err = parser_getItemTx(ctx,
                                       displayIdx,
                                       outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
                break;
            }
            case entityType: {
                if (displayIdx == 0) {
                    snprintf(outKey, outKeyLen, "Type");
                    snprintf(outVal, outValLen, "Entity signing");
                } else {
                    err = parser_getItemEntity(&parser_tx_obj.oasis.entity,
                                               displayIdx - 1,
                                               outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
                }
                break;
            }

            default:
                return parser_unexpected_type;
        }
    }

    ///////////////////////////////
    ///////////////////////////////
    // Add paging values
    if (err == parser_ok && *pageCount > 1) {
        size_t keyLen = strlen(outKey);
        if (keyLen < outKeyLen) {
            snprintf(outKey + keyLen, outKeyLen - keyLen, " [%d/%d]", pageIdx + 1, *pageCount);
        }
    }
    ///////////////////////////////
    ///////////////////////////////

    return err;
}

#endif // APP_CONSUMER
