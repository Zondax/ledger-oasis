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

#if defined(APP_VALIDATOR)

#include <stdio.h>
#include <zxmacros.h>
#include <zxformat.h>
#include <bech32.h>
#include <stdbool.h>
#include "parser_impl_val.h"
#include "bignum.h"
#include "parser.h"
#include "parser_txdef_val.h"
#include "coin.h"
#include "vote_fsm.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2) || defined(TARGET_STAX) || defined(TARGET_FLEX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

#define WIRE_TYPE_VARINT   0
#define WIRE_TYPE_64BIT    1
#define WIRE_TYPE_LEN      2
#define WIRE_TYPE_32BIT    5

#define FIELD_ZERO     0
#define FIELD_TYPE     1
#define FIELD_HEIGHT   2
#define FIELD_ROUND    3
#define FIELD_UNKNOWN  4

#define FIELD_NUM(x) ((uint8_t)((x) >> 3u))
#define WIRE_TYPE(x) ((uint8_t)((x) & 0x7u))

vote_state_t vote_state;
vote_t vote;

__Z_INLINE parser_error_t readRawVarint(parser_context_t *ctx, uint64_t *value) {
    uint16_t offset = ctx->offset + ctx->lastConsumed;
    uint16_t consumed = 0;

    const uint8_t *p = ctx->buffer + offset;
    const uint8_t *end = ctx->buffer + ctx->bufferLen + 1;
    *value = 0;

    // Extract value
    uint16_t shift = 0;
    while (p < end && shift < 64) {
        const uint64_t tmp = ((*p) & 0x7Fu);

        if (shift == 63 && tmp > 1) {
            return parser_value_out_of_range;
        }

        *value += tmp << shift;

        consumed++;
        if (!(*p & 0x80u)) {
            ctx->lastConsumed += consumed;
            return parser_ok;
        }
        shift += 7;
        p++;
    }

    return parser_unexpected_buffer_end;
}

__Z_INLINE parser_error_t read_amino_64bits(parser_context_t *ctx, int64_t *value) {
    uint16_t offset = ctx->offset + ctx->lastConsumed;

    const uint8_t *p = ctx->buffer + offset;
    *value = 0;

    // Extract value
    int64_t v = 0;
    p += 7;
    for (int8_t i = 0; i < 8; i++, p--) {
        v <<= 8;
        v += *p;
    }

    *value = v;

    ctx->offset += 8;
    ctx->lastConsumed = 0;

    return parser_ok;
}

__Z_INLINE parser_error_t readVoteLength(parser_context_t *c, parser_tx_t *v) {
    parser_error_t err;
    //Read tx's length
    uint64_t _length = 0;
    c->lastConsumed = 0;
    err = readRawVarint(c, &_length);
    if(err != parser_ok) {
        return err;
    }
    c->offset += c->lastConsumed;
    c->lastConsumed = 0;

    v->oasis.voteTx.voteLen = (size_t)_length;
    v->oasis.voteTx.votePtr = c->buffer + c->offset;

    return parser_ok;
}

parser_error_t readVoteType(parser_context_t *ctx, uint8_t* val) {
    parser_error_t err;

    uint64_t tmp;
    err = readRawVarint(ctx, &tmp);

    if(err != parser_ok) {
        ctx->lastConsumed = 0;
        return err;
    }

    *val = (uint8_t) tmp;

    ctx->offset += ctx->lastConsumed;
    ctx->lastConsumed = 0;

    return err;
}

parser_error_t readVoteHeight(parser_context_t *ctx, int64_t* val) {
    parser_error_t err;
    err = read_amino_64bits(ctx, val);
    return err;
}

parser_error_t readVoteRound(parser_context_t *ctx, int64_t* val) {
    parser_error_t err;
    err = read_amino_64bits(ctx, val);
    return err;
}

parser_error_t vote_amino_parse(parser_context_t *ctx, oasis_tx_vote_t *voteTx) {
    uint8_t expected_field = FIELD_TYPE;

    uint64_t val;
    bool_t doParse = true;

    voteTx->vote.Height = 0;
    voteTx->vote.Type = 0;
    voteTx->vote.Round = 0;

    while (doParse && (ctx->offset < ctx->bufferLen)) {

        CHECK_PARSER_ERR(readRawVarint(ctx, &val));
        ctx->offset = ctx->offset + ctx->lastConsumed;
        ctx->lastConsumed = 0;

        const uint8_t field_num = FIELD_NUM(val);
        const uint8_t wire_type = WIRE_TYPE(val);

        switch (field_num) {
            case FIELD_ZERO: {
                return parser_unexpected_field;
            }

            case FIELD_TYPE: {
                if (expected_field < FIELD_TYPE) {
                    return parser_unexpected_field;
                }
                if (wire_type != WIRE_TYPE_VARINT) {
                    return parser_unexpected_wire_type;
                }

                CHECK_PARSER_ERR(readVoteType(ctx, &voteTx->vote.Type));

                expected_field = FIELD_HEIGHT;
                break;
            }

            case FIELD_HEIGHT: {
                if (expected_field < FIELD_TYPE) {
                    return parser_unexpected_field;
                }
                if (wire_type != WIRE_TYPE_64BIT) {
                    return parser_unexpected_wire_type;
                }

                CHECK_PARSER_ERR(readVoteHeight(ctx, &voteTx->vote.Height));

                expected_field = FIELD_ROUND;
                break;
            }

            case FIELD_ROUND: {
                if (expected_field < FIELD_TYPE) {
                    return parser_unexpected_field;
                }
                if (wire_type != WIRE_TYPE_64BIT) {
                    return parser_unexpected_wire_type;
                }

                CHECK_PARSER_ERR(readVoteRound(ctx, &voteTx->vote.Round));

                if (voteTx->vote.Round < 0) {
                    return parser_unexpected_round_value;
                }
                if (voteTx->vote.Round > 255) {
                    return parser_unexpected_round_value;
                }

                expected_field = FIELD_UNKNOWN;
                break;
            }

            default: {
                doParse = false;
                break;
            }
        }
        // NOTE: Other fields are not parsed. In particular BlockID
    }

    // NOTE: for proposal POLRound is not parsed or verified

    return parser_ok;
}

__Z_INLINE parser_error_t readVoteTx(parser_context_t *ctx, parser_tx_t *v) {
    CHECK_PARSER_ERR(readVoteLength(ctx, v))
    CHECK_PARSER_ERR(vote_amino_parse(ctx, &v->oasis.voteTx));
    return parser_ok;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    CHECK_PARSER_ERR(_readContext(ctx, &parser_tx_obj))
    CHECK_PARSER_ERR(_extractContextSuffixForValidator(&parser_tx_obj))

    switch (parser_tx_obj.type) {
        case consensusType:
            CHECK_PARSER_ERR(readVoteTx(ctx, &parser_tx_obj))
            break;
        case nodeType:
            //Do not parse cbor encoded Tx, for now
            break;
        default:
            return parser_context_unknown_prefix;
    }

    return parser_ok;
}

parser_error_t parser_validate(__Z_UNUSED const parser_context_t *ctx) {
    if(parser_tx_obj.type == nodeType) {
        //We don't validate anything, for now
        return parser_ok;
    }

    // Initialize vote values
    vote.Type = 0;
    vote.Round = 0;
    vote.Height = 0;

    // Validate values
    switch (parser_tx_obj.oasis.voteTx.vote.Type) {
        case TYPE_PREVOTE:
        case TYPE_PRECOMMIT:
        case TYPE_PROPOSAL:
            break;
        default:
            return parser_unexpected_type_value;
    }
    if (parser_tx_obj.oasis.voteTx.vote.Height < 0) {
        return parser_unexpected_height_value;
    }
    if (parser_tx_obj.oasis.voteTx.vote.Round < 0) {
        return parser_unexpected_round_value;
    }

    //All fields are good, update vote
    vote.Type = parser_tx_obj.oasis.voteTx.vote.Type;
    vote.Height = parser_tx_obj.oasis.voteTx.vote.Height;
    vote.Round = parser_tx_obj.oasis.voteTx.vote.Round;

    return parser_ok;
}

parser_error_t parser_getNumItems(__Z_UNUSED const parser_context_t *ctx, uint8_t *num_items) {
    if(vote_state.isInitialized) {
        *num_items = 0;
        return parser_ok;
    }

    //we're only parsing: type, height, round
    *num_items = 3;
    return parser_ok;
}

__Z_INLINE parser_error_t parser_getItemVote(__Z_UNUSED const parser_context_t *ctx,
                                           int8_t displayIdx,
                                           char *outKey, uint16_t outKeyLen,
                                           char *outVal, uint16_t outValLen,
                                           __Z_UNUSED uint8_t pageIdx, uint8_t *pageCount) {
    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Type");
        const char *type;
        switch (parser_tx_obj.oasis.voteTx.vote.Type) {
            case TYPE_PREVOTE:
                type = "Prevote";
                break;
            case TYPE_PRECOMMIT:
                type = "Precommit";
                break;
            case TYPE_PROPOSAL:
                type = "Proposal";
                break;
        }
        snprintf(outVal, outValLen, "%s", type);
        *pageCount = 1;
        return parser_ok;
    }

    if (displayIdx == 1) {
        snprintf(outKey, outKeyLen, "Height");
        uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.voteTx.vote.Height);
        *pageCount = 1;
        return parser_ok;
    }

    if (displayIdx == 2) {
        snprintf(outKey, outKeyLen, "Round");
        uint64_to_str(outVal, outValLen, parser_tx_obj.oasis.voteTx.vote.Round);
        *pageCount = 1;
        return parser_ok;
    }

    return parser_unexpected_number_items;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint16_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    //No user input is required once vote_state is initialized
    if(vote_state.isInitialized) {
        return parser_no_data;
    }

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

    parser_error_t err;

    err = parser_getItemVote(ctx, displayIdx, outKey, outKeyLen,
                             outVal, outValLen, pageIdx, pageCount);

    if (err == parser_ok && *pageCount > 1) {
        size_t keyLen = strlen(outKey);
        if (keyLen < outKeyLen) {
            snprintf(outKey + keyLen, outKeyLen - keyLen, " [%d/%d]", pageIdx + 1, *pageCount);
        }
    }

    return err;
}

#endif  // APP_VALIDATOR
