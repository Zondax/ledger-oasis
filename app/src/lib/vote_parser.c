/*******************************************************************************
*   (c) 2018 ZondaX GmbH
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

#include "vote_parser.h"
#include "parser_txdef.h"

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

//int64_t decode_amino_64bits(const uint8_t *p) {
//    int64_t v = 0;
//    p += 7;
//    for (int8_t i = 0; i < 8; i++, p--) {
//        v <<= 8;
//        v += *p;
//    }
//    return v;
//}

parser_error_t read_amino_64bits(parser_context_t *ctx, uint64_t *value) {
    uint16_t offset = ctx->offset + ctx->lastConsumed;

    const uint8_t *p = ctx->buffer + offset;
    *value = 0;

    // Extract value
    uint16_t shift = 0;
    for (uint8_t i = 0; i < 8; i++, p++) {
        const uint64_t tmp = ((*p) & 0x7Fu);

        if (shift == 63 && tmp > 1) {
            return parser_value_out_of_range;
        }

        *value += tmp << shift;

        shift += 7;
    }

    ctx->lastConsumed += 7;

    ctx->offset += ctx->lastConsumed;
    ctx->lastConsumed = 0;

    return parser_ok;
}

parser_error_t _readRawVarint(parser_context_t *ctx, uint64_t *value) {
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

parser_error_t _readVarint(parser_context_t *ctx, uint64_t *value) {
    ctx->lastConsumed = 0;

    parser_error_t err = _readRawVarint(ctx, value);
    if (err != parser_ok) {
        ctx->lastConsumed = 0;
        return err;
    }

//    if (WIRE_TYPE(*value) != WIRE_TYPE_VARINT) {
//        ctx->lastConsumed = 0;
//        return parser_unexpected_wire_type;
//    }

    err = _readRawVarint(ctx, value);

    if (err == parser_ok) {
        ctx->offset += ctx->lastConsumed;
        ctx->lastConsumed = 0;
    }

    return err;
}

parser_error_t _readArray(parser_context_t *ctx, const uint8_t **arrayPtr, uint16_t *arrayLength) {
    ctx->lastConsumed = 0;

    // First retrieve array type and confirm
    uint64_t v;
    parser_error_t err = _readRawVarint(ctx, &v);
    if (err != parser_ok) {
        ctx->lastConsumed = 0;
        return 0;
    }

     uint8_t field_num = FIELD_NUM(v);
     uint8_t wire_type = WIRE_TYPE(v);


    if (WIRE_TYPE(v) != WIRE_TYPE_LEN) {
        ctx->lastConsumed = 0;
        return parser_unexpected_wire_type;
    }

    // Now get number of bytes
    uint64_t tmpValue;
    err = _readRawVarint(ctx, &tmpValue);

    if (tmpValue >= (uint64_t) UINT16_MAX) {
        err = parser_value_out_of_range;
    }
    if (err != parser_ok) {
        ctx->lastConsumed = 0;
        return err;
    }
    *arrayLength = tmpValue;

    // check that the returned buffer is not out of bounds
    if (ctx->offset + ctx->lastConsumed + *arrayLength > ctx->bufferLen) {
        ctx->lastConsumed = 0;
        return parser_unexpected_buffer_end;
    }

    // Set a pointer to the start of the first element
    *arrayPtr = ctx->buffer + ctx->offset + ctx->lastConsumed;
    ctx->lastConsumed += *arrayLength;

    ctx->offset += ctx->lastConsumed;
    ctx->lastConsumed = 0;
    return parser_ok;
}

parser_error_t readVote(parser_context_t *c, parser_tx_t *v) {
    parser_error_t err = parser_ok;
    //err = _readArray(c, &v->oasis.voteTx.votePtr, &v->oasis.voteTx.voteLen);
    return err;
}

parser_error_t vote_amino_parse(parser_context_t *ctx, oasis_tx_vote_t *voteTx, vote_t *_vote) {
    uint8_t expected_field = FIELD_TYPE;

    // Initialize vote values
    _vote->Type = 0;
    _vote->Round = 0;
    _vote->Height = 0;

    uint32_t size = voteTx->voteLen;
    uint64_t val;

    parser_error_t err = parser_ok;

    bool_t doParse = true;

    while (doParse && (ctx->offset < ctx->bufferLen)) {

        err = _readVarint(ctx, &val);

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

                err = _readRawVarint(ctx, &val);
                _vote->Type = val;
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

                err = read_amino_64bits(ctx, &val);
                if(err != parser_ok) {
                    return err;
                }
                _vote->Height = val;
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

                err = read_amino_64bits(ctx, &val);
                if (err != parser_ok) {
                    return err;
                }
                if (val < 0) {
                    return parser_unexpected_round_value;
                }
                if (val > 255) {
                    return parser_unexpected_round_value;
                }
                _vote->Round = (uint8_t) val;
                expected_field = FIELD_UNKNOWN;
                break;
            }

            default: {
                if (size > 10000) {
                    return parser_unexpected_buffer_size;
                }
                doParse = false;
                break;
            }
        }
        // NOTE: Other fields are not parsed. In particular BlockID
    }

    // Validate values
    switch (_vote->Type) {
        case TYPE_PREVOTE:
        case TYPE_PRECOMMIT:
        case TYPE_PROPOSAL:
            break;
        default:
            return parser_unexpected_type_value;
    }
    if (_vote->Height < 0) {
        return parser_unexpected_height_value;
    }
    if (_vote->Round < 0) {
        return parser_unexpected_height_value;
    }

    // NOTE: for proposal POLRound is not parsed or verified

    return parser_ok;
}

parser_error_t vote_parse(parser_context_t *c, parser_tx_t *v) {
    parser_error_t error = vote_amino_parse(c, &v->oasis.voteTx, &vote);
    return error;
}
