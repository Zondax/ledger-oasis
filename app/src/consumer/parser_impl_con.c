/*******************************************************************************
*  (c) 2019 Zondax GmbH
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
#include <zxmacros.h>
#include "parser_impl_con.h"
#include "parser_txdef_con.h"
#include "sha512.h"
#include "zxformat.h"
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    #include "cx.h"
#else
    #include "picohash.h"
    #if !defined(CX_SHA256_SIZE)
        #define CX_SHA256_SIZE 32
    #endif
#endif
#if defined(APP_CONSUMER)

#include "cbor_helper.h"

parser_tx_t parser_tx_obj;

const char context_prefix_tx[] = "oasis-core/consensus: tx for chain ";
const char context_prefix_entity[] = "oasis-core/registry: register entity";
const char context_prefix_node[] = "oasis-core/registry: register node";
const char context_prefix_consensus[] = "oasis-core/tendermint";
const char context_prefix_entity_metadata[] = "oasis-metadata-registry: entity";
const char context_prefix_runtime[] = "oasis-runtime-sdk/tx: v0 for chain ";

parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->lastConsumed = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        ctx->buffer = NULL;
        ctx->bufferLen = 0;
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize));
    return parser_ok;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";
        case parser_unexepected_error:
            return "Unexpected internal error";
            // cbor
        case parser_cbor_unexpected:
            return "unexpected CBOR error";
        case parser_cbor_not_canonical:
            return "CBOR was not in canonical order";
        case parser_cbor_unexpected_EOF:
            return "Unexpected CBOR EOF";
            // Coin specific
        case parser_root_item_should_be_a_map:
            return "Root item should be a map";
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_method:
            return "Unexpected method";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
        case parser_unsupported_cal:
            return "Unsupported Call Format";
        case parser_required_chain_context:
            return "Required chain context";
        case parser_required_runtime_id:
            return "Required Runtime Id";
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_unknown_prefix:
            return "context unknown prefix";
        case parser_context_invalid_chars:
            return "context invalid chars";
            // Required fields error
        case parser_required_nonce:
            return "Required field nonce";
        case parser_required_method:
            return "Required field method";
        case parser_required_body:
            return "Required field body";
        case parser_required_call:
            return "Required field call";
        case parser_required_v:
            return "Required field v (version)";
        case parser_invalid_v_value:
            return "Invalid v (version) value";
        case parser_required_serial:
            return "Requiered field serial";
        case parser_invalid_url_format:
            return "Invalid url format (expect to start with https:// and not containing query or fragments)";
        case parser_invalid_url_length:
            return "Invalid url length (max 64 characters)";
        case parser_invalid_email_format:
            return "Invalid email format";
        case parser_invalid_email_length:
            return "Invalid email length (max 32 characters)";
        case parser_invalid_handle_format:
            return "Invalid handle format";
        case parser_invalid_handle_length:
            return "Invalid handle length (max 32 characters)";
        case parser_invalid_name_length:
            return "Invalid name length (max 50 characters)";
        case parser_invalid_eth_mapping:
            return "Invalid Ethaddr, doesn't match transaction's to";
        case parser_required_id:
            return "Required field id";
        case parser_required_code_id:
            return "Required field code_id";
        case parser_required_pk:
            return "Required field pk";
        case parser_required_data:
            return "Required field data";
        case parser_required_expert_mode:
            return "Required Expert Mode";
        default:
            return "Unrecognized error code";
    }
}

#if !defined(TARGET_NANOS) && !defined(TARGET_NANOS2) && !defined(TARGET_NANOX) && !defined(TARGET_STAX) && !defined(TARGET_FLEX)
parser_error_t parser_picoHash(uint8_t *src, size_t srcLen, uint8_t *dest, size_t destLen) {
    if(destLen < KECCAK256_HASH_LEN) {
        return parser_unexpected_buffer_size;
    }
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, src, srcLen);
    picohash_final(&ctx, dest);

    return parser_ok;
}
#endif


void parser_setCborState(cbor_parser_state_t *state, const CborParser *parser, const CborValue *it) {
    state->parser = *parser;
    state->startValue = *it;
    if (state->startValue.parser == parser) {
        // Repoint to copy
        state->startValue.parser = &state->parser;
    }
}

__Z_INLINE parser_error_t _readAddressRaw(CborValue *value, address_raw_t *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType)
    CborValue dummy;
    size_t len = sizeof(address_raw_t);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) out, &len, &dummy))
    if (len != sizeof(address_raw_t)) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t _readBoolean(CborValue *value, bool *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborBooleanType)
    CHECK_CBOR_ERR(cbor_value_get_boolean(value, out))

    return parser_ok;
}

__Z_INLINE parser_error_t _readPublicKey(CborValue *value, publickey_t *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType)
    CborValue dummy;
    size_t len = sizeof(publickey_t);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) out, &len, &dummy))
    if (len != sizeof(publickey_t)) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t _readQuantity(CborValue *value, quantity_t *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType)
    CborValue dummy;
    MEMZERO(out, sizeof(quantity_t));
    out->len = sizeof_field(quantity_t, buffer);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) out->buffer, &out->len, &dummy))
    return parser_ok;
}

__Z_INLINE parser_error_t _readUint64(CborValue *value, uint64_t *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborIntegerType)
    CHECK_CBOR_ERR(cbor_value_get_uint64(value, out))

    return parser_ok;
}

__Z_INLINE parser_error_t _readRawSignature(CborValue *value, raw_signature_t *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType)
    CborValue dummy;
    size_t len = sizeof(raw_signature_t);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) out, &len, &dummy))
    if (len != sizeof(raw_signature_t)) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t _readString(CborValue *value, uint8_t *out, size_t maxLen) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborTextStringType)
    CborValue dummy;
    size_t len = maxLen;
    CHECK_CBOR_ERR(cbor_value_copy_text_string(value, (char *) out, &len, &dummy))
    if (len == 0) {
        return parser_unexpected_value;
    }
    return parser_ok;
}

__Z_INLINE parser_error_t _readOrigTo(CborValue *value, uint8_t *out) {
    if (value == NULL || out == NULL) {
        return parser_unexpected_value;
    }
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborTextStringType)
    CborValue dummy;
    size_t len = ORIG_TO_SIZE;
    char tmp[ORIG_TO_SIZE] = {0};
    CHECK_CBOR_ERR(cbor_value_copy_text_string(value, tmp, &len, &dummy))
    if (len == ORIG_TO_SIZE && (strncmp(tmp, "0x",2) == 0 || strncmp(tmp, "0X",2) == 0) ) {
        MEMCPY(out, tmp, ORIG_TO_SIZE);
    } else if (len == (ORIG_TO_SIZE-2) && (strncmp(tmp, "0x",2) != 0 || strncmp(tmp, "0X",2) != 0)) {
        out[0]= '0';
        out[1]= 'x';
        MEMCPY(out + 2, tmp, ORIG_TO_SIZE - 2);
    } else {
        return parser_unexpected_value;
    }

    return parser_ok;
}


__Z_INLINE parser_error_t _readRuntimeString(CborValue *value, string_t *out) {
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborByteStringType)
    CborValue dummy;
    MEMZERO(out, sizeof(string_t));
    out->len = sizeof_field(string_t, buffer);
    CHECK_CBOR_ERR(cbor_value_copy_byte_string(value, (uint8_t *) out->buffer, &out->len, &dummy))
    return parser_ok;
}

__Z_INLINE parser_error_t _readVersion(CborValue *target, version_t *out) {
    CborValue versions;
    size_t numItems;
    CHECK_CBOR_TYPE(cbor_value_get_type(target), CborMapType)
    CHECK_CBOR_ERR(cbor_value_get_map_length(target, &numItems))

    if( numItems == 0 ) {
        return parser_unexpected_value;
    }

    CHECK_CBOR_ERR(cbor_value_enter_container(target, &versions))

    if (CBOR_KEY_MATCHES(&versions, "major")){
        CHECK_CBOR_ERR(cbor_value_advance(&versions))
        CHECK_PARSER_ERR(_readUint64(&versions, &out->major))
        CHECK_CBOR_ERR(cbor_value_advance(&versions))
    } else {
        out->major = 0;
    }

    if (CBOR_KEY_MATCHES(&versions, "minor")){
        CHECK_CBOR_ERR(cbor_value_advance(&versions))
        CHECK_PARSER_ERR(_readUint64(&versions, &out->minor))
        CHECK_CBOR_ERR(cbor_value_advance(&versions))
    } else {
        out->minor = 0;
    }

    if (CBOR_KEY_MATCHES(&versions, "patch")) {
        CHECK_CBOR_ERR(cbor_value_advance(&versions))
        CHECK_PARSER_ERR(_readUint64(&versions, &out->patch))
        CHECK_CBOR_ERR(cbor_value_advance(&versions))
    } else {
        out->patch = 0;
    }

    return parser_ok;

}

__Z_INLINE parser_error_t _readSignature(CborValue *value, signature_t *out) {
// {
//   "signature": ...
//   "public_key": ...
// }

    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType)

    CHECK_CBOR_MAP_LEN(value, 2)
    CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents))

    CHECK_PARSER_ERR(_matchKey(&contents, "signature"))
    CHECK_CBOR_ERR(cbor_value_advance(&contents))
    CHECK_PARSER_ERR(_readRawSignature(&contents, &out->raw_signature))
    CHECK_CBOR_ERR(cbor_value_advance(&contents))

    CHECK_PARSER_ERR(_matchKey(&contents, "public_key"))
    CHECK_CBOR_ERR(cbor_value_advance(&contents))
    CHECK_PARSER_ERR(_readPublicKey(&contents, &out->public_key))
    CHECK_CBOR_ERR(cbor_value_advance(&contents))

    return parser_ok;
}

__Z_INLINE parser_error_t _readRate(CborValue *value, commissionRateStep_t *out) {
//      {
//        "rate": "0",
//        "start": 0
//      }
//  canonical cbor orders keys by length
// https://tools.ietf.org/html/rfc7049#section-3.9

    // Keys are optional. Set default values and try to find overriding fields
    MEMZERO(out, sizeof(commissionRateStep_t));

    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType)

    CborValue tmp;
    CHECK_CBOR_ERR(cbor_value_map_find_value(value, "rate", &tmp))
    if (cbor_value_is_valid(&tmp)) {
        CHECK_PARSER_ERR(_readQuantity(&tmp, &out->rate))
    }

    CHECK_CBOR_ERR(cbor_value_map_find_value(value, "start", &tmp))
    if (cbor_value_is_valid(&tmp)) {
        CHECK_CBOR_ERR(cbor_value_get_uint64(&tmp, &out->start))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readBound(CborValue *value, commissionRateBoundStep_t *out) {
//  {
//    "start": 0,
//    "rate_min": "0",
//    "rate_max": "0"
//  }
//  canonical cbor orders keys by length
// https://tools.ietf.org/html/rfc7049#section-3.9

    MEMZERO(out, sizeof(commissionRateBoundStep_t));

    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType)

    CborValue tmp;
    CHECK_CBOR_ERR(cbor_value_map_find_value(value, "start", &tmp))
    if (tmp.type != CborInvalidType) {
        CHECK_CBOR_ERR(cbor_value_get_uint64(&tmp, &out->start))
    }

    CHECK_CBOR_ERR(cbor_value_map_find_value(value, "rate_max", &tmp))
    if (tmp.type != CborInvalidType) {
        CHECK_PARSER_ERR(_readQuantity(&tmp, &out->rate_max))
    }

    CHECK_CBOR_ERR(cbor_value_map_find_value(value, "rate_min", &tmp))
    if (tmp.type != CborInvalidType) {
        CHECK_PARSER_ERR(_readQuantity(&tmp, &out->rate_min))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readAmendment(parser_tx_t *v, CborValue *value) {
//  {
//    "rates": [
//     ...
//    ],
//    "bounds": [
//     ...
//    ]
//  }

    /// Enter container
    CborValue contents;
    CHECK_CBOR_TYPE(cbor_value_get_type(value), CborMapType)
    CHECK_CBOR_MAP_LEN(value, 2)
    CHECK_CBOR_ERR(cbor_value_enter_container(value, &contents))

    CHECK_PARSER_ERR(_matchKey(&contents, "rates"))
    CHECK_CBOR_ERR(cbor_value_advance(&contents))
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborArrayType)

    // Array of rates
    cbor_value_get_array_length(&contents, &v->oasis.tx.body.stakingAmendCommissionSchedule.rates_length);

    CHECK_CBOR_ERR(cbor_value_advance(&contents))

    CHECK_PARSER_ERR(_matchKey(&contents, "bounds"))
    CHECK_CBOR_ERR(cbor_value_advance(&contents))
    CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborArrayType)

    // Array of bounds
    cbor_value_get_array_length(&contents, &v->oasis.tx.body.stakingAmendCommissionSchedule.bounds_length);

    return parser_ok;
}

__Z_INLINE parser_error_t _readFee(parser_tx_t *v, CborValue *rootItem) {
    v->oasis.tx.has_fee = false;

    CborValue feeField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "fee", &feeField))

    // We have fee
    //    "fee": {
    //        "gas": 0,
    //        "amount": ""
    //    },
    if (cbor_value_is_valid(&feeField)) {
        v->oasis.tx.has_fee = true;

        CborValue tmp;
        CHECK_CBOR_TYPE(cbor_value_get_type(&feeField), CborMapType)

        CHECK_CBOR_ERR(cbor_value_map_find_value(&feeField, "gas", &tmp))
        if (cbor_value_is_valid(&tmp)) {
            CHECK_CBOR_ERR(cbor_value_get_uint64(&tmp, &v->oasis.tx.fee_gas))
        }

        CHECK_CBOR_ERR(cbor_value_map_find_value(&feeField, "amount", &tmp))
        if (cbor_value_is_valid(&tmp)) {
            CHECK_PARSER_ERR(_readQuantity(&tmp, &v->oasis.tx.fee_amount))
        }
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readEntity(oasis_entity_t *entity) {
    /* Not using cbor_value_map_find because Cbor canonical order should be respected */
    CborValue value = entity->cborState.startValue;    // copy to avoid moving the original iteratorCborValue contents;
    CborValue tmp;

    CHECK_CBOR_TYPE(cbor_value_get_type(&value), CborMapType)

    CHECK_CBOR_ERR(cbor_value_map_find_value(&value, "v", &tmp))
    if (cbor_value_is_valid(&tmp)) {
        if (!cbor_value_is_unsigned_integer(&tmp)) {
            return parser_unexpected_type;
        }
        CHECK_CBOR_ERR(cbor_value_get_uint64(&tmp, &entity->obj.descriptor_version))
    }

    CHECK_CBOR_ERR(cbor_value_map_find_value(&value, "id", &tmp))
    if (cbor_value_is_valid(&tmp)) {
        CHECK_PARSER_ERR(_readPublicKey(&tmp, &entity->obj.id))
    }

    CHECK_CBOR_ERR(cbor_value_map_find_value(&value, "nodes", &tmp))
    // Only get length
    if (cbor_value_is_valid(&tmp)) {
        CHECK_CBOR_TYPE(cbor_value_get_type(&tmp), CborArrayType)
        CHECK_CBOR_ERR(cbor_value_get_array_length(&tmp, &entity->obj.nodes_length));
    }

    // too many node ids in the blob to be printed
    if (entity->obj.nodes_length > MAX_ENTITY_NODES) {
        return parser_unexpected_number_items;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readBody(parser_tx_t *v, CborValue *rootItem) {
    if (v->oasis.tx.method == registryDeregisterEntity) {
        // This method doesn't have a body
        return parser_ok;
    }

    CborValue bodyField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "body", &bodyField))
    if (!cbor_value_is_valid(&bodyField))
        return parser_required_body;
    CHECK_CBOR_TYPE(cbor_value_get_type(&bodyField), CborMapType)

    CborValue contents;
    size_t numItems;

    switch (v->oasis.tx.method) {
        case stakingTransfer: {
            CHECK_CBOR_MAP_LEN(&bodyField, 2)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "to"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readAddressRaw(&contents, &v->oasis.tx.body.stakingTransfer.to))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "amount"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingTransfer.amount))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            break;
        }
        case stakingBurn: {
            CHECK_CBOR_MAP_LEN(&bodyField, 1)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "amount"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingBurn.amount))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            break;
        }
        case stakingWithdraw: {

            CHECK_CBOR_MAP_LEN(&bodyField, 2)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "from"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readAddressRaw(&contents, &v->oasis.tx.body.stakingWithdraw.from))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "amount"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingWithdraw.amount))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            break;
        }
        case stakingAllow: {
            CHECK_CBOR_ERR(cbor_value_get_map_length(&bodyField, &numItems))
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))
            if(numItems < 2 || numItems > 3) return parser_unexpected_number_items;

            if( numItems == 3 ){
                CHECK_PARSER_ERR(_matchKey(&contents, "negative"))
                CHECK_CBOR_ERR(cbor_value_advance(&contents))
                CHECK_PARSER_ERR(_readBoolean(&contents, &v->oasis.tx.body.stakingAllow.negative))
                CHECK_CBOR_ERR(cbor_value_advance(&contents))
            } else {
                v->oasis.tx.body.stakingAllow.negative = false;
            }

            CHECK_PARSER_ERR(_matchKey(&contents, "beneficiary"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readAddressRaw(&contents, &v->oasis.tx.body.stakingAllow.beneficiary))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "amount_change"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingAllow.amount_change))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            break;
        }
        case stakingEscrow: {
            CHECK_CBOR_MAP_LEN(&bodyField, 2)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "amount"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingEscrow.amount))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "account"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readAddressRaw(&contents, &v->oasis.tx.body.stakingEscrow.account))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            break;
        }
        case stakingReclaimEscrow: {
            CHECK_CBOR_MAP_LEN(&bodyField, 2)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "shares"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.tx.body.stakingReclaimEscrow.shares))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "account"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readAddressRaw(&contents, &v->oasis.tx.body.stakingReclaimEscrow.account))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            break;
        }
        case stakingAmendCommissionSchedule: {
            CHECK_CBOR_MAP_LEN(&bodyField, 1)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "amendment"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            // ONLY READ LENGTH ! THEN GET ON ITEM ON DEMAND
            CHECK_PARSER_ERR(_readAmendment(v, &contents))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            break;
        }
        case registryUnfreezeNode: {
            CHECK_CBOR_MAP_LEN(&bodyField, 1)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "node_id"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readPublicKey(&contents, &v->oasis.tx.body.registryUnfreezeNode.node_id))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            break;
        }
        case registryRegisterEntity : {
            CHECK_CBOR_MAP_LEN(&bodyField, 2)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "signature"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            // Read signature
            CHECK_PARSER_ERR(_readSignature(&contents, &v->oasis.tx.body.registryRegisterEntity.signature))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "untrusted_raw_value"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            if (!cbor_value_is_byte_string(&contents)) {
                return parser_unexpected_type;
            }

            // We create new Cbor parser with the byte string
            const uint8_t *buffer;
            size_t buffer_size;

            CHECK_CBOR_ERR(_cbor_value_begin_string_iteration(&contents))
            CHECK_CBOR_ERR(_cbor_value_get_string_chunk(&contents, (const void **) &buffer, &buffer_size, NULL))
            cbor_parser_state_t *cborState = &v->oasis.tx.body.registryRegisterEntity.entity.cborState;
            CHECK_CBOR_ERR(cbor_parser_init(buffer, buffer_size, 0, &cborState->parser, &cborState->startValue))

            // Now we can read entity
            CHECK_PARSER_ERR(_readEntity(&v->oasis.tx.body.registryRegisterEntity.entity))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            break;
        }
        case governanceSubmitProposal: {
            CHECK_CBOR_ERR(cbor_value_get_map_length(&bodyField, &numItems))
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))
            if (numItems != 1) {
                return parser_unexpected_number_items;
            }

            if (CBOR_KEY_MATCHES(&contents, "upgrade")){
                CborValue upgradeVal;
                CHECK_CBOR_ERR(cbor_value_advance(&contents))
                CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborMapType)
                CHECK_CBOR_MAP_LEN(&contents, 4)
                CHECK_CBOR_ERR(cbor_value_enter_container(&contents, &upgradeVal))

                CHECK_PARSER_ERR(_matchKey(&upgradeVal, "v"))
                CHECK_CBOR_ERR(cbor_value_advance(&upgradeVal))
                CHECK_PARSER_ERR(_readUint64(&upgradeVal, &v->oasis.tx.body.governanceSubmitProposal.upgrade.version))
                CHECK_CBOR_ERR(cbor_value_advance(&upgradeVal))
                if (v->oasis.tx.body.governanceSubmitProposal.upgrade.version == 0){
                    return parser_unexpected_value;
                }

                // epoch element is a uint64
                CHECK_PARSER_ERR(_matchKey(&upgradeVal, "epoch"))
                CHECK_CBOR_ERR(cbor_value_advance(&upgradeVal))
                CHECK_PARSER_ERR(_readUint64(&upgradeVal, &v->oasis.tx.body.governanceSubmitProposal.upgrade.epoch))
                CHECK_CBOR_ERR(cbor_value_advance(&upgradeVal))
                if(v->oasis.tx.body.governanceSubmitProposal.upgrade.epoch < 1 || v->oasis.tx.body.governanceSubmitProposal.upgrade.epoch >= EPOCH_MAX_VALUE){
                    return parser_unexpected_value;
                }

                // Target element is a map
                CborValue target;
                CHECK_PARSER_ERR(_matchKey(&upgradeVal, "target"))
                CHECK_CBOR_ERR(cbor_value_advance(&upgradeVal))
                CHECK_CBOR_TYPE(cbor_value_get_type(&upgradeVal), CborMapType)
                CHECK_CBOR_MAP_LEN(&upgradeVal, 3)
                CHECK_CBOR_ERR(cbor_value_enter_container(&upgradeVal, &target))
                CHECK_CBOR_ERR(cbor_value_advance(&upgradeVal))

                // consensus_protocol is an element of target map
                CHECK_PARSER_ERR(_matchKey(&target, "consensus_protocol"))
                CHECK_CBOR_ERR(cbor_value_advance(&target))
                CHECK_PARSER_ERR(_readVersion(&target, &v->oasis.tx.body.governanceSubmitProposal.upgrade.target.consensus_protocol))
                CHECK_CBOR_ERR(cbor_value_advance(&target))

                // runtime_committee_protocol is an element of target map
                CHECK_PARSER_ERR(_matchKey(&target, "runtime_host_protocol"))
                CHECK_CBOR_ERR(cbor_value_advance(&target))
                CHECK_PARSER_ERR(_readVersion(&target, &v->oasis.tx.body.governanceSubmitProposal.upgrade.target.runtime_host_protocol))
                CHECK_CBOR_ERR(cbor_value_advance(&target))

                // runtime_host_protocol is an element of target map
                CHECK_PARSER_ERR(_matchKey(&target, "runtime_committee_protocol"))
                CHECK_CBOR_ERR(cbor_value_advance(&target))
                CHECK_PARSER_ERR(_readVersion(&target, &v->oasis.tx.body.governanceSubmitProposal.upgrade.target.runtime_committee_protocol))
                CHECK_CBOR_ERR(cbor_value_advance(&target))

                // handler element is a string
                CHECK_PARSER_ERR(_matchKey(&upgradeVal, "handler"))
                CHECK_CBOR_ERR(cbor_value_advance(&upgradeVal))
                CHECK_PARSER_ERR(_readString(&upgradeVal,(uint8_t *) &v->oasis.tx.body.governanceSubmitProposal.upgrade.handler, HANDLER_MAX_LENGTH));
                CHECK_CBOR_ERR(cbor_value_advance(&upgradeVal))


                v->oasis.tx.body.governanceSubmitProposal.type = upgrade;
            } else if (CBOR_KEY_MATCHES(&contents, "cancel_upgrade")){
                CborValue cancelUpgradeVal;
                CHECK_CBOR_ERR(cbor_value_advance(&contents))
                CHECK_CBOR_TYPE(cbor_value_get_type(&contents), CborMapType)
                CHECK_CBOR_MAP_LEN(&contents, 1)
                CHECK_CBOR_ERR(cbor_value_enter_container(&contents, &cancelUpgradeVal))

                // epoch element is a uint64
                CHECK_PARSER_ERR(_matchKey(&cancelUpgradeVal, "proposal_id"))
                CHECK_CBOR_ERR(cbor_value_advance(&cancelUpgradeVal))
                CHECK_PARSER_ERR(_readUint64(&cancelUpgradeVal, &v->oasis.tx.body.governanceSubmitProposal.cancel_upgrade.proposal_id))
                CHECK_CBOR_ERR(cbor_value_advance(&cancelUpgradeVal))

                v->oasis.tx.body.governanceSubmitProposal.type = cancelUpgrade;
            } else {
                CHECK_PARSER_ERR(parser_unexpected_field);
            }

            break;
        }
        case governanceCastVote: {
            CHECK_CBOR_MAP_LEN(&bodyField, 2)
            CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "id"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readUint64(&contents, &v->oasis.tx.body.governanceCastVote.id))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            CHECK_PARSER_ERR(_matchKey(&contents, "vote"))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))
            CHECK_PARSER_ERR(_readUint64(&contents, &v->oasis.tx.body.governanceCastVote.vote))
            CHECK_CBOR_ERR(cbor_value_advance(&contents))

            break;
        }
        case unknownMethod:
        default:
            return parser_unexpected_method;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readNonce(parser_tx_t *v, CborValue *rootItem) {
    CborValue nonceField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "nonce", &nonceField))
    if (!cbor_value_is_valid(&nonceField))
        return parser_required_nonce;

    CHECK_CBOR_TYPE(cbor_value_get_type(&nonceField), CborIntegerType)
    CHECK_CBOR_ERR(cbor_value_get_uint64(&nonceField, &v->oasis.tx.nonce))

    return parser_ok;
}

__Z_INLINE parser_error_t _readMethod(parser_tx_t *v, CborValue *rootItem) {
    v->oasis.tx.method = unknownMethod;
    if (!cbor_value_is_valid(rootItem)) {
        return parser_required_method;
    }
    // Verify it is well formed (no missing bytes...)
    CHECK_CBOR_ERR(cbor_value_validate_basic(rootItem))

    CborValue tmp;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "method", &tmp))
    if (!cbor_value_is_valid(&tmp)) {
        return parser_required_method;
    }

    if (CBOR_KEY_MATCHES(&tmp, "staking.Transfer")) {
        v->oasis.tx.method = stakingTransfer;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "staking.Burn")) {
        v->oasis.tx.method = stakingBurn;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "staking.Withdraw")) {
        v->oasis.tx.method = stakingWithdraw;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "staking.Allow")) {
        v->oasis.tx.method = stakingAllow;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "staking.AddEscrow")) {
        v->oasis.tx.method = stakingEscrow;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "staking.ReclaimEscrow")) {
        v->oasis.tx.method = stakingReclaimEscrow;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "staking.AmendCommissionSchedule")) {
        v->oasis.tx.method = stakingAmendCommissionSchedule;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "registry.DeregisterEntity")) {
        v->oasis.tx.method = registryDeregisterEntity;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "registry.UnfreezeNode")) {
        v->oasis.tx.method = registryUnfreezeNode;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "registry.RegisterEntity")) {
        v->oasis.tx.method = registryRegisterEntity;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "governance.SubmitProposal")) {
        v->oasis.tx.method = governanceSubmitProposal;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "governance.CastVote")) {
        v->oasis.tx.method = governanceCastVote;
        return parser_ok;
    }

    return parser_unexpected_method;
}

__Z_INLINE parser_error_t _readFormatVersion(parser_tx_t *v, CborValue *rootItem) {
    // v: format version (uint16, required, must be 1)
    CborValue vField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "v", &vField))
    if (!cbor_value_is_valid(&vField))
        return parser_required_v;

    CHECK_CBOR_TYPE(cbor_value_get_type(&vField), CborIntegerType)

    int64_t tmpVersion = v->oasis.entity_metadata.v;
    CHECK_CBOR_ERR(cbor_value_get_int64_checked(&vField, &tmpVersion))
    v->oasis.entity_metadata.v = tmpVersion;

    if (v->oasis.entity_metadata.v != ENTITY_METADATA_V) {
        return parser_invalid_v_value;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeVersion(parser_tx_t *v, CborValue *rootItem) {
    // v: format version (uint16, required, must be 1)
    CborValue vField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "v", &vField))
    if (!cbor_value_is_valid(&vField))
        return parser_required_v;

    CHECK_CBOR_TYPE(cbor_value_get_type(&vField), CborIntegerType)

    int64_t tmpVersion = v->oasis.runtime.v;
    CHECK_CBOR_ERR(cbor_value_get_int64_checked(&vField, &tmpVersion))
    v->oasis.runtime.v = tmpVersion;

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeMeta(parser_tx_t *v, CborValue *rootItem) {
    CborValue dataField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "chain_context", &dataField))
    if (!cbor_value_is_valid(&dataField)) {
        return parser_required_chain_context;
    }
    CHECK_PARSER_ERR(_readString(&dataField, (uint8_t *)&v->oasis.runtime.meta.chain_context, sizeof(v->oasis.runtime.meta.chain_context)))

    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "runtime_id", &dataField))
    if (!cbor_value_is_valid(&dataField)) {
        return parser_required_runtime_id;
    }
    CHECK_PARSER_ERR(_readString(&dataField, (uint8_t *)&v->oasis.runtime.meta.runtime_id, sizeof(v->oasis.runtime.meta.runtime_id)))

    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "orig_to", &dataField))
    if (cbor_value_is_valid(&dataField)) {
         v->oasis.runtime.meta.has_orig_to = true;
        CHECK_PARSER_ERR(_readOrigTo(&dataField, (uint8_t *)&v->oasis.runtime.meta.orig_to))
    } else {
        v->oasis.runtime.meta.has_orig_to = false;
        MEMZERO((void *)&v->oasis.runtime.meta.orig_to,sizeof(v->oasis.runtime.meta.orig_to));
    }
    return parser_ok;
}

__Z_INLINE parser_error_t _readSerial(parser_tx_t *v, CborValue *rootItem) {
    // serial: the serial number of the entity metadata statement where the highest serial number should be treated as the most recent (uint64)
    CborValue serialField;

    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "serial", &serialField))
    if (!cbor_value_is_valid(&serialField))
        return parser_required_serial;

    CHECK_CBOR_TYPE(cbor_value_get_type(&serialField), CborIntegerType)
    CHECK_CBOR_ERR(cbor_value_get_uint64(&serialField, &v->oasis.entity_metadata.serial))

    return parser_ok;
}

__Z_INLINE parser_error_t _readName(parser_tx_t *v, CborValue *rootItem) {
    // name: an entity name (string, optional, max 50 characters)
    CborValue nameField;
    CborValue dummy;
    size_t cbor_name_length;

    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "name", &nameField))
    if (!cbor_value_is_valid(&nameField)) {
        v->oasis.entity_metadata.name.len = 0;
        return parser_ok;
    }

    CHECK_CBOR_TYPE(cbor_value_get_type(&nameField), CborTextStringType)
    MEMZERO(&v->oasis.entity_metadata.name, sizeof(name_t));
    v->oasis.entity_metadata.name.len = sizeof_field(name_t, buffer);

    CHECK_CBOR_ERR(cbor_value_get_string_length(&nameField, &cbor_name_length))
    if (cbor_name_length > ENTITY_METADATA_NAME_MAX_CHAR) {
        return parser_invalid_name_length;
    }

    CHECK_CBOR_ERR(cbor_value_copy_text_string(&nameField, (char *) &v->oasis.entity_metadata.name.buffer,
                                                 &v->oasis.entity_metadata.name.len, &dummy))

    return parser_ok;
}

parser_error_t _isValidUrl(url_t *url) {
    // Verify they are all printable char
    for (uint8_t i = 0; i < (uint8_t)url->len; i++) {
        uint8_t c = *(url->buffer + i);
        // 33  because no space in url
        if (c < 33 || c > 127) {
            return parser_invalid_url_format;
        }
    }

    const char https_prefix[] = "https://";
    if (strncmp(https_prefix, (const char *) url->buffer, strlen(https_prefix)) != 0)
        return parser_invalid_url_format;

    // Dectect query by lookin for the `?` separator
    char query_separator = '?';
    if (strchr((const char *) url->buffer, query_separator) != NULL)
        return parser_invalid_url_format;

    // Dectect fragment by looking for the `#` the fragment identifier
    char fragment_identifier = '#';
    if (strchr((const char *) url->buffer, fragment_identifier) != NULL)
        return parser_invalid_url_format;

    return parser_ok;
}

__Z_INLINE parser_error_t _readUrl(parser_tx_t *v, CborValue *rootItem) {
    // url: an URL associated with the entity (string, optional, max 64 characters, must be a valid URL using the scheme https without any query or fragments)
    CborValue urlField;
    CborValue dummy;
    size_t cbor_url_length;

    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "url", &urlField))
    if (!cbor_value_is_valid(&urlField)) {
        v->oasis.entity_metadata.url.len = 0;
        return parser_ok;
    }

    CHECK_CBOR_ERR(cbor_value_get_string_length(&urlField, &cbor_url_length))
    if (cbor_url_length > ENTITY_METADATA_URL_MAX_CHAR) {
        return parser_invalid_url_length;
    }

    CHECK_CBOR_TYPE(cbor_value_get_type(&urlField), CborTextStringType)
    MEMZERO(&v->oasis.entity_metadata.url, sizeof(url_t));
    v->oasis.entity_metadata.url.len = sizeof_field(url_t, buffer);
    CHECK_CBOR_ERR(cbor_value_copy_text_string(&urlField, (char *) &v->oasis.entity_metadata.url.buffer,
                                               &v->oasis.entity_metadata.url.len, &dummy))

    CHECK_PARSER_ERR(_isValidUrl(&v->oasis.entity_metadata.url))

    return parser_ok;
}

parser_error_t _isValidEmail(email_t *email) {
    uint8_t arobase_count = 0;
    uint8_t punct_count = 0;

    for (uint8_t i = 0; i < (uint8_t)email->len; i++) {
        uint8_t c = *(email->buffer + i);
        // Verify they are all printable char
        if (c < 33 || c > 127) {
            return parser_invalid_email_format;
        }

        // Should have exactly one @
        if (c == '@') {
            arobase_count++;
            continue;
        }

        // We are in the second part of the email
        if (arobase_count == 1) {
            if (c == '.') {
                punct_count++;
                continue;
            }
            if ((c < 48 || c > 57) && (c < 65 || c > 90) && (c < 97 || c > 122) && c != '-') {
                return parser_invalid_email_format;
            }
        }

    }

    if (arobase_count > 1 || punct_count < 1)
        return parser_invalid_email_format;

    return parser_ok;
}

__Z_INLINE parser_error_t _readEmail(parser_tx_t *v, CborValue *rootItem) {
    // email: an e-mail address associated with the entity (string, optional, max 32 characters, must be a valid e-mail address)
    CborValue emailField;
    CborValue dummy;
    size_t cbor_email_length;

    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "email", &emailField))
    if (!cbor_value_is_valid(&emailField)) {
        v->oasis.entity_metadata.email.len = 0;
        return parser_ok;
    }

    CHECK_CBOR_ERR(cbor_value_get_string_length(&emailField, &cbor_email_length))
    if (cbor_email_length > ENTITY_METADATA_EMAIL_MAX_CHAR) {
        return parser_invalid_email_length;
    }


    CHECK_CBOR_TYPE(cbor_value_get_type(&emailField), CborTextStringType)
    MEMZERO(&v->oasis.entity_metadata.email, sizeof(email_t));
    v->oasis.entity_metadata.email.len = sizeof_field(email_t, buffer);
    CHECK_CBOR_ERR(cbor_value_copy_text_string(&emailField, (char *) &v->oasis.entity_metadata.email.buffer,
                                               &v->oasis.entity_metadata.email.len, &dummy))

    CHECK_PARSER_ERR(_isValidEmail(&v->oasis.entity_metadata.email))

    return parser_ok;
}

parser_error_t _isValidHandle(handle_t *handle) {
    // Verify they are all printable char
    for (uint8_t i = 0; i < (uint8_t)handle->len; i++) {
        uint8_t c = *(handle->buffer + i);
        if ((c < 48 || c > 57) && (c < 65 || c > 90) && (c < 97 || c > 122) && c != '-' && c != '_') {
            return parser_invalid_handle_format;
        }
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readKeybase(parser_tx_t *v, CborValue *rootItem) {
    //keybase: a keybase.io handle (string, optional, max 32 characters, must match the regular expression ^[A-Za-z0-9_]+$)
    CborValue keybaseField;
    CborValue dummy;
    size_t cbor_keybase_length;

    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "keybase", &keybaseField))
    if (!cbor_value_is_valid(&keybaseField)) {
        v->oasis.entity_metadata.keybase.len = 0;
        return parser_ok;
    }

    CHECK_CBOR_ERR(cbor_value_get_string_length(&keybaseField, &cbor_keybase_length))
    if (cbor_keybase_length > ENTITY_METADATA_HANDLE_MAX_CHAR) {
        return parser_invalid_handle_length;
    }

    CHECK_CBOR_TYPE(cbor_value_get_type(&keybaseField), CborTextStringType)
    MEMZERO(&v->oasis.entity_metadata.keybase, sizeof(handle_t));
    v->oasis.entity_metadata.keybase.len = sizeof_field(handle_t, buffer);
    CHECK_CBOR_ERR(cbor_value_copy_text_string(&keybaseField, (char *) &v->oasis.entity_metadata.keybase.buffer,
                                               &v->oasis.entity_metadata.keybase.len, &dummy))

    CHECK_PARSER_ERR(_isValidHandle(&v->oasis.entity_metadata.keybase))

    return parser_ok;
}

__Z_INLINE parser_error_t _readTwitter(parser_tx_t *v, CborValue *rootItem) {
    //twitter: a Twitter handle (string, optional, max 32 characters, must match the regular expression ^[A-Za-z0-9_]+$)
    CborValue twitterField;
    CborValue dummy;
    size_t cbor_twitter_length;

    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "twitter", &twitterField))
    if (!cbor_value_is_valid(&twitterField)) {
        v->oasis.entity_metadata.twitter.len = 0;
        return parser_ok;
    }

    CHECK_CBOR_ERR(cbor_value_get_string_length(&twitterField, &cbor_twitter_length))
    if (cbor_twitter_length > ENTITY_METADATA_HANDLE_MAX_CHAR) {
        return parser_invalid_handle_length;
    }

    CHECK_CBOR_TYPE(cbor_value_get_type(&twitterField), CborTextStringType)
    MEMZERO(&v->oasis.entity_metadata.twitter, sizeof(handle_t));
    v->oasis.entity_metadata.twitter.len = sizeof_field(handle_t, buffer);
    CHECK_CBOR_ERR(cbor_value_copy_text_string(&twitterField, (char *) &v->oasis.entity_metadata.twitter.buffer,
                                               &v->oasis.entity_metadata.twitter.len, &dummy))

    CHECK_PARSER_ERR(_isValidHandle(&v->oasis.entity_metadata.twitter))

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeMethod(parser_tx_t *v, CborValue *rootItem) {
    v->oasis.runtime.call.method = unknownMethod;
    if (!cbor_value_is_valid(rootItem)) {
        return parser_required_method;
    }
    // Verify it is well formed (no missing bytes...)
    CHECK_CBOR_ERR(cbor_value_validate_basic(rootItem))

    CborValue tmp;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "method", &tmp))

    if (CBOR_KEY_MATCHES(&tmp, "accounts.Transfer")) {
        v->oasis.runtime.call.method = accountsTransfer;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "consensus.Deposit")) {
        v->oasis.runtime.call.method = consensusDeposit;
        return parser_ok;
    }
    if (CBOR_KEY_MATCHES(&tmp, "consensus.Withdraw")) {
        v->oasis.runtime.call.method = consensusWithdraw;
        return parser_ok;
    }

    if (CBOR_KEY_MATCHES(&tmp, "contracts.Upgrade")) {
        v->oasis.runtime.call.method = contractsUpgrade;
        return parser_ok;
    }

    if (CBOR_KEY_MATCHES(&tmp, "contracts.Instantiate")) {
        v->oasis.runtime.call.method = contractsInstantiate;
        return parser_ok;
    }

    if (CBOR_KEY_MATCHES(&tmp, "contracts.Call")) {
        v->oasis.runtime.call.method = contractsCall;
        return parser_ok;
    }

        if (CBOR_KEY_MATCHES(&tmp, "evm.Call")) {
        v->oasis.runtime.call.method = evmCall;
        return parser_ok;
    }

    if (CBOR_KEY_MATCHES(&tmp, "consensus.Delegate")) {
        v->oasis.runtime.call.method = consensusDelegate;
        return parser_ok;
    }

    if (CBOR_KEY_MATCHES(&tmp, "consensus.Undelegate")) {
        v->oasis.runtime.call.method = consensusUndelegate;
        return parser_ok;
    }

    return parser_unexpected_method;
}

__Z_INLINE parser_error_t _readRuntimeContractsBody(parser_tx_t *v, CborValue *rootItem) {
    if (!cbor_value_is_valid(rootItem)) {
        return parser_required_method;
    }
    // Verify it is well formed (no missing bytes...)
    CHECK_CBOR_ERR(cbor_value_validate_basic(rootItem))

    CborValue bodyField;
    size_t numItems = 0;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "body", &bodyField))
    if (!cbor_value_is_valid(&bodyField))
        return parser_required_body;

    CHECK_CBOR_ERR(cbor_value_get_map_length(&bodyField, &numItems))
    if (numItems < 1 || numItems > 5) return parser_unexpected_number_items;

    CborValue contents;
    if (v->oasis.runtime.call.method != contractsInstantiate) {
        CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "id", &contents))
        if (!cbor_value_is_valid(&contents) || !cbor_value_is_unsigned_integer(&contents)) {
            return parser_required_id;
        }
        CHECK_CBOR_ERR(cbor_value_get_uint64(&contents, &v->oasis.runtime.call.body.contracts.id))
    }

    if (v->oasis.runtime.call.method != contractsCall) {
        CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "code_id", &contents))
        if (!cbor_value_is_valid(&contents) || !cbor_value_is_unsigned_integer(&contents)) {
            return parser_required_code_id;
        }
        CHECK_CBOR_ERR(cbor_value_get_uint64(&contents, &v->oasis.runtime.call.body.contracts.code_id))
    }

   CborValue dataField;
   CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "data", &dataField))
   if (cbor_value_is_valid(&dataField) ) {
        v->oasis.runtime.call.body.contracts.dataValid = true;
        // We create new Cbor parser with the byte string from data
        uint8_t *buf;
        size_t buffer_size;
        CHECK_CBOR_ERR(_cbor_value_begin_string_iteration(&dataField))
        CHECK_CBOR_ERR(_cbor_value_get_string_chunk(&dataField, (const void **) &buf, &buffer_size, NULL))
        v->oasis.runtime.call.body.contracts.dataPtr = buf;
        v->oasis.runtime.call.body.contracts.dataLen = buffer_size;
        cbor_parser_state_t *cborState = &v->oasis.runtime.call.body.contracts.cborState;
        CHECK_CBOR_ERR(cbor_parser_init(buf, buffer_size, 0, &cborState->parser, &cborState->startValue))

        CborValue data = cborState->startValue;
        size_t data_size=0;
        cbor_value_get_map_length(&data,&data_size);
        if (cbor_value_get_type(&data) != CborMapType || data_size == 0) {
            v->oasis.runtime.call.body.contracts.dataValid = false;
            v->oasis.runtime.call.body.contracts.dataPtr = NULL;
            v->oasis.runtime.call.body.contracts.dataLen = 0;
        }
   } else {
        v->oasis.runtime.call.body.contracts.dataPtr = NULL;
        v->oasis.runtime.call.body.contracts.dataLen = 0;
        v->oasis.runtime.call.body.contracts.dataValid = false;
   }

    CborValue tokensField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "tokens", &tokensField))
    CHECK_CBOR_TYPE(cbor_value_get_type(&tokensField), CborArrayType)

    // Array of tokens
    cbor_value_get_array_length(&tokensField, &v->oasis.runtime.call.body.contracts.tokensLen);
    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeConsensusBody(parser_tx_t *v, CborValue *rootItem) {
    if (!cbor_value_is_valid(rootItem)) {
        return parser_required_method;
    }
    // Verify it is well formed (no missing bytes...)
    CHECK_CBOR_ERR(cbor_value_validate_basic(rootItem))

    CborValue bodyField;
    size_t numItems = 0;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "body", &bodyField))
    if (!cbor_value_is_valid(&bodyField))
        return parser_required_body;

    CHECK_CBOR_ERR(cbor_value_get_map_length(&bodyField, &numItems))
    if (numItems < 1 || numItems > 2) return parser_unexpected_number_items;


    CborValue contents;
    CHECK_CBOR_ERR(cbor_value_enter_container(&bodyField, &contents))
    if (CBOR_KEY_MATCHES(&contents, "to") || CBOR_KEY_MATCHES(&contents, "from")) {
        v->oasis.runtime.call.body.consensus.has_to = true;
        CHECK_CBOR_ERR(cbor_value_advance(&contents))
        CHECK_PARSER_ERR(_readAddressRaw(&contents, &v->oasis.runtime.call.body.consensus.to))
        CHECK_CBOR_ERR(cbor_value_advance(&contents))
    } else {
        v->oasis.runtime.call.body.consensus.has_to = false;
        MEMZERO(&v->oasis.runtime.call.body.consensus.to, sizeof(address_raw_t));
    }
    if(v->oasis.runtime.call.method != consensusUndelegate) {
        CborValue amount;
        CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "amount", &amount))
        if (!cbor_value_is_valid(&amount)) {
            return parser_required_call;
        }
        CHECK_CBOR_ERR(cbor_value_enter_container(&amount, &contents))
        CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.runtime.call.body.consensus.amount))
        CHECK_CBOR_ERR(cbor_value_advance(&contents))
        CHECK_PARSER_ERR(_readRuntimeString(&contents, &v->oasis.runtime.call.body.consensus.denom))
    } else {
        CborValue shares;
        CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "shares", &shares))
        if (!cbor_value_is_valid(&shares)) {
            return parser_required_call;
        }
        CHECK_CBOR_ERR(cbor_value_advance(&contents))
        CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.runtime.call.body.consensus.shares))
        CHECK_CBOR_ERR(cbor_value_advance(&contents))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeEncrypted(parser_tx_t *v, CborValue *rootItem) {
    if (!cbor_value_is_valid(rootItem)) {
        return parser_required_method;
    }
    // Verify it is well formed (no missing bytes...)
    CHECK_CBOR_ERR(cbor_value_validate_basic(rootItem))
    CborValue bodyField;
    size_t numItems = 0;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "body", &bodyField))
    if (!cbor_value_is_valid(&bodyField))
        return parser_required_body;

    CHECK_CBOR_ERR(cbor_value_get_map_length(&bodyField, &numItems))
    if (numItems < 1 || numItems > 4) return parser_unexpected_number_items;

    CborValue pkField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "pk", &pkField))
    if (!cbor_value_is_valid(&pkField)) {
        return parser_required_pk;
    }
    CHECK_PARSER_ERR(_readPublicKey(&pkField, &v->oasis.runtime.call.body.encrypted.pk))

    CborValue nonceField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "nonce", &nonceField))
    if (!cbor_value_is_valid(&nonceField)) {
        return parser_required_nonce;
    }
    CHECK_PARSER_ERR(_readRuntimeString(&nonceField, &v->oasis.runtime.call.body.encrypted.nonce))

    CborValue dataField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "data", &dataField))
    if (!cbor_value_is_valid(&dataField)) {
        return parser_required_nonce;
    }
    const uint8_t *buffer;
    size_t buffer_size;
    CHECK_CBOR_ERR(_cbor_value_begin_string_iteration(&dataField))
    CHECK_CBOR_ERR(_cbor_value_get_string_chunk(&dataField, (const void **) &buffer, &buffer_size, NULL))

    MEMZERO(&v->oasis.runtime.call.body.encrypted.data_hash, sizeof(v->oasis.runtime.call.body.encrypted.data_hash));
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    cx_sha256_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cx_sha256_init_no_throw(&ctx);
   CHECK_CX_PARSER_OK(cx_hash_no_throw(&ctx.header, CX_LAST, buffer, buffer_size, (unsigned char *)&v->oasis.runtime.call.body.encrypted.data_hash,
            sizeof(v->oasis.runtime.call.body.encrypted.data_hash)));
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, buffer, buffer_size);
    picohash_final(&ctx, &v->oasis.runtime.call.body.encrypted.data_hash);
#endif

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeEvmBody(parser_tx_t *v, CborValue *rootItem) {
    if (!cbor_value_is_valid(rootItem)) {
        return parser_required_method;
    }
    // Verify it is well formed (no missing bytes...)
    CHECK_CBOR_ERR(cbor_value_validate_basic(rootItem))
    CborValue bodyField;
    size_t numItems;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "body", &bodyField))
    if (!cbor_value_is_valid(&bodyField))
        return parser_required_body;

    CHECK_CBOR_ERR(cbor_value_get_map_length(&bodyField, &numItems))
    if (numItems < 1 || numItems > 4) return parser_unexpected_number_items;

    CborValue addrField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "address", &addrField))
    if (!cbor_value_is_valid(&addrField)) {
        return parser_required_nonce;
    }
    CHECK_PARSER_ERR(_readRuntimeString(&addrField, &v->oasis.runtime.call.body.evm.address))

    CborValue dataField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "data", &dataField))
    if (!cbor_value_is_valid(&dataField)) {
        return parser_required_nonce;
    }
    const uint8_t *buffer;
    size_t buffer_size;
    CHECK_CBOR_ERR(_cbor_value_begin_string_iteration(&dataField))
    CHECK_CBOR_ERR(_cbor_value_get_string_chunk(&dataField, (const void **) &buffer, &buffer_size, NULL))

    MEMZERO(&v->oasis.runtime.call.body.evm.data_hash, sizeof(v->oasis.runtime.call.body.evm.data_hash));
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX) || defined(TARGET_FLEX)
    cx_sha256_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cx_sha256_init_no_throw(&ctx);
    CHECK_CX_PARSER_OK(cx_hash_no_throw(&ctx.header, CX_LAST, buffer, buffer_size, (unsigned char *)&v->oasis.runtime.call.body.encrypted.data_hash,
                     sizeof(v->oasis.runtime.call.body.encrypted.data_hash)));
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, buffer, buffer_size);
    picohash_final(&ctx, &v->oasis.runtime.call.body.evm.data_hash);
#endif

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeCall(parser_tx_t *v, CborValue *rootItem) {

    CborValue callField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "call", &callField))
    if (!cbor_value_is_valid(&callField)) {
        return parser_required_body;
    }

    CHECK_CBOR_TYPE(cbor_value_get_type(&callField), CborMapType)
    size_t numItems;
    CHECK_CBOR_ERR(cbor_value_get_map_length(&callField, &numItems))
    if (numItems < 2 || numItems > 4) return parser_unexpected_number_items;

    // Read format
    CborValue tmp;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&callField, "format", &tmp))
    if (cbor_value_is_valid(&tmp)) {
        if (!cbor_value_is_unsigned_integer(&tmp)) {
            return parser_unexpected_type;
        }
        CHECK_CBOR_ERR(cbor_value_get_uint64(&tmp, &v->oasis.runtime.call.format))
        if(v->oasis.runtime.call.format > 1) return parser_unsupported_cal;
    } else {
        v->oasis.runtime.call.format = 0;
    }

    if (v->oasis.runtime.call.format) {
        v->oasis.runtime.call.method = transactionEncrypted;
         CHECK_PARSER_ERR(_readRuntimeEncrypted(v,&callField))
    } else{
        CHECK_PARSER_ERR(_readRuntimeMethod(v,&callField))
        switch(v->oasis.runtime.call.method)
        {
            case consensusDeposit:
            case consensusDelegate:
            case consensusUndelegate:
            case consensusWithdraw:
            case accountsTransfer:
                CHECK_PARSER_ERR(_readRuntimeConsensusBody(v,&callField))
            break;
            case contractsCall:
            case contractsInstantiate:
            case contractsUpgrade:
                CHECK_PARSER_ERR(_readRuntimeContractsBody(v,&callField))
            break;
            case evmCall:
                CHECK_PARSER_ERR(_readRuntimeEvmBody(v,&callField))
            break;
            default:
                return parser_unexpected_method;
        }
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeFee(parser_tx_t *v, CborValue *rootItem) {
    if (!cbor_value_is_valid(rootItem)) {
        return parser_required_method;
    }
    // Verify it is well formed (no missing bytes...)
    CHECK_CBOR_ERR(cbor_value_validate_basic(rootItem))

    CborValue feeField;
    size_t numItems = 0;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "fee", &feeField))
    if (!cbor_value_is_valid(&feeField)) {
        return parser_required_body;
    }

    CHECK_CBOR_ERR(cbor_value_get_map_length(&feeField, &numItems))
    if (numItems < 1 || numItems > 3) return parser_unexpected_number_items;


    CborValue amount;
    CborValue contents;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&feeField, "amount", &amount))
    if (!cbor_value_is_valid(&amount)) {
        return parser_required_call;
    }
    CHECK_CBOR_ERR(cbor_value_enter_container(&amount, &contents))
    CHECK_PARSER_ERR(_readQuantity(&contents, &v->oasis.runtime.ai.fee.amount))
    CHECK_CBOR_ERR(cbor_value_advance(&contents))
    CHECK_PARSER_ERR(_readRuntimeString(&contents, &v->oasis.runtime.ai.fee.denom))

    CborValue tmp;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&feeField, "gas", &tmp))
    if (cbor_value_is_valid(&tmp)) {
        if (!cbor_value_is_unsigned_integer(&tmp)) {
            return parser_unexpected_type;
        }
        CHECK_CBOR_ERR(cbor_value_get_uint64(&tmp, &v->oasis.runtime.ai.fee.gas))
    } else {
        v->oasis.runtime.ai.fee.gas = 0;
    }

    v->oasis.runtime.ai.fee.consensus_msg = 0;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&feeField, "consensus_messages", &tmp))
    if (cbor_value_is_valid(&tmp)) {
        if (!cbor_value_is_unsigned_integer(&tmp)) {
            return parser_unexpected_type;
        }
        CHECK_CBOR_ERR(cbor_value_get_uint64(&tmp, &v->oasis.runtime.ai.fee.consensus_msg))
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntimeAi(parser_tx_t *v, CborValue *rootItem) {
    CborValue aiField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(rootItem, "ai", &aiField))
    if (!cbor_value_is_valid(&aiField)) {
        return parser_required_body;
    }
    size_t numItems = 0;
    CHECK_CBOR_ERR(cbor_value_get_map_length(&aiField, &numItems))
    if (numItems < 1 || numItems > 3) return parser_unexpected_number_items;

    CHECK_PARSER_ERR(_readRuntimeFee(v, &aiField))

    return parser_ok;
}

const char *_context_expected_prefix(const parser_tx_t *v) {
    switch (v->type) {
        case txType:
            return context_prefix_tx;
        case entityType:
            return context_prefix_entity;
        case nodeType:
            return context_prefix_node;
        case consensusType:
            return context_prefix_consensus;
        case entityMetadataType:
            return context_prefix_entity_metadata;
        case runtimeType:
            return context_prefix_runtime;
        default:
            return NULL;
    }
}

__Z_INLINE parser_error_t _computeRuntimeSigContext(parser_tx_t *v) {
    uint8_t total[(CHAIN_CONTEXT_BYTE_LEN*2) + RUNTIME_ID_BYTE_LEN] = {0};

    hexstr_to_array(total, RUNTIME_ID_BYTE_LEN, (char *)v->oasis.runtime.meta.runtime_id,
                    sizeof(v->oasis.runtime.meta.runtime_id));
    MEMCPY(total + RUNTIME_ID_BYTE_LEN, v->oasis.runtime.meta.chain_context, CHAIN_CONTEXT_BYTE_LEN*2);

    uint8_t messageDigest[SIGCONTEXT_HASH_LEN];
    SHA512_256(total, sizeof(total), messageDigest);
    array_to_hexstr(v->oasis.runtime.sigcxt, sizeof(v->oasis.runtime.sigcxt), messageDigest, 32 );
    z_str3join(v->oasis.runtime.sigcxt, sizeof(v->oasis.runtime.sigcxt),(char *)context_prefix_runtime,"");

    return parser_ok;
}

__Z_INLINE parser_error_t _evaluateCborInit(parser_context_t *c, CborValue * it) {
    CborParser parser;
    CborError err = cbor_parser_init(c->buffer + c->offset, c->bufferLen - c->offset, 0, &parser, it);

    if (err != CborNoError){
        return parser_cbor_unexpected;
    }

    return parser_ok;
}

parser_error_t _readContext(parser_context_t *c, parser_tx_t *v) {
    v->context.suffixPtr = NULL;
    v->context.suffixLen = 0;

    CborValue it;
    CborParser parser;
    CborError err = cbor_parser_init(c->buffer + c->offset, c->bufferLen - c->offset, 0, &parser, &it);

    //Get Metadata
    if (cbor_value_is_map(&it) && err == CborNoError) {
        CHECK_PARSER_ERR(_readRuntimeMeta(v, &it))
        CHECK_PARSER_ERR(_computeRuntimeSigContext(v))
        v->context.ptr = (uint8_t *)v->oasis.runtime.sigcxt;
        v->context.len = strlen(v->oasis.runtime.sigcxt);

        //Buffer has 2 CBOR maps, found the first now get the offset for tbe second
        CborValue tx;
        c->offset += 1;
        while(c->offset < c->bufferLen){
            if(_evaluateCborInit(c, &tx) == parser_ok && cbor_value_is_map(&tx)) {
                break;
            }
            c->offset++;
        }
        v->oasis.runtime.metaLen = c->offset;
        if(c->offset >= c->bufferLen) {
            return parser_required_body;
        }
    } else if(err == CborNoError || err == CborErrorIllegalNumber){
        // First byte is the context length
        v->context.len = *(c->buffer + c->offset);
        c->offset++;

        if (v->context.len < 2) {
            return parser_init_context_empty;
        }

        if (c->offset + v->context.len > c->bufferLen) {
            return parser_context_unexpected_size;
        }

        v->context.ptr = c->buffer + c->offset;
        c->offset += v->context.len;
    } else {
        return parser_cbor_unexpected;
    }

    // Check all bytes in context as ASCII within 32..127
    for (uint16_t i = 0; i < v->context.len; i++) {
        const uint8_t tmp = v->context.ptr[i];
        if (!IS_PRINTABLE(tmp)) {
            return parser_context_invalid_chars;
        }
    }

    return parser_ok;
}

parser_error_t matchPrefix(char *prefix, uint8_t prefixLen, oasis_blob_type_e *type) {
    uint8_t expectedLen = 0;

    expectedLen = strlen(context_prefix_tx);
    if (expectedLen < prefixLen) {
        if (strncmp(context_prefix_tx, prefix, expectedLen) == 0) {
            *type = txType;
            return parser_ok;
        }
    }

    expectedLen = strlen(context_prefix_runtime);
    if (expectedLen < prefixLen) {
        if (strncmp(context_prefix_runtime, prefix, expectedLen) == 0) {
            *type = runtimeType;
            return parser_ok;
        }
    }

    expectedLen = strlen(context_prefix_entity);
    if (expectedLen == prefixLen) {
        if (strncmp(context_prefix_entity, prefix, expectedLen) == 0) {
            *type = entityType;
            return parser_ok;
        }
    }

    expectedLen = strlen(context_prefix_entity_metadata);
    if (expectedLen == prefixLen) {
        if (strncmp(context_prefix_entity_metadata, prefix, expectedLen) == 0) {
            *type = entityMetadataType;
            return parser_ok;
        }
    }

    return parser_context_unknown_prefix;
}

parser_error_t _extractContextSuffix(parser_tx_t *v) {
    v->context.suffixPtr = NULL;
    v->context.suffixLen = 0;

    CHECK_PARSER_ERR(matchPrefix((char *) v->context.ptr, v->context.len, &v->type))

    const char *expectedPrefix = _context_expected_prefix(v);
    if (expectedPrefix == NULL) {
        return parser_context_unknown_prefix;
    }

    // confirm that the context starts with the correct prefix
    const size_t prefixLen = strlen(expectedPrefix);
    if (v->context.len < prefixLen) {
        return parser_context_mismatch;
    }
    if (strncmp(expectedPrefix, (char *) v->context.ptr, prefixLen) != 0) {
        return parser_context_mismatch;
    }

    if (v->context.len > prefixLen) {
        v->context.suffixPtr = v->context.ptr + prefixLen;
        v->context.suffixLen = v->context.len - prefixLen;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _readTx(parser_tx_t *v, CborValue *rootItem) {
    CHECK_CBOR_TYPE(cbor_value_get_type(rootItem), CborMapType)
    CHECK_PARSER_ERR(_readMethod(v, rootItem))
    CHECK_PARSER_ERR(_readFee(v, rootItem))
    CHECK_PARSER_ERR(_readNonce(v, rootItem))
    CHECK_PARSER_ERR(_readBody(v, rootItem))
    return parser_ok;
}

__Z_INLINE parser_error_t _readEntityMetadata(parser_tx_t *v, CborValue *rootItem) {
    CHECK_CBOR_TYPE(cbor_value_get_type(rootItem), CborMapType)
    CHECK_PARSER_ERR(_readFormatVersion(v, rootItem))
    CHECK_PARSER_ERR(_readSerial(v, rootItem))
    CHECK_PARSER_ERR(_readName(v, rootItem))
    CHECK_PARSER_ERR(_readUrl(v, rootItem))
    CHECK_PARSER_ERR(_readEmail(v, rootItem))
    CHECK_PARSER_ERR(_readKeybase(v, rootItem))
    CHECK_PARSER_ERR(_readTwitter(v, rootItem))

    return parser_ok;
}

__Z_INLINE parser_error_t _readRuntime(parser_tx_t *v, CborValue *rootItem) {
    CHECK_CBOR_TYPE(cbor_value_get_type(rootItem), CborMapType)
    CHECK_PARSER_ERR(_readRuntimeVersion(v, rootItem))
    CHECK_PARSER_ERR(_readRuntimeCall(v, rootItem))
    CHECK_PARSER_ERR(_readRuntimeAi(v, rootItem))

    return parser_ok;
}

parser_error_t _read(const parser_context_t *c, parser_tx_t *v) {
    if (c->bufferLen <= c->offset) {
        return parser_unexpected_buffer_end;
    }

    CborValue rootItem = {0};
    INIT_CBOR_PARSER(c, rootItem)

    CHECK_CBOR_ERR(cbor_value_validate_basic(&rootItem))

    if (cbor_value_at_end(&rootItem)) {
        return parser_unexpected_buffer_end;
    }

    if (!cbor_value_is_map(&rootItem)) {
        return parser_root_item_should_be_a_map;
    }

    switch (v->type) {
        case txType:
            // Read TXs
            MEMZERO(&v->oasis.tx, sizeof(oasis_tx_t));
            CHECK_PARSER_ERR(_readTx(v, &rootItem))
            break;
        case entityType:
            // Read Entity
            MEMZERO(&v->oasis.entity, sizeof(oasis_entity_t));
            parser_setCborState(&v->oasis.entity.cborState, &parser, &rootItem);
            CHECK_PARSER_ERR(_readEntity(&v->oasis.entity))
            break;
        case entityMetadataType:
            // Read Entity Metadata
            MEMZERO(&v->oasis.entity_metadata, sizeof(oasis_entity_metadata_t));
            CHECK_PARSER_ERR(_readEntityMetadata(v, &rootItem))
            break;
        case runtimeType:
             CHECK_PARSER_ERR(_readRuntime(v, &rootItem))
            break;
        default:
            return parser_context_unknown_prefix;
    }

    return parser_ok;
}


parser_error_t _validateTx(const parser_context_t *c, __Z_UNUSED const parser_tx_t *v) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)

    return parser_ok;
}

uint8_t _getNumItems(__Z_UNUSED const parser_context_t *c, const parser_tx_t *v) {
    // typical tx: Type, Fee, Gas (exclude Genesis hash)
    const uint8_t commonElements = 3;
    // Type + ID
    const uint8_t entityFixedElements = 2;

    // Just the ID
    const uint8_t registerEntityFixedElements = 1;

    uint8_t itemCount = commonElements;

    // Entity (not a tx)
    if (v->type == entityType) {
        itemCount = entityFixedElements + v->oasis.entity.obj.nodes_length;
        return itemCount;
    }

    if (v->type == entityMetadataType) {
        uint8_t metadataEntityCount = 2; // v and serial required

        if (v->oasis.entity_metadata.name.len > 0) {
            metadataEntityCount += 1;
        }

        if (v->oasis.entity_metadata.url.len > 0) {
            metadataEntityCount += 1;
        }

        if (v->oasis.entity_metadata.email.len > 0) {
            metadataEntityCount += 1;
        }

        if (v->oasis.entity_metadata.keybase.len > 0) {
            metadataEntityCount += 1;
        }

        if (v->oasis.entity_metadata.twitter.len > 0) {
            metadataEntityCount += 1;
        }

        return metadataEntityCount + 1;
    }

    if (!v->oasis.tx.has_fee && v->type == txType) {
        itemCount = 1;
    }

    switch (v->oasis.tx.method) {
        case stakingTransfer:
            itemCount += 2;
            break;
        case stakingBurn:
            itemCount += 1;
            break;
        case stakingWithdraw:
            itemCount += 2;
            break;
        case stakingAllow:
            itemCount += 2;
            break;
        case stakingEscrow:
            itemCount += 2;
            break;
        case stakingReclaimEscrow:
            itemCount += 2;
            break;
        case stakingAmendCommissionSchedule:
            // Each rate contains 2 items (start & rate)
            itemCount += v->oasis.tx.body.stakingAmendCommissionSchedule.rates_length * 2;
            // Each bound contains 3 items (start, rate_max & rate_min)
            itemCount += v->oasis.tx.body.stakingAmendCommissionSchedule.bounds_length * 3;
            break;
        case registryDeregisterEntity:
            itemCount += 0;
            break;
        case registryUnfreezeNode:
            itemCount += 1;
            break;
        case registryRegisterEntity: {
            itemCount += registerEntityFixedElements + v->oasis.tx.body.registryRegisterEntity.entity.obj.nodes_length;
            break;
        case governanceCastVote:
                itemCount += 2;
            break;
        case governanceSubmitProposal:
            if( v->oasis.tx.body.governanceSubmitProposal.type == upgrade){
                itemCount += 6;
            }
            if(v->oasis.tx.body.governanceSubmitProposal.type == cancelUpgrade){
                itemCount += 2;
            }
            break;
        }
        case unknownMethod:
        default:
            break;
    }

    if ((v->type == runtimeType)) {
        switch (v->oasis.runtime.call.method) {
            case consensusDeposit:
                __attribute__((fallthrough));
            case accountsTransfer:
                __attribute__((fallthrough));
            case consensusWithdraw:
                __attribute__((fallthrough));
            case consensusDelegate:
                __attribute__((fallthrough));
            case consensusUndelegate:
                itemCount += 3;
                break;
            default:
            case contractsCall:
                __attribute__((fallthrough));
            case contractsInstantiate:
                itemCount += 2 + v->oasis.runtime.call.body.contracts.tokensLen + v->oasis.runtime.call.body.contracts.dataValid;
                break;
            case contractsUpgrade:
                itemCount += 3 + v->oasis.runtime.call.body.contracts.tokensLen + v->oasis.runtime.call.body.contracts.dataValid;
                break;
            case transactionEncrypted:
                itemCount += 5;
                break;
            case evmCall:
                itemCount += 4;
                break;
        }
    }

    return itemCount;
}

__Z_INLINE parser_error_t _getAmendmentContainer(CborValue *value, CborValue *amendmentContainer) {
    if (cbor_value_at_end(value)) {
        return parser_unexpected_buffer_end;
    }

    if (!cbor_value_is_map(value)) {
        return parser_unexpected_type;
    }

    CborValue bodyContainer;
    CHECK_CBOR_ERR(cbor_value_map_find_value(value, "body", &bodyContainer))

    if (!cbor_value_is_map(&bodyContainer)) {
        return parser_unexpected_type;
    }

    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyContainer, "amendment", amendmentContainer))

    if (!cbor_value_is_map(amendmentContainer)) {
        return parser_unexpected_type;
    }

    return parser_ok;
}

__Z_INLINE parser_error_t _getRatesContainer(CborValue *value, CborValue *ratesContainer) {

    CborValue amendmentContainer;
    CHECK_PARSER_ERR(_getAmendmentContainer(value, &amendmentContainer))

    CborValue container;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&amendmentContainer, "rates", &container))

    if (!cbor_value_is_array(&container)) {
        return parser_unexpected_type;
    }

    CHECK_CBOR_ERR(cbor_value_enter_container(&container, ratesContainer))

    return parser_ok;
}

__Z_INLINE parser_error_t _getBoundsContainer(CborValue *value, CborValue *boundsContainer) {

    CborValue amendmentContainer;
    CHECK_PARSER_ERR(_getAmendmentContainer(value, &amendmentContainer))

    CborValue container;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&amendmentContainer, "bounds", &container))

    if (!cbor_value_is_array(&container)) {
        return parser_unexpected_type;
    }

    CHECK_CBOR_ERR(cbor_value_enter_container(&container, boundsContainer))

    return parser_ok;
}

parser_error_t _getCommissionRateStepAtIndex(const parser_context_t *c, commissionRateStep_t *rate, uint8_t index) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)

    // We should have already initiated v but should we verify ?

    CborValue ratesContainer;
    CHECK_PARSER_ERR(_getRatesContainer(&it, &ratesContainer))

    for (int i = 0; i < index; i++) {
        // Skip values
        CHECK_CBOR_ERR(cbor_value_advance(&ratesContainer))
    }

    CHECK_PARSER_ERR(_readRate(&ratesContainer, rate))

    return parser_ok;

}

parser_error_t _getCommissionBoundStepAtIndex(const parser_context_t *c,
                                              commissionRateBoundStep_t *bound,
                                              uint8_t index) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)

    if (cbor_value_at_end(&it)) {
        return parser_unexpected_buffer_end;
    }

    CborValue boundsContainer;
    CHECK_PARSER_ERR(_getBoundsContainer(&it, &boundsContainer))

    for (int i = 0; i < index; i++) {
        CHECK_CBOR_ERR(cbor_value_advance(&boundsContainer))
    }

    CHECK_PARSER_ERR(_readBound(&boundsContainer, bound))

    return parser_ok;
}

parser_error_t _getEntityNodesIdAtIndex(const oasis_entity_t *entity, publickey_t *node, uint8_t index) {
    CborValue it = entity->cborState.startValue;

    if (cbor_value_at_end(&it)) {
        return parser_unexpected_buffer_end;
    }

    if (!cbor_value_is_map(&it)) {
        return parser_unexpected_type;
    }

    CborValue nodesContainer;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&it, "nodes", &nodesContainer))

    if (!cbor_value_is_array(&nodesContainer)) {
        return parser_unexpected_type;
    }

    CborValue nodesArrayContainer;
    CHECK_CBOR_ERR(cbor_value_enter_container(&nodesContainer, &nodesArrayContainer))

    for (int i = 0; i < index; i++) {
        CHECK_CBOR_ERR(cbor_value_advance(&nodesArrayContainer))
    }

    CHECK_PARSER_ERR(_readPublicKey(&nodesArrayContainer, node))

    return parser_ok;
}

parser_error_t _getTokenAtIndex(const parser_context_t *c, token_t *token, uint8_t index) {
    CborValue it;
    INIT_CBOR_PARSER(c, it)

    CHECK_CBOR_ERR(cbor_value_validate_basic(&it))

    if (cbor_value_at_end(&it)) {
        return parser_unexpected_buffer_end;
    }

    if (!cbor_value_is_map(&it)) {
        return parser_root_item_should_be_a_map;
    }

    CborValue callField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&it, "call", &callField))
    if (!cbor_value_is_valid(&callField)) {
        return parser_required_call;
    }

    CborValue bodyField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&callField, "body", &bodyField))
    if (!cbor_value_is_valid(&bodyField)) {
        return parser_required_body;
    }

    CborValue tokensField;
    CHECK_CBOR_ERR(cbor_value_map_find_value(&bodyField, "tokens", &tokensField))

    CborValue array;
    CHECK_CBOR_ERR(cbor_value_enter_container(&tokensField, &array))

    CborValue amount;
    CHECK_CBOR_ERR(cbor_value_enter_container(&tokensField, &amount))
    for (int i = 0; i < index; i++) {
        CHECK_CBOR_ERR(cbor_value_advance(&amount))
    }

    CborValue content;
    CHECK_CBOR_ERR(cbor_value_enter_container(&amount, &content))
    _readQuantity(&content, &token->amount);
    CHECK_CBOR_ERR(cbor_value_advance(&content))
    _readRuntimeString(&content, &token->denom);

    return parser_ok;
}

#endif
