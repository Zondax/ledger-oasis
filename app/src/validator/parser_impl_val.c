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
#include "parser_impl_val.h"
#include "parser_txdef_val.h"

#if defined(APP_VALIDATOR)
parser_tx_t parser_tx_obj;

const char context_prefix_tx[] = "oasis-core/consensus: tx for chain ";
const char context_prefix_entity[] = "oasis-core/registry: register entity";
const char context_prefix_node[] = "oasis-core/registry: register node";
const char context_prefix_consensus[] = "oasis-core/tendermint";

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
            return "Unexepected internal error";
            // cbor
        case parser_cbor_unexpected:
            return "unexpected CBOR error";
        case parser_cbor_not_canonical:
            return "CBOR was not in canonical order";
        case parser_cbor_unexpected_EOF:
            return "Unexpected CBOR EOF";
            // Coin specific
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
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
        case parser_context_unknown_prefix:
            return "context uknown prefix";
            // Required fields error
        case parser_required_nonce:
            return "Required field nonce";
        case parser_required_method:
            return "Required field method";
        default:
            return "Unrecognized error code";
    }
}

parser_error_t _readContext(parser_context_t *c, parser_tx_t *v) {
    v->context.suffixPtr = NULL;
    v->context.suffixLen = 0;
    v->context.len = *(c->buffer + c->offset);

    if (c->offset + v->context.len >= c->bufferLen) {
        return parser_context_unexpected_size;
    }

    v->context.ptr = (c->buffer + 1);
    c->offset += 1 + v->context.len;

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
        default:
            return NULL;
    }
}

parser_error_t _extractContextSuffixForValidator(parser_tx_t *v) {
    v->context.suffixPtr = NULL;
    v->context.suffixLen = 0;

    // Check all bytes in context as ASCII within 32..127
    for (uint8_t i = 0; i < v->context.len; i++) {
        uint8_t c = *(v->context.ptr + i);
        if (c < 32 || c > 127) {
            return parser_context_invalid_chars;
        }
    }

    if (strncmp(context_prefix_consensus, (char *) v->context.ptr, strlen(context_prefix_consensus)) == 0) {
        v->type = consensusType;
    } else {
        if (strncmp(context_prefix_node, (char *) v->context.ptr, strlen(context_prefix_node)) == 0) {
            v->type = nodeType;
        } else {
            return parser_context_unknown_prefix;
        }
    }

    const char *expectedPrefix = _context_expected_prefix(v);
    if (expectedPrefix == NULL)
        return parser_context_unknown_prefix;

    if (v->context.len > strlen(expectedPrefix)) {
        v->context.suffixPtr = v->context.ptr + strlen(expectedPrefix);
        v->context.suffixLen = v->context.len - strlen(expectedPrefix);
    }

    return parser_ok;
}

#endif
