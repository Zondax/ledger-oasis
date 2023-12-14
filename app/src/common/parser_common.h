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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define CHECK_PARSER_ERR(__CALL) { \
    parser_error_t __err = __CALL;  \
    CHECK_APP_CANARY()  \
    if (__err!=parser_ok) return __err;}

typedef enum {
    // Generic errors
    parser_ok = 0,
    parser_no_data,
    parser_init_context_empty,
    parser_display_idx_out_of_range,
    parser_display_page_out_of_range,
    parser_unexepected_error,
    // Coin generic
    parser_root_item_should_be_a_map,
    parser_unexpected_type,
    parser_unexpected_method,
    parser_unexpected_buffer_end,
    parser_unexpected_value,
    parser_unexpected_number_items,
    parser_unexpected_version,
    parser_unexpected_characters,
    parser_unexpected_field,
    parser_duplicated_field,
    parser_value_out_of_range,
    parser_invalid_address,
    parser_unexpected_chain,
    parser_query_no_results,
    parser_unsupported_cal,
    // Coin Specific
    parser_cbor_unexpected,
    parser_cbor_unexpected_EOF,
    parser_cbor_not_canonical,
    // Context related errors
    parser_context_mismatch,
    parser_context_unexpected_size,
    parser_context_invalid_chars,
    parser_context_unknown_prefix,
    // Required fields
    parser_required_nonce,
    parser_required_method,
    parser_required_body,
    parser_required_call,
    parser_required_chain_context,
    parser_required_runtime_id,
    // Amino related
    parser_unexpected_wire_type,
    parser_unexpected_round_value,
    parser_unexpected_buffer_size,
    parser_unexpected_type_value,
    parser_unexpected_height_value,
    // Entity Metadata
    parser_required_v,
    parser_invalid_v_value,
    parser_required_serial,
    parser_invalid_url_format,
    parser_invalid_url_length,
    parser_invalid_email_format,
    parser_invalid_email_length,
    parser_invalid_handle_format,
    parser_invalid_handle_length,
    parser_invalid_name_length,
    parser_invalid_eth_mapping,
    parser_required_id,
    parser_required_code_id,
    parser_required_pk,
    parser_required_data,
    parser_required_expert_mode,
    parser_unsupported_tx,
    parser_invalid_rlp_data,
    parser_invalid_chain_id,
    parser_invalid_rs_values,
    parser_no_depth,
} parser_error_t;

typedef enum {
  oasis_tx = 0,
  eth_tx,
}tx_type_t;

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    uint16_t lastConsumed;
    tx_type_t tx_type;
} parser_context_t;

#ifdef __cplusplus
}
#endif
