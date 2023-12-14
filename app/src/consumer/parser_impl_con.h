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

#include "parser_common.h"
#include "parser_txdef_con.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHECK_CX_PARSER_OK(CALL)         \
    do {                          \
        cx_err_t __cx_err = CALL; \
        if (__cx_err != CX_OK) {  \
            return parser_unexepected_error; \
        }                         \
    } while (0)

extern const char context_prefix_tx[];
extern const char context_prefix_entity[];
extern const char context_prefix_entity_metadata[];

#if defined(APP_CONSUMER)

extern parser_tx_t parser_tx_obj;

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize);

parser_error_t _read(const parser_context_t *c, parser_tx_t *v);

parser_error_t _readContext(parser_context_t *c, parser_tx_t *v);

parser_error_t _validateTx(const parser_context_t *c, const parser_tx_t *v);

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v);

parser_error_t _getCommissionRateStepAtIndex(const parser_context_t *c,
                                             commissionRateStep_t *rate,
                                             uint8_t index);

parser_error_t _getCommissionBoundStepAtIndex(const parser_context_t *c,
                                              commissionRateBoundStep_t *bound,
                                              uint8_t index);

parser_error_t _getTokenAtIndex(const parser_context_t *c, token_t *token, uint8_t index);

parser_error_t _getEntityNodesIdAtIndex(const oasis_entity_t *entity, publickey_t *node, uint8_t index);

parser_error_t _extractContextSuffix(parser_tx_t *v);

parser_error_t _isValidUrl(url_t *url);

parser_error_t _isValidEmail(email_t *email);

parser_error_t _isValidHandle(handle_t *handle);

parser_error_t parser_picoHash(uint8_t *src, size_t srcLen, uint8_t *dest, size_t destLen);

#endif

#ifdef __cplusplus
}
#endif
