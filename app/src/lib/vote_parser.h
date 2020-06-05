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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "vote.h"
#include <stdint.h>
#include <common/parser_common.h>
#include "parser_txdef.h"

parser_error_t readVote(parser_context_t *c, parser_tx_t *v);

parser_error_t _readArray(parser_context_t *ctx, const uint8_t **arrayPtr, uint16_t *arrayLength);

parser_error_t vote_amino_parse(parser_context_t *ctx, oasis_tx_vote_t *voteTx, vote_t *vote);

/// Parse vote in buffer
/// This function should be called as soon as full buffer data is loaded.
/// \return It an error core or PARSE_OK
parser_error_t vote_parse();

#ifdef __cplusplus
}
#endif
