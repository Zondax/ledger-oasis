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

#if defined(APP_VALIDATOR)

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "vote.h"
#include <stdint.h>
#include <common/parser_common.h>
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

parser_error_t readVoteTx(parser_context_t *ctx, parser_tx_t *v);


/// Parse vote in buffer
/// This function should be called as soon as full buffer data is loaded.
/// \return It an error core or PARSE_OK
parser_error_t vote_parse();

#ifdef __cplusplus
}
#endif


#endif //APP_VALIDATOR