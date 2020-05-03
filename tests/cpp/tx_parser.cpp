/*******************************************************************************
*   (c) 2019 ZondaX GmbH
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

#include <gmock/gmock.h>
#include <fmt/core.h>

#include <zxmacros.h>
#include "common/parser.h"
#include "base64.h"
#include "common.h"
#include "testcases.h"

// Test some specific corner cases that may not be part of the test vectors
TEST(TxParser, EmptyBuffer) {
    parser_context_t ctx;
    auto buffer = std::vector<uint8_t>();
    buffer.push_back(0);
    auto err = parser_parse(&ctx, buffer.data(), buffer.size());
    ASSERT_EQ(err, parser_cbor_unexpected_EOF) << parser_getErrorDescription(err);
}

TEST(TxParser, RandomDataAtEnd) {
    parser_context_t ctx;

    std::string context = "oasis-core/consensus: tx for chain ";
    std::string cborString = "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy";
    auto buffer = prepareBlob(context, cborString);
    buffer.push_back(0);

    auto err = parser_parse(&ctx, buffer.data(), buffer.size());
    ASSERT_EQ(err, parser_cbor_unexpected_EOF) << parser_getErrorDescription(err);
}

TEST(TxParser, MissingLastByte) {
    parser_context_t ctx;

    std::string context = "oasis-core/consensus: tx for chain ";
    std::string cborString = "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy";
    auto buffer = prepareBlob(context, cborString);
    auto err = parser_parse(&ctx, buffer.data(), buffer.size() - 1);
    ASSERT_EQ(err, parser_cbor_unexpected_EOF) << parser_getErrorDescription(err);
}
