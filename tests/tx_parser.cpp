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

#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include <zxmacros.h>
#include <lib/crypto.h>
#include <bech32.h>
#include "lib/parser.h"
#include "util/base64.h"
#include "util/common.h"

// Test some specific corner cases that may not be part of the test vectors
TEST(TxParser, RandomDataAtEnd) {
    std::string cborString;
    macaron::Base64::Decode("pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy", cborString);

    EXPECT_EQ(cborString.size(), 111);

    cborString = cborString + "123456";
    EXPECT_EQ(cborString.size(), 117);

    const auto *buffer = (const uint8_t *) cborString.c_str();
    uint16_t bufferLen = cborString.size();

    parser_context_t ctx;
    auto err = parser_parse(&ctx, buffer, bufferLen);
    ASSERT_EQ(err, parser_unexpected_data_at_end) << parser_getErrorDescription(err);
}

TEST(TxParser, MissingLastByte) {
    std::string cborString;
    macaron::Base64::Decode("pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy", cborString);

    EXPECT_EQ(cborString.size(), 111);

    const auto *buffer = (const uint8_t *) cborString.c_str();
    uint16_t bufferLen = cborString.size() - 1;

    parser_context_t ctx;
    auto err = parser_parse(&ctx, buffer, bufferLen);
    ASSERT_EQ(err, parser_cbor_unexpected) << parser_getErrorDescription(err);
}
