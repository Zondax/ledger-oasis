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

#include "gtest/gtest.h"
#include <string>
#include <lib/parser.h>
#include <hexutils.h>
#include <cbor.h>

namespace {
    TEST(CBORParserTest, TransferExample) {
        // {"nonce": 123456, "xfer_to": "1234567890abcdef", "xfer_tokens": 887766554433}
        uint8_t inBuffer[100];
        auto inBufferLen = parseHexString(
            "A3656E6F6E63651A0001E24067786665725F746F70313233343"
            "536373839306162636465666B786665725F746F6B656E731B000000CEB3029741",
            inBuffer);

        CborParser parser;
        CborValue it;
        CborError err = cbor_parser_init(inBuffer, inBufferLen, 0, &parser, &it);
        EXPECT_EQ(err, CborNoError);

        // TODO: Complete test
    }
}
