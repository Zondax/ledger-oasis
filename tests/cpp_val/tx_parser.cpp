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
#include "hexutils.h"

TEST(VoteParser, BasicVote) {
    parser_context_t ctx;

    std::string context = "oasis-core/tendermint";


    char txString[] ="9701080111889601000000000022480a20b96edf9fc64ff6e0a44d4389944451a0a56cc4ef6fa7e8dfee573785ffdebe2512240a20d22611dc07b3a0676a800e552b8d2910dc4e2911c3768fc8e2e16930e44bcd8f10012a0b08b2c9d3f70510a2b4de1032326136333464323232346435343962383536303338616364396264616434373638346431333236326438376531633062386361";

    uint8_t voteData[300];

    auto len = parseHexString(voteData, sizeof(voteData), txString);

    uint16_t bufferLen = 1 + context.size() + len;
    auto buffer = std::vector<uint8_t>(bufferLen);

    buffer[0] = context.size();
    MEMCPY(buffer.data() + 1, context.c_str(), context.size());
    MEMCPY(buffer.data() + 1 + context.size(), voteData, len);

    auto err = parser_parse(&ctx, buffer.data(), buffer.size() - 1);
    ASSERT_EQ(err, parser_ok);
    err = parser_validate(&ctx);
    ASSERT_EQ(err, parser_ok);
}
