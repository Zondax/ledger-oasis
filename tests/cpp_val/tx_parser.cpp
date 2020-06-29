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

TEST(VoteParser, GoodVote) {
    parser_context_t ctx;

    std::string context = "oasis-core/tendermint";
    char txString[] ="21080111c80f0000000000001901000000000000002a0b088092b8c398feffffff01";

    uint8_t voteData[100];

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

TEST(VoteParser, NegativeHeight) {
    parser_context_t ctx;

    std::string context = "oasis-core/tendermint";
    char txString[] ="21080111ffffffffffffffff1901000000000000002a0b088092b8c398feffffff01";

    uint8_t voteData[100];

    auto len = parseHexString(voteData, sizeof(voteData), txString);

    uint16_t bufferLen = 1 + context.size() + len;
    auto buffer = std::vector<uint8_t>(bufferLen);

    buffer[0] = context.size();
    MEMCPY(buffer.data() + 1, context.c_str(), context.size());
    MEMCPY(buffer.data() + 1 + context.size(), voteData, len);

    auto err = parser_parse(&ctx, buffer.data(), buffer.size() - 1);
    ASSERT_EQ(err, parser_ok);
    err = parser_validate(&ctx);
    ASSERT_EQ(err, parser_unexpected_height_value);
}

TEST(VoteParser, NegativeRound) {
    parser_context_t ctx;

    std::string context = "oasis-core/tendermint";
    char txString[] ="210801110d0000000000000019ffffffffffffffff2a0b088092b8c398feffffff01";

    uint8_t voteData[100];

    auto len = parseHexString(voteData, sizeof(voteData), txString);

    uint16_t bufferLen = 1 + context.size() + len;
    auto buffer = std::vector<uint8_t>(bufferLen);

    buffer[0] = context.size();
    MEMCPY(buffer.data() + 1, context.c_str(), context.size());
    MEMCPY(buffer.data() + 1 + context.size(), voteData, len);

    auto err = parser_parse(&ctx, buffer.data(), buffer.size() - 1);
    ASSERT_EQ(err, parser_unexpected_round_value);
}

TEST(VoteParser, Height_Round_Zero) {
    parser_context_t ctx;

    std::string context = "oasis-core/tendermint";
    char txString[] ="0f08012a0b088092b8c398feffffff01";

    uint8_t voteData[100];

    auto len = parseHexString(voteData, sizeof(voteData), txString);

    uint16_t bufferLen = 1 + context.size() + len;
    auto buffer = std::vector<uint8_t>(bufferLen);

    buffer[0] = context.size();
    MEMCPY(buffer.data() + 1, context.c_str(), context.size());
    MEMCPY(buffer.data() + 1 + context.size(), voteData, len);

    auto err = parser_parse(&ctx, buffer.data(), buffer.size() - 1);
    ASSERT_EQ(err, parser_ok);
}

TEST(VoteParser, MaxValues) {
    parser_context_t ctx;

    std::string context = "oasis-core/tendermint";
    char txString[] ="21080111ffffffffffffff7f19ffffffffffffff7f2a0b088092b8c398feffffff01";
    uint8_t voteData[100];

    auto len = parseHexString(voteData, sizeof(voteData), txString);

    uint16_t bufferLen = 1 + context.size() + len;
    auto buffer = std::vector<uint8_t>(bufferLen);

    buffer[0] = context.size();
    MEMCPY(buffer.data() + 1, context.c_str(), context.size());
    MEMCPY(buffer.data() + 1 + context.size(), voteData, len);

    auto err = parser_parse(&ctx, buffer.data(), buffer.size() - 1);
    ASSERT_EQ(err, parser_unexpected_round_value);
}
