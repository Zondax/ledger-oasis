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

using ::testing::TestWithParam;
using ::testing::Values;
using json = nlohmann::json;

typedef struct {
    std::string index;
    std::string kind;
    std::string signature_context;
    std::string encoded_tx;
    bool valid;
    std::vector<std::string> expected_ui_output;
} testcase_t;

class JsonTests : public ::testing::TestWithParam<testcase_t> {
public:
    struct PrintToStringParamName {
        template<class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << p.index << "_" << p.kind;
            return ss.str();
        }
    };
};

std::string FormatPKasAddress(const std::string &base64PK, uint8_t idx, uint8_t *pageCount) {
    std::string pkBytes;
    macaron::Base64::Decode(base64PK, pkBytes);

    char buffer[200];
    bech32EncodeFromBytes(buffer, COIN_HRP, (const uint8_t *) pkBytes.c_str(), PK_LEN);

    char outBuffer[40];
    pageString(outBuffer, sizeof(outBuffer), buffer, idx, pageCount);

    return std::string(outBuffer);
}

std::string FormatRates(const json &rates, uint8_t idx, uint8_t *pageCount) {
    *pageCount = rates.size() * 2;
    if (idx < *pageCount) {
        auto r = rates[idx / 2];
        switch (idx % 2) {
            case 0:
                return fmt::format("[{}] start: {}", idx / 2, (uint64_t) r["start"]);
            case 1:
                return fmt::format("[{}] rate: {}", idx / 2, (std::string) r["rate"]);
        }
    }

    return "";
}

std::string FormatBounds(const json &bounds, uint8_t idx, uint8_t *pageCount) {
    *pageCount = bounds.size() * 3;
    if (idx < *pageCount) {
        auto r = bounds[idx / 3];
        switch (idx % 3) {
            case 0:
                return fmt::format("[{}] start: {}", idx / 3, (uint64_t) r["start"]);
            case 1:
                return fmt::format("[{}] min: {}", idx / 3, (std::string) r["rate_min"]);
            case 2:
                return fmt::format("[{}] max: {}", idx / 3, (std::string) r["rate_max"]);
        }
    }

    return "";
}

std::vector<std::string> GenerateExpectedUIOutput(json j) {
    auto answer = std::vector<std::string>();

    auto type = (std::string) j["tx"]["method"];

    if (type == "staking.Transfer") {
        answer.push_back(fmt::format("0 | Type : Transfer"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", (std::string) j["tx"]["fee"]["amount"]));
        answer.push_back(fmt::format("2 | Fee Gas : {}", (uint64_t) j["tx"]["fee"]["gas"]));

        uint8_t dummy;
        answer.push_back(fmt::format("3 | To : {}", FormatPKasAddress(j["tx"]["body"]["xfer_to"], 0, &dummy)));
        answer.push_back(fmt::format("3 | To : {}", FormatPKasAddress(j["tx"]["body"]["xfer_to"], 1, &dummy)));
        answer.push_back(fmt::format("4 | Tokens : {}", (std::string) j["tx"]["body"]["xfer_tokens"]));
    }

    if (type == "staking.Burn") {
        answer.push_back(fmt::format("0 | Type : Burn"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", (std::string) j["tx"]["fee"]["amount"]));
        answer.push_back(fmt::format("2 | Fee Gas : {}", (uint64_t) j["tx"]["fee"]["gas"]));
        answer.push_back(fmt::format("3 | Tokens : {}", (std::string) j["tx"]["body"]["burn_tokens"]));
    }

    if (type == "staking.AddEscrow") {
        answer.push_back(fmt::format("0 | Type : Add escrow"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", (std::string) j["tx"]["fee"]["amount"]));
        answer.push_back(fmt::format("2 | Fee Gas : {}", (uint64_t) j["tx"]["fee"]["gas"]));

        uint8_t dummy;
        answer.push_back(
                fmt::format("3 | Escrow : {}", FormatPKasAddress(j["tx"]["body"]["escrow_account"], 0, &dummy)));
        answer.push_back(
                fmt::format("3 | Escrow : {}", FormatPKasAddress(j["tx"]["body"]["escrow_account"], 1, &dummy)));
        answer.push_back(fmt::format("4 | Tokens : {}", (std::string) j["tx"]["body"]["escrow_tokens"]));
    }

    if (type == "staking.ReclaimEscrow") {
        answer.push_back(fmt::format("0 | Type : Reclaim escrow"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", (std::string) j["tx"]["fee"]["amount"]));
        answer.push_back(fmt::format("2 | Fee Gas : {}", (uint64_t) j["tx"]["fee"]["gas"]));

        uint8_t dummy;
        answer.push_back(
                fmt::format("3 | Escrow : {}", FormatPKasAddress(j["tx"]["body"]["escrow_account"], 0, &dummy)));
        answer.push_back(
                fmt::format("3 | Escrow : {}", FormatPKasAddress(j["tx"]["body"]["escrow_account"], 1, &dummy)));
        answer.push_back(fmt::format("4 | Tokens : {}", (std::string) j["tx"]["body"]["reclaim_shares"]));
    }

    if (type == "staking.AmendCommissionSchedule") {
        answer.push_back(fmt::format("0 | Type : Amend commission schedule"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", (std::string) j["tx"]["fee"]["amount"]));
        answer.push_back(fmt::format("2 | Fee Gas : {}", (uint64_t) j["tx"]["fee"]["gas"]));

        uint8_t pageIdx = 0;
        uint8_t pageCount = 1;
        while (pageIdx < pageCount) {
            auto s = FormatRates(j["tx"]["body"]["amendment"]["rates"], pageIdx, &pageCount);
            if (!s.empty())
                answer.push_back(fmt::format("3 | Rates : {}", s));
            pageIdx++;
        }

        pageIdx = 0;
        pageCount = 1;
        while (pageIdx < pageCount) {
            auto s = FormatBounds(j["tx"]["body"]["amendment"]["bounds"], pageIdx, &pageCount);
            if (!s.empty())
                answer.push_back(fmt::format("4 | Bounds : {}", s));
            pageIdx++;
        }
    }

    return answer;
}

std::vector<testcase_t> GetJsonTestCases() {
    auto answer = std::vector<testcase_t>();

    json j;
    std::ifstream inFile("testcases.json");
    EXPECT_TRUE(inFile.is_open())
                        << "\n"
                        << "******************\n"
                        << "Check that your working directory points to the tests directory\n"
                        << "In CLion use $PROJECT_DIR$\\tests\n"
                        << "******************\n";
    if (!inFile.is_open())
        return answer;

    // Retrieve all test cases
    inFile >> j;
    std::cout << "Number of testcases: " << j.size() << std::endl;

    int count = 0;
    for (auto &item : j) {
        count++;
        answer.push_back(testcase_t{
                std::to_string(count),
                item["kind"],
                item["signature_context"],
                item["encoded_tx"],
                item["valid"],
                GenerateExpectedUIOutput(item)
        });
    }

    return answer;
}

void check_testcase(const testcase_t &tc) {
    // Output Expected value as a reference
    std::cout << std::endl;
    for (const auto &i : tc.expected_ui_output) {
        std::cout << i << std::endl;
    }

    parser_context_t ctx;
    parser_error_t err;

    std::string cborString;
    macaron::Base64::Decode(tc.encoded_tx, cborString);

    const auto *buffer = (const uint8_t *) cborString.c_str();
    uint16_t bufferLen = cborString.size();

    char bufferOut[500];
    array_to_hexstr(bufferOut, (uint8_t *) cborString.c_str(), (uint8_t) bufferLen);

    err = parser_parse(&ctx, buffer, bufferLen);
    if (tc.valid) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
    }

    auto output = dumpUI(&ctx, 40, 40);

    std::cout << std::endl;
    for (const auto &i : output) {
        std::cout << i << std::endl;
    }

    EXPECT_EQ(output.size(), tc.expected_ui_output.size());
    for (size_t i = 0; i < tc.expected_ui_output.size(); i++) {
        if (i < output.size()) {
            EXPECT_THAT(output[i], testing::Eq(tc.expected_ui_output[i]));
        }
    }
}

INSTANTIATE_TEST_CASE_P

(
        JsonTestCases,
        JsonTests,
        ::testing::ValuesIn(GetJsonTestCases()), JsonTests::PrintToStringParamName()
);

TEST_P(JsonTests, CheckUIOutput) { check_testcase(GetParam()); }
