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
#include <json/json.h>
#include <zxmacros.h>
#include <lib/crypto.h>
#include <bech32.h>
#include <lib/context.h>
#include "lib/parser.h"
#include "util/base64.h"
#include "util/common.h"

using ::testing::TestWithParam;
using ::testing::Values;

typedef struct {
    std::string description;
    std::string index;
    std::string kind;
    std::string signature_context;
    std::string encoded_tx;
    bool valid;
    std::vector<std::string> expected_ui_output;
} testcase_t;

std::string FormatPKasAddress(const std::string &base64PK, uint8_t idx, uint8_t *pageCount) {
    std::string pkBytes;
    macaron::Base64::Decode(base64PK, pkBytes);

    char buffer[200];
    bech32EncodeFromBytes(buffer, COIN_HRP, (const uint8_t *) pkBytes.c_str(), PK_LEN);

    char outBuffer[40];
    pageString(outBuffer, sizeof(outBuffer), buffer, idx, pageCount);

    return std::string(outBuffer);
}

std::string FormatAmount(const std::string &amount) {
    char buffer[500];
    MEMZERO(buffer, sizeof(buffer));
    fpstr_to_str(buffer, amount.c_str(), COIN_AMOUNT_DECIMAL_PLACES);
    return std::string(buffer);
}

std::string FormatRate(const std::string &rate) {
    char buffer[500];
    MEMZERO(buffer, sizeof(buffer));
    // This is shifting two decimal places to show as a percentage
    fpstr_to_str(buffer, rate.c_str(), COIN_RATE_DECIMAL_PLACES - 2);
    return std::string(buffer) + "%";
}

std::string FormatRates(const Json::Value &rates, uint8_t idx, uint8_t *pageCount) {
    *pageCount = rates.size() * 2;
    if (idx < *pageCount) {
        auto r = rates[idx / 2];
        switch (idx % 2) {
            case 0:
                return fmt::format("[{}] start : {}", idx / 2, r["start"].asUInt64());
            case 1:
                return fmt::format("[{}] rate : {}", idx / 2, FormatRate(r["rate"].asString()));
        }
    }

    return "";
}

std::string FormatBounds(const Json::Value &bounds, uint8_t idx, uint8_t *pageCount) {
    *pageCount = bounds.size() * 3;
    if (idx < *pageCount) {
        auto r = bounds[idx / 3];
        switch (idx % 3) {
            case 0:
                return fmt::format("[{}] start : {}", idx / 3, r["start"].asUInt64());
            case 1:
                return fmt::format("[{}] min : {}", idx / 3, FormatRate(r["rate_min"].asString()));
            case 2:
                return fmt::format("[{}] max : {}", idx / 3, FormatRate(r["rate_max"].asString()));
        }
    }

    return "";
}

bool TestcaseIsValid(const Json::Value &tc) {
    // TODO: Extend as necessary
    if (tc["kind"] == "AmendCommissionSchedule") {
        auto rates = tc["tx"]["body"]["amendment"]["rates"];
        auto bounds = tc["tx"]["body"]["amendment"]["bounds"];
        if (rates.empty()) {
            return false;
        }
        if (bounds.empty()) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> GenerateExpectedUIOutputForTx(std::string context, Json::Value j) {
    auto answer = std::vector<std::string>();

    auto expectedPrefix = std::string("oasis-core/consensus: tx for chain ");
    auto contextSuffix = context.replace(context.find(expectedPrefix), expectedPrefix.size(), "");

    auto type = j["tx"]["method"].asString();
    auto tx = j["tx"];
    auto txbody = tx["body"];

    if (type == "staking.Transfer") {
        answer.push_back(fmt::format("0 | Type : Transfer"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", FormatAmount(tx["fee"]["amount"].asString())));
        answer.push_back(fmt::format("2 | Fee Gas : {}", tx["fee"]["gas"].asUInt64()));
        answer.push_back(fmt::format("3 | Context : {}", contextSuffix));

        uint8_t dummy;
        answer.push_back(fmt::format("4 | To : {}", FormatPKasAddress(txbody["xfer_to"].asString(), 0, &dummy)));
        answer.push_back(fmt::format("4 | To : {}", FormatPKasAddress(txbody["xfer_to"].asString(), 1, &dummy)));
        answer.push_back(fmt::format("5 | Tokens : {}", FormatAmount(txbody["xfer_tokens"].asString())));
    }

    if (type == "staking.Burn") {
        answer.push_back(fmt::format("0 | Type : Burn"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", FormatAmount(tx["fee"]["amount"].asString())));
        answer.push_back(fmt::format("2 | Fee Gas : {}", tx["fee"]["gas"].asUInt64()));
        answer.push_back(fmt::format("3 | Context : {}", contextSuffix));

        answer.push_back(fmt::format("4 | Tokens : {}", FormatAmount(txbody["burn_tokens"].asString())));
    }

    if (type == "staking.AddEscrow") {
        answer.push_back(fmt::format("0 | Type : Add escrow"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", FormatAmount(tx["fee"]["amount"].asString())));
        answer.push_back(fmt::format("2 | Fee Gas : {}", tx["fee"]["gas"].asUInt64()));
        answer.push_back(fmt::format("3 | Context : {}", contextSuffix));

        uint8_t dummy;
        answer.push_back(fmt::format("4 | Escrow : {}",
                                     FormatPKasAddress(txbody["escrow_account"].asString(), 0, &dummy)));
        answer.push_back(fmt::format("4 | Escrow : {}",
                                     FormatPKasAddress(txbody["escrow_account"].asString(), 1, &dummy)));
        answer.push_back(fmt::format("5 | Tokens : {}", FormatAmount(txbody["escrow_tokens"].asString())));
    }

    if (type == "staking.ReclaimEscrow") {
        answer.push_back(fmt::format("0 | Type : Reclaim escrow"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", FormatAmount(tx["fee"]["amount"].asString())));
        answer.push_back(fmt::format("2 | Fee Gas : {}", tx["fee"]["gas"].asUInt64()));
        answer.push_back(fmt::format("3 | Context : {}", contextSuffix));

        uint8_t dummy;
        answer.push_back(fmt::format("4 | Escrow : {}",
                                     FormatPKasAddress(txbody["escrow_account"].asString(), 0, &dummy)));
        answer.push_back(fmt::format("4 | Escrow : {}",
                                     FormatPKasAddress(txbody["escrow_account"].asString(), 1, &dummy)));
        answer.push_back(fmt::format("5 | Tokens : {}", FormatAmount(txbody["reclaim_shares"].asString())));
    }

    if (type == "staking.AmendCommissionSchedule") {
        answer.push_back(fmt::format("0 | Type : Amend commission schedule"));
        answer.push_back(fmt::format("1 | Fee Amount : {}", FormatAmount(tx["fee"]["amount"].asString())));
        answer.push_back(fmt::format("2 | Fee Gas : {}", tx["fee"]["gas"].asUInt64()));
        answer.push_back(fmt::format("3 | Context : {}", contextSuffix));

        uint32_t itemCount = 4;
        uint8_t pageIdx = 0;
        uint8_t pageCount = 1;
        while (pageIdx < pageCount) {
            auto s = FormatRates(txbody["amendment"]["rates"], pageIdx, &pageCount);
            if (!s.empty())
                answer.push_back(fmt::format("{} | Rates : {}", itemCount, s));
            pageIdx++;
            itemCount++;
        }
        pageIdx = 0;
        pageCount = 1;
        while (pageIdx < pageCount) {
            auto s = FormatBounds(txbody["amendment"]["bounds"], pageIdx, &pageCount);
            if (!s.empty())
                answer.push_back(fmt::format("{} | Bounds : {}", itemCount, s));
            pageIdx++;
            itemCount++;
        }
    }

    return answer;
}

std::vector<std::string> GenerateExpectedUIOutputForEntity(std::string context, Json::Value j) {
    auto answer = std::vector<std::string>();
    auto entity = j["entity"];

    answer.push_back(fmt::format("0 | Type : Entity signing"));

    uint8_t dummy;
    answer.push_back(fmt::format("1 | ID : {}", FormatPKasAddress(entity["id"].asString(), 0, &dummy)));
    answer.push_back(fmt::format("1 | ID : {}", FormatPKasAddress(entity["id"].asString(), 1, &dummy)));

    uint32_t itemCount = 2;

    int nodeIndex;
    for (nodeIndex = 0; nodeIndex < entity["nodes"].size(); nodeIndex++) {
        uint8_t dummy;
        answer.push_back(fmt::format("{} | Node : {}", itemCount,
                                     FormatPKasAddress(entity["nodes"][nodeIndex].asString(), 0, &dummy)));
        answer.push_back(fmt::format("{} | Node : {}", itemCount,
                                     FormatPKasAddress(entity["nodes"][nodeIndex].asString(), 1, &dummy)));

        itemCount++;
    }

    if (entity["allow_entity_signed_nodes"]) {
        answer.push_back(fmt::format("{} | Allowed", itemCount));
    } else {
        answer.push_back(fmt::format("{} | Not Allowed", itemCount));
    }

    return answer;
}

std::vector<std::string> GenerateExpectedUIOutput(std::string context, Json::Value j) {
    auto answer = std::vector<std::string>();

    if (!TestcaseIsValid(j)) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    // Entity or tx ?
    if (j.isMember("tx")) {
        // is tx
        return GenerateExpectedUIOutputForTx(context, j);
    } else {
        // is entity
        return GenerateExpectedUIOutputForEntity(context, j);
    }

}

std::vector<testcase_t> GetJsonTestCases(std::string filename) {
    auto answer = std::vector<testcase_t>();

    Json::CharReaderBuilder builder;
    Json::Value obj;

    std::ifstream inFile(filename);
    EXPECT_TRUE(inFile.is_open())
                        << "\n"
                        << "******************\n"
                        << "Check that your working directory points to the tests directory\n"
                        << "In CLion use $PROJECT_DIR$\\tests\n"
                        << "******************\n";
    if (!inFile.is_open())
        return answer;

    // Retrieve all test cases
    JSONCPP_STRING errs;
    Json::parseFromStream(builder, inFile, &obj, &errs);
    std::cout << "Number of testcases: " << obj.size() << std::endl;

    for (int i = 0; i < obj.size(); i++) {
        auto v = obj[i];
        auto description = std::string("");

        if (v.isMember("description")) {
            description = v["description"].asString();
        } else {
            description = v["kind"].asString();
        }
        description.erase(remove_if(description.begin(), description.end(), isspace), description.end());

        answer.push_back(testcase_t{
                description,
                std::to_string(i),
                v["kind"].asString(),
                v["signature_context"].asString(),
                v["encoded_tx"].asString(),
                v["valid"] && TestcaseIsValid(obj[i]),
                GenerateExpectedUIOutput(obj[i]["signature_context"].asString(), obj[i])
        });
    }

    return answer;
}

void check_testcase(const testcase_t &tc) {
    parser_context_t ctx;
    parser_error_t err;

    std::string cborString;
    macaron::Base64::Decode(tc.encoded_tx, cborString);

    const auto *buffer = (const uint8_t *) cborString.c_str();
    uint16_t bufferLen = cborString.size();

    err = parser_parse(&ctx, buffer, bufferLen);
    if (tc.valid) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        // TODO: maybe we can eventually match error codes too
        ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
        return;
    }

    crypto_set_context((const uint8_t *) tc.signature_context.c_str(),
                       tc.signature_context.size());

    err = parser_validate(&ctx);
    if (tc.valid) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        // TODO: maybe we can eventually match error codes too
        ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
        return;
    }

    auto output = dumpUI(&ctx, 40, 40);

    std::cout << std::endl;
    for (const auto &i : output) {
        std::cout << i << std::endl;
    }

    std::cout << " EXPECTED ============" << std::endl;
    for (const auto &i : tc.expected_ui_output  ) {
        std::cout << i << std::endl;
    }

    EXPECT_EQ(output.size(), tc.expected_ui_output.size());
    for (size_t i = 0; i < tc.expected_ui_output.size(); i++) {
        if (i < output.size()) {
            EXPECT_THAT(output[i], testing::Eq(tc.expected_ui_output[i]));
        }
    }
}

///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
// Define groups of test vectors

class OasisTests : public ::testing::TestWithParam<testcase_t> {
public:
    struct PrintToStringParamName {
        template<class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << std::setfill('0') << std::setw(5) << p.index << "_" << p.description;
            return ss.str();
        }
    };
};

INSTANTIATE_TEST_CASE_P(
        Generated,
        OasisTests,
        ::testing::ValuesIn(GetJsonTestCases("oasis_testvectors.json")), OasisTests::PrintToStringParamName()
);

TEST_P(OasisTests, CheckUIOutput_Oasis) { check_testcase(GetParam()); }

///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////

class ManualTests : public ::testing::TestWithParam<testcase_t> {
public:
    struct PrintToStringParamName {
        template<class ParamType>
        std::string operator()(const testing::TestParamInfo<ParamType> &info) const {
            auto p = static_cast<testcase_t>(info.param);
            std::stringstream ss;
            ss << std::setfill('0') << std::setw(5) << p.index << "_" << p.description;
            return ss.str();
        }
    };
};

INSTANTIATE_TEST_CASE_P(
        Manual,
        ManualTests,
        ::testing::ValuesIn(GetJsonTestCases("manual_testvectors.json")), ManualTests::PrintToStringParamName()
);

TEST_P(ManualTests, CheckUIOutput_Manual) { check_testcase(GetParam()); }
