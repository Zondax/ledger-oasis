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

#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include <zxmacros.h>
#include "lib/parser.h"
#include "util/base64.h"
#include "util/common.h"

using ::testing::TestWithParam;
using ::testing::Values;
using json = nlohmann::json;

typedef struct {
//    std::string nonce;
//    std::string fee_amount;
//    std::string fee_gas;
//    std::string method;
//    std::string body;
} tx_t;

typedef struct {
    std::string index;
    std::string kind;
    std::string signature_context;
    std::string encoded_tx;
    bool valid;

//    std::string parsingErr;
////    std::string signed_tx;
//    std::string encoded_signed_tx;
//    bool valid;
//    std::string signer_private_key;
//    std::string signer_public_key;
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
                item["valid"]
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

    char bufferOut[500];
    array_to_hexstr(bufferOut, (uint8_t *) cborString.c_str(), (uint8_t) bufferLen);
    std::cout << bufferOut << std::endl;

    err = parser_parse(&ctx, buffer, bufferLen);
    if (tc.valid) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
    }

    auto output = dumpUI(&ctx, 40, 40);

    for (const auto &i : output) {
        std::cout << i << std::endl;
    }
    std::cout << std::endl << std::endl;

//    EXPECT_EQ(output.size(), tc.expected.size());
//    for (size_t i = 0; i < tc.expected.size(); i++) {
//        if (i < output.size()) {
//            EXPECT_THAT(output[i], testing::Eq(tc.expected[i]));
//        }
//    }
}

INSTANTIATE_TEST_CASE_P

(
        JsonTestCases,
        JsonTests,
        ::testing::ValuesIn(GetJsonTestCases()), JsonTests::PrintToStringParamName()
);

TEST_P(JsonTests, CheckUIOutput) { check_testcase(GetParam()); }
