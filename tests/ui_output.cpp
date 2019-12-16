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
#include "util/testcases.h"

#include <iostream>
#include <memory>
#include <zxmacros.h>
#include "lib/parser.h"
#include "util/base64.h"
#include "util/common.h"

using ::testing::TestWithParam;
using ::testing::Values;

void check_testcase(const testcase_t &testcase) {
    auto tc = ReadTestCaseData(testcase.testcases, testcase.index);

    parser_context_t ctx;
    parser_error_t err;

    std::string cborString;
    macaron::Base64::Decode(tc.encoded_tx, cborString);

    ASSERT_LT(tc.signature_context.size(), 256);

    // Allocate and prepare buffer
    // context size
    // context
    // CBOR payload
    uint16_t bufferLen = 1 + tc.signature_context.size() + cborString.size();
    auto bufferAllocation = std::unique_ptr<uint8_t[]>(new uint8_t[bufferLen]);
    bufferAllocation[0] = tc.signature_context.size();
    MEMCPY(bufferAllocation.get() + 1, tc.signature_context.c_str(), tc.signature_context.size());
    MEMCPY(bufferAllocation.get() + 1 + tc.signature_context.size(), cborString.c_str(), cborString.size());

    const auto *buffer = (const uint8_t *) bufferAllocation.get();

    err = parser_parse(&ctx, buffer, bufferLen);
    if (tc.valid) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        // TODO: maybe we can eventually match error codes too
        ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
        return;
    }

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
    for (const auto &i : tc.expected_ui_output) {
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
