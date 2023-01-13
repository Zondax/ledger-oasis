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
#include "testcases.h"
#include "common.h"

#include <iostream>
#include <memory>
#include "common/parser.h"

using ::testing::TestWithParam;

void check_testcase(const testcase_t &testcase) {
    int runtime = 0;
    auto tc = utils::ReadTestCaseData(testcase.testcases, testcase.index, &runtime);

    parser_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    auto buffer = std::vector<uint8_t>();
    if (runtime) {
        buffer = utils::prepareRuntimeBlob(tc.signature_context, tc.encoded_tx);
    } else {
        buffer = utils::prepareBlob(tc.signature_context, tc.encoded_tx);
    }

    parser_error_t err = parser_parse(&ctx, buffer.data(), buffer.size());
    if (tc.valid) {
        ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        ASSERT_NE(err, parser_ok) << parser_getErrorDescription(err);
        return;
    }

    err = parser_validate(&ctx);
    if (tc.valid) {
        EXPECT_EQ(err, parser_ok) << parser_getErrorDescription(err);
    } else {
        EXPECT_NE(err, parser_ok) << parser_getErrorDescription(err);
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

INSTANTIATE_TEST_SUITE_P(
        Manual,
        ManualTests,
        ::testing::ValuesIn(utils::GetJsonTestCases("testvectors/manual.json")), ManualTests::PrintToStringParamName()
);

TEST_P(ManualTests, CheckUIOutput_Manual) { check_testcase(GetParam()); }

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

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

INSTANTIATE_TEST_SUITE_P(
        Generated,
        OasisTests,
        ::testing::ValuesIn(utils::GetJsonTestCases("testvectors/generated.json")), OasisTests::PrintToStringParamName()
);

INSTANTIATE_TEST_SUITE_P(
        GeneratedGovernance,
        OasisTests,
        ::testing::ValuesIn(utils::GetJsonTestCases("testvectors/governance.json")), OasisTests::PrintToStringParamName()
);

INSTANTIATE_TEST_SUITE_P(
        GeneratedEntity,
        OasisTests,
        ::testing::ValuesIn(utils::GetJsonTestCases("testvectors/registry.json")), OasisTests::PrintToStringParamName()
);

INSTANTIATE_TEST_SUITE_P(
        GeneratedEntityMetadata,
        OasisTests,
        ::testing::ValuesIn(utils::GetJsonTestCases("testvectors/generated_entity_metadata.json")), OasisTests::PrintToStringParamName()
);

INSTANTIATE_TEST_SUITE_P(
        GeneratedRuntime,
        OasisTests,
        ::testing::ValuesIn(utils::GetJsonTestCases("testvectors/addr0014_generated.json")), OasisTests::PrintToStringParamName()
);

TEST_P(OasisTests, CheckUIOutput_Oasis) { check_testcase(GetParam()); }


