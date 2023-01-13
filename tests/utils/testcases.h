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
#pragma once
#include <json/json.h>
#include <fstream>

typedef struct {
    bool empty;
    std::string description;
    std::string index;
    std::string kind;
    std::string signature_context;
    std::string encoded_tx;
    bool valid;
    bool valid_tx;
    std::vector<std::string> expected_ui_output;
} testcaseData_t;

typedef struct {
    std::shared_ptr<Json::Value> testcases;
    int64_t index;
    std::string description;
} testcase_t;

namespace utils {
    std::vector<uint8_t> prepareBlob(const std::string &context, const std::string &base64Cbor);

    std::vector<uint8_t> prepareRuntimeBlob(const std::string &context, const std::string &base64Cbor);

    testcaseData_t ReadTestCaseData(const std::shared_ptr<Json::Value>& jsonSource, int index, int *runtime);

    std::vector<testcase_t> GetJsonTestCases(const std::string& filename);

    std::vector<std::string> GenerateExpectedUIOutput(std::string context, const Json::Value& j);

    bool TestcaseIsValid(const Json::Value &tc);
}
