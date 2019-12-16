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
#include "testcases.h"
#include "base64.h"
#include <fmt/core.h>
#include <lib/crypto.h>
#include <bech32.h>
#include <gtest/gtest.h>
#include <algorithm>

std::vector<uint8_t> prepareBlob(const std::string &context, const std::string &base64Cbor) {
    std::string cborString;
    macaron::Base64::Decode(base64Cbor, cborString);

    if (context.size() >= 256) {
        throw std::invalid_argument("context should be < 256 bytes");
    }

    // Allocate and prepare buffer
    // context size
    // context
    // CBOR payload
    uint16_t bufferLen = 1 + context.size() + cborString.size();
    auto bufferAllocation = std::vector<uint8_t>(bufferLen);

    bufferAllocation[0] = context.size();
    MEMCPY(bufferAllocation.data() + 1, context.c_str(), context.size());
    MEMCPY(bufferAllocation.data() + 1 + context.size(), cborString.c_str(), cborString.size());

    return bufferAllocation;
}

testcaseData_t ReadTestCaseData(const std::shared_ptr<Json::Value> &jsonSource, int index) {
    testcaseData_t answer;
    auto v = (*jsonSource)[index];
    auto description = std::string("");

    if (v.isMember("description")) {
        description = v["description"].asString();
    } else {
        description = v["kind"].asString();
    }
    description.erase(remove_if(description.begin(), description.end(), isspace), description.end());

    return {
            false,
            description,
            std::to_string(index),
            v["kind"].asString(),
            v["signature_context"].asString(),
            v["encoded_tx"].asString(),
            v["valid"] && TestcaseIsValid(v),
            GenerateExpectedUIOutput(v["signature_context"].asString(), v)
    };
}

std::vector<testcase_t> GetJsonTestCases(const std::string &filename) {
    auto answer = std::vector<testcase_t>();

    Json::CharReaderBuilder builder;
    std::shared_ptr<Json::Value> obj(new Json::Value());

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
    Json::parseFromStream(builder, inFile, obj.get(), &errs);
    std::cout << "Number of testcases: " << obj->size() << std::endl;
    answer.reserve(obj->size());

    for (int i = 0; i < obj->size(); i++) {
        auto v = (*obj)[i];
        auto description = std::string("");

        if (v.isMember("description")) {
            description = v["description"].asString();
        } else {
            description = v["kind"].asString();
        }
        description.erase(remove_if(description.begin(), description.end(), isspace), description.end());

        answer.push_back(testcase_t{obj, i, description});
    }

    return answer;
}

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

template<typename S, typename... Args>
void addTo(std::vector<std::string> &answer, const S &format_str, Args &&... args) {
    answer.push_back(fmt::format(format_str, args...));
}

std::vector<std::string> GenerateExpectedUIOutputForTx(Json::Value j, uint32_t &itemCount) {
    auto answer = std::vector<std::string>();

    auto type = j["tx"]["method"].asString();
    auto tx = j["tx"];
    auto txbody = tx["body"];

    uint8_t dummy;

    if (type == "staking.Transfer") {
        addTo(answer, "{} | Type : Transfer", itemCount++);
        if (tx.isMember("fee")) {
            addTo(answer, "{} | Fee Amount : {}", itemCount++, FormatAmount(tx["fee"]["amount"].asString()));
            addTo(answer, "{} | Fee Gas : {}", itemCount++, tx["fee"]["gas"].asUInt64());
        }

        addTo(answer, "{} | To : {}", itemCount, FormatPKasAddress(txbody["xfer_to"].asString(), 0, &dummy));
        addTo(answer, "{} | To : {}", itemCount++, FormatPKasAddress(txbody["xfer_to"].asString(), 1, &dummy));
        addTo(answer, "{} | Tokens : {}", itemCount++, FormatAmount(txbody["xfer_tokens"].asString()));
    }

    if (type == "staking.Burn") {
        addTo(answer, "{} | Type : Burn", itemCount++);
        if (tx.isMember("fee")) {
            addTo(answer, "{} | Fee Amount : {}", itemCount++, FormatAmount(tx["fee"]["amount"].asString()));
            addTo(answer, "{} | Fee Gas : {}", itemCount++, tx["fee"]["gas"].asUInt64());
        }
        addTo(answer, "{} | Tokens : {}", itemCount++, FormatAmount(txbody["burn_tokens"].asString()));
    }

    if (type == "staking.AddEscrow") {
        addTo(answer, "{} | Type : Add escrow", itemCount++);
        if (tx.isMember("fee")) {
            addTo(answer, "{} | Fee Amount : {}", itemCount++, FormatAmount(tx["fee"]["amount"].asString()));
            addTo(answer, "{} | Fee Gas : {}", itemCount++, tx["fee"]["gas"].asUInt64());
        }

        auto escrowAccount = txbody["escrow_account"].asString();
        addTo(answer, "{} | Escrow : {}", itemCount, FormatPKasAddress(escrowAccount, 0, &dummy));
        addTo(answer, "{} | Escrow : {}", itemCount++, FormatPKasAddress(escrowAccount, 1, &dummy));
        addTo(answer, "{} | Tokens : {}", itemCount++, FormatAmount(txbody["escrow_tokens"].asString()));
    }

    if (type == "staking.ReclaimEscrow") {
        addTo(answer, "{} | Type : Reclaim escrow", itemCount++);
        if (tx.isMember("fee")) {
            addTo(answer, "{} | Fee Amount : {}", itemCount++, FormatAmount(tx["fee"]["amount"].asString()));
            addTo(answer, "{} | Fee Gas : {}", itemCount++, tx["fee"]["gas"].asUInt64());
        }

        auto escrowAccount = txbody["escrow_account"].asString();
        addTo(answer, "{} | Escrow : {}", itemCount, FormatPKasAddress(escrowAccount, 0, &dummy));
        addTo(answer, "{} | Escrow : {}", itemCount++, FormatPKasAddress(escrowAccount, 1, &dummy));
        addTo(answer, "{} | Tokens : {}", itemCount++, FormatAmount(txbody["reclaim_shares"].asString()));
    }

    if (type == "staking.AmendCommissionSchedule") {
        addTo(answer, "{} | Type : Amend commission schedule", itemCount++);
        if (tx.isMember("fee")) {
            addTo(answer, "{} | Fee Amount : {}", itemCount++, FormatAmount(tx["fee"]["amount"].asString()));
            addTo(answer, "{} | Fee Gas : {}", itemCount++, tx["fee"]["gas"].asUInt64());
        }

        uint8_t pageIdx = 0;
        uint8_t pageCount = 1;
        while (pageIdx < pageCount) {
            auto s = FormatRates(txbody["amendment"]["rates"], pageIdx, &pageCount);
            if (!s.empty())
                addTo(answer, "{} | Rates : {}", itemCount, s);
            pageIdx++;
            itemCount++;
        }
        pageIdx = 0;
        pageCount = 1;
        while (pageIdx < pageCount) {
            auto s = FormatBounds(txbody["amendment"]["bounds"], pageIdx, &pageCount);
            if (!s.empty())
                addTo(answer, "{} | Bounds : {}", itemCount, s);
            pageIdx++;
            itemCount++;
        }
    }

    return answer;
}

std::vector<std::string> GenerateExpectedUIOutputForEntity(Json::Value j, uint32_t &itemCount) {
    auto answer = std::vector<std::string>();
    auto entity = j["entity"];
    uint8_t dummy;

    addTo(answer, "{} | Type : Entity signing", itemCount++);
    addTo(answer, "{} | ID : {}", itemCount, FormatPKasAddress(entity["id"].asString(), 0, &dummy));
    addTo(answer, "{} | ID : {}", itemCount++, FormatPKasAddress(entity["id"].asString(), 1, &dummy));

    int nodeIndex;
    for (nodeIndex = 0; nodeIndex < entity["nodes"].size(); nodeIndex++) {
        auto nodeData = entity["nodes"][nodeIndex].asString();
        addTo(answer, "{} | Node : {}", itemCount, FormatPKasAddress(nodeData, 0, &dummy));
        addTo(answer, "{} | Node : {}", itemCount++, FormatPKasAddress(nodeData, 1, &dummy));
    }

    if (entity["allow_entity_signed_nodes"]) {
        addTo(answer, "{} | Allowed", itemCount);
    } else {
        addTo(answer, "{} | Not Allowed", itemCount);
    }

    return answer;
}

std::vector<std::string> GenerateExpectedUIOutput(std::string context, const Json::Value &j) {
    auto answer = std::vector<std::string>();
    uint32_t itemCount = 0;

    if (!TestcaseIsValid(j)) {
        answer.emplace_back("Test case is not valid!");
        return answer;
    }

    // Entity or tx ?
    if (j.isMember("tx")) {
        // is tx
        answer = GenerateExpectedUIOutputForTx(j, itemCount);
    } else {
        // is entity
        answer = GenerateExpectedUIOutputForEntity(j, itemCount);
    }

    auto expectedPrefix = std::string("oasis-core/consensus: tx for chain ");
    auto contextSuffix = context.replace(context.find(expectedPrefix), expectedPrefix.size(), "");

    addTo(answer, "{} | Context : {}", itemCount, contextSuffix);
    return answer;
}
