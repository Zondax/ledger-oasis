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
#include <zxformat.h>

extern "C" {
#include "sha512.h"
}

TEST(SHA512_256, API_Check) {
    uint8_t input[] = {'A', 'B', 'C', 'a', 'b', 'c'};
    uint8_t messageDigest[64];

    SHA512_256(input, sizeof(input), messageDigest);

    char s[100];
    array_to_hexstr(s, sizeof(s), messageDigest, 32 );
    std::cout << s << std::endl;

    EXPECT_STREQ(s, "AAA731E500EAB8062B5F95830900872A4A4A85560FDF56CECFA0242036299AC7");
}
