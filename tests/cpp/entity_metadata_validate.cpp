/*******************************************************************************
*   (c) 2021 ZondaX GmbH
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
#include "consumer/parser_impl_con.h"
#include "base64.h"
#include "common.h"
#include "testcases.h"
#include "hexutils.h"

TEST(EntityMetadataUrl, EntityMetadataUrlsNotStartingWithHTTPS) {
    url_t url;
    char buffer[] = "OK";
    MEMZERO(&url, sizeof(url_t));
    MEMCPY(&url, buffer, strlen(buffer));
    url.len = strlen(buffer);
    auto err = _isValidUrl(&url);
    ASSERT_EQ(err, parser_invalid_url_format) << parser_getErrorDescription(err);
}

TEST(EntityMetadataUrl, EntityMetadataUrlsContainsQuery) {
    url_t url;
    char buffer[] = "https://example.com?name=lola";
    MEMZERO(&url, sizeof(url_t));
    MEMCPY(&url, buffer, strlen(buffer));
    url.len = strlen(buffer);
    auto err = _isValidUrl(&url);
    ASSERT_EQ(err, parser_invalid_url_format) << parser_getErrorDescription(err);
}

TEST(EntityMetadataUrl, EntityMetadataUrlsContainsFragment) {
    url_t url;
    char buffer[] = "https://example.com#lola";
    MEMZERO(&url, sizeof(url_t));
    MEMCPY(&url, buffer, strlen(buffer));
    url.len = strlen(buffer);
    auto err = _isValidUrl(&url);
    ASSERT_EQ(err, parser_invalid_url_format) << parser_getErrorDescription(err);
}

TEST(EntityMetadataUrl, EntityMetadataUrlsContainsSpace) {
    url_t url;
    char buffer[] = "https://example.com lola";
    MEMZERO(&url, sizeof(url_t));
    MEMCPY(&url, buffer, strlen(buffer));
    url.len = strlen(buffer);
    auto err = _isValidUrl(&url);
    ASSERT_EQ(err, parser_invalid_url_format) << parser_getErrorDescription(err);
}

TEST(EntityMetadataEmail, EntityMetadataEmailValid) {
    email_t email;
    char buffer[] = "me@example.com";
    MEMZERO(&email, sizeof(email_t));
    MEMCPY(&email, buffer, strlen(buffer));
    email.len = strlen(buffer);
    auto err = _isValidEmail(&email);
    ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
}

TEST(EntityMetadataEmail, EntityMetadataEmail2Arobases) {
    email_t email;
    char buffer[] = "me@bug@example.com";
    MEMZERO(&email, sizeof(email_t));
    MEMCPY(&email, buffer, strlen(buffer));
    email.len = strlen(buffer);
    auto err = _isValidEmail(&email);
    ASSERT_EQ(err, parser_invalid_email_format) << parser_getErrorDescription(err);
}

TEST(EntityMetadataEmail, EntityMetadataEmailNotValidDomainName) {
    email_t email;
    char buffer[] = "me@example";
    MEMZERO(&email, sizeof(email_t));
    MEMCPY(&email, buffer, strlen(buffer));
    email.len = strlen(buffer);
    auto err = _isValidEmail(&email);
    ASSERT_EQ(err, parser_invalid_email_format) << parser_getErrorDescription(err);
}

TEST(EntityMetadataEmail, EntityMetadataEmailNoArobase) {
    email_t email;
    char buffer[] = "me.example.com";
    MEMZERO(&email, sizeof(email_t));
    MEMCPY(&email, buffer, strlen(buffer));
    email.len = strlen(buffer);
    auto err = _isValidEmail(&email);
    ASSERT_EQ(err, parser_invalid_email_format) << parser_getErrorDescription(err);
}

TEST(EntityMetadataHandle, EntityMetadataHandle) {
    handle_t handle;
    char buffer[] = "example_com";
    MEMZERO(&handle, sizeof(handle_t));
    MEMCPY(&handle, buffer, strlen(buffer));
    handle.len = strlen(buffer);
    auto err = _isValidHandle(&handle);
    ASSERT_EQ(err, parser_ok) << parser_getErrorDescription(err);
}

TEST(EntityMetadataHandle, EntityMetadataHandleNotAllowChar) {
    handle_t handle;
    char buffer[] = "example*com";
    MEMZERO(&handle, sizeof(handle_t));
    MEMCPY(&handle, buffer, strlen(buffer));
    handle.len = strlen(buffer);
    auto err = _isValidHandle(&handle);
    ASSERT_EQ(err, parser_invalid_handle_format) << parser_getErrorDescription(err);
}

TEST(EntityMetadataHandle, EntityMetadataHandleNotAllowChar2) {
    handle_t handle;
    char buffer[] = "@examplecom";
    MEMZERO(&handle, sizeof(handle_t));
    MEMCPY(&handle, buffer, strlen(buffer));
    handle.len = strlen(buffer);
    auto err = _isValidHandle(&handle);
    ASSERT_EQ(err, parser_invalid_handle_format) << parser_getErrorDescription(err);
}