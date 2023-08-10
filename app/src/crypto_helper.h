/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <stdint.h>
#include "zxerror.h"

zxerr_t crypto_getBytesToSign(uint8_t *toSign, size_t toSignLen);
const uint8_t *crypto_getSr25519BytesToSign(uint8_t *msgDigest, size_t msgDigestLen, uint32_t *ctxLen);
