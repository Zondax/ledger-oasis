/*******************************************************************************
*  (c) 2020 Zondax GmbH
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

#define MAINNET_GENESIS_HASH "b11b369e0da5bb230b220127f5e7b242d385ef8c6f54906243f30af63c815535"
#define TESTNET_GENESIS_HASH "50304f98ddb656620ea817cc1446c401752a05a249b36c9b90dba4616829977a"

#if defined(APP_CONSUMER)
#include "consumer/coin_consumer.h"
#elif defined(APP_VALIDATOR)
#include "validator/coin_validator.h"
#else
#error "APP MODE IS NOT SUPPORTED"
#endif
