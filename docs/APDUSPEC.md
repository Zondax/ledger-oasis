# Oasis App

## General structure

The Application Identifier depends on the app type:
| Type | APP_CLA   |
| ----- | -------- |
| Validator | 0xf5 |
| Consumer  | 0x05 |

The general structure of commands and responses is as follows:

#### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | APP_CLA |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

#### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

#### Return codes

| Return code | Description             |
| ----------- | ----------------------- |
| 0x6400      | Execution Error         |
| 0x6982      | Empty buffer            |
| 0x6983      | Output buffer too small |
| 0x6985      | Conditions not satisfied |
| 0x6986      | Command not allowed     |
| 0x6D00      | INS not supported       |
| 0x6E00      | CLA not supported       |
| 0x6F00      | Unknown                 |
| 0x9000      | Success                 |

---------

## Command definition

### GET_VERSION

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | APP_CLA  |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                            |
| ------- | -------- | ---------------- | ------------------------------- |
| TEST    | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR   | byte (1) | Version Major    |                                 |
| MINOR   | byte (1) | Version Minor    |                                 |
| PATCH   | byte (1) | Version Patch    |                                 |
| LOCKED  | byte (1) | Device is locked |                                 |
| SW1-SW2 | byte (2) | Return code      | see list of return codes        |

--------------

### GET_ADDR_ED25519

#### Command

| Field      | Type           | Content                | Expected       |
| ---------- | -------------- | ---------------------- | -------------- |
| CLA        | byte (1)       | Application Identifier | APP_CLA           |
| INS        | byte (1)       | Instruction ID         | 0x01           |
| P1         | byte (1)       | Request User confirmation | No = 0      |
| P2         | byte (1)       | Parameter 2            | ignored        |
| L          | byte (1)       | Bytes in payload       | (depends)      |
| Path[0]    | byte (4)       | Derivation Path Data   | 44             |
| Path[1]    | byte (4)       | Derivation Path Data   | 474            |
| Path[2]    | byte (4)       | Derivation Path Data   | ?              |
| Path[3]    | byte (4)       | Derivation Path Data   | ?              |
| Path[4]    | byte (4)       | Derivation Path Data   | ?              |

First three items in the derivation path will be hardened automatically hardened

#### Response

| Field   | Type      | Content               | Note                     |
| ------- | --------- | --------------------- | ------------------------ |
| PK      | byte (32) | Public Key            |                          |
| ADDR    | byte (??) | Bech 32 addr          |                          |
| SW1-SW2 | byte (2)  | Return code           | see list of return codes |

### SIGN_ED25519

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | APP_CLA      |
| INS   | byte (1) | Instruction ID         | 0x02      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks should contain message to sign

The chunk size is 250 bytes.

*First Packet*

| Field      | Type     | Content                | Expected  |
| ---------- | -------- | ---------------------- | --------- |
| Path[0]    | byte (4) | Derivation Path Data   | 44        |
| Path[1]    | byte (4) | Derivation Path Data   | 474       |
| Path[2]    | byte (4) | Derivation Path Data   | ?         |
| Path[3]    | byte (4) | Derivation Path Data   | ?         |
| Path[4]    | byte (4) | Derivation Path Data   | ?         |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Context+Message |          |

Data is defined as:

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| CtxLen  | byte     | Context Length  |          |
| Context | bytes..  | Context         | CtxLen bytes|
| Message | bytes..  | CBOR data to sign   |      |

#### Response

The response depends on app type:

*Consumer Response*

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

*Validator Response*

The Validator response has a validation flow that can result in diferente responses:

 If Oasis Blob is a Consensus Type:
   1. Vote State is checked and if it is not initialized, a new valid vote is set:

   | Field   | Type      | Content     | Note                     |
   | ------- | --------- | ----------- | ------------------------ |
   | SW1-SW2 | byte (2)  | Return code | see list of return codes |

2. Vote is initialized and the current vote state is returned alongside the conflicting vote data [vote][vote_state][error]


| Field     | Type      | Content     | Note                     |
| -------   | --------- | ----------- | ------------------------ |
| Buffer    | byte (1)  | Vote type         |          |
|           | byte (8)  | Vote height       |          |
|           | byte (8)  | Vote round        |          |
|           | byte (1)  | Vote state type   |          |
|           | byte (8)  | Vote state height |          |
|           | byte (8)  | Vote state round  |          |
| SW1-SW2   | byte (2)  | Return code       | see list of return codes |


If Oasis Blob is not a Consensus Type:

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

--------------
### SIGN_RT_ED25519

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- |-----------|
| CLA   | byte (1) | Application Identifier | 0x05      |
| INS   | byte (1) | Instruction ID         | 0x05      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks should contain message to sign

The chunk size is 250 bytes.

*First Packet*

| Field      | Type     | Content                | Expected  |
| ---------- | -------- | ---------------------- | --------- |
| Path[0]    | byte (4) | Derivation Path Data   | 44        |
| Path[1]    | byte (4) | Derivation Path Data   | 474       |
| Path[2]    | byte (4) | Derivation Path Data   | ?         |
| Path[3]    | byte (4) | Derivation Path Data   | ?         |
| Path[4]    | byte (4) | Derivation Path Data   | ?         |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Context+Message |          |

Data is defined as:

| Field   | Type    | Content            | Expected |
|---------|---------|--------------------|----------|
| Meta    | byte..  | CBOR metadata      |          |
| Message | bytes.. | CBOR data to sign  |          |

Meta contains the following fields:
- runtime_id: 32-byte runtime ID
- chain_context: 32-byte chain ID
- orig_to (optional): 20-byte ethereum destination address

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

--------------

### GET_ADDR_SECP256K1

#### Command

| Field      | Type           | Content                   | Expected  |
| ---------- | -------------- |---------------------------|-----------|
| CLA        | byte (1)       | Application Identifier    | 0x05      |
| INS        | byte (1)       | Instruction ID            | 0x04      |
| P1         | byte (1)       | Request User confirmation | No = 0    |
| P2         | byte (1)       | Parameter 2               | ignored   |
| L          | byte (1)       | Bytes in payload          | (depends) |
| Path[0]    | byte (4)       | Derivation Path Data      | 44        |
| Path[1]    | byte (4)       | Derivation Path Data      | 60         |
| Path[2]    | byte (4)       | Derivation Path Data      | ?         |
| Path[3]    | byte (4)       | Derivation Path Data      | ?         |
| Path[4]    | byte (4)       | Derivation Path Data      | ?         |

First three items in the derivation path are hardened

#### Response

| Field   | Type      | Content               | Note                     |
| ------- |-----------|-----------------------| ------------------------ |
| PK      | byte (33) | Compressed Public Key |                          |
| ADDR    | byte (??) | Hex addr              |                          |
| SW1-SW2 | byte (2)  | Return code           | see list of return codes |

--------------
### SIGN_RT_SECP256K1

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- |-----------|
| CLA   | byte (1) | Application Identifier | 0x05      |
| INS   | byte (1) | Instruction ID         | 0x07      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks should contain message to sign

*First Packet*

| Field      | Type     | Content                | Expected |
| ---------- | -------- | ---------------------- |----------|
| Path[0]    | byte (4) | Derivation Path Data   | 44       |
| Path[1]    | byte (4) | Derivation Path Data   | 60       |
| Path[2]    | byte (4) | Derivation Path Data   | ?        |
| Path[3]    | byte (4) | Derivation Path Data   | ?        |
| Path[4]    | byte (4) | Derivation Path Data   | ?        |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Meta+Message |          |

Data is defined as:

| Field   | Type    | Content            | Expected |
|---------|---------|--------------------|----------|
| Meta    | byte..  | CBOR metadata      |          |
| Message | bytes.. | CBOR data to sign  |          |

Meta contains the following fields:
- runtime_id: 32-byte runtime ID
- chain_context: 32-byte chain ID
- orig_to (optional): 20-byte ethereum destination address


#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

### GET_ADDR_SR25519

#### Command

| Field      | Type           | Content                   | Expected  |
| ---------- | -------------- |---------------------------|-----------|
| CLA        | byte (1)       | Application Identifier    | 0x05      |
| INS        | byte (1)       | Instruction ID            | 0x03      |
| P1         | byte (1)       | Request User confirmation | No = 0    |
| P2         | byte (1)       | Parameter 2               | ignored   |
| L          | byte (1)       | Bytes in payload          | (depends) |
| Path[0]    | byte (4)       | Derivation Path Data      | 44        |
| Path[1]    | byte (4)       | Derivation Path Data      | 474       |
| Path[2]    | byte (4)       | Derivation Path Data      | ?         |
| Path[3]    | byte (4)       | Derivation Path Data      | ?         |
| Path[4]    | byte (4)       | Derivation Path Data      | ?         |

First three items in the derivation path are hardened

#### Response

| Field   | Type      | Content               | Note                     |
| ------- | --------- | --------------------- | ------------------------ |
| PK      | byte (32) | Public Key            |                          |
| ADDR    | byte (??) | Bech 32 addr          |                          |
| SW1-SW2 | byte (2)  | Return code           | see list of return codes |

### SIGN_RT_SR25519

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- |-----------|
| CLA   | byte (1) | Application Identifier | 0x05      |
| INS   | byte (1) | Instruction ID         | 0x06      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks should contain message to sign

*First Packet*

| Field      | Type     | Content                | Expected |
| ---------- | -------- | ---------------------- |----------|
| Path[0]    | byte (4) | Derivation Path Data   | 44       |
| Path[1]    | byte (4) | Derivation Path Data   | 474      |
| Path[2]    | byte (4) | Derivation Path Data   | ?        |
| Path[3]    | byte (4) | Derivation Path Data   | ?        |
| Path[4]    | byte (4) | Derivation Path Data   | ?        |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Meta+Message |          |

Data is defined as:

| Field   | Type    | Content            | Expected |
|---------|---------|--------------------|----------|
| Meta    | byte..  | CBOR metadata      |          |
| Message | bytes.. | CBOR data to sign  |          |

Meta contains the following fields:
- runtime_id: 32-byte runtime ID
- chain_context: 32-byte chain ID
- orig_to (optional): 20-byte ethereum destination address


#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |
