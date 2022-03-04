TODO: Move to gist.

# Design doc: UI for signing ParaTime transactions

This document proposes UI/UX on the Ledger devices for:
1. signing deposit/withdrawal ROSE transaction to/from ParaTime,
2. signing the smart contract upload, instantiate and call transaction on
   Cipher ParaTime.

## Signing deposit/withdrawal ROSE to/from ParaTime

The UI behaves similar to the existing interface for regular ROSE transfers
with few additions.

### Deposit

TODO: In the future, "roothash submit message" transaction will replace allowance+deposit tranasction.
See incoming messages oasis-core ADR.

Deposit operation consists of two transactions. First, we submit the allowance
transaction which permits the ParaTime to move the tokens from the user's
consensus account to the ParaTime's `oasis1` address.

```ledger
|     Type     > | < Beneficiary (1/1) > | <   Amount    > | <     Fee     > | <  Gas limit  > | < Genesis Hash (1/1) > | <             > | <               |
|   Allowance    |    <RUNTIME OASIS1    |  +-<AMOUNT IN   |  <FEE IN ROSE>  |   <GAS LIMIT>   |     <GENESIS HASH>     |     APPROVE     |      REJECT     |
|                |       ADDRESS>        |   ROSE> ROSE    |  ROSE           |                 |                        |                 |                 |
```

`AMOUNT IN ROSE` is relative and must be prefixed by `+` or `-`.

`RUNTIME OASIS1 ADDRESS` renders the `oasis1` address of the beneficiary. For
specific `oasis1` addresses below, Ledger should render the human-readable
variant:
- `oasis1qrnu9yhwzap7rqh6tdcdcpz0zf86hwhycchkhvt8`: `Cipher (Mainnet)`
- `oasis1qqdn25n5a2jtet2s5amc7gmchsqqgs4j0qcg5k0t`: `Cipher (Testnet)`
- `oasis1qzvlg0grjxwgjj58tx2xvmv26era6t2csqn22pte`: `Emerald (Mainnet)`
- `oasis1qr629x0tg9gm5fyhedgs9lw5eh3d8ycdnsxf0run`: `Emerald (Testnet)`

The addresses above can be hardcoded into Oasis Ledger App. They were
derived from the ParaTime ID using the scheme described in the [staking
document].

The second transaction is the deposit transaction.

```ledger
|     Type     > | <   To (1/1)  > | <   Amount    > | < ParaTime ID (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <               |
|    Deposit     | <OASIS1 OR 0x   | <AMOUNT IN      |     <RUNTIME ID>      |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|   (ParaTime)   |  ADDRESS>       |  ROSE> ROSE     |                       |  ROSE           |                 |                 |                 |
```

The `OASIS1 OR 0x ADDRESS` can either be `oasis1` or the Ethereum's `0x`
address. When signing the transaction however, the `0x` **must be transcoded
into `oasis1` address** by using a special [mapping function].

`RUNTIME ID` shows the 32-byte hex encoded ParaTime ID. For specific Paratime
IDs below, Ledger should render the human-readable variant:
- `000000000000000000000000000000000000000000000000e199119c992377cb`: `Cipher (Mainnet)`
- `0000000000000000000000000000000000000000000000000000000000000000`: `Cipher (Testnet)`
- `000000000000000000000000000000000000000000000000e2eaa99fc008f87f`: `Emerald (Mainnet)`
- `00000000000000000000000000000000000000000000000072c8215e60d5bca7`: `Emerald (Testnet)`

[staking document]: https://docs.oasis.dev/oasis-core/consensus/services/staking/#runtime-accounts
[mapping function]: https://github.com/oasisprotocol/oasis-sdk/blob/e566b326ab1c34f3d811b50f96c53c3a79a91826/client-sdk/go/types/address.go#L125-L149

### Withdrawal

ParaTime withdrawal moves tokens from the ParaTime to `oasis1` address on the
consensus layer. The transaction **can be signed either with `Secp256k1` ("Ethereum")
or `ed25519` key!** The `Secp256k1` key is used, if the originating address is
`0x` ethereum address and it is derived on Ledger by using the standard Ethereum
[BIP44] path. The `ed25519` key is used, if the originating account is `oasis1`
and it is derived on Ledger by using the [ADR8] path.

```ledger
|     Type     > | <    To (1/1)  > | <   Amount    > | <     Fee     > | <  Gas limit  > | < Genesis Hash (1/1) > | <             > | <               |
|   Withdraw     | <OASIS1 ADDRESS> |  <AMOUNT IN     |  <FEE IN ROSE>  |   <GAS LIMIT>   |     <GENESIS HASH>     |     APPROVE     |      REJECT     |
|  (ParaTime)    |                  |   ROSE> ROSE    |  ROSE           |                 |                        |                 |                 |
```

[BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
[ADR8]: https://github.com/oasisprotocol/oasis-core/blob/master/docs/adr/0008-standard-account-key-generation.md

### Example

User wants to make allowance and deposit 100 ROSE to
`0x90adE3B7065fa715c7a150313877dF1d33e777D5` account on Emerald ParaTime on the
Mainnet.

```ledger
|     Type     > | <    To   > | <   Amount    > | <     Fee     > | <  Gas limit  > | < Genesis Hash (1/2) > | < Genesis Hash (2/2) > | <             > | <              |
|   Allowance    |   Emerald   |  +100.00 ROSE   |     0.0 ROSE    |      1278       | 53852332637bacb61b91b6 | c3f82448438826f23898   |     APPROVE     |     REJECT     |
|                |  (Mainnet)  |                 |                 |                 | 411ab4095168ba02a50be4 |                        |                 |                |
```

```ledger
|     Type     > | <   To (1/2)  > | <    To (2/2)   > | <   Amount    > | < ParaTime ID > | <     Fee     > | <  Gas limit  > | <             > | <               |
|    Deposit     | 0x90adE3B7065fa | dF1d33e777D5      |   100.00 ROSE   |     Emerald     |    0.00 ROSE    |      11286      |     APPROVE     |      REJECT     |
|   (ParaTime)   | 715c7a150313877 |                   |                 |    (Mainnet)    |                 |                 |                 |                 |
```

Then, user wants to withdraw the same amount of tokens (minus the fee) back to
the Mainnet.

```ledger
|     Type     > | <    To (1/2)  > | <    To (2/2)   > | <   Amount    > | <     Fee     > | <  Gas limit  > | < Genesis Hash (1/2) > | < Genesis Hash (2/2) > | <             > | <               |
|   Withdraw     | oasis1qrec770vre | 504k68svq7kzve    |  99.99985 ROSE  |   0.00015 ROSE  |      11286      | 53852332637bacb61b91b6 | c3f82448438826f23898   |     APPROVE     |      REJECT     |
|  (ParaTime)    | k0a9a5lcrv0zvt22 |                   |                 |                 |                 | 411ab4095168ba02a50be4 |                        |                 |                 |
```

## Smart contract transactions on Cipher

TODO: This is not actually Cipher-related, but these are general Oasis ParaTime SDK calls. See
https://github.com/oasisprotocol/oasis-sdk/blob/main/runtime-sdk/src/types/transaction.rs

TODO: Add contract upgrade transaction.

TODO: Could we make a generic UI for any ParaTime transaction (npr. governance, delete) so
in the future we wouldn't need to release new version of Oasis Ledger App for each new
ParaTime transaction?

### Deploying smart contracts on Cipher

Deploying smart contracts to Cipher is done in two steps. First, the code is
uploaded:

```ledger
| Review Contract > | < Contract hash (1/1) | < ParaTime ID (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <               |
|     Upload        |    <CONTRACT HASH>    |     <RUNTIME ID>      |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|                   |                       |                       |   ROSE          |                 |                 |                 |
```

TODO: Signing complete smart contract probably won't work in practice (500kB+ size).
Maybe in the future, if only the root hash of the wasm contract would be contained
in the transaction (and signed), this could work (ethereum 2.x does it like this).
Let's ditch contract upload signing on Ledger for now and call it officially
unsupported.

`CONTRACT HASH` is a hash of the WASM contract file. The purpose of this hash
is that the user can check whether the correct file is being signed. It can be
computed either on the Ledger or just computed on the client machine and
sent to Ledger - secure computation of the hash is not mandatory, because
malicious code can be injected into the smart contract by the compiler
already.

Deploy transaction returns a `CODE ID` which we use to instantiate the actual
smart contract next.

```ledger
|  Review Contract > | < Code ID (1/1) > | < ParaTime ID (1/1) > |  <     Fee     > | <  Gas limit  > | <             > | <               |
|   Instantiation    |     <CODE ID>     |     <RUNTIME ID>      |   <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|                    |                   |                       |   ROSE           |                 |                 |                 |
```

When the contract is deployed its `INSTANCE ID` is obtained.

[Network parameters]: https://docs.oasis.dev/general/oasis-network/network-parameters

### Executing smart contract transaction on Cipher

Oasis Ledger App should show details of the Cipher transaction to the user,
when this is possible.

```ledger
|  Review Contract > | <   Amount    > | < Instance ID (1/1) > | < Function (1/1) > | < Argument 1 (1/1) | < Argument 2 (1/1) | ... | < ParaTime ID (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <               |
|       Call         |  <AMOUNT IN     |     <INSTANCE ID>     | <SMART CONTRACT    |  <ARGUMENT VALUE>  |  <ARGUMENT VALUE>  |     |     <RUNTIME ID>      |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|                    |   ROSE> ROSE    |                       |  FUNCTION NAME>    |                    |                    |     |                       |  ROSE           |                 |                 |                 |
```

Where `SMART CONTRACT FUNCTION NAME` is a function name without information on
argument count, types and names.

Function arguments are sent in CBOR format to Ledger. To represent those to the
user, there should be one Argument screen `Argument 1`, `Argument 2`, ...,
`Argument N` for each function argument. `ARGUMENT VALUE` on each screen
represents standard JSON values:
- string
- number (integer, float)
- map (object)
- array
- boolean
- null

Strings are wrapped inside double quotes `""` and any double quotes included in
the string are escaped with a backslash `\"`.

Boolean and null values are rendered as a single-page screens. For strings and
numbers the screen can contain multiple pages to accommodate complete content.

If the argument is of type array or a map, it is shown in a JSON form
including the surrounding `{}` or `[]` symbols. If the representation cannot
fit a single page, the content is trimmed, ellipsis `…` is appended at the end
and the screen **becomes confirmable**. If the user double-clicks it,
subscreens describing that given argument `n` of a map or an array are shown.
Specifically, there is one subscreen for each item of the map or an array
titled `Argument n.1`, `Argument n.2`, ..., `Argument n.N`.

```ledger
|   Argument 1.1 (1/1) > | < Argument 1.2 (1/1) | < Argument 1.3 (1/1) | ... | <          |
|    <ARGUMENT VALUE>    |   <ARGUMENT VALUE>   |   <ARGUMENT VALUE>   |     |    BACK    |
|                        |                      |                      |     |            |
```

Each array item is rendered as `ARGUMENT VALUE`. Map item is shown in form
`KEY: ARGUMENT VALUE`. `KEY` is a string and the screen must have enough
pages to accommodate it. `ARGUMENT VALUE` is treated the same as above
including the confirmability of the screen, if it is a map or an array and
cannot fit one page.

The recursive approach described above allows user to browse siblings in the
tree of arguments with ⬅️ and ➡️ buttons, visit a child by double-clicking and
returning to a parent node by confirming the BACK screen.

The maximum length of the array, the depth of a map, as well as a separate
string length must be reasonably limited. If the limit is reached, Ledger
displays an error on the initial screen. Then, if the user still wants to sign
such a transaction, they need to enable **Blind signing** in the Settings menu.
The following screens are shown when blind-signing a transaction.

```ledger
|  Review Contract > | < BLIND > | <   Amount    > | < Instance ID (1/1) > | < ParaTime ID (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <               |
|       Call         |  SIGNING! |  <AMOUNT IN     |     <INSTANCE ID>     |     <RUNTIME ID>      |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|                    |           |   ROSE> ROSE    |                       |                       |  ROSE           |                 |                 |                 |
```

### Example

To upload, instantiate and call the [hello world example](https://docs.oasis.dev/oasis-sdk/contract/hello-world#deploying-the-contract)
on testnet Cipher the Ledger screens would be the following:

```ledger
| Review Contract > | < Contract hash (1/2) > | < Contract hash (2/2) > | < ParaTime ID > | <    Fee    > | <  Gas limit  > | <             > | <               |
|     Upload        | a8fc73270dff2bbd2bc7a15 | 6b69847e90b782e781      |     Cipher      |   0.0 ROSE    |     182343      |     APPROVE     |      REJECT     |
|                   | cf4c1ec6375e6deefc5f2d5 |                         |    (Testnet)    |               |                 |                 |                 |
```

```ledger
|  Review Contract > | < Code ID > | < ParaTime ID > |  <    Fee    > | < Gas limit  > | <             > | <               |
|   Instantiation    |      3      |     Cipher      |    0.0 ROSE    |     25202      |     APPROVE     |      REJECT     |
|                    |             |    (Testnet)    |                |                |                 |                 |
```

```ledger
| Review Contract > | <   Amount    > | < Instance ID > | < Function > | < Argument 1 > | < ParaTime ID > | <     Fee     > | <  Gas limit  > | <            > | <              |
|      Call         |    0.0 ROSE     |       2         |   say_hello  |  {"who":"me"}  |     Cipher      |     0.0 ROSE    |      32968      |    APPROVE     |     REJECT     |
|                   |                 |                 |              |                |    (Testnet)    |                 |                 |                |                |
```

## Open Questions

1. The proposed UI only shows ParaTime ID and omits the Genesis root hash for
   ParaTime transactions. Is this sufficient security-wise? Is there a threat
   that someone registers a ParaTime with the same ID on a different network
   and consumes users' tokens this way?
   1. => NO, genesis should be shown
2. (Ledger) Currently, we never show information where the tokens were
   sent/deposited/withdrawn **from**. This is the same in Ethereum Ledger App.
   Isn't there a security issue, that the app could pick a wrong account ID to
   send the tokens and the user wouldn't know it?
   Should we add:
   - the from address for all Oasis transactions,
   - the originating genesis hash and ParaTime ID for all cross-chain transactions?
3. (Ledger) ParaTime Deposit requires two transactions (allowance + deposit).
   Could we simplify the UI on Ledger by batching them and signing them both in
   a single user intervention? Or is double-click mandatory to access the Ledger's
   private key each time?
4. (Ledger) Would there be any issues with Ledger when parsing CBOR to
   recursively build a UI for browsing the function arguments?

TODO: Hide Gas limit info, because it's not relevant for signing.

TODO: Ledger should store denomination symbol and number of decimals for common
ParaTimes (Emerald, Cipher), so it shows the correct fee and amount values.
What to do, if the base unit is not known?

TODO: See how transaction is defined
https://github.com/oasisprotocol/oasis-sdk/blob/main/runtime-sdk/src/types/transaction.rs
Document it in oasis sdk docs.
