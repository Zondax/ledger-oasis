# Design doc: UI for signing ParaTime transactions

This document proposes UI on the Ledger devices for:
1. signing deposit/withdrawal ROSE transaction to/from ParaTime
2. deploying smart contracts on Cipher
3. executing smart contract transaction on Cipher

## Signing deposit/withdrawal ROSE to/from ParaTime

The UI behaves similar to the existing interface for regular ROSE transfers
with few additions.

### Deposit

Deposit operation consists of two transactions: the allowance transaction which
permits the ParaTime to move the tokens from the user's account to the ParaTime
address; and the actual deposit transaction.

```ledger
|     Type     > | <   To (1/1)   > | <   Amount    > | <     Fee     > | <  Gas limit  > | < Genesis Hash (1/1) > | <             > | <               |
|   Allowance    | <RUNTIME OASIS1  |  <AMOUNT IN     |  <FEE IN ROSE>  |   <GAS LIMIT>   |     <GENESIS HASH>     |     APPROVE     |      REJECT     |
|                |    ADDRESS>      |   ROSE> ROSE    |  ROSE           |                 |                        |                 |                 |
```

The deposit transaction is always performed to `oasis1` account on the
ParaTime. However, because we also run an EVM-compatible ParaTime, the ethereum-
style `0x`addresses are common there. To help dApps developers to overcome this,
we use a [mapping function] from `0x` to the corresponding `oasis1` address.
This way, the end user can generate their address with an ECDSA keypair and all
the apps will show their Ethereum's address. In the background however, the
tokens are always transferred to the corresponding `oasis1` address. Ledger
should also take a similar approach and use the `0x` address as a base and show
it to the user, but then perform a translation to `oasis1` address in the
background in order to sign the transaction(s).

```ledger
|     Type     > | <   To (1/1)  > | <   Amount    > | < ParaTime ID (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <               |
|   Deposit      | <OASIS1 OR 0x   | <AMOUNT IN      |     <RUNTIME ID>      |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|                |  ADDRESS>       |  ROSE> ROSE     |                       |  ROSE           |                 |                 |                 |
```

[mapping function]: https://github.com/oasisprotocol/oasis-sdk/blob/e566b326ab1c34f3d811b50f96c53c3a79a91826/client-sdk/go/types/address.go#L125-L149
### Withdrawal

Withdrawal is always performed to `oasis1` address, but **can be signed with
either `ECDSA` ("Ethereum") or `ed25519` key!**

```ledger
|     Type     > | <    To (1/1)  > | <   Amount    > | <     Fee     > | <  Gas limit  > | < Genesis Hash (1/1) > | <             > | <               |
|   Withdraw     | <OASIS1 ADDRESS> |  <AMOUNT IN     |  <FEE IN ROSE>  |   <GAS LIMIT>   |     <GENESIS HASH>     |     APPROVE     |      REJECT     |
|                |                  |   ROSE> ROSE    |  ROSE           |                 |                        |                 |                 |
```

### TODO: Example

## Smart contract transactions on Cipher

### Deploying smart contracts on Cipher

In contrast to EVM, deploying to Cipher is a two-step process. First, the code
is uploaded:

```ledger
| Review Contract > | < Contract hash (1/1) | < ParaTime ID (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <               |
|     Upload        |    <CONTRACT HASH>    |     <RUNTIME ID>      |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|                   |                       |                       |   ROSE          |                 |                 |                 |
```

`CONTRACT HASH` is a sha256 sum of the WASM-compiled smart contract file.

The transaction returns a `CODE ID` which we use to instantiate the actual
smart contract next.

```ledger
|  Review Contract > | < Code ID (1/1) > | < ParaTime ID (1/1) > |  <     Fee     > | <  Gas limit  > | <             > | <               |
|   Instantiation    |    <CODE ID>      |     <RUNTIME ID>      |   <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|                    |                   |                       |   ROSE           |                 |                 |                 |
```

When deploying a smart contract the `INSTANCE ID` is obtained.

### Executing smart contract transaction on Cipher

In contrast to blind signing (as is the case when using Ledger with Metamask
to sign Ethereum's smart contract calls), Oasis Ledger App should take a better
approach and show the relevant details of Cipher transaction to the user.

```ledger
|  Review Contract > | <   Amount    > | < Instance ID (1/1) > | < Function (1/1) > | < Argument 1 (1/1) | < Argument 2 (1/1) | ... | < ParaTime ID (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <               |
|       Call         |  <AMOUNT IN     |     <INSTANCE ID>     | <SMART CONTRACT    |  <ARGUMENT VALUE>  |  <ARGUMENT VALUE>  |     |     <RUNTIME ID>      |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
|                    |   ROSE> ROSE    |                       |  FUNCTION NAME>    |                    |                    |     |                       |  ROSE           |                 |                 |                 |
```

Where `SMART CONTRACT FUNCTION NAME` is a function name without information on
argument count, types and names.

The argument screens consist of `Argument 1`, `Argument 2`, ..., `Argument N`
one for each function argument. `ARGUMENT VALUE` in each argument screen
represents standard JSON values:
- string
- number (integer, float)
- map (object)
- array
- boolean
- null

For strings and numbers the screen can have multiple pages, if needed.

If the value is of type array or a map, it is shown in its JSON form including
the surrounding `{}` or `[]`symbols. No multiple pages are allowed. If a
deserialization cannot fit a single screen, the content is trimmed, ellipsis
`…` is appended at the end and the screen becomes clickable. If the user
clicks it, a subscreen describing the given argument `n` is shown where each
item of the array or a map is represented as new `Argument n.1`, `Argument n.2`,
..., `Argument n.N` screen:

```ledger
|   Argument 1.1 (1/1) > | < Argument 1.2 (1/1) | < Argument 1.3 (1/1) | ... | <          |
|    <ARGUMENT VALUE>    |   <ARGUMENT VALUE>   |   <ARGUMENT VALUE>   |     |    BACK    |
|                        |                      |                      |     |            |
```

This recursive approach describes a complete tree of function arguments. The
maximum recursive depth of an array or a map can be defined to avoid out of
memory issues.

### Example

To upload, instantiate and execute the [hello world example](https://docs.oasis.dev/oasis-sdk/contract/hello-world#deploying-the-contract)
on testnet Cipher the Ledger screens would be the following:

```ledger
| Review Contract > | < Signature (1/2) > | < Signature (2/2) > | < ParaTime ID (1/2) > | < ParaTime ID (2/2) > | <    Fee    > | <  Gas limit  > | <             > | <               |
|     Upload        | MJ2XCjkj132C9YWpDUS | wE1Bg=              | 000000000000000000000 | 000000000000000000000 |   0.0 ROSE    |     182343      |     APPROVE     |      REJECT     |
|                   | QFjkCTI8bSw8bi0w9Ew |                     | 000000000000000000000 | 0                     |               |                 |                 |                 |
```

```ledger
|  Review Contract > | < Code ID > | < ParaTime ID (1/2) > | < ParaTime ID (2/2) > |  <    Fee    > | < Gas limit  > | <             > | <               |
|   Instantiation    |      3      | 000000000000000000000 | 000000000000000000000 |    0.0 ROSE    |     25202      |     APPROVE     |      REJECT     |
|                    |             | 000000000000000000000 | 0                     |                |                |                 |                 |
```

```ledger
| Review Contract > | < Instance ID > | < Funciton (1/1) > | < Argument 1 > | < ParaTime ID (1/2) > | < ParaTime ID (2/2) > | <     Fee     > | <  Gas limit  > | <            > | <              |
|      Call         |       2         |     say_hello      |  {"who":"me"}  | 000000000000000000000 | 000000000000000000000 |     0.0 ROSE    |      32968      |    APPROVE     |     REJECT     |
|                   |                 |                    |                | 000000000000000000000 | 0                     |                 |                 |                |                |
```

## Open Questions

1. The proposed UI favors ParaTime ID instead of the Genesis root hash. This
   is because the ParaTime ID is more common (e.g. on the block explorer,
   network parameters page). Is this fine?
2. The underlying transaction for making a Deposit to a ParaTime is actually of
   type `Withdraw`, because the ParaTime "withdraws" tokens from the user's
   consensus address to the ParaTime. How do we discriminate between ParaTime's
   withdraw which is actually a deposit and any other general consensus
   withdraw transactions?
3. Deposit requires two transactions (allowance + deposit). Could we unify the
   UI on Ledger to sign both transactions with a single user intervention?
