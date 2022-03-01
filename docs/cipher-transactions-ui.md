# Design doc: UI for signing Cipher transactions

This documents proposes UI shown on the Ledger for:
1. signing deposit/withdrawal ROSE to/from ParaTime
2. deploying smart contracts on Cipher
3. executing smart contract transaction on Cipher

## Signing deposit/withdrawal ROSE to/from ParaTime

The UI takes the existing interface of the regular ROSE transfers with smaller
tweaks.

### Deposit

Deposit is always performed to `oasis1` account on ParaTime but the UI must
also support showing Ethereum's `0x` address. In this case, the `0x` address
is submitted to Ledger and it needs to perform translation to `oasis1` address
in order to sign the transaction(s).

```ledger
     Type     > | <   To (1/1)  > | <   Amount    > | <     Fee     > | <  Gas limit  > | < ParaTime ID (1/1) > | <             > | <             > |
   Deposit      | <OASIS1 OR 0x   | <AMOUNT IN      |  <FEE IN ROSE>  |   <GAS LIMIT>   |     <RUNTIME ID>      |     APPROVE     |      REJECT     |
                |  ADDRESS>       |  ROSE> ROSE     |  ROSE           |                 |                       |                 |                 |
```

### Withdrawal

Withdrawal is always performed to `oasis1` address, but can be signed with
either `ECDSA` ("Ethereum") or `ed25519` key. This detail is hidden from the
user, but the signing account ID is sent to the Ledger.

```ledger
     Type     > | <    To (1/1)  > | <   Amount    > | <     Fee     > | <  Gas limit  > | < Genesis Hash (1/1) > | <             > | <             > |
   Withdraw     | <OASIS1 ADDRESS> |  <AMOUNT IN     |  <FEE IN ROSE>  |   <GAS LIMIT>   |     <GENESIS HASH>     |     APPROVE     |      REJECT     |
                |                  |   ROSE> ROSE    |  ROSE           |                 |                        |                 |                 |
```

## Deploying smart contracts on Cipher

```ledger
  Review Smart > | < Genesis Hash (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <             > |
    Contract     |     <GENESIS HASH>     |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
     Upload      |                        |  ROSE           |                 |                 |                 |
```

```ledger
  Review Smart > | < Code ID (1/1) > | < Genesis Hash (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <             > |
    Contract     |    <CODE ID>      |     <GENESIS HASH>     |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
 Instantiation   |                   |                        |  ROSE           |                 |                 |                 |
```

## Executing smart contract transaction on Cipher

In contrast to blind signing (as is the case when using Ledger with Metamask
to sign Ethereum's smart contract calls), a complete Cipher transaction is sent
to Ledger which decodes it and shows detailed information to the user.

```ledger
  Review Smart > | <   Amount    > | < Address (1/1) > | < Function (1/1) > | < Argument 1 (1/1) | < Argument 2 (1/1) | ... | < Genesis Hash (1/1) > | <     Fee     > | <  Gas limit  > | <             > | <             > |
 Contract Call   |  <AMOUNT IN     |   <INSTANCE ID>   | <SMART CONTRACT    |  <ARGUMENT VALUE>  |  <ARGUMENT VALUE>  |     |     <GENESIS HASH>     |  <FEE IN ROSE>  |   <GAS LIMIT>   |     APPROVE     |      REJECT     |
                 |   ROSE> ROSE    |                   |  FUNCTION NAME>    |                    |                    |     |                        |  ROSE           |                 |                 |                 |
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
< Argument 1.1 (1/1) > | < Argument 1.2 (1/1) | < Argument 1.3 (1/1) | ... | <        > |
   <ARGUMENT VALUE>    |   <ARGUMENT VALUE>   |   <ARGUMENT VALUE>   |     |    BACK    |
                       |                      |                      |     |            |
```

This recursive approach describes a complete tree of arguments up to some non-
trivial depth.

### Example

To deploy and execute the [hello world example](https://docs.oasis.dev/oasis-sdk/contract/hello-world#deploying-the-contract)
the Ledger screens would be the following:

```ledger

```

```ledger
  Review Smart > | < Address (1/2) > | < Address (2/2) > | < Funciton (1/1) > | < Argument 1 > | < Genesis Hash (1/2) > | < Genesis Hash (2/2) > | <     Fee     > | <  Gas limit  > | <            > | <            > |
 Contract Call   | oasis1ag9Egi49Fas | ebfasg            |     say_hello      |  {"who":"me"}  | c672b8d1ef56ed28ab87c3 | 737498d0c01ecef0967a   |    0.25 ROSE    |   3000000000    |    APPROVE     |     REJECT     |
                 | asoig9EXGIAeg9ieg |                   |                    |                | 622c5114069bdd3ad7b8f9 |                        |                 |                 |                |                |
```
