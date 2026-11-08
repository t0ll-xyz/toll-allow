# toll-allow

Solidity helpers to require a **Toll ALLOW ticket** before a sensitive call on Robinhood Chain (4663).

Toll checks a transaction off-chain (`check_tx`, `/api/tx/check`). When the answer is ALLOW (or a WARN with no high or critical warning) and you ask for a ticket, Toll signs a compact EIP-712 verdict bound to one exact call, one account, an optional consumer contract and a 60 second window. A contract that inherits `TollAllowConsumer` accepts the call only with a valid, unused ticket.

A BLOCK is never signed. A ticket is never issued without `from`, or for a transaction carrying an EIP-7702 authorization list.

## Toll's ALLOW signer

Toll's ALLOW signer on Robinhood Chain (4663):

```
0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba
```

Pin it as `tollSigner` in your consumer, or pin a `TollSignerSet` you control that includes it (then you can add or
remove keys without redeploying). Tickets signed by any other key do not verify. How to get a ticket and use it:
https://t0ll.xyz/agents/allow

## Contracts

| File | What |
| --- | --- |
| `src/TollAllow.sol` | `Ticket` struct + library: `hash`, `verify` (EOA or ERC-1271 signer), `callSubject`, `swapSubject`, `splitSuffix`, `encodeSuffix` |
| `src/TollAllowConsumer.sol` | abstract: `used[keccak256(signer, nonce)]`, immutable `tollSigner`, `_consume(...)` reverts on any failed check, emits `TicketConsumed` |
| `src/TollAllowEnforcer.sol` | MetaMask Delegation Framework caveat enforcer: each redemption needs a ticket for the exact call (see below) |
| `src/TollSignerSet.sol` | ERC-1271 signer over a set of keys; the owner (Toll's Safe, two-step ownership) adds and removes keys, so keys rotate without redeploying consumers |

## The ticket

```solidity
struct Ticket {
    uint8   scope;      // 1 CALL, 2 V4SWAP, 3 TXHASH (off-chain only)
    uint8   verdict;    // 0 ALLOW, 1 WARN
    address account;    // who makes the call
    address consumer;   // contract allowed to consume it, 0 = any
    bytes32 subject;    // what it is bound to
    uint64  validAfter; // block.timestamp window
    uint64  validUntil;
    bytes32 nonce;      // single use
    bytes32 reportHash; // links to the facts-only ERC-8481 report
}
```

EIP-712 domain: `EIP712Domain(string name,string version,uint256 chainId)` with `name = "Toll Allow"`, `version = "1"`, `chainId = 4663`. There is no `verifyingContract`; the `consumer` field binds a ticket to a contract instead.

Subjects:

- scope 1 CALL: `keccak256(abi.encode(target, value, keccak256(data)))`
- scope 2 V4SWAP: `keccak256(abi.encode(poolId, zeroForOne, amountSpecified, sqrtPriceLimitX96))`
- scope 3 TXHASH: off-chain (RPC, audit). `_consume` rejects it.

Calldata suffix (for routers that cannot take an extra argument):

```
body ‖ abi.encode(ticket, sig) ‖ uint32 len ‖ bytes4(keccak256("TollAllow.v1"))   // magic 0x900bc3e1
```

`len` is the byte length of `abi.encode(ticket, sig)`. The subject is computed over `body` only.

## Checks in `_consume`

In order: scope is 1 or 2 (or the exact scope you pass), `verdict <= maxVerdict`, `account` matches, `consumer` is this contract or `address(0)`, `subject` matches, `validAfter <= block.timestamp <= validUntil`, not used, signature valid (ECDSA or ERC-1271). Then the nonce is marked used and `TicketConsumed` is emitted.

**Use `block.timestamp`.** On Arbitrum Orbit chains, Robinhood Chain included, `block.number` returns the L1 block number.

## Use it

### Router

```solidity
contract MyRouter is TollAllowConsumer {
    constructor(address tollSignerSet) TollAllowConsumer(tollSignerSet) {}

    function exec(address target, bytes calldata data) external payable {
        (bytes calldata body, Ticket memory t, bytes memory sig, bool found) = TollAllow.splitSuffix(data);
        require(found, "ticket required");
        _consume(t, sig, msg.sender, TollAllow.SCOPE_CALL, TollAllow.callSubject(target, msg.value, body), 0);
        (bool ok,) = target.call{value: msg.value}(body);
        require(ok);
    }
}
```

### Uniswap v4 hook (hookData)

Pass `abi.encode(ticket, sig)` as `hookData`. In `beforeSwap`:

```solidity
(Ticket memory t, bytes memory sig) = abi.decode(hookData, (Ticket, bytes));
bytes32 subject = TollAllow.swapSubject(
    PoolId.unwrap(key.toId()), params.zeroForOne, params.amountSpecified, params.sqrtPriceLimitX96);
_consume(t, sig, account, TollAllow.SCOPE_V4SWAP, subject, 0);
```

`sender` in a hook is the router, not the trader. Decide what `account` means for your hook (for example a router that forwards the trader in `hookData`) and ask Toll for a ticket with that account.

## MetaMask delegation caveat

`src/TollAllowEnforcer.sol` is a caveat enforcer for the
[MetaMask Delegation Framework](https://github.com/MetaMask/delegation-framework). Add it to a delegation and every
redemption must carry a fresh Toll ticket for the exact call being executed. On Robinhood Chain the framework's v1.3.0
`DelegationManager` is `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3` and `EIP7702StatelessDeleGatorImpl` is
`0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B` (their `documents/Deployments.md`). The enforcer extends their
`CaveatEnforcer`, vendored from v1.3.0 under `src/vendor/` with license headers kept (only the pragma is relaxed; see
the header of each file).

The enforcer is not deployed yet; until it is, deploy your own copy (it has no owner and no constructor arguments).

**Terms** (set by the delegator, signed into the delegation):

```solidity
abi.encode(address tollSigner, uint8 maxVerdict, uint256 valueThreshold)
// tollSigner:     0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba, or a TollSignerSet that includes it
// maxVerdict:     0 = ALLOW only, 1 = ALLOW or WARN
// valueThreshold: 0 = always need a ticket; N > 0 = plain ETH sends (empty calldata) below N wei need none
```

**Args** (set by the redeemer at redemption; `args` is not part of the delegation hash, so it can change per call):

```solidity
abi.encode(Ticket ticket, bytes signature)
```

Ask Toll for a ticket with `account` = the delegator (the account that executes), `consumer` = the enforcer address
(or `address(0)`), scope 1 CALL, and the exact `target`, `value` and `callData` of the execution.

**Checks in `beforeHook`**, in order: call type single and exec type default (batch and try modes revert
`BatchNotSupported` / `ExecTypeNotSupported`); the small plain ETH exemption above; a ticket is present
(`TicketMissing`); scope 1; `verdict <= maxVerdict`; `account == delegator`; `consumer` is the enforcer or
`address(0)`; `subject == callSubject(target, value, callData)`; `validAfter <= block.timestamp <= validUntil`; not
used; signature valid (ECDSA or ERC-1271). Then the ticket is marked used and `TicketConsumed` is emitted.

Replay: `used[keccak256(abi.encode(delegationManager, tollSigner, nonce))]`, where `delegationManager` is the hook's
caller. A ticket works once across all delegations. Because the key includes the caller, anyone who copies a pending
ticket and calls the hook directly cannot burn it for the real redemption.

**Add the caveat** (MetaMask Delegation Toolkit, TypeScript):

```ts
import { createCaveat } from "@metamask/delegation-toolkit";
import { encodeAbiParameters } from "viem";

const TOLL_ENFORCER = "0x..."; // TollAllowEnforcer on Robinhood Chain
const terms = encodeAbiParameters(
  [{ type: "address" }, { type: "uint8" }, { type: "uint256" }],
  ["0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba", 0, 0n],
);

// add it next to the framework's own caveats (allowed targets, value limits, time window)
delegation.caveats.push(createCaveat(TOLL_ENFORCER, terms));
// ...sign the delegation as usual
```

**Redeem with a ticket**: get a ticket from Toll for the exact execution, then set the caveat's `args` before
`redeemDelegations`:

```ts
const args = encodeAbiParameters(
  [
    {
      type: "tuple",
      components: [
        { name: "scope", type: "uint8" }, { name: "verdict", type: "uint8" },
        { name: "account", type: "address" }, { name: "consumer", type: "address" },
        { name: "subject", type: "bytes32" }, { name: "validAfter", type: "uint64" },
        { name: "validUntil", type: "uint64" }, { name: "nonce", type: "bytes32" },
        { name: "reportHash", type: "bytes32" },
      ],
    },
    { type: "bytes" },
  ],
  [ticket, ticketSignature],
);
signedDelegation.caveats[tollCaveatIndex].args = args;
```

**Limits**

- Single call only in v1. Batch executions revert; send one call per redemption.
- Tickets live 60 seconds and are single use, so ask for the ticket right before redeeming.
- Put the caveat on the root delegation, where the delegator is the account that executes. On a redelegation the
  `delegator` the hook sees is the intermediate account, so the `account` check would not match the executing account.
- The delegator can revoke the delegation at any time with `DelegationManager.disableDelegation`, which does not need
  Toll. If Toll is down, no new redemptions pass (except small plain ETH sends under `valueThreshold`), but the
  delegator's own account is never locked.
- A ticket is necessary, never sufficient. Keep the framework's own enforcers for targets, amounts and time.

## Gas

Measured with `forge test` (snapshot in `snapshots/`), including the external call into a minimal consumer:

| Path | Gas |
| --- | --- |
| `_consume`, EOA signer | ~69,100 |
| `_consume`, `TollSignerSet` (ERC-1271) | ~70,700 (a few thousand more when the set is cold) |
| `TollAllowEnforcer.beforeHook`, EOA signer | ~78,100 |
| `TollAllowEnforcer.beforeHook`, `TollSignerSet` (ERC-1271) | ~73,500 (runs second in the test, so the enforcer and precompile are already warm) |

Most of it is the fresh `used` slot (~22k) and the signature check.

## Trust model

- **A ticket is necessary, never sufficient.** It says Toll saw no blocking risk for this exact call when it signed. Keep your own checks: slippage, limits, access control.
- **Keep an owner bypass behind a timelock.** If Toll is down or its key is lost, users must still be able to get out. A delayed bypass keeps that path open without making the ticket optional day to day.
- **Point `tollSigner` at a `TollSignerSet`.** Toll can then rotate or revoke keys without you redeploying. Removing a key kills every unconsumed ticket it signed.
- Tickets live 60 seconds and are single use per consumer (`used[keccak256(signer, nonce)]`). Bind them to your contract (`consumer`) unless you share one `used` map on purpose.
- The domain uses `block.chainid`, so a ticket for 4663 never verifies on another chain.

## Test

```
forge install
forge test -vv
forge snapshot
```

Golden vectors (public test keys, never real keys):

- `test/vectors/allowticket-vectors.json`: written by Toll's TypeScript signer. `test_vectors_match_ts` checks the domain separator, type hash, call and swap subjects, digests and signatures byte for byte, then consumes each ticket on-chain.
- `test/vectors/allowticket-vectors.viem.json`: independent vectors built with viem, including calldata suffixes. `test_vectors_viem_suffix` also splits each suffix back into body, ticket and signature.

## Test vectors and the test key

`test/vectors/allowticket-vectors.json` is shared with Toll's server so both sides compute the same digests. Its `testSigner.privateKey` is a **test-only key derived from a public phrase**: it has never held funds and is not Toll's signer. Toll's real signer is a separate key that never leaves the server; consumers pin its address, `0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba` (or a `TollSignerSet`).

## License

MIT
