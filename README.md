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
| `src/TollGateHook.sol` | Uniswap v4 hook (beforeSwap only): each swap in a pool that uses it needs a scope 2 ticket for that exact swap, unless it is under an optional size threshold. Not deployed yet |
| `src/TollAssert.sol` | post-conditions in the same transaction: balance deltas within `[min, max]` since a snapshot (transient storage), allowance at most a cap. Not deployed yet |
| `script/DeployTollGateHook.s.sol` | mines a CREATE2 salt for a hook address with only the beforeSwap flag and prints it; deploying is a separate `deploy()` call |

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

Use `TollGateHook` (below), or inherit `TollAllowConsumer` in your own hook. Pass `abi.encode(ticket, sig)` as
`hookData`. In `beforeSwap`:

```solidity
(Ticket memory t, bytes memory sig) = abi.decode(hookData, (Ticket, bytes));
bytes32 subject = TollAllow.swapSubject(
    PoolId.unwrap(key.toId()), params.zeroForOne, params.amountSpecified, params.sqrtPriceLimitX96);
_consume(t, sig, account, TollAllow.SCOPE_V4SWAP, subject, 0);
```

`sender` in a hook is the router, not the trader. Decide what `account` means for your hook and ask Toll for a ticket
with that account. `TollGateHook` makes this an explicit, immutable choice (`AccountMode`).

## MetaMask delegation caveat

**Deployed on Robinhood Chain (4663):** `TollAllowEnforcer` at
[`0x6290dfc474f566b3bf612ad78e9dd3890473fdb5`](https://robinhoodchain.blockscout.com/address/0x6290dfc474f566b3bf612ad78e9dd3890473fdb5)
(tx `0x4b8aff0fac170f08bfc9891d63b65f9cc99554829efbac3ed8f1e42c29620ec3`). Source verified on
[Sourcify](https://repo.sourcify.dev/4663/0x6290dfc474f566b3bf612ad78e9dd3890473fdb5) (exact match, creation and runtime).
It has no owner and no admin: nothing about it can be changed after deployment.

`src/TollAllowEnforcer.sol` is a caveat enforcer for the
[MetaMask Delegation Framework](https://github.com/MetaMask/delegation-framework). Add it to a delegation and every
redemption must carry a fresh Toll ticket for the exact call being executed. On Robinhood Chain the framework's v1.3.0
`DelegationManager` is `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3` and `EIP7702StatelessDeleGatorImpl` is
`0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B` (their `documents/Deployments.md`). The enforcer extends their
`CaveatEnforcer`, vendored from v1.3.0 under `src/vendor/` with license headers kept (only the pragma is relaxed; see
the header of each file).

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

**Add the caveat** (MetaMask Delegation Toolkit, TypeScript). Sketch only: check the toolkit's current docs for the exact
caveat-builder call; what matters is the enforcer address and the `terms` encoding below.

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

## Uniswap v4 hook gate (TollGateHook)

**Status: not deployed yet.** Built and tested (unit tests, plus a fork test against the live Uniswap v4 PoolManager
on Robinhood Chain, `0x8366a39CC670B4001A1121B8F6A443A643e40951`).

`src/TollGateHook.sol` is a Uniswap v4 hook with one permission, `beforeSwap`. A pool opts in by naming the hook in
its `PoolKey`; from then on every swap in that pool must carry a fresh, single-use Toll ticket (scope 2 V4SWAP) for
that exact swap in `hookData`, unless the swap is under the deployment's size threshold. A pool's hook is fixed when
the pool is created, and the hook has no owner, so the gate cannot be switched off later.

**Config** (constructor, immutable; no owner, no proxy):

```solidity
constructor(
    address poolManager,       // Uniswap v4 PoolManager (Robinhood Chain: 0x8366a39CC670B4001A1121B8F6A443A643e40951)
    address tollSigner,        // 0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba, or a TollSignerSet that includes it
    uint8   maxVerdict,        // 0 = ALLOW only, 1 = ALLOW or WARN; anything higher reverts
    AccountMode accountMode,   // SENDER, ORIGIN or NONE (below)
    address thresholdCurrency, // currency the threshold is measured in; address(0) = native ETH
    uint256 threshold          // 0 = every swap needs a ticket
)
```

The constructor reverts unless the hook address has exactly the beforeSwap flag (`1 << 7`) in its lowest 14 bits.
`script/DeployTollGateHook.s.sol` mines the CREATE2 salt for the deterministic deployer
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`, present on Robinhood Chain):

```
forge script script/DeployTollGateHook.s.sol --rpc-url rh                    # mine and print, sends nothing
forge script script/DeployTollGateHook.s.sol --sig "deploy()" --rpc-url rh --broadcast --account <yours>
```

Config comes from env (`POOL_MANAGER`, `TOLL_SIGNER`, `MAX_VERDICT`, `ACCOUNT_MODE`, `THRESHOLD_CURRENCY`,
`THRESHOLD`); the defaults are the addresses above, ALLOW only, `ORIGIN`, no threshold.

**Who the trader is.** In v4, `sender` in `beforeSwap` is the contract that called `PoolManager.swap` (usually a
router), not the trader. The hook cannot see the trader on its own, so each deployment picks one `AccountMode`:

| Mode | `ticket.account` must equal | Fits | Does not fit |
| --- | --- | --- | --- |
| `SENDER` | `sender` (the caller of `PoolManager.swap`) | an agent smart account or per-user router that calls the PoolManager itself | shared public routers: it would bind the router, which binds nobody |
| `ORIGIN` | `tx.origin` | EOA traders through any router (Universal Router, V4Router) | ERC-4337 (`tx.origin` is the bundler), relayed or sponsored transactions |
| `NONE` | not checked | any caller | anyone holding the ticket can use it once; a copy from the mempool can be used first for the same swap (with the copier's funds), which uses up the ticket |

In every mode the ticket also binds the pool (the poolId includes the hook address, so no other pool or hook
matches), the direction, the exact `amountSpecified`, the `sqrtPriceLimitX96`, a 60 second window and one use.

**Threshold.** If `threshold > 0`, a swap whose specified amount is in `thresholdCurrency` and whose absolute value
is below `threshold` needs no ticket. The specified currency is the input for exact-in (`amountSpecified < 0`) and the
output for exact-out (`amountSpecified > 0`). Swaps specified in the other currency always need a ticket.

**Checks in `beforeSwap`**, in order: caller is the PoolManager (`NotPoolManager`, so nobody can burn a copied ticket
by calling the hook directly); threshold exemption; ticket present (`TicketMissing`); scope 2; `verdict <=
maxVerdict`; `account` per mode; `consumer` is the hook or `address(0)`; `subject == swapSubject(poolId, zeroForOne,
amountSpecified, sqrtPriceLimitX96)`; `validAfter <= block.timestamp <= validUntil`; not used; signature valid (ECDSA
or ERC-1271). Then `used[keccak256(tollSigner, nonce)]` is set and `TicketConsumed` is emitted. Through the
PoolManager a failed check arrives wrapped in v4's `WrappedError(hook, beforeSwap.selector, reason, HookCallFailed())`.

**Ask Toll for** a scope 2 ticket with `consumer` = the hook, `account` per the mode, and `subject` =
`hook.subjectFor(key, params)` (or compute it: `keccak256(abi.encode(poolId, zeroForOne, amountSpecified,
sqrtPriceLimitX96))`). Then pass it as the swap's `hookData`:

```ts
import { encodeAbiParameters } from "viem";

// TICKET_COMPONENTS: the same Ticket tuple as in the delegation `args` example above
const hookData = encodeAbiParameters(
  [{ type: "tuple", components: TICKET_COMPONENTS }, { type: "bytes" }],
  [ticket, ticketSignature],
);
// V4Router / Universal Router: put it in ExactInputSingleParams.hookData for this pool
```

**What a ticket proves here, and what it does not**

- It proves Toll's signer saw no blocking risk for this exact swap (pool, direction, amount, price limit) when it
  signed, within the last 60 seconds, and, in `SENDER` or `ORIGIN` mode, for this account.
- It does not bind where the output goes (the router decides the recipient), the price beyond `sqrtPriceLimitX96`,
  or anything else in the transaction. It does not gate other pools in a multi-hop route, or liquidity changes.
- The amount must match exactly. Routers that work out the amount at execution time (open deltas, contract balance,
  the middle hops of a route) will not match a ticket signed in advance.
- Quoters and aggregators simulate swaps without your ticket, so they fail on gated pools above the threshold.
- If Toll is down, swaps above the threshold in gated pools revert until it is back. Liquidity can still be removed:
  the hook does not gate `modifyLiquidity`.
- A ticket is necessary, never sufficient. Keep slippage limits and the router's own checks.

## Post-trade checks (TollAssert)

**Status: not deployed yet.** It has no owner and no constructor arguments; one deployment can serve everyone.

`src/TollAssert.sol` checks, at the end of a transaction, that a trade did what the pre-sign check said and that
nothing else listed left the wallet. Toll's `check_tx` simulates the transaction and returns the balance change of
each token; turn those into bounds (widened by your slippage) and append the checks after the trade in the same
batch. If any check fails the whole transaction reverts, trade included.

```solidity
struct Expectation { address token; int256 minDelta; int256 maxDelta; } // token address(0) = native ETH; bounds inclusive

snapshot(address[] tokens)                          // account = msg.sender
snapshot(address account, address[] tokens)
assertBalances(Expectation[] expect)                // account = msg.sender
assertBalances(address account, Expectation[] expect)
assertNoNewApproval(address token, address spender)              // allowance(msg.sender, spender) must be 0
assertNoNewApproval(address token, address spender, uint256 cap) // ... at most cap
assertAllowanceAtMost(address owner, address token, address spender, uint256 cap)
```

A smart account batch (ERC-7579 `execute`, a Safe MultiSend, or similar) for a simulated -100 USDG, +2,000 MEME at
1% slippage (pseudo-code):

```solidity
tokens = [USDG, MEME, OTHER];                      // every token that should not move unexpectedly
e = [
    Expectation(USDG, -100e6, -100e6),             // exactly what the simulation said
    Expectation(MEME, 1_980e18, type(int256).max), // at least 99% of the simulated amount
    Expectation(OTHER, 0, 0)                       // nothing else leaves
];
// one batch, in this order, all from the account:
//   TollAssert.snapshot(tokens)
//   Router.swap(...)
//   TollAssert.assertBalances(e)
//   TollAssert.assertNoNewApproval(USDG, Router)  // no approval left behind
```

Errors: `BalanceOutOfRange(token, delta, minDelta, maxDelta)`, `SnapshotMissing(account, token)`,
`SnapshotExists(account, token)`, `AllowanceAboveCap(token, spender, allowance, cap)`, `BadRange`, `ReadFailed(token)`
(not a contract, or `balanceOf` / `allowance` failed), `BalanceTooLarge`.

**How it works and its limits**

- Snapshots live in transient storage (EIP-1153 `TSTORE`/`TLOAD`). They vanish when the transaction ends, so nothing
  is kept between transactions. Robinhood Chain executes `TSTORE`/`TLOAD` (checked with an `eth_call` on 4663), and
  the repo builds for `cancun`.
- A snapshot is keyed by `(msg.sender, account, token)`. Only the caller that took it can assert against it, and a
  second snapshot for the same key reverts until an assert clears it. Call TollAssert from the account itself or a
  caller only you control: through a public multicall, a contract called during the trade can act as the same
  `msg.sender`, assert with wide bounds (which clears your snapshot) and snapshot again after moving funds.
- Only the tokens you list are checked. List every token the simulation shows and every token you hold that a bad
  call could take.
- Approvals: the check covers ERC-20 `allowance` only. NFT `setApprovalForAll` and Permit2 allowances are not
  checked.
- Gas is paid before execution, so it does not change the native balance between snapshot and assert.
  Fee-on-transfer and rebasing tokens move by more or less than the nominal amount; set the bounds for that.

## Gas

Measured with `forge test` (snapshot in `snapshots/`), including the external call into a minimal consumer:

| Path | Gas |
| --- | --- |
| `_consume`, EOA signer | ~69,100 |
| `_consume`, `TollSignerSet` (ERC-1271) | ~70,700 (a few thousand more when the set is cold) |
| `TollAllowEnforcer.beforeHook`, EOA signer | ~78,100 |
| `TollAllowEnforcer.beforeHook`, `TollSignerSet` (ERC-1271) | ~73,500 (runs second in the test, so the enforcer and precompile are already warm) |
| `TollGateHook.beforeSwap`, EOA signer | ~68,100 |
| `TollGateHook.beforeSwap`, `TollSignerSet` (ERC-1271) | ~69,900 (runs second in the test, precompile warm) |
| `TollGateHook.beforeSwap`, below the threshold (no ticket) | ~26,400 |
| `TollAssert` snapshot + assertBalances, 2 tokens, inside a smart account batch | ~81,100 (143,800 for snapshot + swap + assert, minus 62,700 for the same swap alone) |

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
TOLL_FORK=1 forge test --match-contract TollGateHookForkTest   # TollGateHook against the live v4 PoolManager (needs the rh RPC)
```

Golden vectors (public test keys, never real keys):

- `test/vectors/allowticket-vectors.json`: written by Toll's TypeScript signer. `test_vectors_match_ts` checks the domain separator, type hash, call and swap subjects, digests and signatures byte for byte, then consumes each ticket on-chain.
- `test/vectors/allowticket-vectors.viem.json`: independent vectors built with viem, including calldata suffixes. `test_vectors_viem_suffix` also splits each suffix back into body, ticket and signature.

## Test vectors and the test key

`test/vectors/allowticket-vectors.json` is shared with Toll's server so both sides compute the same digests. Its `testSigner.privateKey` is a **test-only key derived from a public phrase**: it has never held funds and is not Toll's signer. Toll's real signer is a separate key that never leaves the server; consumers pin its address, `0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba` (or a `TollSignerSet`).

## License

MIT
