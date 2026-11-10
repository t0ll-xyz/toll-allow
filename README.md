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
| `src/TollGateHook.sol` | Uniswap v4 hook (beforeSwap only): each swap in a pool that uses it needs a scope 2 ticket for that exact swap, unless it is under an optional size threshold. Deployed: `0x08324e1aDeC7a4047D2DA692d02B891179B14080` |
| `src/TollAllowModule.sol` | ERC-7579 hook module for modular smart accounts: each call the account executes needs a scope 1 ticket for that exact call, unless the account exempted it at install. Deployed: `0xa86955745ff2caffed94ee3c363fd86091a972fd` |
| `src/TollAssert.sol` | post-conditions in the same transaction: balance deltas within `[min, max]` since a snapshot (transient storage), allowance at most a cap. Deployed: `0x7623a849b2c5fa6f6765163bf4bf66aef16fe1b1` |
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

**Deployed on Robinhood Chain (4663):** [`0x08324e1aDeC7a4047D2DA692d02B891179B14080`](https://robinhoodchain.blockscout.com/address/0x08324e1aDeC7a4047D2DA692d02B891179B14080) (tx `0x9240dc7e965b1dd2a6dfec1c47ff6704a053aee9a59b72624d887bcf0314aae8`,
through the CREATE2 deployer, salt `0x…90df`). Source verified on [Sourcify](https://repo.sourcify.dev/4663/0x08324e1aDeC7a4047D2DA692d02B891179B14080) (exact match, creation and runtime).
This deployment: PoolManager `0x8366a39CC670B4001A1121B8F6A443A643e40951`, signer Toll's ALLOW key
`0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba`, ALLOW only (`maxVerdict` 0), `AccountMode.ORIGIN`, no size threshold
(every swap needs a ticket). No owner, no admin. Built and tested (unit tests, plus a fork test against the live
Uniswap v4 PoolManager on Robinhood Chain). Other settings = deploy your own with the script below.

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

## ERC-7579 module (TollAllowModule)

**Deployed on Robinhood Chain (4663):** [`0xa86955745ff2caffed94ee3c363fd86091a972fd`](https://robinhoodchain.blockscout.com/address/0xa86955745ff2caffed94ee3c363fd86091a972fd) (tx `0xdb34f47f027d2d36411869224c11a40e025f8cbda561ebaddec68b6247b959ed`).
Source verified on [Sourcify](https://repo.sourcify.dev/4663/0xa86955745ff2caffed94ee3c363fd86091a972fd) (exact match, creation and runtime). Built and tested against a minimal ERC-7579 account in `test/TollAllowModule.t.sol`
(shaped like the reference implementation: the account calls `preCheck(msg.sender, msg.value, msg.data)` before it
executes and `postCheck` after). No owner, no proxy, no admin; one deployment can serve every account.

`src/TollAllowModule.sol` is an ERC-7579 **hook** module (module type 4). Install it on a modular smart account and
every call the account executes must carry a fresh, single-use Toll ticket (scope 1 CALL) for that exact call.

**Why a hook.** The account runs its hook around every execution, whoever asked for it: a userOp signed by any
validator, an executor module (`executeFromExecutor`), or the owner calling `execute` directly. A validator (type 1)
only sees userOps, and an executor (type 2) only gates calls that go through itself, so either would leave other
paths open.

**Install** (`installModule(4, module, initData)`):

```solidity
initData = abi.encode(TollAllowModule.InstallData({
    signer:            0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba, // or a TollSignerSet that includes it (ERC-1271)
    maxVerdict:        0,                // 0 = ALLOW only, 1 = ALLOW or WARN; higher reverts
    valueThreshold:    0,                // 0 = off; N > 0 = plain ETH sends (empty calldata) below N wei need no ticket
    allowDelegatecall: false,            // true = DELEGATECALL allowed, but only to skipTargets (never ticketed)
    skipTargets:       new address[](0)  // targets that need no ticket (any value, any calldata)
}));
```

`onUninstall` deletes the config and retires the allowlist in constant gas (a per-account epoch is bumped), so
uninstalling can never run out of gas and a later install starts clean.

**Where the ticket travels.** Appended to the account's own calldata, after the ABI-encoded arguments of `execute`:

```
execute(mode, executionCalldata) ‖ abi.encode(ticket, sig)       ‖ uint32 len ‖ 0x900bc3e1   // one ticket (TollAllow.encodeSuffix)
execute(mode, executionCalldata) ‖ abi.encode(tickets[], sigs[]) ‖ uint32 len ‖ 0x99b190bc   // several: bytes4(keccak256("TollAllow.batch.v1"))
```

The account's ABI decoder ignores bytes past its arguments, so nothing is stripped and no target ever sees the
ticket. The hook gets the full `msg.data`, splits the trailer off, and decodes the executions from the rest with the
same `ExecutionLib` the account uses. Every offset must stay inside the part before the trailer, so the trailer can
never be read as an execution. For a userOp, put the trailer at the end of `userOp.callData` before signing the userOp
(get the ticket first; it lives 60 seconds). `encodeBatchSuffix(tickets, sigs)` builds the batch trailer.

**One ticket per call.** Single and batch modes are handled. In a batch, each execution that is not exempt needs its
own ticket with `subject = keccak256(abi.encode(target, value, keccak256(callData)))`, the same subject Toll signs for
a single transaction, so no new ticket type is needed. Tickets are matched to the non-exempt executions in order.
A missing ticket (`TicketMissing(executionIndex)`), a ticket for another call (`TicketSubject`) or a leftover ticket
(`TicketsLeftOver`) reverts the whole execution. `subjectsFor(account, mode, executionCalldata)` lists the subjects to
ask Toll for, in order.

**Ask Toll for** scope 1 tickets with `account` = the smart account, `consumer` = the module address (or
`address(0)`), and the exact `target`, `value` and `callData` of each execution.

**Checks in `preCheck`**, in order:

1. the calling account has the module installed (`NotInitialized`);
2. the trailer, if present, is well formed (`TicketSuffixMalformed`);
3. the call: `execute` and `executeFromExecutor` are checked; `installModule` and `uninstallModule` pass without a
   ticket; anything else the account routes through the hook (`executeUserOp`, fallback handlers, vendor functions)
   reverts `UnsupportedCall`, so it is refused rather than let through unchecked;
4. the mode: default mode selector only (a vendor mode could lay out executions differently,
   `ModeSelectorNotSupported`), exec type default or try (`ExecTypeNotSupported`), call type single, batch or
   delegatecall (`CallTypeNotSupported`);
5. delegatecall: only if `allowDelegatecall` and the target is in `skipTargets` (`DelegatecallNotAllowed`); a scope 1
   ticket describes a call, never a delegatecall, so no ticket can unlock one;
6. per execution: exempt if `valueThreshold > 0`, `value < valueThreshold` and the calldata is empty, or if the target
   is in `skipTargets`; otherwise the next ticket must pass: scope 1, `verdict <= maxVerdict`, `account ==` the
   account, `consumer` is the module or `address(0)`, subject, `validAfter <= block.timestamp <= validUntil`, not used,
   signature by the account's signer (ECDSA or ERC-1271). Then `used[keccak256(abi.encode(signer, nonce))]` is set and
   `TicketConsumed` is emitted;
7. every ticket in the trailer was used.

`postCheck` does nothing. With exec type try, a ticket is used up even if its call then fails.

**Trust model: what binds and what does not**

- Binds: the account (`msg.sender` of `preCheck`), the exact target, value and calldata of each call, this module
  (or any module, with `consumer = 0`), a 60 second window and one use.
- Replay: one `used` map for every account on this deployment, keyed by `(signer, nonce)`. A ticket names its
  account, so nobody can burn another account's ticket by calling `preCheck` directly (an uninstalled caller gets
  `NotInitialized`, any other account gets `TicketAccount`).
- Does not bind: the trailer itself is not covered by the subject (it carries the ticket). Gas, the order of other
  executions in the batch, and anything outside the account's `execute` are not bound. Exempt calls (allowlisted
  targets, small plain ETH sends) are not checked at all; an allowlisted target gets any calldata and any value, so
  never allowlist the account itself, a token you hold, or a router.
- The account's own management calls are not gated. `installModule` / `uninstallModule` pass, so whoever controls the
  account's root validator can remove the module at any time. That is the exit if Toll is down or its key is lost,
  and it also means the gate only holds against keys that cannot reach those calls: give an agent a session key or
  executor scoped to `execute`, and keep the root key with the owner.
- Accounts differ in what they pass as `msgData`. The module expects the account's calldata for `execute` /
  `executeFromExecutor` (as the reference implementation does). An account that wraps userOps in `executeUserOp` and
  runs the hook around that wrapper is refused with `UnsupportedCall`, not silently let through; check your account
  before relying on the module.
- A ticket is necessary, never sufficient. Keep the account's own policies (spending limits, target scopes, time
  windows).

## Post-trade checks (TollAssert)

**Deployed on Robinhood Chain (4663):** [`0x7623a849b2c5fa6f6765163bf4bf66aef16fe1b1`](https://robinhoodchain.blockscout.com/address/0x7623a849b2c5fa6f6765163bf4bf66aef16fe1b1) (tx `0x557990239e4c61d5a077eb914b2bbe403f74131d3072947942bf55434d893992`).
Source verified on [Sourcify](https://repo.sourcify.dev/4663/0x7623a849b2c5fa6f6765163bf4bf66aef16fe1b1) (exact match, creation and runtime). It has no owner and no constructor arguments; one
deployment serves everyone.

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
| `TollAllowModule.preCheck`, one call, EOA signer | ~80,500 |
| `TollAllowModule.preCheck`, one call, `TollSignerSet` (ERC-1271) | ~84,400 (separate test, set and precompile cold) |
| `TollAllowModule.preCheck`, batch of 2 calls, 2 tickets, EOA signer | ~129,300 (runs after the single call in the same test) |
| `TollAllowModule.preCheck`, allowlisted target (no ticket) | ~38,600 |
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
