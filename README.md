# toll-allow

Solidity helpers to require a **Toll ALLOW ticket** before a sensitive call on Robinhood Chain (4663).

Toll checks a transaction off-chain (`check_tx`, `/api/tx/check`). When the answer is ALLOW (or a WARN with no high or critical warning) and you ask for a ticket, Toll signs a compact EIP-712 verdict bound to one exact call, one account, an optional consumer contract and a 60 second window. A contract that inherits `TollAllowConsumer` accepts the call only with a valid, unused ticket.

A BLOCK is never signed. A ticket is never issued without `from`, or for a transaction carrying an EIP-7702 authorization list.

## Contracts

| File | What |
| --- | --- |
| `src/TollAllow.sol` | `Ticket` struct + library: `hash`, `verify` (EOA or ERC-1271 signer), `callSubject`, `swapSubject`, `splitSuffix`, `encodeSuffix` |
| `src/TollAllowConsumer.sol` | abstract: `used[keccak256(signer, nonce)]`, immutable `tollSigner`, `_consume(...)` reverts on any failed check, emits `TicketConsumed` |
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

### Delegation caveat (args)

A caveat enforcer (for example under the MetaMask DelegationManager) can take `abi.encode(ticket, sig)` as the redeemer's `args` and, in `beforeHook`, compute `callSubject(target, value, callData)` from the execution, with `account` = the delegator. Keep one enforcer per signer so `used` is shared across all delegations.

## Gas

Measured with `forge test` (snapshot in `snapshots/`), including the external call into a minimal consumer:

| Path | Gas |
| --- | --- |
| `_consume`, EOA signer | ~69,100 |
| `_consume`, `TollSignerSet` (ERC-1271) | ~70,700 (a few thousand more when the set is cold) |

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

## License

MIT
