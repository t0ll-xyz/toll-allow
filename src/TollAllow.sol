// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @notice A single-use ALLOW ticket: Toll's signed verdict for one exact call.
/// @param scope      1 = CALL, 2 = V4SWAP, 3 = TXHASH (off-chain only, never consumed on-chain).
/// @param verdict    0 = ALLOW, 1 = WARN (no high/critical warning). A BLOCK is never signed.
/// @param account    The account that will make the call (the trader / smart account).
/// @param consumer   The contract that may consume the ticket, or address(0) for any consumer.
/// @param subject    What the ticket is bound to (see {TollAllow.callSubject} / {TollAllow.swapSubject}).
/// @param validAfter First second (block.timestamp) the ticket is valid.
/// @param validUntil Last second (block.timestamp) the ticket is valid.
/// @param nonce      Random per ticket; consumers mark keccak256(signer, nonce) as used.
/// @param reportHash Links to the facts-only ERC-8481 report the verdict was drawn from.
struct Ticket {
    uint8 scope;
    uint8 verdict;
    address account;
    address consumer;
    bytes32 subject;
    uint64 validAfter;
    uint64 validUntil;
    bytes32 nonce;
    bytes32 reportHash;
}

/// @title TollAllow
/// @notice Hashing, verification and calldata-suffix helpers for Toll ALLOW tickets.
/// @dev EIP-712 domain: name "Toll Allow", version "1", chainId = block.chainid (4663 on
///      Robinhood Chain), no verifyingContract. Binding to a contract is done by the
///      `consumer` field instead, so one signature format works for routers, hooks and caveats.
///
///      Time: every expiry is checked against `block.timestamp`. On Arbitrum Orbit chains
///      (Robinhood Chain included) `block.number` returns the L1 block number, so it must
///      never be used for ticket windows.
///
///      Trust: a ticket is NECESSARY, NEVER SUFFICIENT. It says Toll saw no blocking risk for
///      this exact call at signing time. The consumer must still enforce its own rules
///      (slippage, limits, access). Consumers should also keep an owner bypass behind a
///      timelock, so users are not locked out if Toll is down or its key is lost.
library TollAllow {
    uint8 internal constant SCOPE_CALL = 1;
    uint8 internal constant SCOPE_V4SWAP = 2;
    uint8 internal constant SCOPE_TXHASH = 3;

    uint8 internal constant VERDICT_ALLOW = 0;
    uint8 internal constant VERDICT_WARN = 1;

    bytes32 internal constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId)");
    bytes32 internal constant TICKET_TYPEHASH = keccak256(
        "Ticket(uint8 scope,uint8 verdict,address account,address consumer,bytes32 subject,uint64 validAfter,uint64 validUntil,bytes32 nonce,bytes32 reportHash)"
    );
    bytes32 internal constant NAME_HASH = keccak256("Toll Allow");
    bytes32 internal constant VERSION_HASH = keccak256("1");

    /// @notice Trailer magic of a ticket-carrying calldata suffix.
    bytes4 internal constant SUFFIX_MAGIC = bytes4(keccak256("TollAllow.v1"));

    function domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid));
    }

    function structHash(Ticket memory t) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TICKET_TYPEHASH,
                t.scope,
                t.verdict,
                t.account,
                t.consumer,
                t.subject,
                t.validAfter,
                t.validUntil,
                t.nonce,
                t.reportHash
            )
        );
    }

    /// @notice EIP-712 digest that Toll signs.
    function hash(Ticket memory t) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash(t)));
    }

    /// @notice Full stateless check (everything except replay, which needs storage).
    /// @dev `consumer` is checked against address(this), i.e. the contract that calls the library.
    ///      `signer` may be an EOA or an ERC-1271 contract such as {TollSignerSet}.
    function verify(
        Ticket memory t,
        bytes memory sig,
        address signer,
        address account,
        bytes32 subject,
        uint8 maxVerdict
    ) internal view returns (bool) {
        if (t.verdict > maxVerdict) return false;
        if (t.account != account) return false;
        if (t.consumer != address(0) && t.consumer != address(this)) return false;
        if (t.subject != subject) return false;
        if (block.timestamp < t.validAfter || block.timestamp > t.validUntil) return false;
        return SignatureChecker.isValidSignatureNow(signer, hash(t), sig);
    }

    /// @notice Scope 1 subject: keccak256(abi.encode(target, value, keccak256(data))).
    function callSubject(address target, uint256 value, bytes calldata data) internal pure returns (bytes32) {
        return keccak256(abi.encode(target, value, keccak256(data)));
    }

    /// @notice Same as {callSubject} for data held in memory.
    function callSubjectMem(address target, uint256 value, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encode(target, value, keccak256(data)));
    }

    /// @notice Scope 2 subject: keccak256(abi.encode(poolId, zeroForOne, amountSpecified, sqrtPriceLimitX96)).
    function swapSubject(bytes32 poolId, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(poolId, zeroForOne, amountSpecified, sqrtPriceLimitX96));
    }

    /// @notice Split `body ‖ abi.encode(t, sig) ‖ uint32 len ‖ bytes4 magic` back into its parts.
    /// @dev `len` is the byte length of `abi.encode(t, sig)`. The subject is computed over `body`.
    ///      If no valid trailer is present, returns (d, empty, empty, false).
    function splitSuffix(bytes calldata d)
        internal
        pure
        returns (bytes calldata body, Ticket memory t, bytes memory sig, bool found)
    {
        uint256 n = d.length;
        if (n < 8 || bytes4(d[n - 4:n]) != SUFFIX_MAGIC) return (d, t, sig, false);
        uint256 len = uint32(bytes4(d[n - 8:n - 4]));
        // abi.encode(Ticket, bytes) is at least 9 + 2 words.
        if (len < 352 || len > n - 8) return (d, t, sig, false);
        uint256 start = n - 8 - len;
        (t, sig) = abi.decode(d[start:n - 8], (Ticket, bytes));
        return (d[:start], t, sig, true);
    }

    /// @notice Build a suffix (off-chain helpers do the same; exposed for tests and routers).
    function encodeSuffix(Ticket memory t, bytes memory sig) internal pure returns (bytes memory) {
        bytes memory enc = abi.encode(t, sig);
        return abi.encodePacked(enc, uint32(enc.length), SUFFIX_MAGIC);
    }
}
