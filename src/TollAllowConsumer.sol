// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Ticket, TollAllow} from "./TollAllow.sol";

/// @title TollAllowConsumer
/// @notice Inherit to require a single-use Toll ALLOW ticket before a sensitive call.
/// @dev Checks, in order: on-chain scope, verdict <= maxVerdict, account, consumer
///      (this contract or address(0)), subject, validAfter <= block.timestamp <= validUntil,
///      not used, signature (EOA or ERC-1271). Then marks keccak256(signer, nonce) used.
///
///      Windows use `block.timestamp`: on Arbitrum Orbit (Robinhood Chain) `block.number`
///      is the L1 block number.
///
///      A ticket is NECESSARY, NEVER SUFFICIENT: keep your own checks (slippage, limits, access).
///      Recommended: an owner bypass behind a timelock, so users are not stuck if Toll is down.
///      Point `tollSigner` at a {TollSignerSet} so Toll can rotate keys without a redeploy.
abstract contract TollAllowConsumer {
    error TicketScope(uint8 scope);
    error TicketVerdict(uint8 verdict, uint8 maxVerdict);
    error TicketAccount(address expected, address got);
    error TicketConsumer(address consumer);
    error TicketSubject(bytes32 expected, bytes32 got);
    error TicketNotYetValid(uint64 validAfter);
    error TicketExpired(uint64 validUntil);
    error TicketUsed(bytes32 nonce);
    error TicketSignature();

    event TicketConsumed(
        bytes32 indexed nonce, address indexed account, bytes32 indexed subject, uint8 verdict, bytes32 reportHash
    );

    /// @notice keccak256(abi.encode(signer, nonce)) => consumed.
    mapping(bytes32 => bool) public used;

    /// @notice Toll's signer: an EOA or an ERC-1271 contract (e.g. TollSignerSet).
    address public immutable tollSigner;

    constructor(address signer) {
        tollSigner = signer;
    }

    /// @notice Consume a CALL (1) or V4SWAP (2) ticket. Reverts on any failed check.
    function _consume(Ticket memory t, bytes memory sig, address account, bytes32 subject, uint8 maxVerdict) internal {
        if (t.scope != TollAllow.SCOPE_CALL && t.scope != TollAllow.SCOPE_V4SWAP) revert TicketScope(t.scope);
        _consumeChecked(t, sig, account, subject, maxVerdict);
    }

    /// @notice Same as {_consume} but requires one exact scope.
    function _consume(
        Ticket memory t,
        bytes memory sig,
        address account,
        uint8 scope,
        bytes32 subject,
        uint8 maxVerdict
    ) internal {
        if (t.scope != scope || scope == TollAllow.SCOPE_TXHASH) revert TicketScope(t.scope);
        _consumeChecked(t, sig, account, subject, maxVerdict);
    }

    function _consumeChecked(Ticket memory t, bytes memory sig, address account, bytes32 subject, uint8 maxVerdict)
        private
    {
        if (t.verdict > maxVerdict) revert TicketVerdict(t.verdict, maxVerdict);
        if (t.account != account) revert TicketAccount(account, t.account);
        if (t.consumer != address(0) && t.consumer != address(this)) revert TicketConsumer(t.consumer);
        if (t.subject != subject) revert TicketSubject(subject, t.subject);
        if (block.timestamp < t.validAfter) revert TicketNotYetValid(t.validAfter);
        if (block.timestamp > t.validUntil) revert TicketExpired(t.validUntil);
        bytes32 key = keccak256(abi.encode(tollSigner, t.nonce));
        if (used[key]) revert TicketUsed(t.nonce);
        if (!SignatureChecker.isValidSignatureNow(tollSigner, TollAllow.hash(t), sig)) revert TicketSignature();
        used[key] = true;
        emit TicketConsumed(t.nonce, account, subject, t.verdict, t.reportHash);
    }
}
