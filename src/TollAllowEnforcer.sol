// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {CaveatEnforcer} from "./vendor/delegation-framework/enforcers/CaveatEnforcer.sol";
import {ModeCode, CallType, ExecType} from "./vendor/delegation-framework/utils/Types.sol";
import {CALLTYPE_SINGLE, CALLTYPE_BATCH, EXECTYPE_DEFAULT} from "./vendor/delegation-framework/utils/Constants.sol";
import {ModeLib} from "./vendor/erc7579/lib/ModeLib.sol";
import {ExecutionLib} from "./vendor/erc7579/lib/ExecutionLib.sol";
import {Ticket, TollAllow} from "./TollAllow.sol";

/// @title TollAllowEnforcer
/// @notice MetaMask Delegation Framework caveat: each redemption of the delegation must carry a
///         single-use Toll ALLOW ticket for the exact call being executed.
/// @dev Terms (set by the delegator, signed into the delegation):
///        abi.encode(address tollSigner, uint8 maxVerdict, uint256 valueThreshold)
///      Args (set by the redeemer at redemption, not signed by the delegator):
///        abi.encode(Ticket ticket, bytes signature)
///
///      Checks in {beforeHook}, in order:
///        - call type SINGLE and exec type DEFAULT (batch is rejected in v1);
///        - plain small ETH send exemption: if valueThreshold > 0, value < valueThreshold and the
///          calldata is empty, no ticket is needed. Everything else needs a ticket;
///        - ticket scope = CALL (1), verdict <= maxVerdict, account = delegator,
///          consumer = this enforcer or address(0), subject = TollAllow.callSubject(target, value, callData),
///          validAfter <= block.timestamp <= validUntil, not used, signature by tollSigner (EOA or ERC-1271).
///
///      Replay: keyed by keccak256(msg.sender, tollSigner, nonce). A ticket is used once per
///      DelegationManager across ALL delegations (the same call cannot run twice through two delegations
///      of one delegator). msg.sender is the DelegationManager, so a third party calling this hook
///      directly with a copied ticket cannot burn it for the real redemption (the same msg.sender
///      scoping as their LimitedCallsEnforcer).
///
///      Put this caveat on the root delegation (the one whose delegator is the account that executes).
///      Windows use block.timestamp: on Arbitrum Orbit (Robinhood Chain) block.number is the L1 number.
///      A ticket is NECESSARY, NEVER SUFFICIENT: combine with the framework's own enforcers
///      (allowed targets, value limits, time windows). The delegator can disable the delegation at any time.
contract TollAllowEnforcer is CaveatEnforcer {
    using ExecutionLib for bytes;

    error InvalidTermsLength(uint256 length);
    error BatchNotSupported();
    error CallTypeNotSupported(bytes1 callType);
    error ExecTypeNotSupported(bytes1 execType);
    error TicketMissing();
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
        address indexed delegationManager,
        bytes32 indexed delegationHash,
        bytes32 indexed nonce,
        address delegator,
        bytes32 subject,
        uint8 verdict,
        bytes32 reportHash
    );

    /// @notice keccak256(abi.encode(delegationManager, tollSigner, nonce)) => consumed.
    mapping(bytes32 => bool) public used;

    /// @notice Require a Toll ALLOW ticket for the single call about to be executed.
    function beforeHook(
        bytes calldata _terms,
        bytes calldata _args,
        ModeCode _mode,
        bytes calldata _executionCallData,
        bytes32 _delegationHash,
        address _delegator,
        address
    ) public override {
        _checkMode(_mode);
        _enforce(_terms, _args, _executionCallData, _delegationHash, _delegator);
    }

    /// @notice Decode the terms: abi.encode(address tollSigner, uint8 maxVerdict, uint256 valueThreshold).
    function getTermsInfo(bytes calldata _terms)
        public
        pure
        returns (address tollSigner, uint8 maxVerdict, uint256 valueThreshold)
    {
        if (_terms.length != 96) revert InvalidTermsLength(_terms.length);
        (tollSigner, maxVerdict, valueThreshold) = abi.decode(_terms, (address, uint8, uint256));
    }

    /// @notice Replay key for a ticket redeemed through `delegationManager`.
    function usedKey(address delegationManager, address tollSigner, bytes32 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(delegationManager, tollSigner, nonce));
    }

    function _checkMode(ModeCode _mode) private pure {
        (CallType callType, ExecType execType,,) = ModeLib.decode(_mode);
        if (callType == CALLTYPE_BATCH) revert BatchNotSupported();
        if (!(callType == CALLTYPE_SINGLE)) revert CallTypeNotSupported(CallType.unwrap(callType));
        if (!(execType == EXECTYPE_DEFAULT)) revert ExecTypeNotSupported(ExecType.unwrap(execType));
    }

    function _enforce(
        bytes calldata _terms,
        bytes calldata _args,
        bytes calldata _executionCallData,
        bytes32 _delegationHash,
        address _delegator
    ) private {
        bytes32 subject;
        {
            (address target, uint256 value, bytes calldata callData) = _executionCallData.decodeSingle();
            (,, uint256 valueThreshold) = getTermsInfo(_terms);
            if (valueThreshold != 0 && value < valueThreshold && callData.length == 0) return;
            subject = TollAllow.callSubject(target, value, callData);
        }
        if (_args.length == 0) revert TicketMissing();
        _consumeArgs(_terms, _args, _delegator, subject, _delegationHash);
    }

    function _consumeArgs(
        bytes calldata _terms,
        bytes calldata _args,
        address delegator,
        bytes32 subject,
        bytes32 delegationHash
    ) private {
        (address signer, uint8 maxVerdict,) = getTermsInfo(_terms);
        (Ticket memory t, bytes memory sig) = abi.decode(_args, (Ticket, bytes));
        _consume(t, sig, signer, maxVerdict, delegator, subject, delegationHash);
    }

    function _consume(
        Ticket memory t,
        bytes memory sig,
        address signer,
        uint8 maxVerdict,
        address delegator,
        bytes32 subject,
        bytes32 delegationHash
    ) private {
        if (t.scope != TollAllow.SCOPE_CALL) revert TicketScope(t.scope);
        if (t.verdict > maxVerdict) revert TicketVerdict(t.verdict, maxVerdict);
        if (t.account != delegator) revert TicketAccount(delegator, t.account);
        if (t.consumer != address(0) && t.consumer != address(this)) revert TicketConsumer(t.consumer);
        if (t.subject != subject) revert TicketSubject(subject, t.subject);
        if (block.timestamp < t.validAfter) revert TicketNotYetValid(t.validAfter);
        if (block.timestamp > t.validUntil) revert TicketExpired(t.validUntil);
        bytes32 key = usedKey(msg.sender, signer, t.nonce);
        if (used[key]) revert TicketUsed(t.nonce);
        if (!SignatureChecker.isValidSignatureNow(signer, TollAllow.hash(t), sig)) revert TicketSignature();
        used[key] = true;
        emit TicketConsumed(msg.sender, delegationHash, t.nonce, delegator, subject, t.verdict, t.reportHash);
    }
}
