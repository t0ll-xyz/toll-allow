// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ticket, TollAllow} from "../src/TollAllow.sol";
import {TollAllowEnforcer} from "../src/TollAllowEnforcer.sol";
import {TollSignerSet} from "../src/TollSignerSet.sol";
import {ModeCode, CallType, ExecType, ModeSelector, ModePayload} from "../src/vendor/delegation-framework/utils/Types.sol";
import {CALLTYPE_SINGLE, CALLTYPE_BATCH, EXECTYPE_DEFAULT, EXECTYPE_TRY, MODE_DEFAULT} from
    "../src/vendor/delegation-framework/utils/Constants.sol";
import {ModeLib} from "../src/vendor/erc7579/lib/ModeLib.sol";
import {Execution} from "../src/vendor/erc7579/interfaces/IERC7579Account.sol";

/// Minimal harness: calls beforeHook the way the DelegationManager does (msg.sender = manager).
contract TollAllowEnforcerTest is Test {
    uint256 internal constant CHAIN = 4663;
    uint256 internal signerKey;
    address internal signer;
    address internal manager = makeAddr("delegationManager");
    address internal delegator = makeAddr("delegator");
    address internal redeemer = makeAddr("redeemer");
    address internal target = makeAddr("target");
    bytes32 internal delegationHash = keccak256("delegation");
    TollAllowEnforcer internal enf;
    bytes internal data = abi.encodeWithSignature("transfer(address,uint256)", address(0xBEEF), 25e6);
    ModeCode internal single;

    function setUp() public {
        vm.chainId(CHAIN);
        vm.warp(1_793_000_000);
        signerKey = uint256(keccak256("toll-allow/test-key/v1"));
        signer = vm.addr(signerKey);
        enf = new TollAllowEnforcer();
        single = ModeLib.encodeSimpleSingle();
    }

    // ---------------------------------------------------------------- helpers

    function _terms(address s, uint8 maxVerdict, uint256 threshold) internal pure returns (bytes memory) {
        return abi.encode(s, maxVerdict, threshold);
    }

    function _exec(address to, uint256 value, bytes memory cd) internal pure returns (bytes memory) {
        return abi.encodePacked(to, value, cd);
    }

    function _ticket(uint256 value, bytes memory cd) internal view returns (Ticket memory t) {
        t = Ticket({
            scope: 1,
            verdict: 0,
            account: delegator,
            consumer: address(enf),
            subject: keccak256(abi.encode(target, value, keccak256(cd))),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 60),
            nonce: keccak256(abi.encode("nonce", block.timestamp, value)),
            reportHash: keccak256("report")
        });
    }

    function _args(Ticket memory t) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, TollAllow.hash(t));
        return abi.encode(t, abi.encodePacked(r, s, v));
    }

    function _hook(bytes memory terms, bytes memory args, ModeCode mode, bytes memory exec) internal {
        vm.prank(manager);
        enf.beforeHook(terms, args, mode, exec, delegationHash, delegator, redeemer);
    }

    function _hookDefault(bytes memory args) internal {
        _hook(_terms(signer, 0, 0), args, single, _exec(target, 0, data));
    }

    // ---------------------------------------------------------------- happy path

    function test_ok() public {
        Ticket memory t = _ticket(0, data);
        bytes memory args = _args(t);
        vm.expectEmit(true, true, true, true, address(enf));
        emit TollAllowEnforcer.TicketConsumed(manager, delegationHash, t.nonce, delegator, t.subject, 0, t.reportHash);
        _hookDefault(args);
        assertTrue(enf.used(enf.usedKey(manager, signer, t.nonce)));
    }

    function test_anyConsumer_ok() public {
        Ticket memory t = _ticket(0, data);
        t.consumer = address(0);
        _hookDefault(_args(t));
    }

    function test_withValue_ok() public {
        Ticket memory t = _ticket(1 ether, data);
        _hook(_terms(signer, 0, 0.01 ether), _args(t), single, _exec(target, 1 ether, data));
    }

    function test_warnAllowedWhenMaxIsWarn() public {
        Ticket memory t = _ticket(0, data);
        t.verdict = 1;
        _hook(_terms(signer, 1, 0), _args(t), single, _exec(target, 0, data));
    }

    function test_smallPlainEth_underThreshold_noTicket() public {
        _hook(_terms(signer, 0, 0.01 ether), "", single, _exec(target, 0.005 ether, ""));
    }

    function test_gas_beforeHook() public {
        bytes memory terms = _terms(signer, 0, 0);
        bytes memory exec = _exec(target, 0, data);
        bytes memory args = _args(_ticket(0, data));
        vm.prank(manager);
        vm.startSnapshotGas("enforcer_beforeHook_eoa_signer");
        enf.beforeHook(terms, args, single, exec, delegationHash, delegator, redeemer);
        vm.stopSnapshotGas();

        address[] memory keys = new address[](1);
        keys[0] = signer;
        address set = address(new TollSignerSet(address(this), keys));
        Ticket memory t2 = _ticket(0, data);
        t2.nonce = keccak256("n2");
        bytes memory args2 = _args(t2);
        bytes memory terms2 = _terms(set, 0, 0);
        vm.prank(manager);
        vm.startSnapshotGas("enforcer_beforeHook_1271_signer_set");
        enf.beforeHook(terms2, args2, single, exec, delegationHash, delegator, redeemer);
        vm.stopSnapshotGas();
    }

    // ---------------------------------------------------------------- threshold edges

    function test_plainEth_atThreshold_needsTicket() public {
        vm.expectRevert(TollAllowEnforcer.TicketMissing.selector);
        _hook(_terms(signer, 0, 0.01 ether), "", single, _exec(target, 0.01 ether, ""));
    }

    function test_smallValueWithCalldata_needsTicket() public {
        vm.expectRevert(TollAllowEnforcer.TicketMissing.selector);
        _hook(_terms(signer, 0, 0.01 ether), "", single, _exec(target, 1, data));
    }

    function test_zeroThreshold_plainEth_needsTicket() public {
        vm.expectRevert(TollAllowEnforcer.TicketMissing.selector);
        _hook(_terms(signer, 0, 0), "", single, _exec(target, 1, ""));
    }

    // ---------------------------------------------------------------- reverts

    function test_missingTicket_reverts() public {
        vm.expectRevert(TollAllowEnforcer.TicketMissing.selector);
        _hookDefault("");
    }

    function test_wrongSubject_reverts() public {
        Ticket memory t = _ticket(0, data);
        bytes memory args = _args(t);
        bytes memory other = abi.encodeWithSignature("transfer(address,uint256)", address(0xBAD), 25e6);
        bytes32 want = TollAllow.callSubjectMem(target, 0, other);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketSubject.selector, want, t.subject));
        _hook(_terms(signer, 0, 0), args, single, _exec(target, 0, other));
    }

    function test_wrongValue_reverts() public {
        Ticket memory t = _ticket(0, data);
        bytes memory args = _args(t);
        bytes32 want = TollAllow.callSubjectMem(target, 1, data);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketSubject.selector, want, t.subject));
        _hook(_terms(signer, 0, 0), args, single, _exec(target, 1, data));
    }

    function test_wrongDelegator_reverts() public {
        Ticket memory t = _ticket(0, data);
        bytes memory args = _args(t);
        address other = makeAddr("otherDelegator");
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketAccount.selector, other, delegator));
        vm.prank(manager);
        enf.beforeHook(_terms(signer, 0, 0), args, single, _exec(target, 0, data), delegationHash, other, redeemer);
    }

    function test_wrongConsumer_reverts() public {
        Ticket memory t = _ticket(0, data);
        t.consumer = address(0xC0FFEE);
        bytes memory args = _args(t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketConsumer.selector, address(0xC0FFEE)));
        _hookDefault(args);
    }

    function test_expired_reverts() public {
        Ticket memory t = _ticket(0, data);
        bytes memory args = _args(t);
        vm.warp(t.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketExpired.selector, t.validUntil));
        _hookDefault(args);
    }

    function test_notYetValid_reverts() public {
        Ticket memory t = _ticket(0, data);
        t.validAfter = uint64(block.timestamp + 5);
        bytes memory args = _args(t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketNotYetValid.selector, t.validAfter));
        _hookDefault(args);
    }

    function test_replay_reverts() public {
        Ticket memory t = _ticket(0, data);
        bytes memory args = _args(t);
        _hookDefault(args);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketUsed.selector, t.nonce));
        _hookDefault(args);
    }

    function test_replay_acrossDelegations_reverts() public {
        Ticket memory t = _ticket(0, data);
        bytes memory args = _args(t);
        _hookDefault(args);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketUsed.selector, t.nonce));
        vm.prank(manager);
        enf.beforeHook(_terms(signer, 0, 0), args, single, _exec(target, 0, data), keccak256("other"), delegator, redeemer);
    }

    function test_directCall_cannotBurnTicket() public {
        Ticket memory t = _ticket(0, data);
        bytes memory args = _args(t);
        // someone copies the args and calls the hook directly first
        vm.prank(makeAddr("griefer"));
        enf.beforeHook(_terms(signer, 0, 0), args, single, _exec(target, 0, data), delegationHash, delegator, redeemer);
        // the real redemption through the manager still works
        _hookDefault(args);
    }

    function test_verdictAboveMax_reverts() public {
        Ticket memory t = _ticket(0, data);
        t.verdict = 1;
        bytes memory args = _args(t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketVerdict.selector, 1, 0));
        _hookDefault(args);
    }

    function test_wrongScope_reverts() public {
        Ticket memory t = _ticket(0, data);
        t.scope = 3;
        bytes memory args = _args(t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.TicketScope.selector, 3));
        _hookDefault(args);
    }

    function test_badSignature_reverts() public {
        Ticket memory t = _ticket(0, data);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(keccak256("not toll")), TollAllow.hash(t));
        vm.expectRevert(TollAllowEnforcer.TicketSignature.selector);
        _hookDefault(abi.encode(t, abi.encodePacked(r, s, v)));
    }

    function test_batchMode_reverts() public {
        Execution[] memory xs = new Execution[](1);
        xs[0] = Execution(target, 0, data);
        vm.expectRevert(TollAllowEnforcer.BatchNotSupported.selector);
        _hook(_terms(signer, 0, 0), _args(_ticket(0, data)), ModeLib.encodeSimpleBatch(), abi.encode(xs));
    }

    function test_tryMode_reverts() public {
        ModeCode m = ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(0x00));
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.ExecTypeNotSupported.selector, bytes1(0x01)));
        _hook(_terms(signer, 0, 0), _args(_ticket(0, data)), m, _exec(target, 0, data));
    }

    function test_delegatecallMode_reverts() public {
        ModeCode m = ModeLib.encode(CallType.wrap(0xFF), EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0x00));
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.CallTypeNotSupported.selector, bytes1(0xFF)));
        _hook(_terms(signer, 0, 0), _args(_ticket(0, data)), m, _exec(target, 0, data));
    }

    function test_badTerms_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(TollAllowEnforcer.InvalidTermsLength.selector, 64));
        _hook(abi.encode(signer, uint8(0)), _args(_ticket(0, data)), single, _exec(target, 0, data));
    }

    // ---------------------------------------------------------------- ERC-1271 signer set

    function test_signerSet_1271_and_rotation() public {
        address[] memory keys = new address[](1);
        keys[0] = signer;
        TollSignerSet set = new TollSignerSet(address(this), keys);
        bytes memory terms = _terms(address(set), 0, 0);

        Ticket memory t = _ticket(0, data);
        _hook(terms, _args(t), single, _exec(target, 0, data));

        // remove the key: a fresh ticket signed by it no longer passes
        set.removeKey(signer);
        Ticket memory t2 = _ticket(0, data);
        t2.nonce = keccak256("n2");
        bytes memory args2 = _args(t2);
        vm.expectRevert(TollAllowEnforcer.TicketSignature.selector);
        _hook(terms, args2, single, _exec(target, 0, data));
    }
}
