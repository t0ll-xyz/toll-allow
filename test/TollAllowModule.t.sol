// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ticket, TollAllow} from "../src/TollAllow.sol";
import {TollAllowModule, IERC7579Hook} from "../src/TollAllowModule.sol";
import {TollSignerSet} from "../src/TollSignerSet.sol";
import {Execution} from "../src/vendor/erc7579/interfaces/IERC7579Account.sol";
import {
    ModeLib,
    ModeCode,
    CallType,
    ExecType,
    ModeSelector,
    ModePayload,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_STATIC,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    MODE_DEFAULT,
    MODE_OFFSET
} from "../src/vendor/erc7579/lib/ModeLib.sol";
import {ExecutionLib} from "../src/vendor/erc7579/lib/ExecutionLib.sol";

/// Minimal ERC-7579-style account with one hook, shaped like the reference implementation:
/// preCheck(msg.sender, msg.value, msg.data) -> execute -> postCheck(hookData). Owner = whoever deployed it.
contract MockAccount7579 {
    address public immutable owner;
    address public hook;
    address public executor;

    constructor() {
        owner = msg.sender;
    }

    modifier withHook() {
        address h = hook;
        bytes memory hookData;
        if (h != address(0)) hookData = IERC7579Hook(h).preCheck(msg.sender, msg.value, msg.data);
        _;
        if (h != address(0)) IERC7579Hook(h).postCheck(hookData);
    }

    function execute(ModeCode mode, bytes calldata executionCalldata) external payable withHook {
        require(msg.sender == owner, "not owner");
        _run(mode, executionCalldata);
    }

    function executeFromExecutor(ModeCode mode, bytes calldata executionCalldata)
        external
        payable
        withHook
        returns (bytes[] memory)
    {
        require(msg.sender == executor, "not executor");
        _run(mode, executionCalldata);
        return new bytes[](0);
    }

    function installModule(uint256 typeId, address module, bytes calldata initData) external payable withHook {
        require(msg.sender == owner, "not owner");
        if (typeId == 4) {
            require(hook == address(0), "hook set");
            hook = module;
            TollAllowModule(module).onInstall(initData);
        } else if (typeId == 2) {
            executor = module;
        } else {
            revert("type");
        }
    }

    function uninstallModule(uint256 typeId, address module, bytes calldata deInitData) external payable withHook {
        require(msg.sender == owner, "not owner");
        if (typeId == 4) {
            require(hook == module, "not hook");
            hook = address(0);
            TollAllowModule(module).onUninstall(deInitData);
        } else if (typeId == 2) {
            executor = address(0);
        }
    }

    /// A vendor function routed through the hook (stands in for executeUserOp / fallback handlers).
    function vendorThing() external payable withHook {}

    function _run(ModeCode mode, bytes calldata exec) private {
        CallType ct = ModeLib.getCallType(mode);
        if (ct == CALLTYPE_SINGLE) {
            (address t, uint256 v, bytes calldata d) = ExecutionLib.decodeSingle(exec);
            _call(t, v, d);
        } else if (ct == CALLTYPE_BATCH) {
            Execution[] calldata b = ExecutionLib.decodeBatch(exec);
            for (uint256 i; i < b.length; ++i) {
                _call(b[i].target, b[i].value, b[i].callData);
            }
        } else if (ct == CALLTYPE_DELEGATECALL) {
            address t = address(bytes20(exec[:20]));
            (bool ok, bytes memory ret) = t.delegatecall(exec[20:]);
            _bubble(ok, ret);
        } else {
            revert("calltype");
        }
    }

    function _call(address t, uint256 v, bytes calldata d) private {
        (bool ok, bytes memory ret) = t.call{value: v}(d);
        _bubble(ok, ret);
    }

    function _bubble(bool ok, bytes memory ret) private pure {
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    receive() external payable {}
}

contract Target {
    uint256 public hits;
    bytes32 public lastDataHash;
    uint256 public lastValue;

    function hit(uint256 x) external payable {
        hits += x;
        lastDataHash = keccak256(msg.data);
        lastValue = msg.value;
    }
}

/// Delegatecall library: writes into the account's storage slot 100.
contract DelegateLib {
    function mark() external {
        assembly {
            sstore(100, 1)
        }
    }
}

contract Executor {
    function run(MockAccount7579 acct, bytes calldata cd) external {
        (bool ok, bytes memory ret) = address(acct).call(cd);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

contract TollAllowModuleTest is Test {
    uint256 internal constant CHAIN = 4663;

    uint256 internal signerKey;
    address internal signer;
    TollAllowModule internal mod;
    MockAccount7579 internal acct;
    Target internal tgt;
    Target internal tgt2;
    address internal payee = makeAddr("payee");

    ModeCode internal single;
    ModeCode internal batch;
    uint256 internal nonceSeq;

    function setUp() public {
        vm.chainId(CHAIN);
        vm.warp(1_793_000_000);
        signerKey = uint256(keccak256("toll-allow/test-key/v1"));
        signer = vm.addr(signerKey);
        mod = new TollAllowModule();
        acct = new MockAccount7579();
        tgt = new Target();
        tgt2 = new Target();
        vm.deal(address(acct), 10 ether);
        single = ModeLib.encodeSimpleSingle();
        batch = ModeLib.encodeSimpleBatch();
    }

    // ---------------------------------------------------------------- helpers

    function _initData(address s, uint8 maxVerdict, uint256 threshold, bool allowDc, address[] memory skip)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(TollAllowModule.InstallData(s, maxVerdict, threshold, allowDc, skip));
    }

    function _install(address s, uint8 maxVerdict, uint256 threshold, bool allowDc, address[] memory skip) internal {
        acct.installModule(4, address(mod), _initData(s, maxVerdict, threshold, allowDc, skip));
    }

    function _installDefault() internal {
        _install(signer, 0, 0, false, new address[](0));
    }

    function _none() internal pure returns (address[] memory) {
        return new address[](0);
    }

    function _one(address a) internal pure returns (address[] memory r) {
        r = new address[](1);
        r[0] = a;
    }

    function _hitData(uint256 x) internal pure returns (bytes memory) {
        return abi.encodeCall(Target.hit, (x));
    }

    function _ticket(address target, uint256 value, bytes memory data) internal returns (Ticket memory t) {
        t = Ticket({
            scope: 1,
            verdict: 0,
            account: address(acct),
            consumer: address(mod),
            subject: keccak256(abi.encode(target, value, keccak256(data))),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 60),
            nonce: keccak256(abi.encode("nonce", ++nonceSeq)),
            reportHash: keccak256("report")
        });
    }

    function _sig(Ticket memory t) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, TollAllow.hash(t));
        return abi.encodePacked(r, s, v);
    }

    function _execCd(ModeCode mode, bytes memory exec) internal pure returns (bytes memory) {
        return abi.encodeCall(MockAccount7579.execute, (mode, exec));
    }

    function _single(address target, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(target, value, data);
    }

    function _withTicket(bytes memory cd, Ticket memory t) internal view returns (bytes memory) {
        return abi.encodePacked(cd, TollAllow.encodeSuffix(t, _sig(t)));
    }

    function _withTickets(bytes memory cd, Ticket[] memory ts) internal view returns (bytes memory) {
        bytes[] memory sigs = new bytes[](ts.length);
        for (uint256 i; i < ts.length; ++i) {
            sigs[i] = _sig(ts[i]);
        }
        return abi.encodePacked(cd, mod.encodeBatchSuffix(ts, sigs));
    }

    /// Owner calls the account with raw calldata (execute ‖ trailer); reverts bubble up unchanged.
    function callAcct(bytes memory cd) public {
        (bool ok, bytes memory ret) = address(acct).call(cd);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// One single call `tgt.hit(x)` with a ticket.
    function _singleHit(uint256 x, Ticket memory t) internal view returns (bytes memory) {
        return _withTicket(_execCd(single, _single(address(tgt), 0, _hitData(x))), t);
    }

    function _batch2(Execution memory a, Execution memory b) internal pure returns (bytes memory) {
        Execution[] memory e = new Execution[](2);
        e[0] = a;
        e[1] = b;
        return ExecutionLib.encodeBatch(e);
    }

    // ---------------------------------------------------------------- module shape

    function test_moduleTypeIds() public view {
        assertTrue(mod.isModuleType(4));
        assertFalse(mod.isModuleType(1));
        assertFalse(mod.isModuleType(2));
        assertFalse(mod.isModuleType(3));
        assertFalse(mod.isModuleType(0));
    }

    function test_selectors() public pure {
        assertEq(IERC7579Hook.preCheck.selector, bytes4(keccak256("preCheck(address,uint256,bytes)")));
        assertEq(IERC7579Hook.postCheck.selector, bytes4(keccak256("postCheck(bytes)")));
        assertEq(MockAccount7579.execute.selector, bytes4(0xe9ae5c53));
        assertEq(MockAccount7579.executeFromExecutor.selector, bytes4(0xd691c964));
        assertEq(MockAccount7579.installModule.selector, bytes4(0x9517e29f));
        assertEq(MockAccount7579.uninstallModule.selector, bytes4(0xa71763a8));
    }

    function test_batchMagic() public view {
        assertEq(mod.BATCH_SUFFIX_MAGIC(), bytes4(keccak256("TollAllow.batch.v1")));
    }

    // ---------------------------------------------------------------- install / uninstall

    function test_install_setsConfig() public {
        _install(signer, 1, 0.01 ether, true, _one(address(tgt2)));
        assertTrue(mod.isInitialized(address(acct)));
        TollAllowModule.Config memory c = mod.configOf(address(acct));
        assertEq(c.signer, signer);
        assertEq(c.maxVerdict, 1);
        assertEq(c.valueThreshold, 0.01 ether);
        assertTrue(c.allowDelegatecall);
        assertTrue(mod.isSkipTarget(address(acct), address(tgt2)));
        assertFalse(mod.isSkipTarget(address(acct), address(tgt)));
    }

    function test_install_twice_reverts() public {
        _installDefault();
        vm.prank(address(acct));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.AlreadyInitialized.selector, address(acct)));
        mod.onInstall(_initData(signer, 0, 0, false, _none()));
    }

    function test_install_zeroSigner_reverts() public {
        vm.expectRevert(TollAllowModule.ZeroSigner.selector);
        _install(address(0), 0, 0, false, _none());
    }

    function test_install_maxVerdictAbove1_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.MaxVerdictTooHigh.selector, 2));
        _install(signer, 2, 0, false, _none());
    }

    function test_uninstall_clearsConfig_andAllowlist() public {
        _install(signer, 1, 1 ether, true, _one(address(tgt2)));
        // uninstall goes through the hook too, and needs no ticket
        acct.uninstallModule(4, address(mod), "");
        assertFalse(mod.isInitialized(address(acct)));
        TollAllowModule.Config memory c = mod.configOf(address(acct));
        assertEq(c.signer, address(0));
        assertEq(c.valueThreshold, 0);
        assertFalse(c.allowDelegatecall);
        assertFalse(mod.isSkipTarget(address(acct), address(tgt2)));
        assertEq(mod.epochOf(address(acct)), 1);

        // reinstall without an allowlist: the old entry does not come back
        _installDefault();
        assertFalse(mod.isSkipTarget(address(acct), address(tgt2)));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketMissing.selector, 0));
        acct.execute(single, _single(address(tgt2), 0, _hitData(1)));
    }

    function test_notInstalled_preCheck_reverts() public {
        vm.prank(address(acct));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.NotInitialized.selector, address(acct)));
        mod.preCheck(address(this), 0, _execCd(single, _single(address(tgt), 0, _hitData(1))));
    }

    // ---------------------------------------------------------------- single call

    function test_validTicket_passesOnce_targetNeverSeesTrailer() public {
        _installDefault();
        bytes memory data = _hitData(7);
        Ticket memory t = _ticket(address(tgt), 0, data);
        bytes memory cd = _singleHit(7, t);

        vm.expectEmit(true, true, true, true, address(mod));
        emit TollAllowModule.TicketConsumed(t.nonce, address(acct), t.subject, 0, t.reportHash);
        callAcct(cd);
        assertEq(tgt.hits(), 7);
        assertEq(tgt.lastDataHash(), keccak256(data)); // the trailer stays on the account's calldata
        assertTrue(mod.used(keccak256(abi.encode(signer, t.nonce))));

        // replay
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketUsed.selector, t.nonce));
        this.callAcct(cd);
    }

    function test_withValue_ok() public {
        _installDefault();
        bytes memory data = _hitData(1);
        Ticket memory t = _ticket(address(tgt), 1 ether, data);
        callAcct(_withTicket(_execCd(single, _single(address(tgt), 1 ether, data)), t));
        assertEq(tgt.lastValue(), 1 ether);
    }

    function test_noTicket_reverts() public {
        _installDefault();
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketMissing.selector, 0));
        acct.execute(single, _single(address(tgt), 0, _hitData(1)));
    }

    function test_wrongTarget_reverts() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt2), 0, _hitData(1));
        bytes32 want = keccak256(abi.encode(address(tgt), uint256(0), keccak256(_hitData(1))));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketSubject.selector, want, t.subject));
        this.callAcct(_singleHit(1, t));
    }

    function test_wrongValue_reverts() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 1, _hitData(1));
        vm.expectPartialRevert(TollAllowModule.TicketSubject.selector);
        this.callAcct(_singleHit(1, t));
    }

    function test_wrongData_reverts() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(2));
        vm.expectPartialRevert(TollAllowModule.TicketSubject.selector);
        this.callAcct(_singleHit(1, t));
    }

    function test_expired_reverts() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        bytes memory cd = _singleHit(1, t);
        vm.warp(block.timestamp + 61);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketExpired.selector, t.validUntil));
        this.callAcct(cd);
    }

    function test_notYetValid_reverts() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        t.validAfter = uint64(block.timestamp + 5);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketNotYetValid.selector, t.validAfter));
        this.callAcct(_singleHit(1, t));
    }

    function test_warn_refusedUnderAllowOnly() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        t.verdict = 1;
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketVerdict.selector, 1, 0));
        this.callAcct(_singleHit(1, t));
    }

    function test_warn_okWhenMaxIsWarn() public {
        _install(signer, 1, 0, false, _none());
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        t.verdict = 1;
        callAcct(_singleHit(1, t));
        assertEq(tgt.hits(), 1);
    }

    function test_wrongAccount_reverts() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        t.account = address(0xA11CE);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketAccount.selector, address(acct), address(0xA11CE)));
        this.callAcct(_singleHit(1, t));
    }

    function test_otherConsumer_reverts_anyConsumer_ok() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        t.consumer = address(0xC0);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketConsumer.selector, address(0xC0)));
        this.callAcct(_singleHit(1, t));
        t.consumer = address(0);
        callAcct(_singleHit(1, t));
    }

    function test_scope2_reverts() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        t.scope = 2;
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketScope.selector, 2));
        this.callAcct(_singleHit(1, t));
    }

    function test_badSignature_reverts() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(keccak256("someone else")), TollAllow.hash(t));
        bytes memory cd = abi.encodePacked(
            _execCd(single, _single(address(tgt), 0, _hitData(1))), TollAllow.encodeSuffix(t, abi.encodePacked(r, s, v))
        );
        vm.expectRevert(TollAllowModule.TicketSignature.selector);
        this.callAcct(cd);
    }

    function test_thirdParty_cannotBurnTicket() public {
        _installDefault();
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        bytes memory cd = _singleHit(1, t);
        // an uninstalled caller is refused
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.NotInitialized.selector, address(this)));
        mod.preCheck(address(this), 0, cd);
        // an attacker that installs the module for itself fails the account check
        address attacker = makeAddr("attacker");
        vm.startPrank(attacker);
        mod.onInstall(_initData(signer, 0, 0, false, _none()));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketAccount.selector, attacker, address(acct)));
        mod.preCheck(attacker, 0, cd);
        vm.stopPrank();
        // the real execution still works
        callAcct(cd);
        assertEq(tgt.hits(), 1);
    }

    function test_1271_signerSet() public {
        address[] memory keys = new address[](1);
        keys[0] = signer;
        TollSignerSet set = new TollSignerSet(address(this), keys);
        _install(address(set), 0, 0, false, _none());
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        callAcct(_singleHit(1, t));
        assertTrue(mod.used(keccak256(abi.encode(address(set), t.nonce))));

        set.removeKey(signer);
        Ticket memory t2 = _ticket(address(tgt), 0, _hitData(1));
        vm.expectRevert(TollAllowModule.TicketSignature.selector);
        this.callAcct(_singleHit(1, t2));
    }

    // ---------------------------------------------------------------- exemptions

    function test_threshold_plainEthBelow_noTicket() public {
        _install(signer, 0, 0.01 ether, false, _none());
        acct.execute(single, _single(payee, 0.005 ether, ""));
        assertEq(payee.balance, 0.005 ether);
    }

    function test_threshold_atThreshold_needsTicket() public {
        _install(signer, 0, 0.01 ether, false, _none());
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketMissing.selector, 0));
        acct.execute(single, _single(payee, 0.01 ether, ""));
    }

    function test_threshold_withCalldata_needsTicket() public {
        _install(signer, 0, 0.01 ether, false, _none());
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketMissing.selector, 0));
        acct.execute(single, _single(address(tgt), 1, _hitData(1)));
    }

    function test_allowlist_skip() public {
        _install(signer, 0, 0, false, _one(address(tgt)));
        acct.execute(single, _single(address(tgt), 1 ether, _hitData(3)));
        assertEq(tgt.hits(), 3);
        // other targets still need a ticket
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketMissing.selector, 0));
        acct.execute(single, _single(address(tgt2), 0, _hitData(3)));
    }

    function test_exemptCall_withTicketAttached_leftOver_reverts() public {
        _install(signer, 0, 0, false, _one(address(tgt)));
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketsLeftOver.selector, 0, 1));
        this.callAcct(_singleHit(1, t));
    }

    // ---------------------------------------------------------------- batch

    function test_batch_twoTickets_ok_thenReplayFails() public {
        _installDefault();
        bytes memory d1 = _hitData(1);
        bytes memory d2 = _hitData(2);
        Ticket[] memory ts = new Ticket[](2);
        ts[0] = _ticket(address(tgt), 0, d1);
        ts[1] = _ticket(address(tgt2), 0.1 ether, d2);
        bytes memory cd = _withTickets(
            _execCd(batch, _batch2(Execution(address(tgt), 0, d1), Execution(address(tgt2), 0.1 ether, d2))), ts
        );
        callAcct(cd);
        assertEq(tgt.hits(), 1);
        assertEq(tgt2.hits(), 2);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketUsed.selector, ts[0].nonce));
        this.callAcct(cd);
    }

    function test_batch_exemptPlusOneTicket_singleTrailer_ok() public {
        _install(signer, 0, 0.01 ether, false, _none());
        bytes memory d2 = _hitData(2);
        Ticket memory t = _ticket(address(tgt2), 0, d2);
        bytes memory cd =
            _withTicket(_execCd(batch, _batch2(Execution(payee, 0.001 ether, ""), Execution(address(tgt2), 0, d2))), t);
        callAcct(cd);
        assertEq(payee.balance, 0.001 ether);
        assertEq(tgt2.hits(), 2);
    }

    function test_batch_missingSecondTicket_reverts() public {
        _installDefault();
        bytes memory d1 = _hitData(1);
        Ticket memory t = _ticket(address(tgt), 0, d1);
        bytes memory cd =
            _withTicket(_execCd(batch, _batch2(Execution(address(tgt), 0, d1), Execution(address(tgt2), 0, d1))), t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketMissing.selector, 1));
        this.callAcct(cd);
    }

    function test_batch_wrongOrder_reverts() public {
        _installDefault();
        bytes memory d1 = _hitData(1);
        bytes memory d2 = _hitData(2);
        Ticket[] memory ts = new Ticket[](2);
        ts[0] = _ticket(address(tgt2), 0, d2);
        ts[1] = _ticket(address(tgt), 0, d1);
        bytes memory cd =
            _withTickets(_execCd(batch, _batch2(Execution(address(tgt), 0, d1), Execution(address(tgt2), 0, d2))), ts);
        vm.expectPartialRevert(TollAllowModule.TicketSubject.selector);
        this.callAcct(cd);
    }

    function test_batch_extraTicket_reverts() public {
        _installDefault();
        bytes memory d1 = _hitData(1);
        Ticket[] memory ts = new Ticket[](3);
        ts[0] = _ticket(address(tgt), 0, d1);
        ts[1] = _ticket(address(tgt2), 0, d1);
        ts[2] = _ticket(address(tgt2), 0, d1);
        bytes memory cd =
            _withTickets(_execCd(batch, _batch2(Execution(address(tgt), 0, d1), Execution(address(tgt2), 0, d1))), ts);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketsLeftOver.selector, 2, 3));
        this.callAcct(cd);
    }

    function test_batch_sameTicketTwice_reverts() public {
        _installDefault();
        bytes memory d1 = _hitData(1);
        Ticket[] memory ts = new Ticket[](2);
        ts[0] = _ticket(address(tgt), 0, d1);
        ts[1] = ts[0];
        bytes memory cd =
            _withTickets(_execCd(batch, _batch2(Execution(address(tgt), 0, d1), Execution(address(tgt), 0, d1))), ts);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketUsed.selector, ts[0].nonce));
        this.callAcct(cd);
    }

    function test_tryExecType_ok() public {
        _installDefault();
        ModeCode tryMode = ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(0));
        bytes memory data = _hitData(1);
        Ticket memory t = _ticket(address(tgt), 0, data);
        callAcct(_withTicket(_execCd(tryMode, _single(address(tgt), 0, data)), t));
        assertEq(tgt.hits(), 1);
    }

    // ---------------------------------------------------------------- delegatecall + modes

    function test_delegatecall_refusedByDefault() public {
        DelegateLib lib = new DelegateLib();
        _install(signer, 0, 0, false, _one(address(lib)));
        ModeCode dc = ModeLib.encode(CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.DelegatecallNotAllowed.selector, address(lib)));
        acct.execute(dc, abi.encodePacked(address(lib), abi.encodeCall(DelegateLib.mark, ())));
    }

    function test_delegatecall_enabled_onlyAllowlisted() public {
        DelegateLib lib = new DelegateLib();
        DelegateLib other = new DelegateLib();
        _install(signer, 0, 0, true, _one(address(lib)));
        ModeCode dc = ModeLib.encode(CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0));
        acct.execute(dc, abi.encodePacked(address(lib), abi.encodeCall(DelegateLib.mark, ())));
        assertEq(uint256(vm.load(address(acct), bytes32(uint256(100)))), 1);
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.DelegatecallNotAllowed.selector, address(other)));
        acct.execute(dc, abi.encodePacked(address(other), abi.encodeCall(DelegateLib.mark, ())));
    }

    function test_staticCallType_refused() public {
        _installDefault();
        ModeCode st = ModeLib.encode(CALLTYPE_STATIC, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.CallTypeNotSupported.selector, bytes1(0xFE)));
        acct.execute(st, _single(address(tgt), 0, _hitData(1)));
    }

    function test_vendorModeSelector_refused() public {
        _installDefault();
        ModeCode m = ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, MODE_OFFSET, ModePayload.wrap(0));
        vm.expectRevert(
            abi.encodeWithSelector(TollAllowModule.ModeSelectorNotSupported.selector, ModeSelector.unwrap(MODE_OFFSET))
        );
        acct.execute(m, _single(address(tgt), 0, _hitData(1)));
    }

    function test_unknownExecType_refused() public {
        _installDefault();
        ModeCode m = ModeLib.encode(CALLTYPE_SINGLE, ExecType.wrap(0x02), MODE_DEFAULT, ModePayload.wrap(0));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.ExecTypeNotSupported.selector, bytes1(0x02)));
        acct.execute(m, _single(address(tgt), 0, _hitData(1)));
    }

    // ---------------------------------------------------------------- call routing

    function test_executeFromExecutor_isGated() public {
        _installDefault();
        Executor ex = new Executor();
        acct.installModule(2, address(ex), "");
        bytes memory data = _hitData(5);
        bytes memory plain =
            abi.encodeCall(MockAccount7579.executeFromExecutor, (single, _single(address(tgt), 0, data)));
        vm.expectRevert(abi.encodeWithSelector(TollAllowModule.TicketMissing.selector, 0));
        ex.run(acct, plain);
        Ticket memory t = _ticket(address(tgt), 0, data);
        ex.run(acct, _withTicket(plain, t));
        assertEq(tgt.hits(), 5);
    }

    function test_unsupportedCall_refused() public {
        _installDefault();
        vm.expectRevert(
            abi.encodeWithSelector(TollAllowModule.UnsupportedCall.selector, MockAccount7579.vendorThing.selector)
        );
        acct.vendorThing();
    }

    function test_installOtherModule_passesWithoutTicket() public {
        _installDefault();
        acct.installModule(2, address(0xE7), "");
        assertEq(acct.executor(), address(0xE7));
    }

    // ---------------------------------------------------------------- malformed input

    function test_badTrailerLength_reverts() public {
        _installDefault();
        bytes memory cd = abi.encodePacked(
            _execCd(single, _single(address(tgt), 0, _hitData(1))), uint32(type(uint32).max), TollAllow.SUFFIX_MAGIC
        );
        vm.expectRevert(TollAllowModule.TicketSuffixMalformed.selector);
        this.callAcct(cd);
        bytes memory cd2 = abi.encodePacked(
            _execCd(single, _single(address(tgt), 0, _hitData(1))), uint32(64), mod.BATCH_SUFFIX_MAGIC()
        );
        vm.expectRevert(TollAllowModule.TicketSuffixMalformed.selector);
        this.callAcct(cd2);
    }

    function test_offsetIntoTrailer_refused() public {
        _installDefault();
        // execute(mode, bytes) whose `bytes` offset points past the body, into the ticket trailer
        Ticket memory t = _ticket(address(tgt), 0, _hitData(1));
        bytes memory suffix = TollAllow.encodeSuffix(t, _sig(t));
        bytes memory body = abi.encodePacked(MockAccount7579.execute.selector, ModeCode.unwrap(single), uint256(0x40));
        vm.prank(address(acct));
        vm.expectRevert(TollAllowModule.ExecutionDecodingError.selector);
        mod.preCheck(address(this), 0, abi.encodePacked(body, suffix));
    }

    // ---------------------------------------------------------------- client views

    function test_subjectsFor() public {
        _install(signer, 0, 0.01 ether, false, _one(address(tgt2)));
        Execution[] memory e = new Execution[](3);
        e[0] = Execution(address(tgt), 0, _hitData(1));
        e[1] = Execution(address(tgt2), 0, _hitData(2)); // allowlisted
        e[2] = Execution(payee, 0.001 ether, ""); // under threshold
        bytes32[] memory s = mod.subjectsFor(address(acct), batch, ExecutionLib.encodeBatch(e));
        assertEq(s.length, 1);
        assertEq(s[0], keccak256(abi.encode(address(tgt), uint256(0), keccak256(_hitData(1)))));
        bytes32[] memory s1 = mod.subjectsFor(address(acct), single, _single(address(tgt), 1, _hitData(9)));
        assertEq(s1.length, 1);
        assertEq(s1[0], keccak256(abi.encode(address(tgt), uint256(1), keccak256(_hitData(9)))));
    }

    // ---------------------------------------------------------------- gas

    function test_gas_preCheck() public {
        _installDefault();
        bytes memory cd = _singleHit(1, _ticket(address(tgt), 0, _hitData(1)));
        vm.prank(address(acct));
        vm.startSnapshotGas("module_preCheck_single_eoa_signer");
        mod.preCheck(address(this), 0, cd);
        vm.stopSnapshotGas();

        bytes memory d1 = _hitData(1);
        Ticket[] memory ts = new Ticket[](2);
        ts[0] = _ticket(address(tgt), 0, d1);
        ts[1] = _ticket(address(tgt2), 0, d1);
        bytes memory bcd =
            _withTickets(_execCd(batch, _batch2(Execution(address(tgt), 0, d1), Execution(address(tgt2), 0, d1))), ts);
        vm.prank(address(acct));
        vm.startSnapshotGas("module_preCheck_batch2_eoa_signer");
        mod.preCheck(address(this), 0, bcd);
        vm.stopSnapshotGas();
    }

    function test_gas_preCheck_1271() public {
        address[] memory keys = new address[](1);
        keys[0] = signer;
        TollSignerSet set = new TollSignerSet(address(this), keys);
        _install(address(set), 0, 0, false, _none());
        bytes memory cd = _singleHit(1, _ticket(address(tgt), 0, _hitData(1)));
        vm.prank(address(acct));
        vm.startSnapshotGas("module_preCheck_single_1271_signer_set");
        mod.preCheck(address(this), 0, cd);
        vm.stopSnapshotGas();
    }

    function test_gas_preCheck_exempt() public {
        _install(signer, 0, 0, false, _one(address(tgt)));
        bytes memory cd = _execCd(single, _single(address(tgt), 0, _hitData(1)));
        vm.prank(address(acct));
        vm.startSnapshotGas("module_preCheck_allowlisted_no_ticket");
        mod.preCheck(address(this), 0, cd);
        vm.stopSnapshotGas();
    }
}
