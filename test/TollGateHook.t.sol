// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ticket, TollAllow} from "../src/TollAllow.sol";
import {TollAllowConsumer} from "../src/TollAllowConsumer.sol";
import {TollGateHook} from "../src/TollGateHook.sol";
import {TollSignerSet} from "../src/TollSignerSet.sol";
import {PoolKey, SwapParams, V4Hooks, IBeforeSwapHook} from "../src/vendor/uniswap-v4/V4Types.sol";
import {HookMiner} from "../script/HookMiner.sol";

/// Calls beforeSwap the way the PoolManager does (msg.sender = poolManager, sender = router).
contract TollGateHookTest is Test {
    uint256 internal constant CHAIN = 4663;
    uint160 internal constant MIN_SQRT = 4295128740; // v4 MIN_SQRT_PRICE + 1

    uint256 internal signerKey;
    address internal signer;
    address internal pm = makeAddr("poolManager");
    address internal router = makeAddr("router");
    address internal trader = makeAddr("trader");
    address internal weth = address(0); // native ETH as currency0
    address internal token = address(0xE1);

    PoolKey internal key;
    SwapParams internal params;

    uint160 internal nextAddr = 1;

    function setUp() public {
        vm.chainId(CHAIN);
        vm.warp(1_793_000_000);
        signerKey = uint256(keccak256("toll-allow/test-key/v1"));
        signer = vm.addr(signerKey);
        params = SwapParams({zeroForOne: true, amountSpecified: -1 ether, sqrtPriceLimitX96: MIN_SQRT});
    }

    // ---------------------------------------------------------------- helpers

    /// Deploy at a fresh address whose low 14 bits are exactly BEFORE_SWAP_FLAG.
    function _deploy(address s, uint8 maxVerdict, TollGateHook.AccountMode mode, address cur, uint256 threshold)
        internal
        returns (TollGateHook h)
    {
        address where = address(uint160(0xABCD) << 144 | (nextAddr++ << 14) | V4Hooks.BEFORE_SWAP_FLAG);
        deployCodeTo("TollGateHook.sol:TollGateHook", abi.encode(pm, s, maxVerdict, mode, cur, threshold), where);
        h = TollGateHook(where);
    }

    function _hook(TollGateHook.AccountMode mode) internal returns (TollGateHook h) {
        h = _deploy(signer, 0, mode, address(0), 0);
        key = PoolKey({currency0: weth, currency1: token, fee: 3000, tickSpacing: 60, hooks: address(h)});
    }

    function _subject(PoolKey memory k, SwapParams memory p) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256(abi.encode(k)), p.zeroForOne, p.amountSpecified, p.sqrtPriceLimitX96));
    }

    function _ticket(TollGateHook h, address account) internal view returns (Ticket memory t) {
        t = Ticket({
            scope: 2,
            verdict: 0,
            account: account,
            consumer: address(h),
            subject: _subject(key, params),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 60),
            nonce: keccak256(abi.encode("nonce", block.timestamp, account, address(h))),
            reportHash: keccak256("report")
        });
    }

    function _data(Ticket memory t) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, TollAllow.hash(t));
        return abi.encode(t, abi.encodePacked(r, s, v));
    }

    function _swap(TollGateHook h, bytes memory hookData) internal returns (bytes4 sel) {
        vm.prank(pm, trader); // msg.sender = PoolManager, tx.origin = trader
        (sel,,) = h.beforeSwap(router, key, params, hookData);
    }

    // ---------------------------------------------------------------- shape

    function test_selector_matches_v4() public pure {
        assertEq(
            IBeforeSwapHook.beforeSwap.selector,
            bytes4(keccak256("beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)"))
        );
        assertEq(IBeforeSwapHook.beforeSwap.selector, bytes4(0x575e24b4));
    }

    function test_constructor_rejectsWrongAddressBits() public {
        address bad = address(uint160(0xABCD) << 144 | V4Hooks.BEFORE_SWAP_FLAG | 1); // extra flag bit
        (bool ok, bytes memory ret) =
            _rawDeploy(bad, abi.encode(pm, signer, uint8(0), TollGateHook.AccountMode.ORIGIN, address(0), uint256(0)));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(TollGateHook.HookAddressFlags.selector, bad));
    }

    function test_constructor_rejectsMaxVerdictAbove1() public {
        address where = address(uint160(0xABCD) << 144 | (uint160(999) << 14) | V4Hooks.BEFORE_SWAP_FLAG);
        (bool ok, bytes memory ret) =
            _rawDeploy(where, abi.encode(pm, signer, uint8(2), TollGateHook.AccountMode.ORIGIN, address(0), uint256(0)));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(TollGateHook.MaxVerdictTooHigh.selector, 2));
    }

    /// Run the constructor at `where` (as deployCodeTo does) and return its result.
    function _rawDeploy(address where, bytes memory args) internal returns (bool ok, bytes memory ret) {
        vm.etch(where, abi.encodePacked(type(TollGateHook).creationCode, args));
        (ok, ret) = where.call("");
    }

    function test_miner_findsBeforeSwapAddress_andCreate2Deploys() public {
        bytes memory args = abi.encode(pm, signer, uint8(0), TollGateHook.AccountMode.ORIGIN, address(0), uint256(0));
        (address want, bytes32 salt) =
            HookMiner.find(address(this), V4Hooks.BEFORE_SWAP_FLAG, type(TollGateHook).creationCode, args);
        assertEq(uint160(want) & V4Hooks.ALL_HOOK_MASK, V4Hooks.BEFORE_SWAP_FLAG);
        TollGateHook h = new TollGateHook{salt: salt}(pm, signer, 0, TollGateHook.AccountMode.ORIGIN, address(0), 0);
        assertEq(address(h), want);
        assertEq(h.poolManager(), pm);
        assertEq(h.tollSigner(), signer);
    }

    function test_subjectFor_matchesTollAllow() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        assertEq(h.subjectFor(key, params), _subject(key, params));
        assertEq(
            h.subjectFor(key, params),
            TollAllow.swapSubject(
                keccak256(abi.encode(key)), params.zeroForOne, params.amountSpecified, params.sqrtPriceLimitX96
            )
        );
    }

    // ---------------------------------------------------------------- happy path + replay

    function test_validTicket_passesOnce_thenReplayFails() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        bytes memory d = _data(t);
        vm.expectEmit(true, true, true, true, address(h));
        emit TollAllowConsumer.TicketConsumed(t.nonce, trader, t.subject, 0, t.reportHash);
        assertEq(_swap(h, d), IBeforeSwapHook.beforeSwap.selector);
        assertTrue(h.used(keccak256(abi.encode(signer, t.nonce))));

        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketUsed.selector, t.nonce));
        _swap(h, d);
    }

    function test_anyConsumer_ok() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        t.consumer = address(0);
        _swap(h, _data(t));
    }

    function test_gas_beforeSwap() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        bytes memory d = _data(_ticket(h, trader));
        vm.prank(pm, trader);
        vm.startSnapshotGas("hook_beforeSwap_eoa_signer");
        h.beforeSwap(router, key, params, d);
        vm.stopSnapshotGas();

        address[] memory keys = new address[](1);
        keys[0] = signer;
        address set = address(new TollSignerSet(address(this), keys));
        TollGateHook h2 = _deploy(set, 0, TollGateHook.AccountMode.ORIGIN, address(0), 0);
        key.hooks = address(h2);
        bytes memory d2 = _data(_ticket(h2, trader));
        vm.prank(pm, trader);
        vm.startSnapshotGas("hook_beforeSwap_1271_signer_set");
        h2.beforeSwap(router, key, params, d2);
        vm.stopSnapshotGas();

        // exempt path (below threshold): no ticket work at all
        TollGateHook h3 = _deploy(signer, 0, TollGateHook.AccountMode.ORIGIN, address(0), 2 ether);
        key.hooks = address(h3);
        vm.prank(pm, trader);
        vm.startSnapshotGas("hook_beforeSwap_below_threshold");
        h3.beforeSwap(router, key, params, "");
        vm.stopSnapshotGas();
    }

    // ---------------------------------------------------------------- wrong swap

    function test_wrongPool_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        bytes memory d = _data(t);
        key.fee = 500; // same pair, other pool
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketSubject.selector, _subject(key, params), t.subject));
        _swap(h, d);
    }

    function test_wrongDirection_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        bytes memory d = _data(t);
        params.zeroForOne = false;
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketSubject.selector, _subject(key, params), t.subject));
        _swap(h, d);
    }

    function test_wrongAmount_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        bytes memory d = _data(t);
        params.amountSpecified = -2 ether;
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketSubject.selector, _subject(key, params), t.subject));
        _swap(h, d);
    }

    function test_wrongPriceLimit_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        bytes memory d = _data(t);
        params.sqrtPriceLimitX96 = MIN_SQRT + 1;
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketSubject.selector, _subject(key, params), t.subject));
        _swap(h, d);
    }

    function test_callScopeTicket_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        t.scope = 1;
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketScope.selector, 1));
        _swap(h, _data(t));
    }

    // ---------------------------------------------------------------- time

    function test_expired_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        bytes memory d = _data(t);
        vm.warp(t.validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketExpired.selector, t.validUntil));
        _swap(h, d);
        vm.warp(t.validUntil); // last valid second
        _swap(h, d);
    }

    function test_notYetValid_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        t.validAfter = uint64(block.timestamp + 5);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketNotYetValid.selector, t.validAfter));
        _swap(h, _data(t));
    }

    // ---------------------------------------------------------------- verdict

    function test_warnRefused_whenMaxIsAllow() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        t.verdict = 1;
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketVerdict.selector, 1, 0));
        _swap(h, _data(t));
    }

    function test_warnAccepted_whenMaxIsWarn() public {
        TollGateHook h = _deploy(signer, 1, TollGateHook.AccountMode.ORIGIN, address(0), 0);
        key = PoolKey({currency0: weth, currency1: token, fee: 3000, tickSpacing: 60, hooks: address(h)});
        Ticket memory t = _ticket(h, trader);
        t.verdict = 1;
        _swap(h, _data(t));
    }

    // ---------------------------------------------------------------- account modes

    function test_origin_wrongTrader_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        bytes memory d = _data(t);
        address copier = makeAddr("copier");
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketAccount.selector, copier, trader));
        vm.prank(pm, copier); // someone copied hookData from the mempool
        h.beforeSwap(router, key, params, d);
    }

    function test_sender_mode_bindsSender() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.SENDER);
        address smartAccount = makeAddr("smartAccount");
        Ticket memory t = _ticket(h, smartAccount);
        bytes memory d = _data(t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketAccount.selector, router, smartAccount));
        vm.prank(pm, trader);
        h.beforeSwap(router, key, params, d);
        vm.prank(pm, trader);
        h.beforeSwap(smartAccount, key, params, d);
    }

    function test_none_mode_accountNotChecked() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.NONE);
        Ticket memory t = _ticket(h, makeAddr("anyone"));
        _swap(h, _data(t));
    }

    // ---------------------------------------------------------------- threshold

    function _thresholdHook(uint256 threshold) internal returns (TollGateHook h) {
        h = _deploy(signer, 0, TollGateHook.AccountMode.ORIGIN, weth, threshold);
        key = PoolKey({currency0: weth, currency1: token, fee: 3000, tickSpacing: 60, hooks: address(h)});
    }

    function test_belowThreshold_needsNoTicket() public {
        TollGateHook h = _thresholdHook(2 ether);
        assertTrue(h.isExempt(key, params)); // exact-in 1 ETH (currency0, zeroForOne)
        assertEq(_swap(h, ""), IBeforeSwapHook.beforeSwap.selector);
    }

    function test_belowThreshold_exactOut_inThresholdCurrency() public {
        TollGateHook h = _thresholdHook(2 ether);
        params = SwapParams({zeroForOne: false, amountSpecified: 1 ether, sqrtPriceLimitX96: 0}); // receive 1 ETH
        assertTrue(h.isExempt(key, params));
        _swap(h, "");
    }

    function test_atThreshold_needsTicket() public {
        TollGateHook h = _thresholdHook(1 ether);
        assertFalse(h.isExempt(key, params));
        vm.expectRevert(TollGateHook.TicketMissing.selector);
        _swap(h, "");
    }

    function test_specifiedInOtherCurrency_needsTicket() public {
        TollGateHook h = _thresholdHook(2 ether);
        params = SwapParams({zeroForOne: false, amountSpecified: -1, sqrtPriceLimitX96: 0}); // exact-in 1 wei of token
        assertFalse(h.isExempt(key, params));
        vm.expectRevert(TollGateHook.TicketMissing.selector);
        _swap(h, "");
    }

    function test_int256Min_needsTicket() public {
        TollGateHook h = _thresholdHook(type(uint256).max);
        params.amountSpecified = type(int256).min;
        assertFalse(h.isExempt(key, params));
    }

    function test_noThreshold_missingTicket_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        params.amountSpecified = -1;
        vm.expectRevert(TollGateHook.TicketMissing.selector);
        _swap(h, "");
    }

    // ---------------------------------------------------------------- caller + signature

    function test_notPoolManager_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        bytes memory d = _data(_ticket(h, trader));
        address griefer = makeAddr("griefer");
        vm.expectRevert(abi.encodeWithSelector(TollGateHook.NotPoolManager.selector, griefer));
        vm.prank(griefer, trader);
        h.beforeSwap(router, key, params, d);
        _swap(h, d); // the real swap still has its ticket
    }

    function test_badSignature_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(keccak256("not toll")), TollAllow.hash(t));
        vm.expectRevert(TollAllowConsumer.TicketSignature.selector);
        _swap(h, abi.encode(t, abi.encodePacked(r, s, v)));
    }

    function test_otherConsumer_reverts() public {
        TollGateHook h = _hook(TollGateHook.AccountMode.ORIGIN);
        Ticket memory t = _ticket(h, trader);
        t.consumer = address(0xC0FFEE);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketConsumer.selector, address(0xC0FFEE)));
        _swap(h, _data(t));
    }

    function test_signerSet_1271_and_rotation() public {
        address[] memory keys = new address[](1);
        keys[0] = signer;
        TollSignerSet set = new TollSignerSet(address(this), keys);
        TollGateHook h = _deploy(address(set), 0, TollGateHook.AccountMode.ORIGIN, address(0), 0);
        key = PoolKey({currency0: weth, currency1: token, fee: 3000, tickSpacing: 60, hooks: address(h)});

        _swap(h, _data(_ticket(h, trader)));

        set.removeKey(signer);
        vm.warp(block.timestamp + 1);
        bytes memory d2 = _data(_ticket(h, trader));
        vm.expectRevert(TollAllowConsumer.TicketSignature.selector);
        _swap(h, d2);
    }
}
