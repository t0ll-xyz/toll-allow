// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {TollAssert} from "../src/TollAssert.sol";

contract Tkn is ERC20 {
    constructor(string memory s) ERC20(s, s) {}

    function mint(address to, uint256 a) external {
        _mint(to, a);
    }
}

/// A "swap" target: takes `inAmt` of tokenIn, pays `outAmt` of tokenOut. A bad one also pulls `extra` of
/// tokenExtra, or calls back into a shared caller to reset the trader's snapshot.
contract Swapper {
    function swap(Tkn tokenIn, uint256 inAmt, Tkn tokenOut, uint256 outAmt) external payable {
        tokenIn.transferFrom(msg.sender, address(this), inAmt);
        tokenOut.mint(msg.sender, outAmt);
    }

    function swapAndPull(Tkn tokenIn, uint256 inAmt, Tkn tokenOut, uint256 outAmt, Tkn extra, uint256 extraAmt)
        external
    {
        tokenIn.transferFrom(msg.sender, address(this), inAmt);
        tokenOut.mint(msg.sender, outAmt);
        extra.transferFrom(msg.sender, address(this), extraAmt);
    }
}

/// A shared multicall-like caller that anyone can route through (do not use one with TollAssert in production).
contract SharedCaller {
    function call(address to, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = to.call{value: msg.value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        return ret;
    }
}

/// Reaches back through the shared caller mid-trade to re-snapshot the victim's balances.
contract Resnapshotter {
    function attack(SharedCaller shared, TollAssert ta, address victim, address[] calldata tokens) external {
        shared.call(address(ta), abi.encodeWithSignature("snapshot(address,address[])", victim, tokens));
    }
}

/// The agent's smart account: runs a batch of calls in one transaction (snapshot, trade, assert).
contract SmartAccount {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    function execute(Call[] calldata calls) external payable {
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory ret) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!ok) {
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
        }
    }

    receive() external payable {}
}

/// Transient storage lives for one transaction, so each scenario runs as one SmartAccount.execute batch.
contract TollAssertTest is Test {
    TollAssert internal ta;
    Tkn internal usdg;
    Tkn internal meme;
    Tkn internal other;
    Swapper internal swapper;
    SmartAccount internal acct;
    SmartAccount.Call[] internal calls;

    function setUp() public {
        ta = new TollAssert();
        usdg = new Tkn("USDG");
        meme = new Tkn("MEME");
        other = new Tkn("OTHER");
        swapper = new Swapper();
        acct = new SmartAccount();
        usdg.mint(address(acct), 1_000e6);
        other.mint(address(acct), 50e18);
        vm.startPrank(address(acct));
        usdg.approve(address(swapper), type(uint256).max);
        other.approve(address(swapper), type(uint256).max);
        vm.stopPrank();
    }

    // ---------------------------------------------------------------- helpers

    function _add(address to, bytes memory data) internal {
        calls.push(SmartAccount.Call(to, 0, data));
    }

    function _addValue(address to, uint256 value, bytes memory data) internal {
        calls.push(SmartAccount.Call(to, value, data));
    }

    function _take() internal returns (SmartAccount.Call[] memory c) {
        c = calls;
        delete calls;
    }

    function _run() internal {
        acct.execute(_take());
    }

    function _tokens2() internal view returns (address[] memory t) {
        t = new address[](2);
        t[0] = address(usdg);
        t[1] = address(meme);
    }

    function _one(address token) internal pure returns (address[] memory t) {
        t = new address[](1);
        t[0] = token;
    }

    function _exp(address token, int256 lo, int256 hi) internal pure returns (TollAssert.Expectation memory) {
        return TollAssert.Expectation({token: token, minDelta: lo, maxDelta: hi});
    }

    /// check_tx simulated: -100 USDG, +2,000 MEME. Bounds: USDG exactly -100, MEME at least 1,980 (1% slippage).
    function _expect() internal view returns (TollAssert.Expectation[] memory e) {
        e = new TollAssert.Expectation[](2);
        e[0] = _exp(address(usdg), -100e6, -100e6);
        e[1] = _exp(address(meme), 1_980e18, type(int256).max);
    }

    function _snap(address[] memory toks) internal {
        _add(address(ta), abi.encodeWithSignature("snapshot(address[])", toks));
    }

    function _assert(TollAssert.Expectation[] memory e) internal {
        _add(address(ta), abi.encodeWithSignature("assertBalances((address,int256,int256)[])", e));
    }

    function _swap(uint256 inAmt, uint256 outAmt) internal {
        _add(address(swapper), abi.encodeCall(Swapper.swap, (usdg, inAmt, meme, outAmt)));
    }

    function _via(SharedCaller multi, address to, bytes memory data) internal {
        _add(address(multi), abi.encodeCall(SharedCaller.call, (to, data)));
    }

    // ---------------------------------------------------------------- balances

    function test_withinRange_passes() public {
        _snap(_tokens2());
        _swap(100e6, 1_995e18);
        _assert(_expect());
        _run();
        assertEq(meme.balanceOf(address(acct)), 1_995e18);
    }

    function test_gas_snapshot_assert() public {
        _snap(_tokens2());
        _swap(100e6, 1_995e18);
        _assert(_expect());
        SmartAccount.Call[] memory c = _take();
        vm.startSnapshotGas("assert_snapshot_swap_assert_2_tokens");
        acct.execute(c);
        vm.stopSnapshotGas();

        // the same swap alone, to isolate TollAssert's share
        _swap(100e6, 1_995e18);
        c = _take();
        vm.startSnapshotGas("assert_baseline_swap_only");
        acct.execute(c);
        vm.stopSnapshotGas();
    }

    function test_tooLittleOut_reverts() public {
        _snap(_tokens2());
        _swap(100e6, 1_000e18); // got half
        _assert(_expect());
        vm.expectRevert(
            abi.encodeWithSelector(
                TollAssert.BalanceOutOfRange.selector,
                address(meme),
                int256(1_000e18),
                int256(1_980e18),
                type(int256).max
            )
        );
        _run();
    }

    function test_tooMuchIn_reverts() public {
        _snap(_tokens2());
        _swap(150e6, 2_000e18);
        _assert(_expect());
        vm.expectRevert(
            abi.encodeWithSelector(
                TollAssert.BalanceOutOfRange.selector, address(usdg), int256(-150e6), int256(-100e6), int256(-100e6)
            )
        );
        _run();
    }

    function test_listedTokenDrained_reverts() public {
        address[] memory toks = new address[](3);
        toks[0] = address(usdg);
        toks[1] = address(meme);
        toks[2] = address(other);
        _snap(toks);
        _add(address(swapper), abi.encodeCall(Swapper.swapAndPull, (usdg, 100e6, meme, 2_000e18, other, 50e18)));
        TollAssert.Expectation[] memory e = new TollAssert.Expectation[](3);
        e[0] = _exp(address(usdg), -100e6, -100e6);
        e[1] = _exp(address(meme), 1_980e18, type(int256).max);
        e[2] = _exp(address(other), 0, 0); // nothing else may leave
        _assert(e);
        vm.expectRevert(
            abi.encodeWithSelector(
                TollAssert.BalanceOutOfRange.selector, address(other), int256(-50e18), int256(0), int256(0)
            )
        );
        _run();
    }

    function test_nativeEth_delta() public {
        vm.deal(address(acct), 10 ether);
        address pool = makeAddr("pool");
        TollAssert.Expectation[] memory e = new TollAssert.Expectation[](1);
        e[0] = _exp(address(0), -1 ether, -1 ether);

        _snap(_one(address(0)));
        _addValue(pool, 1 ether, "");
        _assert(e);
        _run();

        _snap(_one(address(0)));
        _addValue(pool, 2 ether, "");
        _assert(e);
        vm.expectRevert(
            abi.encodeWithSelector(
                TollAssert.BalanceOutOfRange.selector, address(0), int256(-2 ether), int256(-1 ether), int256(-1 ether)
            )
        );
        _run();
    }

    function test_explicitAccount_viaMulticall() public {
        // a caller contract checks its own balances with the account passed explicitly; key includes the caller
        SharedCaller multi = new SharedCaller();
        usdg.mint(address(multi), 500e6);
        TollAssert.Expectation[] memory e = new TollAssert.Expectation[](1);
        e[0] = _exp(address(usdg), -25e6, -15e6);
        _via(multi, address(ta), abi.encodeWithSignature("snapshot(address,address[])", address(multi), _one(address(usdg))));
        _via(multi, address(usdg), abi.encodeCall(usdg.transfer, (address(1), 20e6)));
        _via(
            multi,
            address(ta),
            abi.encodeWithSignature("assertBalances(address,(address,int256,int256)[])", address(multi), e)
        );
        _run();
    }

    // ---------------------------------------------------------------- snapshot rules

    function test_snapshotMissing_reverts() public {
        _assert(_expect());
        vm.expectRevert(abi.encodeWithSelector(TollAssert.SnapshotMissing.selector, address(acct), address(usdg)));
        _run();
    }

    function test_snapshotOfOtherCaller_notUsable() public {
        // acct snapshots itself; a different caller (multi) asserting on acct finds no snapshot under its key
        SharedCaller multi = new SharedCaller();
        _snap(_tokens2());
        _via(
            multi,
            address(ta),
            abi.encodeWithSignature("assertBalances(address,(address,int256,int256)[])", address(acct), _expect())
        );
        vm.expectRevert(abi.encodeWithSelector(TollAssert.SnapshotMissing.selector, address(acct), address(usdg)));
        _run();
    }

    function test_doubleSnapshot_reverts() public {
        _snap(_tokens2());
        _snap(_tokens2());
        vm.expectRevert(abi.encodeWithSelector(TollAssert.SnapshotExists.selector, address(acct), address(usdg)));
        _run();
    }

    function test_midTradeResnapshot_throughSharedCaller_reverts() public {
        SharedCaller shared = new SharedCaller();
        Resnapshotter evil = new Resnapshotter();
        address[] memory toks = _tokens2();
        // the trader snapshots through a shared caller
        _via(shared, address(ta), abi.encodeWithSignature("snapshot(address,address[])", address(acct), toks));
        // during the trade a called contract tries to reset the baseline through the same shared caller
        _add(address(evil), abi.encodeCall(Resnapshotter.attack, (shared, ta, address(acct), toks)));
        vm.expectRevert(abi.encodeWithSelector(TollAssert.SnapshotExists.selector, address(acct), address(usdg)));
        _run();
    }

    function test_assertClears_thenSnapshotAgain() public {
        _snap(_tokens2());
        _swap(100e6, 2_000e18);
        _assert(_expect());
        _snap(_tokens2()); // allowed again in the same tx
        _swap(100e6, 2_000e18);
        _assert(_expect());
        _run();
    }

    function test_snapshotGone_nextTransaction() public {
        _snap(_tokens2());
        _run();
        (bool set,) = ta.snapshotOf(address(acct), address(acct), address(usdg));
        assertFalse(set); // transient: nothing survives the transaction
        _assert(_expect());
        vm.expectRevert(abi.encodeWithSelector(TollAssert.SnapshotMissing.selector, address(acct), address(usdg)));
        _run();
    }

    function test_badRange_reverts() public {
        TollAssert.Expectation[] memory e = new TollAssert.Expectation[](1);
        e[0] = _exp(address(usdg), 1, -1);
        _snap(_tokens2());
        _assert(e);
        vm.expectRevert(abi.encodeWithSelector(TollAssert.BadRange.selector, address(usdg), int256(1), int256(-1)));
        _run();
    }

    function test_nonContractToken_reverts() public {
        _snap(_one(address(0xdead)));
        vm.expectRevert(abi.encodeWithSelector(TollAssert.ReadFailed.selector, address(0xdead)));
        _run();
    }

    // ---------------------------------------------------------------- approvals

    function test_noApprovalLeft_passes() public {
        _add(address(usdg), abi.encodeCall(usdg.approve, (address(swapper), 0)));
        _add(address(ta), abi.encodeWithSignature("assertNoNewApproval(address,address)", address(usdg), address(swapper)));
        _run();
    }

    function test_approvalLeft_reverts() public {
        // setUp left an unlimited approval to the swapper
        _add(address(ta), abi.encodeWithSignature("assertNoNewApproval(address,address)", address(usdg), address(swapper)));
        vm.expectRevert(
            abi.encodeWithSelector(
                TollAssert.AllowanceAboveCap.selector, address(usdg), address(swapper), type(uint256).max, uint256(0)
            )
        );
        _run();
    }

    function test_approvalCap() public {
        _add(address(usdg), abi.encodeCall(usdg.approve, (address(swapper), 100e6)));
        _add(
            address(ta),
            abi.encodeWithSignature(
                "assertNoNewApproval(address,address,uint256)", address(usdg), address(swapper), uint256(100e6)
            )
        );
        _run();
        _add(
            address(ta),
            abi.encodeWithSignature(
                "assertNoNewApproval(address,address,uint256)", address(usdg), address(swapper), uint256(99e6)
            )
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                TollAssert.AllowanceAboveCap.selector, address(usdg), address(swapper), uint256(100e6), uint256(99e6)
            )
        );
        _run();
        // explicit owner (a multicall checking another account)
        ta.assertAllowanceAtMost(address(acct), address(usdg), address(swapper), 100e6);
    }

    function test_allowance_nonContract_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(TollAssert.ReadFailed.selector, address(0xdead)));
        ta.assertAllowanceAtMost(address(acct), address(0xdead), address(swapper), 0);
    }
}
