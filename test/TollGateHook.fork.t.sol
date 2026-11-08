// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ticket, TollAllow} from "../src/TollAllow.sol";
import {TollAllowConsumer} from "../src/TollAllowConsumer.sol";
import {TollGateHook} from "../src/TollGateHook.sol";
import {PoolKey, SwapParams, V4Hooks, IBeforeSwapHook} from "../src/vendor/uniswap-v4/V4Types.sol";

struct ModifyLiquidityParams {
    int24 tickLower;
    int24 tickUpper;
    int256 liquidityDelta;
    bytes32 salt;
}

/// The PoolManager calls used here (ABI-compatible with v4-core IPoolManager).
interface IPoolManagerMin {
    function initialize(PoolKey memory key, uint160 sqrtPriceX96) external returns (int24);
    function unlock(bytes calldata data) external returns (bytes memory);
    function modifyLiquidity(PoolKey memory key, ModifyLiquidityParams memory params, bytes calldata hookData)
        external
        returns (int256 callerDelta, int256 feesAccrued);
    function swap(PoolKey memory key, SwapParams memory params, bytes calldata hookData) external returns (int256);
    function sync(address currency) external;
    function settle() external payable returns (uint256);
    function take(address currency, address to, uint256 amount) external;
}

contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MOCK") {
        _mint(msg.sender, 1e30);
    }
}

/// Runs against the real Uniswap v4 PoolManager on Robinhood Chain (fork). Skipped unless TOLL_FORK=1:
///   TOLL_FORK=1 forge test --match-contract TollGateHookForkTest
contract TollGateHookForkTest is Test {
    IPoolManagerMin internal constant PM = IPoolManagerMin(0x8366a39CC670B4001A1121B8F6A443A643e40951);
    uint160 internal constant MIN_SQRT = 4295128740;

    uint256 internal signerKey = uint256(keccak256("toll-allow/test-key/v1"));
    TollGateHook internal hook;
    MockToken internal token;
    PoolKey internal key;

    function _setUpFork() internal returns (bool) {
        if (!vm.envOr("TOLL_FORK", false)) {
            vm.skip(true);
            return false;
        }
        vm.createSelectFork("rh");
        token = new MockToken();
        address where = address(uint160(0x7011) << 144 | (uint160(0x42) << 14) | V4Hooks.BEFORE_SWAP_FLAG);
        deployCodeTo(
            "TollGateHook.sol:TollGateHook",
            abi.encode(address(PM), vm.addr(signerKey), uint8(0), TollGateHook.AccountMode.SENDER, address(0), uint256(0)),
            where
        );
        hook = TollGateHook(where);
        key = PoolKey({currency0: address(0), currency1: address(token), fee: 3000, tickSpacing: 60, hooks: where});
        PM.initialize(key, uint160(1) << 96);
        vm.deal(address(this), 100 ether);
        PM.unlock(abi.encode(uint8(0), bytes(""), SwapParams(false, 0, 0)));
        return true;
    }

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        require(msg.sender == address(PM));
        (uint8 op, bytes memory hookData, SwapParams memory p) = abi.decode(data, (uint8, bytes, SwapParams));
        int256 delta;
        if (op == 0) {
            (delta,) = PM.modifyLiquidity(key, ModifyLiquidityParams(-600, 600, 1e21, 0), "");
        } else {
            delta = PM.swap(key, p, hookData);
        }
        _settle(address(0), int128(delta >> 128));
        _settle(address(token), int128(delta));
        return "";
    }

    function _settle(address currency, int128 amount) internal {
        if (amount < 0) {
            uint256 owed = uint256(int256(-amount));
            if (currency == address(0)) {
                PM.settle{value: owed}();
            } else {
                PM.sync(currency);
                token.transfer(address(PM), owed);
                PM.settle();
            }
        } else if (amount > 0) {
            PM.take(currency, address(this), uint256(int256(amount)));
        }
    }

    function _ticket(SwapParams memory p) internal view returns (bytes memory) {
        Ticket memory t = Ticket({
            scope: 2,
            verdict: 0,
            account: address(this), // SENDER mode: this contract calls PoolManager.swap
            consumer: address(hook),
            subject: hook.subjectFor(key, p),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 60),
            nonce: keccak256("fork-nonce"),
            reportHash: keccak256("report")
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, TollAllow.hash(t));
        return abi.encode(t, abi.encodePacked(r, s, v));
    }

    function test_fork_realPoolManager_swapNeedsTicket() public {
        if (!_setUpFork()) return;
        SwapParams memory p = SwapParams(true, -0.01 ether, MIN_SQRT);

        // no ticket: the PoolManager wraps the hook's revert (v4 CustomRevert.WrappedError)
        vm.expectRevert(_wrapped(abi.encodeWithSelector(TollGateHook.TicketMissing.selector)));
        PM.unlock(abi.encode(uint8(1), bytes(""), p));

        // with a ticket: the swap goes through and the ticket is used
        bytes memory d = _ticket(p);
        uint256 before = token.balanceOf(address(this));
        PM.unlock(abi.encode(uint8(1), d, p));
        assertGt(token.balanceOf(address(this)), before);

        // same ticket again: refused
        vm.expectRevert(
            _wrapped(abi.encodeWithSelector(TollAllowConsumer.TicketUsed.selector, keccak256("fork-nonce")))
        );
        PM.unlock(abi.encode(uint8(1), d, p));
    }

    function _wrapped(bytes memory reason) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            bytes4(keccak256("WrappedError(address,bytes4,bytes,bytes)")),
            address(hook),
            IBeforeSwapHook.beforeSwap.selector,
            reason,
            abi.encodeWithSelector(bytes4(keccak256("HookCallFailed()")))
        );
    }

    receive() external payable {}
}
