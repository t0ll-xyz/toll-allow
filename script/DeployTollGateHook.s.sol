// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {TollGateHook} from "../src/TollGateHook.sol";
import {V4Hooks} from "../src/vendor/uniswap-v4/V4Types.sol";
import {HookMiner} from "./HookMiner.sol";

/// @notice Mine a CREATE2 salt for a TollGateHook address with only the beforeSwap flag, and print it.
///
///   forge script script/DeployTollGateHook.s.sol --rpc-url rh            # mine + print, sends nothing
///
/// Deploying is a separate, explicit step: call `deploy()` with --broadcast and your own key. It sends one
/// transaction to the deterministic CREATE2 deployer (0x4e59…956C, present on Robinhood Chain).
///
/// Config (env, all optional):
///   POOL_MANAGER        default 0x8366a39cc670b4001a1121b8f6a443a643e40951 (Uniswap v4 PoolManager, Robinhood Chain)
///   TOLL_SIGNER         default 0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba (Toll's ALLOW signer), or a TollSignerSet
///   MAX_VERDICT         default 0 (ALLOW only); 1 = ALLOW or WARN
///   ACCOUNT_MODE        default 1 (ORIGIN); 0 = SENDER, 2 = NONE
///   THRESHOLD_CURRENCY  default address(0) (native ETH)
///   THRESHOLD           default 0 (every swap needs a ticket)
contract DeployTollGateHook is Script {
    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function _args() internal view returns (bytes memory) {
        address pm = vm.envOr("POOL_MANAGER", address(0x8366a39CC670B4001A1121B8F6A443A643e40951));
        address signer = vm.envOr("TOLL_SIGNER", address(0x4A2C93066d94F1E69f3EAd5438c4efDdf80a46ba));
        uint8 maxVerdict = uint8(vm.envOr("MAX_VERDICT", uint256(0)));
        uint8 mode = uint8(vm.envOr("ACCOUNT_MODE", uint256(1)));
        address cur = vm.envOr("THRESHOLD_CURRENCY", address(0));
        uint256 threshold = vm.envOr("THRESHOLD", uint256(0));
        return abi.encode(pm, signer, maxVerdict, TollGateHook.AccountMode(mode), cur, threshold);
    }

    function _mine() internal view returns (address hook, bytes32 salt, bytes memory initCode) {
        initCode = abi.encodePacked(type(TollGateHook).creationCode, _args());
        (hook, salt) = HookMiner.findFrom(CREATE2_DEPLOYER, V4Hooks.BEFORE_SWAP_FLAG, keccak256(initCode), 0);
    }

    /// @notice Mine and print. Sends nothing.
    function run() external view {
        (address hook, bytes32 salt, bytes memory initCode) = _mine();
        console2.log("TollGateHook address:", hook);
        console2.log("salt:");
        console2.logBytes32(salt);
        console2.log("init code hash:");
        console2.logBytes32(keccak256(initCode));
    }

    /// @notice Deploy through the CREATE2 deployer. Only runs with --broadcast and a key you pass.
    function deploy() external returns (address hook) {
        bytes32 salt;
        bytes memory initCode;
        (hook, salt, initCode) = _mine();
        vm.startBroadcast();
        (bool ok,) = CREATE2_DEPLOYER.call(abi.encodePacked(salt, initCode));
        vm.stopBroadcast();
        require(ok && hook.code.length > 0, "deploy failed");
        console2.log("TollGateHook deployed:", hook);
    }
}
