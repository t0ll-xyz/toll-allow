// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimal, ABI-compatible definitions of the Uniswap v4 types a beforeSwap-only hook needs.
// Written for this repo from the public v4-core ABI (PoolKey, SwapParams, BeforeSwapDelta,
// Hooks permission flags); no v4-core source is copied. Only what TollGateHook uses is here.
//
// ABI notes, checked against v4-core:
// - PoolKey: (Currency currency0, Currency currency1, uint24 fee, int24 tickSpacing, IHooks hooks).
//   Currency and IHooks are address-typed, so the struct below has the same ABI encoding.
// - PoolId = keccak256 of the 5-word PoolKey (v4-core hashes the struct in memory), which equals
//   keccak256(abi.encode(key)) for this all-static struct.
// - SwapParams: (bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96).
//   amountSpecified < 0 is exact input, > 0 is exact output.
// - beforeSwap returns (bytes4 selector, BeforeSwapDelta, uint24 lpFeeOverride); BeforeSwapDelta is int256.
// - Hook permissions live in the lowest 14 bits of the hook address; BEFORE_SWAP_FLAG = 1 << 7.

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

struct SwapParams {
    bool zeroForOne;
    int256 amountSpecified;
    uint160 sqrtPriceLimitX96;
}

library V4Hooks {
    uint160 internal constant ALL_HOOK_MASK = uint160((1 << 14) - 1);
    uint160 internal constant BEFORE_SWAP_FLAG = uint160(1 << 7);

    /// @notice PoolId as v4-core computes it.
    function poolId(PoolKey calldata key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }
}

/// @notice The one hook entry point TollGateHook implements (selector-compatible with v4-core IHooks).
interface IBeforeSwapHook {
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData)
        external
        returns (bytes4, int256, uint24);
}
