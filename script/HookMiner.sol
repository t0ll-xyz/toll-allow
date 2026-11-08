// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title HookMiner
/// @notice Find a CREATE2 salt whose resulting address carries exactly the wanted Uniswap v4 hook flags in its
///         lowest 14 bits (the HookMiner pattern from v4-periphery, written for this repo).
library HookMiner {
    uint160 internal constant FLAG_MASK = uint160((1 << 14) - 1);
    uint256 internal constant MAX_LOOP = 200_000;

    error SaltNotFound();

    function find(address deployer, uint160 flags, bytes memory creationCode, bytes memory constructorArgs)
        internal
        view
        returns (address hook, bytes32 salt)
    {
        return findFrom(deployer, flags, keccak256(abi.encodePacked(creationCode, constructorArgs)), 0);
    }

    function findFrom(address deployer, uint160 flags, bytes32 initCodeHash, uint256 start)
        internal
        view
        returns (address hook, bytes32 salt)
    {
        flags = flags & FLAG_MASK;
        for (uint256 i = start; i < start + MAX_LOOP; ++i) {
            salt = bytes32(i);
            hook = computeAddress(deployer, salt, initCodeHash);
            if (uint160(hook) & FLAG_MASK == flags && hook.code.length == 0) return (hook, salt);
        }
        revert SaltNotFound();
    }

    function computeAddress(address deployer, bytes32 salt, bytes32 initCodeHash) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, initCodeHash)))));
    }
}
