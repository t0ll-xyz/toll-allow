// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
// Vendored from erc7579/erc7579-implementation commit 16138d1afd4e9711f6c1425133538837bd7787b5
// (the submodule pinned by MetaMask/delegation-framework v1.3.0). Copyright (c) 2024 Rhinestone, MIT.
// Change: trimmed to the Execution struct (the original also declares the IERC7579Account interface).

struct Execution {
    address target;
    uint256 value;
    bytes callData;
}
