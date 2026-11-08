// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity ^0.8.23;
// Vendored from MetaMask/delegation-framework v1.3.0 (commit bfbdf9795a976833ed2fa000baf42fbb83958b03),
// the release whose DelegationManager / EIP7702StatelessDeleGator are listed in documents/Deployments.md.
// Change: trimmed to the ModeLib re-exports CaveatEnforcer needs (the original also defines
// the EIP-712 delegation typehashes).

import {
    CALLTYPE_SINGLE, CALLTYPE_BATCH, EXECTYPE_DEFAULT, EXECTYPE_TRY, MODE_DEFAULT, MODE_OFFSET
} from "../../erc7579/lib/ModeLib.sol";
