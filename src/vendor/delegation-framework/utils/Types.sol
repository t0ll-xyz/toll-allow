// SPDX-License-Identifier: MIT AND Apache-2.0
pragma solidity ^0.8.23;
// Vendored from MetaMask/delegation-framework v1.3.0 (commit bfbdf9795a976833ed2fa000baf42fbb83958b03),
// the release whose DelegationManager / EIP7702StatelessDeleGator are listed in documents/Deployments.md.
// Change: trimmed to the ModeCode re-exports CaveatEnforcer needs (the original also defines
// Delegation, Caveat, P256 and WebAuthn structs and imports account-abstraction).

import { Execution } from "../../erc7579/interfaces/IERC7579Account.sol";
import { ModeCode, CallType, ExecType, ModeSelector, ModePayload } from "../../erc7579/lib/ModeLib.sol";
