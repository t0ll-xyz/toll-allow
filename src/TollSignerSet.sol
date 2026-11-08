// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title TollSignerSet
/// @notice ERC-1271 signer backed by a set of ECDSA keys. Consumers set this contract as
///         `tollSigner`; the owner (Toll's Safe) adds and removes keys, so keys rotate
///         without redeploying any consumer.
/// @dev A signature is valid if it recovers (ECDSA, low-s, 65 or 64 bytes) to a current key.
///      Removing a key invalidates every unconsumed ticket that key signed.
contract TollSignerSet is IERC1271, Ownable2Step {
    error ZeroKey();

    event KeyAdded(address indexed key);
    event KeyRemoved(address indexed key);

    mapping(address => bool) public isKey;

    constructor(address owner_, address[] memory keys) Ownable(owner_) {
        for (uint256 i; i < keys.length; ++i) {
            _add(keys[i]);
        }
    }

    function addKey(address key) external onlyOwner {
        _add(key);
    }

    function removeKey(address key) external onlyOwner {
        if (isKey[key]) {
            isKey[key] = false;
            emit KeyRemoved(key);
        }
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 digest, bytes memory signature) external view returns (bytes4) {
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, signature);
        if (err == ECDSA.RecoverError.NoError && isKey[rec]) return IERC1271.isValidSignature.selector;
        return 0xffffffff;
    }

    function _add(address key) private {
        if (key == address(0)) revert ZeroKey();
        if (!isKey[key]) {
            isKey[key] = true;
            emit KeyAdded(key);
        }
    }
}
