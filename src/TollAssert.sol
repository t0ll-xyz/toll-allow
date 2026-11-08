// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title TollAssert
/// @notice Post-conditions for a trade, checked in the same transaction: "the call did what the pre-sign check
///         said, and nothing else listed left the wallet". An agent's smart account (or a multicall) calls
///         {snapshot} before the trade and {assertBalances} / {assertAllowanceAtMost} after it. Any failed check
///         reverts, so the whole transaction (trade included) reverts.
/// @dev Expected deltas come from Toll's check_tx simulation (its balance changes per token), widened by your
///      slippage. Example: simulated -1 ETH, +2,000 TOKEN at 1% slippage => ETH [-1e18, -1e18], TOKEN [1980e18, max].
///
///      Snapshots live in transient storage (EIP-1153 TSTORE/TLOAD, Cancun), so they vanish at the end of the
///      transaction: nothing is stored between transactions, and there is no owner and no admin.
///      Robinhood Chain (Arbitrum Orbit) executes TSTORE/TLOAD.
///
///      A snapshot is keyed by (msg.sender, account, token):
///        - only the caller that took a snapshot can assert against it, so a contract called during the trade
///          cannot read or replace your baseline from its own address;
///        - a second snapshot for the same key in the same transaction reverts (SnapshotExists) until an assert
///          clears it;
///        - {assertBalances} clears the snapshots it checks, so one transaction can snapshot and assert again.
///      Call TollAssert from the account itself (msg.sender = account) or from a caller only you control. Through
///      a public multicall, a contract called during the trade can make calls as that same msg.sender: it cannot
///      take a second snapshot, but it can assert with wide bounds (which clears the snapshot) and then take a new
///      one after moving funds. The key is only as private as the caller.
///
///      Only the tokens you list are checked. A token you did not snapshot is not watched; list every token the
///      simulation shows and every token you hold that a bad call could take. address(0) is native ETH.
///      Gas is paid by tx.origin before execution, so it does not move the native balance between the two calls.
///      Fee-on-transfer and rebasing tokens move by more or less than the nominal amount: set the bounds for that.
contract TollAssert {
    address public constant NATIVE = address(0);

    struct Expectation {
        address token; // address(0) = native ETH
        int256 minDelta; // inclusive, balance after - balance before
        int256 maxDelta; // inclusive
    }

    error SnapshotExists(address account, address token);
    error SnapshotMissing(address account, address token);
    error BalanceOutOfRange(address token, int256 delta, int256 minDelta, int256 maxDelta);
    error AllowanceAboveCap(address token, address spender, uint256 allowance, uint256 cap);
    error ReadFailed(address token);
    error BadRange(address token, int256 minDelta, int256 maxDelta);
    error BalanceTooLarge(address token, uint256 balance);

    // ------------------------------------------------------------------ snapshot

    /// @notice Record the balances of `account` for `tokens`, for this caller, for the rest of this transaction.
    function snapshot(address account, address[] calldata tokens) public {
        for (uint256 i; i < tokens.length; ++i) {
            address token = tokens[i];
            bytes32 slot = _slot(msg.sender, account, token);
            if (_tload(bytes32(uint256(slot) + 1)) != 0) revert SnapshotExists(account, token);
            _tstore(slot, _balance(account, token));
            _tstore(bytes32(uint256(slot) + 1), 1);
        }
    }

    /// @notice {snapshot} with account = msg.sender (the smart account calls TollAssert itself).
    function snapshot(address[] calldata tokens) external {
        snapshot(msg.sender, tokens);
    }

    // ------------------------------------------------------------------ assert

    /// @notice Revert unless every listed token's balance of `account` moved within [minDelta, maxDelta] since this
    ///         caller's snapshot in this transaction. Clears the checked snapshots.
    function assertBalances(address account, Expectation[] calldata expect) public {
        for (uint256 i; i < expect.length; ++i) {
            Expectation calldata e = expect[i];
            if (e.minDelta > e.maxDelta) revert BadRange(e.token, e.minDelta, e.maxDelta);
            bytes32 slot = _slot(msg.sender, account, e.token);
            bytes32 flag = bytes32(uint256(slot) + 1);
            if (_tload(flag) == 0) revert SnapshotMissing(account, e.token);
            int256 delta = _toInt(e.token, _balance(account, e.token)) - _toInt(e.token, _tload(slot));
            if (delta < e.minDelta || delta > e.maxDelta) {
                revert BalanceOutOfRange(e.token, delta, e.minDelta, e.maxDelta);
            }
            _tstore(slot, 0);
            _tstore(flag, 0);
        }
    }

    /// @notice {assertBalances} with account = msg.sender.
    function assertBalances(Expectation[] calldata expect) external {
        assertBalances(msg.sender, expect);
    }

    /// @notice Revert if `owner` has an ERC-20 allowance to `spender` above `cap` (use 0 for "no approval left").
    function assertAllowanceAtMost(address owner, address token, address spender, uint256 cap) public view {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0xdd62ed3e, owner, spender));
        if (!ok || ret.length < 32 || token.code.length == 0) revert ReadFailed(token);
        uint256 a = abi.decode(ret, (uint256));
        if (a > cap) revert AllowanceAboveCap(token, spender, a, cap);
    }

    /// @notice {assertAllowanceAtMost} with owner = msg.sender and cap = 0: no approval to `spender` is left.
    function assertNoNewApproval(address token, address spender) external view {
        assertAllowanceAtMost(msg.sender, token, spender, 0);
    }

    /// @notice {assertAllowanceAtMost} with owner = msg.sender: the allowance to `spender` is at most `cap`.
    function assertNoNewApproval(address token, address spender, uint256 cap) external view {
        assertAllowanceAtMost(msg.sender, token, spender, cap);
    }

    // ------------------------------------------------------------------ views

    /// @notice The snapshot this caller holds for (account, token) in this transaction.
    function snapshotOf(address caller, address account, address token) external view returns (bool set, uint256 bal) {
        bytes32 slot = _slot(caller, account, token);
        return (_tload(bytes32(uint256(slot) + 1)) != 0, _tload(slot));
    }

    // ------------------------------------------------------------------ internals

    function _slot(address caller, address account, address token) private pure returns (bytes32) {
        return keccak256(abi.encode("TollAssert.v1", caller, account, token));
    }

    function _balance(address account, address token) private view returns (uint256) {
        if (token == NATIVE) return account.balance;
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0x70a08231, account));
        if (!ok || ret.length < 32 || token.code.length == 0) revert ReadFailed(token);
        return abi.decode(ret, (uint256));
    }

    function _toInt(address token, uint256 v) private pure returns (int256) {
        if (v > uint256(type(int256).max)) revert BalanceTooLarge(token, v);
        return int256(v);
    }

    function _tstore(bytes32 slot, uint256 v) private {
        assembly ("memory-safe") {
            tstore(slot, v)
        }
    }

    function _tload(bytes32 slot) private view returns (uint256 v) {
        assembly ("memory-safe") {
            v := tload(slot)
        }
    }
}
