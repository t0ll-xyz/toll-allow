// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ticket, TollAllow} from "./TollAllow.sol";
import {TollAllowConsumer} from "./TollAllowConsumer.sol";
import {PoolKey, SwapParams, V4Hooks, IBeforeSwapHook} from "./vendor/uniswap-v4/V4Types.sol";

/// @title TollGateHook
/// @notice Uniswap v4 hook (beforeSwap only): every swap in a pool that uses this hook must carry a
///         fresh, single-use Toll ALLOW ticket (scope 2 V4SWAP) for that exact swap, unless the swap is
///         below the optional size threshold.
/// @dev A pool opts in by naming this contract as `hooks` in its PoolKey; that choice is fixed when the
///      pool is initialized. The ticket travels in `hookData` as abi.encode(Ticket ticket, bytes signature).
///
///      Subject (what the ticket binds):
///        keccak256(abi.encode(poolId, zeroForOne, amountSpecified, sqrtPriceLimitX96))
///      The poolId includes the hook address, so a ticket for one pool never passes in another pool or hook.
///
///      Who the trader is. In v4, `sender` in beforeSwap is the contract that called PoolManager.swap
///      (a router, or a smart account that calls the PoolManager itself), not the trader. A hook cannot
///      see the trader by itself, so each deployment picks one immutable AccountMode:
///        - SENDER: ticket.account == sender. Use when the trader's own contract (an agent smart account
///          or a dedicated router per trader) calls PoolManager.swap. With a shared public router this
///          binds the router, which binds nobody.
///        - ORIGIN: ticket.account == tx.origin. Binds the EOA that signed the transaction, through any
///          router. Does not fit ERC-4337 (tx.origin is the bundler) or relayed transactions.
///        - NONE: ticket.account is not checked. The ticket still binds this pool (via poolId), the exact
///          direction, amount and price limit, a 60 second window and one use. Whoever holds the ticket
///          can use it once; someone who copies it from the mempool can make that same swap first, which
///          uses up the ticket (they trade with their own funds; the original swap then reverts).
///
///      Checks in {beforeSwap}, in order: caller is the PoolManager; size threshold exemption; ticket present;
///      then TollAllowConsumer._consume with scope 2: verdict <= maxVerdict, account (per mode), consumer is
///      this hook or address(0), subject, validAfter <= block.timestamp <= validUntil, not used, signature by
///      tollSigner (EOA or ERC-1271 such as TollSignerSet). Then keccak256(tollSigner, nonce) is marked used.
///
///      Threshold: if `threshold > 0`, a swap whose specified amount is in `thresholdCurrency` and whose absolute
///      value is below `threshold` needs no ticket. The specified currency is the input for exact-in
///      (amountSpecified < 0) and the output for exact-out (amountSpecified > 0). Swaps specified in any other
///      currency always need a ticket. address(0) is native ETH, as in v4.
///
///      Immutable config, no owner, no proxy. Windows use block.timestamp: on Arbitrum Orbit (Robinhood Chain)
///      block.number is the L1 block number. A ticket is NECESSARY, NEVER SUFFICIENT: it does not replace
///      slippage limits or the router's own checks. If Toll is down, gated swaps above the threshold revert until
///      it is back; liquidity can still be removed, because this hook does not gate modifyLiquidity.
contract TollGateHook is TollAllowConsumer, IBeforeSwapHook {
    enum AccountMode {
        SENDER,
        ORIGIN,
        NONE
    }

    error NotPoolManager(address caller);
    error HookAddressFlags(address hook);
    error MaxVerdictTooHigh(uint8 maxVerdict);
    error TicketMissing();

    /// @notice The Uniswap v4 PoolManager allowed to call this hook.
    address public immutable poolManager;
    /// @notice 0 = ALLOW only, 1 = ALLOW or WARN.
    uint8 public immutable maxVerdict;
    /// @notice How ticket.account is checked (see contract docs).
    AccountMode public immutable accountMode;
    /// @notice Currency the size threshold is measured in (address(0) = native ETH).
    address public immutable thresholdCurrency;
    /// @notice Swaps specified in `thresholdCurrency` below this absolute amount need no ticket; 0 = always need one.
    uint256 public immutable threshold;

    constructor(
        address poolManager_,
        address tollSigner_,
        uint8 maxVerdict_,
        AccountMode accountMode_,
        address thresholdCurrency_,
        uint256 threshold_
    ) TollAllowConsumer(tollSigner_) {
        if (uint160(address(this)) & V4Hooks.ALL_HOOK_MASK != V4Hooks.BEFORE_SWAP_FLAG) {
            revert HookAddressFlags(address(this));
        }
        if (maxVerdict_ > TollAllow.VERDICT_WARN) revert MaxVerdictTooHigh(maxVerdict_);
        poolManager = poolManager_;
        maxVerdict = maxVerdict_;
        accountMode = accountMode_;
        thresholdCurrency = thresholdCurrency_;
        threshold = threshold_;
    }

    /// @inheritdoc IBeforeSwapHook
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData)
        external
        override
        returns (bytes4, int256, uint24)
    {
        if (msg.sender != poolManager) revert NotPoolManager(msg.sender);
        if (!_exempt(key, params)) {
            if (hookData.length == 0) revert TicketMissing();
            (Ticket memory t, bytes memory sig) = abi.decode(hookData, (Ticket, bytes));
            bytes32 subject = TollAllow.swapSubject(
                V4Hooks.poolId(key), params.zeroForOne, params.amountSpecified, params.sqrtPriceLimitX96
            );
            _consume(t, sig, _account(sender, t), TollAllow.SCOPE_V4SWAP, subject, maxVerdict);
        }
        return (IBeforeSwapHook.beforeSwap.selector, 0, 0);
    }

    /// @notice Whether this swap is below the threshold and needs no ticket.
    function isExempt(PoolKey calldata key, SwapParams calldata params) external view returns (bool) {
        return _exempt(key, params);
    }

    /// @notice The subject a ticket for this swap must carry.
    function subjectFor(PoolKey calldata key, SwapParams calldata params) external pure returns (bytes32) {
        return TollAllow.swapSubject(
            V4Hooks.poolId(key), params.zeroForOne, params.amountSpecified, params.sqrtPriceLimitX96
        );
    }

    function _account(address sender, Ticket memory t) private view returns (address) {
        if (accountMode == AccountMode.SENDER) return sender;
        if (accountMode == AccountMode.ORIGIN) return tx.origin;
        return t.account; // NONE: not checked
    }

    function _exempt(PoolKey calldata key, SwapParams calldata params) private view returns (bool) {
        if (threshold == 0) return false;
        int256 amt = params.amountSpecified;
        if (amt == type(int256).min) return false;
        bool exactIn = amt < 0;
        // exact-in: specified = input currency; exact-out: specified = output currency
        bool specifiedIsCurrency0 = exactIn == params.zeroForOne;
        address specified = specifiedIsCurrency0 ? key.currency0 : key.currency1;
        if (specified != thresholdCurrency) return false;
        uint256 abs = uint256(exactIn ? -amt : amt);
        return abs < threshold;
    }
}
