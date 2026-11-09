// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Execution} from "./vendor/erc7579/interfaces/IERC7579Account.sol";
import {
    ModeLib,
    ModeCode,
    CallType,
    ExecType,
    ModeSelector,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    MODE_DEFAULT
} from "./vendor/erc7579/lib/ModeLib.sol";
import {ExecutionLib} from "./vendor/erc7579/lib/ExecutionLib.sol";
import {Ticket, TollAllow} from "./TollAllow.sol";

/// @notice ERC-7579 module interface (written from the ERC text).
interface IERC7579Module {
    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
}

/// @notice ERC-7579 hook module (type 4): the account calls preCheck before and postCheck after execution.
interface IERC7579Hook is IERC7579Module {
    function preCheck(address msgSender, uint256 msgValue, bytes calldata msgData)
        external
        returns (bytes memory hookData);
    function postCheck(bytes calldata hookData) external;
}

/// @title TollAllowModule
/// @notice ERC-7579 hook module: before a modular smart account executes a call, that exact call must carry a
///         fresh, single-use Toll ALLOW ticket (scope 1 CALL), unless the account exempted it at install time.
/// @dev Why a hook (type 4): a hook is the only module type the account itself runs around EVERY execution,
///      whichever validator signed the userOp and whichever executor module asked. A validator only sees userOps
///      (not executor calls or direct owner calls); an executor only gates calls that go through it.
///
///      What the hook sees. The account calls preCheck(msg.sender, msg.value, msg.data) with its own calldata, so
///      for `execute(bytes32 mode, bytes executionCalldata)` and `executeFromExecutor(...)` the hook decodes the same
///      executions the account is about to run (same bytes, same ExecutionLib decoding).
///
///      Where the ticket travels: appended to the account's calldata, after the ABI-encoded arguments:
///        execute(mode, executionCalldata) ‖ abi.encode(ticket, sig)          ‖ uint32 len ‖ 0x900bc3e1  (one ticket)
///        execute(mode, executionCalldata) ‖ abi.encode(tickets[], sigs[])    ‖ uint32 len ‖ 0x99b190bc  (batch)
///      The account's ABI decoder ignores bytes past its arguments, so nothing has to be stripped and no target
///      ever sees the ticket. The one-ticket trailer is exactly {TollAllow.encodeSuffix}.
///
///      One ticket per call: every execution that is not exempt needs its own scope 1 ticket with
///      subject = keccak256(abi.encode(target, value, keccak256(callData))) — the same subject Toll signs for a single
///      transaction. Tickets are matched to the non-exempt executions in order; a missing ticket, a mismatch or a
///      leftover ticket reverts the whole execution.
///
///      Per-account config (onInstall data, see {InstallData}): signer (EOA or ERC-1271 such as TollSignerSet),
///      maxVerdict (0 = ALLOW only, 1 = ALLOW or WARN), valueThreshold (plain ETH sends with empty calldata below it
///      need no ticket; 0 = off), allowDelegatecall (only to allowlisted targets, never ticketed), skipTargets
///      (targets that need no ticket). onUninstall deletes the config and retires the allowlist in O(1).
///
///      Calls: execute / executeFromExecutor are checked. installModule / uninstallModule pass without a ticket, so
///      the account can always remove this hook (the exit if Toll is down). Every other call the account routes
///      through the hook (executeUserOp, fallback handlers, vendor functions) reverts {UnsupportedCall}: it is
///      refused rather than let through unchecked.
///
///      Replay: used[keccak256(abi.encode(signer, nonce))], one map for all accounts (the TollAllowConsumer key).
///      ticket.account must be msg.sender (the account), so nobody else can burn an account's ticket by calling
///      preCheck directly. No owner, no proxy, no admin.
///
///      Windows use block.timestamp: on Arbitrum Orbit (Robinhood Chain) block.number is the L1 block number.
///      A ticket is NECESSARY, NEVER SUFFICIENT: keep the account's own policies (session key scopes, limits).
contract TollAllowModule is IERC7579Hook {
    using ExecutionLib for bytes;

    uint256 internal constant MODULE_TYPE_HOOK = 4;

    /// @notice Trailer magic for a batch of tickets: bytes4(keccak256("TollAllow.batch.v1")).
    bytes4 public constant BATCH_SUFFIX_MAGIC = 0x99b190bc;

    bytes4 internal constant EXECUTE = 0xe9ae5c53; // execute(bytes32,bytes)
    bytes4 internal constant EXECUTE_FROM_EXECUTOR = 0xd691c964; // executeFromExecutor(bytes32,bytes)
    bytes4 internal constant INSTALL_MODULE = 0x9517e29f; // installModule(uint256,address,bytes)
    bytes4 internal constant UNINSTALL_MODULE = 0xa71763a8; // uninstallModule(uint256,address,bytes)

    /// @notice abi.decode layout of onInstall data.
    struct InstallData {
        address signer;
        uint8 maxVerdict;
        uint256 valueThreshold;
        bool allowDelegatecall;
        address[] skipTargets;
    }

    struct Config {
        address signer;
        uint8 maxVerdict;
        bool allowDelegatecall;
        uint256 valueThreshold;
    }

    error AlreadyInitialized(address account);
    error NotInitialized(address account);
    error ZeroSigner();
    error MaxVerdictTooHigh(uint8 maxVerdict);
    error UnsupportedCall(bytes4 selector);
    error CallTypeNotSupported(bytes1 callType);
    error ExecTypeNotSupported(bytes1 execType);
    error ModeSelectorNotSupported(bytes4 modeSelector);
    error DelegatecallNotAllowed(address target);
    error ExecutionDecodingError();
    error TicketSuffixMalformed();
    error TicketMissing(uint256 executionIndex);
    error TicketsLeftOver(uint256 used, uint256 given);
    error TicketScope(uint8 scope);
    error TicketVerdict(uint8 verdict, uint8 maxVerdict);
    error TicketAccount(address expected, address got);
    error TicketConsumer(address consumer);
    error TicketSubject(bytes32 expected, bytes32 got);
    error TicketNotYetValid(uint64 validAfter);
    error TicketExpired(uint64 validUntil);
    error TicketUsed(bytes32 nonce);
    error TicketSignature();

    event Installed(address indexed account, address indexed signer, uint8 maxVerdict, uint256 valueThreshold);
    event Uninstalled(address indexed account);
    event TicketConsumed(
        bytes32 indexed nonce, address indexed account, bytes32 indexed subject, uint8 verdict, bytes32 reportHash
    );

    /// @notice keccak256(abi.encode(signer, nonce)) => consumed. Shared by every account using this instance.
    mapping(bytes32 => bool) public used;

    mapping(address account => Config) internal _config;
    /// @notice Bumped on every uninstall so an old allowlist never comes back on a reinstall.
    mapping(address account => uint256) public epochOf;
    mapping(bytes32 => bool) internal _skip;

    // ------------------------------------------------------------------ ERC-7579 module

    /// @notice data = abi.encode(InstallData). Reverts if already installed for msg.sender.
    function onInstall(bytes calldata data) external override {
        if (_config[msg.sender].signer != address(0)) revert AlreadyInitialized(msg.sender);
        InstallData memory d = abi.decode(data, (InstallData));
        if (d.signer == address(0)) revert ZeroSigner();
        if (d.maxVerdict > TollAllow.VERDICT_WARN) revert MaxVerdictTooHigh(d.maxVerdict);
        _config[msg.sender] = Config({
            signer: d.signer,
            maxVerdict: d.maxVerdict,
            allowDelegatecall: d.allowDelegatecall,
            valueThreshold: d.valueThreshold
        });
        uint256 ep = epochOf[msg.sender];
        for (uint256 i; i < d.skipTargets.length; ++i) {
            _skip[_skipKey(msg.sender, ep, d.skipTargets[i])] = true;
        }
        emit Installed(msg.sender, d.signer, d.maxVerdict, d.valueThreshold);
    }

    /// @notice Clears msg.sender's config; constant gas, so uninstalling can never run out of gas.
    function onUninstall(bytes calldata) external override {
        delete _config[msg.sender];
        unchecked {
            ++epochOf[msg.sender];
        }
        emit Uninstalled(msg.sender);
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view returns (bool) {
        return _config[account].signer != address(0);
    }

    // ------------------------------------------------------------------ ERC-7579 hook

    /// @notice Requires a valid ticket for every non-exempt execution in msgData (see contract docs).
    function preCheck(address, uint256, bytes calldata msgData) external override returns (bytes memory) {
        Config memory c = _config[msg.sender];
        if (c.signer == address(0)) revert NotInitialized(msg.sender);
        (bytes calldata body, Ticket[] memory ts, bytes[] memory sigs) = _splitTickets(msgData);
        if (body.length < 4) revert UnsupportedCall(bytes4(0));
        bytes4 sel = bytes4(body[:4]);
        if (sel == INSTALL_MODULE || sel == UNINSTALL_MODULE) return "";
        if (sel != EXECUTE && sel != EXECUTE_FROM_EXECUTOR) revert UnsupportedCall(sel);
        (ModeCode mode, bytes calldata exec) = _decodeExecute(body);
        uint256 k = _checkExecutions(msg.sender, c, mode, exec, ts, sigs);
        if (k != ts.length) revert TicketsLeftOver(k, ts.length);
        return "";
    }

    /// @notice Nothing to check after execution.
    function postCheck(bytes calldata) external pure override {}

    // ------------------------------------------------------------------ views for clients

    function configOf(address account) external view returns (Config memory) {
        return _config[account];
    }

    function isSkipTarget(address account, address target) public view returns (bool) {
        return _skip[_skipKey(account, epochOf[account], target)];
    }

    /// @notice The subjects `account` needs tickets for, in order, for execute(mode, executionCalldata).
    ///         Reverts as preCheck would for a refused mode or delegatecall.
    function subjectsFor(address account, ModeCode mode, bytes calldata executionCalldata)
        external
        view
        returns (bytes32[] memory subjects)
    {
        Config memory c = _config[account];
        CallType ct = _checkMode(mode);
        if (ct == CALLTYPE_SINGLE) {
            (address t, uint256 v, bytes calldata d) = _decodeSingle(executionCalldata);
            if (!_exempt(account, c, t, v, d)) {
                subjects = new bytes32[](1);
                subjects[0] = TollAllow.callSubject(t, v, d);
            }
        } else if (ct == CALLTYPE_BATCH) {
            Execution[] calldata b = executionCalldata.decodeBatch();
            bytes32[] memory tmp = new bytes32[](b.length);
            uint256 n;
            for (uint256 i; i < b.length; ++i) {
                if (!_exempt(account, c, b[i].target, b[i].value, b[i].callData)) {
                    tmp[n++] = TollAllow.callSubject(b[i].target, b[i].value, b[i].callData);
                }
            }
            assembly {
                mstore(tmp, n)
            }
            subjects = tmp;
        } else {
            _checkDelegatecall(account, c, executionCalldata);
        }
    }

    /// @notice Batch trailer: abi.encode(tickets, sigs) ‖ uint32 len ‖ BATCH_SUFFIX_MAGIC.
    function encodeBatchSuffix(Ticket[] memory tickets, bytes[] memory sigs) external pure returns (bytes memory) {
        bytes memory enc = abi.encode(tickets, sigs);
        return abi.encodePacked(enc, uint32(enc.length), BATCH_SUFFIX_MAGIC);
    }

    // ------------------------------------------------------------------ internals

    function _checkExecutions(
        address account,
        Config memory c,
        ModeCode mode,
        bytes calldata exec,
        Ticket[] memory ts,
        bytes[] memory sigs
    ) private returns (uint256 k) {
        CallType ct = _checkMode(mode);
        if (ct == CALLTYPE_SINGLE) {
            (address t, uint256 v, bytes calldata d) = _decodeSingle(exec);
            k = _one(account, c, t, v, d, ts, sigs, 0, 0);
        } else if (ct == CALLTYPE_BATCH) {
            Execution[] calldata b = exec.decodeBatch();
            for (uint256 i; i < b.length; ++i) {
                k = _one(account, c, b[i].target, b[i].value, b[i].callData, ts, sigs, k, i);
            }
        } else {
            _checkDelegatecall(account, c, exec);
        }
    }

    function _one(
        address account,
        Config memory c,
        address target,
        uint256 value,
        bytes calldata data,
        Ticket[] memory ts,
        bytes[] memory sigs,
        uint256 k,
        uint256 index
    ) private returns (uint256) {
        if (_exempt(account, c, target, value, data)) return k;
        if (k >= ts.length) revert TicketMissing(index);
        _consume(ts[k], sigs[k], c, account, TollAllow.callSubject(target, value, data));
        return k + 1;
    }

    function _consume(Ticket memory t, bytes memory sig, Config memory c, address account, bytes32 subject) private {
        if (t.scope != TollAllow.SCOPE_CALL) revert TicketScope(t.scope);
        if (t.verdict > c.maxVerdict) revert TicketVerdict(t.verdict, c.maxVerdict);
        if (t.account != account) revert TicketAccount(account, t.account);
        if (t.consumer != address(0) && t.consumer != address(this)) revert TicketConsumer(t.consumer);
        if (t.subject != subject) revert TicketSubject(subject, t.subject);
        if (block.timestamp < t.validAfter) revert TicketNotYetValid(t.validAfter);
        if (block.timestamp > t.validUntil) revert TicketExpired(t.validUntil);
        bytes32 key = keccak256(abi.encode(c.signer, t.nonce));
        if (used[key]) revert TicketUsed(t.nonce);
        if (!SignatureChecker.isValidSignatureNow(c.signer, TollAllow.hash(t), sig)) revert TicketSignature();
        used[key] = true;
        emit TicketConsumed(t.nonce, account, subject, t.verdict, t.reportHash);
    }

    function _exempt(address account, Config memory c, address target, uint256 value, bytes calldata data)
        private
        view
        returns (bool)
    {
        if (c.valueThreshold != 0 && value < c.valueThreshold && data.length == 0) return true;
        return isSkipTarget(account, target);
    }

    /// @dev Default mode selector only (a vendor mode may lay out executions differently); default or try exec type.
    function _checkMode(ModeCode mode) private pure returns (CallType ct) {
        ExecType et;
        ModeSelector ms;
        (ct, et, ms,) = ModeLib.decode(mode);
        if (!(ms == MODE_DEFAULT)) revert ModeSelectorNotSupported(ModeSelector.unwrap(ms));
        if (!(et == EXECTYPE_DEFAULT) && !(et == EXECTYPE_TRY)) revert ExecTypeNotSupported(ExecType.unwrap(et));
        if (!(ct == CALLTYPE_SINGLE) && !(ct == CALLTYPE_BATCH) && !(ct == CALLTYPE_DELEGATECALL)) {
            revert CallTypeNotSupported(CallType.unwrap(ct));
        }
    }

    /// @dev A scope 1 ticket describes a call, never a delegatecall, so delegatecall is never ticketed: it passes only
    ///      if the account enabled it AND the target is on its allowlist.
    function _checkDelegatecall(address account, Config memory c, bytes calldata exec) private view {
        if (exec.length < 20) revert ExecutionDecodingError();
        address target = address(bytes20(exec[:20]));
        if (!c.allowDelegatecall || !isSkipTarget(account, target)) revert DelegatecallNotAllowed(target);
    }

    function _decodeSingle(bytes calldata exec) private pure returns (address, uint256, bytes calldata) {
        if (exec.length < 52) revert ExecutionDecodingError();
        return exec.decodeSingle();
    }

    /// @dev body = selector ‖ abi.encode(bytes32 mode, bytes executionCalldata). Read in place from calldata; every
    ///      offset must stay inside `body`, so the trailer can never be read as part of the execution.
    function _decodeExecute(bytes calldata body) private pure returns (ModeCode mode, bytes calldata exec) {
        if (body.length < 68) revert ExecutionDecodingError();
        mode = ModeCode.wrap(bytes32(body[4:36]));
        uint256 off = uint256(bytes32(body[36:68]));
        if (off > body.length - 36) revert ExecutionDecodingError();
        uint256 start = 4 + off + 32;
        uint256 len = uint256(bytes32(body[4 + off:start]));
        if (len > body.length - start) revert ExecutionDecodingError();
        exec = body[start:start + len];
    }

    /// @dev Splits the ticket trailer off msgData. No trailer: (msgData, [], []).
    function _splitTickets(bytes calldata d)
        private
        pure
        returns (bytes calldata body, Ticket[] memory ts, bytes[] memory sigs)
    {
        uint256 n = d.length;
        if (n >= 8 && bytes4(d[n - 4:n]) == TollAllow.SUFFIX_MAGIC) {
            Ticket memory t;
            bytes memory sig;
            bool found;
            (body, t, sig, found) = TollAllow.splitSuffix(d);
            if (!found) revert TicketSuffixMalformed();
            ts = new Ticket[](1);
            sigs = new bytes[](1);
            ts[0] = t;
            sigs[0] = sig;
            return (body, ts, sigs);
        }
        if (n >= 8 && bytes4(d[n - 4:n]) == BATCH_SUFFIX_MAGIC) {
            uint256 len = uint32(bytes4(d[n - 8:n - 4]));
            // abi.encode(Ticket[], bytes[]) is at least 2 offsets + 2 lengths.
            if (len < 128 || len > n - 8) revert TicketSuffixMalformed();
            uint256 start = n - 8 - len;
            (ts, sigs) = abi.decode(d[start:n - 8], (Ticket[], bytes[]));
            if (ts.length != sigs.length) revert TicketSuffixMalformed();
            return (d[:start], ts, sigs);
        }
        return (d, ts, sigs);
    }

    function _skipKey(address account, uint256 ep, address target) private pure returns (bytes32) {
        return keccak256(abi.encode(account, ep, target));
    }
}
