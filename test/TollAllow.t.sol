// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Ticket, TollAllow} from "../src/TollAllow.sol";
import {TollAllowConsumer} from "../src/TollAllowConsumer.sol";
import {TollSignerSet} from "../src/TollSignerSet.sol";

/// Example consumer: a router that requires a ticket carried as a calldata suffix.
contract RouterHarness is TollAllowConsumer {
    constructor(address signer) TollAllowConsumer(signer) {}

    function consume(Ticket memory t, bytes memory sig, address account, bytes32 subject, uint8 maxVerdict) external {
        _consume(t, sig, account, subject, maxVerdict);
    }

    /// `data` = body ‖ abi.encode(t, sig) ‖ uint32 len ‖ magic; the ticket binds (target, value, body).
    function route(address target, bytes calldata data) external payable returns (bytes calldata body) {
        Ticket memory t;
        bytes memory sig;
        bool found;
        (body, t, sig, found) = TollAllow.splitSuffix(data);
        require(found, "no ticket");
        _consume(t, sig, msg.sender, TollAllow.SCOPE_CALL, TollAllow.callSubject(target, msg.value, body), 0);
    }

    function digest(Ticket memory t) external view returns (bytes32) {
        return TollAllow.hash(t);
    }

    function verifyView(Ticket memory t, bytes memory sig, address account, bytes32 subject, uint8 maxVerdict)
        external
        view
        returns (bool)
    {
        return TollAllow.verify(t, sig, tollSigner, account, subject, maxVerdict);
    }
}

contract LibHarness {
    function split(bytes calldata d)
        external
        pure
        returns (bytes memory body, Ticket memory t, bytes memory sig, bool found)
    {
        (body, t, sig, found) = TollAllow.splitSuffix(d);
    }

    function callSubject(address target, uint256 value, bytes calldata data) external pure returns (bytes32) {
        return TollAllow.callSubject(target, value, data);
    }
}

contract TollAllowTest is Test {
    uint256 internal constant CHAIN = 4663;
    uint256 internal signerKey;
    address internal signer;
    address internal account = makeAddr("account");
    address internal target = makeAddr("target");
    RouterHarness internal router;
    LibHarness internal lib;
    bytes internal data = abi.encodeWithSignature("transfer(address,uint256)", address(0xBEEF), 25e6);

    function setUp() public {
        vm.chainId(CHAIN);
        vm.warp(1_793_000_000);
        signerKey = uint256(keccak256("toll-allow/test-key/v1"));
        signer = vm.addr(signerKey);
        router = new RouterHarness(signer);
        lib = new LibHarness();
    }

    function _ticket(address consumer) internal view returns (Ticket memory t) {
        t = Ticket({
            scope: 1,
            verdict: 0,
            account: account,
            consumer: consumer,
            subject: keccak256(abi.encode(target, uint256(0), keccak256(data))),
            validAfter: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 60),
            nonce: keccak256(abi.encode("nonce", block.timestamp, consumer)),
            reportHash: keccak256("report")
        });
    }

    function _sign(uint256 key, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, d);
        return abi.encodePacked(r, s, v);
    }

    function _signed(Ticket memory t) internal view returns (bytes memory) {
        return _sign(signerKey, router.digest(t));
    }

    // ---------------------------------------------------------------- happy path

    function test_verify_ok() public {
        Ticket memory t = _ticket(address(router));
        bytes memory sig = _signed(t);
        assertTrue(router.verifyView(t, sig, account, t.subject, 0));
        vm.expectEmit(true, true, true, true, address(router));
        emit TollAllowConsumer.TicketConsumed(t.nonce, account, t.subject, 0, t.reportHash);
        router.consume(t, sig, account, t.subject, 0);
        assertTrue(router.used(keccak256(abi.encode(signer, t.nonce))));
        // subject helper agrees with the manual encoding
        assertEq(lib.callSubject(target, 0, data), t.subject);
    }

    function test_anyConsumer_ok() public {
        Ticket memory t = _ticket(address(0));
        router.consume(t, _signed(t), account, t.subject, 0);
    }

    function test_gas_consume() public {
        Ticket memory t = _ticket(address(router));
        bytes memory sig = _signed(t);
        vm.startSnapshotGas("consume_eoa_signer");
        router.consume(t, sig, account, t.subject, 0);
        vm.stopSnapshotGas();

        address[] memory keys = new address[](1);
        keys[0] = signer;
        RouterHarness r = new RouterHarness(address(new TollSignerSet(address(this), keys)));
        Ticket memory t2 = _ticket(address(r));
        bytes memory sig2 = _sign(signerKey, r.digest(t2));
        vm.startSnapshotGas("consume_1271_signer_set");
        r.consume(t2, sig2, account, t2.subject, 0);
        vm.stopSnapshotGas();
    }

    // ---------------------------------------------------------------- reverts

    function test_expired_reverts() public {
        Ticket memory t = _ticket(address(router));
        bytes memory sig = _signed(t);
        vm.warp(t.validUntil + 1);
        assertFalse(router.verifyView(t, sig, account, t.subject, 0));
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketExpired.selector, t.validUntil));
        router.consume(t, sig, account, t.subject, 0);
        // the last valid second still works
        vm.warp(t.validUntil);
        router.consume(t, sig, account, t.subject, 0);
    }

    function test_notYetValid_reverts() public {
        Ticket memory t = _ticket(address(router));
        t.validAfter = uint64(block.timestamp + 10);
        t.validUntil = uint64(block.timestamp + 70);
        bytes memory sig = _signed(t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketNotYetValid.selector, t.validAfter));
        router.consume(t, sig, account, t.subject, 0);
    }

    function test_replay_reverts() public {
        Ticket memory t = _ticket(address(router));
        bytes memory sig = _signed(t);
        router.consume(t, sig, account, t.subject, 0);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketUsed.selector, t.nonce));
        router.consume(t, sig, account, t.subject, 0);
    }

    function test_wrongAccount_reverts() public {
        Ticket memory t = _ticket(address(router));
        bytes memory sig = _signed(t);
        address other = makeAddr("other");
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketAccount.selector, other, account));
        router.consume(t, sig, other, t.subject, 0);
    }

    function test_wrongConsumer_reverts() public {
        // A ticket for consumer X must not verify at consumer Y.
        RouterHarness other = new RouterHarness(signer);
        Ticket memory t = _ticket(address(other));
        bytes memory sig = _signed(t);
        assertFalse(router.verifyView(t, sig, account, t.subject, 0));
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketConsumer.selector, address(other)));
        router.consume(t, sig, account, t.subject, 0);
        other.consume(t, sig, account, t.subject, 0); // fine at X
    }

    function test_wrongSubject_reverts() public {
        Ticket memory t = _ticket(address(router));
        bytes memory sig = _signed(t);
        bytes32 other = lib.callSubject(target, 1, data); // same call, different value
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketSubject.selector, other, t.subject));
        router.consume(t, sig, account, other, 0);
    }

    function test_verdictAboveMax_reverts() public {
        Ticket memory t = _ticket(address(router));
        t.verdict = 1; // WARN
        bytes memory sig = _signed(t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketVerdict.selector, 1, 0));
        router.consume(t, sig, account, t.subject, 0);
        router.consume(t, sig, account, t.subject, 1); // allowed when the consumer accepts WARN
    }

    function test_badSignature_reverts() public {
        Ticket memory t = _ticket(address(router));
        bytes memory sig = _sign(uint256(keccak256("not toll")), router.digest(t));
        vm.expectRevert(TollAllowConsumer.TicketSignature.selector);
        router.consume(t, sig, account, t.subject, 0);
    }

    function test_txhashScope_reverts() public {
        Ticket memory t = _ticket(address(router));
        t.scope = 3;
        bytes memory sig = _signed(t);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketScope.selector, 3));
        router.consume(t, sig, account, t.subject, 0);
    }

    function test_otherChain_fails() public {
        Ticket memory t = _ticket(address(router));
        bytes memory sig = _signed(t);
        vm.chainId(1);
        vm.expectRevert(TollAllowConsumer.TicketSignature.selector);
        router.consume(t, sig, account, t.subject, 0);
    }

    // ---------------------------------------------------------------- ERC-1271 key set

    function test_1271_rotation() public {
        address safe = makeAddr("safe");
        uint256 key2 = uint256(keccak256("toll-allow/test-key/v2"));
        address[] memory keys = new address[](1);
        keys[0] = signer;
        TollSignerSet set = new TollSignerSet(safe, keys);
        RouterHarness r = new RouterHarness(address(set));

        // key 1 works
        Ticket memory t1 = _ticket(address(r));
        r.consume(t1, _sign(signerKey, r.digest(t1)), account, t1.subject, 0);

        // key 2 not yet a member
        vm.warp(block.timestamp + 1);
        Ticket memory t2 = _ticket(address(r));
        bytes memory sig2 = _sign(key2, r.digest(t2));
        vm.expectRevert(TollAllowConsumer.TicketSignature.selector);
        r.consume(t2, sig2, account, t2.subject, 0);

        // only the owner rotates
        vm.expectRevert();
        set.addKey(vm.addr(key2));
        vm.startPrank(safe);
        set.addKey(vm.addr(key2));
        set.removeKey(signer);
        vm.stopPrank();

        // key 2 now works without redeploying the consumer
        r.consume(t2, sig2, account, t2.subject, 0);

        // a removed key's unconsumed ticket dies
        vm.warp(block.timestamp + 1);
        Ticket memory t3 = _ticket(address(r));
        bytes memory sig3 = _sign(signerKey, r.digest(t3));
        vm.expectRevert(TollAllowConsumer.TicketSignature.selector);
        r.consume(t3, sig3, account, t3.subject, 0);
    }

    // ---------------------------------------------------------------- calldata suffix

    function test_suffix_roundtrip() public {
        Ticket memory t = _ticket(address(router));
        t.account = address(this);
        bytes memory sig = _signed(t);
        bytes memory full = bytes.concat(data, TollAllow.encodeSuffix(t, sig));

        (bytes memory body, Ticket memory got, bytes memory gotSig, bool found) = lib.split(full);
        assertTrue(found);
        assertEq(body, data);
        assertEq(abi.encode(got), abi.encode(t));
        assertEq(gotSig, sig);

        // no trailer -> passthrough
        (body,,, found) = lib.split(data);
        assertFalse(found);
        assertEq(body, data);
        (body,,, found) = lib.split("");
        assertFalse(found);

        // bogus length -> not found
        bytes memory bad = bytes.concat(data, bytes4(uint32(1_000_000)), TollAllow.SUFFIX_MAGIC);
        (,,, found) = lib.split(bad);
        assertFalse(found);

        // end to end through the router: subject is over the body only
        bytes memory ret = router.route(target, full);
        assertEq(ret, data);
        vm.expectRevert(abi.encodeWithSelector(TollAllowConsumer.TicketUsed.selector, t.nonce));
        router.route(target, full);
    }

    // ---------------------------------------------------------------- golden vectors (TypeScript <-> Solidity)

    function _vt(string memory json, string memory p) internal pure returns (Ticket memory t) {
        t.scope = uint8(vm.parseJsonUint(json, string.concat(p, ".ticket.scope")));
        t.verdict = uint8(vm.parseJsonUint(json, string.concat(p, ".ticket.verdict")));
        t.account = vm.parseJsonAddress(json, string.concat(p, ".ticket.account"));
        t.consumer = vm.parseJsonAddress(json, string.concat(p, ".ticket.consumer"));
        t.subject = vm.parseJsonBytes32(json, string.concat(p, ".ticket.subject"));
        t.validAfter = uint64(vm.parseJsonUint(json, string.concat(p, ".ticket.validAfter")));
        t.validUntil = uint64(vm.parseJsonUint(json, string.concat(p, ".ticket.validUntil")));
        t.nonce = vm.parseJsonBytes32(json, string.concat(p, ".ticket.nonce"));
        t.reportHash = vm.parseJsonBytes32(json, string.concat(p, ".ticket.reportHash"));
    }

    function _callVector(string memory json, string memory p, Ticket memory t) internal view returns (bytes32 subject) {
        bytes memory d = vm.parseJsonBytes(json, string.concat(p, ".data"));
        subject = lib.callSubject(
            vm.parseJsonAddress(json, string.concat(p, ".target")),
            vm.parseJsonUint(json, string.concat(p, ".value")),
            d
        );
        // the TS-built suffix splits back into the same body, ticket and signature
        (bytes memory body, Ticket memory st, bytes memory ssig, bool found) =
            lib.split(vm.parseJsonBytes(json, string.concat(p, ".suffixedData")));
        assertTrue(found, "suffix found");
        assertEq(body, d, "suffix body");
        assertEq(abi.encode(st), abi.encode(t), "suffix ticket");
        assertEq(ssig, vm.parseJsonBytes(json, string.concat(p, ".signature")), "suffix sig");
    }

    function _swapVector(string memory json, string memory p) internal pure returns (bytes32) {
        return TollAllow.swapSubject(
            vm.parseJsonBytes32(json, string.concat(p, ".poolId")),
            vm.parseJsonBool(json, string.concat(p, ".zeroForOne")),
            vm.parseJsonInt(json, string.concat(p, ".amountSpecified")),
            uint160(vm.parseJsonUint(json, string.concat(p, ".sqrtPriceLimitX96")))
        );
    }

    function test_vectors_match_ts() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/allowticket-vectors.json"));
        assertEq(vm.parseJsonUint(json, ".domain.chainId"), CHAIN);
        assertEq(vm.parseJsonBytes32(json, ".domainSeparator"), TollAllow.domainSeparator(), "domain");
        assertEq(vm.parseJsonBytes32(json, ".ticketTypehash"), TollAllow.TICKET_TYPEHASH, "typehash");
        assertEq(bytes4(vm.parseJsonBytes(json, ".suffixMagic")), TollAllow.SUFFIX_MAGIC, "magic");
        address vSigner = vm.parseJsonAddress(json, ".signer");
        assertEq(vm.addr(uint256(vm.parseJsonBytes32(json, ".testKey"))), vSigner, "signer");

        uint256 n;
        while (vm.keyExistsJson(json, string.concat(".vectors[", vm.toString(n), "]"))) ++n;
        assertGt(n, 0);

        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            Ticket memory t = _vt(json, p);
            string memory kind = vm.parseJsonString(json, string.concat(p, ".kind"));
            bytes32 subject =
                keccak256(bytes(kind)) == keccak256("call") ? _callVector(json, p, t) : _swapVector(json, p);
            assertEq(subject, vm.parseJsonBytes32(json, string.concat(p, ".subject")), "subject");
            assertEq(subject, t.subject, "ticket subject");
            assertEq(TollAllow.structHash(t), vm.parseJsonBytes32(json, string.concat(p, ".structHash")), "structHash");
            bytes32 d712 = TollAllow.hash(t);
            assertEq(d712, vm.parseJsonBytes32(json, string.concat(p, ".digest")), "digest");
            bytes memory sig = vm.parseJsonBytes(json, string.concat(p, ".signature"));
            assertTrue(SignatureChecker.isValidSignatureNow(vSigner, d712, sig), "signature");

            // full on-chain consume at the vector's consumer (or any consumer), inside its window
            address at = t.consumer == address(0) ? makeAddr(string.concat("any", vm.toString(i))) : t.consumer;
            vm.etch(at, address(new RouterHarness(vSigner)).code);
            vm.warp(t.validAfter);
            RouterHarness(at).consume(t, sig, t.account, subject, 1);
        }
    }
}
