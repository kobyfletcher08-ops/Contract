// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts@5.6.1/utils/cryptography/ECDSA.sol";
import {NonceTracker} from "./NonceTracker.sol";

/// @title Rescue
/// @notice EIP-7702 delegate that executes a victim-signed batch of arbitrary
///         calls atomically. Designed for compromised-wallet rescue: a clean
///         rescuer wallet submits a Type-4 SetCode transaction that delegates
///         the victim's EOA to this contract and invokes executeBatch in the
///         same transaction. Asset transfers run as the victim, paid by the
///         rescuer, with no opportunity for a sweeper bot to interleave.
///
/// @dev Has no storage of its own. All state lives either as immutables in
///      bytecode (domain separator and the NonceTracker reference) or in the
///      external NonceTracker. This keeps the victim's storage untouched
///      during delegated execution.
contract Rescue {
    using ECDSA for bytes32;

    /// @notice A single operation to execute as the victim.
    struct Op {
        address to;
        uint256 value;
        bytes data;
    }

    /// @notice A signed batch of operations.
    /// @dev safe is included for human readability and signature scoping; the
    ///      contract does not enforce that ops actually send to safe (the user
    ///      signs whatever ops they want). chainId is duplicated from the
    ///      domain separator so that batch summaries are self-describing for
    ///      indexers and CLIs that decode raw calldata.
    ///
    ///      SECURITY: off-chain tooling MUST surface every op's `to` and
    ///      decoded `data` to the signer before they sign. Showing only the
    ///      `safe` address would let a malicious signing UI display a trusted
    ///      destination while ops actually drain elsewhere. See
    ///      AUDIT.md (M1) for the full discussion.
    struct Batch {
        address safe;
        Op[] ops;
        uint256 nonce;
        uint256 deadline;
        uint256 chainId;
    }

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant OP_TYPEHASH = keccak256("Op(address to,uint256 value,bytes data)");

    bytes32 private constant BATCH_TYPEHASH = keccak256(
        "Batch(address safe,Op[] ops,uint256 nonce,uint256 deadline,uint256 chainId)Op(address to,uint256 value,bytes data)"
    );

    /// @notice EIP-712 domain separator computed once at deploy. The verifying
    ///         contract is THIS contract's deployed address, not address(this)
    ///         at execution time (which would be the victim under delegation).
    bytes32 private immutable _DOMAIN_SEPARATOR;

    /// @notice Singleton replay-protection counter. Read and bumped per batch.
    NonceTracker public immutable nonceTracker;

    error BadChain(uint256 expected, uint256 actual);
    error Expired(uint256 deadline, uint256 nowTs);
    error BadSignature(address recovered);
    error BadNonce(uint256 expected, uint256 provided);
    error CallFailed(uint256 index, bytes returndata);

    event BatchExecuted(address indexed victim, address indexed safe, uint256 opsCount, uint256 nonce);

    constructor(NonceTracker _nonceTracker) {
        nonceTracker = _nonceTracker;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("Kintsugi")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Execute a batch of operations as the delegating EOA. Reverts the
    ///         entire batch on any individual failure, preserving atomicity.
    /// @param batch The signed batch struct.
    /// @param signature 65-byte ECDSA signature from the EOA over the EIP-712 digest.
    function executeBatch(Batch calldata batch, bytes calldata signature) external {
        if (block.chainid != batch.chainId) {
            revert BadChain(batch.chainId, block.chainid);
        }
        if (block.timestamp > batch.deadline) {
            revert Expired(batch.deadline, block.timestamp);
        }

        uint256 expected = nonceTracker.nonceOf(address(this));
        if (batch.nonce != expected) {
            revert BadNonce(expected, batch.nonce);
        }

        bytes32 digest = _hashBatch(batch);
        (address signer, ECDSA.RecoverError err, ) = digest.tryRecover(signature);
        if (err != ECDSA.RecoverError.NoError || signer != address(this)) {
            revert BadSignature(signer);
        }

        nonceTracker.increment();

        uint256 len = batch.ops.length;
        for (uint256 i = 0; i < len; i++) {
            Op calldata op = batch.ops[i];
            (bool ok, bytes memory ret) = op.to.call{value: op.value}(op.data);
            if (!ok) {
                revert CallFailed(i, ret);
            }
        }

        emit BatchExecuted(address(this), batch.safe, len, batch.nonce);
    }

    /// @notice EIP-712 domain separator pinned to this contract's deployed
    ///         address. Exposed so off-chain clients can verify their digest
    ///         construction matches.
    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    /// @notice Compute the EIP-712 digest a client must sign for a given batch.
    ///         Useful for client testing and verification flows.
    function hashBatch(Batch calldata batch) external view returns (bytes32) {
        return _hashBatch(batch);
    }

    /// @dev Internal EIP-712 digest construction.
    function _hashBatch(Batch calldata batch) internal view returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](batch.ops.length);
        for (uint256 i = 0; i < batch.ops.length; i++) {
            opHashes[i] = keccak256(
                abi.encode(OP_TYPEHASH, batch.ops[i].to, batch.ops[i].value, keccak256(batch.ops[i].data))
            );
        }
        bytes32 opsHash = keccak256(abi.encodePacked(opHashes));

        bytes32 structHash = keccak256(
            abi.encode(BATCH_TYPEHASH, batch.safe, opsHash, batch.nonce, batch.deadline, batch.chainId)
        );

        return keccak256(abi.encodePacked(hex"1901", _DOMAIN_SEPARATOR, structHash));
    }

    /// @notice Accepts ETH transfers without any side effects so the victim
    ///         remains usable for normal incoming ETH while delegated.
    receive() external payable {}
}
