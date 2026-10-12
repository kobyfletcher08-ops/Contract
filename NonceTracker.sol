// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title NonceTracker
/// @notice External replay-protection counter for the Kintsugi rescue contract.
/// @dev Storing nonces inside the delegated EOA is unsafe: any other EIP-7702
///      delegate the same EOA has set in the past or future could read or
///      overwrite that storage slot, enabling signature replay. Keeping the
///      counter in this singleton contract isolates it from victim storage.
///
///      The nonce is keyed by msg.sender. When the rescue contract executes as
///      a 7702 delegate of the victim, the call into NonceTracker has
///      msg.sender == victim, so victim's own nonce is read and incremented.
///      No other party can increment a different account's nonce because the
///      key is the caller, not a parameter.
contract NonceTracker {
    /// @notice Per-account monotonic nonce. Starts at zero, only ever increments.
    mapping(address account => uint256 nonce) public nonceOf;

    /// @notice Increments msg.sender's own nonce.
    /// @return previous The nonce just consumed (the value before the bump).
    function increment() external returns (uint256 previous) {
        previous = nonceOf[msg.sender];
        unchecked {
            nonceOf[msg.sender] = previous + 1;
        }
    }
}
