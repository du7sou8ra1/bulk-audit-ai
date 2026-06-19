// SPDX-License-Identifier: MIT
// Test fixture: intentionally vulnerable cross-chain bridge. NOT for deployment.
pragma solidity ^0.8.19;

contract VulnerableBridge {
    mapping(bytes32 => bool) public finalized;
    mapping(bytes32 => uint256) public deposits;

    function deposit(bytes32 id) external payable {
        deposits[id] = msg.value;
    }

    // BUG: failed-deposit recovery never clears deposit state -> replayable refund.
    function claimFailedDeposit(bytes32 id, address to, uint256 amount) external {
        require(deposits[id] == amount, "no deposit");
        payable(to).transfer(amount);
        // missing: delete deposits[id];
    }

    // BUG: finalization moves value with NO proof verification, and marks the
    // message processed AFTER the external transfer (CEI violation).
    function finalizeWithdrawal(bytes32 msgId, address to, uint256 amount) external {
        require(!finalized[msgId], "done");
        payable(to).transfer(amount);
        finalized[msgId] = true;
    }
}
