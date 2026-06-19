// SPDX-License-Identifier: MIT
// Test fixture: a "safe" contract — upgrade is guarded by onlyOwner.
pragma solidity ^0.8.19;

abstract contract Ownable {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}

contract SafeVault is Ownable {
    address public implementation;

    // Guarded upgrade — governance power, not a bug by itself.
    function upgradeTo(address newImplementation) external onlyOwner {
        implementation = newImplementation;
    }

    function withdraw(uint256 amount) external onlyOwner {
        payable(owner).transfer(amount);
    }
}
