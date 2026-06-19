// SPDX-License-Identifier: MIT
// Test fixture: intentionally vulnerable. NOT for deployment.
pragma solidity ^0.8.19;

contract VulnerableUpgradeable {
    address public implementation;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BUG: no access control on an upgrade function.
    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }

    // BUG: arbitrary external call with user-controlled target + data, no auth.
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }

    // BUG: delegatecall to a user-supplied address.
    function delegate(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
