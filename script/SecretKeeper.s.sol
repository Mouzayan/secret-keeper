// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {SecretKeeper} from "../src/SecretKeeper.sol";

contract SecretKeeperScript is Script {
    SecretKeeper public secretKeeper;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        secretKeeper = new SecretKeeper();

        vm.stopBroadcast();
    }
}
