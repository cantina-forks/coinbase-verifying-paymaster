// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";

import {SafeSingletonDeployer} from "../src/SafeSingletonDeployer.sol";
import {VerifyingPaymaster} from "../src/VerifyingPaymaster.sol";

contract DeployScript is Script {
  function run() public {
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
    address entrypoint = vm.envAddress("ENTRYPOINT");
    address verifyingSigner = vm.envAddress("VERIFYING_SIGNER");
    address owner = vm.envAddress("OWNER");

    SafeSingletonDeployer.broadcastDeploy({
      deployerPrivateKey: deployerPrivateKey,
      creationCode: type(VerifyingPaymaster).creationCode,
      args: abi.encode(entrypoint, verifyingSigner, owner),
      salt: 0x3078636200000000000000000000000000000000000000000000000000000000
    });
  }
}