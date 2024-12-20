// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";

import {VerifyingPaymaster} from "../src/VerifyingPaymaster.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "@account-abstraction/core/UserOperationLib.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {SimpleAccountFactory, SimpleAccount} from "@account-abstraction/samples/SimpleAccountFactory.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {MockERC20} from "./MockERC20.sol";


contract VerifyingPaymasterTest is Test {
    using UserOperationLib for PackedUserOperation;

    EntryPoint public entrypoint;
    VerifyingPaymaster public paymaster;
    SimpleAccount public account;
    MockERC20 public mockToken;
    

    uint48 constant MOCK_VALID_UNTIL = 281474976710655;
    uint48 constant MOCK_VALID_AFTER = 0;
    uint48 constant MOCK_POST_OP_GAS_OVERHEAD = 24_000;
    uint128 constant MOCK_SPONSOR_ID = 1;
    address constant MOCK_TOKEN_ADDRESS = address(0x1234);
    address constant MOCK_TOKEN_RECEIVER = address(0x5678);
    uint256 constant MOCK_TOKEN_EXCHANGE_RATE = 1e18;
    bytes constant MOCK_SIG = "0x1234";
    bytes32 constant MOCK_HASH = bytes32(0);
    address constant PAYMASTER_SIGNER =
        0xC3Bf2750F0d47098f487D45b2FB26b32eCbAf9a2;
    uint256 constant PAYMASTER_SIGNER_KEY =
        0x6a6c11c6f4703865cc4a88c6ebf0a605fdeeccd8052d66101d1d02730740a3c0;
    address constant ACCOUNT_OWNER = 0x39c0Bb04Bf6B779ac994f6A5211204e3Dbe16741;
    uint256 constant ACCOUNT_OWNER_KEY =
        0x4034df11fcc455209edcb8948449a4dff732376dab6d03dc2d099d0084b0f023;

    function setUp() public {
        entrypoint = new EntryPoint();
        paymaster = new VerifyingPaymaster(entrypoint, PAYMASTER_SIGNER, address(this));
        SimpleAccountFactory factory = new SimpleAccountFactory(entrypoint);
        account = factory.createAccount(ACCOUNT_OWNER, 0);
        mockToken = new MockERC20();
        mockToken.mint(address(account), 1000 ether);
    
        (bool success, ) = address(paymaster).call{value: 1 ether}("");
        require(success, "failed to fund paymaster");
        require(paymaster.verifyingSigner() == PAYMASTER_SIGNER, "signer not set");
    }

    function test_constructor_reverts_whenEntryPointNotAContract() public {
        vm.expectRevert();
        new VerifyingPaymaster(IEntryPoint(address(0x1234)), PAYMASTER_SIGNER, address(this));
    }

    function test_renouceOwnership_reverts() public {
        vm.expectRevert();
        paymaster.renounceOwnership();
    }

    function test_getHash_isCorrect() public view {
        PackedUserOperation memory userOp = createUserOp();
        VerifyingPaymaster.PaymasterData memory paymasterData = createPaymasterData();
        
        bytes32 hash = paymaster.getHash(
            userOp,
            paymasterData
        );
        // Replace with the expected hash value
        assertEq(
            hash,
            0xc372ec6e68f9f54f8a4aa771437e3852d647b56011383d36389782a755caa2da
        );
    }

    function test_validatePaymasterUserOp_success_whenUserOpValidSignature() public {
        PackedUserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, true, address(0), false);
        signUserOp(userOp);

        
        vm.prank(address(entrypoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, MOCK_HASH , 256);
        uint256 sigFailed = 1 & validationData;
        assertEq(sigFailed, 0, "First bit should be 0 to represent sig success");
        assertFalse(context.length == 0, "Should not be an empty context");
    }

    function test_validatePaymasterUserOp_reverts_WhenUserOpHasWrongSigner() public {
        PackedUserOperation memory userOp = createUserOp();
        VerifyingPaymaster.PaymasterData memory paymasterData = createPaymasterData();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            ACCOUNT_OWNER_KEY,
            MessageHashUtils.toEthSignedMessageHash(
                paymaster.getHash(
                    userOp,
                    paymasterData
                )
            )
        );
        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100000),
            uint128(100000),
            MOCK_VALID_UNTIL,
            MOCK_VALID_AFTER,
            MOCK_SPONSOR_ID,
            true,
            false,
            false,
            MOCK_TOKEN_ADDRESS,
            MOCK_TOKEN_RECEIVER,
            MOCK_TOKEN_EXCHANGE_RATE,
            MOCK_POST_OP_GAS_OVERHEAD,
            r,
            s,
            v
        );
        signUserOp(userOp);
        vm.prank(address(entrypoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, MOCK_HASH , 256);
        uint256 sigFailed = 1 & validationData;
        assertEq(sigFailed, 1, "First bit should be 1 to represent sig failed");
        assertEq(context.length, 0, "Should be empty context");
    }

    function test_validatePaymasterUserOp_reverts_whenUserOpHasNoSignature() public {
        PackedUserOperation memory userOp = createUserOp();
        
        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100000),
            uint128(100000),
            abi.encodePacked(
                MOCK_VALID_UNTIL,
                MOCK_VALID_AFTER,
                MOCK_SPONSOR_ID,
                true,
                false,
                false,
                MOCK_TOKEN_ADDRESS,
                MOCK_TOKEN_RECEIVER,
                MOCK_TOKEN_EXCHANGE_RATE,
                MOCK_POST_OP_GAS_OVERHEAD
            )
        );
        signUserOp(userOp);
        vm.prank(address(entrypoint));
        vm.expectRevert(abi.encodeWithSelector(VerifyingPaymaster.InvalidSignatureLength.selector));
        paymaster.validatePaymasterUserOp(userOp, MOCK_HASH , 256);
    }

    function test_validatePaymasterUserOp_reverts_whenUserOpHasInvalidSignature() public {
        PackedUserOperation memory userOp = createUserOp();
        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100000),
            uint128(100000),
            abi.encodePacked(
                MOCK_VALID_UNTIL,
                MOCK_VALID_AFTER,
                MOCK_SPONSOR_ID,
                true,
                false,
                false,
                MOCK_TOKEN_ADDRESS,
                MOCK_TOKEN_RECEIVER,
                MOCK_TOKEN_EXCHANGE_RATE,
                MOCK_POST_OP_GAS_OVERHEAD
            ),
            bytes32(0),
            bytes32(0),
            uint8(0)
        );
        signUserOp(userOp);

        vm.prank(address(entrypoint));
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignature.selector));
        paymaster.validatePaymasterUserOp(userOp, MOCK_HASH , 256);
    }

    // Non-erc20 sponsorship
    function test_entrypointHandleOps_successForStandardSponsorship() public {        
        PackedUserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, true, address(0), false);
        signUserOp(userOp);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        entrypoint.handleOps(ops, payable(address(12)));
    }

    function test_entrypointHandleOps_success_forERC20SponsorshipInPostOp() public {
        uint256 initialBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);
        PackedUserOperation memory userOp = createUserOp();
        bytes memory approveCallData = abi.encodeWithSelector(
            mockToken.approve.selector,
            paymaster,
            1 * 10**18 
        );
        bytes memory walletCallData = abi.encodeWithSelector(account.execute.selector, address(mockToken), 0, approveCallData);
        userOp.callData = walletCallData;
        addPaymasterData(userOp, true, address(mockToken), false);

        signUserOp(userOp);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        entrypoint.handleOps(ops, payable(address(12)));

        uint256 postOpBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);

        assertTrue(
            postOpBalance > initialBalance
        );
    }

    function test_entrypointHandleOps_reverts_ForERC20SponsorshipInValidationIfCantPay() public {
        PackedUserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, true, address(mockToken), true);

        signUserOp(userOp);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.expectRevert(); 
        entrypoint.handleOps(ops, payable(address(12)));
    }

    function test_entrypointHandleOps_success_ForERC20SponsorshipInValidationIfPrepaymentRequired() public {
        // First op do not sponsor 
        (bool success, ) = address(account).call{value: 1 ether}("");
        assertTrue(success);
        uint256 initialBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);
        PackedUserOperation memory userOp = createUserOp();
        bytes memory approveCallData = abi.encodeWithSelector(
            mockToken.approve.selector,
            paymaster,
            1 * 10**18 
        );
        bytes memory walletCallData = abi.encodeWithSelector(account.execute.selector, address(mockToken), 0, approveCallData);
        userOp.callData = walletCallData;

        signUserOp(userOp);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        entrypoint.handleOps(ops, payable(address(12)));

        uint256 postOpBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);

        assertTrue(
            postOpBalance == initialBalance, "postOpBalance != initial for first transfer"
        );

        // Now we pay for the op with the paymaster
        userOp = createUserOp();
        userOp.nonce = 1;
        addPaymasterData(userOp, true, address(mockToken), true);

        signUserOp(userOp);
        ops[0] = userOp;
        entrypoint.handleOps(ops, payable(address(12)));

        postOpBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);

        assertFalse(
            postOpBalance == initialBalance, "postOpBalance == initial for second op"
        );
         assertTrue(
            postOpBalance > initialBalance, "postOpBalance < initial for second op"
        );
    }

    function test_entrypointHandleOps_reverts_ifBundlerNotOnAllowlist() public {
        PackedUserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, false, address(0), false);
        signUserOp(userOp);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Simulate an invalid bundler 
        vm.expectRevert(); 
        entrypoint.handleOps(ops, payable(address(12)));
    }

    function test_entrypointHandleOps_failedERC20TransferInPostOp_DoesNotRevert() public {
        uint256 initialBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);

        PackedUserOperation memory userOp = createUserOp();
        addPaymasterData(userOp, true, address(mockToken), false);
        signUserOp(userOp);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        entrypoint.handleOps(ops, payable(address(12)));
        uint256 postOpBalance = mockToken.balanceOf(MOCK_TOKEN_RECEIVER);
        assertTrue(
            postOpBalance == initialBalance
        );
    }

    function test_receive_success() public {
        assertEq(1 ether, entrypoint.getDepositInfo(address(paymaster)).deposit);
        (bool callSuccess, ) = address(paymaster).call{value: 1 ether}("");
        require(callSuccess, "Receive failed");
        assertEq(2 ether, entrypoint.getDepositInfo(address(paymaster)).deposit);
    }


    /* Helper functions */

    function createUserOp() public view returns (PackedUserOperation memory) {
        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.accountGasLimits = bytes32(abi.encodePacked(bytes16(uint128(80000)), bytes16(uint128(50000))));
        userOp.gasFees = bytes32(abi.encodePacked(bytes16(uint128(100)), bytes16(uint128(1000000000))));
        userOp.preVerificationGas = 100000;

        return userOp;
    }

    function addPaymasterData(PackedUserOperation memory userOp, bool anyBundler, address token, bool prepay) public view {
        VerifyingPaymaster.PaymasterData memory paymasterData = createPaymasterData();
        paymasterData.allowAnyBundler = anyBundler;
        paymasterData.token = token;
        paymasterData.prepaymentRequired = prepay;

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            PAYMASTER_SIGNER_KEY,
            MessageHashUtils.toEthSignedMessageHash(
                paymaster.getHash(
                    userOp,
                    paymasterData
                )
            )
        );

        userOp.paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100000),
            uint128(100000),
            abi.encodePacked(
                paymasterData.validUntil,
                paymasterData.validAfter,
                paymasterData.sponsorUUID,
                paymasterData.allowAnyBundler,
                paymasterData.precheckBalance,
                paymasterData.prepaymentRequired,
                paymasterData.token,
                paymasterData.receiver,
                paymasterData.exchangeRate,
                paymasterData.postOpGas
            ),
            r,
            s,
            v
        );
    }

   

    function signUserOp(PackedUserOperation memory userOp) public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            ACCOUNT_OWNER_KEY,
            MessageHashUtils.toEthSignedMessageHash(entrypoint.getUserOpHash(userOp))
        );
        userOp.signature = abi.encodePacked(r, s, v);
    }

   function createPaymasterData() public pure returns (VerifyingPaymaster.PaymasterData memory) {
        return VerifyingPaymaster.PaymasterData(
            MOCK_VALID_UNTIL,
            MOCK_VALID_AFTER,
            MOCK_SPONSOR_ID,
            true,
            false,
            false,
            MOCK_TOKEN_ADDRESS,
            MOCK_TOKEN_RECEIVER,
            MOCK_TOKEN_EXCHANGE_RATE,
            MOCK_POST_OP_GAS_OVERHEAD
        );
    }
}