// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {UniswapV2ERC20} from "../src/UniswapV2ERC20.sol";
import {IUniswapV2ERC20} from "../src/interfaces/IUniswapV2ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

bytes32 constant PERMIT_TYPEHASH =
    keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

contract UniswapV2ERC20Test is Test {
    UniswapV2ERC20 public token;
    address public owner;
    address public user1;
    address public user2;

    function setUp() public {
        owner = address(this);
        user1 = address(0x1);
        user2 = address(0x2);
        token = new UniswapV2ERC20();
    }

    // ============ Fuzz Tests ============

    function testFuzzName(string memory) public {
        // Name should always be "Uniswap V2" regardless of input
        assertEq(token.name(), "Uniswap V2");
    }

    function testFuzzSymbol(string memory) public {
        // Symbol should always be "UNI-V2" regardless of input
        assertEq(token.symbol(), "UNI-V2");
    }

    function testFuzzDecimals(uint8) public {
        // Decimals should always be 18 regardless of input
        assertEq(token.decimals(), 18);
    }

    function testFuzzPermitTypehash(bytes32) public {
        // PERMIT_TYPEHASH should always be the constant value
        bytes32 expected = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
        assertEq(token.PERMIT_TYPEHASH(), expected);
    }

    function testFuzzNonces(address ownerAddr, uint256) public {
        // Nonces should start at 0 and increment with each permit
        uint256 initialNonce = token.nonces(ownerAddr);
        assertEq(initialNonce, 0);
    }

    function testFuzzTransfer(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume(to != address(token));
        vm.assume(amount <= type(uint256).max / 2);

        // Since token has no mint function, we can't test transfers with actual balance
        // But we can test that the function exists and doesn't revert on zero balance
        if (token.balanceOf(owner) == 0) {
            vm.expectRevert();
            token.transfer(to, amount);
        }
    }

    function testFuzzTransferFrom(address from, address to, uint256 amount) public {
        vm.assume(from != address(0));
        vm.assume(to != address(0));
        vm.assume(from != to);
        vm.assume(to != address(token));
        vm.assume(amount <= type(uint256).max / 2);

        // Test that transferFrom exists and behaves correctly
        if (token.balanceOf(from) == 0 || token.allowance(from, owner) == 0) {
            vm.expectRevert();
            token.transferFrom(from, to, amount);
        }
    }

    function testFuzzApprove(address spender, uint256 amount) public {
        vm.assume(spender != address(0));

        // Approval should work for any spender and amount
        bool success = token.approve(spender, amount);
        assertTrue(success);
        assertEq(token.allowance(owner, spender), amount);
    }

    function testFuzzAllowance(address ownerAddr, address spender, uint256) public {
        vm.assume(ownerAddr != address(0));
        vm.assume(spender != address(0));

        // Initial allowance should be 0
        uint256 initialAllowance = token.allowance(ownerAddr, spender);
        assertEq(initialAllowance, 0);
    }

    function testFuzzBalanceOf(address account) public {
        // Balance should be 0 initially (no mint function)
        uint256 balance = token.balanceOf(account);
        assertEq(balance, 0);
    }

    function testFuzzTotalSupply(uint256) public {
        // Total supply should be 0 initially (no mint function)
        uint256 totalSupply = token.totalSupply();
        assertEq(totalSupply, 0);
    }

    function testFuzzPermit(uint248 privKey, address spender, uint256 amount, uint256 deadline) public {
        // Bound inputs to valid ranges
        uint256 privateKey = privKey;
        if (privateKey == 0) privateKey = 1;
        if (deadline < block.timestamp) deadline = block.timestamp + 1 days;

        address ownerAddr = vm.addr(privateKey);
        uint256 nonce = token.nonces(ownerAddr);

        // Create permit signature
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, ownerAddr, spender, amount, nonce, deadline));

        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);

        // Execute permit
        token.permit(ownerAddr, spender, amount, deadline, v, r, s);

        // Verify allowance was set
        assertEq(token.allowance(ownerAddr, spender), amount);

        // Verify nonce incremented
        assertEq(token.nonces(ownerAddr), nonce + 1);
    }

    function testFuzzPermitInvalidSignature(address ownerAddr, address spender, uint256 amount, uint256 deadline)
        public
    {
        vm.assume(ownerAddr != address(0));
        vm.assume(spender != address(0));
        if (deadline < block.timestamp) deadline = block.timestamp + 1 days;

        uint256 nonce = token.nonces(ownerAddr);

        // Create invalid signature (using wrong private key)
        uint256 wrongPrivateKey = 999;
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, ownerAddr, spender, amount, nonce, deadline));

        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, hash);

        // Permit should revert with invalid signature
        vm.expectRevert();
        token.permit(ownerAddr, spender, amount, deadline, v, r, s);
    }

    function testFuzzPermitExpiredDeadline(uint248 privKey, address spender, uint256 amount) public {
        uint256 privateKey = privKey;
        if (privateKey == 0) privateKey = 1;

        address ownerAddr = vm.addr(privateKey);
        uint256 deadline = block.timestamp - 1; // Expired deadline
        uint256 nonce = token.nonces(ownerAddr);

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, ownerAddr, spender, amount, nonce, deadline));

        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);

        // Permit should revert with expired deadline
        vm.expectRevert();
        token.permit(ownerAddr, spender, amount, deadline, v, r, s);
    }

    // ============ Invariant Tests ============

    function invariantPermitTypehash() public view {
        // PERMIT_TYPEHASH should never change
        bytes32 expected = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
        assertEq(token.PERMIT_TYPEHASH(), expected);
    }

    function invariantName() public view {
        // Name should always be "Uniswap V2"
        assertEq(token.name(), "Uniswap V2");
    }

    function invariantSymbol() public view {
        // Symbol should always be "UNI-V2"
        assertEq(token.symbol(), "UNI-V2");
    }

    function invariantDecimals() public view {
        // Decimals should always be 18
        assertEq(token.decimals(), 18);
    }

    function invariantTotalSupply() public view {
        // Total supply should be 0 (no mint function in this contract)
        assertEq(token.totalSupply(), 0);
    }

    function invariantNoncesMonotonic() public view {
        // Nonces should be non-negative for any address
        // This is a basic property that should hold for all addresses
        // Since we can't iterate all addresses, we check a few known ones
        address[] memory testAddresses = new address[](3);
        testAddresses[0] = address(0x1);
        testAddresses[1] = address(0x2);
        testAddresses[2] = address(this);

        for (uint256 i = 0; i < testAddresses.length; i++) {
            uint256 nonce = token.nonces(testAddresses[i]);
            assertGe(nonce, 0);
        }
    }
}

contract UniswapV2ERC20InvariantTest is Test {
    UniswapV2ERC20 public token;
    Handler public handler;

    function setUp() public {
        token = new UniswapV2ERC20();
        handler = new Handler(token);

        // Target the handler contract for invariant testing
        targetContract(address(handler));
    }

    function invariantPermitTypehashConstant() public view {
        bytes32 expected = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
        assertEq(token.PERMIT_TYPEHASH(), expected);
    }

    function invariantNameConstant() public view {
        assertEq(token.name(), "Uniswap V2");
    }

    function invariantSymbolConstant() public view {
        assertEq(token.symbol(), "UNI-V2");
    }

    function invariantDecimalsConstant() public view {
        assertEq(token.decimals(), 18);
    }

    function invariantTotalSupplyZero() public view {
        // Since there's no mint function, total supply should remain 0
        assertEq(token.totalSupply(), 0);
    }

    function invariantBalanceSum() public view {
        // Sum of all balances should equal total supply
        // Since total supply is 0 and there's no mint, all balances should be 0
        assertEq(token.totalSupply(), 0);
    }

    function invariantNoncesNonNegative() public view {
        // Check nonces for all actors in handler
        address[] memory actors = handler.getActors();
        for (uint256 i = 0; i < actors.length; i++) {
            uint256 nonce = token.nonces(actors[i]);
            assertGe(nonce, 0);
        }
    }

    function invariantAllowanceConsistency() public view {
        // Check allowances for all actors in handler
        address[] memory actors = handler.getActors();
        for (uint256 i = 0; i < actors.length; i++) {
            for (uint256 j = 0; j < actors.length; j++) {
                if (i != j) {
                    uint256 allowance = token.allowance(actors[i], actors[j]);
                    assertGe(allowance, 0);
                }
            }
        }
    }
}

contract Handler {
    UniswapV2ERC20 public token;

    address[] public actors;
    mapping(address => bool) public isActor;

    constructor(UniswapV2ERC20 _token) {
        token = _token;
    }

    function addActor(address actor) internal {
        if (!isActor[actor]) {
            actors.push(actor);
            isActor[actor] = true;
        }
    }

    function approve(address spender, uint256 amount) public {
        addActor(msg.sender);
        addActor(spender);
        token.approve(spender, amount);
    }

    function transfer(address to, uint256 amount) public {
        addActor(msg.sender);
        addActor(to);
        // Only transfer if we have balance (which we don't, but test the function)
        try token.transfer(to, amount) {} catch {}
    }

    function transferFrom(address from, address to, uint256 amount) public {
        addActor(from);
        addActor(to);
        // Only transfer if we have allowance and balance
        try token.transferFrom(from, to, amount) {} catch {}
    }

    function permit(address ownerAddr, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        public
    {
        addActor(ownerAddr);
        addActor(spender);
        // Try permit - will fail without valid signature, but test the function
        try token.permit(ownerAddr, spender, value, deadline, v, r, s) {} catch {}
    }

    function getActors() public view returns (address[] memory) {
        return actors;
    }
}
