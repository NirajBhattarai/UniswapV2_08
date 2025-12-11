// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IUniswapV2Pair} from "./interfaces/IUniswapV2Pair.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {UniswapV2ERC20} from "./UniswapV2ERC20.sol";
import {Math} from "./libraries/Math.sol";

contract UniswapV2Pair is IUniswapV2Pair, UniswapV2ERC20 {
    address public token0;
    address public token1;

    uint112 private reserve0; // uses single storage slot, accessible via getReserves
    uint112 private reserve1; // uses single storage slot, accessible via getReserves
    uint32 private blockTimestampLast; // uses single storage slot, accessible via getReserves

    constructor(address _token0, address _token1) {
        token0 = _token0;
        token1 = _token1;
    }

    function getReserves() public view returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast) {
        _reserve0 = reserve0;
        _reserve1 = reserve1;
        _blockTimestampLast = blockTimestampLast;
    }

    function mint(address to) external returns (uint256 liquidity) {
        // 10000
        // fetch reserve amounts
        (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings

        // get amounts of token0 and token1 held by this contract
        uint256 balance0 = IERC20(token0).balanceOf(address(this));
        uint256 balance1 = IERC20(token1).balanceOf(address(this));

        uint256 amount0 = balance0 - _reserve0;
        uint256 amount1 = balance1 - _reserve1;

        uint256 _totalSupply = totalSupply;

        if (_totalSupply == 0) {
            liquidity = Math.sqrt(amount0 * amount1);
        } else {
            liquidity = Math.min(amount0 * _totalSupply / _reserve0, amount1 * _totalSupply / _reserve1);
        }
        _mint(to, liquidity);
        return 0;
    }

    function price0CumulativeLast() external view returns (uint256) {
        return 0;
    }

    function price1CumulativeLast() external view returns (uint256) {
        return 0;
    }

    function kLast() external view returns (uint256) {
        return 0;
    }
}
