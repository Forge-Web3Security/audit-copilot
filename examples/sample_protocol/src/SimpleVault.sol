// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SimpleVault {
    IERC20 public asset;
    address public owner;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public lastClaim;
    uint256 public rewardRate;

    event Deposit(address indexed user, uint256 amount, uint256 mintedShares);
    event Withdraw(address indexed user, uint256 sharesBurned, uint256 amountOut);
    event Claim(address indexed user, uint256 amount);

    constructor(IERC20 _asset) {
        asset = _asset;
        owner = msg.sender;
        rewardRate = 1e18;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setRewardRate(uint256 newRate) external onlyOwner {
        rewardRate = newRate;
    }

    function deposit(uint256 amount) external {
        uint256 assetsBefore = asset.balanceOf(address(this));
        require(asset.transferFrom(msg.sender, address(this), amount), "transfer failed");
        uint256 minted = totalShares == 0 ? amount : (amount * totalShares) / assetsBefore;
        shares[msg.sender] += minted;
        totalShares += minted;
        emit Deposit(msg.sender, amount, minted);
    }

    function withdraw(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "too many shares");
        uint256 amountOut = (asset.balanceOf(address(this)) * shareAmount) / totalShares;
        require(asset.transfer(msg.sender, amountOut), "transfer failed");
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        emit Withdraw(msg.sender, shareAmount, amountOut);
    }

    function claimRewards() external {
        uint256 elapsed = block.timestamp - lastClaim[msg.sender];
        uint256 amount = elapsed * rewardRate * shares[msg.sender] / 1e18;
        lastClaim[msg.sender] = block.timestamp;
        require(asset.transfer(msg.sender, amount), "transfer failed");
        emit Claim(msg.sender, amount);
    }
}
