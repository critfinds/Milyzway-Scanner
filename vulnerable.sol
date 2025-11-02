pragma solidity ^0.8.0;

contract Vulnerable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() public {
        payable(owner).transfer(address(this).balance);
    }
}
