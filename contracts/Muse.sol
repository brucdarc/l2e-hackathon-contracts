// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Muse is ERC20('MUSE', 'MUSE') {

    mapping(uint256 => bool) consumedNonces;

    address approvedServer = 0x24f597d211E487814fAA990dcD4699dB678Fb011;

    function VerifyMessage(bytes32 _hashedMessage, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, _hashedMessage));
        address signer = ecrecover(prefixedHashMessage, _v, _r, _s);
        return signer;
    }

    function checkSig(address user, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s ) public pure returns (address) {
        bytes32 _hashedMessage = keccak256(abi.encodePacked(user, amount, nonce));

        address recovered = VerifyMessage(_hashedMessage, v, r, s);

        return recovered;
    }

    function claimTokens(address user, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) public {

        require(!consumedNonces[nonce], 'Signature already used');

        consumedNonces[nonce] = true;

        address recovered = checkSig(user, amount, nonce, v, r, s);

        require(approvedServer == recovered, 'Invalid Signature');

        //1 token per hour of listening time
        _mint(user, amount * 1e18 / 3600000);
    }
}
