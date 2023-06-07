pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Muse is ERC20('MUSE', 'MUSE') {

    function VerifyMessage(bytes32 _hashedMessage, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, _hashedMessage));
        address signer = ecrecover(prefixedHashMessage, _v, _r, _s);
        return signer;
    }

    function makeHash(address user, uint256 amount) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, amount));
    }

    function checkSig(address user, uint256 amount, uint8 v, bytes32 r, bytes32 s ) public pure returns (address) {
        bytes32 _hashedMessage = keccak256(abi.encodePacked(user, amount));

        address recovered = VerifyMessage(_hashedMessage, v, r, s);

        return recovered;
    }

    function checkSigWhole(address user, uint256 amount, bytes calldata sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(sig);
        bytes32 _hashedMessage = keccak256(abi.encodePacked(user, amount));
        address recovered = VerifyMessage(_hashedMessage, v, r, s);
    }

    function checkSigNoBs(bytes32 digest, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {

        address recovered = ecrecover(digest, v, r, s);

        return recovered;
    }

    function checkDigest(address user, uint256 amount) public pure returns (bytes32, bytes32){
        bytes32 _hashedMessage = keccak256(abi.encodePacked(user, amount));
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, _hashedMessage));
        return (prefixedHashMessage, _hashedMessage);
    }

    function splitSignature(
        bytes memory sig
    ) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
        /*
        First 32 bytes stores the length of the signature

        add(sig, 32) = pointer of sig + 32
        effectively, skips first 32 bytes of signature

        mload(p) loads next 32 bytes starting at the memory address p into memory
        */

        // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
        // second 32 bytes
            s := mload(add(sig, 64))
        // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }

    function claimTokens(address server, address user, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {

        address recovered = checkSig(user, amount, v, r, s);

        require(server == recovered, 'Invalid Signature');

        _mint(user, amount);
    }
}
