// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Contract-bound VC registry for container images
/// @notice Write operations are restricted to the contract owner (the issuer
/// service's deployer key). Without this restriction any address could
/// register arbitrary DIDs, front-run legitimate VC recordings, or revoke
/// VCs it does not own, which would let an attacker deny service to the
/// real issuer or forge issuer attribution for a given vcId.
contract DIDRegistry {
    struct VCRecord {
        bytes32 issuerDid;
        bool recorded;
        bool revoked;
    }

    address public owner;

    mapping(bytes32 => VCRecord) private records;

    event RegisteredDID(bytes32 indexed issuerDid, bytes32 didCid);
    event RecordedVC(bytes32 indexed vcId, bytes32 issuerDid, bytes32 ipfsCid);
    event RevokedVC(bytes32 indexed vcId);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    mapping(bytes32 => bytes32) public didCid;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function registerDID(bytes32 issuerDid, bytes32 didDocCid) external onlyOwner {
        didCid[issuerDid] = didDocCid;
        emit RegisteredDID(issuerDid, didDocCid);
    }

    function recordVC(bytes32 vcId, bytes32 issuerDid, bytes32 ipfsCid) external onlyOwner {
        VCRecord storage r = records[vcId];
        require(!r.recorded, "already recorded");
        r.issuerDid = issuerDid;
        r.recorded = true;
        r.revoked = false;
        emit RecordedVC(vcId, issuerDid, ipfsCid);
    }

    function revokeVC(bytes32 vcId) external onlyOwner {
        VCRecord storage r = records[vcId];
        require(r.recorded, "not recorded");
        require(!r.revoked, "already revoked");
        r.revoked = true;
        emit RevokedVC(vcId);
    }

    function isVCRecorded(bytes32 vcId) external view returns (bool) {
        return records[vcId].recorded;
    }

    function isVCRevoked(bytes32 vcId) external view returns (bool) {
        return records[vcId].revoked;
    }

    function getVCIssuer(bytes32 vcId) external view returns (bytes32) {
        require(records[vcId].recorded, "not recorded");
        return records[vcId].issuerDid;
    }
}
