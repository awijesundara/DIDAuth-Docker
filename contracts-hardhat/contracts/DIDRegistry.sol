// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title Contract-bound VC registry for container images
contract DIDRegistry {
    struct VCRecord {
        bytes32 issuerDid;
        bool recorded;
        bool revoked;
    }

    mapping(bytes32 => VCRecord) private records;

    event RegisteredDID(bytes32 indexed issuerDid, bytes32 didCid);
    event RecordedVC(bytes32 indexed vcId, bytes32 issuerDid, bytes32 ipfsCid);
    event RevokedVC(bytes32 indexed vcId);

    mapping(bytes32 => bytes32) public didCid;

    function registerDID(bytes32 issuerDid, bytes32 didDocCid) external {
        didCid[issuerDid] = didDocCid;
        emit RegisteredDID(issuerDid, didDocCid);
    }

    function recordVC(bytes32 vcId, bytes32 issuerDid, bytes32 ipfsCid) external {
        VCRecord storage r = records[vcId];
        require(!r.recorded, "already recorded");
        r.issuerDid = issuerDid;
        r.recorded = true;
        r.revoked = false;
        emit RecordedVC(vcId, issuerDid, ipfsCid);
    }

    function revokeVC(bytes32 vcId) external {
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
