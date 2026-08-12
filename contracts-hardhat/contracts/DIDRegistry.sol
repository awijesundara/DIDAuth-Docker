// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

/// @title CBC-Provenance DID and Verifiable Credential Registry
/// @notice Anchors DID Documents and the lifecycle of contract-bound OCI VCs.
contract DIDRegistry {
    struct DIDRecord {
        bytes32 documentCid;
        address owner;
        bool registered;
    }

    struct VCRecord {
        bytes32 issuerDid;
        bytes32 ipfsCid;
        uint64 issuanceTimestamp;
        bool recorded;
        bool revoked;
    }

    address public owner;
    mapping(bytes32 => DIDRecord) private dids;
    mapping(bytes32 => mapping(address => bool)) public delegates;
    mapping(bytes32 => VCRecord) private records;

    event DIDRegistered(bytes32 indexed issuerDid, bytes32 documentCid, address indexed didOwner);
    event DIDDocumentUpdated(bytes32 indexed issuerDid, bytes32 documentCid);
    event DelegateUpdated(bytes32 indexed issuerDid, address indexed delegate, bool authorized);
    event VCRecorded(bytes32 indexed vcId, bytes32 indexed issuerDid, bytes32 ipfsCid, uint64 issuanceTimestamp);
    event VCRevoked(bytes32 indexed vcId, bytes32 indexed issuerDid, uint64 revokedAt);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "not contract owner");
        _;
    }

    modifier onlyDIDController(bytes32 issuerDid) {
        DIDRecord storage d = dids[issuerDid];
        require(d.registered, "DID not registered");
        require(msg.sender == d.owner || delegates[issuerDid][msg.sender], "not DID controller");
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

    function registerDID(bytes32 issuerDid, bytes32 documentCid) external {
        require(issuerDid != bytes32(0) && documentCid != bytes32(0), "zero value");
        DIDRecord storage d = dids[issuerDid];
        if (!d.registered) {
            d.owner = msg.sender;
            d.registered = true;
            d.documentCid = documentCid;
            emit DIDRegistered(issuerDid, documentCid, msg.sender);
        } else {
            require(msg.sender == d.owner, "not DID owner");
            d.documentCid = documentCid;
            emit DIDDocumentUpdated(issuerDid, documentCid);
        }
    }

    function setDelegate(bytes32 issuerDid, address delegate, bool authorized)
        external onlyDIDController(issuerDid)
    {
        require(delegate != address(0), "zero address");
        delegates[issuerDid][delegate] = authorized;
        emit DelegateUpdated(issuerDid, delegate, authorized);
    }

    function recordVC(bytes32 vcId, bytes32 issuerDid, bytes32 ipfsCid)
        public onlyDIDController(issuerDid)
    {
        require(vcId != bytes32(0) && ipfsCid != bytes32(0), "zero value");
        require(!records[vcId].recorded, "already recorded");
        records[vcId] = VCRecord(issuerDid, ipfsCid, uint64(block.timestamp), true, false);
        emit VCRecorded(vcId, issuerDid, ipfsCid, uint64(block.timestamp));
    }

    function batchRecordVC(bytes32[] calldata vcIds, bytes32 issuerDid, bytes32[] calldata ipfsCids)
        external onlyDIDController(issuerDid)
    {
        require(vcIds.length > 0 && vcIds.length == ipfsCids.length, "length mismatch");
        for (uint256 i = 0; i < vcIds.length; i++) {
            recordVC(vcIds[i], issuerDid, ipfsCids[i]);
        }
    }

    function revokeVC(bytes32 vcId) external {
        VCRecord storage r = records[vcId];
        require(r.recorded, "not recorded");
        DIDRecord storage d = dids[r.issuerDid];
        require(msg.sender == d.owner || delegates[r.issuerDid][msg.sender], "not DID controller");
        require(!r.revoked, "already revoked");
        r.revoked = true;
        emit VCRevoked(vcId, r.issuerDid, uint64(block.timestamp));
    }

    function didCid(bytes32 issuerDid) external view returns (bytes32) { return dids[issuerDid].documentCid; }
    function didOwner(bytes32 issuerDid) external view returns (address) { return dids[issuerDid].owner; }
    function isDIDRegistered(bytes32 issuerDid) external view returns (bool) { return dids[issuerDid].registered; }
    function isVCRecorded(bytes32 vcId) external view returns (bool) { return records[vcId].recorded; }
    function isVCRevoked(bytes32 vcId) external view returns (bool) { return records[vcId].revoked; }
    function isVCValid(bytes32 vcId) external view returns (bool) { return records[vcId].recorded && !records[vcId].revoked; }
    function getVCIssuer(bytes32 vcId) external view returns (bytes32) {
        require(records[vcId].recorded, "not recorded");
        return records[vcId].issuerDid;
    }
    function getVCRecord(bytes32 vcId) external view returns (VCRecord memory) { return records[vcId]; }
}
