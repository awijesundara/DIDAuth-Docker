import { expect } from "chai";
import { ethers } from "hardhat";
import { DIDRegistry } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

function b32(s: string): string {
  return ethers.encodeBytes32String(s);
}

describe("DIDRegistry", () => {
  let registry: DIDRegistry;
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;

  beforeEach(async () => {
    [owner, attacker] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("DIDRegistry", owner);
    registry = (await Factory.deploy()) as unknown as DIDRegistry;
    await registry.waitForDeployment();
  });

  it("sets the deployer as owner", async () => {
    expect(await registry.owner()).to.equal(owner.address);
  });

  describe("access control", () => {
    it("rejects registerDID from a non-owner", async () => {
      await expect(
        registry.connect(attacker).registerDID(b32("did"), b32("cid"))
      ).to.be.revertedWith("not owner");
    });

    it("rejects recordVC from a non-owner", async () => {
      await expect(
        registry.connect(attacker).recordVC(b32("vc1"), b32("did"), b32("cid"))
      ).to.be.revertedWith("not owner");
    });

    it("rejects revokeVC from a non-owner", async () => {
      await registry.connect(owner).recordVC(b32("vc1"), b32("did"), b32("cid"));
      await expect(
        registry.connect(attacker).revokeVC(b32("vc1"))
      ).to.be.revertedWith("not owner");
    });

    it("rejects transferOwnership from a non-owner", async () => {
      await expect(
        registry.connect(attacker).transferOwnership(attacker.address)
      ).to.be.revertedWith("not owner");
    });

    it("allows the owner to transfer ownership and updates access", async () => {
      await registry.connect(owner).transferOwnership(attacker.address);
      expect(await registry.owner()).to.equal(attacker.address);
      // old owner can no longer write
      await expect(
        registry.connect(owner).registerDID(b32("did"), b32("cid"))
      ).to.be.revertedWith("not owner");
      // new owner can
      await expect(registry.connect(attacker).registerDID(b32("did"), b32("cid")))
        .to.emit(registry, "RegisteredDID");
    });

    it("rejects transferring ownership to the zero address", async () => {
      await expect(
        registry.connect(owner).transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWith("zero address");
    });
  });

  describe("DID registration", () => {
    it("stores the did doc cid and emits an event", async () => {
      await expect(registry.registerDID(b32("did:web:example.org"), b32("cid1")))
        .to.emit(registry, "RegisteredDID")
        .withArgs(b32("did:web:example.org"), b32("cid1"));
      expect(await registry.didCid(b32("did:web:example.org"))).to.equal(b32("cid1"));
    });
  });

  describe("VC lifecycle", () => {
    const vcId = b32("vc1");
    const issuerDid = b32("did:web:example.org");
    const cid = b32("cid1");

    it("records a VC once", async () => {
      await expect(registry.recordVC(vcId, issuerDid, cid))
        .to.emit(registry, "RecordedVC")
        .withArgs(vcId, issuerDid, cid);
      expect(await registry.isVCRecorded(vcId)).to.equal(true);
      expect(await registry.isVCRevoked(vcId)).to.equal(false);
      expect(await registry.getVCIssuer(vcId)).to.equal(issuerDid);
    });

    it("rejects recording the same vcId twice", async () => {
      await registry.recordVC(vcId, issuerDid, cid);
      await expect(registry.recordVC(vcId, issuerDid, cid)).to.be.revertedWith(
        "already recorded"
      );
    });

    it("rejects revoking an unrecorded vcId", async () => {
      await expect(registry.revokeVC(vcId)).to.be.revertedWith("not recorded");
    });

    it("revokes a recorded VC and rejects double revocation", async () => {
      await registry.recordVC(vcId, issuerDid, cid);
      await expect(registry.revokeVC(vcId)).to.emit(registry, "RevokedVC").withArgs(vcId);
      expect(await registry.isVCRevoked(vcId)).to.equal(true);
      await expect(registry.revokeVC(vcId)).to.be.revertedWith("already revoked");
    });

    it("rejects querying the issuer of an unrecorded vcId", async () => {
      await expect(registry.getVCIssuer(vcId)).to.be.revertedWith("not recorded");
    });

    it("reports unrecorded VCs as not recorded and not revoked", async () => {
      expect(await registry.isVCRecorded(vcId)).to.equal(false);
      expect(await registry.isVCRevoked(vcId)).to.equal(false);
    });
  });
});
