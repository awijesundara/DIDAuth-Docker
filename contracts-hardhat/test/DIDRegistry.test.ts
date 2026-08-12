import { expect } from "chai";
import { ethers } from "hardhat";

const h = (value: string) => ethers.keccak256(ethers.toUtf8Bytes(value));

describe("DIDRegistry", () => {
  async function fixture() {
    const [deployer, maintainer, delegate, attacker] = await ethers.getSigners();
    const registry = await ethers.deployContract("DIDRegistry", [], deployer);
    await registry.waitForDeployment();
    const did = h("did:key:zMaintainer");
    const didCid = h("bafy-did-document");
    await registry.connect(maintainer).registerDID(did, didCid);
    return { registry, deployer, maintainer, delegate, attacker, did, didCid };
  }

  it("registers a DID Document under the caller's control", async () => {
    const { registry, maintainer, did, didCid } = await fixture();
    expect(await registry.didCid(did)).to.equal(didCid);
    expect(await registry.didOwner(did)).to.equal(maintainer.address);
    expect(await registry.isDIDRegistered(did)).to.equal(true);
  });

  it("allows only the DID owner to update its document", async () => {
    const { registry, maintainer, attacker, did } = await fixture();
    await expect(registry.connect(attacker).registerDID(did, h("replacement")))
      .to.be.revertedWith("not DID owner");
    await expect(registry.connect(maintainer).registerDID(did, h("replacement")))
      .to.emit(registry, "DIDDocumentUpdated");
  });

  it("records and revokes a VC only through its DID controller", async () => {
    const { registry, maintainer, attacker, did } = await fixture();
    const vcId = h("vc");
    await expect(registry.connect(attacker).recordVC(vcId, did, h("cid")))
      .to.be.revertedWith("not DID controller");
    await expect(registry.connect(maintainer).recordVC(vcId, did, h("cid")))
      .to.emit(registry, "VCRecorded");
    expect(await registry.isVCValid(vcId)).to.equal(true);
    await expect(registry.connect(attacker).revokeVC(vcId))
      .to.be.revertedWith("not DID controller");
    await registry.connect(maintainer).revokeVC(vcId);
    expect(await registry.isVCValid(vcId)).to.equal(false);
  });

  it("supports explicit delegates and batch recording", async () => {
    const { registry, maintainer, delegate, did } = await fixture();
    await registry.connect(maintainer).setDelegate(did, delegate.address, true);
    const ids = [h("vc-1"), h("vc-2")];
    await registry.connect(delegate).batchRecordVC(ids, did, [h("cid-1"), h("cid-2")]);
    expect(await registry.isVCRecorded(ids[0])).to.equal(true);
    expect(await registry.getVCIssuer(ids[1])).to.equal(did);
  });

  it("prevents duplicate recording and revocation", async () => {
    const { registry, maintainer, did } = await fixture();
    const vcId = h("vc");
    await registry.connect(maintainer).recordVC(vcId, did, h("cid"));
    await expect(registry.connect(maintainer).recordVC(vcId, did, h("cid")))
      .to.be.revertedWith("already recorded");
    await registry.connect(maintainer).revokeVC(vcId);
    await expect(registry.connect(maintainer).revokeVC(vcId))
      .to.be.revertedWith("already revoked");
  });
});
