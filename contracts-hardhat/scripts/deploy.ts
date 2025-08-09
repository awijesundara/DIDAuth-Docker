import { ethers } from "hardhat";

async function main() {
  const Factory = await ethers.getContractFactory("DIDRegistry");
  const c = await Factory.deploy();
  await c.waitForDeployment();
  console.log("DIDRegistry:", await c.getAddress());
}
main().catch((e) => { console.error(e); process.exit(1); });
