import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";
dotenv.config();

// Only wire up the live network when its secrets are actually present, so
// that `hardhat compile` / `hardhat test` keep working in fresh checkouts
// and CI where no .env file exists.
const arbitrumSepoliaRpc = process.env.ARBITRUM_SEPOLIA_RPC;
const deployerPk = process.env.DEPLOYER_PK;

const config: HardhatUserConfig = {
  solidity: "0.8.21",
  networks: {
    ...(arbitrumSepoliaRpc && deployerPk
      ? {
          arbitrumSepolia: {
            url: arbitrumSepoliaRpc,
            accounts: [deployerPk],
          },
        }
      : {}),
  },
};
export default config;
