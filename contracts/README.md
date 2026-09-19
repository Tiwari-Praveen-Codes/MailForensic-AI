# Monad Testnet Blockchain Integration & Deployment Guide

This project includes on-chain forensic threat logging and verification on **Monad Testnet** (Chain ID: `10143`), fulfilling the **AICTE PS-106: Blockchain & Cybersecurity** track requirement for Smart India Hackathon.

---

## 1. Monad Testnet Specifications

| Parameter | Value |
|-----------|-------|
| **Network Name** | Monad Testnet |
| **Chain ID** | `10143` |
| **RPC URL** | `https://rpc.testnet.monad.xyz` |
| **Currency Symbol** | `MON` |
| **Block Explorer** | [https://testnet.monadscan.com](https://testnet.monadscan.com) |

---

## 2. Setting Up Your Wallet (MetaMask / Rabby / Phantom)

1. Open your Web3 wallet (e.g. MetaMask).
2. Go to **Settings** > **Networks** > **Add a network manually**.
3. Enter the network details:
   - **Network Name**: `Monad Testnet`
   - **New RPC URL**: `https://rpc.testnet.monad.xyz`
   - **Chain ID**: `10143`
   - **Currency Symbol**: `MON`
   - **Block Explorer URL**: `https://testnet.monadscan.com`
4. Save and switch to the **Monad Testnet** network.

---

## 3. Getting Free Monad Testnet Tokens (Faucet)

1. Visit the Monad Testnet faucet portal: [https://testnet.monad.xyz](https://testnet.monad.xyz)
2. Connect your wallet or paste your public EVM address (`0x...`).
3. Click **"Get Testnet Tokens"**.
4. You will receive testnet `MON` tokens to cover transaction gas fees.

---

## 4. Deploying the Smart Contract (`EmailThreatRegistry.sol`)

The smart contract is located at [`contracts/EmailThreatRegistry.sol`](./EmailThreatRegistry.sol).

### Option A: Deploy via Remix IDE (Recommended & Fastest - No CLI needed)

1. Open **[Remix IDE](https://remix.ethereum.org)** in your browser.
2. In the file explorer, create a new file named `EmailThreatRegistry.sol`.
3. Copy the entire contents of [`contracts/EmailThreatRegistry.sol`](./EmailThreatRegistry.sol) and paste it into Remix.
4. On the left navigation, click the **Solidity Compiler** tab:
   - Select compiler version `0.8.20` or higher.
   - Click **Compile EmailThreatRegistry.sol**.
5. Click the **Deploy & Run Transactions** tab:
   - Change **Environment** from `Remix VM` to **`Injected Provider - MetaMask`**.
   - Make sure your MetaMask network is set to **Monad Testnet (Chain ID 10143)**.
   - Select contract `EmailThreatRegistry`.
   - Click **Deploy** and confirm the transaction in MetaMask.
6. Once mined (usually < 1 second on Monad!), copy your deployed contract address (e.g. `0x123...abc`).
7. View your contract live on **[MonadScan Testnet](https://testnet.monadscan.com)** by pasting the contract address.

---

### Option B: Deploy via Hardhat

```bash
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox dotenv
```

In `hardhat.config.js`:
```javascript
require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

module.exports = {
  solidity: "0.8.20",
  networks: {
    monadTestnet: {
      url: "https://rpc.testnet.monad.xyz",
      chainId: 10143,
      accounts: process.env.MONAD_PRIVATE_KEY ? [process.env.MONAD_PRIVATE_KEY] : []
    }
  }
};
```

Run deployment:
```bash
npx hardhat run scripts/deploy.js --network monadTestnet
```

---

### Option C: Deploy via Python Web3 Script

Run the automated Python deployment script:
```bash
# Set your private key in .env or pass it:
python scripts/deploy_monad.py --private-key 0xYOUR_TESTNET_PRIVATE_KEY
```

---

## 5. Connecting Contract to Mailforensic AI

In your project `.env` file:
```env
MONAD_RPC_URL=https://rpc.testnet.monad.xyz
MONAD_CHAIN_ID=10143
MONAD_CONTRACT_ADDRESS=0xa898e4C6FF1060cA00B4747B1d7343c86C724C2a
MONAD_ADMIN_ADDRESS=0xa898e4C6FF1060cA00B4747B1d7343c86C724C2a
# MONAD_PRIVATE_KEY=0xYOUR_PRIVATE_KEY_FOR_AUTOMATED_REPORTING
```

Once configured, the system automatically:
1. Calculates SHA-256 cryptographic hashes for scanned malicious emails.
2. Commits threat intelligence, risk scores, sender domains, and report hashes to Monad Testnet.
3. Provides one-click verification links on **MonadScan**.
