#!/usr/bin/env python3
"""
Deploy and Test EmailThreatRegistry on Monad Testnet (Chain ID 10143)
Usage:
    python scripts/deploy_monad.py --private-key 0x...
"""

import sys
import os
import argparse
import json

# Monad Testnet Specs
MONAD_RPC_URL = "https://rpc.testnet.monad.xyz"
MONAD_CHAIN_ID = 10143
MONAD_EXPLORER_URL = "https://testnet.monadscan.com"

def check_rpc():
    print("=" * 60)
    print(f"Connecting to Monad Testnet ({MONAD_RPC_URL})...")
    print(f"Chain ID: {MONAD_CHAIN_ID}")
    print(f"Block Explorer: {MONAD_EXPLORER_URL}")
    print("=" * 60)

    try:
        import urllib.request
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        }).encode("utf-8")
        req = urllib.request.Request(MONAD_RPC_URL, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as response:
            res = json.loads(response.read().decode())
            block_hex = res.get("result")
            block_num = int(block_hex, 16) if block_hex else 0
            print(f"[SUCCESS] Connected to Monad Testnet! Latest Block: #{block_num}")
            return True
    except Exception as e:
        print(f"[ERROR] Could not reach Monad RPC: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Monad Testnet Checker & Deployer")
    parser.add_argument("--private-key", help="EVM Private key with testnet MON tokens")
    parser.add_argument("--test-hash", default="0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", help="Test SHA-256 hash")
    args = parser.parse_args()

    connected = check_rpc()
    if not connected:
        sys.exit(1)

    print("\nSmart Contract location:")
    print("  -> contracts/EmailThreatRegistry.sol")
    print("\nTo deploy via Remix (simplest):")
    print("  1. Open https://remix.ethereum.org")
    print("  2. Paste contracts/EmailThreatRegistry.sol")
    print("  3. Set network in MetaMask to Monad Testnet (RPC: https://rpc.testnet.monad.xyz, Chain: 10143)")
    print("  4. Select Injected Provider in Remix and click Deploy!")
    print(f"  5. View transaction on {MONAD_EXPLORER_URL}")

if __name__ == "__main__":
    main()
