"""
Monad Testnet Blockchain Service
Author: Praveen Tiwari
Handles on-chain forensic logging, threat verification, and immutable audit trails
on Monad EVM Testnet (Chain ID: 10143).
"""

import os
import hashlib
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Monad Testnet Defaults (as per official network specs)
DEFAULT_MONAD_RPC = os.getenv("MONAD_RPC_URL", "https://rpc.testnet.monad.xyz")
MONAD_CHAIN_ID = int(os.getenv("MONAD_CHAIN_ID", "10143"))
MONAD_EXPLORER_URL = os.getenv("MONAD_EXPLORER_URL", "https://testnet.monadscan.com")

# ABI for EmailThreatRegistry
EMAIL_THREAT_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "_emailHash", "type": "bytes32"},
            {"internalType": "string", "name": "_senderDomain", "type": "string"},
            {"internalType": "string", "name": "_threatType", "type": "string"},
            {"internalType": "uint8", "name": "_riskScore", "type": "uint8"},
            {"internalType": "string", "name": "_ipfsReportHash", "type": "string"},
            {"internalType": "string", "name": "_originIp", "type": "string"}
        ],
        "name": "recordThreat",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "_emailHash", "type": "bytes32"}],
        "name": "verifyThreat",
        "outputs": [
            {"internalType": "bool", "name": "exists", "type": "bool"},
            {"internalType": "string", "name": "senderDomain", "type": "string"},
            {"internalType": "string", "name": "threatType", "type": "string"},
            {"internalType": "uint8", "name": "riskScore", "type": "uint8"},
            {"internalType": "string", "name": "ipfsReportHash", "type": "string"},
            {"internalType": "string", "name": "originIp", "type": "string"},
            {"internalType": "address", "name": "reporter", "type": "address"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getTotalThreats",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]


class MonadBlockchainService:
    def __init__(self):
        self.rpc_url = DEFAULT_MONAD_RPC
        self.chain_id = MONAD_CHAIN_ID
        self.explorer_url = MONAD_EXPLORER_URL
        self.contract_address = os.getenv("MONAD_CONTRACT_ADDRESS", "")
        self.private_key = os.getenv("MONAD_PRIVATE_KEY", "")
        self._w3 = None
        self._contract = None

    def compute_email_hash(self, email_text_or_headers: str) -> str:
        """
        Compute deterministic SHA-256 hash formatted as 0x-prefixed 32-byte hex.
        Used as the immutable cryptographic anchor.
        """
        content = email_text_or_headers.strip().encode("utf-8")
        h = hashlib.sha256(content).hexdigest()
        return "0x" + h

    def _get_w3(self):
        """Lazy load web3 provider if web3 library is installed"""
        if self._w3 is None:
            try:
                from web3 import Web3
                self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            except ImportError:
                logger.info("web3 package not installed; running in lightweight audit hash mode")
                return None
        return self._w3

    def get_network_status(self) -> Dict[str, Any]:
        """Check connection to Monad Testnet"""
        w3 = self._get_w3()
        if w3 and w3.is_connected():
            latest_block = w3.eth.block_number
            return {
                "connected": True,
                "network": "Monad Testnet",
                "chain_id": self.chain_id,
                "rpc_url": self.rpc_url,
                "explorer_url": self.explorer_url,
                "latest_block": latest_block,
                "contract_configured": bool(self.contract_address),
                "contract_address": self.contract_address or "Not deployed yet"
            }
        return {
            "connected": False,
            "network": "Monad Testnet",
            "chain_id": self.chain_id,
            "rpc_url": self.rpc_url,
            "explorer_url": self.explorer_url,
            "latest_block": None,
            "contract_configured": bool(self.contract_address),
            "contract_address": self.contract_address or "Not configured"
        }

    def verify_threat_on_chain(self, email_hash: str) -> Dict[str, Any]:
        """
        Query Monad Testnet smart contract to verify if this email hash
        is an existing logged threat in the decentralized registry.
        """
        if not email_hash.startswith("0x"):
            email_hash = "0x" + email_hash

        w3 = self._get_w3()
        if not w3 or not self.contract_address:
            return {
                "verified_on_chain": False,
                "email_hash": email_hash,
                "message": "Monad smart contract address not configured or Web3 offline",
                "explorer_url": f"{self.explorer_url}/address/{self.contract_address}" if self.contract_address else None
            }

        try:
            contract = w3.eth.contract(address=w3.to_checksum_address(self.contract_address), abi=EMAIL_THREAT_REGISTRY_ABI)
            res = contract.functions.verifyThreat(bytes.fromhex(email_hash[2:])).call()
            
            exists = res[0]
            if exists:
                return {
                    "verified_on_chain": True,
                    "email_hash": email_hash,
                    "sender_domain": res[1],
                    "threat_type": res[2],
                    "risk_score": res[3],
                    "ipfs_report_hash": res[4],
                    "origin_ip": res[5],
                    "reporter": res[6],
                    "timestamp": res[7],
                    "explorer_contract_url": f"{self.explorer_url}/address/{self.contract_address}"
                }
            return {
                "verified_on_chain": False,
                "email_hash": email_hash,
                "message": "Hash not found in Monad threat registry"
            }
        except Exception as e:
            logger.error(f"Error checking threat on Monad testnet: {e}")
            return {
                "verified_on_chain": False,
                "email_hash": email_hash,
                "error": str(e)
            }

    def record_threat_on_chain(
        self,
        email_hash: str,
        sender_domain: str,
        threat_type: str,
        risk_score: int,
        ipfs_report_hash: str = "",
        origin_ip: str = ""
    ) -> Dict[str, Any]:
        """
        Sign and broadcast a transaction to Monad Testnet recording the threat.
        Requires MONAD_PRIVATE_KEY and MONAD_CONTRACT_ADDRESS in .env.
        """
        if not email_hash.startswith("0x"):
            email_hash = "0x" + email_hash

        w3 = self._get_w3()
        if not w3 or not self.contract_address or not self.private_key:
            # Return transaction payload simulation for testing/demo
            return {
                "status": "simulated",
                "email_hash": email_hash,
                "network": "Monad Testnet (Chain ID 10143)",
                "sender_domain": sender_domain,
                "threat_type": threat_type,
                "risk_score": risk_score,
                "origin_ip": origin_ip,
                "notice": "To broadcast live transactions, set MONAD_CONTRACT_ADDRESS and MONAD_PRIVATE_KEY in .env",
                "sample_explorer_link": f"{self.explorer_url}/address/{self.contract_address or '0x0000000000000000000000000000000000000000'}"
            }

        try:
            account = w3.eth.account.from_key(self.private_key)
            contract = w3.eth.contract(address=w3.to_checksum_address(self.contract_address), abi=EMAIL_THREAT_REGISTRY_ABI)

            hash_bytes = bytes.fromhex(email_hash[2:])
            nonce = w3.eth.get_transaction_count(account.address)

            tx = contract.functions.recordThreat(
                hash_bytes,
                sender_domain or "unknown",
                threat_type or "Suspicious",
                int(risk_score),
                ipfs_report_hash or "",
                origin_ip or ""
            ).build_transaction({
                'from': account.address,
                'nonce': nonce,
                'gasPrice': w3.eth.gas_price,
                'chainId': self.chain_id
            })

            signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_hash_hex = w3.to_hex(tx_hash)

            return {
                "status": "success",
                "tx_hash": tx_hash_hex,
                "explorer_url": f"{self.explorer_url}/tx/{tx_hash_hex}",
                "email_hash": email_hash,
                "sender_domain": sender_domain,
                "threat_type": threat_type,
                "risk_score": risk_score
            }
        except Exception as e:
            logger.error(f"Failed to record threat on Monad: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "email_hash": email_hash
            }


_monad_service_instance = None

def get_monad_service() -> MonadBlockchainService:
    global _monad_service_instance
    if _monad_service_instance is None:
        _monad_service_instance = MonadBlockchainService()
    return _monad_service_instance
