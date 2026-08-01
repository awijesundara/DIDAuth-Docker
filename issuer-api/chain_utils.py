import os
from web3 import Web3
from eth_account import Account

# Ethereum RPC calls the contract with keccak-hashed content, so we can
# safely use Web3.keccak for any-length identifiers here.

ABI = [
  {"inputs":[{"internalType":"bytes32","name":"issuerDid","type":"bytes32"},
             {"internalType":"bytes32","name":"didDocCid","type":"bytes32"}],
   "name":"registerDID","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"vcId","type":"bytes32"},
             {"internalType":"bytes32","name":"issuerDid","type":"bytes32"},
             {"internalType":"bytes32","name":"ipfsCid","type":"bytes32"}],
   "name":"recordVC","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"vcId","type":"bytes32"}],
   "name":"revokeVC","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"vcId","type":"bytes32"}],
   "name":"isVCRecorded","outputs":[{"internalType":"bool","name":"","type":"bool"}],
   "stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"vcId","type":"bytes32"}],
   "name":"isVCRevoked","outputs":[{"internalType":"bool","name":"","type":"bool"}],
   "stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"bytes32","name":"vcId","type":"bytes32"}],
   "name":"getVCIssuer","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],
   "stateMutability":"view","type":"function"}
]

def connect():
    w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL")))
    c = w3.eth.contract(address=os.getenv("CONTRACT_ADDRESS"), abi=ABI)
    acct = Account.from_key(os.getenv("DEPLOYER_PK")) if os.getenv("DEPLOYER_PK") else None
    return w3, c, acct

def to_bytes32(s: str) -> bytes:
    """Deterministically map an arbitrary-length identifier (DID, IPFS CID,
    vc_id, ...) to a bytes32 for on-chain storage.

    This must hash rather than truncate: vc_ids are "vcid:" + 64 hex chars
    (69 bytes) and IPFS CIDs commonly exceed 32 bytes too, so naive
    truncation to the first 32 bytes silently discards most of the entropy.
    Two different vc_ids/CIDs that share a 32-byte prefix would then collide
    on-chain, causing spurious "already recorded" reverts or, worse, VCs
    resolving to the wrong recorded/revoked state.
    """
    return Web3.keccak(text=s)

def tx_send(w3, acct, tx):
    tx.update({"nonce": w3.eth.get_transaction_count(acct.address)})
    tx.update({"gasPrice": w3.eth.gas_price})
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.rawTransaction)
    r = w3.eth.wait_for_transaction_receipt(h)
    return r
