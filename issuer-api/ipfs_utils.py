import os
import requests, json

IPFS_API = None
REQUEST_TIMEOUT = float(os.getenv("EXTERNAL_REQUEST_TIMEOUT_SECS", "5"))

def init(ipfs_api: str):
    global IPFS_API
    IPFS_API = ipfs_api

def add_json(obj: dict) -> str:
    assert IPFS_API, "IPFS_API not initialized"
    data = json.dumps(obj, separators=(",",":")).encode()
    files = {'file': ('data.json', data, 'application/json')}
    r = requests.post(f"{IPFS_API}/add", files=files, params={"pin":"true"}, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()["Hash"]

def cat(cid: str) -> dict:
    assert IPFS_API, "IPFS_API not initialized"
    r = requests.post(f"{IPFS_API}/cat", params={"arg": cid}, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()
