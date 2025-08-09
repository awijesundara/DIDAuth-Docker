import requests, json

IPFS_API = None

def init(ipfs_api: str):
    global IPFS_API
    IPFS_API = ipfs_api

def add_json(obj: dict) -> str:
    assert IPFS_API, "IPFS_API not initialized"
    data = json.dumps(obj, separators=(",",":")).encode()
    files = {'file': ('data.json', data, 'application/json')}
    r = requests.post(f"{IPFS_API}/add", files=files, params={"pin":"true"})
    r.raise_for_status()
    return r.json()["Hash"]

def cat(cid: str) -> dict:
    assert IPFS_API, "IPFS_API not initialized"
    r = requests.post(f"{IPFS_API}/cat", params={"arg": cid})
    r.raise_for_status()
    return r.json()
