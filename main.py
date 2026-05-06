from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import requests
import hashlib
import struct

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Token configs
TOKENS = {
    "USDT": {
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "decimals": 6,
    },
    "USDC": {
        "address": "0xA0b86a33E6441E6C7D3D4B4f6c7B8e9F0a1B2c3D",
        "decimals": 6,
    }
}

RPC_ENDPOINTS = [
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum.publicnode.com",
    "https://eth.drpc.org",
]

# ERC20 transfer function selector: keccak("transfer(address,uint256)")[:4]
TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")

def keccak256(data: bytes) -> bytes:
    """Keccak-256 hash (Ethereum's hash function)"""
    try:
        import sha3
        k = sha3.keccak_256()
        k.update(data)
        return k.digest()
    except ImportError:
        # Fallback: use pysha3 via hashlib if available
        try:
            k = hashlib.new('keccak_256')
            k.update(data)
            return k.digest()
        except:
            # Pure Python fallback
            return _pure_keccak256(data)

def _pure_keccak256(data: bytes) -> bytes:
    """Pure Python keccak - simplified fallback"""
    # For the transfer selector, we use the precomputed constant
    # For tx hashing we use sha3 from available packages
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except:
        # Last resort - use regular sha256 (not correct for eth but works for demo)
        return hashlib.sha256(data).digest()

def pad_32_bytes(data: bytes) -> bytes:
    """Left-pad bytes to 32 bytes"""
    return b'\x00' * (32 - len(data)) + data

def encode_address(addr_hex: str) -> bytes:
    """Encode Ethereum address as 32-byte padded"""
    addr_clean = addr_hex.replace("0x", "")
    return pad_32_bytes(bytes.fromhex(addr_clean))

def encode_uint256(value: int) -> bytes:
    """Encode uint256 as 32-byte big-endian"""
    return value.to_bytes(32, 'big')

def build_erc20_transfer_data(to_address: str, amount: int) -> bytes:
    """Encode transfer(address,uint256) function call"""
    # Selector (4 bytes) + padded address (32 bytes) + padded uint256 (32 bytes)
    return TRANSFER_SELECTOR + encode_address(to_address) + encode_uint256(amount)

def rlp_encode(item):
    """Simple RLP encoder for transaction fields"""
    if isinstance(item, int):
        if item == 0:
            return bytes([0x80])
        # Encode integer as minimal bytes
        byte_length = (item.bit_length() + 7) // 8
        int_bytes = item.to_bytes(byte_length, 'big')
        return rlp_encode(int_bytes)
    elif isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        elif len(item) <= 55:
            return bytes([0x80 + len(item)]) + item
        else:
            length_bytes = len(item).to_bytes((len(item).bit_length() + 7) // 8, 'big')
            return bytes([0xb7 + len(length_bytes)]) + length_bytes + item
    elif isinstance(item, list):
        encoded = b''.join(rlp_encode(sub) for sub in item)
        if len(encoded) <= 55:
            return bytes([0xc0 + len(encoded)]) + encoded
        else:
            length_bytes = len(encoded).to_bytes((len(encoded).bit_length() + 7) // 8, 'big')
            return bytes([0xf7 + len(length_bytes)]) + length_bytes + encoded
    else:
        raise TypeError(f"Cannot RLP encode {type(item)}")

def build_fake_tx(token_addr: str, to_addr: str, amount: int, nonce=0, gas_price=20000000000, gas_limit=100000, chain_id=1):
    """Build a fake-signed Ethereum transaction for ERC-20 transfer"""
    token_addr_bytes = bytes.fromhex(token_addr.replace('0x', ''))
    data = build_erc20_transfer_data(to_addr, amount)

    # EIP-155 transaction: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
    tx_fields = [
        nonce,
        gas_price,
        gas_limit,
        token_addr_bytes,
        0,  # value (ETH sent with tx)
        data,
        chain_id,
        0,
        0,
    ]

    tx_rlp = rlp_encode(tx_fields)
    tx_hash = keccak256(tx_rlp)
    tx_hex = '0x' + tx_rlp.hex()
    tx_hash_hex = '0x' + tx_hash.hex() if tx_hash else '0x' + hashlib.sha256(tx_rlp).hexdigest()

    return tx_hash_hex, tx_hex

@app.post("/flash")
async def flash(request: Request):
    body = await request.json()
    addr = body.get("address", "").strip()
    amt = float(body.get("amount", 0))
    coin = body.get("coin", "USDT").upper()

    if coin not in TOKENS:
        return {"error": f"Unsupported coin. Choose: {', '.join(TOKENS.keys())}"}

    token = TOKENS[coin]

    # Basic Ethereum address validation
    if not addr or not addr.startswith('0x') or len(addr) != 42:
        return {"error": "Invalid Ethereum address. Must be 0x... (42 chars)"}

    try:
        int(addr[2:], 16)
    except ValueError:
        return {"error": "Invalid Ethereum address hex"}

    # Convert amount to token decimals
    token_amount = int(amt * (10 ** token["decimals"]))

    # Build fake transaction
    tx_hash, tx_hex = build_fake_tx(
        token_addr=token["address"],
        to_addr=addr,
        amount=token_amount
    )

    # Broadcast attempts to multiple RPC nodes
    results = []
    for rpc_url in RPC_ENDPOINTS:
        try:
            r = requests.post(rpc_url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_sendRawTransaction",
                "params": [tx_hex]
            }, timeout=10, headers={"Content-Type": "application/json"})

            resp = r.json()
            if "error" in resp:
                err_msg = resp["error"].get("message", str(resp["error"]))
                if "already known" in err_msg.lower():
                    results.append({"endpoint": rpc_url, "status": 200, "resp": "Transaction seen by node"})
                else:
                    results.append({"endpoint": rpc_url, "status": r.status_code, "error": err_msg[:200]})
            else:
                results.append({"endpoint": rpc_url, "status": r.status_code, "resp": "Broadcast accepted"})
        except Exception as e:
            results.append({"endpoint": rpc_url, "error": str(e)[:200]})

    return {
        "tx_hash": tx_hash,
        "raw_tx": tx_hex,
        "target": addr,
        "amount": amt,
        "coin": coin,
        "token_address": token["address"],
        "broadcast_attempts": results,
        "note": "Fake tx with null signature (r=0,s=0). Nodes will reject but tx hash may appear in mempool explorers briefly."
    }

@app.get("/")
async def root():
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>USDC / USDT Flash</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0a0a0f;
            color: #00e5ff;
            font-family: 'Courier New', monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: #111118;
            border: 1px solid #00e5ff;
            border-radius: 8px;
            padding: 40px;
            width: 100%;
            max-width: 520px;
            box-shadow: 0 0 30px rgba(0, 229, 255, 0.1);
        }
        h1 {
            text-align: center;
            margin-bottom: 8px;
            font-size: 22px;
            text-transform: uppercase;
            letter-spacing: 3px;
            color: #00e5ff;
        }
        .subtitle {
            text-align: center;
            font-size: 11px;
            color: #666;
            margin-bottom: 30px;
            letter-spacing: 1px;
        }
        .coin-select {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        .coin-btn {
            flex: 1;
            padding: 12px;
            background: #000;
            border: 1px solid #333;
            color: #888;
            font-family: inherit;
            font-size: 14px;
            font-weight: bold;
            cursor: pointer;
            text-align: center;
            transition: all 0.2s;
        }
        .coin-btn.active {
            border-color: #00e5ff;
            color: #00e5ff;
            box-shadow: 0 0 10px rgba(0, 229, 255, 0.2);
        }
        .coin-btn:hover:not(.active) {
            border-color: #555;
            color: #ccc;
        }
        .input-group { margin-bottom: 20px; }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #00e5ff;
        }
        input {
            width: 100%;
            background: #000;
            border: 1px solid #00e5ff;
            color: #00e5ff;
            padding: 12px;
            font-family: inherit;
            font-size: 14px;
            outline: none;
            border-radius: 2px;
        }
        input:focus {
            box-shadow: 0 0 12px rgba(0, 229, 255, 0.25);
        }
        input::placeholder { color: #333; }
        button {
            width: 100%;
            background: #00e5ff;
            color: #000;
            border: none;
            padding: 14px;
            font-family: inherit;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-top: 10px;
            border-radius: 2px;
        }
        button:hover { background: #00bcd4; }
        button:disabled {
            background: #004d5a;
            cursor: not-allowed;
            color: #333;
        }
        #result {
            margin-top: 25px;
            padding: 15px;
            background: #000;
            border: 1px solid #00e5ff;
            font-size: 11px;
            word-break: break-all;
            line-height: 1.6;
            display: none;
            border-radius: 2px;
        }
        #result.active { display: block; }
        #result.error {
            color: #ff3366;
            border-color: #ff3366;
        }
        .loading {
            text-align: center;
            animation: pulse 1s infinite;
            color: #00e5ff;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }
        .success-badge {
            color: #00ff88;
            font-weight: bold;
        }
        .fail-badge {
            color: #ff3366;
        }
        .endpoint-row {
            margin: 4px 0;
            padding: 6px 0;
            border-bottom: 1px solid #111;
        }
        .note {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #222;
            color: #666;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>ERC-20 Flash</h1>
        <div class="subtitle">USDC / USDT Ethereum Network</div>

        <div class="coin-select">
            <div class="coin-btn active" data-coin="USDT" onclick="selectCoin('USDT')">USDT</div>
            <div class="coin-btn" data-coin="USDC" onclick="selectCoin('USDC')">USDC</div>
        </div>

        <div class="input-group">
            <label>Target Address (0x...)</label>
            <input type="text" id="addr" placeholder="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb" autocomplete="off">
        </div>
        <div class="input-group">
            <label>Amount</label>
            <input type="number" id="amt" placeholder="1000.00" step="0.01">
        </div>
        <button onclick="flash()" id="btn">INITIATE FLASH</button>
        <div id="result"></div>
    </div>

    <script>
        let selectedCoin = 'USDT';

        function selectCoin(coin) {
            selectedCoin = coin;
            document.querySelectorAll('.coin-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.coin === coin);
            });
        }

        async function flash() {
            const addr = document.getElementById('addr').value.trim();
            const amt = parseFloat(document.getElementById('amt').value);
            const result = document.getElementById('result');
            const btn = document.getElementById('btn');

            if (!addr || !addr.startsWith('0x') || addr.length !== 42) {
                result.className = 'active error';
                result.innerHTML = 'ERROR: Invalid Ethereum address. Must be 0x + 40 hex chars.';
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
                    body: JSON.stringify({ address: addr, amount: amt, coin: selectedCoin })
                });

                const j = await r.json();

                if (j.error) {
                    result.className = 'active error';
                    result.innerHTML = 'ERROR: ' + j.error;
                } else {
                    let epHtml = '';
                    for (const a of j.broadcast_attempts) {
                        const ok = a.status === 200 && !a.error;
                        epHtml += '<div class="endpoint-row">' +
                            '<span class="' + (ok ? 'success-badge' : 'fail-badge') + '">' +
                            (ok ? '[OK]' : '[FAIL]') + '</span> ' +
                            a.endpoint.replace('https://', '') +
                            (a.error ? ': ' + a.error : '') +
                            '</div>';
                    }

                    result.className = 'active';
                    result.innerHTML =
                        '<b style="color:#00e5ff">TX HASH:</b> ' + j.tx_hash + '<br><br>' +
                        '<b>TOKEN:</b> ' + j.coin + ' @ ' + j.token_address + '<br>' +
                        '<b>TARGET:</b> ' + j.target + '<br>' +
                        '<b>AMOUNT:</b> ' + j.amount + ' ' + j.coin + '<br><br>' +
                        '<b>RAW TX:</b> <span style="color:#666;font-size:10px">' + j.raw_tx.substring(0, 120) + '...</span><br><br>' +
                        '<b>BROADCAST STATUS:</b>' + epHtml +
                        '<div class="note">' + j.note + '</div>';
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
