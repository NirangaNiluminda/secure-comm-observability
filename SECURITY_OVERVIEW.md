# Secure Communication & Traffic Observability
## Complete Security Documentation

> **Course:** Information Security — Semester 7  
> **Project:** Secure real-time chat platform with live attack simulation, cryptographic verification, and network traffic monitoring.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [How the Chat Works (Normal Flow)](#4-how-the-chat-works-normal-flow)
5. [Security Mechanisms (8 Defense Layers)](#5-security-mechanisms-8-defense-layers)
6. [Attack Simulations — All 6 Attacks](#6-attack-simulations--all-6-attacks)
   - [Attack 1: Replay Attack](#attack-1-replay-attack)
   - [Attack 2: Ciphertext Tampering](#attack-2-ciphertext-tampering)
   - [Attack 3: Brute Force Login](#attack-3-brute-force-login)
   - [Attack 4: Forged / Expired JWT](#attack-4-forged--expired-jwt)
   - [Attack 5: MITM Key Substitution](#attack-5-mitm-key-substitution)
   - [Attack 6: Message Flood (DoS)](#attack-6-message-flood-dos)
7. [What Data is Stored in the Database](#7-what-data-is-stored-in-the-database)
8. [Network Monitoring (Scapy + InfluxDB + Grafana)](#8-network-monitoring-scapy--influxdb--grafana)
9. [Audit Log (Hash-Chained, ECDSA-Signed)](#9-audit-log-hash-chained-ecdsa-signed)
10. [STRIDE Threat Model Coverage](#10-stride-threat-model-coverage)
11. [How to Run the Project](#11-how-to-run-the-project)
12. [Service URLs](#12-service-urls)

---

## 1. Project Overview

This project is a **production-quality secure messaging platform** that demonstrates the practical application of modern cryptography and security principles. It is built in two layers:

| Layer | Purpose |
|---|---|
| **Secure Chat** | End-to-end encrypted real-time messaging using ECDH key exchange, AES-256-GCM encryption, and ECDSA digital signatures |
| **Security Dashboard** | Live observability panel showing active defenses, real attack simulations, performance benchmarks, and a live security event feed |

**Key principle:** Every attack in the simulator runs **real code** — real cryptographic functions raise real exceptions, rate limiters process real HTTP requests, and all events are persisted to a real SQLite database visible in the live feed.

---

## 2. System Architecture

```
Browser (React SPA)
       │
       ▼
┌─────────────┐       HTTP/WebSocket
│  Nginx       │ ──────────────────────► ┌─────────────────────┐
│  (port 80)   │   proxy_pass /api/       │  Flask + SocketIO   │
│              │   proxy_pass /socket.io/ │  Backend (port 5000)│
└─────────────┘                          │                     │
                                         │  ┌───────────────┐  │
                                         │  │ SQLite DB     │  │
                                         │  │ users.db      │  │
                                         │  └───────────────┘  │
                                         │  ┌───────────────┐  │
                                         │  │ Audit Log     │  │
                                         │  │ .ndjson chain │  │
                                         │  └───────────────┘  │
                                         └─────────────────────┘
                                                   │
                                         ┌─────────▼───────────┐
                                         │   InfluxDB (8086)   │
                                         │   network_metrics   │
                                         └─────────────────────┘
                                                   │
                                         ┌─────────▼───────────┐
                                         │   Grafana (3000)    │
                                         │   DoS Traffic Charts│
                                         └─────────────────────┘

Host OS (Linux)
  └── Scapy Sniffer (monitor profile)
       Captures TCP traffic on all interfaces
       Writes SYN/ACK ratios to InfluxDB
```

### Data Flow for a Single Encrypted Message

```
Alice's Browser                     Server                     Bob's Browser
      │                               │                               │
      │  1. generateECDHKeyPair()     │                               │
      │  2. generateECDSAKeyPair()    │                               │
      │  3. register(pub_key, sign_key)──►  store in users{}          │
      │                               │                               │
      │  4. get_public_key(Bob) ──────►  return Bob's public keys ───►│
      │                               │                               │
      │  5. ECDH(alice_priv, bob_pub) = shared_key (AES key)         │
      │                               │                               │
      │  6. AES-256-GCM encrypt(msg)  │                               │
      │  7. SHA-256 hash(plaintext)   │                               │
      │  8. ECDSA sign(envelope)      │                               │
      │  9. send_message ─────────────►  verify JWT scope            │
      │                               │  rate_limit check            │
      │                               │  replay dedup check          │
      │                               │  ECDSA verify(alice_sig)     │
      │                               │  forward ─────────────────────►
      │                               │                               │  10. ECDH(bob_priv, alice_pub) = same shared_key
      │                               │                               │  11. ECDSA verify signature
      │                               │                               │  12. AES-256-GCM decrypt
      │                               │                               │  13. SHA-256 verify hash
      │                               │                               │  14. display plaintext ✓
```

---

## 3. Technology Stack

### Backend
| Component | Technology | Purpose |
|---|---|---|
| Web framework | Python / Flask | REST API endpoints |
| WebSocket | Flask-SocketIO | Real-time bidirectional events |
| Symmetric encryption | AES-256-GCM (cryptography lib) | Message confidentiality + integrity |
| Key exchange | ECDH P-256 (cryptography lib) | Perfect Forward Secrecy |
| Digital signatures | ECDSA P-256 / SHA-256 | Non-repudiation |
| Key derivation | HKDF-SHA256 | Derive AES key from ECDH shared secret |
| Password hashing | bcrypt (work factor 12) | Brute-force resistant credential storage |
| Authentication | JWT / HS256 (PyJWT) | Stateless scoped token auth |
| Database | SQLite (via database.py) | User credentials + security events |
| Audit log | NDJSON + SHA-256 chain + ECDSA | Tamper-evident append-only event log |

### Frontend
| Component | Technology | Purpose |
|---|---|---|
| UI framework | React 18 + Vite | Single-page application |
| Real-time crypto | Web Crypto API (SubtleCrypto) | Client-side ECDH, AES-GCM, ECDSA, SHA-256 |
| WebSocket client | Socket.IO | Event-driven chat |
| Animations | Framer Motion | UI transitions |
| Styling | Tailwind CSS | Dark-mode security UI |

### Infrastructure
| Service | Image | Purpose |
|---|---|---|
| Frontend | Nginx + React build | Serves SPA + reverse-proxy to backend |
| Backend | Python 3.11-slim | Flask API + SocketIO |
| InfluxDB | influxdb:2.7 | Time-series storage for network metrics |
| Grafana | grafana/grafana:latest | SYN/ACK ratio charts + DoS alerts |
| Monitor (optional) | Scapy sniffer | Captures TCP packets on host interfaces |

---

## 4. How the Chat Works (Normal Flow)

### Step-by-step message lifecycle

**1. Registration**
- User sends `POST /api/register` → username stored in SQLite with bcrypt-hashed password

**2. Login**
- `POST /api/login` → bcrypt.checkpw() → JWT issued (HS256, 60 min TTL, scopes: `chat:send`, `chat:read`, `key:read`)

**3. WebSocket connection**
- Browser connects via Socket.IO with JWT in auth header
- Rate limit checked: max 40 connections per 60s per IP

**4. Key generation (browser)**
```javascript
// Two separate key pairs generated in browser using Web Crypto API:
const ecdhKeys  = await generateECDHKeyPair();   // for key exchange
const ecdsaKeys = await generateECDSAKeyPair();   // for message signing
// Public keys exported as JWK and sent to server via socket 'register' event
```

**5. Key exchange (ECDH)**
```javascript
// When Alice opens a chat with Bob:
const bobPublicKey = await socket.emit('get_public_key', {username: 'Bob'});
const sharedKey = await ECDH(alice_private, bob_public);
// Bob derives the SAME key: ECDH(bob_private, alice_public)
// This is HKDF-SHA256 derived into a 256-bit AES key
// Neither side ever transmits the shared key
```

**6. Send a message**
```javascript
const hash       = SHA256(plaintext);                    // integrity
const {iv, ct}   = AES_256_GCM_encrypt(sharedKey, msg); // confidentiality
const envelope   = JSON.stringify({from,to,id,ts,iv,ct,hash}); // canonical
const signature  = ECDSA_sign(alice_ecdsa_private, envelope);  // authenticity
socket.emit('send_message', {ciphertext, iv, signature, hash, message_id, ...});
```

**7. Server forwards (after 4 checks)**
```python
# Check 1: JWT scope 'chat:send'
# Check 2: rate limit ('send', username, 120 per 60s)
# Check 3: replay dedup (message_id not in seen_message_ids set)
# Check 4: ECDSA verify(alice_registered_sign_key, signature, envelope)
# → emit('receive_message', data) to Bob's socket
```

**8. Bob receives and verifies**
```javascript
// 1. Replay check: seenIdsRef.has(`${from}:${message_id}`)
// 2. Timestamp window: |Date.now() - sent_at| < 5 minutes
// 3. ECDSA verify(alice_sign_public, signature, envelope)
// 4. AES-256-GCM decrypt(sharedKey, iv, ciphertext)
// 5. SHA-256 verify: hash(plaintext) === data.hash
// → display message with ✓ Verified badge
```

**Server NEVER sees plaintext** — it only forwards the encrypted ciphertext blob.

---

## 5. Security Mechanisms (8 Defense Layers)

### Layer 1: AES-256-GCM Encryption
**What it does:** Encrypts every message with Authenticated Encryption with Associated Data (AEAD). A single operation provides both confidentiality (encryption) and integrity (authentication tag).

```python
# Backend (Python)
def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(12)          # random 96-bit nonce each time
    return iv + AESGCM(key).encrypt(iv, plaintext, aad=None)
    # output: 12-byte IV + ciphertext + 16-byte GCM auth tag

def decrypt_aes_gcm(key: bytes, data: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], aad=None)
    # raises cryptography.exceptions.InvalidTag if ANY byte changed
```

```javascript
// Browser (Web Crypto API)
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, sharedKey, encoded);
```

**Defense:** If an attacker modifies even 1 bit of the ciphertext in transit, `AESGCM.decrypt()` raises `InvalidTag` and the message is rejected.

---

### Layer 2: ECDH P-256 Key Exchange (Perfect Forward Secrecy)
**What it does:** Both parties generate fresh ephemeral EC keypairs each session. The shared secret is derived via ECDH and then HKDF-SHA256. This gives **Perfect Forward Secrecy** — even if a private key is compromised later, past sessions cannot be decrypted.

```python
# Server-side ECDH (for simulation/benchmark)
def derive_shared_key(private_key, peer_public_key, length=32) -> bytes:
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'handshake data').derive(shared)
```

```javascript
// Browser: keys are generated fresh on every page load (every session)
const shared = await crypto.subtle.deriveKey(
  {name:'ECDH', public: bobEcdhPublicKey},
  aliceEcdhPrivateKey,
  {name:'AES-GCM', length:256}, true, ['encrypt','decrypt']
);
// Bob derives IDENTICAL key using his private + Alice's public
```

**Defense:** No static long-term encryption key. Each session has a unique AES key that is never transmitted. Compromising one session key does not reveal any other session.

---

### Layer 3: ECDSA P-256 Digital Signatures
**What it does:** Every message is signed with the sender's ECDSA private key over a canonical envelope containing ALL message fields. The server and receiver both verify the signature against the sender's registered public key.

```python
# Server verifies every send_message event
sig_bytes = base64.b64decode(data['signature'])
envelope_str = json.dumps({
    'from': data['from'], 'to': data['to'],
    'message_id': data['message_id'], 'sent_at': data['sent_at'],
    'iv': data['iv'], 'ciphertext': data['ciphertext'], 'hash': data['hash'],
}, separators=(',',':'))  # canonical JSON, fixed key order

sender_key = load_public_key_from_jwk(users[sender]['sign_public_key'])
crypto.verify_ecdsa(sender_key, sig_bytes, envelope_str.encode('utf-8'))
# Raises InvalidSignature if signature doesn't match → reject message
```

**Defense:** Non-repudiation — a message cannot be forged or modified without the sender's private key. The P1363 (Web Crypto) and DER (Python) signature formats are both handled automatically.

---

### Layer 4: SHA-256 Plaintext Hash
**What it does:** Before encrypting, the browser computes `SHA-256(plaintext)`. This hash is included in the message envelope (and signed by ECDSA). After decryption, the receiver recomputes the hash and compares.

```javascript
// Sender
const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
// hash is sent as part of the signed envelope

// Receiver
const computed = await generateHash(plaintext);
if (computed !== data.hash) throw new Error('Hash mismatch — message was tampered');
```

**Defense:** Even if AES-GCM somehow passed (impossible in practice), a plaintext modification would be caught by the hash mismatch.

---

### Layer 5: JWT Authentication with Scopes
**What it does:** Every API and WebSocket operation requires a valid JWT. Tokens are short-lived (60 min), signed with HS256, and carry scopes that restrict what each token can do.

```python
def generate_jwt(username):
    payload = {
        'username': username,
        'scopes': ['chat:send', 'chat:read', 'key:read'],
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=60),
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token, required_scope=None):
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    # Raises ExpiredSignatureError if expired
    # Raises InvalidTokenError if signature wrong
    if required_scope and required_scope not in payload['scopes']:
        return None, f'Missing scope: {required_scope}'
    return payload, None
```

**Defense:** Forged tokens (wrong secret) → `InvalidTokenError`. Expired tokens → `ExpiredSignatureError`. Wrong scope → scope error. All rejected before any action is taken.

---

### Layer 6: Sliding-Window Rate Limiting
**What it does:** Every action (login, connect, send message, flood test) is tracked per-IP or per-user in a sliding time window using a `deque`. Requests exceeding the limit return HTTP 429.

```python
def _check_rate_limit(action, subject, limit):
    now    = time.time()
    key    = f'{action}:{subject}'
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS  # 60 seconds
    with rate_limit_lock:
        q = rate_limit_state.setdefault(key, deque())
        while q and q[0] < cutoff:   # purge expired timestamps
            q.popleft()
        if len(q) >= limit:
            retry = int(RATE_LIMIT_WINDOW_SECONDS - (now - q[0]))
            return False, retry       # BLOCKED — return retry-after seconds
        q.append(now)
    return True, 0                    # ALLOWED
```

| Endpoint / Event | Key | Limit |
|---|---|---|
| `POST /api/login` | per IP | 15 per 60s |
| `GET /api/flood-test` | per username | 120 per 60s |
| Socket `send_message` | per username | 120 per 60s |
| Socket `connect` | per IP | 40 per 60s |
| Socket `register` | per IP | 15 per 60s |

**Defense:** Brute force attacks are throttled after 15 login attempts. Message floods are throttled after 120 messages per minute.

---

### Layer 7: bcrypt Password Hashing
**What it does:** Passwords are hashed with bcrypt using a cost factor of 12 (auto-selected salt). bcrypt is intentionally slow — each verification takes ~100–200ms, making large-scale brute force attacks computationally expensive.

```python
# Registration
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())  # cost=12
db.create_user(username, hashed)

# Login verification
if not bcrypt.checkpw(password.encode(), stored_hash):
    return 401  # wrong password

# User enumeration protection: even for non-existent users, we do a dummy check
bcrypt.checkpw(b'dummy', bcrypt.hashpw(b'dummy', bcrypt.gensalt()))
# This takes the same time as a real check → attacker cannot tell if user exists
```

**Defense:** Even if the database is leaked, bcrypt hashes cannot be reversed quickly. Rainbow table attacks fail due to per-password salting. Each guess takes ~100ms, so 1 million guesses would take ~28 hours per CPU core.

---

### Layer 8: Hash-Chained ECDSA-Signed Audit Log
**What it does:** Every security-relevant event is appended to an NDJSON file where each entry contains: the event, the SHA-256 hash of `(previous_hash + event_json)`, and an ECDSA signature of the hash. This forms a tamper-evident chain.

```python
def _append_audit_log(event_type, event_data):
    event = {'event_type': event_type, 'timestamp': utcnow(), **event_data}
    canonical = json.dumps(event, sort_keys=True, separators=(',',':'))
    
    entry_hash = SHA256(prev_hash + canonical)
    signature  = ECDSA_sign(audit_private_key, entry_hash)
    
    entry = {
        'previous_hash': prev_hash,   # links to previous entry
        'entry_hash':    entry_hash,  # this entry's hash
        'signature':     sig_b64,     # ECDSA signature of entry_hash
        'event':         event,       # the actual event data
    }
    append_to_file(entry)             # append-only
    # Also mirrors to SQLite security_events table for dashboard
```

**Defense:** If any historical entry is modified, all subsequent hashes become invalid (chain broken). The ECDSA signature proves the entry was created by this server's private key. The chain_valid flag is shown in the UI.

---

### Layer 9: Server-Side Message Replay Detection
**What it does:** An in-memory set tracks all `(from, message_id)` pairs seen this session. Any duplicate is rejected with an error and logged.

```python
seen_message_ids: set = set()  # in-memory, ephemeral per process

# In handle_message():
msg_key = f"{data['from']}:{data['message_id']}"
with seen_message_ids_lock:
    if msg_key in seen_message_ids:
        _append_audit_log('attack_replay_blocked', {...})
        emit('delivery_error', {'error': 'Replay attack detected: duplicate message_id'})
        return
    seen_message_ids.add(msg_key)
```

The client also has a client-side dedup (`seenIdsRef`) and a 5-minute timestamp window check.

---

## 6. Attack Simulations — All 6 Attacks

All attacks use **real code execution**. No hardcoded fake results. Events are written to SQLite and appear in the Live Security Events feed.

---

### Attack 1: Replay Attack

**STRIDE Category:** Spoofing / Repudiation

**What the attack does:**
An attacker intercepts a valid encrypted message and re-sends it later (or multiple times) with the exact same `message_id`, hoping the receiver processes it again. This could trick a payment system into executing a transaction twice, or confuse a state machine.

**How the attack works:**
```
1. Attacker intercepts: {from:"Alice", message_id:"uuid-abc123", ciphertext:"..."}
2. Waits for 10 seconds
3. Re-sends the EXACT same packet to Bob's socket
```

**How the system defends:**

**Defense 1 — Server-side `seen_message_ids` set (primary):**
```python
# handle_message() in app.py
msg_key = "alice:uuid-abc123"
with seen_message_ids_lock:
    if msg_key in seen_message_ids:          # True on replay
        emit('delivery_error', {
            'error': 'Replay attack detected: duplicate message_id'
        })
        _append_audit_log('attack_replay_blocked', {...})
        return                               # BLOCKED — never reaches recipient
    seen_message_ids.add(msg_key)           # first delivery: record it
```

**Defense 2 — Client-side deduplication:**
```javascript
// receive_message handler in App.jsx
const key = `${data.from}:${data.message_id}`;
if (seenIdsRef.current.has(key)) return;   // BLOCKED client-side too
seenIdsRef.current.add(key);
```

**Defense 3 — Timestamp window:**
```javascript
const ms = Date.parse(data.sent_at);
if (Math.abs(Date.now() - ms) > 5 * 60 * 1000)  // > 5 minutes old
    throw new Error('Stale timestamp');             // REJECTED
```

**What gets logged:** `attack_replay_blocked` event written to SQLite + audit chain

**In the simulator:** The backend uses the real `seen_message_ids` set — `seen_message_ids.add(key)` followed by `key in seen_message_ids` returns `True`. A real `attack_replay_blocked` row appears in the Live Feed.

---

### Attack 2: Ciphertext Tampering

**STRIDE Category:** Tampering / Information Disclosure

**What the attack does:**
A Man-in-the-Middle intercepts the encrypted message in transit and flips one or more bits in the ciphertext, hoping to modify the plaintext that Bob receives, or to confuse the decryption.

**How the attack works:**
```
Alice sends: IV[12] + Ciphertext[n] + GCM_Tag[16]
Attacker changes: ct[0] = ct[0] XOR 0xFF   (flips 8 bits)
Bob receives: IV[12] + Corrupted_Ciphertext[n] + GCM_Tag[16]
```

**How the system defends:**

**Defense 1 — AES-256-GCM Authentication Tag (primary, server-verified):**
```python
# In _run_attack_simulation (real code):
ct_blob     = crypto.encrypt_aes_gcm(key, b'Hello Bob - secret transfer!')
corrupted   = bytes([ct_blob[12] ^ 0xFF]) + ct_blob[13:]  # flip one byte
corrupted_blob = ct_blob[:12] + corrupted                  # re-assemble

try:
    crypto.decrypt_aes_gcm(key, corrupted_blob)
except Exception as exc:
    # Raises: cryptography.hazmat.primitives.ciphers.aead.InvalidTag
    gcm_error = type(exc).__name__    # → "InvalidTag"
    # Message REJECTED
```

**Defense 2 — ECDSA Signature (secondary, also verifies envelope integrity):**
```python
sig_orig = crypto.sign_ecdsa(alice_private, original_ct_blob)
try:
    crypto.verify_ecdsa(alice_public, sig_orig, corrupted_blob)
except Exception as exc:
    ecdsa_error = type(exc).__name__  # → "InvalidSignature"
    # Message REJECTED
```

**Defense 3 — SHA-256 Hash (client-side, final check):**
```javascript
const computed = await generateHash(decryptedPlaintext);
if (computed !== data.hash)
    throw new Error('Hash mismatch — message was tampered');
```

**In the chat UI:** Enable "Tamper Attack Demo" toggle → send a message → Bob sees `⚠ Verification failed: ...` in red. The browser's `AES-GCM decrypt` call throws a `DOMException` because the auth tag doesn't match.

**What gets logged:** `message_rejected` with reason `signature_verification_failed`

---

### Attack 3: Brute Force Login

**STRIDE Category:** Elevation of Privilege

**What the attack does:**
An attacker sends rapid login requests with different passwords, attempting to guess a user's credentials. With no protection, an automated script could try thousands of passwords per minute.

**How the attack works (real HTTP calls from browser):**
```
for attempt in 1..16:
    POST /api/login  {"username": "demo_admin", "password": "wrong_pass_N"}
    → expect: 401 Unauthorized
→ eventually: 429 Too Many Requests
```

**How the system defends:**

**Defense 1 — Sliding-Window Rate Limiter on `/api/login` (primary):**
```python
@app.route('/api/login', methods=['POST'])
def http_login():
    ip = _client_ip()  # reads X-Forwarded-For from Nginx
    ok, retry = _check_rate_limit('login', ip, 15)  # 15 per 60s per IP
    if not ok:
        _append_audit_log('attack_brute_force_blocked', {
            'ip': ip, 'reason': 'rate_limit_exceeded', 'retry_after': retry,
        })
        return jsonify({
            'error': f'Too many login attempts. Retry after {retry}s.',
            'retry_after': retry,
        }), 429   # HTTP 429 Too Many Requests
    # ... proceed with bcrypt check only if rate limit allows
```

**Defense 2 — bcrypt Work Factor (slows each guess):**
```python
# Each allowed attempt that reaches bcrypt takes ~100-200ms
if not bcrypt.checkpw(password.encode(), stored_hash):
    _append_audit_log('login_failed', {'username': username, 'ip': ip, 'reason': 'wrong_password'})
    return 401

# For non-existent users: SAME time (prevents enumeration)
bcrypt.checkpw(b'dummy', bcrypt.hashpw(b'dummy', bcrypt.gensalt()))
```

**Timeline in the simulator:**
```
Attempt  1: POST /api/login → rate limit OK → bcrypt check → 401 (logged)
Attempt  2: POST /api/login → rate limit OK → bcrypt check → 401 (logged)
...
Attempt 15: POST /api/login → rate limit OK → bcrypt check → 401 (logged)
Attempt 16: POST /api/login → rate limit FULL → 429 → attack_brute_force_blocked (logged)
```

**What gets logged:**
- 14–15 × `login_failed` rows in SQLite (visible in Live Feed as they appear)
- 1 × `attack_brute_force_blocked` row

**Streaming UI:** Each HTTP response appears as a step in real-time. The UI shows attempts ticking over (~100ms each due to bcrypt) until the 429 fires.

---

### Attack 4: Forged / Expired JWT

**STRIDE Category:** Spoofing / Elevation of Privilege

**What the attack does:**
An attacker tries to forge a JWT token to impersonate another user, uses a stolen but expired token, or crafts a token with elevated scopes.

**3 real attack vectors tested:**

**Vector 1 — Wrong secret (signature forgery):**
```python
forged_token = jwt.encode(
    {'username': 'admin', 'scopes': ['chat:send'], 'exp': now + 1h},
    'WRONG_SECRET',      # attacker doesn't know the real secret
    algorithm='HS256'
)
_, err = verify_token(forged_token)
# jwt.decode() raises: jwt.exceptions.InvalidSignatureError
# → err = "Invalid token"
```

**Vector 2 — Expired token:**
```python
expired_token = jwt.encode(
    {'username': username, 'scopes': ['chat:send'],
     'iat': now - 2h, 'exp': now - 1h},   # expired 1 hour ago
    app.config['SECRET_KEY'], algorithm='HS256'
)
_, err = verify_token(expired_token)
# jwt.decode() raises: jwt.exceptions.ExpiredSignatureError
# → err = "Token expired"
```

**Vector 3 — Missing required scope:**
```python
limited_token = jwt.encode(
    {'username': username, 'scopes': ['key:read']},  # only key:read, not chat:send
    SECRET_KEY, algorithm='HS256'
)
_, err = verify_token(limited_token, required_scope='chat:send')
# payload['scopes'] doesn't contain 'chat:send'
# → err = "Missing scope: chat:send"
```

**How `verify_token` works:**
```python
def verify_token(token, required_scope=None):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if required_scope and required_scope not in payload.get('scopes', []):
            return None, f'Missing scope: {required_scope}'
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, 'Token expired'
    except jwt.InvalidTokenError:
        return None, 'Invalid token'
```

**What gets logged:** `attack_invalid_jwt_blocked`

---

### Attack 5: MITM Key Substitution

**STRIDE Category:** Spoofing / Information Disclosure

**What the attack does:**
During the ECDH key exchange phase, a Man-in-the-Middle intercepts the public key exchange and substitutes Mallory's own public key for Alice's. If successful, Mallory could decrypt messages meant for Bob.

**How the attack works:**
```
Alice sends: alice_ecdh_public_key, alice_sign_public_key
Mallory intercepts and substitutes: mallory_ecdh_public_key
Bob receives: mallory_ecdh_public_key (thinks it's Alice's)
Bob derives: ECDH(bob_priv, mallory_pub) → wrong shared key!
```

**How the system defends:**

**Defense — ECDSA Signature Bound to Registered Public Key:**
```python
# Real execution in _run_attack_simulation:
alice_priv,   alice_pub   = crypto.generate_ec_keypair()
mallory_priv, mallory_pub = crypto.generate_ec_keypair()

message = b'Transfer 1000 to Bob - signed by Alice'

sig_alice   = crypto.sign_ecdsa(alice_priv,   message)  # legitimate
sig_mallory = crypto.sign_ecdsa(mallory_priv, message)  # Mallory's forgery

# Server verifies: Mallory's signature against Alice's REGISTERED public key
try:
    crypto.verify_ecdsa(alice_pub, sig_mallory, message)
    # ^ raises InvalidSignature — alice_pub cannot verify mallory's signature
except Exception as exc:
    mitm_blocked = True
    # → exc.__name__ = "InvalidSignature"

# Alice's own signature DOES pass:
crypto.verify_ecdsa(alice_pub, sig_alice, message)   # ✓ valid
```

**Why this works:** The server stores Alice's signing public key at registration time. Even if Mallory substitutes her ECDH key, she cannot produce a valid ECDSA signature for Alice's registered signing key. The server's `handle_message()` calls `verify_ecdsa(registered_sign_key, sig, envelope)` — Mallory's signature fails.

**What gets logged:** `attack_mitm_blocked`

---

### Attack 6: Message Flood (DoS)

**STRIDE Category:** Denial of Service

**What the attack does:**
An attacker sends an overwhelming number of requests in a short time, attempting to exhaust server resources, consume all available connections, or degrade service for legitimate users.

**How the attack works (real HTTP calls from browser):**
```
for i in 1..121:
    GET /api/flood-test  (Authorization: Bearer <valid_jwt>)
    → expect: 200 OK for first 120
    → expect: 429 on request 121
```

**How the system defends:**

**Defense 1 — Sliding-Window Rate Limiter (primary):**
```python
@app.route('/api/flood-test', methods=['GET', 'POST'])
def http_flood_test():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload, err = verify_token(token)
    username = payload.get('username')
    
    # Same rate limiter used for real chat message sending
    ok, retry = _check_rate_limit('flood_test', username, 120)  # 120 per 60s
    if not ok:
        _append_audit_log('attack_dos_blocked', {
            'username': username, 'ip': _client_ip(),
            'retry_after': retry,
        })
        return jsonify({'error': f'Rate limit exceeded. Retry after {retry}s.'}), 429
    
    return jsonify({'ok': True})
```

**Defense 2 — Scapy SYN/ACK Ratio Monitor (network layer):**
```python
# sniffer.py — runs on host with NET_RAW capability
def write_ratio_metric(timestamp_ns):
    syn_count = sum(syn_window)    # last 200 packets
    ack_count = sum(ack_window)
    ratio     = syn_count / max(ack_count, 1)
    is_anomalous = 1 if ratio >= 3.0 and syn_count > 10 else 0
    
    # Write to InfluxDB → Grafana raises visual alert
    Point("network_anomaly") \
        .field("syn_ack_ratio", ratio) \
        .field("dos_suspected", is_anomalous)
```

**Defense 3 — SocketIO message rate limit:**
```python
# In handle_message() for real chat messages:
ok, retry = _check_rate_limit('send', sender, 120)  # same 120/60s limit
if not ok:
    emit('rate_limit', {'error': 'Too many messages', 'retry_after': retry})
    return
```

**Streaming UI:** The counter ticks up in real-time (every 20 requests) showing "110/121 accepted" then "429 BLOCKED at #121". The event appears immediately in the Live Feed.

**What gets logged:** `attack_dos_blocked`

---

## 7. What Data is Stored in the Database

### SQLite (`users.db`) — Two Tables

#### Table: `users`
```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash BLOB    NOT NULL,  -- bcrypt hash (60 bytes)
    created_at    TEXT    DEFAULT (datetime('now'))
);
```
**Stores:** Username + bcrypt hash of password  
**Does NOT store:** Plaintext passwords, JWT tokens, IP addresses, public keys (those are in-memory only)

#### Table: `security_events`
```sql
CREATE TABLE security_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT    NOT NULL,   -- e.g. 'login_failed', 'message_sent'
    detail     TEXT,               -- JSON string of extra context
    ip         TEXT,               -- client IP address
    username   TEXT,               -- affected username
    ts         TEXT    DEFAULT (datetime('now'))
);
```
**Stores:** All security events — logins, failures, attacks, messages (metadata only)

### What is Stored vs. What is NOT Stored

| Data | Stored? | Where | Notes |
|---|---|---|---|
| Username | ✅ Yes | SQLite `users` | Required for login |
| Password (plaintext) | ❌ No | — | Never stored anywhere |
| Password hash | ✅ Yes | SQLite `users` | bcrypt, cost factor 12 |
| Chat message content | ❌ No | — | **E2EE: server never sees plaintext** |
| Encrypted ciphertext | ❌ No | — | Forwarded to recipient, not stored |
| Message metadata | ✅ Yes (partial) | SQLite `security_events` | event_type + hash only, no ciphertext |
| Login attempts | ✅ Yes | SQLite `security_events` | `login_failed` rows |
| Attack events | ✅ Yes | SQLite `security_events` | All 6 attack types logged |
| Public keys (ECDH/ECDSA) | ❌ No | In-memory only | Lost on server restart (PFS) |
| JWT tokens | ❌ No | — | Stateless, validated by signature |
| Audit log | ✅ Yes | `.ndjson` file | Hash-chained, ECDSA-signed entries |

### Key Security Property
**Chat messages are End-to-End Encrypted.** The server acts purely as a relay. It receives `{ciphertext, iv, signature, hash}` — an encrypted blob that only the recipient can decrypt using the ECDH-derived shared key. Even the server operators cannot read message content.

---

## 8. Network Monitoring (Scapy + InfluxDB + Grafana)

### Scapy Packet Sniffer (`monitor/sniffer.py`)

Runs on the Docker host (requires `NET_RAW` capability) and captures all TCP traffic:

```python
from scapy.all import sniff, IP, TCP, get_if_list

def process_packet(packet):
    if IP in packet and TCP in packet:
        flags = parse_tcp_flags(packet[TCP].flags)
        
        syn_window.append(flags["S"])   # 1 if SYN set, else 0
        ack_window.append(flags["A"])   # 1 if ACK set, else 0
        
        # Write per-packet metrics to InfluxDB
        Point("network_traffic") \
            .tag("src_ip", packet[IP].src) \
            .field("size", len(packet)) \
            .field("syn",  flags["S"])
        
        # Write SYN/ACK ratio (DoS indicator)
        syn_count = sum(syn_window)     # last 200 packets
        ack_count = sum(ack_window)
        ratio     = syn_count / max(ack_count, 1)
        is_dos    = 1 if ratio >= 3.0 and syn_count > 10 else 0
        
        Point("network_anomaly") \
            .field("syn_ack_ratio",  ratio) \
            .field("dos_suspected",  is_dos)

sniff(filter="tcp port 80", iface=get_if_list(), prn=process_packet)
```

**Why SYN/ACK ratio?** In normal TCP traffic, for every SYN (connection initiation) there is an ACK (acknowledgment). During a SYN flood DoS attack, an attacker sends many SYN packets but never completes the handshake, causing the ratio `SYN_count / ACK_count` to spike far above 1. A ratio ≥ 3.0 with more than 10 SYNs triggers an alert.

### InfluxDB (Time-Series Database)
- **Bucket:** `network_metrics`
- **Measurements:**
  - `network_traffic` — per-packet fields: `size`, `src_port`, `dst_port`, `syn`, `ack`, `fin`, `rst`, `psh`, `urg`
  - `network_anomaly` — computed fields: `syn_count`, `ack_count`, `syn_ack_ratio`, `dos_suspected`

### Grafana Dashboard (`monitor/grafana_dashboard.json`)
Four panels:
1. **Packet Size Distribution** — time-series of average packet sizes (bytes)
2. **SYN/ACK Ratio** — ratio plotted over time; red threshold line at 3.0; `dos_suspected=1` highlighted in red
3. **Total Packets Captured** — stat panel showing packet count
4. **DoS Alerts** — count of `dos_suspected=1` events in the time window

Queries use **Flux** (InfluxDB 2.x query language):
```flux
from(bucket: "network_metrics")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "network_anomaly"
                     and r._field == "syn_ack_ratio")
  |> aggregateWindow(every: v.windowPeriod, fn: mean, createEmpty: false)
  |> yield(name: "syn_ack_ratio")
```

---

## 9. Audit Log (Hash-Chained, ECDSA-Signed)

### Format
Each entry in `audit_log.ndjson`:
```json
{
  "previous_hash": "a3f1...dead",
  "entry_hash":    "b7c2...beef",
  "signature":     "<base64-ECDSA-DER>",
  "event": {
    "event_type": "message_sent",
    "timestamp":  "2026-05-17T10:23:45.123Z",
    "from":       "alice",
    "to":         "bob",
    "message_id": "uuid-abc123",
    "payload_hash": "sha256-of-plaintext...",
    "signature_verified": true
  }
}
```

### How the Chain Works
```
Entry #1: previous_hash = "000...0" (genesis)
          entry_hash    = SHA256("000...0" + event1_json)
          signature     = ECDSA(audit_private_key, entry_hash)

Entry #2: previous_hash = entry_hash_of_#1
          entry_hash    = SHA256(previous_hash + event2_json)
          signature     = ECDSA(audit_private_key, entry_hash)
...
```

If an attacker modifies event #1, its `entry_hash` changes, which makes entry #2's `previous_hash` wrong, breaking the entire chain from that point forward. The UI shows **✓ chain valid** or **✗ broken** via `/api/audit`.

### Events Logged

| Event Type | Trigger |
|---|---|
| `account_created` | Successful user registration |
| `login_success` | Successful password verification |
| `login_failed` | Wrong password or unknown user |
| `chat_joined` | User registers their WebSocket session |
| `message_sent` | Message forwarded to recipient with valid signature |
| `message_rejected` | ECDSA signature verification failed |
| `handshake` | ECDH key exchange acknowledged |
| `attack_replay_blocked` | Duplicate message_id detected |
| `attack_brute_force_blocked` | Login rate limit exceeded |
| `attack_dos_blocked` | Flood-test rate limit exceeded |
| `attack_invalid_jwt` | JWT forgery/expiry/scope simulation run |
| `attack_mitm_blocked` | MITM key substitution simulation run |
| `attack_tamper_detected` | Ciphertext tampering simulation run |

---

## 10. STRIDE Threat Model Coverage

| Letter | Threat | Attack Simulated | Defense Mechanism |
|---|---|---|---|
| **S** | Spoofing | Forged JWT, MITM Key Substitution | JWT HS256 signature, ECDSA bound to registered key |
| **T** | Tampering | Ciphertext Tampering | AES-256-GCM `InvalidTag`, ECDSA `InvalidSignature`, SHA-256 hash mismatch |
| **R** | Repudiation | (Audit log covers all events) | Hash-chained ECDSA-signed audit log — every action traceable |
| **I** | Information Disclosure | MITM Key Substitution | ECDH P-256 (PFS) + AES-256-GCM E2EE — server never sees plaintext |
| **D** | Denial of Service | Message Flood | Sliding-window rate limiter (120/60s) + Scapy SYN/ACK monitor + Grafana alert |
| **E** | Elevation of Privilege | Brute Force Login, Forged JWT | Rate limiter (15/60s) + bcrypt, JWT scope enforcement |

---

## 11. How to Run the Project

### Prerequisites
- Docker + Docker Compose installed
- Linux (for the Scapy sniffer; optional)

### Start all services
```bash
# Clone / navigate to project directory
cd secure-comm-observability

# Start core services (frontend + backend + InfluxDB + Grafana)
docker compose up --build

# Optionally start the Scapy packet sniffer (Linux only)
docker compose --profile monitor up --build
```

### First-time Grafana setup
1. Go to `http://localhost:3000` (admin / admin)
2. Add data source: **InfluxDB**
   - Query Language: **Flux**
   - URL: `http://influxdb:8086`
   - Auth: **disable Basic Auth**, use **Token**
   - Token: `my-super-secret-auth-token`
   - Organization: `securechat`
   - Default Bucket: `network_metrics`
3. Import `monitor/grafana_dashboard.json` as a new dashboard

### Demo walkthrough
1. Open `http://localhost` — register two accounts (Alice + Bob)
2. Log in as Alice in one browser tab, Bob in another
3. Start a chat — send messages — click the Cpu icon on a message to see crypto details
4. Switch to **Security Dashboard** tab
5. Run each attack by clicking its button, observe:
   - Step-by-step execution trace with ⚡ REAL EXECUTION badge
   - Live Security Events feed updating in real-time
   - `attack_*_blocked` events appearing in the feed

---

## 12. Service URLs

| Service | URL | Credentials |
|---|---|---|
| Frontend (Chat + Dashboard) | `http://localhost` | Register a new account |
| Backend API | `http://localhost:5000` | — |
| Grafana (Traffic Monitor) | `http://localhost:3000` | admin / admin |
| InfluxDB | `http://localhost:8086` | admin / adminpassword |

### Key API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/register` | None | Create account |
| POST | `/api/login` | None | Login → JWT (rate limited: 15/60s per IP) |
| GET | `/api/audit` | JWT | View hash-chained audit log |
| GET | `/api/dashboard/stats` | JWT | Stats + recent security events |
| POST | `/api/attack/simulate` | JWT | Run tamper/replay/jwt/mitm simulations |
| GET | `/api/flood-test` | JWT | DoS demo endpoint (rate limited: 120/60s per user) |
| GET | `/api/benchmark` | JWT | Crypto performance comparison |

---

*This document covers the full implementation as of May 2026. All security mechanisms are active and enforced on every request.*
