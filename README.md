# Secure Communication and Traffic Observability

This repository implements a secure client-server communication model with **full mutual authentication** and a real-time traffic analyser for observability and availability monitoring. The system assumes a hostile network environment and enforces Confidentiality, Integrity, and Availability at the application level using modern cryptography and time-series monitoring.

**Contents**
- `backend/` — Flask + SocketIO server and cryptographic integrations.
- `frontend/` — React-based Chat UI with Web Crypto API (ECDH, ECDSA, AES-256-GCM).
- `monitor/` — Scapy-based traffic sniffer and helper scripts to push metrics to InfluxDB.
- `docker-compose.yml` — Docker Compose stack (backend · frontend · InfluxDB · Grafana · optional monitor sniffer).
- `DIAGRAMS.html` — Interactive Mermaid diagram viewer: architecture, all auth flows, attack simulations, STRIDE.

**Goals**
- Authenticate the **server to the client** at the transport layer using TLS 1.3 with a CA-signed certificate (closes the "Trudy acts as server" gap).
- Provide end-to-end encrypted and authenticated messaging between untrusted peers.
- Maintain Perfect Forward Secrecy (PFS) at two independent layers: TLS ECDHE (transport) and ephemeral ECDH (application).
- Offer non-repudiation via ECDSA digital signatures and a hash-chained audit log.
- Close all three mutual authentication gaps: Challenge-Response login, server-signed key certificates, and Safety Numbers.
- Provide real-time availability monitoring (volumetric/DoS detection) via packet feature extraction and Grafana heatmaps.

---

**Requirements**

- System: Linux / macOS / Windows (with WSL recommended for packet capture on Windows).
- OpenSSL 1.1+ for TLS certificate generation (`openssl version` to check).
- Python 3.9+ for `backend/` and `monitor/` scripts.
- Node.js 16+ and npm/yarn for `frontend/`.
- Docker & Docker Compose (recommended) for InfluxDB and Grafana, or local install of those services.

Python packages (see `backend/requirements.txt` and `monitor/requirements.txt`):
- Flask, Flask-SocketIO
- cryptography (for ECDH, ECDSA, AES-GCM)
- PyJWT (for JWT handling)
- scapy (for packet sniffing)
- influxdb-client (for pushing metrics)

Node packages are defined in `frontend/package.json`.

---

**Transport Security (TLS Layer)**

0) TLS — Server Authentication to Client
- Problem: Without TLS, a network-level attacker (Trudy) can intercept all traffic before any application-layer crypto runs, impersonating the server.
- Solution: Nginx terminates HTTPS on port 8443 using a certificate signed by a Local CA. The browser verifies the certificate before sending any login data.
- Trust chain: `certs/ca.crt` (Local CA) → signs `certs/server.crt` (SAN: localhost, 127.0.0.1) → nginx presents on TLS handshake → browser verifies → server identity confirmed.
- TLS 1.3 with ECDHE cipher suites — forward secrecy at the transport layer.
- HSTS header (`max-age=31536000`) enforces HTTPS for 1 year after first visit.
- Security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`.
- HTTP port 8080 returns `301 Moved Permanently` to `https://localhost:8443`.

Generate / regenerate certificates:
```bash
bash scripts/generate-certs.sh
```
To trust the cert (no browser warning): import `certs/ca.crt` into your browser's Certificate Authority trust store.
For production: replace with Let's Encrypt — the nginx.conf works unchanged.

**Secure Communication Design (Application Layer)**

1) Handshake & Key Exchange
- Mechanism: Elliptic Curve Diffie-Hellman (ECDH) with ephemeral key pairs (P-256 / secp256r1).
- Process: Each peer generates fresh ECDH + ECDSA key pairs at login. Public keys are exchanged via the server. The shared AES-256 key is derived locally via HKDF-SHA256 — never transmitted. Ephemeral keys provide Perfect Forward Secrecy (PFS).

2) Confidentiality & Integrity
- AEAD: AES-256-GCM for message encryption. GCM appends a 16-byte authentication tag — any ciphertext modification raises `InvalidTag`.
- Three independent integrity checks per message: AES-GCM auth tag · ECDSA envelope signature · SHA-256 plaintext hash.

3) Full Mutual Authentication (three gaps closed)

**GAP1 — Client → Server (Challenge-Response Login)**
- Old: password only. New: two-step protocol.
  1. `POST /api/auth/challenge {username, password}` → server verifies bcrypt, returns 32-byte random challenge + ID (60s TTL).
  2. Client signs challenge bytes with ECDSA private key → `POST /api/auth/complete {challenge_id, username, signature, ecdsaPubJwk}` → server verifies signature → JWT issued.
- A stolen password alone cannot log in — the attacker also needs the ECDSA private key.

**GAP2 — Server → Client (Server-Signed Key Certificates)**
- On successful login, server signs the client's ECDSA public key with its own ECDSA private key (`audit_private_key`) → returns `server_key_cert` (DER base64).
- `GET /api/server/pubkey` exposes server's ECDSA public key as JWK.
- When Alice retrieves Bob's key, she also gets `bob.server_key_cert`. She verifies it: `SubtleCrypto.verify(serverKey, derToP1363(cert), canonical(bobEcdsaPub))`. ✓ = server vouches for Bob's key.

**GAP3 — Client ↔ Client (Safety Numbers)**
- `computeSafetyNumber(myEcdsaPubJwk, theirEcdsaPubJwk)` = SHA-256 of both keys (sorted for symmetry) → 12 groups of 5 decimal digits.
- Both Alice and Bob compute the same number. A MITM produces a different number — detectable by a phone call.
- Displayed in the chat header under the "Certified / Unverified" button.

4) Authentication Tokens & Non-repudiation
- JWT HS256 with 60-min TTL and per-action scopes (`chat:send · chat:read · key:read`).
- Every message envelope is ECDSA-signed. Server verifies against the sender's registered key before forwarding.
- Hash-chained ECDSA-signed audit log: every security event is tamper-evident.

5) Protocol notes / Best practices
- Unique 12-byte random IVs per message. AES-GCM key never reused.
- HKDF-SHA256 derives the symmetric key from the ECDH shared secret with a domain-separation info string.
- Ephemeral keys per session (new keypair each login) → PFS.
- Rate limiting: 15 logins / 60s per IP, 120 messages / 60s per user, 40 connections / 60s per IP.

---

**Traffic Analyser & Availability Monitoring**

Overview
- A monitoring component captures raw packets (TCP port 5000 by default), extracts features, and pushes metrics into InfluxDB. Grafana reads InfluxDB and visualizes heatmaps and derived metrics to detect anomalies (DoS, exfiltration, scans).

Data capture (monitor/)
- `monitor/sniffer.py` (or similar) uses Scapy to sniff packets filtered to the application port. Extracted features include:
  - timestamp
  - source IP, destination IP
  - packet size (len)
  - TCP flags (SYN, ACK, FIN, RST, PSH, URG)
  - counts and rates aggregated into short windows (e.g., 1s, 10s)

Storage
- InfluxDB (time-series) stores measurements like `packet_count`, `bytes`, `syn_count`, `ack_count`, and derived ratios such as `syn_ack_ratio`.

Visualization
- Grafana heatmaps and timeseries dashboards visualize:
  - Packet size distribution (heatmap of packet size vs time).
  - SYN/ACK ratio heatmap (spikes in SYN without ACKs indicate possible DoS).
  - High-volume per-source IP graphs to spot flooders.

---

**STRIDE Threat Model (summary)**

| Letter | Threat | Attack Simulated | Defense |
|--------|--------|-----------------|---------|
| **S** Spoofing | Impersonating a user or server | Forged JWT · MITM key substitution · Trudy acting as fake server | **TLS cert verification (⓪)** · JWT HS256 · ECDSA on registered key · **Challenge-Response (⑪)** · **Server Key Cert (⑫)** · **Safety Numbers (⑬)** |
| **T** Tampering | Modifying data in transit | Ciphertext bit-flip (demo toggle) | AES-256-GCM auth tag · ECDSA envelope signature · SHA-256 hash |
| **R** Repudiation | Denying an action occurred | Replay attack | ECDSA non-repudiation · Hash-chained ECDSA-signed audit log |
| **I** Info Disclosure | Exposing private data | MITM key substitution · network eavesdropping | **TLS 1.3 transport encryption (⓪)** · ECDH PFS (key never transmitted) · AES-256-GCM E2EE |
| **D** Denial of Service | Making service unavailable | 121-request message flood | Sliding-window rate limiter (120/60s) · Scapy SYN/ACK monitor → Grafana |
| **E** Elevation of Privilege | Gaining unauthorized access | Brute-force login · Forged JWT scopes | bcrypt (cost 12) · Rate limit (15/60s per IP) · JWT scope enforcement |

---

**How to run (quick start)**

Recommended: Docker Compose (starts all services automatically):

```bash
# Start everything (frontend · backend · InfluxDB · Grafana):
docker compose up --build

# Also start the Scapy packet sniffer (Linux host only):
docker compose --profile monitor up --build
```

Service URLs after startup:
- **Frontend** (React chat + dashboard): https://localhost:8443  ← main entry point (HTTPS)
- **Frontend** (HTTP redirect): http://localhost:8080  ← redirects to HTTPS automatically
- **Backend** (Flask API): http://localhost:5001  (internal — do not expose publicly)
- **Grafana** (DoS anomaly charts): http://localhost:3001  (admin / admin)
- **InfluxDB** (time-series metrics): http://localhost:8087

> **First run only:** Certificates are pre-generated in `certs/`. On first browser visit to `https://localhost:8443`, you will see a security warning because the Local CA is not yet trusted by your browser. Either click "Advanced → Proceed" (connection is still encrypted), or import `certs/ca.crt` into your browser's CA trust store to eliminate the warning permanently.

New API endpoints (mutual auth):
- `POST /api/auth/challenge` — Step 1: verify password, receive challenge
- `POST /api/auth/complete`  — Step 2: submit ECDSA signature, receive JWT + server key cert
- `GET  /api/server/pubkey`  — Fetch server's ECDSA public key JWK (for cert verification)

Manual backend run (without Docker):

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Manual frontend run:

```bash
cd frontend
npm install
npm run dev
```

Notes:
- Scapy packet capture requires Linux and NET_RAW capability (or root). Windows users should use Docker or WSL.
- The monitor container uses `network_mode: host` to capture real traffic on port 5000.

---

**Grafana dashboards & alert ideas**

- Create a heatmap panel for packet size distribution using `packet_size` measurement.
- Create a timeseries and heatmap for `syn_count`, `ack_count`, and the `syn_ack_ratio` (SYNs / max(1, ACKs)).
- Alerts to create:
  - SYN/ACK ratio > threshold for X seconds => possible DoS.
  - Packet size distribution shifting to large sizes from a single host => possible data exfiltration.

---

**Crypto Implementation**

The repository includes:
- `backend/crypto.py` — Low-level crypto primitives: ECDH key generation, HKDF KDF, AES-256-GCM encryption/decryption, ECDSA signing/verification.
- `backend/app.py` — Flask + SocketIO server with integrated handshake, session key derivation, and signature verification for non-repudiation.
- `backend/demo_crypto.py` — Standalone demo showing ECDH handshake, encryption, and signature verification.
- `backend/client_crypto_demo.py` — Full end-to-end demo simulating Alice→Bob encrypted message exchange with server signature verification.

**Running the crypto demos:**

```bash
cd backend
python -m pip install cryptography
python demo_crypto.py          # Basic crypto primitives
python client_crypto_demo.py   # Full E2EE message flow
```

---

**Testing & Simulation**

- Use `monitor/simulate_dos.py` (if present) or `scapy` to generate crafted traffic and validate Grafana alerts.
- Unit tests: create tests around key derivation, AES-GCM encryption/decryption with the derived keys, and ECDSA signature verification.

---

**HTTP API Endpoints**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/register` | Create user account (bcrypt hashed) |
| POST | `/api/auth/challenge` | **[NEW]** Step 1 of challenge-response: verify password → issue challenge |
| POST | `/api/auth/complete` | **[NEW]** Step 2: verify ECDSA signature → issue JWT + server key cert |
| GET  | `/api/server/pubkey` | **[NEW]** Server's ECDSA public key JWK (for cert verification) |
| POST | `/api/login` | Legacy single-step login (kept for backward compat / attack demos) |
| GET  | `/api/audit` | Read hash-chained audit log (requires JWT) |
| GET  | `/api/dashboard/stats` | Security event counts + recent events |
| POST | `/api/attack/simulate` | Run attack simulation (replay/tamper/brute_force/jwt/mitm/dos) |
| GET  | `/api/flood-test` | Rate-limited endpoint for DoS demo |
| GET  | `/api/benchmark` | Crypto performance benchmark |

**SocketIO Events**

- `register` — Register ECDH + ECDSA public keys + `server_key_cert` (from challenge-response login).
- `send_message` — Send AES-256-GCM encrypted, ECDSA-signed message.
- `receive_message` — Server forwards to recipient (never decrypts content).
- `get_public_key` — Retrieve peer's public keys + `server_key_cert` (for GAP2 verification).
- `handshake` — Acknowledge key exchange with a peer.

---

**Files of interest**
- Backend server: `backend/app.py` — Flask + SocketIO; challenge-response endpoints; ECDSA cert signing; rate limiting; attack simulator
- Crypto primitives: `backend/crypto.py` — ECDH, ECDSA, AES-256-GCM, HKDF, `public_key_to_jwk()`
- Database: `backend/database.py` — SQLite users + security events; `get_security_stats()`
- Frontend app: `frontend/src/App.jsx` — Challenge-response login flow; Safety Numbers UI; cert verification
- Frontend crypto: `frontend/src/crypto.js` — Web Crypto API wrappers; `computeSafetyNumber()`; `verifyServerKeyCert()`; `_derToP1363()`
- Nginx config: `frontend/nginx.conf` — TLS termination; HTTP→HTTPS redirect; security headers; Socket.IO proxy
- Security dashboard: `frontend/src/Dashboard.jsx` — Live event feed; attack simulator UI; benchmarks
- Sniffer: `monitor/sniffer.py` — Scapy packet capture; SYN/ACK ratio; InfluxDB writes
- DoS simulator: `monitor/simulate_dos.py` — SYN flood / TCP connect flood; InfluxDB alert check
- TLS certificates: `certs/` — `ca.crt` (Local CA), `server.crt` (server cert), config files
- Cert generator: `scripts/generate-certs.sh` — Regenerate Local CA + server cert with correct SANs
- Diagrams: `DIAGRAMS.html` — All Mermaid diagrams; TLS flow; auth flow; mutual auth; attack sequences; STRIDE

---

**License**

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.
