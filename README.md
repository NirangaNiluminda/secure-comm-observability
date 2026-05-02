# Secure Communication and Traffic Observability

This repository implements a secure client-server communication model and a real-time traffic analyser for observability and availability monitoring. The system assumes a hostile network environment and enforces Confidentiality, Integrity, and Availability at the application level using modern cryptography and time-series monitoring.

**Contents**
- `backend/` — Flask + SocketIO server and cryptographic integrations.
- `frontend/` — React-based Chat UI.
- `monitor/` — Scapy-based traffic sniffer and helper scripts to push metrics to InfluxDB.
- `docker-compose.yml` — helper compose file (optional) for InfluxDB & Grafana.

**Goals**
- Provide end-to-end encrypted and authenticated messaging between untrusted peers.
- Maintain Perfect Forward Secrecy (PFS) with ephemeral key exchanges.
- Offer non-repudiation via digital signatures.
- Provide real-time availability monitoring (volumetric/DoS detection) via packet feature extraction and Grafana heatmaps.

---

**Requirements**

- System: Linux / macOS / Windows (with WSL recommended for packet capture on Windows).
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

**Secure Communication Design (Application Layer)**

1) Handshake & Key Exchange
- Mechanism: Elliptic Curve Diffie-Hellman (ECDH) with ephemeral key pairs.
- Process: Each peer generates an ephemeral EC key pair (recommended curve: `secp256r1` or `secp384r1`). Peers exchange public keys and derive a shared master key via ECDH. Ephemeral keys provide Perfect Forward Secrecy (PFS).

2) Confidentiality & Integrity
- AEAD: Use AES-256-GCM for message encryption. AES-GCM provides confidentiality and an authentication tag (GMAC) for integrity.
- Hashing: Use SHA-256 for fixed-size digests where needed (file integrity, offline verification).

3) Authentication & Non-repudiation
- Authentication: Use JSON Web Tokens (JWT) to assert identity and scopes (short-lived tokens recommended). Verify signatures strictly and enforce scopes.
- Non-repudiation: Sign messages (or message digests) with ECDSA using the sender's private key. Recipients verify signatures with the sender's public key and log signed events in an append-only audit log.

4) Protocol notes / Best practices
- Use unique per-message nonces / IVs with AES-GCM. Never reuse IVs for the same key.
- Derive symmetric keys from the ECDH master secret via a KDF (HKDF-SHA256) and use separate keys for encryption and signing.
- Rotate ephemeral keys per session and use short JWT lifetimes.
- Protect private keys at rest (OS-protected storage or HSM when available).

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

- Spoofing (Authentication): Attacker impersonates a user. Mitigation: JWT with strict verification, mutual ECDH auth where appropriate.
- Tampering (Integrity): Attacker modifies messages. Mitigation: AES-GCM authentication tags and SHA-256 digests for stored resources.
- Repudiation (Non-repudiation): Actor denies actions. Mitigation: ECDSA-signed messages and secure audit logs.
- Information Disclosure (Confidentiality): Packet sniffing. Mitigation: E2EE with AES-256-GCM and ephemeral ECDH keys.
- Denial of Service (Availability): Volumetric flooding. Mitigation: Monitor SYN/ACK ratios, rate limiting, and Grafana alerting.
- Elevation of Privilege (Authorization): Unauthorized access. Mitigation: RBAC and strict JWT scope enforcement.

---

**How to run (quick start)**

1) Start InfluxDB & Grafana (recommended via Docker Compose)

```bash
docker-compose up -d influxdb grafana
```

If your `docker-compose.yml` includes `influxdb` and `grafana` services, this will start the required services. Otherwise, run official InfluxDB and Grafana images per their docs.

2) Backend

```bash
cd backend
python -m venv .venv
.venv\\Scripts\\activate  # Windows
source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
python app.py
```

3) Frontend

```bash
cd frontend
npm install
npm run dev
```

4) Monitor

```bash
cd monitor
pip install -r requirements.txt
python sniffer.py --port 5000 --influx-url http://localhost:8086 --org your-org --bucket your-bucket --token <INFLUX_TOKEN>
```

Notes:
- On Windows, packet capture may require Administrator privileges or running via WSL.
- Update the InfluxDB connection parameters to match your environment.

---

**Grafana dashboards & alert ideas**

- Create a heatmap panel for packet size distribution using `packet_size` measurement.
- Create a timeseries and heatmap for `syn_count`, `ack_count`, and the `syn_ack_ratio` (SYNs / max(1, ACKs)).
- Alerts to create:
  - SYN/ACK ratio > threshold for X seconds => possible DoS.
  - Packet size distribution shifting to large sizes from a single host => possible data exfiltration.

---

**Testing & Simulation**

- Use `monitor/simulate_dos.py` (if present) or `scapy` to generate crafted traffic and validate Grafana alerts.
- Unit tests: create tests around key derivation, AES-GCM encryption/decryption with the derived keys, and ECDSA signature verification.

---

**Files of interest**
- Backend server: `backend/app.py`
- Sniffer & simulator: `monitor/sniffer.py`, `monitor/simulate_dos.py`
- Frontend entry: `frontend/src/main.jsx`

---

(Repository includes examples and starter modules for the components described above. See `backend/crypto.py` for a starter ECDH/ECDSA helper and `monitor/grafana_dashboard.json` for a sample Grafana dashboard.)
