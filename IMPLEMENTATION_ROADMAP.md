# Secure Communication and Traffic Observability

This document maps the target security architecture to the current implementation and defines the next implementation increments.

## 1) Security Architecture

### Handshake and Key Exchange
- Primitive: ECDH over P-256 (ephemeral per user session context).
- Implemented in: frontend/src/crypto.js and frontend/src/App.jsx.
- Flow:
  1. Each user generates ECDH + ECDSA keypairs in browser memory.
  2. Client registers public keys with backend.
  3. A sender fetches recipient public keys and derives AES-256-GCM shared key.

### Confidentiality and Integrity
- Primitive: AES-256-GCM for authenticated encryption.
- Additional digest: SHA-256 over plaintext for independent integrity check.
- Implemented in: frontend/src/crypto.js and frontend/src/App.jsx.
- Signed envelope fields: from, to, message_id, sent_at, iv, ciphertext, hash.

### Authentication and Authorization
- Primitive: JWT (short-lived, scoped) on Socket.IO events.
- Scope model:
  - chat:send
  - chat:read
  - key:read
- Implemented in: backend/app.py.
- Controls:
  - Token verification and expiry checks.
  - Scope enforcement for key lookup and message send.
  - Sender identity bound to token subject.
  - Backend rate limiting for connect, register, and send actions.

### Non-Repudiation
- Primitive: ECDSA P-256 signatures.
- Implemented in: frontend/src/crypto.js and frontend/src/App.jsx.
- Receiver verifies signature over deterministic envelope before accepting message.
- Server-side persistence: append-only hash-chain audit log with ECDSA signatures in backend/audit_log.ndjson.

## 2) Availability and Observability

### Packet Capture
- Primitive: Scapy sniff on backend traffic port.
- Implemented in: monitor/sniffer.py.
- Extracted metrics:
  - src_ip, dst_ip, src_port, dst_port
  - packet size
  - TCP flags (syn, ack, fin, rst, psh, urg)

### Time-Series Storage
- Backend: InfluxDB 2.x (Docker service).
- Measurement names:
  - network_traffic
  - network_anomaly

### Detection Logic
- Rolling window SYN/ACK ratio with threshold:
  - syn_ack_ratio = sum(SYN window) / max(sum(ACK window), 1)
- Alert indicator:
  - dos_suspected = 1 when ratio exceeds DOS_RATIO_THRESHOLD and SYN volume is high.

## 3) Grafana Panel Queries

Use InfluxDB data source (Flux).

### Packet Size Distribution (Heatmap)
```flux
from(bucket: "network_metrics")
  |> range(start: -15m)
  |> filter(fn: (r) => r._measurement == "network_traffic")
  |> filter(fn: (r) => r._field == "size")
```

### SYN/ACK Ratio (Time series)
```flux
from(bucket: "network_metrics")
  |> range(start: -15m)
  |> filter(fn: (r) => r._measurement == "network_anomaly")
  |> filter(fn: (r) => r._field == "syn_ack_ratio")
```

### DoS Suspicion Flag (State timeline)
```flux
from(bucket: "network_metrics")
  |> range(start: -15m)
  |> filter(fn: (r) => r._measurement == "network_anomaly")
  |> filter(fn: (r) => r._field == "dos_suspected")
```

## 4) Environment Variables

### Backend
- JWT_SECRET
- JWT_TTL_MINUTES
- RATE_LIMIT_WINDOW_SECONDS
- RATE_LIMIT_CONNECT_PER_WINDOW
- RATE_LIMIT_REGISTER_PER_WINDOW
- RATE_LIMIT_SEND_PER_WINDOW
- AUDIT_LOG_PATH
- AUDIT_STATE_PATH
- AUDIT_PRIVATE_KEY_PATH
- AUDIT_PUBLIC_KEY_PATH

### Sniffer
- INFLUX_URL
- INFLUX_TOKEN
- INFLUX_ORG
- INFLUX_BUCKET
- CAPTURE_FILTER
- SYN_ACK_WINDOW
- DOS_RATIO_THRESHOLD

## 5) Operational Validation Commands

### DoS simulation and alert validation
```bash
python monitor/simulate_dos.py --mode syn --count 1200 --pps 300 --check-alert
```

### Verify audit chain and signatures
```bash
python backend/verify_audit_log.py
```

## 6) Roadmap Alignment

Phase 1: React + Flask-SocketIO chat
- Status: implemented.

Phase 2: ECDH, ECDSA, SHA-256, AES-GCM
- Status: implemented and hardened with signed message envelope + replay checks.

Phase 3: Scapy to InfluxDB
- Status: implemented and extended with anomaly measurement.

Phase 4: Grafana heatmaps and DoS simulation
- Status: completed (monitor/simulate_dos.py added, with optional Influx alert check).

Phase 5: STRIDE documentation for viva
- Status: strengthened with signed append-only audit chain and audit verifier script for evidence.
