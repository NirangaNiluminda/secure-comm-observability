# STRIDE Threat Modeling Analysis

This document details the threat modeling analysis conducted for the Secure Communication and Traffic Observability system, employing the STRIDE methodology.

## 1. System Context
The system consists of a Client-Server architecture utilizing WebSockets for real-time messaging. The network environment is assumed hostile. All security properties (Confidentiality, Integrity, and Availability) are enforced at the application level through cryptographic proofs. A parallel Traffic Analyser monitors network traffic on the application port to identify anomalous behavior.

## 2. STRIDE Analysis

| Threat Category | Affected Property | Description & Scenario | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Authentication | An attacker attempts to impersonate a legitimate user by replaying or forging login requests. | The system utilizes **JWT (JSON Web Tokens)** issued upon secure registration for strict session verification. Furthermore, initial handshakes rely on verifiable **ECDH** key generation and strict identity mapping in the backend. |
| **Tampering** | Integrity | An adversary intercepts network traffic and modifies an encrypted packet (e.g., flipping bits) to corrupt the payload or alter the message meaning. | **AES-256-GCM**, an Authenticated Encryption with Associated Data (AEAD) mode, is employed. The built-in **GMAC** tag immediately flags any ciphertext tampering. Additionally, standalone **SHA-256** digests provide an extra layer of pre-decryption payload validation. |
| **Repudiation** | Non-repudiation | A sender malicious denies having sent a specific command or message, complicating audit trails. | All outgoing messages are strictly signed using **ECDSA (Elliptic Curve Digital Signature Algorithm)**. The recipient inherently verifies the signature using the sender's public key, forming irrefutable cryptographic proof of origin. |
| **Information Disclosure** | Confidentiality | An eavesdropper sniffs network packets to extract sensitive conversational data or credentials. | True **End-to-End Encryption (E2EE)** is implemented. A shared master key is derived via **ECDH**, and all data is encrypted via **AES-256-GCM** before leaving the client. The backend and network only observe opaque ciphertext. |
| **Denial of Service** | Availability | A botnet floods the backend with TCP connections (e.g., SYN flood) or massive payloads, preventing legitimate users from communicating. | The **Traffic Analyser (Scapy + InfluxDB)** continuously monitors network flow. Real-time **Grafana Heatmaps** track the SYN/ACK ratio and packet size distribution, allowing for immediate anomaly detection and the potential for automated mitigation (e.g., rate-limiting at the firewall level). |
| **Elevation of Privilege** | Authorization | A standard user attempts to manipulate socket events to access administrative endpoints or other users' sessions. | Strict scope and room validation are enforced. Socket.IO private rooms and strict **JWT payload validation** ensure users can only emit and receive messages intended for their authorized alias. E2EE ensures even if they received another user's message, they could not decrypt it. |

## 3. Conclusion
By heavily relying on modern cryptographic primitives (ECDH for Forward Secrecy, AES-GCM for Authenticated Encryption, ECDSA for Non-repudiation) and establishing a robust observability pipeline, the system effectively neutralizes critical threats at the application layer, treating the underlying network as entirely untrusted.
