export async function generateECDHKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
}

export async function generateECDSAKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
}

export async function exportKey(key) {
  return await window.crypto.subtle.exportKey("jwk", key);
}

export async function importECDHPublicKey(jwk) {
  return await window.crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

export async function importECDSAPublicKey(jwk) {
  return await window.crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

export async function deriveSharedKey(privateKey, publicKey) {
  return await window.crypto.subtle.deriveKey(
    { name: "ECDH", public: publicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptMessage(sharedKey, plaintext) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    sharedKey,
    encoded
  );
  
  return {
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertextBuffer)
  };
}

export async function decryptMessage(sharedKey, ivBase64, ciphertextBase64) {
  const iv = base64ToArrayBuffer(ivBase64);
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    sharedKey,
    ciphertext
  );
  
  return new TextDecoder().decode(decryptedBuffer);
}

export async function signMessage(privateKey, message) {
  const encoded = new TextEncoder().encode(message);
  const signature = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    encoded
  );
  return arrayBufferToBase64(signature);
}

export async function verifySignature(publicKey, signatureBase64, message) {
  const signature = base64ToArrayBuffer(signatureBase64);
  const encoded = new TextEncoder().encode(message);
  return await window.crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    publicKey,
    signature,
    encoded
  );
}

export async function generateHash(message) {
  const encoded = new TextEncoder().encode(message);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", encoded);
  return arrayBufferToBase64(hashBuffer);
}

export function buildSignedEnvelope(fields) {
  const ordered = {
    from: fields.from,
    to: fields.to,
    message_id: fields.message_id,
    sent_at: fields.sent_at,
    iv: fields.iv,
    ciphertext: fields.ciphertext,
    hash: fields.hash
  };
  return JSON.stringify(ordered);
}

// ─────────────────────────────────────────────────────────────
// IndexedDB — persistent identity key storage
//
// The ECDSA identity keypair is generated ONCE at registration and stored
// here so it survives browser tab/window close.  Private keys never leave
// the browser — only the public half is sent to the server.
//
// Keys are scoped per username so multiple accounts can share a browser.
// ─────────────────────────────────────────────────────────────

const IDB_NAME  = 'securechat-identity';
const IDB_STORE = 'keys';
const IDB_VER   = 1;

function _openIdentityDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VER);
    req.onupgradeneeded = e => e.target.result.createObjectStore(IDB_STORE);
    req.onsuccess = e  => resolve(e.target.result);
    req.onerror   = () => reject(req.error);
  });
}

/**
 * Persist an ECDSA keypair for a specific username.
 * CryptoKey objects are structured-cloneable — IndexedDB stores them natively.
 * Called once during registration; survives page reloads and browser restarts.
 */
export async function saveIdentityKeyPair(username, keyPair) {
  const idb = await _openIdentityDB();
  return new Promise((resolve, reject) => {
    const tx = idb.transaction(IDB_STORE, 'readwrite');
    tx.objectStore(IDB_STORE).put(keyPair, `identity_${username}`);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

/**
 * Load the persisted ECDSA keypair for a username.
 * Returns null if not found (user registered on a different device/browser,
 * or browser data was cleared).
 */
export async function loadIdentityKeyPair(username) {
  const idb = await _openIdentityDB();
  return new Promise((resolve, reject) => {
    const tx  = idb.transaction(IDB_STORE, 'readonly');
    const req = tx.objectStore(IDB_STORE).get(`identity_${username}`);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });
}

// ─────────────────────────────────────────────────────────────
// Sign raw bytes (used for challenge-response during login)
// ─────────────────────────────────────────────────────────────

/**
 * Sign an ArrayBuffer/Uint8Array directly with an ECDSA private key.
 * Used to sign the random server challenge during the login flow.
 */
export async function signBytes(privateKey, data) {
  const signature = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    data
  );
  return arrayBufferToBase64(signature);
}

// ─────────────────────────────────────────────────────────────
// Safety Numbers  (GAP3: peer key fingerprint for out-of-band verification)
// ─────────────────────────────────────────────────────────────

/**
 * Compute a Safety Number (Signal-style) from two ECDSA public key JWKs.
 * Both sides compute the same number regardless of call order.
 * Format: 12 groups of 5 digits  e.g. "12345 67890 11234 56789 01234 56789 …"
 */
export async function computeSafetyNumber(myEcdsaPubJwk, theirEcdsaPubJwk) {
  // Use only key material (crv, x, y) — stable across different JWK field sets
  const keyStr = (jwk) => `P-256:${jwk.x}:${jwk.y}`;
  // Sort the two strings so result is symmetric (same for both chat partners)
  const [a, b] = [keyStr(myEcdsaPubJwk), keyStr(theirEcdsaPubJwk)].sort();
  const encoded = new TextEncoder().encode(a + '|' + b);
  const hashBuf = await window.crypto.subtle.digest('SHA-256', encoded);
  const bytes   = new Uint8Array(hashBuf);
  // Encode as decimal groups: take 20 bytes → 60 decimal digits → 12 groups of 5
  let dec = '';
  for (let i = 0; i < 20; i++) dec += bytes[i].toString().padStart(3, '0');
  const groups = [];
  for (let i = 0; i < 60; i += 5) groups.push(dec.slice(i, i + 5));
  return groups.join(' ');
}

// ─────────────────────────────────────────────────────────────
// Server key certificate verification  (GAP2: server acts as mini-CA)
// ─────────────────────────────────────────────────────────────

/**
 * Verify the server-issued certificate on a peer's ECDSA public key.
 *
 * The server signs canonical(ecdsaPubJwk) with its ECDSA private key → DER encoded.
 * This function:
 *   1. Imports the server public key from its JWK
 *   2. Converts the DER certificate to P1363 format (required by Web Crypto)
 *   3. Verifies the signature over the canonical JWK bytes
 *
 * Returns true if the server vouches for this key, false otherwise.
 */
export async function verifyServerKeyCert(serverPubJwk, certB64, ecdsaPubJwk) {
  try {
    // Canonical form must match what Python's json.dumps(sort_keys=True) produces
    const canonical = JSON.stringify(
      Object.keys(ecdsaPubJwk).sort().reduce((o, k) => { o[k] = ecdsaPubJwk[k]; return o; }, {})
    );
    const encoded  = new TextEncoder().encode(canonical);
    const derBytes = new Uint8Array(base64ToArrayBuffer(certB64));
    // Web Crypto ECDSA.verify() needs P1363 (r‖s); server signs in DER → convert
    const p1363    = _derToP1363(derBytes);
    const serverKey = await window.crypto.subtle.importKey(
      'jwk', serverPubJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, ['verify']
    );
    return await window.crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      serverKey, p1363, encoded
    );
  } catch {
    return false;
  }
}

/** Convert DER-encoded ECDSA signature to IEEE P1363 (r‖s, 64 bytes for P-256). */
function _derToP1363(der) {
  let off = 0;
  if (der[off++] !== 0x30) throw new Error('Not a DER SEQUENCE');
  // Skip length field (may be 1 or 2 bytes)
  if (der[off] & 0x80) off += (der[off] & 0x7f) + 1; else off++;
  // r INTEGER
  if (der[off++] !== 0x02) throw new Error('Expected INTEGER (r)');
  const rLen = der[off++];
  const r    = der.slice(off, off + rLen); off += rLen;
  // s INTEGER
  if (der[off++] !== 0x02) throw new Error('Expected INTEGER (s)');
  const sLen = der[off++];
  const s    = der.slice(off, off + sLen);
  // Pad each to exactly 32 bytes (remove leading 0x00 padding, right-align)
  const padInt = (src, out, outOff) => {
    const start = (src[0] === 0 && src.length > 32) ? 1 : 0;
    const len   = src.length - start;
    out.set(src.slice(start), outOff + (32 - len));
  };
  const p1363 = new Uint8Array(64);
  padInt(r, p1363, 0);
  padInt(s, p1363, 32);
  return p1363;
}

export function generateMessageId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
}

export function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}
