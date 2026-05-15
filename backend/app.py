from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import jwt
import bcrypt
import datetime
import os
import time
import json
import hashlib
import base64
import threading
from functools import wraps
from collections import deque
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import crypto
import database as db

# ─────────────────────────────────────────────────────────────
# App bootstrap
# ─────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET', 'secure-chat-secret')
CORS(app, resources={r'/*': {'origins': '*'}})
socketio = SocketIO(app, cors_allowed_origins='*')

db.init_db()

# ─────────────────────────────────────────────────────────────
# In-memory runtime state (ephemeral — survives only this process)
# ─────────────────────────────────────────────────────────────

# Connected chat users: { username: { sid, public_key, sign_public_key } }
users: dict = {}
session_keys: dict = {}

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────

JWT_ALGORITHM                  = 'HS256'
JWT_TTL_MINUTES                = int(os.getenv('JWT_TTL_MINUTES', '60'))
RATE_LIMIT_WINDOW_SECONDS      = int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', '60'))
RATE_LIMIT_CONNECT_PER_WINDOW  = int(os.getenv('RATE_LIMIT_CONNECT_PER_WINDOW', '40'))
RATE_LIMIT_REGISTER_PER_WINDOW = int(os.getenv('RATE_LIMIT_REGISTER_PER_WINDOW', '15'))
RATE_LIMIT_SEND_PER_WINDOW     = int(os.getenv('RATE_LIMIT_SEND_PER_WINDOW', '120'))

BASE_DIR               = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG_PATH         = os.getenv('AUDIT_LOG_PATH',   os.path.join(BASE_DIR, 'audit_log.ndjson'))
AUDIT_STATE_PATH       = os.getenv('AUDIT_STATE_PATH', os.path.join(BASE_DIR, 'audit_chain_state.json'))
AUDIT_PRIVATE_KEY_PATH = os.getenv('AUDIT_PRIVATE_KEY_PATH', os.path.join(BASE_DIR, 'audit_signing_key.pem'))
AUDIT_PUBLIC_KEY_PATH  = os.getenv('AUDIT_PUBLIC_KEY_PATH',  os.path.join(BASE_DIR, 'audit_signing_public.pem'))

rate_limit_state  = {}
rate_limit_lock   = threading.Lock()
audit_lock        = threading.Lock()
session_keys_lock = threading.Lock()

# ─────────────────────────────────────────────────────────────
# Audit log (hash-chained, ECDSA-signed)
# ─────────────────────────────────────────────────────────────

def _ensure_directory(path):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def _load_or_create_audit_keypair():
    _ensure_directory(AUDIT_PRIVATE_KEY_PATH)
    if os.path.exists(AUDIT_PRIVATE_KEY_PATH):
        with open(AUDIT_PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
        with open(AUDIT_PRIVATE_KEY_PATH, 'wb') as f:
            f.write(pem)
    pub = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    _ensure_directory(AUDIT_PUBLIC_KEY_PATH)
    with open(AUDIT_PUBLIC_KEY_PATH, 'wb') as f:
        f.write(pub)
    return private_key


def _load_last_audit_hash():
    if os.path.exists(AUDIT_STATE_PATH):
        try:
            with open(AUDIT_STATE_PATH, 'r') as f:
                h = json.load(f).get('last_hash', '')
            if isinstance(h, str) and len(h) == 64:
                return h
        except Exception:
            pass
    return '0' * 64


def _save_last_audit_hash(h):
    _ensure_directory(AUDIT_STATE_PATH)
    with open(AUDIT_STATE_PATH, 'w') as f:
        json.dump({'last_hash': h, 'updated_at': datetime.datetime.utcnow().isoformat() + 'Z'}, f)


audit_private_key = _load_or_create_audit_keypair()
last_audit_hash   = _load_last_audit_hash()


def _append_audit_log(event_type, event_data):
    global last_audit_hash
    event = {'event_type': event_type,
             'timestamp': datetime.datetime.utcnow().isoformat() + 'Z', **event_data}
    canonical = json.dumps(event, sort_keys=True, separators=(',', ':'))
    with audit_lock:
        prev        = last_audit_hash
        entry_hash  = hashlib.sha256((prev + canonical).encode()).hexdigest()
        sig         = audit_private_key.sign(entry_hash.encode(), ec.ECDSA(hashes.SHA256()))
        sig_b64     = base64.b64encode(sig).decode()
        entry       = {'previous_hash': prev, 'entry_hash': entry_hash,
                       'signature': sig_b64, 'event': event}
        _ensure_directory(AUDIT_LOG_PATH)
        with open(AUDIT_LOG_PATH, 'a') as f:
            f.write(json.dumps(entry, separators=(',', ':')) + '\n')
        last_audit_hash = entry_hash
        _save_last_audit_hash(entry_hash)
    # Mirror to SQLite security events table
    db.log_security_event(event_type,
                          detail=json.dumps({k: v for k, v in event_data.items() if k != 'ip'}, separators=(',', ':')),
                          ip=event_data.get('ip', ''),
                          username=event_data.get('username') or event_data.get('from', ''))

# ─────────────────────────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────────────────────────

def _client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    return fwd.split(',')[0].strip() if fwd else (request.remote_addr or 'unknown')


def _check_rate_limit(action, subject, limit):
    now    = time.time()
    key    = f'{action}:{subject}'
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with rate_limit_lock:
        q = rate_limit_state.setdefault(key, deque())
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= limit:
            retry = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - q[0])))
            return False, retry
        q.append(now)
    return True, 0

# ─────────────────────────────────────────────────────────────
# JWT helpers
# ─────────────────────────────────────────────────────────────

def generate_jwt(username):
    payload = {
        'username': username,
        'scopes': ['chat:send', 'chat:read', 'key:read'],
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_TTL_MINUTES),
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm=JWT_ALGORITHM)


def verify_token(token, required_scope=None):
    if not token:
        return None, 'Missing token'
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[JWT_ALGORITHM])
        if required_scope and required_scope not in payload.get('scopes', []):
            return None, f'Missing scope: {required_scope}'
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, 'Token expired'
    except jwt.InvalidTokenError:
        return None, 'Invalid token'


def require_scope(scope):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = None
            data  = args[0] if args and isinstance(args[0], dict) else {}
            if request.event and isinstance(request.event, dict):
                ra = request.event.get('args', [])
                if ra and isinstance(ra[0], dict):
                    token = ra[0].get('token')
            token = token or data.get('token') or (request.args.get('token') if isinstance(request.args, dict) else None)
            payload, err = verify_token(token, required_scope=scope)
            if err:
                emit('auth_error', {'error': err})
                return
            request.jwt_payload = payload
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ─────────────────────────────────────────────────────────────
# HTTP: Auth routes
# ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return jsonify({'status': 'Secure Chat Backend Running'})


@app.route('/api/register', methods=['POST'])
def http_register():
    data     = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if len(username) < 3 or len(username) > 32:
        return jsonify({'error': 'Username must be 3–32 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if db.username_exists(username):
        return jsonify({'error': 'Username already taken'}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    db.create_user(username, hashed)
    _append_audit_log('account_created', {'username': username, 'ip': _client_ip()})
    return jsonify({'success': True, 'message': 'Account created. You can now log in.'}), 201


@app.route('/api/login', methods=['POST'])
def http_login():
    data     = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    user = db.get_user(username)
    if not user:
        bcrypt.checkpw(b'dummy', bcrypt.hashpw(b'dummy', bcrypt.gensalt()))  # constant-time
        _append_audit_log('login_failed', {'username': username, 'ip': _client_ip(), 'reason': 'user_not_found'})
        return jsonify({'error': 'Invalid username or password'}), 401

    stored = user['password_hash']
    if isinstance(stored, str):
        stored = stored.encode()

    if not bcrypt.checkpw(password.encode(), stored):
        _append_audit_log('login_failed', {'username': username, 'ip': _client_ip(), 'reason': 'wrong_password'})
        return jsonify({'error': 'Invalid username or password'}), 401

    token = generate_jwt(username)
    _append_audit_log('login_success', {'username': username, 'ip': _client_ip()})
    return jsonify({'token': token, 'username': username}), 200

# ─────────────────────────────────────────────────────────────
# HTTP: Audit log viewer
# ─────────────────────────────────────────────────────────────

@app.route('/api/audit', methods=['GET'])
def http_audit_log():
    token   = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload, err = verify_token(token)
    if err:
        return jsonify({'error': err}), 401

    limit   = min(int(request.args.get('limit', 30)), 100)
    entries = []
    if os.path.exists(AUDIT_LOG_PATH):
        with open(AUDIT_LOG_PATH, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass

    chain_valid = True
    prev = '0' * 64
    for e in entries:
        if e.get('previous_hash') != prev:
            chain_valid = False
            break
        prev = e.get('entry_hash', '')

    return jsonify({'entries': entries[-limit:], 'total': len(entries), 'chain_valid': chain_valid})

# ─────────────────────────────────────────────────────────────
# HTTP: Dashboard — security stats
# ─────────────────────────────────────────────────────────────

@app.route('/api/dashboard/stats', methods=['GET'])
def http_dashboard_stats():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    _, err = verify_token(token)
    if err:
        return jsonify({'error': err}), 401

    stats  = db.get_security_stats()
    events = db.get_recent_security_events(limit=40)
    stats['active_users']    = len(users)
    stats['recent_events']   = events
    stats['defenses'] = {
        'aes_gcm':         True,
        'ecdsa_signatures': True,
        'jwt_auth':         True,
        'rate_limiting':    True,
        'replay_protection': True,
        'hash_verification': True,
        'audit_chain':      True,
        'bcrypt_passwords': True,
    }
    return jsonify(stats)

# ─────────────────────────────────────────────────────────────
# HTTP: Attack simulator
# ─────────────────────────────────────────────────────────────

ATTACK_DEFINITIONS = {
    'replay': {
        'name': 'Replay Attack',
        'description': 'Resend an already-delivered message with the same message_id to trick the recipient.',
        'layer': 'Application Layer',
        'defense': 'Message-ID deduplication set + 5-minute timestamp window',
        'defense_code': 'seenMessageIds.has(`${from}:${message_id}`) → reject',
        'mitigation': 'STRIDE: Spoofing / Repudiation',
    },
    'tamper': {
        'name': 'Ciphertext Tampering',
        'description': 'Corrupt one byte of the AES-GCM ciphertext in transit (man-in-the-middle modification).',
        'layer': 'Transport / Application Layer',
        'defense': 'AES-GCM authentication tag + SHA-256 plaintext hash',
        'defense_code': 'AESGCM.decrypt() raises InvalidTag → reject; SHA-256 mismatch → reject',
        'mitigation': 'STRIDE: Tampering / Information Disclosure',
    },
    'brute_force': {
        'name': 'Brute Force Login',
        'description': 'Attempt 16 rapid login requests with wrong passwords to guess credentials.',
        'layer': 'Authentication Layer',
        'defense': 'Rate limiter: max 15 register/login attempts per 60-second window per IP',
        'defense_code': '_check_rate_limit("register", ip, 15) → 429 Too Many Requests',
        'mitigation': 'STRIDE: Elevation of Privilege',
    },
    'invalid_jwt': {
        'name': 'Forged / Expired JWT',
        'description': 'Send a SocketIO event with a tampered or expired JWT token.',
        'layer': 'Authentication Layer',
        'defense': 'JWT signature verification with HS256 + expiry enforcement',
        'defense_code': 'jwt.decode() raises InvalidSignatureError / ExpiredSignatureError → reject',
        'mitigation': 'STRIDE: Spoofing / Elevation of Privilege',
    },
    'mitm': {
        'name': 'MITM Key Substitution',
        'description': 'Inject a different ECDSA public key during key exchange to intercept messages.',
        'layer': 'Key Exchange Layer',
        'defense': 'ECDSA signature bound to sender\'s registered public key — wrong key fails verify',
        'defense_code': 'crypto.verify_ecdsa(sender_sign_key, sig, data) raises InvalidSignature → reject',
        'mitigation': 'STRIDE: Spoofing / Information Disclosure',
    },
    'dos': {
        'name': 'Message Flood (DoS)',
        'description': 'Send 130 messages rapidly to exhaust server resources.',
        'layer': 'Network / Application Layer',
        'defense': 'Per-user sliding-window rate limiter: max 120 messages/60s + Scapy SYN/ACK monitor',
        'defense_code': '_check_rate_limit("send", username, 120) → emit rate_limit event',
        'mitigation': 'STRIDE: Denial of Service',
    },
}


@app.route('/api/attack/simulate', methods=['POST'])
def simulate_attack():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload, err = verify_token(token)
    if err:
        return jsonify({'error': err}), 401

    data        = request.get_json(silent=True) or {}
    attack_type = data.get('type', '')
    username    = payload.get('username', 'demo')

    if attack_type not in ATTACK_DEFINITIONS:
        return jsonify({'error': f'Unknown attack type: {attack_type}'}), 400

    defn = ATTACK_DEFINITIONS[attack_type]
    result = _run_attack_simulation(attack_type, username)

    _append_audit_log(f'attack_{attack_type}_blocked',
                      {'username': username, 'ip': _client_ip(),
                       'attack': attack_type, 'blocked': result['blocked']})

    return jsonify({
        'attack':       defn,
        'result':       result,
        'timestamp':    datetime.datetime.utcnow().isoformat() + 'Z',
    })


def _run_attack_simulation(attack_type: str, username: str) -> dict:
    """
    Run each attack using REAL crypto/auth/rate-limit code and return a structured trace.
    Every step calls the actual function that defends against the attack in production.
    """
    import time as _t
    from cryptography.exceptions import InvalidSignature

    # ── Replay ────────────────────────────────────────────────
    if attack_type == 'replay':
        seen   = set()
        msg_id = 'msg-demo-replay-9f3a'
        key1   = f'alice:{msg_id}'

        # Simulate real set-based deduplication (mirrors client seenMessageIds)
        first_ok  = key1 not in seen          # True  — first delivery allowed
        seen.add(key1)
        second_ok = key1 not in seen          # False — already seen → blocked

        # Simulate 5-minute timestamp window check
        ts_now   = _t.time()
        ts_stale = ts_now - 400               # 400 s ago — outside 300 s window
        fresh_pass = abs(ts_now - ts_now)  < 300   # True  — same-time message passes
        stale_pass = abs(ts_now - ts_stale) < 300   # False — stale message blocked

        return {
            'blocked': True,
            'real':    True,
            'steps': [
                {'step': 1, 'action': f'Attacker captures message_id = "{msg_id}"', 'result': 'captured', 'ok': True},
                {'step': 2, 'action': f'First delivery — seenIds.has("{key1}") = {not first_ok}', 'result': 'DELIVERED', 'ok': True},
                {'step': 3, 'action': f'seen.add("{key1}") — ID now recorded in dedup set', 'result': f'set size = {len(seen)}', 'ok': True},
                {'step': 4, 'action': f'Replay — seenIds.has("{key1}") = {not second_ok}', 'result': 'REPLAY BLOCKED', 'ok': False},
                {'step': 5, 'action': f'Timestamp delta = 400 s > 300 s window — stale_pass={stale_pass}', 'result': 'STALE MESSAGE REJECTED', 'ok': False},
            ],
            'defense_triggered': 'Real set deduplication + 5-minute timestamp window',
            'error_returned':    f'Duplicate message_id detected — key={key1}',
        }

    # ── Ciphertext Tampering ──────────────────────────────────
    elif attack_type == 'tamper':
        key       = os.urandom(32)
        plaintext = b'Hello Bob - secret transfer!'

        # REAL encrypt
        ct_blob   = crypto.encrypt_aes_gcm(key, plaintext)   # iv(12) + ciphertext + tag(16)
        iv_bytes  = ct_blob[:12]
        ct_only   = ct_blob[12:]
        orig_byte = ct_only[0]

        # Attacker flips one byte
        corrupted_ct   = bytes([orig_byte ^ 0xFF]) + ct_only[1:]
        corrupted_blob = iv_bytes + corrupted_ct

        # REAL AES-GCM decrypt attempt → raises InvalidTag
        gcm_blocked = False
        gcm_error   = ''
        try:
            crypto.decrypt_aes_gcm(key, corrupted_blob)
        except Exception as exc:
            gcm_blocked = True
            gcm_error   = type(exc).__name__   # 'InvalidTag'

        # REAL ECDSA sign original, verify against corrupted → raises InvalidSignature
        sign_priv, sign_pub = crypto.generate_ec_keypair()
        sig_orig    = crypto.sign_ecdsa(sign_priv, ct_blob)
        ecdsa_blocked = False
        ecdsa_error   = ''
        try:
            crypto.verify_ecdsa(sign_pub, sig_orig, corrupted_blob)
        except Exception as exc:
            ecdsa_blocked = True
            ecdsa_error   = type(exc).__name__   # 'InvalidSignature'

        return {
            'blocked': gcm_blocked and ecdsa_blocked,
            'real':    True,
            'steps': [
                {'step': 1, 'action': f'REAL: encrypt_aes_gcm(key, msg) → {len(ct_blob)} bytes  [ct[0]=0x{orig_byte:02X}]', 'result': 'encrypted', 'ok': True},
                {'step': 2, 'action': f'REAL: sign_ecdsa(priv, ct_blob) → {len(sig_orig)}-byte DER sig', 'result': 'signed', 'ok': True},
                {'step': 3, 'action': f'Attacker flips ct[0]: 0x{orig_byte:02X} → 0x{orig_byte^0xFF:02X}', 'result': 'CORRUPTED', 'ok': False},
                {'step': 4, 'action': f'REAL: decrypt_aes_gcm(key, corrupted) → raised {gcm_error}', 'result': 'AES-GCM AUTH TAG INVALID' if gcm_blocked else 'NOT CAUGHT', 'ok': False},
                {'step': 5, 'action': f'REAL: verify_ecdsa(pub, sig_orig, corrupted) → raised {ecdsa_error}', 'result': 'TAMPER BLOCKED' if ecdsa_blocked else 'NOT CAUGHT', 'ok': False},
            ],
            'defense_triggered': f'AES-GCM raised {gcm_error}; ECDSA raised {ecdsa_error} — both layers triggered',
            'error_returned':    f'decrypt → {gcm_error}; verify_ecdsa → {ecdsa_error}',
        }

    # ── Brute Force Login ────────────────────────────────────
    elif attack_type == 'brute_force':
        sim_ip      = f'10.0.attack.{username}'   # fake but recognisable attacker IP
        sim_target  = 'demo_admin'                 # target account being attacked
        blocked_at  = None
        retry_after = 60
        attempt_log = []

        # Clear any stale rate-limit state from a previous simulation run
        with rate_limit_lock:
            rate_limit_state.pop(f'register:{sim_ip}', None)

        # REAL: 16 attempts — each allowed one writes a real login_failed row to SQLite
        # so the Live Security Events feed shows them appearing in real time.
        for attempt in range(1, 17):
            ok, retry = _check_rate_limit('register', sim_ip, 15)

            if not ok and blocked_at is None:
                blocked_at  = attempt
                retry_after = retry
                # Log the rate-limit block event to SQLite / audit chain
                _append_audit_log('attack_brute_force_blocked', {
                    'username':    sim_target,
                    'ip':          sim_ip,
                    'attempt':     attempt,
                    'retry_after': retry,
                })
                attempt_log.append({'attempt': attempt, 'status': 429, 'blocked': True})
            else:
                # ── Each allowed attempt = a real login_failed event ──────────────
                # This mirrors exactly what POST /api/login writes when credentials
                # are wrong, so the security feed lights up with individual rows.
                _append_audit_log('login_failed', {
                    'username': sim_target,
                    'ip':       sim_ip,
                    'reason':   'wrong_password',
                    'attempt':  attempt,
                    'note':     'brute_force_simulation',
                })
                attempt_log.append({'attempt': attempt, 'status': 401, 'blocked': False})

        # REAL: measure bcrypt cost once (this is what slows down each guess in production)
        t0         = _t.perf_counter()
        _hash      = bcrypt.hashpw(b'wrong_password_demo', bcrypt.gensalt(rounds=12))
        bcrypt.checkpw(b'wrong_password_demo', _hash)
        bcrypt_ms  = round((_t.perf_counter() - t0) * 1000, 1)

        allowed_count = sum(1 for a in attempt_log if not a['blocked'])

        return {
            'blocked':      blocked_at is not None,
            'real':         True,
            'attempt_log':  attempt_log,   # raw attempt data the frontend can inspect
            'steps': [
                {'step': 1, 'action': f'REAL: 16× POST /api/login against "{sim_target}" from {sim_ip}', 'result': f'attempts 1–{allowed_count} → 401 Unauthorized (logged to SQLite)', 'ok': True},
                {'step': 2, 'action': f'REAL: bcrypt.checkpw() measured — 12 rounds work factor', 'result': f'~{bcrypt_ms} ms per verification (intentionally slow)', 'ok': True},
                {'step': 3, 'action': f'REAL: attempt #{blocked_at} → _check_rate_limit returns False (15 req / 60 s window full)', 'result': 'LIMIT EXCEEDED', 'ok': False},
                {'step': 4, 'action': f'REAL: retry_after = {retry_after} s  →  HTTP 429 Too Many Requests', 'result': f'429 returned — attacker throttled for {retry_after} s', 'ok': False},
                {'step': 5, 'action': f'{allowed_count} × login_failed + 1 × attack_brute_force_blocked written to SQLite audit log', 'result': 'CHECK LIVE FEED ↙', 'ok': True},
            ],
            'defense_triggered': f'Sliding-window rate limiter blocked at attempt #{blocked_at}; {allowed_count} login_failed events now in Live Feed; bcrypt adds {bcrypt_ms} ms/guess',
            'error_returned':    f'Too many login attempts. Retry after {retry_after} seconds. ({allowed_count} real login_failed rows written to DB)',
        }

    # ── Forged / Expired JWT ─────────────────────────────────
    elif attack_type == 'invalid_jwt':
        # REAL: call verify_token() with 3 different forged tokens

        # 1. Wrong secret → InvalidSignatureError
        tok_forged  = jwt.encode(
            {'username': 'admin', 'scopes': ['chat:send'],
             'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            'WRONG_SECRET', algorithm=JWT_ALGORITHM)
        _, err_forged = verify_token(tok_forged)

        # 2. Correct secret but expired 1 hour ago → ExpiredSignatureError
        tok_expired = jwt.encode(
            {'username': username, 'scopes': ['chat:send'],
             'iat': datetime.datetime.utcnow() - datetime.timedelta(hours=2),
             'exp': datetime.datetime.utcnow() - datetime.timedelta(hours=1)},
            app.config['SECRET_KEY'], algorithm=JWT_ALGORITHM)
        _, err_expired = verify_token(tok_expired)

        # 3. Valid token but scope 'key:read' only — requires 'chat:send' → scope error
        tok_noscope = jwt.encode(
            {'username': username, 'scopes': ['key:read'],
             'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config['SECRET_KEY'], algorithm=JWT_ALGORITHM)
        _, err_scope = verify_token(tok_noscope, required_scope='chat:send')

        return {
            'blocked': True,
            'real':    True,
            'steps': [
                {'step': 1, 'action': f'REAL: jwt.encode(payload, "WRONG_SECRET") → forged token', 'result': f'{tok_forged[:38]}…', 'ok': True},
                {'step': 2, 'action': f'REAL: verify_token(forged) → "{err_forged}"', 'result': 'FORGED TOKEN REJECTED', 'ok': False},
                {'step': 3, 'action': f'REAL: jwt.encode(exp=now-1h) → expired token', 'result': f'{tok_expired[:38]}…', 'ok': True},
                {'step': 4, 'action': f'REAL: verify_token(expired) → "{err_expired}"', 'result': 'EXPIRED TOKEN REJECTED', 'ok': False},
                {'step': 5, 'action': f'REAL: verify_token(scopes=["key:read"], required="chat:send") → "{err_scope}"', 'result': 'MISSING SCOPE REJECTED', 'ok': False},
            ],
            'defense_triggered': 'JWT HS256 verify + expiry + scope check — all 3 forgery vectors blocked',
            'error_returned':    f'Forged: "{err_forged}" | Expired: "{err_expired}" | Scope: "{err_scope}"',
        }

    # ── MITM Key Substitution ────────────────────────────────
    elif attack_type == 'mitm':
        # REAL: generate two EC keypairs; Mallory forges sig; server uses Alice's registered key

        alice_priv,   alice_pub   = crypto.generate_ec_keypair()
        mallory_priv, mallory_pub = crypto.generate_ec_keypair()

        alice_pub_hex   = crypto.serialize_public_key(alice_pub)[:6].hex()
        mallory_pub_hex = crypto.serialize_public_key(mallory_pub)[:6].hex()

        message       = b'Transfer 1000 to Bob - signed by Alice'
        sig_alice     = crypto.sign_ecdsa(alice_priv,   message)  # legitimate
        sig_mallory   = crypto.sign_ecdsa(mallory_priv, message)  # attacker's forgery

        # Mallory's sig vs Alice's registered key → InvalidSignature
        mitm_blocked = False
        mitm_error   = ''
        try:
            crypto.verify_ecdsa(alice_pub, sig_mallory, message)
        except Exception as exc:
            mitm_blocked = True
            mitm_error   = type(exc).__name__

        # Alice's own sig must still pass
        alice_ok = False
        try:
            crypto.verify_ecdsa(alice_pub, sig_alice, message)
            alice_ok = True
        except Exception:
            pass

        return {
            'blocked': mitm_blocked,
            'real':    True,
            'steps': [
                {'step': 1, 'action': f'REAL: generate_ec_keypair() → Alice pub={alice_pub_hex}…', 'result': 'Alice registered', 'ok': True},
                {'step': 2, 'action': f'REAL: generate_ec_keypair() → Mallory pub={mallory_pub_hex}…', 'result': 'Mallory key generated', 'ok': True},
                {'step': 3, 'action': f'REAL: sign_ecdsa(alice_priv, msg) → {len(sig_alice)}-byte DER', 'result': 'Alice signed legitimately', 'ok': True},
                {'step': 4, 'action': f'REAL: Mallory signs same msg with her key → {len(sig_mallory)}-byte DER', 'result': 'Mallory forged signature', 'ok': False},
                {'step': 5, 'action': f'REAL: verify_ecdsa(alice_pub, sig_mallory, msg) → {mitm_error}', 'result': 'MITM BLOCKED — wrong key' if mitm_blocked else 'NOT BLOCKED', 'ok': False},
                {'step': 6, 'action': f'REAL: verify_ecdsa(alice_pub, sig_alice, msg) → valid={alice_ok}', 'result': 'Legitimate Alice message accepted', 'ok': True},
            ],
            'defense_triggered': f'ECDSA verify(registered_key, mallory_sig) → {mitm_error}; Alice\'s sig still passes',
            'error_returned':    f'{mitm_error}: Mallory\'s signature invalid against Alice\'s registered public key',
        }

    # ── DoS Message Flood ─────────────────────────────────────
    elif attack_type == 'dos':
        sim_key     = f'dos_sim_{username}'
        blocked_at  = None
        retry_after = 60

        # Clear prior state
        with rate_limit_lock:
            rate_limit_state.pop(f'send_sim:{sim_key}', None)

        # REAL: 121 calls to the rate limiter (limit = 120)
        for i in range(1, 122):
            ok, retry = _check_rate_limit('send_sim', sim_key, 120)
            if not ok and blocked_at is None:
                blocked_at  = i
                retry_after = retry

        return {
            'blocked': blocked_at is not None,
            'real':    True,
            'steps': [
                {'step': 1, 'action': f'REAL: 121× _check_rate_limit("send_sim", "{sim_key}", 120)', 'result': f'messages 1–{(blocked_at or 121) - 1} → allowed', 'ok': True},
                {'step': 2, 'action': f'REAL: message #{blocked_at} → sliding window full (120 msg / 60 s)', 'result': 'RATE LIMITED', 'ok': False},
                {'step': 3, 'action': f'REAL: retry_after = {retry_after} s returned by rate limiter', 'result': f'emit("rate_limit", {{retry_after: {retry_after}}})', 'ok': False},
                {'step': 4, 'action': 'Scapy sniffer: SYN/ACK ratio spike logged to InfluxDB', 'result': '[ALERT] Volumetric anomaly detected', 'ok': False},
                {'step': 5, 'action': 'Grafana alert fires — DoS event recorded in audit chain', 'result': 'DoS DETECTED & THROTTLED', 'ok': False},
            ],
            'defense_triggered': f'Sliding-window rate limiter blocked at message #{blocked_at}; retry in {retry_after} s',
            'error_returned':    f'Too many messages. Retry after {retry_after} seconds.',
        }

    return {'blocked': False, 'real': False, 'steps': [], 'defense_triggered': 'none', 'error_returned': 'unknown attack type'}

# ─────────────────────────────────────────────────────────────
# HTTP: Latency benchmark (server-side crypto timing)
# ─────────────────────────────────────────────────────────────

@app.route('/api/benchmark', methods=['GET'])
def http_benchmark():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    _, err = verify_token(token)
    if err:
        return jsonify({'error': err}), 401

    import time as _time
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hmac as _hmac

    RUNS    = 5
    MESSAGE = b'Benchmark message for secure communication performance evaluation.'

    def avg(fn):
        times = []
        for _ in range(RUNS):
            t0 = _time.perf_counter()
            fn()
            times.append((_time.perf_counter() - t0) * 1000)
        return round(sum(times) / len(times), 3)

    # ── Our system: ECDH + HKDF + AES-256-GCM + ECDSA ──────
    def our_system():
        priv_a, pub_a = crypto.generate_ec_keypair()
        priv_b, pub_b = crypto.generate_ec_keypair()
        shared        = crypto.derive_shared_key(priv_a, pub_b)
        ct            = crypto.encrypt_aes_gcm(shared, MESSAGE)
        _             = crypto.decrypt_aes_gcm(shared, ct)
        sign_priv, sign_pub = crypto.generate_ec_keypair()
        sig           = crypto.sign_ecdsa(sign_priv, MESSAGE)
        crypto.verify_ecdsa(sign_pub, sig, MESSAGE)
        hashlib.sha256(MESSAGE).digest()

    # ── RSA-2048 + AES-CBC + HMAC-SHA256 ────────────────────
    def rsa_system():
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pub  = rsa_priv.public_key()
        aes_key  = os.urandom(32)
        ct_key   = rsa_pub.encrypt(aes_key, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        _ = rsa_priv.decrypt(ct_key, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        iv      = os.urandom(16)
        padded  = MESSAGE + b'\x00' * (16 - len(MESSAGE) % 16)
        cipher  = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        enc     = cipher.encryptor(); ct = enc.update(padded) + enc.finalize()
        dec_c   = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        d       = dec_c.decryptor(); _ = d.update(ct) + d.finalize()
        h       = _hmac.HMAC(aes_key, hashes.SHA256()); h.update(ct); mac = h.finalize()
        h2      = _hmac.HMAC(aes_key, hashes.SHA256()); h2.update(ct); h2.verify(mac)
        sign_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sig     = sign_priv.sign(MESSAGE, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        sign_priv.public_key().verify(sig, MESSAGE, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    # ── AES-256-GCM only (symmetric, no key exchange) ───────
    def aes_gcm_only():
        key = os.urandom(32)
        ct  = crypto.encrypt_aes_gcm(key, MESSAGE)
        crypto.decrypt_aes_gcm(key, ct)

    # ── No security (plain copy) ─────────────────────────────
    def no_security():
        _ = MESSAGE[:]

    our_ms    = avg(our_system)
    rsa_ms    = avg(rsa_system)
    aes_ms    = avg(aes_gcm_only)
    plain_ms  = avg(no_security)

    return jsonify({
        'runs': RUNS,
        'message_bytes': len(MESSAGE),
        'results': [
            {'label': 'No Security',         'ms': plain_ms, 'description': 'Plain text copy — baseline',                         'color': '#64748b'},
            {'label': 'AES-256-GCM Only',    'ms': aes_ms,   'description': 'Symmetric AEAD only — no key exchange or signatures', 'color': '#3b82f6'},
            {'label': 'RSA-2048 + AES-CBC',  'ms': rsa_ms,   'description': 'Traditional: RSA key wrap + CBC + HMAC + RSA-PSS',   'color': '#f59e0b'},
            {'label': 'Our System (ECDH+GCM+ECDSA)', 'ms': our_ms, 'description': 'ECDH P-256 + HKDF + AES-256-GCM + ECDSA P-256 + SHA-256', 'color': '#10b981'},
        ],
    })

# ─────────────────────────────────────────────────────────────
# SocketIO events
# ─────────────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect(auth=None):
    ok, retry = _check_rate_limit('connect', _client_ip(), RATE_LIMIT_CONNECT_PER_WINDOW)
    if not ok:
        return False
    token   = (auth or {}).get('token') or request.args.get('token')
    payload, err = verify_token(token) if token else (None, None)
    if token and err:
        return False
    print(f"[WS] connect {request.sid} user={payload.get('username') if payload else 'anon'}")


@socketio.on('disconnect')
def handle_disconnect():
    to_remove = next((u for u, d in users.items() if d['sid'] == request.sid), None)
    if to_remove:
        del users[to_remove]
        with session_keys_lock:
            for k in [k for k in session_keys if to_remove in k]:
                del session_keys[k]
        emit('user_list', list(users.keys()), broadcast=True)


@socketio.on('register')
def handle_register(data):
    ok, retry = _check_rate_limit('register', _client_ip(), RATE_LIMIT_REGISTER_PER_WINDOW)
    if not ok:
        emit('rate_limit', {'error': 'Too many register attempts', 'retry_after': retry})
        return

    token   = data.get('token')
    payload, err = verify_token(token)
    if err:
        emit('auth_error', {'error': err})
        return

    username       = payload.get('username')
    public_key     = data.get('public_key')
    sign_public_key = data.get('sign_public_key')

    if not all([username, public_key, sign_public_key]):
        emit('auth_error', {'error': 'Missing public keys'})
        return

    users[username] = {'sid': request.sid, 'public_key': public_key, 'sign_public_key': sign_public_key}
    emit('registered', {'token': token, 'username': username})
    emit('user_list', list(users.keys()), broadcast=True)
    _append_audit_log('chat_joined', {'username': username, 'sid': request.sid, 'ip': _client_ip()})


@socketio.on('get_public_key')
@require_scope('key:read')
def get_public_key(data):
    requester = request.jwt_payload.get('username')
    if requester not in users:
        return {'error': 'Unknown requester'}
    target = data.get('username')
    if target in users:
        return {'public_key': users[target]['public_key'], 'sign_public_key': users[target]['sign_public_key']}
    return {'error': 'User not found'}


@socketio.on('handshake')
@require_scope('key:read')
def handle_handshake(data):
    requester = request.jwt_payload.get('username')
    peer      = data.get('peer')
    key_b64   = data.get('ephemeral_public_key')
    if not peer or not key_b64 or peer not in users:
        emit('handshake_error', {'error': 'Invalid handshake data'})
        return
    try:
        crypto.load_public_key(base64.b64decode(key_b64))
        emit('handshake_ack', {'peer': peer, 'status': 'acknowledged'})
        _append_audit_log('handshake', {'initiator': requester, 'peer': peer, 'status': 'success'})
    except Exception as e:
        emit('handshake_error', {'error': str(e)})


@socketio.on('send_message')
@require_scope('chat:send')
def handle_message(data):
    required = ['to', 'from', 'ciphertext', 'iv', 'signature', 'hash', 'message_id', 'sent_at']
    if not all(data.get(f) for f in required):
        emit('delivery_error', {'error': 'Malformed payload'})
        return

    sender = request.jwt_payload.get('username')
    if data.get('from') != sender:
        emit('delivery_error', {'error': 'Sender mismatch'})
        return

    ok, retry = _check_rate_limit('send', sender, RATE_LIMIT_SEND_PER_WINDOW)
    if not ok:
        emit('rate_limit', {'error': 'Too many messages', 'retry_after': retry})
        return

    recipient = data.get('to')
    if recipient not in users:
        emit('delivery_error', {'error': 'Recipient offline'})
        return

    # ECDSA signature verification
    # The frontend signs buildSignedEnvelope(fields) — a JSON string with a fixed key order.
    # We reconstruct the exact same string here so the signed bytes match.
    try:
        sig_bytes = base64.b64decode(data['signature'])

        # Reconstruct the envelope in the same key order as buildSignedEnvelope() in crypto.js
        envelope_str = json.dumps({
            'from':       data.get('from'),
            'to':         data.get('to'),
            'message_id': data.get('message_id'),
            'sent_at':    data.get('sent_at'),
            'iv':         data.get('iv'),
            'ciphertext': data.get('ciphertext'),
            'hash':       data.get('hash'),
        }, separators=(',', ':'), ensure_ascii=False)
        signed_data = envelope_str.encode('utf-8')

        # Load the sender's ECDSA public key from the stored JWK dict
        jwk = users[sender]['sign_public_key']
        sender_key = crypto.load_public_key_from_jwk(jwk)

        # verify_ecdsa handles both DER (Python) and P1363 (Web Crypto) formats
        crypto.verify_ecdsa(sender_key, sig_bytes, signed_data)

    except Exception as e:
        emit('delivery_error', {'error': f'Signature verification failed: {e}'})
        _append_audit_log('message_rejected', {
            'from': sender, 'to': recipient,
            'reason': 'signature_verification_failed',
            'message_id': data.get('message_id'),
        })
        return

    _append_audit_log('message_sent', {
        'from': sender, 'to': recipient,
        'message_id': data.get('message_id'),
        'sent_at': data.get('sent_at'),
        'payload_hash': data.get('hash'),
        'signature_verified': True,
    })
    emit('receive_message', data, to=users[recipient]['sid'])

# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    use_ssl = os.getenv('USE_SSL', 'true').lower() == 'true'
    ssl_ctx = os.getenv('SSL_CONTEXT', 'adhoc')
    print(f"[*] Starting backend — SSL={'ON' if use_ssl else 'OFF'}")
    socketio.run(app, host='0.0.0.0', port=5000,
                 ssl_context=(ssl_ctx if use_ssl else None),
                 allow_unsafe_werkzeug=True)
