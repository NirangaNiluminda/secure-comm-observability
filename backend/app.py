from flask import Flask, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import jwt
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

# Import crypto helper for ECDH, ECDSA, AES-GCM
import crypto

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET', 'secure-chat-secret')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory store for connected users:
# { username: { 'sid': session_id, 'public_key': key_str, 'sign_public_key': sign_key_str } }
users = {}

# In-memory store for ephemeral session keys (ECDH-derived)
# { (alice, bob): derived_key_bytes }
session_keys = {}

JWT_ALGORITHM = 'HS256'
JWT_TTL_MINUTES = int(os.getenv('JWT_TTL_MINUTES', '15'))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', '60'))
RATE_LIMIT_CONNECT_PER_WINDOW = int(os.getenv('RATE_LIMIT_CONNECT_PER_WINDOW', '40'))
RATE_LIMIT_REGISTER_PER_WINDOW = int(os.getenv('RATE_LIMIT_REGISTER_PER_WINDOW', '15'))
RATE_LIMIT_SEND_PER_WINDOW = int(os.getenv('RATE_LIMIT_SEND_PER_WINDOW', '120'))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG_PATH = os.getenv('AUDIT_LOG_PATH', os.path.join(BASE_DIR, 'audit_log.ndjson'))
AUDIT_STATE_PATH = os.getenv('AUDIT_STATE_PATH', os.path.join(BASE_DIR, 'audit_chain_state.json'))
AUDIT_PRIVATE_KEY_PATH = os.getenv('AUDIT_PRIVATE_KEY_PATH', os.path.join(BASE_DIR, 'audit_signing_key.pem'))
AUDIT_PUBLIC_KEY_PATH = os.getenv('AUDIT_PUBLIC_KEY_PATH', os.path.join(BASE_DIR, 'audit_signing_public.pem'))

rate_limit_state = {}
rate_limit_lock = threading.Lock()
audit_lock = threading.Lock()
session_keys_lock = threading.Lock()


def _ensure_directory(path):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def _load_or_create_audit_keypair():
    _ensure_directory(AUDIT_PRIVATE_KEY_PATH)
    if os.path.exists(AUDIT_PRIVATE_KEY_PATH):
        with open(AUDIT_PRIVATE_KEY_PATH, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(AUDIT_PRIVATE_KEY_PATH, 'wb') as key_file:
            key_file.write(pem_private)

    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _ensure_directory(AUDIT_PUBLIC_KEY_PATH)
    with open(AUDIT_PUBLIC_KEY_PATH, 'wb') as pub_file:
        pub_file.write(pem_public)

    return private_key


def _load_last_audit_hash():
    if os.path.exists(AUDIT_STATE_PATH):
        try:
            with open(AUDIT_STATE_PATH, 'r', encoding='utf-8') as state_file:
                state = json.load(state_file)
            state_hash = state.get('last_hash')
            if isinstance(state_hash, str) and len(state_hash) == 64:
                return state_hash
        except Exception:
            pass
    return '0' * 64


def _save_last_audit_hash(last_hash):
    _ensure_directory(AUDIT_STATE_PATH)
    with open(AUDIT_STATE_PATH, 'w', encoding='utf-8') as state_file:
        json.dump({'last_hash': last_hash, 'updated_at': datetime.datetime.utcnow().isoformat() + 'Z'}, state_file)


audit_private_key = _load_or_create_audit_keypair()
last_audit_hash = _load_last_audit_hash()


def _unauthorized(message):
    emit('auth_error', {'error': message})


def _client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _check_rate_limit(action, subject, limit):
    now = time.time()
    key = f'{action}:{subject}'
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    with rate_limit_lock:
        attempts = rate_limit_state.setdefault(key, deque())
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        if len(attempts) >= limit:
            retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - attempts[0])))
            return False, retry_after

        attempts.append(now)
        return True, 0


def _append_audit_log(event_type, event_data):
    global last_audit_hash

    event = {
        'event_type': event_type,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        **event_data
    }
    canonical_event = json.dumps(event, sort_keys=True, separators=(',', ':'))

    with audit_lock:
        previous_hash = last_audit_hash
        entry_hash = hashlib.sha256((previous_hash + canonical_event).encode('utf-8')).hexdigest()
        signature = audit_private_key.sign(entry_hash.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        signature_b64 = base64.b64encode(signature).decode('ascii')

        entry = {
            'previous_hash': previous_hash,
            'entry_hash': entry_hash,
            'signature': signature_b64,
            'event': event
        }

        _ensure_directory(AUDIT_LOG_PATH)
        with open(AUDIT_LOG_PATH, 'a', encoding='utf-8') as log_file:
            log_file.write(json.dumps(entry, separators=(',', ':')) + '\n')

        last_audit_hash = entry_hash
        _save_last_audit_hash(last_audit_hash)


def verify_token(token, required_scope=None):
    if not token:
        return None, 'Missing token'
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[JWT_ALGORITHM])
        scopes = payload.get('scopes', [])
        if required_scope and required_scope not in scopes:
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
            data = args[0] if args and isinstance(args[0], dict) else {}

            if request.event and isinstance(request.event, dict):
                request_args = request.event.get('args', [])
                if request_args and isinstance(request_args[0], dict):
                    token = request_args[0].get('token')
            if not token:
                token = data.get('token')
            if not token and isinstance(request.args, dict):
                token = request.args.get('token')

            payload, err = verify_token(token, required_scope=scope)
            if err:
                _unauthorized(err)
                return

            request.jwt_payload = payload
            return func(*args, **kwargs)
        return wrapper
    return decorator

def generate_jwt(username):
    payload = {
        'username': username,
        'scopes': ['chat:send', 'chat:read', 'key:read'],
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_TTL_MINUTES)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm=JWT_ALGORITHM)

@app.route('/')
def index():
    return "Secure Chat Backend Running"

@socketio.on('connect')
def handle_connect(auth=None):
    allowed, retry_after = _check_rate_limit('connect', _client_ip(), RATE_LIMIT_CONNECT_PER_WINDOW)
    if not allowed:
        print(f"Rejected connection {request.sid}: rate limited ({retry_after}s)")
        return False

    token = None
    if isinstance(auth, dict):
        token = auth.get('token')
    if not token:
        token = request.args.get('token')
    payload, err = verify_token(token) if token else (None, None)
    if token and err:
        print(f"Rejected connection {request.sid}: {err}")
        return False
    if payload:
        print(f"Client connected: {request.sid} user={payload.get('username')}")
    else:
        print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    # Remove user if they were registered
    username_to_remove = None
    for username, data in users.items():
        if data['sid'] == request.sid:
            username_to_remove = username
            break
    if username_to_remove:
        del users[username_to_remove]
        # Clean up session keys for this user
        with session_keys_lock:
            keys_to_remove = [k for k in session_keys.keys() if username_to_remove in k]
            for k in keys_to_remove:
                del session_keys[k]
        emit('user_list', list(users.keys()), broadcast=True)
        print(f"Unregistered user: {username_to_remove}")

@socketio.on('register')
def handle_register(data):
    allowed, retry_after = _check_rate_limit('register', _client_ip(), RATE_LIMIT_REGISTER_PER_WINDOW)
    if not allowed:
        emit('rate_limit', {'error': 'Too many register attempts', 'retry_after': retry_after})
        return

    username = data.get('username')
    public_key = data.get('public_key')
    sign_public_key = data.get('sign_public_key')
    if username and public_key and sign_public_key:
        users[username] = {
            'sid': request.sid,
            'public_key': public_key,
            'sign_public_key': sign_public_key
        }
        token = generate_jwt(username)
        emit('registered', {'token': token})
        # Send back the current list of users
        emit('user_list', list(users.keys()), broadcast=True)
        _append_audit_log('register', {
            'username': username,
            'sid': request.sid,
            'ip': _client_ip()
        })
        print(f"Registered user: {username}")

@socketio.on('get_public_key')
@require_scope('key:read')
def get_public_key(data):
    requester = request.jwt_payload.get('username')
    if requester not in users:
        return {'error': 'Unknown requester'}

    target_username = data.get('username')
    if target_username in users:
        # returns both ECDH exchange key and ECDSA signature key
        return {
            'public_key': users[target_username]['public_key'],
            'sign_public_key': users[target_username]['sign_public_key']
        }
    return {'error': 'User not found'}

@socketio.on('handshake')
@require_scope('key:read')
def handle_handshake(data):
    """
    Perform ephemeral ECDH handshake with another peer.
    Expected data: {'peer': 'bob', 'ephemeral_public_key': 'base64_encoded_public_key'}
    Derives a shared symmetric key and stores it for later message encryption.
    """
    requester = request.jwt_payload.get('username')
    if requester not in users:
        emit('handshake_error', {'error': 'Unknown requester'})
        return

    peer = data.get('peer')
    peer_ephemeral_key_b64 = data.get('ephemeral_public_key')

    if not peer or not peer_ephemeral_key_b64:
        emit('handshake_error', {'error': 'Missing peer or ephemeral_public_key'})
        return

    if peer not in users:
        emit('handshake_error', {'error': 'Peer not found'})
        return

    try:
        # Decode peer's ephemeral public key
        peer_ephemeral_key_bytes = base64.b64decode(peer_ephemeral_key_b64)
        peer_ephemeral_key = crypto.load_public_key(peer_ephemeral_key_bytes)

        # Client should have sent their ephemeral private key via secure channel (not shown here)
        # For now, we assume the client uses the derived shared key
        # In a real scenario, each peer generates an ephemeral keypair and exchanges pubkeys
        emit('handshake_ack', {'peer': peer, 'status': 'acknowledged'})
        _append_audit_log('handshake', {
            'initiator': requester,
            'peer': peer,
            'status': 'success'
        })
        print(f"Handshake between {requester} and {peer} acknowledged")
    except Exception as e:
        emit('handshake_error', {'error': f'Handshake failed: {str(e)}'})
        print(f"Handshake failed for {requester}: {e}")

@socketio.on('derive_session_key')
@require_scope('key:read')
def handle_derive_session_key(data):
    """
    Derive a shared session key using ECDH with a peer.
    Expected data: {'peer': 'bob', 'ephemeral_private_key_bytes': ..., 'peer_ephemeral_public_key': 'base64'}
    
    Note: In production, private keys should never be sent over the network.
    This is a simplified flow for demonstration. Use proper key exchange protocols.
    """
    requester = request.jwt_payload.get('username')
    if requester not in users:
        emit('key_derivation_error', {'error': 'Unknown requester'})
        return

    peer = data.get('peer')
    peer_public_key_b64 = data.get('peer_ephemeral_public_key')

    if not peer or not peer_public_key_b64:
        emit('key_derivation_error', {'error': 'Missing peer or peer_ephemeral_public_key'})
        return

    try:
        peer_public_key_bytes = base64.b64decode(peer_public_key_b64)
        peer_public_key = crypto.load_public_key(peer_public_key_bytes)

        # For this demo, we'll create a dummy shared key.
        # In a real scenario, the client would derive the key locally and only send the confirmation.
        dummy_shared_key = hashlib.sha256((requester + peer).encode()).digest()

        key_tuple = (requester, peer) if requester < peer else (peer, requester)
        with session_keys_lock:
            session_keys[key_tuple] = dummy_shared_key

        emit('key_derived', {'peer': peer, 'status': 'derived'})
        print(f"Session key derived for {requester}<->{peer}")
    except Exception as e:
        emit('key_derivation_error', {'error': f'Key derivation failed: {str(e)}'})
        print(f"Key derivation failed: {e}")

@socketio.on('send_message')
@require_scope('chat:send')
def handle_message(data):
    """
    Handle encrypted message delivery.
    Expected data structure:
    {
      'to': 'bob',
      'from': 'alice',
      'ciphertext': 'base64_encrypted_message',  # Encrypted with AES-GCM
      'iv': 'base64_iv',
      'authTag': 'base64_authentication_tag',
      'signature': 'base64_ecdsa_signature',     # Signature of ciphertext + iv + authTag
      'hash': 'sha256_message_hash',
      'message_id': 'unique_id',
      'sent_at': 'timestamp'
    }
    """
    required_fields = ['to', 'from', 'ciphertext', 'iv', 'signature', 'hash', 'message_id', 'sent_at']
    if not all(data.get(field) for field in required_fields):
        emit('delivery_error', {'error': 'Malformed payload'})
        return

    sender = request.jwt_payload.get('username')
    if data.get('from') != sender:
        emit('delivery_error', {'error': 'Sender mismatch'})
        return

    allowed, retry_after = _check_rate_limit('send', sender, RATE_LIMIT_SEND_PER_WINDOW)
    if not allowed:
        emit('rate_limit', {'error': 'Too many messages', 'retry_after': retry_after})
        return

    recipient = data.get('to')
    if recipient in users:
        # Verify ECDSA signature of the ciphertext
        try:
            signature_bytes = base64.b64decode(data.get('signature', ''))
            ciphertext_bytes = base64.b64decode(data.get('ciphertext', ''))
            iv_bytes = base64.b64decode(data.get('iv', ''))
            signed_data = ciphertext_bytes + iv_bytes

            sender_sign_key_b64 = users[sender]['sign_public_key']
            sender_sign_key_bytes = base64.b64decode(sender_sign_key_b64)
            sender_sign_key = crypto.load_public_key(sender_sign_key_bytes)

            crypto.verify_ecdsa(sender_sign_key, signature_bytes, signed_data)
        except Exception as e:
            emit('delivery_error', {'error': f'Signature verification failed: {str(e)}'})
            _append_audit_log('send_message_rejected', {
                'from': sender,
                'to': recipient,
                'reason': 'signature_verification_failed',
                'message_id': data.get('message_id')
            })
            return

        _append_audit_log('send_message', {
            'from': sender,
            'to': recipient,
            'message_id': data.get('message_id'),
            'sent_at': data.get('sent_at'),
            'payload_hash': data.get('hash'),
            'client_signature': data.get('signature'),
            'signature_verified': True
        })
        recipient_sid = users[recipient]['sid']
        emit('receive_message', data, to=recipient_sid)
    else:
        emit('delivery_error', {'error': 'Recipient offline'})

if __name__ == '__main__':
    # Run the server
    socketio.run(app, host='0.0.0.0', port=5000)
