from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-chat-secret'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory store for connected users:
# { username: { 'sid': session_id, 'public_key': key_str, 'sign_public_key': sign_key_str } }
users = {}

def generate_jwt(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

@app.route('/')
def index():
    return "Secure Chat Backend Running"

@socketio.on('connect')
def handle_connect():
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
        emit('user_list', list(users.keys()), broadcast=True)
        print(f"Unregistered user: {username_to_remove}")

@socketio.on('register')
def handle_register(data):
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
        print(f"Registered user: {username}")

@socketio.on('get_public_key')
def get_public_key(data):
    target_username = data.get('username')
    if target_username in users:
        # returns both ECDH exchange key and ECDSA signature key
        return {
            'public_key': users[target_username]['public_key'],
            'sign_public_key': users[target_username]['sign_public_key']
        }
    return {'error': 'User not found'}

@socketio.on('send_message')
def handle_message(data):
    # data structure expected:
    # { 'to': 'bob', 'from': 'alice', 'ciphertext': '...', 'iv': '...', 'authTag': '...', 'signature': '...', 'hash': '...' }
    recipient = data.get('to')
    if recipient in users:
        recipient_sid = users[recipient]['sid']
        emit('receive_message', data, to=recipient_sid)

if __name__ == '__main__':
    # Run the server
    socketio.run(app, host='0.0.0.0', port=5000)
