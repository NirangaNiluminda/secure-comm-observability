import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import { Shield, Lock, Send, User, CheckCircle2, AlertCircle } from 'lucide-react';
import { motion } from 'framer-motion';
import {
  generateECDHKeyPair, generateECDSAKeyPair, exportKey,
  importECDHPublicKey, importECDSAPublicKey, deriveSharedKey,
  encryptMessage, decryptMessage, signMessage, verifySignature, generateHash, generateMessageId,
  buildSignedEnvelope
} from './crypto';

const SOCKET_SERVER_URL = "http://localhost:5000";

function App() {
  const [socket, setSocket] = useState(null);
  const [username, setUsername] = useState("");
  const [isRegistered, setIsRegistered] = useState(false);
  const [token, setToken] = useState("");
  
  const [keys, setKeys] = useState(null); // { ecdh: { private, public }, ecdsa: { private, public } }
  
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  
  const [messages, setMessages] = useState([]); // { id, from, to, plaintext, status }
  const [inputMsg, setInputMsg] = useState("");

  const [activeSession, setActiveSession] = useState(null); // { targetUser, sharedKey, ecdsaPublicKey }
  const [errorBanner, setErrorBanner] = useState("");

  const sessionsRef = useRef({});
  const keysRef = useRef(null);
  const usernameRef = useRef("");
  const tokenRef = useRef("");
  const seenMessageIdsRef = useRef(new Set());

  useEffect(() => {
    const newSocket = io(SOCKET_SERVER_URL, { autoConnect: false });
    setSocket(newSocket);
    
    return () => newSocket.disconnect();
  }, []);

  useEffect(() => {
    keysRef.current = keys;
  }, [keys]);

  useEffect(() => {
    usernameRef.current = username;
  }, [username]);

  useEffect(() => {
    tokenRef.current = token;
  }, [token]);

  useEffect(() => {
    if (!socket) return;

    socket.on('connect', () => {
      console.log('Connected to server');
    });

    socket.on('user_list', (userList) => {
      setUsers(userList.filter(u => u !== usernameRef.current));
    });

    socket.on('registered', (data) => {
      setToken(data.token);
      setIsRegistered(true);
      socket.auth = { token: data.token };
      setErrorBanner("");
    });

    socket.on('auth_error', (data) => {
      setErrorBanner(data?.error || 'Authentication failed');
    });

    socket.on('delivery_error', (data) => {
      setErrorBanner(data?.error || 'Message delivery failed');
    });

    socket.on('rate_limit', (data) => {
      if (data?.retry_after) {
        setErrorBanner(`${data.error || 'Rate limited'} (retry in ${data.retry_after}s)`);
      } else {
        setErrorBanner(data?.error || 'Rate limited');
      }
    });

    socket.on('receive_message', async (data) => {
      if (!keysRef.current) return;

      try {
        const required = ['from', 'to', 'ciphertext', 'iv', 'signature', 'hash', 'message_id', 'sent_at'];
        const complete = required.every((field) => data[field]);
        if (!complete) {
          throw new Error('Malformed message payload');
        }

        const seenKey = `${data.from}:${data.message_id}`;
        if (seenMessageIdsRef.current.has(seenKey)) {
          return;
        }
        seenMessageIdsRef.current.add(seenKey);

        const sentAtMs = Date.parse(data.sent_at);
        if (Number.isNaN(sentAtMs) || Math.abs(Date.now() - sentAtMs) > 5 * 60 * 1000) {
          throw new Error('Stale or invalid message timestamp');
        }

        let session = sessionsRef.current[data.from];
        if (!session) {
          session = await getOrCreateSession(data.from);
        }

        const envelope = buildSignedEnvelope({
          from: data.from,
          to: data.to,
          message_id: data.message_id,
          sent_at: data.sent_at,
          iv: data.iv,
          ciphertext: data.ciphertext,
          hash: data.hash
        });

        const isSigValid = await verifySignature(session.ecdsaPublicKey, data.signature, envelope);
        if (!isSigValid) {
          throw new Error('Signature verification failed');
        }

        const plaintext = await decryptMessage(session.sharedKey, data.iv, data.ciphertext);
        const computedHash = await generateHash(plaintext);
        const isHashValid = computedHash === data.hash;

        if (!isHashValid) {
          throw new Error('Hash mismatch');
        }

        setMessages(prev => [...prev, {
          id: Date.now(),
          from: data.from,
          to: data.to,
          plaintext: plaintext,
          status: 'verified'
        }]);

      } catch (err) {
        setMessages(prev => [...prev, {
          id: Date.now(),
          from: data.from || 'unknown',
          to: data.to || usernameRef.current,
          plaintext: '[Message failed verification]',
          status: 'invalid'
        }]);
        console.error('Message decryption/verification failed:', err);
      }
    });

    return () => {
      socket.off('connect');
      socket.off('user_list');
      socket.off('registered');
      socket.off('receive_message');
      socket.off('auth_error');
      socket.off('delivery_error');
      socket.off('rate_limit');
    };
  }, [socket]);

  const getOrCreateSession = async (targetUser) => {
    if (sessionsRef.current[targetUser]) {
      return sessionsRef.current[targetUser];
    }

    const tokenValue = tokenRef.current;
    const keyMaterial = keysRef.current;
    if (!tokenValue || !keyMaterial) {
      throw new Error('Cannot create secure session before registration');
    }

    return await new Promise((resolve, reject) => {
      socket.emit('get_public_key', { username: targetUser, token: tokenValue }, async (response) => {
        if (!response || response.error) {
          reject(new Error(response?.error || 'Public key lookup failed'));
          return;
        }
        try {
          const theirEcdhPub = await importECDHPublicKey(response.public_key);
          const theirEcdsaPub = await importECDSAPublicKey(response.sign_public_key);
          const sharedMasterKey = await deriveSharedKey(keyMaterial.ecdh.privateKey, theirEcdhPub);

          const session = {
            targetUser,
            sharedKey: sharedMasterKey,
            ecdsaPublicKey: theirEcdsaPub
          };
          sessionsRef.current[targetUser] = session;
          resolve(session);
        } catch (err) {
          reject(err);
        }
      });
    });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!username.trim() || !socket) return;

    try {
      const ecdhKeys = await generateECDHKeyPair();
      const ecdsaKeys = await generateECDSAKeyPair();
      
      setKeys({ ecdh: ecdhKeys, ecdsa: ecdsaKeys });

      const exportedEcdh = await exportKey(ecdhKeys.publicKey);
      const exportedEcdsa = await exportKey(ecdsaKeys.publicKey);

      socket.connect();
      socket.emit('register', {
        username,
        public_key: exportedEcdh,
        sign_public_key: exportedEcdsa
      });
    } catch (err) {
      console.error("Registration failed:", err);
      setErrorBanner('Registration failed. Please retry.');
    }
  };

  const startChat = async (targetUser) => {
    setSelectedUser(targetUser);
    try {
      const session = await getOrCreateSession(targetUser);
      setActiveSession(session);
    } catch (err) {
      console.error('Session setup failed:', err);
      setErrorBanner('Could not establish secure session');
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!inputMsg.trim() || !activeSession || !socket) return;

    const messageToSend = inputMsg;
    setInputMsg("");

    try {
      const hash = await generateHash(messageToSend);
      const { iv, ciphertext } = await encryptMessage(activeSession.sharedKey, messageToSend);

      const messageId = generateMessageId();
      const sentAt = new Date().toISOString();
      const envelope = buildSignedEnvelope({
        from: username,
        to: selectedUser,
        message_id: messageId,
        sent_at: sentAt,
        iv,
        ciphertext,
        hash
      });
      const signature = await signMessage(keys.ecdsa.privateKey, envelope);

      const payload = {
        from: username,
        to: selectedUser,
        ciphertext,
        iv,
        signature,
        hash,
        message_id: messageId,
        sent_at: sentAt,
        token
      };

      socket.emit('send_message', payload);

      setMessages(prev => [...prev, {
        id: Date.now(),
        from: username,
        to: selectedUser,
        plaintext: messageToSend,
        status: 'sent'
      }]);
    } catch (err) {
      console.error("Send failed:", err);
      setErrorBanner('Send failed; verify secure session/token state.');
    }
  };

  if (!isRegistered) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-900 p-4">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800 p-8 rounded-2xl shadow-xl max-w-md w-full border border-slate-700"
        >
          <div className="flex items-center justify-center mb-8">
            <Shield className="w-12 h-12 text-emerald-400 mr-3" />
            <h1 className="text-3xl font-bold text-white">Secure Chat</h1>
          </div>
          <p className="text-slate-400 mb-6 text-center text-sm">
            End-to-End Encrypted via AES-256-GCM and ECDH with ECDSA Signatures.
          </p>
          {errorBanner && (
            <p className="text-red-400 text-sm mb-4">{errorBanner}</p>
          )}
          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-400 text-white"
                placeholder="Enter your alias"
                required
              />
            </div>
            <button
              type="submit"
              className="w-full bg-emerald-500 hover:bg-emerald-600 text-white font-semibold py-3 px-4 rounded-lg transition duration-200 flex items-center justify-center"
            >
              <Lock className="w-5 h-5 mr-2" />
              Generate Keys & Join
            </button>
          </form>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 flex h-screen overflow-hidden">
      {/* Sidebar */}
      <div className="w-80 bg-slate-800 border-r border-slate-700 flex flex-col">
        <div className="p-6 border-b border-slate-700">
          <div className="flex items-center text-emerald-400 font-bold text-xl mb-1">
            <Shield className="w-6 h-6 mr-2" /> Secure Chat
          </div>
          <div className="text-slate-400 text-sm flex items-center">
            <User className="w-4 h-4 mr-1" /> Logged in as: <span className="text-white ml-1">{username}</span>
          </div>
        </div>
        
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-4">Available Users</h2>
          {users.length === 0 ? (
            <p className="text-slate-500 text-sm text-center mt-8">No other users online</p>
          ) : (
            users.map(u => (
              <button
                key={u}
                onClick={() => startChat(u)}
                className={`w-full text-left px-4 py-3 rounded-lg flex items-center transition-colors ${selectedUser === u ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'hover:bg-slate-700 text-slate-300 border border-transparent'}`}
              >
                <div className={`w-2 h-2 rounded-full mr-3 ${selectedUser === u ? 'bg-emerald-400' : 'bg-slate-500'}`} />
                {u}
              </button>
            ))
          )}
        </div>
        
        <div className="p-4 border-t border-slate-700 text-xs text-slate-500 flex items-center justify-between">
            <span>Status: Protected</span>
            <Lock className="w-4 h-4 text-emerald-500" />
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col bg-slate-900">
        {selectedUser ? (
          <>
            <div className="h-16 border-b border-slate-700 flex items-center px-6 justify-between bg-slate-800/50">
              <div className="flex items-center">
                <div className="w-10 h-10 bg-emerald-500/20 text-emerald-400 rounded-full flex items-center justify-center font-bold mr-4">
                  {selectedUser.charAt(0).toUpperCase()}
                </div>
                <div>
                  <h3 className="font-semibold text-white">{selectedUser}</h3>
                  <p className="text-xs text-emerald-400 flex items-center">
                    {activeSession ? (
                        <><Lock className="w-3 h-3 mr-1" /> E2E Encrypted Session Established</>
                    ) : (
                        <span className="text-slate-400">Exchanging keys...</span>
                    )}
                  </p>
                </div>
              </div>
              {errorBanner && <span className="text-xs text-red-400">{errorBanner}</span>}
            </div>
            
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {messages.filter(m => (m.from === selectedUser && m.to === username) || (m.from === username && m.to === selectedUser)).map((msg) => (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  key={msg.id}
                  className={`flex flex-col ${msg.from === username ? 'items-end' : 'items-start'}`}
                >
                  <div className={`max-w-[70%] px-5 py-3 rounded-2xl ${msg.from === username ? 'bg-emerald-600 text-white rounded-br-none' : 'bg-slate-800 text-slate-100 border border-slate-700 rounded-bl-none'}`}>
                    <p className="mb-1">{msg.plaintext}</p>
                    <div className="flex items-center justify-end text-[10px] opacity-70">
                        {msg.from !== username && (
                            msg.status === 'verified' ? 
                            <CheckCircle2 className="w-3 h-3 text-emerald-400 mr-1" title="Signature & Hash Verified" /> :
                            <AlertCircle className="w-3 h-3 text-red-400 mr-1" title="Verification Failed!" />
                        )}
                        <span>{new Date(msg.id).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>

            <div className="p-4 bg-slate-800/80 border-t border-slate-700">
              <form onSubmit={sendMessage} className="flex space-x-3 max-w-4xl mx-auto relative">
                <input
                  type="text"
                  value={inputMsg}
                  onChange={(e) => setInputMsg(e.target.value)}
                  placeholder={activeSession ? "Type an encrypted message..." : "Waiting for secure channel..."}
                  disabled={!activeSession}
                  className="flex-1 bg-slate-900 border border-slate-600 rounded-full px-6 py-3 text-white focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 disabled:opacity-50"
                />
                <button
                  type="submit"
                  disabled={!activeSession || !inputMsg.trim()}
                  className="bg-emerald-500 hover:bg-emerald-600 text-white rounded-full w-12 h-12 flex items-center justify-center transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex-shrink-0"
                >
                  <Send className="w-5 h-5 ml-1" />
                </button>
              </form>
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-500">
            <Shield className="w-16 h-16 mb-4 opacity-20" />
            <p>Select a user to start a secure conversation.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
