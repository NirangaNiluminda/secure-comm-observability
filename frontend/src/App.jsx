import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import { Shield, Lock, Send, User, CheckCircle2, AlertCircle } from 'lucide-react';
import { motion } from 'framer-motion';
import {
  generateECDHKeyPair, generateECDSAKeyPair, exportKey,
  importECDHPublicKey, importECDSAPublicKey, deriveSharedKey,
  encryptMessage, decryptMessage, signMessage, verifySignature, generateHash
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

  useEffect(() => {
    const newSocket = io(SOCKET_SERVER_URL, { autoConnect: false });
    setSocket(newSocket);
    
    return () => newSocket.disconnect();
  }, []);

  useEffect(() => {
    if (!socket) return;

    socket.on('connect', () => {
      console.log('Connected to server');
    });

    socket.on('user_list', (userList) => {
      setUsers(userList.filter(u => u !== username));
    });

    socket.on('registered', (data) => {
      setToken(data.token);
      setIsRegistered(true);
    });

    socket.on('receive_message', async (data) => {
      // data: { from, to, ciphertext, iv, signature, hash }
      if (!keys) return;
      
      try {
        let session = activeSession;
        // If we don't have an active session with this user, we need their public key
        if (!session || session.targetUser !== data.from) {
            // we should ideally fetch it synchronously or queue the message
            // for simplicity, let's fetch it via REST or wait for socket
            // In a real app we'd request the key and wait
            console.warn("Received message from non-active session. Need their public key.");
            return;
        }

        // 1. Decrypt
        const plaintext = await decryptMessage(session.sharedKey, data.iv, data.ciphertext);
        
        // 2. Verify Hash
        const computedHash = await generateHash(plaintext);
        const isHashValid = computedHash === data.hash;

        // 3. Verify Signature
        const isSigValid = await verifySignature(session.ecdsaPublicKey, data.signature, plaintext);

        setMessages(prev => [...prev, {
          id: Date.now(),
          from: data.from,
          to: data.to,
          plaintext: plaintext,
          status: isHashValid && isSigValid ? 'verified' : 'invalid'
        }]);

      } catch (err) {
        console.error("Message decryption/verification failed:", err);
      }
    });

    return () => {
      socket.off('connect');
      socket.off('user_list');
      socket.off('registered');
      socket.off('receive_message');
    };
  }, [socket, username, keys, activeSession]);

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
    }
  };

  const startChat = (targetUser) => {
    setSelectedUser(targetUser);
    socket.emit('get_public_key', { username: targetUser }, async (response) => {
      if (response.error) {
        console.error(response.error);
        return;
      }
      try {
        const theirEcdhPub = await importECDHPublicKey(response.public_key);
        const theirEcdsaPub = await importECDSAPublicKey(response.sign_public_key);
        
        const sharedMasterKey = await deriveSharedKey(keys.ecdh.privateKey, theirEcdhPub);
        
        setActiveSession({
          targetUser,
          sharedKey: sharedMasterKey,
          ecdsaPublicKey: theirEcdsaPub
        });
      } catch (err) {
        console.error("Session setup failed:", err);
      }
    });
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!inputMsg.trim() || !activeSession || !socket) return;

    const messageToSend = inputMsg;
    setInputMsg("");

    try {
      // 1. Hash
      const hash = await generateHash(messageToSend);
      // 2. Sign
      const signature = await signMessage(keys.ecdsa.privateKey, messageToSend);
      // 3. Encrypt
      const { iv, ciphertext } = await encryptMessage(activeSession.sharedKey, messageToSend);

      const payload = {
        from: username,
        to: selectedUser,
        ciphertext,
        iv,
        signature,
        hash
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
