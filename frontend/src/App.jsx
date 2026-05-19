import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Lock, Send, User, CheckCircle2, AlertCircle,
  LogIn, UserPlus, Eye, EyeOff, ChevronDown, ChevronUp,
  Activity, FileText, AlertTriangle, Key, Hash, Cpu,
  RefreshCw, LogOut, Wifi, WifiOff, ShieldCheck, ShieldAlert,
  LayoutDashboard, MessageSquare
} from 'lucide-react';
import Dashboard from './Dashboard';
import {
  generateECDHKeyPair, generateECDSAKeyPair, exportKey,
  importECDHPublicKey, importECDSAPublicKey, deriveSharedKey,
  encryptMessage, decryptMessage, signMessage, verifySignature,
  generateHash, generateMessageId, buildSignedEnvelope,
  signBytes, computeSafetyNumber, verifyServerKeyCert,
  base64ToArrayBuffer, arrayBufferToBase64,
  saveIdentityKeyPair, loadIdentityKeyPair,
} from './crypto';

const SOCKET_SERVER_URL = window.location.origin;
const API_BASE = '';

// ─────────────────────────────────────────────────────────────
// Tiny reusable components
// ─────────────────────────────────────────────────────────────

function GlowDot({ color = 'emerald', pulse = false }) {
  const colors = {
    emerald: 'bg-emerald-400',
    red: 'bg-red-400',
    yellow: 'bg-yellow-400',
    blue: 'bg-blue-400',
    slate: 'bg-slate-500',
  };
  return (
    <span className="relative flex h-2 w-2">
      {pulse && <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${colors[color]} opacity-60`} />}
      <span className={`relative inline-flex rounded-full h-2 w-2 ${colors[color]}`} />
    </span>
  );
}

function Badge({ children, color = 'emerald' }) {
  const styles = {
    emerald: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    red: 'bg-red-500/10 text-red-400 border-red-500/20',
    yellow: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    slate: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-semibold font-mono border tracking-wider ${styles[color]}`}>
      {children}
    </span>
  );
}

function PasswordStrength({ password }) {
  const checks = [
    password.length >= 8,
    /[A-Z]/.test(password),
    /[0-9]/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ];
  const score = checks.filter(Boolean).length;
  const config = [
    null,
    { label: 'Weak', bar: 'bg-red-500', text: 'text-red-400' },
    { label: 'Fair', bar: 'bg-yellow-500', text: 'text-yellow-400' },
    { label: 'Good', bar: 'bg-blue-400', text: 'text-blue-400' },
    { label: 'Strong', bar: 'bg-emerald-500', text: 'text-emerald-400' },
  ];
  if (!password) return null;
  const c = config[score] || config[1];
  return (
    <div className="mt-2 space-y-1">
      <div className="flex gap-1">
        {[0, 1, 2, 3].map(i => (
          <div key={i} className={`h-1 flex-1 rounded-full transition-all duration-300 ${i < score ? c.bar : 'bg-slate-700'}`} />
        ))}
      </div>
      <p className={`text-[11px] ${c.text}`}>{c.label} password</p>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Auth Screen
// ─────────────────────────────────────────────────────────────

function AuthScreen({ onAuthenticated }) {
  const [tab, setTab] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async (e) => {
    e.preventDefault();
    setError(''); setSuccess('');
    if (password !== confirm) return setError('Passwords do not match');
    if (password.length < 6) return setError('Password must be at least 6 characters');
    setLoading(true);
    try {
      // ── Generate ECDSA identity keypair ─────────────────────────────────────
      // This keypair is created ONCE at registration.  The public half is stored
      // on the server so future logins can verify the challenge signature against
      // a pre-registered key — not whatever key the client submits at login time.
      setSuccess('Generating identity key…');
      const identityKeys   = await generateECDSAKeyPair();
      const identityPubJwk = await exportKey(identityKeys.publicKey);

      // ── Register with server ─────────────────────────────────────────────────
      setSuccess('Creating account…');
      const res = await fetch(`${API_BASE}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, ecdsaIdentityPubJwk: identityPubJwk }),
      });
      const d = await res.json();
      if (!res.ok) return setError(d.error || 'Registration failed');

      // ── Save identity keypair to IndexedDB ───────────────────────────────────
      // Private key stays in the browser — only the public half went to the server.
      // Keyed by username so multiple accounts can share a browser.
      await saveIdentityKeyPair(username, identityKeys);

      setSuccess('Account created! Identity key saved to this browser.');
      setTimeout(() => { setTab('login'); setSuccess(''); setPassword(''); setConfirm(''); }, 2000);
    } catch (err) {
      setError('Cannot reach server. Is the backend running?');
    } finally { setLoading(false); }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError(''); setSuccess('');
    setLoading(true);
    try {
      // ── Step 0a: load identity keypair from IndexedDB ───────────────────
      // The identity key was generated and saved during registration.
      // We load it here to sign the server challenge.
      // Private key never leaves the browser — it was never transmitted.
      setSuccess('Loading identity key…');
      const identityKeys = await loadIdentityKeyPair(username);
      if (!identityKeys) {
        setSuccess('');
        return setError(
          'No identity key found for this account in this browser. ' +
          'Identity keys are device-specific — please re-register, or use the browser you registered with.'
        );
      }

      // ── Step 0b: generate fresh ECDH keypair for this session (PFS) ─────
      // New ECDH key every login → past sessions cannot be decrypted even if
      // this session key is later compromised (Perfect Forward Secrecy).
      const ecdhKeys = await generateECDHKeyPair();

      // ── Step 1: verify password → receive one-time challenge ─────────────
      setSuccess('Verifying credentials…');
      const r1 = await fetch(`${API_BASE}/api/auth/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const d1 = await r1.json();
      if (!r1.ok) { setSuccess(''); return setError(d1.error || 'Login failed'); }

      // ── Step 2: sign the challenge with the IDENTITY private key ─────────
      // Server will verify against the stored public key — not whatever we
      // submit here. Mallory with Alice's password still can't log in because
      // she doesn't hold the private key registered at account creation.
      setSuccess('Signing challenge with identity key…');
      const challengeBytes = base64ToArrayBuffer(d1.challenge);
      const signatureB64   = await signBytes(identityKeys.privateKey, challengeBytes);

      // ── Step 3: submit signature → receive JWT + server key certificate ──
      // Note: ecdsa_public_key is no longer sent — server uses the stored key.
      setSuccess('Completing authentication…');
      const r2 = await fetch(`${API_BASE}/api/auth/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge_id: d1.challenge_id, username, signature: signatureB64 }),
      });
      const d2 = await r2.json();
      if (!r2.ok) { setSuccess(''); return setError(d2.error || 'Authentication failed'); }

      // identityKeys used as the ECDSA keys for message signing too (same key)
      onAuthenticated(d2.token, d2.username, { ecdh: ecdhKeys, ecdsa: identityKeys }, d2.server_key_cert);
    } catch (err) {
      setSuccess('');
      setError('Cannot reach server. Is the backend running?');
    } finally { setLoading(false); }
  };

  const securityItems = [
    { icon: Key, label: 'Key Exchange', value: 'ECDH P-256' },
    { icon: Lock, label: 'Encryption', value: 'AES-256-GCM' },
    { icon: ShieldCheck, label: 'Signatures', value: 'ECDSA SHA-256' },
    { icon: Hash, label: 'Integrity', value: 'SHA-256' },
    { icon: User, label: 'Auth', value: 'JWT + bcrypt' },
    { icon: Wifi, label: 'Transport', value: 'HTTPS / WSS' },
  ];

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden"
      style={{ background: 'radial-gradient(ellipse at 60% 0%, #0d2137 0%, #0a0f1e 60%)' }}
    >
      {/* Background grid */}
      <div className="absolute inset-0 opacity-[0.03]"
        style={{ backgroundImage: 'linear-gradient(#10b981 1px, transparent 1px), linear-gradient(90deg, #10b981 1px, transparent 1px)', backgroundSize: '40px 40px' }} />

      {/* Glow blobs */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] rounded-full blur-[120px] opacity-20"
        style={{ background: 'radial-gradient(circle, #10b981, transparent)' }} />

      <div className="relative z-10 w-full max-w-4xl flex gap-6 items-start">

        {/* Left — branding */}
        <motion.div
          initial={{ opacity: 0, x: -30 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.5 }}
          className="hidden lg:flex flex-col flex-1 pt-8"
        >
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <Shield className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Secure Chat</h1>
              <p className="text-xs text-slate-500">End-to-End Encrypted Messaging</p>
            </div>
          </div>

          <p className="text-slate-400 text-sm leading-relaxed mb-8">
            A cryptographically secure messaging platform demonstrating real-world
            application of modern security primitives — ECDH key exchange, AES-256-GCM
            encryption, ECDSA non-repudiation, and hash-chained audit logs.
          </p>

          <div className="grid grid-cols-2 gap-3">
            {securityItems.map(({ icon: Icon, label, value }) => (
              <div key={label} className="flex items-center gap-3 p-3 rounded-xl bg-slate-800/40 border border-slate-700/50">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center flex-shrink-0">
                  <Icon className="w-4 h-4 text-emerald-400" />
                </div>
                <div>
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</p>
                  <p className="text-xs font-semibold font-mono text-slate-200">{value}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Right — auth card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}
          className="w-full lg:w-[420px] flex-shrink-0"
        >
          <div className="bg-slate-900/80 backdrop-blur-xl border border-slate-700/60 rounded-2xl shadow-2xl overflow-hidden">

            {/* Card header */}
            <div className="px-6 pt-6 pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2 mb-1 lg:hidden">
                <Shield className="w-5 h-5 text-emerald-400" />
                <span className="font-bold text-white">Secure Chat</span>
              </div>

              {/* Tabs */}
              <div className="flex bg-slate-800/60 rounded-xl p-1 gap-1">
                {[['login', LogIn, 'Login'], ['register', UserPlus, 'Register']].map(([id, Icon, lbl]) => (
                  <button key={id} onClick={() => { setTab(id); setError(''); setSuccess(''); }}
                    className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${tab === id
                        ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-900/40'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                      }`}>
                    <Icon className="w-4 h-4" /> {lbl}
                  </button>
                ))}
              </div>
            </div>

            {/* Card body */}
            <div className="p-6">
              {/* Alerts */}
              <AnimatePresence>
                {error && (
                  <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
                    className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-300 text-sm px-4 py-3 rounded-xl mb-4">
                    <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
                  </motion.div>
                )}
                {success && (
                  <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
                    className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-sm px-4 py-3 rounded-xl mb-4">
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" /> {success}
                  </motion.div>
                )}
              </AnimatePresence>

              <form onSubmit={tab === 'login' ? handleLogin : handleRegister} className="space-y-4">
                {/* Username */}
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">Username</label>
                  <div className="relative">
                    <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input type="text" value={username} onChange={e => setUsername(e.target.value)} required minLength={3}
                      className="w-full pl-10 pr-4 py-3 bg-slate-800/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500/50 transition-all"
                      placeholder="Enter your username" />
                  </div>
                </div>

                {/* Password */}
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1.5">Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input type={showPw ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)} required minLength={6}
                      className="w-full pl-10 pr-12 py-3 bg-slate-800/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500/50 transition-all"
                      placeholder="Enter your password" />
                    <button type="button" onClick={() => setShowPw(v => !v)}
                      className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors">
                      {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {tab === 'register' && <PasswordStrength password={password} />}
                </div>

                {/* Confirm password */}
                {tab === 'register' && (
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1.5">Confirm Password</label>
                    <div className="relative">
                      <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                      <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} required
                        className={`w-full pl-10 pr-4 py-3 bg-slate-800/60 border rounded-xl text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 transition-all ${confirm && confirm !== password
                            ? 'border-red-500/50 focus:ring-red-500/30'
                            : 'border-slate-700 focus:ring-emerald-500/50 focus:border-emerald-500/50'
                          }`}
                        placeholder="Confirm your password" />
                    </div>
                    {confirm && confirm !== password && (
                      <p className="text-xs text-red-400 mt-1">Passwords do not match</p>
                    )}
                  </div>
                )}

                <button type="submit" disabled={loading}
                  className="w-full relative bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold py-3 px-4 rounded-xl transition-all duration-200 flex items-center justify-center gap-2 shadow-lg shadow-emerald-900/30 mt-2">
                  {loading
                    ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    : tab === 'login'
                      ? <><LogIn className="w-4 h-4" /> Login &amp; Generate Keys</>
                      : <><UserPlus className="w-4 h-4" /> Create Account</>
                  }
                </button>
              </form>

              {/* Footer note */}
              <p className="text-center text-[11px] text-slate-600 mt-4">
                {tab === 'login'
                  ? 'Password + Challenge-Response · private key never leaves this device'
                  : 'Keys are generated locally — your private key never leaves this device'}
              </p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Audit Log Panel
// ─────────────────────────────────────────────────────────────

function AuditLogPanel({ token }) {
  const [entries, setEntries] = useState([]);
  const [chainValid, setChainValid] = useState(true);
  const [total, setTotal] = useState(0);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  const fetchLog = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/audit?limit=20`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const d = await res.json();
      if (res.ok) { setEntries(d.entries || []); setChainValid(d.chain_valid); setTotal(d.total); }
    } catch { /* ignore */ }
    finally { setLoading(false); }
  };

  useEffect(() => { if (open) fetchLog(); }, [open]);

  const eventStyle = (t = '') => {
    if (t.includes('fail') || t.includes('reject')) return { color: 'text-red-400', bg: 'bg-red-500/10' };
    if (t.includes('message')) return { color: 'text-blue-400', bg: 'bg-blue-500/10' };
    if (t.includes('login') || t.includes('join') || t.includes('creat')) return { color: 'text-emerald-400', bg: 'bg-emerald-500/10' };
    return { color: 'text-slate-400', bg: 'bg-slate-500/10' };
  };

  return (
    <div className="border-t border-slate-800">
      <button onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-4 py-3 text-sm hover:bg-slate-800/40 transition-colors group">
        <span className="flex items-center gap-2.5">
          <FileText className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition-colors" />
          <span className="text-slate-300 font-medium text-xs">Audit Log</span>
          <Badge color={chainValid ? 'emerald' : 'red'}>
            {chainValid ? '✓ chain valid' : '✗ broken'}
          </Badge>
        </span>
        <span className="flex items-center gap-1.5 text-slate-600">
          {total > 0 && <span className="text-[10px]">{total}</span>}
          {open ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </span>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            style={{ overflow: 'hidden' }}>
            <div className="px-3 pb-3 max-h-56 overflow-y-auto space-y-1.5">
              {loading && (
                <div className="flex items-center justify-center py-4">
                  <span className="w-4 h-4 border-2 border-slate-600 border-t-emerald-400 rounded-full animate-spin" />
                </div>
              )}
              {!loading && entries.length === 0 && (
                <p className="text-[11px] text-slate-600 text-center py-3">No entries yet</p>
              )}
              {entries.slice().reverse().map((e, i) => {
                const s = eventStyle(e.event?.event_type);
                return (
                  <div key={i} className={`rounded-lg px-3 py-2 border border-slate-800 ${s.bg}`}>
                    <div className="flex items-center justify-between">
                      <span className={`text-[11px] font-semibold font-mono ${s.color}`}>{e.event?.event_type}</span>
                      <span className="text-[10px] text-slate-600">{new Date(e.event?.timestamp).toLocaleTimeString()}</span>
                    </div>
                    {(e.event?.username || e.event?.from) && (
                      <p className="text-[10px] text-slate-500 mt-0.5">
                        {e.event.username || `${e.event.from} → ${e.event.to}`}
                      </p>
                    )}
                    <p className="text-[9px] text-slate-700 font-mono mt-0.5 truncate">#{e.entry_hash?.slice(0, 20)}…</p>
                  </div>
                );
              })}
              <button onClick={fetchLog}
                className="w-full flex items-center justify-center gap-1.5 text-[11px] text-slate-600 hover:text-slate-400 py-1.5 transition-colors">
                <RefreshCw className="w-3 h-3" /> Refresh
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Message bubble
// ─────────────────────────────────────────────────────────────

function MessageBubble({ msg, isMine, expanded, onToggleExpand }) {
  const statusConfig = {
    verified: { icon: <ShieldCheck className="w-3 h-3 text-emerald-400" />, label: 'Verified', color: 'text-emerald-400' },
    invalid: { icon: <ShieldAlert className="w-3 h-3 text-red-400" />, label: 'FAILED', color: 'text-red-400' },
    sent: { icon: <CheckCircle2 className="w-3 h-3 text-slate-500" />, label: 'Sent', color: 'text-slate-500' },
    tampered_sent: { icon: <AlertTriangle className="w-3 h-3 text-yellow-400" />, label: 'Tampered', color: 'text-yellow-400' },
  };
  const s = statusConfig[msg.status] || statusConfig.sent;

  const bubbleStyle = isMine
    ? msg.status === 'tampered_sent'
      ? 'bg-yellow-600/80 text-white rounded-br-sm'
      : 'bg-emerald-600 text-white rounded-br-sm'
    : msg.status === 'invalid'
      ? 'bg-red-900/30 border border-red-500/20 text-red-200 rounded-bl-sm'
      : 'bg-slate-800 border border-slate-700/60 text-slate-100 rounded-bl-sm';

  return (
    <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
      className={`flex flex-col gap-1 ${isMine ? 'items-end' : 'items-start'}`}>

      <div className={`max-w-[72%] px-4 py-2.5 rounded-2xl text-sm shadow-sm ${bubbleStyle}`}>
        <p className="leading-relaxed break-words">{msg.plaintext}</p>
        <div className="flex items-center justify-end gap-1.5 mt-1.5 opacity-70">
          {!isMine && s.icon}
          <span className="text-[10px]">{new Date(msg.id).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          {msg.meta && Object.keys(msg.meta).length > 0 && (
            <button onClick={() => onToggleExpand(msg.id)}
              className="ml-0.5 hover:opacity-100 transition-opacity">
              <Cpu className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Security detail panel */}
      <AnimatePresence>
        {expanded && msg.meta && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}
            style={{ overflow: 'hidden' }}
            className={`max-w-[72%] w-full rounded-xl border border-slate-700/60 bg-slate-900/90 backdrop-blur px-4 py-3 space-y-1.5`}>
            <p className="text-[9px] font-semibold text-slate-600 uppercase tracking-widest mb-2">Cryptographic Details</p>
            {[
              ['Algorithm', msg.meta.alg, 'emerald'],
              ['AES-GCM IV', msg.meta.iv, 'blue'],
              ['SHA-256 hash', msg.meta.hash, msg.status === 'verified' ? 'emerald' : 'red'],
              ['ECDSA sig', msg.meta.sig, msg.status === 'verified' ? 'emerald' : 'red'],
              ['Status', msg.status, msg.status === 'verified' ? 'emerald' : msg.status === 'sent' ? 'slate' : 'red'],
            ].filter(([, v]) => v).map(([label, value, color]) => (
              <div key={label} className="flex items-center justify-between gap-3">
                <span className="text-[10px] text-slate-500 flex-shrink-0">{label}</span>
                <Badge color={color}>{value}</Badge>
              </div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────
// Main Chat App
// ─────────────────────────────────────────────────────────────

function ChatApp({ token, username, onLogout, embedded = false, keysPregenerated = null, serverKeyCert = null }) {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputMsg, setInputMsg] = useState('');
  const [activeSession, setActiveSession] = useState(null);
  const [errorBanner, setErrorBanner] = useState('');
  const [keys, setKeys] = useState(null);
  const [tamperMode, setTamperMode] = useState(false);
  const [expandedMsg, setExpandedMsg] = useState(null);
  const [showSafetyPanel, setShowSafetyPanel] = useState(false);

  const sessionsRef       = useRef({});
  const keysRef           = useRef(null);
  const tokenRef          = useRef(token);
  const usernameRef       = useRef(username);
  const seenIdsRef        = useRef(new Set());
  const bottomRef         = useRef(null);
  const serverPubJwkRef   = useRef(null);   // server's ECDSA public key (JWK)
  const serverKeyCertRef  = useRef(serverKeyCert); // my own server-signed cert

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  // Use pre-generated keys from login flow, or generate new ones if not available
  // (fallback for direct access without challenge-response)
  useEffect(() => {
    if (keysPregenerated) {
      setKeys(keysPregenerated);
      keysRef.current = keysPregenerated;
      return;
    }
    (async () => {
      const ecdhKeys  = await generateECDHKeyPair();
      const ecdsaKeys = await generateECDSAKeyPair();
      const k = { ecdh: ecdhKeys, ecdsa: ecdsaKeys };
      setKeys(k); keysRef.current = k;
    })();
  }, []);

  // Fetch server's ECDSA public key once (needed to verify peer key certificates)
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/api/server/pubkey`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const d = await res.json();
        if (d.server_pubkey_jwk) serverPubJwkRef.current = d.server_pubkey_jwk;
      } catch { /* non-fatal — cert verification will show as unverified */ }
    })();
  }, []);

  useEffect(() => { tokenRef.current = token; }, [token]);
  useEffect(() => { usernameRef.current = username; }, [username]);

  // Connect socket once keys are ready
  useEffect(() => {
    if (!keys) return;
    const sock = io(SOCKET_SERVER_URL, { autoConnect: false, auth: { token } });
    setSocket(sock);

    sock.on('connect', async () => {
      setConnected(true);
      const exportedEcdh  = await exportKey(keys.ecdh.publicKey);
      const exportedEcdsa = await exportKey(keys.ecdsa.publicKey);
      sock.emit('register', {
        token,
        public_key:      exportedEcdh,
        sign_public_key: exportedEcdsa,
        server_key_cert: serverKeyCertRef.current || '',  // server-signed cert from login
      });
    });
    sock.on('disconnect', () => setConnected(false));
    sock.on('registered', () => setErrorBanner(''));
    sock.on('user_list', list => setUsers(list.filter(u => u !== usernameRef.current)));
    sock.on('auth_error', d => setErrorBanner(d?.error || 'Auth error'));
    sock.on('delivery_error', d => setErrorBanner(d?.error || 'Delivery failed'));
    sock.on('rate_limit', d => setErrorBanner(`${d?.error || 'Rate limited'} — retry in ${d?.retry_after}s`));

    sock.on('receive_message', async (data) => {
      if (!keysRef.current) return;
      try {
        const required = ['from', 'to', 'ciphertext', 'iv', 'signature', 'hash', 'message_id', 'sent_at'];
        if (!required.every(f => data[f])) throw new Error('Malformed payload');
        const key = `${data.from}:${data.message_id}`;
        if (seenIdsRef.current.has(key)) return;
        seenIdsRef.current.add(key);
        const ms = Date.parse(data.sent_at);
        if (Number.isNaN(ms) || Math.abs(Date.now() - ms) > 5 * 60 * 1000) throw new Error('Stale timestamp');

        let session = sessionsRef.current[data.from];
        if (!session) session = await getOrCreateSession(data.from, sock);

        const envelope = buildSignedEnvelope({ from: data.from, to: data.to, message_id: data.message_id, sent_at: data.sent_at, iv: data.iv, ciphertext: data.ciphertext, hash: data.hash });
        const sigOk = await verifySignature(session.ecdsaPublicKey, data.signature, envelope);
        if (!sigOk) throw new Error('Signature verification failed');

        const plaintext = await decryptMessage(session.sharedKey, data.iv, data.ciphertext);
        const computed = await generateHash(plaintext);
        if (computed !== data.hash) throw new Error('Hash mismatch — message was tampered');

        setMessages(prev => [...prev, {
          id: Date.now(), from: data.from, to: data.to, plaintext, status: 'verified', tampered: !!data.tampered,
          meta: { alg: 'AES-256-GCM + ECDSA', iv: data.iv?.slice(0, 12) + '…', hash: data.hash?.slice(0, 12) + '…', sig: data.signature?.slice(0, 12) + '…' }
        }]);
      } catch (err) {
        setMessages(prev => [...prev, {
          id: Date.now(), from: data.from || 'unknown', to: data.to || usernameRef.current,
          plaintext: `⚠ Verification failed: ${err.message}`, status: 'invalid', meta: {}
        }]);
      }
    });

    sock.connect();
    return () => sock.disconnect();
  }, [keys]);

  const getOrCreateSession = async (targetUser, sock) => {
    if (sessionsRef.current[targetUser]) return sessionsRef.current[targetUser];
    return new Promise((resolve, reject) => {
      sock.emit('get_public_key', { username: targetUser, token: tokenRef.current }, async (res) => {
        if (!res || res.error) { reject(new Error(res?.error || 'Key lookup failed')); return; }
        try {
          const theirEcdhPub  = await importECDHPublicKey(res.public_key);
          const theirEcdsaPub = await importECDSAPublicKey(res.sign_public_key);
          const sharedKey     = await deriveSharedKey(keysRef.current.ecdh.privateKey, theirEcdhPub);

          // ── GAP2: Verify server certificate on peer's ECDSA key ───────────
          // server_key_cert = server's ECDSA signature over canonical(peer.sign_public_key)
          // If valid → server has vouched for this key → MITM would need to break server
          let certVerified = false;
          try {
            if (res.server_key_cert && serverPubJwkRef.current) {
              certVerified = await verifyServerKeyCert(
                serverPubJwkRef.current,
                res.server_key_cert,
                res.sign_public_key,
              );
            }
          } catch { /* non-fatal: certVerified stays false */ }

          // ── GAP3: Compute Safety Number for out-of-band verification ──────
          // SHA-256(sort(myEcdsaKey, theirEcdsaKey)) displayed as digit groups
          // Both chat partners see the same number — MITM would produce a different one
          let safetyNumber = '';
          try {
            const myEcdsaPubJwk = await exportKey(keysRef.current.ecdsa.publicKey);
            safetyNumber = await computeSafetyNumber(myEcdsaPubJwk, res.sign_public_key);
          } catch { /* non-fatal */ }

          const session = {
            targetUser,
            sharedKey,
            ecdsaPublicKey: theirEcdsaPub,
            certVerified,               // did server vouch for this key?
            safetyNumber,               // fingerprint for out-of-band verification
            theirSignPubJwk: res.sign_public_key,
          };
          sessionsRef.current[targetUser] = session;
          resolve(session);
        } catch (err) { reject(err); }
      });
    });
  };

  const startChat = async (targetUser) => {
    setSelectedUser(targetUser); setErrorBanner(''); setActiveSession(null);
    try {
      const session = await getOrCreateSession(targetUser, socket);
      setActiveSession(session);
    } catch (err) { setErrorBanner(`Session failed: ${err.message}`); }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!inputMsg.trim() || !activeSession || !socket) return;
    const text = inputMsg; setInputMsg('');
    try {
      const hash = await generateHash(text);
      let { iv, ciphertext } = await encryptMessage(activeSession.sharedKey, text);
      if (tamperMode) {
        const raw = atob(ciphertext);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
        bytes[0] ^= 0xff;
        ciphertext = btoa(String.fromCharCode(...bytes));
      }
      const messageId = generateMessageId();
      const sentAt = new Date().toISOString();
      const envelope = buildSignedEnvelope({ from: username, to: selectedUser, message_id: messageId, sent_at: sentAt, iv, ciphertext, hash });
      const signature = await signMessage(keys.ecdsa.privateKey, envelope);
      socket.emit('send_message', { from: username, to: selectedUser, ciphertext, iv, signature, hash, message_id: messageId, sent_at: sentAt, token, tampered: tamperMode });
      setMessages(prev => [...prev, {
        id: Date.now(), from: username, to: selectedUser,
        plaintext: tamperMode ? `[TAMPERED] ${text}` : text,
        status: tamperMode ? 'tampered_sent' : 'sent',
        meta: { alg: 'AES-256-GCM + ECDSA', iv: iv?.slice(0, 12) + '…', hash: hash?.slice(0, 12) + '…' }
      }]);
    } catch (err) { setErrorBanner(`Send failed: ${err.message}`); }
  };

  const chatMessages = messages.filter(m =>
    (m.from === selectedUser && m.to === username) ||
    (m.from === username && m.to === selectedUser)
  );

  return (
    <div className="h-screen flex overflow-hidden" style={{ background: '#0a0f1e' }}>

      {/* ── Sidebar ── */}
      <div className="w-72 flex flex-col border-r border-slate-800/60 flex-shrink-0"
        style={{ background: 'rgba(15,23,42,0.95)' }}>

        {/* Header */}
        <div className="px-4 py-4 border-b border-slate-800/60">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                <Shield className="w-4 h-4 text-emerald-400" />
              </div>
              <div>
                <p className="text-sm font-bold text-white">Secure Chat</p>
                <div className="flex items-center gap-1.5">
                  <GlowDot color={connected ? 'emerald' : 'slate'} pulse={connected} />
                  <span className="text-[10px] text-slate-500">{connected ? 'Connected' : 'Disconnected'}</span>
                </div>
              </div>
            </div>
            {!embedded && (
              <button onClick={onLogout}
                className="w-7 h-7 rounded-lg hover:bg-red-500/10 flex items-center justify-center text-slate-600 hover:text-red-400 transition-all"
                title="Logout">
                <LogOut className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* User chip */}
          <div className="mt-3 flex items-center gap-2 px-3 py-2 rounded-xl bg-slate-800/60 border border-slate-700/40">
            <div className="w-7 h-7 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold text-xs flex-shrink-0">
              {username.charAt(0).toUpperCase()}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-white truncate">{username}</p>
              <p className="text-[10px] text-slate-500">JWT authenticated</p>
            </div>
          </div>
        </div>

        {/* Users list */}
        <div className="flex-1 overflow-y-auto p-3 space-y-1">
          <p className="text-[10px] font-semibold text-slate-600 uppercase tracking-widest px-2 mb-2">Online Users</p>
          {users.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-slate-600">
              <WifiOff className="w-8 h-8 mb-2 opacity-30" />
              <p className="text-xs">No other users online</p>
            </div>
          ) : (
            users.map(u => (
              <button key={u} onClick={() => startChat(u)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all text-left ${selectedUser === u
                    ? 'bg-emerald-500/10 border border-emerald-500/20 shadow-sm shadow-emerald-900/20'
                    : 'hover:bg-slate-800/60 border border-transparent'
                  }`}>
                <div className={`w-9 h-9 rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 ${selectedUser === u ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-400 border border-slate-700'}`}>
                  {u.charAt(0).toUpperCase()}
                </div>
                <div className="min-w-0">
                  <p className={`text-sm font-medium truncate ${selectedUser === u ? 'text-emerald-300' : 'text-slate-200'}`}>{u}</p>
                  <div className="flex items-center gap-1">
                    <GlowDot color="emerald" />
                    <span className="text-[10px] text-slate-600">online</span>
                  </div>
                </div>
                {selectedUser === u && activeSession && (
                  <Lock className="w-3.5 h-3.5 text-emerald-500 flex-shrink-0 ml-auto" />
                )}
              </button>
            ))
          )}
        </div>

        {/* Tamper demo */}
        <div className="px-3 py-3 border-t border-slate-800/60">
          <button onClick={() => setTamperMode(v => !v)}
            className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl border transition-all text-sm ${tamperMode
                ? 'bg-red-500/10 border-red-500/30 text-red-300'
                : 'bg-slate-800/40 border-slate-700/40 text-slate-400 hover:border-slate-600 hover:text-slate-200'
              }`}>
            <span className="flex items-center gap-2">
              <AlertTriangle className={`w-4 h-4 ${tamperMode ? 'text-red-400' : 'text-slate-500'}`} />
              <span className="font-medium text-xs">Tamper Attack Demo</span>
            </span>
            <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-md ${tamperMode ? 'bg-red-500 text-white' : 'bg-slate-700 text-slate-400'}`}>
              {tamperMode ? 'ON' : 'OFF'}
            </span>
          </button>
          {tamperMode && (
            <p className="text-[10px] text-red-400/80 text-center mt-1.5 leading-tight px-1">
              Ciphertext will be corrupted — receiver will see integrity failure
            </p>
          )}
        </div>

        {/* Audit log */}
        <AuditLogPanel token={token} />
      </div>

      {/* ── Main area ── */}
      <div className="flex-1 flex flex-col min-w-0">
        {selectedUser ? (
          <>
            {/* Chat header */}
            <div className="flex-shrink-0 border-b border-slate-800/60"
              style={{ background: 'rgba(15,23,42,0.7)', backdropFilter: 'blur(12px)' }}>
              <div className="h-[60px] flex items-center justify-between px-5">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-full bg-emerald-500/15 border border-emerald-500/25 flex items-center justify-center font-bold text-emerald-400">
                    {selectedUser.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <p className="font-semibold text-white text-sm">{selectedUser}</p>
                    <div className="flex items-center gap-1.5">
                      <Lock className="w-2.5 h-2.5 text-emerald-500" />
                      <span className="text-[10px] text-emerald-500">
                        {activeSession ? 'E2EE · ECDH P-256 · AES-256-GCM · Challenge-Response' : 'Establishing secure channel…'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {/* Safety Numbers toggle */}
                  {activeSession && (
                    <button
                      onClick={() => setShowSafetyPanel(v => !v)}
                      title="Safety Numbers — compare with your contact to verify no MITM"
                      className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs transition-all ${
                        showSafetyPanel
                          ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400'
                          : activeSession.certVerified
                            ? 'bg-slate-800/60 border-slate-700/40 text-slate-400 hover:text-emerald-400 hover:border-emerald-500/30'
                            : 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400'
                      }`}>
                      <Hash className="w-3.5 h-3.5" />
                      <span className="hidden sm:inline font-medium">
                        {activeSession.certVerified ? 'Certified' : 'Unverified'}
                      </span>
                    </button>
                  )}

                  <AnimatePresence>
                    {errorBanner && (
                      <motion.div initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 10 }}
                        className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-300 text-xs px-3 py-1.5 rounded-lg max-w-xs">
                        <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                        <span className="truncate">{errorBanner}</span>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>

              {/* ── Safety Numbers / Key Certificate panel ─────────────────── */}
              <AnimatePresence>
                {showSafetyPanel && activeSession && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    style={{ overflow: 'hidden' }}>
                    <div className="px-5 py-3 border-t border-slate-800/60 space-y-3">
                      {/* Server Key Certificate status (GAP2) */}
                      <div className="flex items-center gap-2">
                        <ShieldCheck className={`w-4 h-4 flex-shrink-0 ${activeSession.certVerified ? 'text-emerald-400' : 'text-yellow-400'}`} />
                        <div>
                          <span className="text-xs font-semibold text-slate-200">Server Key Certificate</span>
                          <span className={`ml-2 text-[10px] font-mono px-1.5 py-0.5 rounded ${
                            activeSession.certVerified
                              ? 'bg-emerald-500/15 text-emerald-400'
                              : 'bg-yellow-500/15 text-yellow-400'
                          }`}>
                            {activeSession.certVerified
                              ? `✓ ${selectedUser}'s key is server-certified`
                              : `⚠ key unverified — logged in without challenge-response`}
                          </span>
                        </div>
                      </div>

                      {/* Safety Number (GAP3) */}
                      <div>
                        <div className="flex items-center gap-2 mb-1.5">
                          <Hash className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
                          <span className="text-xs font-semibold text-slate-200">Safety Number</span>
                          <span className="text-[10px] text-slate-500">— compare out-of-band with {selectedUser}</span>
                        </div>
                        <p className="font-mono text-sm text-emerald-400 tracking-wider leading-relaxed break-all">
                          {activeSession.safetyNumber || 'Computing…'}
                        </p>
                        <p className="text-[10px] text-slate-600 mt-1">
                          SHA-256({username} key ‖ {selectedUser} key) · If this number matches on both devices, no MITM is present
                        </p>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Messages area */}
            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
              {chatMessages.length === 0 && activeSession && (
                <div className="flex flex-col items-center justify-center h-full text-slate-600 gap-3">
                  <div className="w-14 h-14 rounded-2xl bg-slate-800/60 border border-slate-700/40 flex items-center justify-center">
                    <Lock className="w-6 h-6 text-slate-600" />
                  </div>
                  <div className="text-center">
                    <p className="text-sm text-slate-400 font-medium">Secure channel established</p>
                    <p className="text-xs mt-0.5">Send a message to start the conversation</p>
                  </div>
                </div>
              )}
              {chatMessages.map(msg => (
                <MessageBubble
                  key={msg.id}
                  msg={msg}
                  isMine={msg.from === username}
                  expanded={expandedMsg === msg.id}
                  onToggleExpand={id => setExpandedMsg(prev => prev === id ? null : id)}
                />
              ))}
              <div ref={bottomRef} />
            </div>

            {/* Input bar */}
            <div className={`flex-shrink-0 px-4 py-3 border-t ${tamperMode ? 'border-red-800/40 bg-red-950/20' : 'border-slate-800/60 bg-slate-900/60'} backdrop-blur`}>
              {tamperMode && (
                <div className="flex items-center gap-2 text-xs text-red-400 mb-2 px-1">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Tamper mode active — ciphertext will be corrupted before sending
                </div>
              )}
              <form onSubmit={sendMessage} className="flex gap-2.5 max-w-4xl mx-auto">
                <input
                  type="text" value={inputMsg} onChange={e => setInputMsg(e.target.value)}
                  disabled={!activeSession}
                  placeholder={activeSession ? tamperMode ? 'Type a message to tamper…' : 'Type an encrypted message…' : 'Establishing secure channel…'}
                  className={`flex-1 px-4 py-2.5 rounded-xl text-sm text-white placeholder-slate-600 border focus:outline-none focus:ring-2 transition-all disabled:opacity-40 ${tamperMode
                      ? 'bg-red-950/30 border-red-700/40 focus:ring-red-500/30 focus:border-red-500/50'
                      : 'bg-slate-800/60 border-slate-700/50 focus:ring-emerald-500/30 focus:border-emerald-500/50'
                    }`}
                />
                <button type="submit" disabled={!activeSession || !inputMsg.trim()}
                  className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-lg ${tamperMode
                      ? 'bg-red-600 hover:bg-red-500 shadow-red-900/30'
                      : 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-900/30'
                    }`}>
                  <Send className="w-4 h-4 text-white ml-0.5" />
                </button>
              </form>
            </div>
          </>
        ) : (
          /* Empty state */
          <div className="flex-1 flex flex-col items-center justify-center gap-5 text-slate-600">
            <div className="w-20 h-20 rounded-3xl bg-slate-800/40 border border-slate-700/30 flex items-center justify-center">
              <Shield className="w-10 h-10 opacity-20" />
            </div>
            <div className="text-center">
              <p className="text-lg font-semibold text-slate-400 mb-1">Select a user to begin</p>
              <p className="text-sm text-slate-600">All messages are end-to-end encrypted</p>
            </div>
            <div className="grid grid-cols-3 gap-3 mt-2">
              {[['ECDH', 'Key Exchange', Key], ['AES-256-GCM', 'Encryption', Lock], ['ECDSA', 'Signatures', ShieldCheck]].map(([alg, label, Icon]) => (
                <div key={alg} className="flex flex-col items-center gap-2 px-5 py-4 rounded-2xl bg-slate-800/30 border border-slate-700/30">
                  <Icon className="w-5 h-5 text-emerald-500/60" />
                  <div className="text-center">
                    <p className="text-xs font-semibold font-mono text-emerald-400">{alg}</p>
                    <p className="text-[10px] text-slate-600 mt-0.5">{label}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Top navigation shell (wraps Chat + Dashboard)
// ─────────────────────────────────────────────────────────────

function AppShell({ token, username, onLogout, keysPregenerated = null, serverKeyCert = null }) {
  const [page, setPage] = useState('chat');

  return (
    <div className="h-screen flex flex-col overflow-hidden" style={{ background: '#0a0f1e' }}>
      {/* Top nav bar */}
      <div className="flex-shrink-0 h-12 flex items-center justify-between px-4 border-b border-slate-800/60"
        style={{ background: 'rgba(10,15,30,0.95)', backdropFilter: 'blur(12px)' }}>

        {/* Brand */}
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <span className="text-sm font-bold text-white">SecureComm</span>
          <span className="text-[10px] text-slate-600 font-mono hidden sm:block">E2EE · ECDH · AES-256-GCM · ECDSA</span>
        </div>

        {/* Tab switcher */}
        <div className="flex bg-slate-800/60 rounded-lg p-0.5 gap-0.5">
          {[
            { id: 'chat',      Icon: MessageSquare,    label: 'Chat' },
            { id: 'dashboard', Icon: LayoutDashboard,  label: 'Security Dashboard' },
          ].map(({ id, Icon, label }) => (
            <button key={id} onClick={() => setPage(id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                page === id
                  ? 'bg-emerald-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-700/60'
              }`}>
              <Icon className="w-3.5 h-3.5" /> {label}
            </button>
          ))}
        </div>

        {/* User + logout */}
        <div className="flex items-center gap-2">
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-800/60 border border-slate-700/40">
            <div className="w-5 h-5 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold text-[10px]">
              {username.charAt(0).toUpperCase()}
            </div>
            <span className="text-xs text-slate-300">{username}</span>
          </div>
          <button onClick={onLogout}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-all border border-transparent hover:border-red-500/20">
            <LogOut className="w-3.5 h-3.5" /> Logout
          </button>
        </div>
      </div>

      {/* Page content */}
      <div className="flex-1 overflow-hidden flex flex-col min-h-0">
        {page === 'chat'
          ? <ChatApp
              token={token}
              username={username}
              onLogout={onLogout}
              embedded
              keysPregenerated={keysPregenerated}
              serverKeyCert={serverKeyCert}
            />
          : <Dashboard token={token} />
        }
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Root
// ─────────────────────────────────────────────────────────────

export default function App() {
  const [auth, setAuth] = useState({ token: null, username: null, keys: null, serverKeyCert: null });
  const clearAuth = () => setAuth({ token: null, username: null, keys: null, serverKeyCert: null });
  return auth.token
    ? <AppShell
        token={auth.token}
        username={auth.username}
        keysPregenerated={auth.keys}
        serverKeyCert={auth.serverKeyCert}
        onLogout={clearAuth}
      />
    : <AuthScreen onAuthenticated={(token, username, keys, serverKeyCert) =>
        setAuth({ token, username, keys, serverKeyCert })} />;
}
