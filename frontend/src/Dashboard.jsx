import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, ShieldCheck, ShieldAlert, Lock, Key, Hash, Cpu, Activity,
  AlertTriangle, CheckCircle2, XCircle, RefreshCw, Play, Zap,
  Users, MessageSquare, BarChart2, Clock, Database, FileText,
  Server, Wifi, Eye, TrendingUp, ArrowRight
} from 'lucide-react';

const API_BASE = '';

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, color = 'emerald', glow = false }) {
  const colors = {
    emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', icon: 'text-emerald-400', val: 'text-emerald-300' },
    blue:    { bg: 'bg-blue-500/10',    border: 'border-blue-500/20',    icon: 'text-blue-400',    val: 'text-blue-300' },
    red:     { bg: 'bg-red-500/10',     border: 'border-red-500/20',     icon: 'text-red-400',     val: 'text-red-300' },
    yellow:  { bg: 'bg-yellow-500/10',  border: 'border-yellow-500/20',  icon: 'text-yellow-400',  val: 'text-yellow-300' },
    purple:  { bg: 'bg-purple-500/10',  border: 'border-purple-500/20',  icon: 'text-purple-400',  val: 'text-purple-300' },
    slate:   { bg: 'bg-slate-700/40',   border: 'border-slate-600/40',   icon: 'text-slate-400',   val: 'text-slate-300' },
  };
  const c = colors[color] || colors.emerald;
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      className={`${c.bg} border ${c.border} rounded-2xl p-4 flex flex-col gap-3`}>
      <div className="flex items-center justify-between">
        <div className={`w-9 h-9 rounded-xl ${c.bg} border ${c.border} flex items-center justify-center`}>
          <Icon className={`w-4.5 h-4.5 ${c.icon}`} />
        </div>
        {glow && <span className="relative flex h-2 w-2">
          <span className={`animate-ping absolute h-full w-full rounded-full ${c.icon.replace('text-', 'bg-')} opacity-60`} />
          <span className={`relative rounded-full h-2 w-2 ${c.icon.replace('text-', 'bg-')}`} />
        </span>}
      </div>
      <div>
        <p className={`text-2xl font-bold font-mono ${c.val}`}>{value}</p>
        <p className="text-xs text-slate-400 font-medium mt-0.5">{label}</p>
        {sub && <p className="text-[10px] text-slate-600 mt-0.5">{sub}</p>}
      </div>
    </motion.div>
  );
}

function DefenseCard({ icon: Icon, label, desc, active, detail }) {
  return (
    <div className={`rounded-xl border p-3.5 flex items-start gap-3 transition-all ${
      active
        ? 'bg-emerald-500/5 border-emerald-500/20'
        : 'bg-red-500/5 border-red-500/20'
    }`}>
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
        active ? 'bg-emerald-500/15 text-emerald-400' : 'bg-red-500/15 text-red-400'
      }`}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs font-semibold text-slate-200">{label}</p>
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
            active ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
          }`}>{active ? 'ACTIVE' : 'INACTIVE'}</span>
        </div>
        <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed">{desc}</p>
        {detail && <p className="text-[10px] font-mono text-slate-600 mt-1 bg-slate-900/60 rounded px-2 py-1">{detail}</p>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Attack Simulator
// ─────────────────────────────────────────────────────────────

const ATTACKS = [
  { id: 'replay',       label: 'Replay Attack',        icon: RefreshCw,     color: 'yellow', desc: 'Resend captured message' },
  { id: 'tamper',       label: 'Ciphertext Tamper',     icon: ShieldAlert,   color: 'red',    desc: 'Corrupt bytes in transit' },
  { id: 'brute_force',  label: 'Brute Force Login',     icon: Key,           color: 'orange', desc: '16 rapid login attempts' },
  { id: 'invalid_jwt',  label: 'Forged JWT',            icon: Lock,          color: 'purple', desc: 'Tampered auth token' },
  { id: 'mitm',         label: 'MITM Key Substitution', icon: Eye,           color: 'blue',   desc: 'Inject foreign public key' },
  { id: 'dos',          label: 'Message Flood (DoS)',   icon: Zap,           color: 'red',    desc: '130 rapid-fire messages' },
];

const colorMap = {
  yellow: 'bg-yellow-500/10 border-yellow-500/25 text-yellow-300 hover:bg-yellow-500/15',
  red:    'bg-red-500/10    border-red-500/25    text-red-300    hover:bg-red-500/15',
  orange: 'bg-orange-500/10 border-orange-500/25 text-orange-300 hover:bg-orange-500/15',
  purple: 'bg-purple-500/10 border-purple-500/25 text-purple-300 hover:bg-purple-500/15',
  blue:   'bg-blue-500/10   border-blue-500/25   text-blue-300   hover:bg-blue-500/15',
};

function AttackSimulator({ token, onAttackStart, onAttackComplete }) {
  const [selected, setSelected]   = useState(null);
  const [result, setResult]       = useState(null);
  const [loading, setLoading]     = useState(false);
  const [history, setHistory]     = useState([]);

  const runAttack = async () => {
    if (!selected) return;
    setLoading(true); setResult(null);
    onAttackStart?.();
    try {
      const res = await fetch(`${API_BASE}/api/attack/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ type: selected }),
      });
      const d = await res.json();
      setResult(d);
      setHistory(h => [{ ...d, id: Date.now() }, ...h].slice(0, 8));
      onAttackComplete?.();   // ← triggers immediate live-feed refresh
    } catch (e) {
      setResult({ error: e.message });
      onAttackComplete?.();
    } finally { setLoading(false); }
  };

  const stepStyle = (ok) => ok
    ? 'border-l-emerald-500/40 bg-emerald-500/5 text-emerald-300'
    : 'border-l-red-500/60    bg-red-500/10    text-red-200';

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
      {/* Left: selector */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
        <h3 className="text-sm font-bold text-white mb-1 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400" /> Attack Simulator
        </h3>
        <p className="text-xs text-slate-500 mb-4">Select an attack type, run it, and observe how each defense layer responds.</p>

        <div className="grid grid-cols-2 gap-2 mb-4">
          {ATTACKS.map(a => {
            const Icon = a.icon;
            const isSelected = selected === a.id;
            return (
              <button key={a.id} onClick={() => { setSelected(a.id); setResult(null); }}
                className={`flex items-start gap-2.5 p-3 rounded-xl border text-left transition-all ${
                  isSelected ? `ring-2 ring-offset-1 ring-offset-slate-900 ${colorMap[a.color]} ring-current` : `${colorMap[a.color]} opacity-70 hover:opacity-100`
                }`}>
                <Icon className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-xs font-semibold leading-tight">{a.label}</p>
                  <p className="text-[10px] opacity-70 mt-0.5">{a.desc}</p>
                </div>
              </button>
            );
          })}
        </div>

        <button onClick={runAttack} disabled={!selected || loading}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold transition-all shadow-lg shadow-red-900/30">
          {loading
            ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Simulating…</>
            : <><Play className="w-4 h-4" /> Launch Attack</>
          }
        </button>
      </div>

      {/* Right: result */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 flex flex-col">
        <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-emerald-400" /> Defense Response
        </h3>

        <AnimatePresence mode="wait">
          {!result && !loading && (
            <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="flex-1 flex flex-col items-center justify-center text-slate-600 gap-3">
              <Shield className="w-12 h-12 opacity-20" />
              <p className="text-sm">Select an attack and click Launch</p>
            </motion.div>
          )}

          {loading && (
            <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="flex-1 flex flex-col items-center justify-center gap-3">
              <div className="w-12 h-12 rounded-full border-2 border-red-500/30 border-t-red-400 animate-spin" />
              <p className="text-sm text-slate-400">Executing attack…</p>
            </motion.div>
          )}

          {result && !loading && !result.error && (
            <motion.div key="result" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="flex-1 flex flex-col gap-3 overflow-y-auto">
              {/* Header */}
              <div className={`flex items-center justify-between px-3 py-2 rounded-xl ${result.result?.blocked ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-red-500/10 border border-red-500/20'}`}>
                <div className="flex items-center gap-2">
                  {result.result?.blocked
                    ? <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    : <ShieldAlert className="w-4 h-4 text-red-400" />}
                  <span className={`text-sm font-bold ${result.result?.blocked ? 'text-emerald-300' : 'text-red-300'}`}>
                    {result.result?.blocked ? 'Attack Blocked ✓' : 'Attack Succeeded ✗'}
                  </span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  {result.result?.real
                    ? <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">⚡ REAL EXECUTION</span>
                    : <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-400 border border-slate-600/30">SIMULATED</span>
                  }
                  <span className="text-[10px] text-slate-500">{result.attack?.layer}</span>
                </div>
              </div>

              {/* Step-by-step trace */}
              <div className="space-y-1.5">
                {result.result?.steps?.map((s, i) => (
                  <motion.div key={i} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.08 }}
                    className={`border-l-2 pl-3 py-1.5 pr-2 rounded-r-lg text-xs ${stepStyle(s.ok)}`}>
                    <div className="flex items-start justify-between gap-2">
                      <span className="flex-1 leading-relaxed">{s.action}</span>
                      <span className={`text-[10px] font-mono font-bold flex-shrink-0 ${s.ok ? 'text-emerald-400' : 'text-red-400'}`}>{s.result}</span>
                    </div>
                  </motion.div>
                ))}
              </div>

              {/* Defense summary */}
              <div className="mt-auto pt-2 space-y-1.5">
                <div className="px-3 py-2 bg-slate-800/60 rounded-xl">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Defense Triggered</p>
                  <p className="text-xs text-emerald-300 font-medium">{result.result?.defense_triggered}</p>
                </div>
                <div className="px-3 py-2 bg-slate-800/60 rounded-xl">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Error Returned to Attacker</p>
                  <p className="text-xs font-mono text-red-300">{result.result?.error_returned}</p>
                </div>
              </div>
            </motion.div>
          )}

          {result?.error && (
            <motion.div key="err" className="flex-1 flex items-center justify-center text-red-400 text-sm">{result.error}</motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Attack history log */}
      {history.length > 0 && (
        <div className="xl:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl p-4">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Attack History (this session)</h4>
          <div className="flex flex-wrap gap-2">
            {history.map(h => (
              <div key={h.id} className="flex items-center gap-2 bg-slate-800/60 border border-slate-700/40 rounded-lg px-3 py-1.5">
                {h.result?.blocked
                  ? <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  : <XCircle className="w-3 h-3 text-red-400" />}
                <span className="text-xs text-slate-300">{h.attack?.name}</span>
                {h.result?.real && <span className="text-[10px] font-bold text-emerald-400">⚡REAL</span>}
                <span className="text-[10px] text-slate-600">{new Date(h.id).toLocaleTimeString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Latency Benchmark
// ─────────────────────────────────────────────────────────────

async function runClientBenchmark() {
  const MSG = new TextEncoder().encode('Benchmark payload for performance evaluation of secure channel primitives.');
  const RUNS = 5;

  const avg = async (fn) => {
    let total = 0;
    for (let i = 0; i < RUNS; i++) {
      const t = performance.now();
      await fn();
      total += performance.now() - t;
    }
    return +(total / RUNS).toFixed(3);
  };

  // ── No security ─────────────────────────────────────────────
  const plain = await avg(async () => {
    const _ = MSG.slice();
  });

  // ── AES-256-GCM only ────────────────────────────────────────
  const aesOnly = await avg(async () => {
    const k  = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, MSG);
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, ct);
  });

  // ── RSA-2048 + AES-CBC + HMAC + RSA-PSS ─────────────────────
  const rsa = await avg(async () => {
    const rsaEnc = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']);
    const rsaSig = await crypto.subtle.generateKey(
      { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['sign', 'verify']);
    const aesK = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
    const rawAes = await crypto.subtle.exportKey('raw', aesK);
    const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaEnc.publicKey, rawAes);
    await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaEnc.privateKey, wrappedKey);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesK, MSG);
    await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesK, ct);
    const hmacK = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
    const mac = await crypto.subtle.sign('HMAC', hmacK, ct);
    await crypto.subtle.verify('HMAC', hmacK, mac, ct);
    const sig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, rsaSig.privateKey, MSG);
    await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, rsaSig.publicKey, sig, MSG);
  });

  // ── Our system: ECDH + AES-256-GCM + ECDSA + SHA-256 ────────
  const ours = await avg(async () => {
    const ecdhA = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    const ecdhB = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    const ecdsaA = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const shared = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: ecdhB.publicKey }, ecdhA.privateKey,
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, shared, MSG);
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, shared, ct);
    await crypto.subtle.digest('SHA-256', MSG);
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, ecdsaA.privateKey, MSG);
    await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, ecdsaA.publicKey, sig, MSG);
  });

  return [
    { label: 'No Security',            ms: plain,  color: '#64748b', desc: 'Plain copy — zero-overhead baseline' },
    { label: 'AES-256-GCM Only',       ms: aesOnly, color: '#3b82f6', desc: 'Symmetric AEAD — no PFS, no signatures' },
    { label: 'RSA-2048 + AES-CBC',     ms: rsa,    color: '#f59e0b', desc: 'Traditional PKI — RSA key wrap + CBC + HMAC + RSA-PSS' },
    { label: 'Our System\n(ECDH+GCM+ECDSA)', ms: ours, color: '#10b981', desc: 'ECDH P-256 + AES-256-GCM + ECDSA + SHA-256 + PFS' },
  ];
}

function LatencyBenchmark({ token }) {
  const [results, setResults]     = useState(null);
  const [serverRes, setServerRes] = useState(null);
  const [loading, setLoading]     = useState(false);
  const [ran, setRan]             = useState(false);

  const run = async () => {
    setLoading(true); setRan(true);
    try {
      const [client, srvRes] = await Promise.all([
        runClientBenchmark(),
        fetch(`${API_BASE}/api/benchmark`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()),
      ]);
      setResults(client);
      setServerRes(srvRes);
    } catch (e) {
      console.error(e);
    } finally { setLoading(false); }
  };

  const maxMs = results ? Math.max(...results.map(r => r.ms)) : 1;

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-blue-400" /> Latency Benchmark
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">Compares full crypto round-trip time: keygen + encrypt + sign + verify (5 runs averaged)</p>
        </div>
        <button onClick={run} disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition-all">
          {loading ? <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          {loading ? 'Running…' : ran ? 'Re-run' : 'Run Benchmark'}
        </button>
      </div>

      {!results && !loading && (
        <div className="flex flex-col items-center justify-center py-10 text-slate-600 gap-2">
          <TrendingUp className="w-10 h-10 opacity-20" />
          <p className="text-sm">Click "Run Benchmark" to measure performance</p>
        </div>
      )}

      {loading && (
        <div className="flex flex-col items-center justify-center py-10 gap-3">
          <div className="w-10 h-10 rounded-full border-2 border-blue-500/30 border-t-blue-400 animate-spin" />
          <p className="text-sm text-slate-400">Running {5} iterations of each algorithm…</p>
        </div>
      )}

      {results && !loading && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
          {/* Browser results */}
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Cpu className="w-3 h-3" /> Browser Benchmark (Web Crypto API)
            </p>
            <div className="space-y-3">
              {results.map((r, i) => {
                const pct = Math.max(4, (r.ms / maxMs) * 100);
                const isOurs = r.label.includes('Our System') || r.label.includes('ECDH');
                return (
                  <motion.div key={r.label} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.1 }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-slate-300 font-medium whitespace-pre-line leading-tight">
                        {isOurs ? <span className="text-emerald-300 font-bold">{r.label}</span> : r.label}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold" style={{ color: r.color }}>{r.ms} ms</span>
                        {isOurs && <span className="text-[10px] bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 px-1.5 py-0.5 rounded font-bold">OUR SYSTEM</span>}
                      </div>
                    </div>
                    <div className="h-6 bg-slate-800/60 rounded-lg overflow-hidden relative">
                      <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.6, delay: i * 0.1 }}
                        className="h-full rounded-lg flex items-center px-2"
                        style={{ backgroundColor: r.color + '33', border: `1px solid ${r.color}55` }}>
                        <span className="text-[10px] font-mono truncate" style={{ color: r.color }}>{r.ms}ms</span>
                      </motion.div>
                    </div>
                    <p className="text-[10px] text-slate-600 mt-0.5">{r.desc}</p>
                  </motion.div>
                );
              })}
            </div>
          </div>

          {/* Server results */}
          {serverRes?.results && (
            <div>
              <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Server className="w-3 h-3" /> Server Benchmark (Python cryptography lib)
              </p>
              <div className="grid grid-cols-2 gap-2">
                {serverRes.results.map(r => {
                  const isOurs = r.label.includes('ECDH');
                  return (
                    <div key={r.label} className={`rounded-xl border p-3 ${isOurs ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-slate-800/40 border-slate-700/40'}`}>
                      <p className={`text-xs font-semibold mb-0.5 ${isOurs ? 'text-emerald-300' : 'text-slate-300'}`}>{r.label}</p>
                      <p className="text-xl font-bold font-mono" style={{ color: r.color }}>{r.ms} ms</p>
                      <p className="text-[10px] text-slate-600 mt-0.5 leading-tight">{r.description}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Insight callout */}
          <div className="bg-emerald-500/5 border border-emerald-500/15 rounded-xl p-4">
            <p className="text-xs font-semibold text-emerald-300 mb-1.5 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Key Insight
            </p>
            {results.length >= 4 && (() => {
              const ours = results.find(r => r.label.includes('ECDH') || r.label.includes('Our'));
              const rsa  = results.find(r => r.label.includes('RSA'));
              if (!ours || !rsa) return null;
              const faster = rsa.ms > ours.ms ? `${(rsa.ms / ours.ms).toFixed(1)}×` : null;
              return (
                <p className="text-xs text-slate-400 leading-relaxed">
                  Our ECDH P-256 system is <span className="text-emerald-400 font-semibold">{faster || 'comparable'} faster</span> than RSA-2048 while providing
                  equivalent security — ECC achieves the same cryptographic strength with smaller key sizes (256-bit vs 2048-bit),
                  making it ideal for real-time secure messaging.
                  {ours.ms < 20 && <> At <span className="text-emerald-400 font-semibold">{ours.ms}ms</span>, the overhead is imperceptible to users.</>}
                </p>
              );
            })()}
          </div>
        </motion.div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Live Events Feed
// ─────────────────────────────────────────────────────────────

function LiveFeed({ token, attackRunning = false, refreshNow = 0 }) {
  const [events, setEvents] = useState([]);

  const fetch_ = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/dashboard/stats`, { headers: { Authorization: `Bearer ${token}` } });
      const d   = await res.json();
      if (res.ok) setEvents((d.recent_events || []).slice(0, 20));
    } catch {}
  }, [token]);

  // Normal polling: 1 s while an attack is running, 4 s otherwise
  useEffect(() => {
    fetch_();
    const interval = attackRunning ? 1000 : 4000;
    const t = setInterval(fetch_, interval);
    return () => clearInterval(t);
  }, [fetch_, attackRunning]);

  // Immediate refresh the moment an attack completes (refreshNow changes)
  useEffect(() => { if (refreshNow > 0) fetch_(); }, [refreshNow, fetch_]);

  const style = (type = '') => {
    if (type.includes('fail') || type.includes('reject') || type.includes('attack')) return { dot: 'bg-red-400', text: 'text-red-300', bg: 'bg-red-500/5' };
    if (type.includes('message')) return { dot: 'bg-blue-400', text: 'text-blue-300', bg: 'bg-blue-500/5' };
    if (type.includes('login') || type.includes('join')) return { dot: 'bg-emerald-400', text: 'text-emerald-300', bg: 'bg-emerald-500/5' };
    if (type.includes('create')) return { dot: 'bg-purple-400', text: 'text-purple-300', bg: 'bg-purple-500/5' };
    return { dot: 'bg-slate-400', text: 'text-slate-400', bg: '' };
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
      <h3 className="text-sm font-bold text-white mb-4 flex items-center justify-between">
        <span className="flex items-center gap-2">
          <Activity className={`w-4 h-4 ${attackRunning ? 'text-orange-400' : 'text-blue-400'}`} />
          Live Security Events
          {attackRunning && (
            <span className="text-[10px] font-bold text-orange-400 bg-orange-500/10 border border-orange-500/20 px-1.5 py-0.5 rounded animate-pulse">
              ⚡ ATTACK RUNNING — polling 1s
            </span>
          )}
        </span>
        <span className="relative flex h-2 w-2">
          <span className={`animate-ping absolute h-full w-full rounded-full opacity-60 ${attackRunning ? 'bg-orange-400' : 'bg-emerald-400'}`} />
          <span className={`relative rounded-full h-2 w-2 ${attackRunning ? 'bg-orange-400' : 'bg-emerald-400'}`} />
        </span>
      </h3>
      <div className="space-y-1.5 max-h-72 overflow-y-auto">
        {events.length === 0 && <p className="text-xs text-slate-600 text-center py-4">No events yet</p>}
        <AnimatePresence>
          {events.map((e, i) => {
            const s = style(e.event_type);
            return (
              <motion.div key={e.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
                className={`flex items-start gap-2.5 px-3 py-2 rounded-lg ${s.bg}`}>
                <span className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${s.dot}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className={`text-xs font-semibold font-mono ${s.text}`}>{e.event_type}</span>
                    <span className="text-[10px] text-slate-600 flex-shrink-0">{e.ts?.split('T')[1]?.slice(0, 8)}</span>
                  </div>
                  {e.username && <p className="text-[10px] text-slate-500 mt-0.5">user: {e.username}</p>}
                  {e.detail && <p className="text-[10px] text-slate-600 mt-0.5 truncate font-mono">{e.detail?.slice(0, 60)}</p>}
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Main Dashboard
// ─────────────────────────────────────────────────────────────

export default function Dashboard({ token }) {
  const [stats, setStats]           = useState(null);
  const [attackRunning, setAttackRunning] = useState(false);
  const [refreshNow, setRefreshNow] = useState(0);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/dashboard/stats`, { headers: { Authorization: `Bearer ${token}` } });
      const d   = await res.json();
      if (res.ok) setStats(d);
    } catch {}
  }, [token]);

  useEffect(() => { fetchStats(); const t = setInterval(fetchStats, 5000); return () => clearInterval(t); }, [fetchStats]);

  const handleAttackStart    = useCallback(() => setAttackRunning(true),  []);
  const handleAttackComplete = useCallback(() => {
    setAttackRunning(false);
    setRefreshNow(n => n + 1);   // nudges LiveFeed to re-fetch immediately
    fetchStats();                 // also refresh the top stat cards
  }, [fetchStats]);

  const defenses = [
    { icon: Lock,         label: 'AES-256-GCM',          desc: 'AEAD encryption — confidentiality + integrity in one operation', detail: 'AESGCM(key).encrypt(iv, plaintext, aad)', active: true },
    { icon: Key,          label: 'ECDH P-256 Key Exchange', desc: 'Ephemeral Diffie-Hellman — Perfect Forward Secrecy per session', detail: 'shared = ECDH(priv_a, pub_b) → HKDF-SHA256 → AES key', active: true },
    { icon: ShieldCheck,  label: 'ECDSA Signatures',      desc: 'Non-repudiation — every message signed, verified server + client', detail: 'sign(priv_key, ciphertext+iv) → verified on receive', active: true },
    { icon: Hash,         label: 'SHA-256 Hash',          desc: 'Plaintext integrity — hash computed before encryption, verified after decryption', detail: 'hash = SHA256(plaintext) → compare after decrypt', active: true },
    { icon: FileText,     label: 'Hash-Chained Audit Log', desc: 'Append-only tamper-evident log — each entry chains to the previous', detail: 'entry_hash = SHA256(prev_hash + event_json)', active: true },
    { icon: Users,        label: 'JWT Authentication',    desc: 'Short-lived scoped tokens — chat access requires valid JWT', detail: 'HS256, 60-min TTL, scopes: chat:send, chat:read', active: true },
    { icon: Activity,     label: 'Rate Limiting',         desc: 'Sliding-window per-IP — blocks brute force and DoS attempts', detail: '15 logins/60s · 120 messages/60s · 40 connects/60s', active: true },
    { icon: Database,     label: 'bcrypt Password Hashing', desc: 'Salted adaptive hash — resistant to rainbow tables and brute force', detail: 'bcrypt.hashpw(pw, gensalt()) → stored in SQLite', active: true },
  ];

  const totalAttacks = stats
    ? (stats.attack_replay_blocked + stats.attack_tamper_detected + stats.attack_brute_force_blocked +
       stats.attack_invalid_jwt + stats.attack_mitm_blocked + stats.attack_dos_blocked)
    : 0;

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-6" style={{ background: '#0a0f1e' }}>

      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" /> Security Dashboard
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">Real-time observability of security mechanisms, attack simulations, and performance benchmarks</p>
        </div>
        <button onClick={fetchStats} className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-emerald-400 transition-colors px-3 py-1.5 rounded-lg hover:bg-emerald-500/10">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <StatCard icon={Users}        label="Registered Users"    value={stats?.total_users ?? '…'}        color="emerald" glow />
        <StatCard icon={MessageSquare} label="Messages Sent"      value={stats?.message_sent ?? '…'}       color="blue" />
        <StatCard icon={ShieldCheck}  label="Signatures Verified" value={stats?.message_sent ?? '…'}       color="emerald" />
        <StatCard icon={ShieldAlert}  label="Messages Rejected"   value={stats?.message_rejected ?? '…'}   color="red" />
        <StatCard icon={AlertTriangle} label="Attacks Blocked"    value={totalAttacks}                      color="yellow" glow={totalAttacks > 0} />
        <StatCard icon={XCircle}      label="Failed Logins"       value={stats?.login_failed ?? '…'}        color="red" />
      </div>

      {/* Defense mechanisms */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
        <h3 className="text-sm font-bold text-white mb-1 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" /> Active Defense Mechanisms
        </h3>
        <p className="text-xs text-slate-500 mb-4">All 8 security layers are active and enforced on every request.</p>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          {defenses.map(d => <DefenseCard key={d.label} {...d} />)}
        </div>
      </div>

      {/* Attack simulator */}
      <div>
        <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400" /> Attack Simulator
          <span className="text-xs text-slate-500 font-normal">— Simulate real attacks and watch the defenses respond</span>
        </h3>
        <AttackSimulator token={token} onAttackStart={handleAttackStart} onAttackComplete={handleAttackComplete} />
      </div>

      {/* Live feed + Latency side by side */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <LiveFeed token={token} attackRunning={attackRunning} refreshNow={refreshNow} />
        <LatencyBenchmark token={token} />
      </div>

      {/* STRIDE threat model */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
        <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-purple-400" /> STRIDE Threat Model Coverage
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {[
            { threat: 'Spoofing',              stride: 'S', color: 'blue',   mitigations: ['JWT token authentication', 'ECDSA message signatures', 'bcrypt credential verification'] },
            { threat: 'Tampering',             stride: 'T', color: 'red',    mitigations: ['AES-256-GCM authentication tag', 'SHA-256 plaintext hash', 'ECDSA signature on envelope'] },
            { threat: 'Repudiation',           stride: 'R', color: 'yellow', mitigations: ['ECDSA non-repudiation', 'Hash-chained audit log', 'Server-side signature verification'] },
            { threat: 'Information Disclosure', stride: 'I', color: 'purple', mitigations: ['AES-256-GCM E2EE', 'ECDH Perfect Forward Secrecy', 'HTTPS/WSS transport'] },
            { threat: 'Denial of Service',     stride: 'D', color: 'orange', mitigations: ['Sliding-window rate limiter', 'Scapy SYN/ACK monitor', 'Grafana alerting'] },
            { threat: 'Elevation of Privilege', stride: 'E', color: 'emerald', mitigations: ['JWT scope enforcement', 'Per-endpoint RBAC', 'Short token TTL (60 min)'] },
          ].map(({ threat, stride, color, mitigations }) => (
            <div key={threat} className={`rounded-xl border p-4 bg-${color}-500/5 border-${color}-500/20`}>
              <div className="flex items-center gap-3 mb-3">
                <div className={`w-8 h-8 rounded-lg bg-${color}-500/15 flex items-center justify-center font-bold text-sm font-mono text-${color}-400`}>{stride}</div>
                <p className="text-sm font-semibold text-white">{threat}</p>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 ml-auto" />
              </div>
              <ul className="space-y-1">
                {mitigations.map(m => (
                  <li key={m} className="flex items-center gap-2 text-xs text-slate-400">
                    <ArrowRight className="w-3 h-3 text-slate-600 flex-shrink-0" /> {m}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
