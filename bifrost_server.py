"""
bifrost_server.py — single-file server.
Serves the Bifrost authenticator UI and wraps the bifrost CLI binary.

Multi-user design
-----------------
The server NEVER stores the shared secret on disk. After a successful DH
key-exchange the hex-encoded secret is returned to the browser, which keeps it
in localStorage. Every TOTP code is computed entirely in the browser using a
pure-JS HMAC-SHA-1 implementation, so no secret ever travels back to the
server after registration.

Usage:
    python bifrost_server.py

Environment variables:
    PORT             HTTP port (default 8000)
    BIFROST_BIN      Path to compiled bifrost binary (default ./bifrost)
    HOST_ORIGIN      Allowed CORS origin (default *)
    LOGIN_SERVER_URL URL of the login server (required in production)
"""

import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json
import urllib.parse

BIFROST_BIN     = os.environ.get("BIFROST_BIN", "./bifrost")
HOST_ORIGIN     = os.environ.get("HOST_ORIGIN", "*")
LOGIN_SERVER_URL = os.environ.get("LOGIN_SERVER_URL", "http://localhost:5000/signup/")
PORT            = int(os.environ.get("PORT", 8000))

# Simple in-memory rate limiter
_rate: dict[str, list[float]] = {}
_rate_lock = threading.Lock()
RATE_LIMIT, RATE_WINDOW = 15, 60

def _ok_rate(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        hits = [t for t in _rate.get(ip, []) if now - t < RATE_WINDOW]
        if len(hits) >= RATE_LIMIT:
            return False
        hits.append(now)
        _rate[ip] = hits
    return True

def run_bifrost(stdin_input: str | None = None) -> tuple[str, str, int]:
    """
    Run the bifrost binary and return (stdout, stderr, returncode).
    The binary is fed the registration PIN via stdin.
    It prints the shared secret hex on a line after "Shared Secret key:".
    """
    cmd = [BIFROST_BIN]
    env = os.environ.copy()
    env["LOGIN_SERVER_URL"] = LOGIN_SERVER_URL
    # Unset SECRET_KEY_FILE so the binary always does a fresh exchange.
    # The binary checks for shared_secret.txt on disk; we point it at a
    # path that will never exist so it always goes through the exchange flow.
    env["SECRET_KEY_FILE"] = "/dev/null/nonexistent"
    try:
        r = subprocess.run(
            cmd,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"bifrost binary not found at '{BIFROST_BIN}'", 1
    except subprocess.TimeoutExpired:
        return "", "bifrost timed out", 1

def parse_shared_secret(stdout: str) -> str | None:
    """
    Extract the shared-secret hex from bifrost stdout.
    The binary prints:
        \nShared Secret key:\n<hex>\n
    """
    lines = stdout.splitlines()
    for i, line in enumerate(lines):
        if "Shared Secret key" in line:
            # The hex value is on the next non-empty line
            for j in range(i + 1, len(lines)):
                candidate = lines[j].strip()
                if candidate:
                    # Validate it looks like hex
                    if all(c in "0123456789abcdefABCDEF" for c in candidate) and len(candidate) > 0:
                        return candidate
    return None

# ── HTML ──────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Bifrost</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Epilogue:wght@400;700;900&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#04050a;
  --surface:#0c0d15;
  --surface2:#13141f;
  --border:rgba(255,255,255,0.06);
  --border2:rgba(255,255,255,0.12);
  --accent:#00e5c3;
  --accent-dim:rgba(0,229,195,0.08);
  --accent-glow:rgba(0,229,195,0.2);
  --warn:#ffb547;
  --red:#ff4f6a;
  --text:#dde2f0;
  --muted:#5a5f78;
  --dim:#2a2d3a;
  --mono:'IBM Plex Mono',monospace;
  --sans:'Epilogue',sans-serif;
  --r:10px;
}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--sans);
  min-height:100vh;
  display:flex;
  flex-direction:column;
  align-items:center;
  padding:2.5rem 1rem 5rem;
}
/* scanline overlay */
body::after{
  content:'';
  position:fixed;
  inset:0;
  background:repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,0.07) 2px,
    rgba(0,0,0,0.07) 4px
  );
  pointer-events:none;
  z-index:999;
}
/* corner grid */
body::before{
  content:'';
  position:fixed;
  inset:0;
  background-image:
    linear-gradient(rgba(0,229,195,0.025) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,229,195,0.025) 1px,transparent 1px);
  background-size:48px 48px;
  pointer-events:none;
  z-index:0;
}
.wrap{position:relative;z-index:1;width:100%;max-width:460px}

/* ── Header ── */
header{
  display:flex;align-items:center;gap:16px;
  margin-bottom:2.5rem;padding-top:0.5rem;
}
.logo-mark{
  font-family:var(--mono);font-size:11px;font-weight:600;
  color:var(--accent);letter-spacing:1px;
  border:1px solid rgba(0,229,195,0.3);
  padding:6px 10px;border-radius:6px;
  background:var(--accent-dim);
  white-space:nowrap;
}
.header-text h1{
  font-size:26px;font-weight:900;
  letter-spacing:-1px;color:#fff;
  line-height:1;
}
.header-text p{
  font-size:12px;font-family:var(--mono);
  color:var(--muted);margin-top:4px;
}
.status-pill{
  display:inline-flex;align-items:center;gap:6px;
  font-size:11px;font-family:var(--mono);
  padding:3px 10px;border-radius:99px;
  border:1px solid var(--border2);
  color:var(--muted);background:var(--surface);
  margin-top:6px;
}
.dot{
  width:6px;height:6px;border-radius:50%;
  background:var(--dim);transition:background 0.4s,box-shadow 0.4s;
}
.dot.ok{background:var(--accent);box-shadow:0 0 6px var(--accent);}
.dot.err{background:var(--red);}

/* ── Cards ── */
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--r);
  padding:1.5rem;
  margin-bottom:0.75rem;
  transition:border-color 0.25s;
}
.card:focus-within,.card:hover{border-color:var(--border2);}
.card.lit{border-color:rgba(0,229,195,0.35);box-shadow:0 0 0 1px var(--accent-glow);}

.row{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;}
.section-label{
  font-family:var(--mono);font-size:10px;
  color:var(--muted);letter-spacing:2px;text-transform:uppercase;
}

/* ── Badges ── */
.badge{
  font-family:var(--mono);font-size:10px;
  padding:2px 8px;border-radius:4px;border:1px solid;
}
.b-green{color:var(--accent);border-color:rgba(0,229,195,0.3);background:var(--accent-dim);}
.b-red{color:var(--red);border-color:rgba(255,79,106,0.3);background:rgba(255,79,106,0.08);}
.b-dim{color:var(--muted);border-color:var(--border);background:transparent;}
.b-warn{color:var(--warn);border-color:rgba(255,181,71,0.3);background:rgba(255,181,71,0.08);}

/* ── Inputs ── */
label{
  display:block;font-size:11px;font-family:var(--mono);
  color:var(--muted);margin-bottom:5px;
}
input[type=text]{
  background:var(--surface2);
  border:1px solid var(--border);border-radius:7px;
  color:var(--text);font-family:var(--mono);font-size:15px;
  padding:10px 14px;width:100%;outline:none;
  transition:border-color 0.2s,box-shadow 0.2s;
  letter-spacing:3px;
}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim);}
input::placeholder{color:var(--dim);letter-spacing:0;}

/* ── Tabs ── */
.tabs{
  display:flex;gap:2px;
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:9px;padding:3px;
  margin-bottom:1rem;
}
.tab{
  flex:1;padding:8px;font-family:var(--sans);font-size:13px;font-weight:700;
  border-radius:7px;cursor:pointer;color:var(--muted);
  border:none;background:transparent;transition:all 0.2s;
}
.tab.on{
  background:var(--surface2);color:var(--text);
  border:1px solid var(--border2);
}

/* ── Buttons ── */
.btn{
  display:inline-flex;align-items:center;gap:7px;
  padding:10px 18px;border-radius:8px;
  font-family:var(--sans);font-size:13px;font-weight:700;
  cursor:pointer;border:1px solid;transition:all 0.15s;
}
.btn:disabled{opacity:0.3;cursor:not-allowed;}
.btn-accent{background:var(--accent);border-color:var(--accent);color:#020408;}
.btn-accent:not(:disabled):hover{filter:brightness(1.1);box-shadow:0 0 12px var(--accent-glow);}
.btn-ghost{background:transparent;border-color:var(--border2);color:var(--muted);}
.btn-ghost:not(:disabled):hover{border-color:var(--accent);color:var(--accent);}
.btn-full{width:100%;justify-content:center;}
.btn-sm{padding:5px 11px;font-size:11px;}

/* ── Steps ── */
.steps{display:flex;flex-direction:column;gap:1rem;}
.step{display:flex;gap:12px;align-items:flex-start;opacity:0.35;transition:opacity 0.3s;}
.step.on{opacity:1;}
.snum{
  width:22px;height:22px;border-radius:50%;
  border:1px solid var(--border2);
  font-size:10px;font-family:var(--mono);font-weight:600;
  display:flex;align-items:center;justify-content:center;
  flex-shrink:0;margin-top:1px;color:var(--muted);
}
.snum.done{background:var(--accent);border-color:var(--accent);color:#020408;}
.snum.active{background:transparent;border-color:var(--accent);color:var(--accent);}
.slabel{font-size:13px;font-weight:700;margin-bottom:3px;}
.shint{font-size:11px;font-family:var(--mono);color:var(--muted);margin-bottom:10px;}

/* ── OTP ── */
.otp-num{
  font-family:var(--mono);font-size:52px;font-weight:600;
  letter-spacing:16px;padding-left:16px;
  text-align:center;padding:1.25rem 0 0.5rem;
  transition:color 0.3s;color:#fff;
}
.otp-num.expiring{color:var(--red);}
.otp-num.fresh{color:var(--accent);}
.ptrack{height:2px;background:var(--dim);border-radius:99px;margin:0.75rem 0 0.5rem;overflow:hidden;}
.pfill{height:100%;border-radius:99px;background:var(--accent);transition:width 1s linear,background 0.4s;}
.otp-foot{display:flex;justify-content:space-between;align-items:center;font-size:11px;font-family:var(--mono);color:var(--muted);}

/* ── Health rows ── */
.hrow{
  display:flex;justify-content:space-between;align-items:center;
  font-size:12px;font-family:var(--mono);
  padding:7px 0;border-bottom:1px solid var(--border);
}
.hrow:last-child{border:none;}
.hrow span:first-child{color:var(--muted);}

/* ── Error ── */
.err{font-size:11px;font-family:var(--mono);color:var(--red);margin-top:8px;display:none;}

/* ── Toast ── */
.toast{
  position:fixed;bottom:2rem;left:50%;
  transform:translateX(-50%) translateY(60px);
  background:var(--surface2);border:1px solid var(--border2);
  border-radius:8px;padding:9px 18px;
  font-size:12px;font-family:var(--mono);color:var(--text);
  opacity:0;transition:all 0.28s;z-index:9999;white-space:nowrap;
}
.toast.show{transform:translateX(-50%) translateY(0);opacity:1;}

/* ── Spinner ── */
.spin{
  width:13px;height:13px;
  border:2px solid rgba(255,255,255,0.12);
  border-top-color:#fff;border-radius:50%;
  animation:sp 0.6s linear infinite;display:inline-block;
}
@keyframes sp{to{transform:rotate(360deg)}}

/* fade-in on load */
.wrap{animation:fi 0.4s ease both;}
@keyframes fi{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="logo-mark">BF//CLI</div>
  <div class="header-text">
    <h1>Bifrost</h1>
    <p>authenticator interface</p>
    <div class="status-pill">
      <span class="dot" id="api-dot"></span>
      <span id="api-status">checking...</span>
    </div>
  </div>
</header>

<div class="tabs">
  <button class="tab on" onclick="showTab('register')" id="tab-register">Register</button>
  <button class="tab" onclick="showTab('otp')" id="tab-otp">Authenticator</button>
  <button class="tab" onclick="showTab('status')" id="tab-status">Status</button>
</div>

<!-- ── Register ── -->
<div id="pane-register">
  <div class="card">
    <div class="row"><span class="section-label">key exchange</span><span class="badge b-dim" id="reg-badge">pending</span></div>
    <div class="steps">
      <div class="step on" id="step1">
        <div class="snum active" id="sn1">1</div>
        <div style="flex:1">
          <div class="slabel">Enter server PIN</div>
          <div class="shint">6-digit code from the login server signup page</div>
          <label>PIN</label>
          <input type="text" id="pin" maxlength="6" placeholder="000000" oninput="onPin()" style="max-width:160px;"/>
          <div class="err" id="pin-err"></div>
        </div>
      </div>

      <div class="step" id="step2">
        <div class="snum" id="sn2">2</div>
        <div style="flex:1">
          <div class="slabel">Run bifrost key exchange</div>
          <div class="shint">The server performs DH exchange; your secret is saved locally in this browser</div>
          <button class="btn btn-accent" id="ex-btn" onclick="doExchange()" disabled>
            Exchange keys
          </button>
          <div class="err" id="ex-err"></div>
        </div>
      </div>

      <div class="step" id="step3">
        <div class="snum" id="sn3">3</div>
        <div style="flex:1">
          <div class="slabel">Done — secret saved in browser</div>
          <div class="shint">Switch to Authenticator to generate codes. Your secret never leaves this device.</div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ── OTP ── -->
<div id="pane-otp" style="display:none">
  <div class="card lit">
    <div class="row">
      <span class="section-label">one-time code</span>
      <span class="badge b-green" id="otp-badge">—</span>
    </div>
    <div class="otp-num" id="otp-digits">——————</div>
    <div class="ptrack"><div class="pfill" id="otp-bar" style="width:100%"></div></div>
    <div class="otp-foot">
      <span id="otp-cd">—</span>
      <button class="btn btn-ghost btn-sm" onclick="copyOTP()">copy</button>
    </div>
    <div class="err" id="otp-err" style="margin-top:10px;"></div>
  </div>
  <button class="btn btn-ghost btn-full" onclick="refreshOTP()" style="margin-top:4px;">↺ &nbsp;refresh now</button>
</div>

<!-- ── Status ── -->
<div id="pane-status" style="display:none">
  <div class="card">
    <div class="row"><span class="section-label">server health</span><span class="badge b-dim" id="health-badge">—</span></div>
    <div id="health-rows">
      <div class="hrow"><span>api</span><span id="h-api">—</span></div>
      <div class="hrow"><span>bifrost binary</span><span id="h-bin">—</span></div>
      <div class="hrow"><span>secret (this browser)</span><span id="h-sec">—</span></div>
    </div>
    <button class="btn btn-ghost btn-sm" onclick="checkHealth()" style="margin-top:1rem;">ping again</button>
  </div>
  <div class="card" style="margin-top:0.25rem;">
    <div class="row" style="margin-bottom:0;"><span class="section-label">clear registration</span></div>
    <p style="font-size:12px;font-family:var(--mono);color:var(--muted);margin:0.75rem 0;">
      Removes your secret key from this browser's localStorage. You will need to re-register.
    </p>
    <button class="btn btn-ghost btn-sm" onclick="clearSecret()" style="border-color:rgba(255,79,106,0.3);color:var(--red);">delete secret</button>
    <div class="err" id="clear-err"></div>
  </div>
</div>

</div><!-- .wrap -->

<div class="toast" id="toast"></div>

<script>
// ─────────────────────────────────────────────────────────────
//  Pure-JS TOTP  (RFC 6238 / HMAC-SHA-1)
// ─────────────────────────────────────────────────────────────

// SHA-1 — returns Uint8Array
async function sha1(data){
  return new Uint8Array(await crypto.subtle.digest('SHA-1', data));
}

// HMAC-SHA-1
async function hmacSha1(keyBytes, msgBytes){
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes, {name:'HMAC', hash:'SHA-1'}, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, msgBytes));
}

// Convert hex string → Uint8Array
function hexToBytes(hex){
  const out = new Uint8Array(hex.length / 2);
  for(let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return out;
}

// Big-endian 8-byte encoding of a JS number (safe up to 2^53)
function uint64BE(n){
  const buf = new Uint8Array(8);
  let v = Math.floor(n);
  for(let i = 7; i >= 0; i--){ buf[i] = v & 0xff; v = Math.floor(v / 256); }
  return buf;
}

async function computeTOTP(secretHex){
  const key = hexToBytes(secretHex);
  const timestep = Math.floor(Date.now() / 1000 / 30);
  const msg = uint64BE(timestep);
  const hmac = await hmacSha1(key, msg);
  const offset = hmac[19] & 0x0f;
  const code = (
    ((hmac[offset]   & 0x7f) << 24) |
    ((hmac[offset+1] & 0xff) << 16) |
    ((hmac[offset+2] & 0xff) <<  8) |
     (hmac[offset+3] & 0xff)
  ) % 1000000;
  return String(code).padStart(6, '0');
}

// ─────────────────────────────────────────────────────────────
//  App state
// ─────────────────────────────────────────────────────────────
const LS_KEY = 'bifrost_secret';
let otpTimer = null;
let curOTP   = null;

function loadSecret(){ return localStorage.getItem(LS_KEY); }
function saveSecret(hex){ localStorage.setItem(LS_KEY, hex); }
function deleteSecret(){ localStorage.removeItem(LS_KEY); }

// ─────────────────────────────────────────────────────────────
//  Utils
// ─────────────────────────────────────────────────────────────
function toast(msg, ms=2000){
  const el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  setTimeout(()=>el.classList.remove('show'), ms);
}
function showErr(id, msg){ const e=document.getElementById(id); e.textContent=msg; e.style.display='block'; }
function hideErr(id){ document.getElementById(id).style.display='none'; }

// ─────────────────────────────────────────────────────────────
//  Tabs
// ─────────────────────────────────────────────────────────────
function showTab(t){
  ['register','otp','status'].forEach(p=>{
    document.getElementById('pane-'+p).style.display = p===t ? 'block' : 'none';
    document.getElementById('tab-'+p).classList.toggle('on', p===t);
  });
  if(t==='otp')    startOTP();
  if(t==='status') checkHealth();
}

// ─────────────────────────────────────────────────────────────
//  Health
// ─────────────────────────────────────────────────────────────
async function checkHealth(){
  const dot = document.getElementById('api-dot');
  const st  = document.getElementById('api-status');
  const hb  = document.getElementById('health-badge');
  dot.className='dot'; st.textContent='checking...';
  try{
    const r = await fetch('/health', {signal: AbortSignal.timeout(6000)});
    const d = await r.json();
    dot.className = 'dot ok';
    st.textContent = 'api online';
    hb.className = 'badge b-green'; hb.textContent = 'online';
    document.getElementById('h-api').textContent = '✓ ok';
    document.getElementById('h-bin').innerHTML = d.binary
      ? '<span style="color:var(--accent)">✓ found</span>'
      : '<span style="color:var(--red)">✗ missing</span>';
    // secret lives in the browser, not on the server
    const hasSecret = !!loadSecret();
    document.getElementById('h-sec').innerHTML = hasSecret
      ? '<span style="color:var(--accent)">✓ yes</span>'
      : '<span style="color:var(--muted)">✗ no</span>';
  }catch{
    dot.className = 'dot err'; st.textContent = 'unreachable';
    hb.className = 'badge b-red'; hb.textContent = 'offline';
    document.getElementById('h-api').innerHTML = '<span style="color:var(--red)">✗ offline</span>';
  }
}

// ─────────────────────────────────────────────────────────────
//  Registration — step UI helpers
// ─────────────────────────────────────────────────────────────
function onPin(){
  const v  = document.getElementById('pin').value.trim();
  const ok = /^\d{6}$/.test(v);
  document.getElementById('ex-btn').disabled = !ok;
  setStep(1, ok ? 'done' : 'active');
  if(ok) setStep(2,'active');
}
function setStep(n, s){
  const num  = document.getElementById('sn'+n);
  const step = document.getElementById('step'+n);
  num.className = 'snum' + (s==='done'?' done' : s==='active'?' active':'');
  num.textContent = s==='done' ? '✓' : n;
  step.className  = 'step' + (s!=='' ? ' on' : '');
}

// ─────────────────────────────────────────────────────────────
//  Registration — key exchange
//  Server returns {secret_hex} → saved to localStorage.
//  Secret never travels back to the server after this point.
// ─────────────────────────────────────────────────────────────
async function doExchange(){
  const pin = document.getElementById('pin').value.trim();
  const btn = document.getElementById('ex-btn');
  hideErr('ex-err');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Exchanging...';
  try{
    const r = await fetch('/exchange', {
      method:  'POST',
      headers: {'Content-Type':'application/json'},
      body:    JSON.stringify({pin}),
      signal:  AbortSignal.timeout(20000),
    });
    const d = await r.json();
    if(!r.ok) throw new Error(d.error || 'Exchange failed');
    if(!d.secret_hex) throw new Error('Server did not return a secret');

    // Save the shared secret in this browser only
    saveSecret(d.secret_hex);

    setStep(2,'done'); setStep(3,'active');
    document.getElementById('reg-badge').className = 'badge b-green';
    document.getElementById('reg-badge').textContent = 'registered';
    toast('✓ Key exchange complete — secret saved in browser');
    checkHealth();
  }catch(e){
    showErr('ex-err', e.message);
    setStep(2,'active');
  }
  btn.disabled  = false;
  btn.textContent = 'Exchange keys';
}

// ─────────────────────────────────────────────────────────────
//  OTP — computed entirely in the browser
// ─────────────────────────────────────────────────────────────
async function refreshOTP(){
  hideErr('otp-err');
  const secret = loadSecret();
  if(!secret){
    showErr('otp-err', 'Not registered — complete registration first');
    document.getElementById('otp-digits').textContent = '——————';
    return;
  }
  try{
    curOTP = await computeTOTP(secret);
    const el = document.getElementById('otp-digits');
    el.textContent = curOTP;
    el.classList.add('fresh');
    setTimeout(()=>el.classList.remove('fresh'), 800);
  }catch(e){
    showErr('otp-err', 'Failed to compute OTP: ' + e.message);
    document.getElementById('otp-digits').textContent = '——————';
  }
}

function updateBar(){
  const now = Math.floor(Date.now() / 1000);
  const rem  = 30 - (now % 30);
  const pct  = Math.round((rem / 30) * 100);
  const bar  = document.getElementById('otp-bar');
  bar.style.width      = pct + '%';
  bar.style.background = rem <= 7 ? 'var(--red)' : 'var(--accent)';
  document.getElementById('otp-cd').textContent    = 'expires in ' + rem + 's';
  document.getElementById('otp-badge').textContent = rem + 's';
  const digits = document.getElementById('otp-digits');
  digits.classList.toggle('expiring', rem <= 7);
  // Refresh OTP at the start of each new 30-second window
  if(rem === 30) refreshOTP();
}

function startOTP(){
  if(otpTimer) clearInterval(otpTimer);
  refreshOTP();
  updateBar();
  otpTimer = setInterval(updateBar, 1000);
}

function copyOTP(){
  if(!curOTP) return;
  navigator.clipboard.writeText(curOTP).then(()=>toast('✓ copied'));
}

// ─────────────────────────────────────────────────────────────
//  Clear — browser-only, no server call needed
// ─────────────────────────────────────────────────────────────
function clearSecret(){
  hideErr('clear-err');
  if(!confirm('Delete your secret key from this browser?')) return;
  deleteSecret();
  curOTP = null;
  document.getElementById('otp-digits').textContent = '——————';
  toast('Secret deleted from browser');
  checkHealth();
}

// ─────────────────────────────────────────────────────────────
//  Init — restore registration state from localStorage
// ─────────────────────────────────────────────────────────────
(function init(){
  if(loadSecret()){
    setStep(1,'done'); setStep(2,'done'); setStep(3,'active');
    document.getElementById('reg-badge').className   = 'badge b-green';
    document.getElementById('reg-badge').textContent = 'registered';
  } else {
    setStep(1,'active');
  }
  checkHealth();
})();
</script>
</body>
</html>
"""

# ── Request handler ────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[bifrost] {self.address_string()} {fmt % args}")

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", HOST_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._send_html(HTML)

        elif path == "/health":
            ip = self.client_address[0]
            if not _ok_rate(ip):
                return self._send_json(429, {"error": "rate limit"})
            # Secret lives in the browser — server never has it
            self._send_json(200, {
                "status": "ok",
                "binary": Path(BIFROST_BIN).exists(),
            })

        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/exchange":
            ip = self.client_address[0]
            if not _ok_rate(ip):
                return self._send_json(429, {"error": "rate limit"})
            body = self._read_json()
            pin = str(body.get("pin", "")).strip()
            if not pin or len(pin) != 6 or not pin.isdigit():
                return self._send_json(400, {"error": "Invalid PIN — must be 6 digits"})

            # Run the bifrost binary; feed the PIN via stdin.
            # The binary performs DH with the login server and prints the
            # shared secret hex to stdout. We parse it and return it to
            # the browser — no disk writes.
            stdout, stderr, rc = run_bifrost(stdin_input=pin + "\n")
            if rc != 0:
                return self._send_json(500, {
                    "error": "Key exchange failed",
                    "detail": stderr.strip(),
                })

            secret_hex = parse_shared_secret(stdout)
            if not secret_hex:
                return self._send_json(500, {
                    "error": "Exchange succeeded but could not parse shared secret",
                    "raw": stdout,
                })

            self._send_json(200, {"status": "registered", "secret_hex": secret_hex})

        else:
            self._send_json(404, {"error": "not found"})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[bifrost] server running on http://0.0.0.0:{PORT}")
    print(f"[bifrost] binary  : {BIFROST_BIN}")
    print(f"[bifrost] note    : secrets are stored in each user's browser (localStorage)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[bifrost] shutting down")