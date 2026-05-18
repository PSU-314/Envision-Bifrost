"""
bifrost_server.py — single-file server.
Serves the Bifrost authenticator UI and wraps the bifrost CLI binary.

Usage:
    python bifrost_server.py

Environment variables:
    PORT             HTTP port (default 8000)
    BIFROST_BIN      Path to compiled bifrost binary (default ./bifrost)
    SECRET_KEY_PATH  Path to secret.key file (default ./secret.key)
    HOST_ORIGIN      Allowed CORS origin (default *)
"""

import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json
import urllib.parse

BIFROST_BIN = os.environ.get("BIFROST_BIN", "./bifrost")
SECRET_KEY_PATH = os.environ.get("SECRET_KEY_PATH", "./shared_secret.txt")
HOST_ORIGIN = os.environ.get("HOST_ORIGIN", "*")
LOGIN_SERVER_URL = os.environ.get("LOGIN_SERVER_URL", "http://localhost:5000/signup/")
PORT = int(os.environ.get("PORT", 8000))

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

def run_bifrost(stdin_input: str | None = None, extra_args: list[str] | None = None) -> tuple[str, str, int]:
    cmd = [BIFROST_BIN] + (extra_args or [])
    env = os.environ.copy()
    env["LOGIN_SERVER_URL"] = LOGIN_SERVER_URL
    try:
        r = subprocess.run(cmd, input=stdin_input, capture_output=True, text=True, timeout=15, env=env)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"bifrost binary not found at '{BIFROST_BIN}'", 1
    except subprocess.TimeoutExpired:
        return "", "bifrost timed out", 1

def parse_otp(stdout: str) -> tuple[str | None, int | None]:
    otp = expires = None
    for line in stdout.splitlines():
        s = line.strip()
        # matches "Generated OTP: 818692"
        if s.upper().startswith("GENERATED OTP:"):
            candidate = s.split(":", 1)[1].strip()
            if candidate.isdigit() and len(candidate) == 6:
                otp = candidate
        # fallback: bare 6-digit line
        elif s.isdigit() and len(s) == 6:
            otp = s
        # matches "Valid for: 10s"
        if "Valid for:" in line:
            try:
                expires = int(line.split(":")[1].strip().rstrip("s"))
            except ValueError:
                pass
    return otp, expires

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
          <div class="shint">The server runs the bifrost binary with your PIN</div>
          <button class="btn btn-accent" id="ex-btn" onclick="doExchange()" disabled>
            Exchange keys
          </button>
          <div class="err" id="ex-err"></div>
        </div>
      </div>

      <div class="step" id="step3">
        <div class="snum" id="sn3">3</div>
        <div style="flex:1">
          <div class="slabel">Done — secret saved</div>
          <div class="shint">Switch to Authenticator to generate codes</div>
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
  <button class="btn btn-ghost btn-full" onclick="fetchOTP()" style="margin-top:4px;">↺ &nbsp;refresh now</button>
</div>

<!-- ── Status ── -->
<div id="pane-status" style="display:none">
  <div class="card">
    <div class="row"><span class="section-label">server health</span><span class="badge b-dim" id="health-badge">—</span></div>
    <div id="health-rows">
      <div class="hrow"><span>api</span><span id="h-api">—</span></div>
      <div class="hrow"><span>bifrost binary</span><span id="h-bin">—</span></div>
      <div class="hrow"><span>secret registered</span><span id="h-sec">—</span></div>
    </div>
    <button class="btn btn-ghost btn-sm" onclick="checkHealth()" style="margin-top:1rem;">ping again</button>
  </div>
  <div class="card" style="margin-top:0.25rem;">
    <div class="row" style="margin-bottom:0;"><span class="section-label">clear registration</span></div>
    <p style="font-size:12px;font-family:var(--mono);color:var(--muted);margin:0.75rem 0;">
      Deletes <code>secret.key</code> on the server. You will need to re-register.
    </p>
    <button class="btn btn-ghost btn-sm" onclick="clearSecret()" style="border-color:rgba(255,79,106,0.3);color:var(--red);">delete secret</button>
    <div class="err" id="clear-err"></div>
  </div>
</div>

</div><!-- .wrap -->

<div class="toast" id="toast"></div>

<script>
let otpTimer = null;
let curOTP = null;

// ── Utils ──
function toast(msg,ms=2000){
  const el=document.getElementById('toast');
  el.textContent=msg;el.classList.add('show');
  setTimeout(()=>el.classList.remove('show'),ms);
}
function showErr(id,msg){const e=document.getElementById(id);e.textContent=msg;e.style.display='block';}
function hideErr(id){document.getElementById(id).style.display='none';}

// ── Tabs ──
function showTab(t){
  ['register','otp','status'].forEach(p=>{
    document.getElementById('pane-'+p).style.display=p===t?'block':'none';
    document.getElementById('tab-'+p).classList.toggle('on',p===t);
  });
  if(t==='otp') startOTP();
  if(t==='status') checkHealth();
}

// ── Health ──
async function checkHealth(){
  const dot=document.getElementById('api-dot');
  const st=document.getElementById('api-status');
  const hb=document.getElementById('health-badge');
  dot.className='dot';st.textContent='checking...';
  try{
    const r=await fetch('/health',{signal:AbortSignal.timeout(6000)});
    const d=await r.json();
    dot.className='dot ok';
    st.textContent='api online';
    hb.className='badge b-green';hb.textContent='online';
    document.getElementById('h-api').textContent='✓ ok';
    document.getElementById('h-bin').innerHTML=d.binary
      ?'<span style="color:var(--accent)">✓ found</span>'
      :'<span style="color:var(--red)">✗ missing</span>';
    document.getElementById('h-sec').innerHTML=d.secret_registered
      ?'<span style="color:var(--accent)">✓ yes</span>'
      :'<span style="color:var(--muted)">✗ no</span>';
  }catch{
    dot.className='dot err';st.textContent='unreachable';
    hb.className='badge b-red';hb.textContent='offline';
    document.getElementById('h-api').innerHTML='<span style="color:var(--red)">✗ offline</span>';
  }
}

// ── PIN ──
function onPin(){
  const v=document.getElementById('pin').value.trim();
  const ok=/^\d{6}$/.test(v);
  document.getElementById('ex-btn').disabled=!ok;
  setStep(1,ok?'done':'active');
  if(ok)setStep(2,'active');
}
function setStep(n,s){
  const num=document.getElementById('sn'+n);
  const step=document.getElementById('step'+n);
  num.className='snum'+(s==='done'?' done':s==='active'?' active':'');
  num.textContent=s==='done'?'✓':n;
  step.className='step'+(s!==''?' on':'');
}

// ── Exchange ──
async function doExchange(){
  const pin=document.getElementById('pin').value.trim();
  const btn=document.getElementById('ex-btn');
  hideErr('ex-err');
  btn.disabled=true;
  btn.innerHTML='<span class="spin"></span> Exchanging...';
  try{
    const r=await fetch('/exchange',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({pin}),
      signal:AbortSignal.timeout(20000),
    });
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Exchange failed');
    setStep(2,'done');setStep(3,'active');
    document.getElementById('reg-badge').className='badge b-green';
    document.getElementById('reg-badge').textContent='registered';
    toast('✓ Key exchange complete');
    checkHealth();
  }catch(e){
    showErr('ex-err',e.message);
    setStep(2,'active');
  }
  btn.disabled=false;btn.textContent='Exchange keys';
}

// ── OTP ──
async function fetchOTP(){
  hideErr('otp-err');
  try{
    const r=await fetch('/otp',{signal:AbortSignal.timeout(8000)});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Failed');
    curOTP=d.otp;
    const el=document.getElementById('otp-digits');
    el.textContent=curOTP;
    el.classList.add('fresh');
    setTimeout(()=>el.classList.remove('fresh'),800);
  }catch(e){
    showErr('otp-err',e.message);
    document.getElementById('otp-digits').textContent='——————';
  }
}

function updateBar(){
  const now=Math.floor(Date.now()/1000);
  const rem=30-(now%30);
  const pct=Math.round((rem/30)*100);
  const bar=document.getElementById('otp-bar');
  bar.style.width=pct+'%';
  bar.style.background=rem<=7?'var(--red)':'var(--accent)';
  document.getElementById('otp-cd').textContent='expires in '+rem+'s';
  document.getElementById('otp-badge').textContent=rem+'s';
  const digits=document.getElementById('otp-digits');
  digits.classList.toggle('expiring',rem<=7);
  if(rem===30)fetchOTP();
}

function startOTP(){
  if(otpTimer)clearInterval(otpTimer);
  fetchOTP();
  updateBar();
  otpTimer=setInterval(updateBar,1000);
}

function copyOTP(){
  if(!curOTP)return;
  navigator.clipboard.writeText(curOTP).then(()=>toast('✓ copied'));
}

// ── Clear secret ──
async function clearSecret(){
  hideErr('clear-err');
  if(!confirm('Delete secret.key on the server?'))return;
  try{
    const r=await fetch('/clear',{method:'POST'});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error);
    toast('Secret deleted');
    checkHealth();
  }catch(e){showErr('clear-err',e.message);}
}

// init
checkHealth();
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
            self._send_json(200, {
                "status": "ok",
                "binary": Path(BIFROST_BIN).exists(),
                "secret_registered": Path(SECRET_KEY_PATH).exists(),
            })

        elif path == "/otp":
            ip = self.client_address[0]
            if not _ok_rate(ip):
                return self._send_json(429, {"error": "rate limit"})
            if not Path(SECRET_KEY_PATH).exists():
                return self._send_json(400, {"error": "Not registered — complete registration first"})
            stdout, stderr, rc = run_bifrost()
            if rc != 0:
                return self._send_json(500, {"error": "bifrost failed", "detail": stderr.strip()})
            otp, expires = parse_otp(stdout)
            if not otp:
                return self._send_json(500, {"error": "Could not parse OTP", "raw": stdout})
            self._send_json(200, {"otp": otp, "expires_in": expires})

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
            # Pass any extra arg so bifrost treats it as a fresh registration
            stdout, stderr, rc = run_bifrost(stdin_input=pin + "\n", extra_args=["new"])
            if rc != 0:
                return self._send_json(500, {"error": "Key exchange failed", "detail": stderr.strip()})
            otp, _ = parse_otp(stdout)
            if not otp:
                return self._send_json(500, {"error": "Exchange succeeded but no OTP parsed", "raw": stdout})
            self._send_json(200, {"status": "registered", "otp": otp})

        elif path == "/clear":
            try:
                Path(SECRET_KEY_PATH).unlink(missing_ok=True)
                self._send_json(200, {"status": "cleared"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        else:
            self._send_json(404, {"error": "not found"})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[bifrost] server running on http://0.0.0.0:{PORT}")
    print(f"[bifrost] binary  : {BIFROST_BIN}")
    print(f"[bifrost] secret  : {SECRET_KEY_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[bifrost] shutting down")
