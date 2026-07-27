// GLOBAL STATE
const state = {
  totalReqs: 0, blockedIPs: {}, threats: 0, hmacFails: 0,
  requestLog: [], securityLog: [], timeline: [],
  ipCounters: {}, nginxBucket: 0, startTime: Date.now(),
  attacksBlocked: 0, uniqueIPs: new Set(), monitorReqs: [], monitorBlocks: []
};

const IPS = ['45.33.12.8','192.168.1.50','10.0.0.99','203.0.113.5','198.51.100.2','172.16.0.1'];
const PATHS = ['/api/data','/api/login','/api/user','/dashboard','/admin','/config','/.env','/wp-admin','/static/app.js'];
const METHODS = ['GET','GET','GET','POST','POST'];
const UAS = ['Mozilla/5.0 Chrome','python-requests/2.28','curl/7.64','sqlmap/1.6','Mozilla/5.0 Safari'];

const scenarios = [
  {t:'IP changed in transit',d:'Attacker intercepts the signed command and changes ip from 1.2.3.4 to 8.8.8.8. The payload changes → HMAC recomputed by controller → MISMATCH → 401 returned. iptables never executed.',why:'HMAC digest covers the entire payload. Any byte change produces a totally different 512-bit hash.'},
  {t:'Duration tampered',d:'Attacker changes duration from 3600 to 99999. Even though action and ip are unchanged, the payload string is different → HMAC fails → 401.',why:'sort_keys=True ensures consistent serialisation. Any field change → digest change.'},
  {t:'Forged command',d:'Attacker crafts a fake block command without the secret key. Any signature they guess has 1-in-2^512 chance of matching. Rejected immediately.',why:'Without the secret key, computing a valid HMAC is computationally infeasible.'},
  {t:'Replay attack',d:'Attacker captures a real valid command (HMAC passes!). They replay it 2 minutes later. Timestamp check fires: command_age=120s > 30s limit → 400 stale.',why:'Timestamp is included inside the signed payload, so it cannot be changed. Old commands auto-expire.'}
];

// NAVIGATION
const pageTitles = {
  overview:'Dashboard Overview', layer1:'Layer 1 — Nginx Web Server',
  layer2:'Layer 2 — Request Logger', layer3:'Layer 3 — Threat Detection',
  layer4:'Layer 4 — HMAC-SHA512 Signer', layer5:'Layer 5 — Firewall Controller',
  layer6:'Layer 6 — Security Monitor', 'hmac-lab':'HMAC Lab',
  'attack-sim':'Attack Simulator'
};

function nav(id, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  el.classList.add('active');
  document.getElementById('page-title').textContent = pageTitles[id] || id;
  if (id === 'hmac-lab') { labUpdate(); }
  if (id === 'layer4') { recomputeHmac(); }
}

// CLOCK
function updateClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000); updateClock();

// SIMULATED HMAC (visual only — uses deterministic fake)
function simpleHash(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h;
}

function fakeHmac(key, payload) {
  const combined = key + '|' + payload;
  let result = '';
  const hex = '0123456789abcdef';
  for (let i = 0; i < 128; i++) {
    const h = simpleHash(combined + i);
    result += hex[h % 16];
  }
  return result;
}

// CHARTS
const trafficData = { labels: [], req: [], blocked: [] };
for (let i = 0; i < 20; i++) { trafficData.labels.push(''); trafficData.req.push(0); trafficData.blocked.push(0); }

const trafficChart = new Chart(document.getElementById('traffic-chart'), {
  type: 'line',
  data: {
    labels: trafficData.labels,
    datasets: [
      { label: 'Requests', data: trafficData.req, borderColor: '#3b82f6', backgroundColor: '#3b82f611', fill: true, tension: 0.4, borderWidth: 1.5, pointRadius: 0 },
      { label: 'Blocked', data: trafficData.blocked, borderColor: '#ef4444', backgroundColor: '#ef444411', fill: true, tension: 0.4, borderWidth: 1.5, pointRadius: 0 }
    ]
  },
  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { display: false }, y: { display: true, min: 0, grid: { color: '#1e2d45' }, ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } } } }, animation: false }
});

const monitorChart = new Chart(document.getElementById('monitor-chart'), {
  type: 'bar',
  data: {
    labels: ['1m','2m','3m','4m','5m','6m','7m','8m','9m','10m'],
    datasets: [
      { label: 'Requests', data: Array(10).fill(0), backgroundColor: '#3b82f630', borderColor: '#3b82f6', borderWidth: 1 },
      { label: 'Blocked', data: Array(10).fill(0), backgroundColor: '#ef444430', borderColor: '#ef4444', borderWidth: 1 }
    ]
  },
  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: '#1e2d45' } }, y: { ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: '#1e2d45' }, min: 0 } }, animation: false }
});

const threatChart = new Chart(document.getElementById('threat-chart'), {
  type: 'doughnut',
  data: {
    labels: ['Rate flood', 'Brute force', 'Path scan', 'Bot UA', 'Other'],
    datasets: [{ data: [1,1,1,1,1], backgroundColor: ['#ef4444','#f59e0b','#8b5cf6','#3b82f6','#475569'], borderWidth: 0 }]
  },
  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 }, boxWidth: 10 } } }, animation: false }
});

// LIVE SIMULATION
let tickCount = 0;

function addLog(elId, line, cls='') {
  const el = document.getElementById(elId);
  if (!el) return;
  const div = document.createElement('div');
  div.innerHTML = line;
  if (cls) div.className = cls;
  el.appendChild(div);
  while (el.children.length > 60) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}

function ts() { return new Date().toLocaleTimeString(); }

function simulate() {
  tickCount++;
  const ip = IPS[Math.floor(Math.random() * IPS.length)];
  const path = PATHS[Math.floor(Math.random() * PATHS.length)];
  const method = METHODS[Math.floor(Math.random() * METHODS.length)];
  const sz = Math.floor(Math.random() * 4096);
  const ua = UAS[0];

  state.totalReqs++;
  state.uniqueIPs.add(ip);
  state.ipCounters[ip] = (state.ipCounters[ip] || 0) + 1;

  // Request log
  const isBot = Math.random() > 0.85;
  const isSens = ['/admin','/.env','/config','/wp-admin'].includes(path);
  let logColor = 't-dim';
  if (isSens) logColor = 't-amber';
  if (isBot) logColor = 't-red';

  const badge = state.blockedIPs[ip] ? '<span style="color:var(--red)">[BLOCKED]</span> ' : '';
  addLog('request-log', `<span class="${logColor}">${ts()} ${badge}${ip.padEnd(15)} ${method.padEnd(5)} ${path}</span>`);

  // Update traffic chart
  trafficData.req.push(Math.floor(Math.random() * 20 + 5));
  trafficData.req.shift();
  trafficData.blocked.push(Object.keys(state.blockedIPs).length);
  trafficData.blocked.shift();
  trafficChart.update();

  // Update stats
  document.getElementById('s-total').textContent = state.totalReqs;
  document.getElementById('s-blocked').textContent = Object.keys(state.blockedIPs).length;
  document.getElementById('s-threats').textContent = state.threats;

  // Update Redis panel
  updateRedisPanel();
  updateIPBars();
  updateSQLite(ip, method, path, sz);
  updateMonitor();
  updateFirewallTable();
  updateNginxStats();

  // Occasional threat
  if (tickCount % 15 === 0 || isSens) {
    const threatIp = IPS[Math.floor(Math.random() * 3)];
    if (!state.blockedIPs[threatIp]) {
      state.threats++;
      const reasons = ['Rate threshold exceeded','Brute force detected','Path scan detected','Bot user-agent'];
      const reason = isSens ? 'Path scan detected' : reasons[Math.floor(Math.random() * reasons.length)];
      addSecurityEvent(threatIp, reason);
      if (Math.random() > 0.4) blockIP(threatIp, reason, 45 + Math.floor(Math.random() * 60));
    }
  }

  // Threat badge
  const threatCount = Object.keys(state.blockedIPs).length;
  const badge2 = document.getElementById('threat-badge');
  const sideStatus = document.querySelector('.sidebar-status .status-row:last-child span');
  if (threatCount === 0) { badge2.className='threat-level low'; badge2.textContent='THREAT: LOW'; if(sideStatus) sideStatus.textContent='Threat level · LOW'; }
  else if (threatCount < 3) { badge2.className='threat-level med'; badge2.textContent='THREAT: MEDIUM'; if(sideStatus) sideStatus.textContent='Threat level · MED'; }
  else { badge2.className='threat-level high'; badge2.textContent='THREAT: HIGH'; if(sideStatus) sideStatus.textContent='Threat level · HIGH'; }
}

setInterval(simulate, 700);

// BLOCK / UNBLOCK
const blockTimers = {};

function blockIP(ip, reason, duration) {
  if (state.blockedIPs[ip]) return;
  const expiry = Date.now() + duration * 1000;
  state.blockedIPs[ip] = { reason, expiry, duration };
  state.attacksBlocked++;
  state.timeline.push({ time: ts(), type: 'BLOCK', ip, reason });
  addLog('security-log', `<span class="t-red">${ts()} [BLOCKED] ${ip} — ${reason} (${duration}s)</span>`);
  addLog('full-timeline', `<span class="t-red">${ts()} BLOCK   ${ip.padEnd(15)} ${reason}</span>`);
  addLog('iptables-body-log', '');
  addFwLog(`<span class="t-green">[OK]</span>    iptables -I INPUT -s ${ip} -j DROP`);

  // Show alert ticker
  const ticker = document.getElementById('alert-ticker');
  document.getElementById('ticker-text').textContent = `IP ${ip} BLOCKED — ${reason}`;
  ticker.classList.add('show');
  setTimeout(() => ticker.classList.remove('show'), 5000);

  if (blockTimers[ip]) clearTimeout(blockTimers[ip]);
  blockTimers[ip] = setTimeout(() => unblockIP(ip), duration * 1000);
  updateFirewallTable();
  updateIptablesTable();
}

function unblockIP(ip) {
  delete state.blockedIPs[ip];
  state.timeline.push({ time: ts(), type: 'UNBLOCK', ip });
  addLog('security-log', `<span class="t-green">${ts()} [UNBLOCKED] ${ip} — TTL expired</span>`);
  addLog('full-timeline', `<span class="t-green">${ts()} UNBLOCK ${ip.padEnd(15)} TTL expired</span>`);
  updateFirewallTable();
  updateIptablesTable();
}

function clearAllBlocks() {
  Object.keys(state.blockedIPs).forEach(ip => {
    if (blockTimers[ip]) clearTimeout(blockTimers[ip]);
    unblockIP(ip);
  });
}

// UI UPDATERS
function updateFirewallTable() {
  const tbody = document.getElementById('firewall-table');
  const blocks = Object.entries(state.blockedIPs);
  if (!blocks.length) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text3);padding:20px">No active blocks</td></tr>'; return; }
  tbody.innerHTML = blocks.map(([ip, b], i) => {
    const left = Math.max(0, Math.round((b.expiry - Date.now()) / 1000));
    return `<tr>
      <td>${i+1}</td>
      <td><span class="t-amber">${ip}</span></td>
      <td>${b.reason}</td>
      <td>${b.duration}s</td>
      <td><span class="badge red">${left}s</span></td>
      <td><button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="if(blockTimers['${ip}'])clearTimeout(blockTimers['${ip}']);unblockIP('${ip}')">unblock</button></td>
    </tr>`;
  }).join('');
}

function updateIptablesTable() {
  const tbody = document.getElementById('iptables-body');
  if (!tbody) return;
  const blocks = Object.entries(state.blockedIPs);
  document.getElementById('fw-chain-count').textContent = blocks.length + ' rules';
  if (!blocks.length) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text3);padding:16px">No DROP rules — all traffic ACCEPTED</td></tr>'; return; }
  tbody.innerHTML = blocks.map(([ip, b], i) => {
    const left = Math.max(0, Math.round((b.expiry - Date.now()) / 1000));
    return `<tr>
      <td>${i+1}</td><td><span class="badge red">DROP</span></td>
      <td><span style="color:var(--amber)">${ip}</span></td>
      <td><span class="badge amber">${left}s</span></td>
      <td style="font-size:10px;color:var(--text3)">iptables -I INPUT -s ${ip} -j DROP</td>
      <td><button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="if(blockTimers['${ip}'])clearTimeout(blockTimers['${ip}']);unblockIP('${ip}')">unblock</button></td>
    </tr>`;
  }).join('');
}

setInterval(updateFirewallTable, 1000);
setInterval(updateIptablesTable, 1000);

function updateRedisPanel() {
  const div = document.getElementById('redis-panel');
  if (!div) return;
  const entries = Object.entries(state.ipCounters).sort((a,b)=>b[1]-a[1]).slice(0,6);
  if (!entries.length) return;
  div.innerHTML = entries.map(([ip, cnt]) => {
    const pct = Math.min(cnt / 100 * 100, 100);
    const cls = cnt > 80 ? 'danger' : cnt > 40 ? 'warn' : '';
    return `<div style="display:flex;align-items:center;gap:10px">
      <span style="font-family:var(--mono);font-size:11px;color:var(--text2);min-width:105px">${ip}</span>
      <div class="ip-bar-wrap"><div class="ip-bar ${cls}" style="width:${pct}%"></div></div>
      <span class="badge ${cnt>80?'red':cnt>40?'amber':'blue'}" style="min-width:36px;justify-content:center">${cnt}</span>
      <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">TTL 60s</span>
    </div>`;
  }).join('');
}

function updateIPBars() {
  const div = document.getElementById('ip-bars');
  if (!div) return;
  const entries = Object.entries(state.ipCounters).sort((a,b)=>b[1]-a[1]).slice(0,6);
  div.innerHTML = entries.map(([ip, cnt]) => {
    const pct = Math.min(cnt / 150 * 100, 100);
    const isBlocked = !!state.blockedIPs[ip];
    return `<div style="display:flex;align-items:center;gap:10px">
      <span style="font-family:var(--mono);font-size:11px;color:${isBlocked?'var(--red)':'var(--text2)'};min-width:100px">${ip}</span>
      <div class="ip-bar-wrap"><div class="ip-bar ${isBlocked?'danger':cnt>80?'warn':''}" style="width:${pct}%"></div></div>
      <span style="font-family:var(--mono);font-size:11px;min-width:32px;text-align:right;color:var(--text2)">${cnt}</span>
      ${isBlocked?'<span class="badge red">BLOCKED</span>':''}
    </div>`;
  }).join('');
}

function updateSQLite(ip, method, path, sz) {
  const tbody = document.getElementById('sqlite-body');
  if (!tbody) return;
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${ip}</td><td>${method}</td><td>${path}</td><td>${sz}B</td><td>${ts()}</td>`;
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > 12) tbody.removeChild(tbody.lastChild);
}

function updateMonitor() {
  document.getElementById('m-req').textContent = state.totalReqs;
  document.getElementById('m-att').textContent = state.attacksBlocked;
  document.getElementById('m-ips').textContent = state.uniqueIPs.size;
  const up = Math.floor((Date.now() - state.startTime) / 1000);
  const h = Math.floor(up/3600), m = Math.floor((up%3600)/60), s = up%60;
  document.getElementById('m-up').textContent = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;

  // Update bar chart every 30 ticks
  if (tickCount % 30 === 0) {
    const d = monitorChart.data.datasets;
    d[0].data.push(Math.floor(Math.random()*80+20)); d[0].data.shift();
    d[1].data.push(Object.keys(state.blockedIPs).length * 3); d[1].data.shift();
    monitorChart.update();
    // Threat chart
    threatChart.data.datasets[0].data = [
      Math.floor(Math.random()*10+1), Math.floor(Math.random()*8+1),
      Math.floor(Math.random()*6+1), Math.floor(Math.random()*4+1), Math.floor(Math.random()*3+1)
    ];
    threatChart.update();
  }
}

function updateNginxStats() {
  const el1 = document.getElementById('nginx-rps');
  const el2 = document.getElementById('nginx-blocked');
  const el3 = document.getElementById('nginx-rl');
  if(el1) el1.textContent = Math.floor(Math.random()*15+5);
  if(el2) el2.textContent = Object.keys(state.blockedIPs).length;
  if(el3) el3.textContent = Math.floor(Math.random()*3);
}

function addSecurityEvent(ip, reason) {
  addLog('security-log', `<span class="t-amber">${ts()} [THREAT] ${ip} — ${reason}</span>`);
  addLog('full-timeline', `<span class="t-amber">${ts()} THREAT  ${ip.padEnd(15)} ${reason}</span>`);
}

// NGINX SIMULATOR
let bucket = 0;
function nginxSend(n) {
  const el = document.getElementById('nginx-log');
  for (let i = 0; i < n; i++) {
    bucket++;
    const over = bucket > 20;
    const ip = '45.33.12.8';
    setTimeout(() => {
      if (over || bucket > 20) {
        addLog('nginx-log', `<span class="t-red">${ts()} ${ip} → 429 Too Many Requests (bucket overflow)</span>`);
      } else {
        addLog('nginx-log', `<span class="t-green">${ts()} ${ip} → 200 OK (${bucket}/20)</span>`);
      }
    }, i * 80);
  }
  updateBucket();
  setTimeout(() => { bucket = Math.max(0, bucket - Math.floor(n*0.7)); updateBucket(); }, 500);
}
function updateBucket() {
  const pct = Math.min(bucket / 20 * 100, 100);
  const el = document.getElementById('bucket-fill');
  const pl = document.getElementById('bucket-pct');
  if (!el) return;
  el.style.width = pct + '%';
  el.style.background = pct > 90 ? 'var(--red)' : pct > 60 ? 'var(--amber)' : 'var(--green)';
  pl.textContent = Math.min(bucket, 20) + ' / 20';
  pl.className = 'badge ' + (pct > 90 ? 'red' : pct > 60 ? 'amber' : 'green');
}
function nginxReset() {
  bucket = 0; updateBucket();
  const el = document.getElementById('nginx-log');
  if (el) { el.innerHTML = '<span class="t-dim"># Bucket reset to 0</span>'; }
}

// THREAT DETECTION
function triggerAttack(type) {
  const ip = '99.88.77.66';
  const rules = { rate: 'r-rate', brute: 'r-brute', scan: 'r-scan', bot: 'r-ua' };
  const ruleId = rules[type];
  const card = document.getElementById(ruleId);
  if (card) {
    card.classList.add('firing');
    card.querySelector('span.badge').className = 'badge red';
    card.querySelector('span.badge').textContent = 'FIRING';
    setTimeout(() => { card.classList.remove('firing'); card.querySelector('span.badge').className='badge blue'; card.querySelector('span.badge').textContent='WATCHING'; }, 4000);
  }
  const payload = `{
  "action": "block",
  "ip": "${ip}",
  "duration": 3600,
  "ts": ${Math.floor(Date.now()/1000)}
}`;
  const log = document.getElementById('block-payload');
  if (log) log.innerHTML = `<span class="t-red"># THREAT DETECTED — ${type} attack from ${ip}</span>
<span class="t-amber"># Generating block command...</span>

<span class="t-green">${payload}</span>

<span class="t-dim"># Signing with HMAC-SHA512...</span>
<span class="t-blue">"signature": "${fakeHmac('s3cr3t', payload).substring(0,32)}..."</span>
<span class="t-green"># Command signed → sending to Layer 5</span>`;
  document.getElementById('rules-firing').textContent = '1 firing';
  setTimeout(() => { document.getElementById('rules-firing').textContent = '0 firing'; blockIP(ip, type + ' attack', 60); }, 1500);
}

// HMAC LAYER 4
function recomputeHmac() {
  const payload = document.getElementById('hmac-payload').value;
  const key = document.getElementById('hmac-key').value;
  const digest = fakeHmac(key, payload);
  document.getElementById('hmac-output').textContent = digest;
  const chars = document.getElementById('hmac-chars');
  if (!chars) return;
  chars.innerHTML = digest.substring(0,64).split('').map(c => `<span class="hmac-char match">${c}</span>`).join('');
}

const tamperPayloads = {
  none: '{"action":"block","ip":"1.2.3.4","duration":3600,"ts":1712101234}',
  ip:   '{"action":"block","ip":"8.8.8.8","duration":3600,"ts":1712101234}',
  duration: '{"action":"block","ip":"1.2.3.4","duration":999999,"ts":1712101234}',
  action: '{"action":"allow","ip":"1.2.3.4","duration":3600,"ts":1712101234}'
};

function tamperTest(type) {
  const key = 's3cr3t-256bit-key';
  const origPayload = tamperPayloads.none;
  const testPayload = tamperPayloads[type];
  const origSig = fakeHmac(key, origPayload);
  const testSig = fakeHmac(key, testPayload);
  const match = origSig === testSig;
  const diff = [...origSig].filter((c,i) => c !== testSig[i]).length;
  const el = document.getElementById('tamper-result');
  if (type === 'none') {
    el.innerHTML = `<span class="t-green">Original payload — signature matches ✓</span>
<span class="t-dim">Payload: ${origPayload}</span>
<span class="t-green">Signature: ${origSig.substring(0,32)}...</span>
<span class="t-green">→ Firewall controller ACCEPTS and executes iptables</span>`;
  } else {
    el.innerHTML = `<span class="t-red">TAMPERED payload — HMAC MISMATCH ✗</span>
<span class="t-dim">Modified: ${testPayload}</span>
<span class="t-amber">Original sig: ${origSig.substring(0,32)}...</span>
<span class="t-red">Tampered sig: ${testSig.substring(0,32)}...</span>
<span class="t-red">${diff} of 128 characters differ (${Math.round(diff/128*100)}% changed)</span>
<span class="t-red">→ Firewall controller returns 401 — iptables NOT executed</span>`;
  }
}

// FIREWALL CONTROLLER
function resetPipeline() {
  for (let i = 0; i < 5; i++) {
    const d = document.getElementById('p'+i);
    if (d) { d.className = 'pipe-dot'; }
    const c = document.getElementById('pc'+i);
    if (c) c.className = 'pipe-connector';
  }
}

function addFwLog(line) {
  addLog('fw-log', `<span>${line}</span>`);
}

function sendFwCommand() {
  const ip = document.getElementById('fw-ip').value.trim() || '45.33.12.8';
  const dur = parseInt(document.getElementById('fw-dur').value);
  const hmacMode = document.querySelector('input[name="fw-hmac"]:checked').value;
  const fwLog = document.getElementById('fw-log');
  if (fwLog) fwLog.innerHTML = '';
  resetPipeline();

  const steps = [
    { dot: 'p0', conn: 'pc0', delay: 0, fn: () => {
      addFwLog(`<span class="t-dim">${ts()} POST /firewall/action from 127.0.0.1</span>`);
      addFwLog(`<span class="t-blue">[INFO] Payload received: ip=${ip} dur=${dur}s</span>`);
    }},
    { dot: 'p1', conn: 'pc1', delay: 500, fn: () => {
      if (hmacMode === 'invalid') {
        document.getElementById('p1').className = 'pipe-dot fail';
        addFwLog(`<span class="t-red">[FAIL] HMAC MISMATCH — signature does not match</span>`);
        addFwLog(`<span class="t-red">[ALERT] 401 Unauthorized — payload may be tampered</span>`);
        return false;
      }
      addFwLog(`<span class="t-green">[OK]   HMAC verified successfully</span>`);
      return true;
    }},
    { dot: 'p2', conn: 'pc2', delay: 1000, fn: () => {
      if (hmacMode === 'replay') {
        document.getElementById('p2').className = 'pipe-dot fail';
        addFwLog(`<span class="t-red">[FAIL] TIMESTAMP STALE — command is 120s old (max 30s)</span>`);
        addFwLog(`<span class="t-red">[ALERT] 400 Bad Request — replay attack suspected</span>`);
        return false;
      }
      addFwLog(`<span class="t-green">[OK]   Timestamp fresh (${Math.floor(Math.random()*5)+1}s ago)</span>`);
      return true;
    }},
    { dot: 'p3', conn: 'pc3', delay: 1500, fn: () => {
      addFwLog(`<span class="t-green">[OK]   IP format valid: ${ip}</span>`);
      return true;
    }},
    { dot: 'p4', conn: null, delay: 2000, fn: () => {
      addFwLog(`<span class="t-amber">[EXEC] iptables -I INPUT -s ${ip} -j DROP</span>`);
      addFwLog(`<span class="t-green">[OK]   Rule added — ${ip} now BLOCKED for ${dur}s</span>`);
      addFwLog(`<span class="t-blue">[INFO] threading.Timer(${dur}, unblock) started</span>`);
      addFwLog(`<span class="t-green">[OK]   200 OK returned to threat engine</span>`);
      blockIP(ip, 'Manual block via L5', dur);
      return true;
    }}
  ];

  let stopped = false;
  steps.forEach((step, i) => {
    if (stopped) return;
    setTimeout(() => {
      if (stopped) return;
      const dot = document.getElementById(step.dot);
      if (dot) dot.className = 'pipe-dot active';
      const result = step.fn();
      if (result === false) {
        stopped = true;
        return;
      }
      if (dot) dot.className = 'pipe-dot done';
      if (step.conn) {
        const conn = document.getElementById(step.conn);
        if (conn) conn.className = 'pipe-connector done';
      }
    }, step.delay);
  });
}

// HMAC LAB
function labUpdate() {
  const a = document.getElementById('lab-a').value;
  const b = document.getElementById('lab-b').value;
  const key = 's3cr3t';
  const da = fakeHmac(key, a);
  const db = fakeHmac(key, b);
  document.getElementById('lab-digest-a').textContent = da;
  document.getElementById('lab-digest-b').textContent = db;
  let diff = 0;
  const html = [...da].map((c,i) => {
    const m = c === db[i];
    if (!m) diff++;
    return `<span class="hmac-char ${m?'match':'mismatch'}">${c}</span>`;
  }).join('');
  document.getElementById('lab-compare').innerHTML = html;
  document.getElementById('lab-diff-count').textContent = diff;
  document.getElementById('lab-pct').textContent = Math.round(diff/128*100) + '%';
  document.getElementById('lab-avalanche').textContent = diff > 50 ? 'Strong avalanche!' : diff > 20 ? 'Moderate' : 'Weak (similar inputs)';
}

function showScenario(i) {
  const s = scenarios[i];
  const el = document.getElementById('scenario-detail');
  el.style.display = 'block';
  el.innerHTML = `<span class="t-amber">${s.t}</span>

${s.d}

<span class="t-dim">Why HMAC catches this:</span>
<span class="t-green">${s.why}</span>`;
}

// ATTACK SIMULATOR
const attackConfigs = {
  ddos: {
    name: 'DDoS Flood', ip: '55.66.77.88',
    steps: [
      { layer: 1, delay: 0, status: 'Receiving 500 req/s from 55.66.77.88', color: 'amber' },
      { layer: 2, delay: 600, status: 'Redis counter: rate:55.66.77.88 = 312 in 60s', color: 'amber' },
      { layer: 3, delay: 1200, status: 'THRESHOLD EXCEEDED — generating block command', color: 'red' },
      { layer: 4, delay: 1800, status: 'HMAC-SHA512 signed — command authenticated', color: 'blue' },
      { layer: 5, delay: 2400, status: 'iptables -I INPUT -s 55.66.77.88 -j DROP', color: 'green' }
    ],
    logs: [
      [0, 'red', '[ATTACK] DDoS flood detected from 55.66.77.88'],
      [200, 'amber', '[L1] Nginx rate limiter: 429 to overflow packets'],
      [600, 'amber', '[L2] Redis INCR rate:55.66.77.88 → 312'],
      [1200, 'red', '[L3] Rule fired: rate_threshold > 100 req/min'],
      [1400, 'amber', '[L3] Block command: {"action":"block","ip":"55.66.77.88","duration":3600}'],
      [1800, 'blue', '[L4] HMAC-SHA512 signed: a3f9e1... (128 chars)'],
      [2400, 'green', '[L5] HMAC verified → iptables -I INPUT -s 55.66.77.88 -j DROP'],
      [2600, 'green', '[L5] IP blocked for 3600s — attack neutralised'],
    ]
  },
  brute: {
    name: 'Brute Force Login', ip: '33.44.55.66',
    steps: [
      { layer: 1, delay: 0, status: 'POST /login from 33.44.55.66 (repeated)', color: 'amber' },
      { layer: 2, delay: 600, status: 'Logged: 28 POST /login attempts in 60s', color: 'amber' },
      { layer: 3, delay: 1200, status: 'Brute force rule fired (>10 login attempts)', color: 'red' },
      { layer: 4, delay: 1800, status: 'Block command signed with HMAC-SHA512', color: 'blue' },
      { layer: 5, delay: 2400, status: 'IP dropped at kernel level via iptables', color: 'green' }
    ],
    logs: [
      [0, 'amber', '[ATTACK] Brute force: 28 POST /login from 33.44.55.66'],
      [600, 'amber', '[L2] login:33.44.55.66 counter = 28 (Redis sorted set)'],
      [1200, 'red', '[L3] brute_force rule: 28 > 10 threshold'],
      [1800, 'blue', '[L4] Signed: {"action":"block","ip":"33.44.55.66","duration":1800}'],
      [2400, 'green', '[L5] iptables -I INPUT -s 33.44.55.66 -j DROP'],
      [2600, 'green', '[L5] 33.44.55.66 blocked 1800s — brute force stopped'],
    ]
  },
  scan: {
    name: 'Path Scan', ip: '77.88.99.10',
    steps: [
      { layer: 1, delay: 0, status: 'Requests to /admin, /.env, /wp-admin...', color: 'purple' },
      { layer: 2, delay: 600, status: 'Logged 12 sensitive path accesses', color: 'amber' },
      { layer: 3, delay: 1200, status: 'Path scan pattern detected', color: 'red' },
      { layer: 4, delay: 1800, status: 'Command signed and forwarded', color: 'blue' },
      { layer: 5, delay: 2400, status: 'Scanner blocked at OS level', color: 'green' }
    ],
    logs: [
      [0, 'purple', '[ATTACK] Path scan: /admin /.env /wp-admin /config from 77.88.99.10'],
      [600, 'amber', '[L2] Sensitive paths hit: 12 in 30s'],
      [1200, 'red', '[L3] path_scan rule fired — suspicious endpoint pattern'],
      [1800, 'blue', '[L4] HMAC signed block command'],
      [2400, 'green', '[L5] iptables DROP — scanner neutralised'],
    ]
  }
};

function runAttack(type) {
  const cfg = attackConfigs[type];
  const log = document.getElementById('attack-log');
  log.innerHTML = '';
  document.getElementById('attack-status').textContent = cfg.name;
  document.getElementById('attack-status').className = 'badge red';

  // Reset layer cards
  for (let i = 1; i <= 5; i++) {
    const c = document.getElementById('lr'+i);
    if (c) { c.style.borderColor = ''; c.querySelector('.rule-icon').style.background='var(--bg3)'; }
    const s = document.getElementById('lr'+i+'-status');
    if (s) s.textContent = 'waiting...';
  }

  cfg.steps.forEach(step => {
    setTimeout(() => {
      const card = document.getElementById('lr'+step.layer);
      const status = document.getElementById('lr'+step.layer+'-status');
      const colorMap = { red:'var(--red)', amber:'var(--amber)', blue:'var(--blue)', green:'var(--green)', purple:'var(--purple)' };
      if (card) { card.style.borderColor = colorMap[step.color]; card.querySelector('.rule-icon').style.background = colorMap[step.color]+'22'; card.querySelector('.rule-icon').style.color = colorMap[step.color]; }
      if (status) status.textContent = step.status;
    }, step.delay);
  });

  cfg.logs.forEach(([delay, color, msg]) => {
    setTimeout(() => {
      addLog('attack-log', `<span class="t-${color}">${ts()} ${msg}</span>`);
    }, delay);
  });

  setTimeout(() => {
    blockIP(cfg.ip, cfg.name, 120);
    document.getElementById('attack-status').textContent = 'BLOCKED';
    document.getElementById('attack-status').className = 'badge green';
  }, 2800);
}

// INIT
window.addEventListener('load', () => {
  labUpdate();
  recomputeHmac();
  addLog('request-log', '<span class="t-dim"># NetGuard request logger started — monitoring all endpoints</span>');
  addLog('security-log', '<span class="t-dim"># Security event monitor active — HMAC-SHA512 authentication enabled</span>');
  addLog('fw-log', '<span class="t-dim"># Firewall controller ready on 127.0.0.1:5001</span>');
  addLog('full-timeline', '<span class="t-green">' + ts() + ' [START]  NetGuard security system initialised</span>');
});
