// backend/server.js
require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const db      = require("./db");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Data serangan lengkap ────────────────────────────────────────────────────
const ATTACK_DATA = {
  "Brute Force": {
    risk: "High", score: 80,
    ringkasan: "Penyerang mencoba login berulang kali dengan kombinasi username/password yang berbeda secara otomatis hingga berhasil masuk.",
    lokasi_rentan: [
      { file: "routes/auth.js",      baris: "POST /login",          detail: "Tidak ada rate limiting pada endpoint login" },
      { file: "middleware/auth.js",   baris: "validatePassword()",   detail: "Tidak ada lockout setelah percobaan gagal berulang" },
      { file: "config/session.js",    baris: "session timeout",      detail: "Session timeout terlalu panjang" },
    ],
    pencegahan: [
      "Tambahkan rate limiting: max 5 percobaan login per IP per menit",
      "Implementasi account lockout setelah 5 gagal berturut-turut",
      "Aktifkan Two-Factor Authentication (2FA)",
      "Gunakan CAPTCHA pada form login",
      "Log dan monitor semua percobaan login gagal",
    ],
    contoh_kode_aman: `// Contoh rate limiting dengan express-rate-limit\nconst rateLimit = require('express-rate-limit');\nconst loginLimiter = rateLimit({\n  windowMs: 60 * 1000, // 1 menit\n  max: 5,\n  message: 'Terlalu banyak percobaan login'\n});\napp.post('/login', loginLimiter, authController.login);`
  },
  "SQL Injection": {
    risk: "Critical", score: 95,
    ringkasan: "Penyerang menyisipkan perintah SQL berbahaya melalui input form atau URL untuk memanipulasi atau mencuri data dari database.",
    lokasi_rentan: [
      { file: "models/userModel.js",   baris: "getUserByEmail()",     detail: "Query langsung menggunakan string concatenation" },
      { file: "routes/search.js",      baris: "GET /search?q=",       detail: "Parameter query tidak disanitasi sebelum dimasukkan ke SQL" },
      { file: "controllers/auth.js",   baris: "loginUser()",          detail: "Input username/password tidak menggunakan prepared statement" },
    ],
    pencegahan: [
      "Selalu gunakan Prepared Statement / Parameterized Query",
      "Validasi dan sanitasi semua input dari user",
      "Terapkan prinsip least privilege pada akun database",
      "Gunakan ORM seperti Sequelize atau TypeORM",
      "Aktifkan Web Application Firewall (WAF)",
    ],
    contoh_kode_aman: `// BERBAHAYA - jangan lakukan ini:\ndb.query("SELECT * FROM users WHERE email = '" + email + "'");\n\n// AMAN - gunakan prepared statement:\ndb.query("SELECT * FROM users WHERE email = ?", [email]);`
  },
  "XSS Attack": {
    risk: "High", score: 78,
    ringkasan: "Penyerang menyisipkan script berbahaya ke halaman web yang akan dieksekusi di browser korban, memungkinkan pencurian session/cookie.",
    lokasi_rentan: [
      { file: "views/dashboard.html",  baris: "innerHTML =",          detail: "Menggunakan innerHTML langsung tanpa encoding" },
      { file: "routes/comment.js",     baris: "POST /comment",        detail: "Input komentar tidak di-sanitasi sebelum disimpan" },
      { file: "middleware/render.js",  baris: "res.send(userInput)",   detail: "User input langsung di-render ke HTML response" },
    ],
    pencegahan: [
      "Gunakan textContent bukan innerHTML untuk menampilkan data user",
      "Sanitasi input dengan library DOMPurify",
      "Terapkan Content Security Policy (CSP) header",
      "Encode output sebelum ditampilkan ke HTML",
      "Set flag HttpOnly dan Secure pada cookie",
    ],
    contoh_kode_aman: `// BERBAHAYA:\nelement.innerHTML = userInput;\n\n// AMAN:\nelement.textContent = userInput;\n\n// Atau gunakan DOMPurify:\nelement.innerHTML = DOMPurify.sanitize(userInput);\n\n// CSP Header di Express:\napp.use((req, res, next) => {\n  res.setHeader('Content-Security-Policy', "default-src 'self'");\n  next();\n});`
  },
  "Path Traversal": {
    risk: "Critical", score: 90,
    ringkasan: "Penyerang memanipulasi path file dengan karakter '../' untuk mengakses file di luar direktori yang diizinkan, seperti /etc/passwd atau file konfigurasi.",
    lokasi_rentan: [
      { file: "routes/file.js",        baris: "GET /download?file=",  detail: "Parameter file tidak divalidasi, bisa diisi '../../../etc/passwd'" },
      { file: "controllers/upload.js", baris: "readFile(filename)",    detail: "Nama file dari user langsung digunakan tanpa sanitasi" },
      { file: "config/static.js",      baris: "express.static()",     detail: "Direktori static tidak dibatasi dengan benar" },
    ],
    pencegahan: [
      "Validasi path dengan path.resolve() dan pastikan masih di dalam direktori yang diizinkan",
      "Gunakan whitelist untuk nama file yang diizinkan",
      "Jangan gunakan input user langsung sebagai nama file",
      "Set permission direktori yang ketat di server",
      "Gunakan chroot jail untuk isolasi proses",
    ],
    contoh_kode_aman: `const path = require('path');\nconst BASE_DIR = path.resolve('./uploads');\n\napp.get('/download', (req, res) => {\n  const filename = req.query.file;\n  const filePath = path.resolve(BASE_DIR, filename);\n\n  // Pastikan file masih di dalam BASE_DIR\n  if (!filePath.startsWith(BASE_DIR)) {\n    return res.status(403).send('Akses ditolak');\n  }\n  res.sendFile(filePath);\n});`
  },
  "Port Scanning": {
    risk: "Medium", score: 55,
    ringkasan: "Penyerang melakukan scanning untuk menemukan port yang terbuka pada server, sebagai tahap reconnaissance sebelum serangan lebih lanjut.",
    lokasi_rentan: [
      { file: "config/firewall",       baris: "iptables rules",       detail: "Terlalu banyak port terbuka yang tidak diperlukan" },
      { file: "config/nginx.conf",     baris: "server block",         detail: "Port non-standar terekspos ke publik" },
      { file: "docker-compose.yml",    baris: "ports:",               detail: "Port development ter-expose ke jaringan publik" },
    ],
    pencegahan: [
      "Tutup semua port yang tidak diperlukan dengan firewall",
      "Gunakan port knocking untuk akses SSH",
      "Terapkan fail2ban untuk blokir IP yang melakukan scanning",
      "Sembunyikan versi software dari banner service",
      "Gunakan VPN untuk akses internal service",
    ],
    contoh_kode_aman: `# Contoh aturan iptables:\n# Izinkan hanya port yang diperlukan\niptables -A INPUT -p tcp --dport 80 -j ACCEPT\niptables -A INPUT -p tcp --dport 443 -j ACCEPT\niptables -A INPUT -p tcp --dport 22 -j ACCEPT\n# Blokir semua port lainnya\niptables -A INPUT -j DROP\n\n# Fail2ban config untuk port scanning:\n# /etc/fail2ban/jail.local\n[portscan]\nenabled  = true\nfilter   = portscan\nmaxretry = 3\nbantime  = 3600`
  },
};

const riskColor   = { Critical: "#ff4444", High: "#ff8800", Medium: "#ffcc00", Low: "#00ff88" };
const statusColor = { kritis: "#ff4444", waspada: "#ff8800", perhatian: "#ffcc00", aman: "#00ff88" };
const statusIcon  = { kritis: "🔴", waspada: "🟠", perhatian: "🟡", aman: "🟢" };

function analyzeLog(log) {
  const text = log.toLowerCase();
  if (text.includes("union select") || text.includes("or 1=1") || text.includes("drop table") || text.includes("sql"))
    return { ...ATTACK_DATA["SQL Injection"], threat: "SQL Injection" };
  if (text.includes("login failed") || text.includes("authentication failed") || text.includes("invalid password"))
    return { ...ATTACK_DATA["Brute Force"], threat: "Brute Force" };
  if (text.includes("<script") || text.includes("javascript:") || text.includes("onerror="))
    return { ...ATTACK_DATA["XSS Attack"], threat: "XSS Attack" };
  if (text.includes("../") || text.includes("..\\") || text.includes("/etc/passwd"))
    return { ...ATTACK_DATA["Path Traversal"], threat: "Path Traversal" };
  if (text.includes("nmap") || text.includes("port scan") || text.includes("syn scan"))
    return { ...ATTACK_DATA["Port Scanning"], threat: "Port Scanning" };
  return { threat: "Unknown", risk: "Low", score: 20, ringkasan: "Tidak ada pola serangan dikenal.", lokasi_rentan: [], pencegahan: ["Terus monitor aktivitas jaringan."], contoh_kode_aman: "" };
}

function generateAISummary(alerts) {
  if (!alerts || alerts.length === 0)
    return { status: "aman", message: "Tidak ada ancaman terdeteksi saat ini.", recommendations: ["Terus pantau log secara berkala."] };
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const attackTypes = {};
  alerts.forEach(a => {
    counts[a.risk] = (counts[a.risk] || 0) + 1;
    attackTypes[a.attack] = (attackTypes[a.attack] || 0) + 1;
  });
  const topAttack = Object.entries(attackTypes).sort((a, b) => b[1] - a[1])[0];
  let status = "aman";
  if (counts.Critical > 0) status = "kritis";
  else if (counts.High > 0) status = "waspada";
  else if (counts.Medium > 0) status = "perhatian";
  const data = ATTACK_DATA[topAttack[0]];
  const recommendations = data ? data.pencegahan.slice(0, 3) : ["Lakukan review keamanan menyeluruh."];
  return {
    status, topAttack: topAttack[0], counts,
    message: `Terdeteksi ${alerts.length} ancaman. Serangan dominan: ${topAttack[0]} (${topAttack[1]}x). Tingkat risiko tertinggi: ${counts.Critical > 0 ? "CRITICAL" : counts.High > 0 ? "HIGH" : "MEDIUM"}.`,
    recommendations
  };
}

// ─── GET / → Dashboard ────────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  try {
    const [alerts] = await db.query("SELECT * FROM alerts ORDER BY time DESC LIMIT 50");
    const [recent] = await db.query("SELECT * FROM alerts ORDER BY time DESC LIMIT 10");
    const totalAlerts    = alerts.length;
    const criticalAlerts = alerts.filter(a => a.risk === "Critical").length;
    const highAlerts     = alerts.filter(a => a.risk === "High").length;
    const ai             = generateAISummary(recent);
    const recRows        = ai.recommendations.map(r => `<li style="margin:6px 0">⚡ ${r}</li>`).join("");

    const threatRows = alerts.map(a => `
      <tr onclick="selectAlert(${a.id},'${a.attack}','${a.ip}','${a.country}','${a.risk}')"
          style="cursor:pointer" id="row-${a.id}">
        <td><input type="radio" name="sel" value="${a.id}"></td>
        <td>${a.attack}</td><td>${a.ip}</td><td>${a.country}</td>
        <td><span style="color:${riskColor[a.risk]};font-weight:bold">${a.risk}</span></td>
        <td>${new Date(a.time).toLocaleString("id-ID")}</td>
      </tr>`).join("");

    res.send(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>AI-SOC Dashboard</title>
<style>
*{box-sizing:border-box;}
body{background:#0d1117;color:white;font-family:Arial,sans-serif;margin:0;padding:20px;}
h1{color:#00ff88;} h2{color:#c9d1d9;margin-top:28px;}
.cards{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap;}
.card{background:#161b22;padding:20px;border-radius:10px;min-width:160px;}
.card h2{margin:0 0 6px;font-size:2em;color:white;}
table{width:100%;border-collapse:collapse;background:#161b22;margin-top:8px;}
th,td{border:1px solid #30363d;padding:10px 12px;text-align:left;font-size:0.9em;}
th{background:#21262d;} tr:hover{background:#1c2128;}
tr.sel{background:#0d2a1a !important;outline:2px solid #00ff88;}
.panel{margin-top:20px;background:#161b22;padding:20px;border-radius:10px;}
.ai-box{margin-top:20px;background:#161b22;padding:20px;border-radius:10px;border-left:4px solid ${statusColor[ai.status]};}
.ai-status{font-size:1.05em;font-weight:bold;color:${statusColor[ai.status]};margin-bottom:8px;}
.ai-msg{color:#8b949e;margin-bottom:12px;}
.rec-list{list-style:none;padding:0;margin:0;color:#c9d1d9;}
.sel-info{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:14px;margin:12px 0;color:#8b949e;min-height:50px;}
.sel-info.ok{color:#c9d1d9;border-color:#00ff88;}
.btn{padding:10px 24px;cursor:pointer;background:#00ff88;border:none;border-radius:6px;font-weight:bold;color:#000;font-size:0.95em;}
.btn:disabled{background:#2d3748;color:#555;cursor:not-allowed;}
.result{margin-top:16px;display:none;}
.result.show{display:block;}
.section{background:#0d1117;border-radius:8px;padding:16px;margin-top:12px;}
.section h3{margin:0 0 10px;font-size:1em;color:#00ff88;}
.loc-table{width:100%;border-collapse:collapse;font-size:0.85em;}
.loc-table td{padding:7px 10px;border:1px solid #21262d;}
.loc-table tr:nth-child(odd){background:#161b22;}
.loc-table tr:nth-child(even){background:#0d1117;}
pre{background:#161b22;padding:14px;border-radius:6px;font-size:0.82em;overflow-x:auto;color:#79c0ff;line-height:1.6;white-space:pre-wrap;}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.8em;font-weight:bold;}
.score-bar{background:#21262d;border-radius:6px;height:8px;margin-top:6px;}
.score-fill{height:8px;border-radius:6px;transition:width 0.8s;}
#live-dot{display:inline-block;width:8px;height:8px;background:#00ff88;border-radius:50%;margin-right:6px;animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
</style>
</head>
<body>

<h1>🛡️ AI-SOC Dashboard</h1>
<p><span id="live-dot"></span>AI Powered Security Operations Center &nbsp;
  <span style="color:#555;font-size:0.8em" id="last-update">Live monitoring aktif</span></p>

<div class="cards">
  <div class="card" id="c-total"><h2 id="n-total">${totalAlerts}</h2><p>Total Alerts</p></div>
  <div class="card"><h2 style="color:#ff4444" id="n-critical">${criticalAlerts}</h2><p>Critical</p></div>
  <div class="card"><h2 style="color:#ff8800" id="n-high">${highAlerts}</h2><p>High</p></div>
</div>

<h2>🤖 AI Analysis</h2>
<div class="ai-box" id="ai-box">
  <div class="ai-status" id="ai-status">${statusIcon[ai.status]} Status Keamanan: ${ai.status.toUpperCase()}</div>
  <div class="ai-msg" id="ai-msg">${ai.message}</div>
  <b style="color:#c9d1d9">Rekomendasi Tindakan:</b>
  <ul class="rec-list" id="ai-recs">${recRows}</ul>
</div>

<h2>Recent Threats &nbsp;<span style="font-size:0.75em;color:#555" id="tbl-note"></span></h2>
<table>
  <thead><tr>
    <th style="width:36px"></th>
    <th>Attack</th><th>IP Address</th><th>Country</th><th>Risk</th><th>Time</th>
  </tr></thead>
  <tbody id="tbl-body">${threatRows || '<tr><td colspan="6" style="text-align:center;color:#888">Belum ada data</td></tr>'}</tbody>
</table>

<div class="panel">
  <h2 style="margin-top:0">🔍 Analyze Alert</h2>
  <p style="color:#8b949e;margin:0 0 10px">Klik baris di tabel untuk memilih alert, lalu analyze.</p>
  <div class="sel-info" id="sel-info">Belum ada alert dipilih...</div>
  <button class="btn" id="btn-analyze" disabled onclick="doAnalyze()">⚡ Analyze Selected Alert</button>

  <div class="result" id="result">
    <div class="section" id="sec-summary"></div>
    <div class="section" id="sec-lokasi"></div>
    <div class="section" id="sec-pencegahan"></div>
    <div class="section" id="sec-kode"></div>
  </div>
</div>

<script>
// ── State ──────────────────────────────────────────────────────────────────────
let selected = null;
let isAnalyzing = false;
let pollTimer = null;
const COLORS = { Critical:"#ff4444", High:"#ff8800", Medium:"#ffcc00", Low:"#00ff88" };
const STATUS_COLOR = { kritis:"#ff4444", waspada:"#ff8800", perhatian:"#ffcc00", aman:"#00ff88" };
const STATUS_ICON  = { kritis:"🔴", waspada:"🟠", perhatian:"🟡", aman:"🟢" };

// ── Pilih alert dari tabel ─────────────────────────────────────────────────────
function selectAlert(id, attack, ip, country, risk) {
  selected = { id, attack, ip, country, risk };
  document.querySelectorAll("tr").forEach(r => r.classList.remove("sel"));
  const row = document.getElementById("row-" + id);
  if (row) { row.classList.add("sel"); row.querySelector("input[type=radio]").checked = true; }
  const info = document.getElementById("sel-info");
  info.className = "sel-info ok";
  info.innerHTML = \`<b>ID:</b> \${id} &nbsp;|&nbsp; <b>Attack:</b> \${attack} &nbsp;|&nbsp;
    <b>IP:</b> \${ip} &nbsp;|&nbsp; <b>Country:</b> \${country} &nbsp;|&nbsp;
    <b>Risk:</b> <span style="color:\${COLORS[risk]};font-weight:bold">\${risk}</span>\`;
  document.getElementById("btn-analyze").disabled = false;
  document.getElementById("result").className = "result";
}

// ── Analyze ────────────────────────────────────────────────────────────────────
async function doAnalyze() {
  if (!selected || isAnalyzing) return;
  isAnalyzing = true;
  const btn = document.getElementById("btn-analyze");
  btn.disabled = true; btn.textContent = "⏳ Analyzing...";

  try {
    const res  = await fetch("/analyze-alert", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify(selected)
    });
    const d = await res.json();
    const color = COLORS[d.risk] || "#fff";

    // Summary
    document.getElementById("sec-summary").innerHTML = \`
      <h3>📋 Ringkasan Serangan</h3>
      <p style="margin:0 0 8px"><b style="color:\${color}">\${d.threat}</b>
        &nbsp;<span class="badge" style="background:\${color}22;color:\${color}border:1px solid \${color}">\${d.risk}</span></p>
      <p style="color:#8b949e;margin:0 0 10px">\${d.ringkasan}</p>
      <p style="color:#555;font-size:0.85em;margin:0">Risk Score: \${d.score}/100</p>
      <div class="score-bar"><div class="score-fill" style="width:\${d.score}%;background:\${color}"></div></div>\`;

    // Lokasi rentan
    const locRows = (d.lokasi_rentan || []).map(l => \`
      <tr>
        <td style="color:#79c0ff;font-family:monospace">\${l.file}</td>
        <td style="color:#ffab70;font-family:monospace">\${l.baris}</td>
        <td style="color:#8b949e">\${l.detail}</td>
      </tr>\`).join("");
    document.getElementById("sec-lokasi").innerHTML = \`
      <h3>📁 Lokasi Kode yang Rentan</h3>
      <table class="loc-table">
        <thead><tr>
          <th style="color:#555">File</th>
          <th style="color:#555">Fungsi / Endpoint</th>
          <th style="color:#555">Masalah</th>
        </tr></thead>
        <tbody>\${locRows || '<tr><td colspan="3" style="color:#555">Tidak ada lokasi spesifik</td></tr>'}</tbody>
      </table>\`;

    // Pencegahan
    const precRows = (d.pencegahan || []).map((p,i) => \`
      <li style="margin:8px 0;color:#c9d1d9">
        <span style="color:#00ff88;font-weight:bold">\${i+1}.</span> \${p}
      </li>\`).join("");
    document.getElementById("sec-pencegahan").innerHTML = \`
      <h3>🛡️ Solusi Pencegahan</h3>
      <ol style="list-style:none;padding:0;margin:0">\${precRows}</ol>\`;

    // Contoh kode
    document.getElementById("sec-kode").innerHTML = d.contoh_kode_aman ? \`
      <h3>💡 Contoh Kode Aman</h3>
      <pre>\${d.contoh_kode_aman}</pre>\` : "";

    document.getElementById("result").className = "result show";
  } catch(e) {
    console.error(e);
  }

  btn.disabled = false; btn.textContent = "⚡ Analyze Selected Alert";
  isAnalyzing = false;
}

// ── Background polling (TANPA reload halaman) ──────────────────────────────────
async function pollAlerts() {
  if (isAnalyzing) return; // jangan update tabel saat analyze
  try {
    const res  = await fetch("/alerts");
    const data = await res.json();
    if (!Array.isArray(data)) return;

    const RISKC = { Critical:"#ff4444", High:"#ff8800", Medium:"#ffcc00", Low:"#00ff88" };

    // Update cards
    document.getElementById("n-total").textContent    = data.length;
    document.getElementById("n-critical").textContent = data.filter(a=>a.risk==="Critical").length;
    document.getElementById("n-high").textContent     = data.filter(a=>a.risk==="High").length;

    // Update tabel
    const rows = data.slice(0,50).map(a => \`
      <tr onclick="selectAlert(\${a.id},'\${a.attack}','\${a.ip}','\${a.country}','\${a.risk}')"
          style="cursor:pointer" id="row-\${a.id}" class="\${selected&&selected.id===a.id?'sel':''}">
        <td><input type="radio" name="sel" value="\${a.id}" \${selected&&selected.id===a.id?'checked':''}></td>
        <td>\${a.attack}</td><td>\${a.ip}</td><td>\${a.country}</td>
        <td><span style="color:\${RISKC[a.risk]};font-weight:bold">\${a.risk}</span></td>
        <td>\${new Date(a.time).toLocaleString('id-ID')}</td>
      </tr>\`).join("");
    document.getElementById("tbl-body").innerHTML = rows || '<tr><td colspan="6" style="text-align:center;color:#888">Belum ada data</td></tr>';

    // Update AI summary
    const statsRes = await fetch("/ai-summary");
    const ai = await statsRes.json();
    if (ai && ai.status) {
      document.getElementById("ai-box").style.borderLeftColor = STATUS_COLOR[ai.status] || "#555";
      document.getElementById("ai-status").style.color = STATUS_COLOR[ai.status] || "#fff";
      document.getElementById("ai-status").textContent  = (STATUS_ICON[ai.status]||"") + " Status Keamanan: " + ai.status.toUpperCase();
      document.getElementById("ai-msg").textContent     = ai.message;
      document.getElementById("ai-recs").innerHTML      = (ai.recommendations||[]).map(r=>\`<li style="margin:6px 0">⚡ \${r}</li>\`).join("");
    }

    // Timestamp update
    document.getElementById("last-update").textContent = "Update: " + new Date().toLocaleTimeString("id-ID");
  } catch(e) { /* silent */ }
}

// Mulai polling tiap 8 detik
pollAlerts();
setInterval(pollAlerts, 8000);
</script>
</body>
</html>`);
  } catch (err) {
    console.error("DB Error:", err.message);
    res.status(500).send(`<h2 style="color:red">Database Error</h2><p>${err.message}</p>`);
  }
});

// ─── GET /ai-summary → untuk polling ─────────────────────────────────────────
app.get("/ai-summary", async (req, res) => {
  try {
    const [recent] = await db.query("SELECT * FROM alerts ORDER BY time DESC LIMIT 10");
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const attackTypes = {};
    recent.forEach(a => {
      counts[a.risk] = (counts[a.risk] || 0) + 1;
      attackTypes[a.attack] = (attackTypes[a.attack] || 0) + 1;
    });
    if (!Object.keys(attackTypes).length)
      return res.json({ status: "aman", message: "Tidak ada ancaman terdeteksi.", recommendations: ["Terus pantau log secara berkala."] });
    const topAttack = Object.entries(attackTypes).sort((a, b) => b[1] - a[1])[0];
    let status = "aman";
    if (counts.Critical > 0) status = "kritis";
    else if (counts.High > 0) status = "waspada";
    else if (counts.Medium > 0) status = "perhatian";
    const data = ATTACK_DATA[topAttack[0]];
    res.json({
      status,
      message: `Terdeteksi ${recent.length} ancaman. Dominan: ${topAttack[0]} (${topAttack[1]}x). Risk tertinggi: ${counts.Critical > 0 ? "CRITICAL" : counts.High > 0 ? "HIGH" : "MEDIUM"}.`,
      recommendations: data ? data.pencegahan.slice(0, 3) : ["Review keamanan sistem secara menyeluruh."]
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── POST /analyze-alert → Detail analisis dari tabel ────────────────────────
app.post("/analyze-alert", async (req, res) => {
  const { attack, risk } = req.body;
  if (!attack) return res.status(400).json({ error: "Data tidak lengkap" });
  const data = ATTACK_DATA[attack];
  if (data) return res.json({ threat: attack, ...data });
  res.json({ threat: attack, risk: risk || "Low", score: 20, ringkasan: "Jenis serangan tidak dikenal dalam database.", lokasi_rentan: [], pencegahan: ["Monitor aktivitas jaringan secara berkala."], contoh_kode_aman: "" });
});

// ─── POST /analyze → Manual log ───────────────────────────────────────────────
app.post("/analyze", async (req, res) => {
  const log     = req.body.log     || "";
  const ip      = req.body.ip      || "0.0.0.0";
  const country = req.body.country || "Unknown";
  const result  = analyzeLog(log);
  let saved = false;
  if (result.threat !== "Unknown") {
    try {
      await db.query("INSERT INTO alerts (attack, ip, country, risk) VALUES (?, ?, ?, ?)",
        [result.threat, ip, country, result.risk]);
      saved = true;
    } catch (err) { console.error(err.message); }
  }
  const riskC = riskColor[result.risk] || "#555";
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Analysis Result</title>
<style>body{background:#0d1117;color:white;font-family:Arial,sans-serif;padding:30px;}
.box{background:#161b22;padding:25px;border-radius:10px;max-width:620px;border-left:4px solid ${riskC};}
a{color:#00ff88;} pre{background:#0d1117;padding:12px;border-radius:6px;font-size:0.82em;color:#79c0ff;white-space:pre-wrap;overflow-x:auto;}
li{margin:6px 0;color:#c9d1d9;}</style></head><body>
<div class="box">
  <h2>🔎 AI Analysis Result</h2>
  <p><b>Threat:</b> ${result.threat} &nbsp; <b>Risk:</b> <span style="color:${riskC};font-weight:bold">${result.risk}</span> &nbsp; <b>Score:</b> ${result.score}/100</p>
  <p style="color:#8b949e">${result.ringkasan || ""}</p>
  <b>Rekomendasi:</b>
  <ol>${(result.pencegahan || []).map(p => `<li>${p}</li>`).join("")}</ol>
  ${result.contoh_kode_aman ? `<b>Contoh kode aman:</b><pre>${result.contoh_kode_aman}</pre>` : ""}
  <p style="color:${saved ? "#00ff88" : "#888"}">${saved ? "✅ Alert tersimpan ke database" : "ℹ️ Tidak ada ancaman, tidak disimpan"}</p>
  <a href="/">← Back to Dashboard</a>
</div></body></html>`);
});

// ─── POST /api/attack ─────────────────────────────────────────────────────────
app.post("/api/attack", async (req, res) => {
  const { attack, ip, country, risk, log } = req.body;
  let data = { attack, ip: ip || "0.0.0.0", country: country || "Unknown", risk: risk || "Low" };
  if (log) { const r = analyzeLog(log); data.attack = r.threat; data.risk = r.risk; }
  if (!data.attack || data.attack === "Unknown")
    return res.status(400).json({ error: "Tidak ada ancaman terdeteksi" });
  try {
    const [result] = await db.query("INSERT INTO alerts (attack, ip, country, risk) VALUES (?, ?, ?, ?)",
      [data.attack, data.ip, data.country, data.risk]);
    res.status(201).json({ message: "Alert berhasil disimpan", id: result.insertId, data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── GET /alerts ──────────────────────────────────────────────────────────────
app.get("/alerts", async (req, res) => {
  try {
    const [alerts] = await db.query("SELECT * FROM alerts ORDER BY time DESC LIMIT 50");
    res.json(alerts);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/alerts/:id", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM alerts WHERE id = ?", [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Tidak ditemukan" });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/alerts/:id", async (req, res) => {
  try {
    await db.query("DELETE FROM alerts WHERE id = ?", [req.params.id]);
    res.json({ message: "Alert berhasil dihapus" });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/stats", async (req, res) => {
  try {
    const [[{ total }]]    = await db.query("SELECT COUNT(*) as total FROM alerts");
    const [[{ critical }]] = await db.query("SELECT COUNT(*) as critical FROM alerts WHERE risk = 'Critical'");
    const [[{ high }]]     = await db.query("SELECT COUNT(*) as high FROM alerts WHERE risk = 'High'");
    const [[{ today }]]    = await db.query("SELECT COUNT(*) as today FROM alerts WHERE DATE(time) = CURDATE()");
    res.json({ total, critical, high, today });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});