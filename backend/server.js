const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const alerts = [
  {
    id: 1,
    attack: "Brute Force",
    ip: "185.24.55.12",
    country: "Russia",
    risk: "High",
    time: "2026-06-10 22:30"
  },
  {
    id: 2,
    attack: "SQL Injection",
    ip: "45.91.120.10",
    country: "China",
    risk: "Critical",
    time: "2026-06-10 22:35"
  }
];
app.get("/", (req, res) => {
  const totalAlerts = alerts.length;
  const criticalAlerts = alerts.filter(
    a => a.risk === "Critical"
  ).length;

  const highAlerts = alerts.filter(
    a => a.risk === "High"
  ).length;

  const threatRows = alerts.map(alert => `
<tr>
  <td>${alert.attack}</td>
  <td>${alert.ip}</td>
  <td>${alert.country}</td>
  <td>${alert.risk}</td>
  <td>${alert.time}</td>
</tr>
`).join("");

  res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>AI-SOC Dashboard</title>

<style>
body{
  background:#0d1117;
  color:white;
  font-family:Arial,sans-serif;
  margin:0;
  padding:20px;
}

h1{
  color:#00ff88;
}

.cards{
  display:flex;
  gap:20px;
  margin:25px 0;
  flex-wrap:wrap;
}

.card{
  background:#161b22;
  padding:20px;
  border-radius:10px;
  min-width:200px;
}

table{
  width:100%;
  border-collapse:collapse;
  margin-top:20px;
  background:#161b22;
}

th,td{
  border:1px solid #30363d;
  padding:12px;
  text-align:left;
}

th{
  background:#21262d;
}

.analysis{
  margin-top:30px;
  background:#161b22;
  padding:20px;
  border-radius:10px;
}

textarea{
  width:100%;
  background:#0d1117;
  color:white;
  border:1px solid #30363d;
  padding:10px;
  box-sizing:border-box;
}

button{
  padding:10px 20px;
  cursor:pointer;
  margin-top:10px;
  background:#00ff88;
  border:none;
  border-radius:5px;
}
</style>

</head>

<body>

<h1>AI-SOC Dashboard</h1>
<p>AI Powered Security Operations Center</p>

<p style="color:#00ff88;font-weight:bold;">
🟢 SOC Status: Monitoring Active
</p>
<div class="cards">

  <div class="card">
    <h2>${totalAlerts}</h2>
    <p>Total Alerts</p>
  </div>

  <div class="card">
    <h2>${criticalAlerts}</h2>
    <p>Critical Alerts</p>
  </div>

  <div class="card">
    <h2>${highAlerts}</h2>
    <p>High Alerts</p>
  </div>

</div>

<h2>Recent Threats</h2>

<table>
<thead>
<tr>
  <th>Attack</th>
  <th>IP Address</th>
  <th>Country</th>
  <th>Risk</th>
  <th>Time</th>
</tr>
</thead>

  <tbody>
    ${threatRows}
  </tbody>
</table>

<div class="analysis">
  <h2> AI Analysis</h2>

  <p>
    SQL Injection dengan tingkat risiko Critical terdeteksi.
    Direkomendasikan melakukan validasi input,
    prepared statement, dan review log database.
  </p>
</div>

<div class="analysis">
  <h2> Upload Log Analysis</h2>

  <form action="/analyze" method="POST">

    <textarea
      name="log"
      rows="10"
      placeholder="Paste log di sini..."
    ></textarea>

    <br><br>

    <button type="submit">
      Analyze Threat
    </button>

  </form>
</div>

</body>
</html>
  `);
});

app.post("/analyze", (req, res) => {
  const log = (req.body.log || "").toLowerCase();

  let threat = "Unknown";
  let risk = "Low";
  let score = 20;
  let recommendation = "Continue monitoring";

  if (
    log.includes("union select") ||
    log.includes("or 1=1") ||
    log.includes("sql")
  ) {
    threat = "SQL Injection";
    risk = "Critical";
    score = 95;
    recommendation =
      "Block source IP and review database activity.";
  } else if (
    log.includes("login failed") ||
    log.includes("authentication failed")
  ) {
    threat = "Brute Force";
    risk = "High";
    score = 80;
    recommendation =
      "Enable account lockout and review login attempts.";
  }

  res.send(`
    <h1>AI Analysis Result</h1>

    <p><b>Threat:</b> ${threat}</p>
    <p><b>Risk:</b> ${risk}</p>
    <p><b>Risk Score:</b> ${score}/100</p>
    <p><b>Recommendation:</b> ${recommendation}</p>

    <br>

    <a href="/">Back to Dashboard</a>
  `);
});

app.get("/alerts", (req, res) => {
  res.json(alerts);
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});