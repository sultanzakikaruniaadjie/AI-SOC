const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

const alerts = [
  {
    id: 1,
    attack: "Brute Force",
    ip: "185.24.55.12",
    risk: "High"
  },
  {
    id: 2,
    attack: "SQL Injection",
    ip: "45.91.120.10",
    risk: "Critical"
  }
];

app.get("/", (req, res) => {
  const totalAlerts = alerts.length;
  const criticalAlerts = alerts.filter(a => a.risk === "Critical").length;
  const highAlerts = alerts.filter(a => a.risk === "High").length;

  const threatRows = alerts.map(alert => `
    <tr>
      <td>${alert.attack}</td>
      <td>${alert.ip}</td>
      <td>${alert.risk}</td>
    </tr>
  `).join("");

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>AI-SOC Dashboard</title>
      <style>
        body {
          background: #0d1117;
          color: white;
          font-family: Arial, sans-serif;
          margin: 0;
          padding: 20px;
        }

        h1 {
          color: #00ff88;
        }

        .cards {
          display: flex;
          gap: 20px;
          margin-top: 20px;
        }

        .card {
          background: #161b22;
          padding: 20px;
          border-radius: 10px;
          min-width: 200px;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 20px;
          background: #161b22;
        }

        th, td {
          padding: 12px;
          border: 1px solid #30363d;
          text-align: left;
        }

        th {
          background: #21262d;
        }

        .critical {
          color: red;
          font-weight: bold;
        }

        .high {
          color: orange;
          font-weight: bold;
        }

        .analysis {
          margin-top: 30px;
          background: #161b22;
          padding: 20px;
          border-radius: 10px;
        }
      </style>
    </head>
    <body>

      <h1> AI-SOC Dashboard</h1>
      <p>AI Powered Security Operations Center</p>

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
            <th>Risk</th>
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
          Direkomendasikan untuk melakukan validasi input,
          menggunakan prepared statement, dan melakukan review log database.
        </p>
      </div>

    </body>
    </html>
  `);
});

app.get("/alerts", (req, res) => {
  res.json(alerts);
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});