const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    project: "AI-SOC",
    status: "running"
  });
});

app.get("/alerts", (req, res) => {
  res.json([
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
  ]);
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});