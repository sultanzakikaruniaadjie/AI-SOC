import { useEffect, useState } from "react";
import axios from "axios";

function Dashboard() {

  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    axios.get("http://localhost:5000/alerts")
      .then((res) => {
        setAlerts(res.data);
      });
  }, []);

  return (
    <div>
      <h1>AI-SOC Dashboard</h1>

      {alerts.map((alert, index) => (
        <div key={index}>
          <h3>{alert.attack}</h3>
          <p>{alert.ip}</p>
          <p>{alert.risk}</p>
        </div>
      ))}
    </div>
  );
}

export default Dashboard;