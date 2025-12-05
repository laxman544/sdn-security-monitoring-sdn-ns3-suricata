# dashboard.py
# Simple Dash app to visualise Suricata alerts from eve.json

import json
import pandas as pd
from datetime import datetime

from dash import Dash, dcc, html
import plotly.express as px

EVE_PATH = "../suricata/eve.json"

def load_alerts(eve_path: str) -> pd.DataFrame:
    rows = []
    with open(eve_path, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})
            src_ip = event.get("src_ip")
            dest_ip = event.get("dest_ip")
            category = alert.get("category")
            signature = alert.get("signature")
            timestamp = event.get("timestamp")

            try:
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except Exception:
                ts = None

            rows.append({
                "timestamp": ts,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "category": category,
                "signature": signature,
            })

    df = pd.DataFrame(rows)
    df = df.dropna(subset=["timestamp"])
    df = df.sort_values("timestamp")
    return df

df_alerts = load_alerts(EVE_PATH)

if df_alerts.empty:
    print("No alerts found in eve.json. Did Suricata run correctly?")
else:
    print(f"Loaded {len(df_alerts)} alerts from eve.json")

app = Dash(__name__)
app.title = "SDN Security Monitoring Dashboard"

# Top attackers (by src_ip)
if not df_alerts.empty:
    top_attackers = (df_alerts
                     .groupby("src_ip")
                     .size()
                     .reset_index(name="count")
                     .sort_values("count", ascending=False))

    alerts_over_time = (df_alerts
                        .set_index("timestamp")
                        .resample("1S")
                        .size()
                        .reset_index(name="alert_count"))

    category_counts = (df_alerts
                       .groupby("category")
                       .size()
                       .reset_index(name="count"))
else:
    top_attackers = pd.DataFrame(columns=["src_ip", "count"])
    alerts_over_time = pd.DataFrame(columns=["timestamp", "alert_count"])
    category_counts = pd.DataFrame(columns=["category", "count"])

app.layout = html.Div(
    style={"fontFamily": "Arial, sans-serif", "margin": "20px"},
    children=[
        html.H1("SDN Security Monitoring Dashboard"),
        html.P("Visualising Suricata alerts generated from NS-3 DDoS simulation."),

        dcc.Graph(
            id="top-attackers",
            figure=px.bar(
                top_attackers,
                x="src_ip",
                y="count",
                title="Top Attacker IPs by Alert Count"
            )
        ),

        dcc.Graph(
            id="alerts-over-time",
            figure=px.line(
                alerts_over_time,
                x="timestamp",
                y="alert_count",
                title="Alerts Over Time (1-second buckets)"
            )
        ),

        dcc.Graph(
            id="category-pie",
            figure=px.pie(
                category_counts,
                names="category",
                values="count",
                title="Alert Category Distribution"
            )
        ),
    ]
)

if __name__ == "__main__":
    app.run_server(debug=True)
