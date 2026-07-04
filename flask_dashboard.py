from flask import Flask, render_template
import pandas as pd
import os
from datetime import datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


app = Flask(__name__)


ALERT_FILE = "alerts.csv"
WHITELIST_FILE = "whitelist.txt"


def load_whitelist():
    hosts = []

    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE) as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                parts = line.split(",")

                if len(parts) == 2:
                    hosts.append({
                        "ip": parts[0].strip(),
                        "name": parts[1].strip()
                    })

                else:
                    hosts.append({
                        "ip": parts[0].strip(),
                        "name": "Trusted Host"
                    })

    return hosts


def load_alerts():

    if not os.path.exists(ALERT_FILE):
        return pd.DataFrame()

    try:
        return pd.read_csv(ALERT_FILE)

    except Exception:
        return pd.DataFrame()


@app.route("/")
def dashboard():

    df = load_alerts()
    whitelist = load_whitelist()

    total_alerts = len(df)

    dos_alerts = 0
    portscan_alerts = 0

    alerts = []
    blacklist = []

    alerts_per_ip = {}
    attack_distribution = {
        "Port Scan": 0,
        "DoS": 0
    }

    if not df.empty:

        dos_alerts = len(
            df[df["Anomaly Type"].str.contains("DOS", case=False)]
        )

        portscan_alerts = len(
            df[df["Anomaly Type"].str.contains("PORT", case=False)]
        )

        alerts_per_ip = (
            df["Source IP"]
            .value_counts()
            .to_dict()
        )

        attack_distribution = {
            "Port Scan": portscan_alerts,
            "DoS": dos_alerts
        }

        seen = set()

        for _, row in df.iterrows():

            anomaly = str(row["Anomaly Type"])
            value = int(row["Value"])

            if anomaly == "DOS / TRAFFIC SPIKE":

                if value >= 2000:
                    severity = "High"

                elif value >= 1000:
                    severity = "Medium"

                else:
                    severity = "Low"

            else:
                severity = "High"

            alerts.append({

                "timestamp": row["Timestamp"],
                "ip": row["Source IP"],
                "type": anomaly,
                "value": value,
                "severity": severity

            })

            ip = row["Source IP"]

            if ip not in seen:

                blacklist.append({

                    "ip": ip,
                    "reason": anomaly,
                    "time": row["Timestamp"]

                })

                seen.add(ip)

    # ===============================
    # Generate Alerts Per IP Graph
    # ===============================

    plt.figure(figsize=(6,4))

    if alerts_per_ip:

        plt.bar(
            alerts_per_ip.keys(),
            alerts_per_ip.values(),
            color="#4F81BD"
        )

        plt.title("Alerts Per Source IP")
        plt.ylabel("Number of Alerts")
        plt.grid(axis="y", linestyle="--", alpha=0.4)

    else:

        plt.text(
            0.5,
            0.5,
            "No Alerts",
            ha="center",
            fontsize=14
        )

    plt.tight_layout()

    plt.savefig("static/alerts_per_ip.png")

    plt.close()


    # ===============================
    # Generate Attack Distribution
    # ===============================

    plt.figure(figsize=(5,5))

    values = list(attack_distribution.values())

    labels = list(attack_distribution.keys())

    if sum(values) > 0:

        plt.pie(
            values,
            labels=labels,
            autopct="%1.1f%%",
            startangle=90,
            colors=["#F39C12", "#E74C3C"],
            explode=(0.05,0.05)
        )

        plt.title("Attack Distribution")

    else:

        plt.text(
            0.5,
            0.5,
            "No Alerts",
            ha="center",
            fontsize=14
        )

    plt.tight_layout()

    plt.savefig("static/attack_distribution.png")

    plt.close()


    return render_template(

        "dashboard.html",

        total_alerts=total_alerts,

        dos_alerts=dos_alerts,

        portscan_alerts=portscan_alerts,

        trusted_hosts=len(whitelist),

        blacklist_count=len(blacklist),

        whitelist=whitelist,

        blacklist=blacklist,

        alerts=alerts[::-1],

        last_updated=datetime.now().strftime("%H:%M:%S")

    )



if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
