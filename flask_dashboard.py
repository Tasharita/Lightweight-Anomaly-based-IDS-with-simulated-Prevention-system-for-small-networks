from flask import Flask, render_template, redirect, jsonify, request, session
import pandas as pd
import os
from datetime import datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import subprocess
from functools import wraps


app = Flask(__name__)
app.secret_key = "ids_secret_key_2025"

# Login credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "ids1234"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

ids_process = None

ALERT_FILE = "/home/tasha/ids_project/alerts.csv"
WHITELIST_FILE = "/home/tasha/ids_project/whitelist.txt"


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
@login_required
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

@app.route("/start")
@login_required
def start_ids():
    global ids_process
    if ids_process is None or ids_process.poll() is not None:
        ids_process = subprocess.Popen(
            ["sudo", "python3", "ids.py"],
            cwd="/home/tasha/ids_project"
        )
        print("[*] IDS started")
    return redirect("/")

@app.route("/stop")
@login_required
def stop_ids():
    global ids_process
    if ids_process:
        ids_process.terminate()
        ids_process = None
    return redirect("/")


@app.route("/status")
@login_required
def status():
    global ids_process
    running = ids_process is not None and ids_process.poll() is None
    return jsonify({"running": running})


@app.route("/data")
@login_required
def data():
    df = load_alerts()
    dos_alerts = 0
    portscan_alerts = 0
    blacklist_count = 0
    alerts_html = ""
    blacklist_html = ""

    if not df.empty:
        dos_alerts = len(df[df["Anomaly Type"].str.contains("DOS", case=False)])
        portscan_alerts = len(df[df["Anomaly Type"].str.contains("PORT", case=False)])
        blacklist_count = len(df["Source IP"].unique())

        for _, row in df.iloc[::-1].iterrows():
            anomaly = str(row["Anomaly Type"])
            value = int(row["Value"])
            if "DOS" in anomaly:
                severity = "High" if value >= 2000 else "Medium" if value >= 1000 else "Low"
            else:
                severity = "High"
            badge = f'<span class="badge {severity.lower()}">{severity}</span>'
            alerts_html += f"<tr><td>{row['Timestamp']}</td><td>{row['Source IP']}</td><td>{anomaly}</td><td>{value}</td><td>{badge}</td></tr>"

        seen = set()
        for _, row in df.iterrows():
            ip = row["Source IP"]
            if ip not in seen:
                blacklist_html += f"<tr><td>{ip}</td><td>{row['Anomaly Type']}</td><td>{row['Timestamp']}</td></tr>"
                seen.add(ip)

    return jsonify({
        "total_alerts": len(df),
        "dos_alerts": dos_alerts,
        "portscan_alerts": portscan_alerts,
        "blacklist_count": blacklist_count,
        "last_updated": datetime.now().strftime("%H:%M:%S"),
        "alerts_html": alerts_html if alerts_html else "<tr><td colspan='5'>No alerts detected.</td></tr>",
        "blacklist_html": blacklist_html if blacklist_html else "<tr><td colspan='3'>No blacklisted hosts.</td></tr>"
    })


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect("/")
        else:
            error = "Invalid username or password"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    import webbrowser
    import threading

    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open("http://localhost:5000")

    threading.Thread(target=open_browser).start()
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
