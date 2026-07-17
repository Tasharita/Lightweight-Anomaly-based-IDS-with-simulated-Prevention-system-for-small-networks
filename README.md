# Lightweight Anomaly-Based Intrusion Detection and Prevention System for Small Local Area Networks

## Overview

This project implements a lightweight Python-based Intrusion Detection and Prevention System (IDS/IPS) designed for small Local Area Network (LAN) environments. The system captures and analyses network traffic in real time, detects TCP SYN port scanning and TCP SYN flooding (DoS) attacks using threshold-based anomaly detection, automatically blocks malicious source IP addresses using Linux iptables, and provides a Flask-based web dashboard for monitoring network activity, alerts, trusted hosts, and blocked hosts.

---

## Author

**Natasha Neema Mwangi**

---

## Features

- Real-time packet capture and analysis using Scapy
- Threshold-based anomaly detection
- Detection of TCP SYN port scanning attacks
- Detection of TCP SYN Flood (DoS) attacks
- Automatic blocking of malicious source IP addresses using Linux iptables
- Web-based dashboard built with Flask
- Real-time attack statistics and network monitoring
- Alert logging to `alerts.csv`
- Trusted hosts and blocked hosts management

---

## System Requirements

- Python 3
- Oracle VirtualBox
- Linux environment
- Flask
- Scapy
- Pandas
- Matplotlib

---

## Installation

Install the required Python packages:

```bash
pip3 install flask scapy pandas matplotlib
```

---

## Project Structure

| File | Description |
|------|-------------|
| `flask_dashboard.py` | Launches the web dashboard and controls the IDS |
| `ids.py` | Main intrusion detection and prevention module |
| `baseline.py` | Captures baseline network traffic |
| `sniffer.py` | Packet capture utility |
| `alerts.csv` | Stores detected intrusion events |
| `whitelist.txt` | Stores trusted IP addresses |
| `reset.sh` | Resets firewall rules and clears blocked IPs |
| `templates/` | HTML templates for the Flask dashboard |
| `static/` | Static resources for the dashboard |

---

## Running the System

Start the Flask dashboard:

```bash
python3 flask_dashboard.py
```

Open your browser and navigate to:

```
http://127.0.0.1:5000
```

Click **Start IDS** from the dashboard to begin real-time packet capture, intrusion detection, and automated prevention.

---

## Testing the System

After starting the IDS, generate test traffic from the attacker machine.

### TCP SYN Port Scan

```bash
sudo nmap -sS -p 1-3000 <workstation-ip>
```

### TCP SYN Flood (DoS)

```bash
sudo hping3 --flood -S -p 80 <workstation-ip>
```

---

## Detection Thresholds

| Attack Type | Threshold | Time Window |
|-------------|-----------|-------------|
| TCP SYN Flood (DoS) | 50 packets | 10 seconds |
| TCP SYN Port Scan | 20 unique destination ports | 10 seconds |

The threshold values were determined through baseline traffic observation and experimental testing to achieve a balance between detection sensitivity and false positives.

---

## Virtual Network Setup

| Virtual Machine | Role |
|-----------------|------|
| Attacker | Generates TCP SYN port scan and TCP SYN flooding attacks |
| Monitor | Hosts the IDS/IPS application, captures and analyses network traffic, blocks malicious IP addresses, logs alerts, and runs the Flask dashboard |
| Workstation | Receives both normal and malicious network traffic during testing |

---

## System Output

The system provides:

- Real-time intrusion alerts
- Automatic blocking of malicious source IP addresses
- Logged intrusion events stored in `alerts.csv`
- A web-based dashboard displaying:
  - Recent alerts
  - Attack statistics
  - Trusted hosts
  - Blocked hosts

---

## Technologies Used

- Python
- Flask
- Scapy
- Pandas
- Matplotlib
- Linux iptables
- Oracle VirtualBox
- Nmap
- hping3

---

## License

This project is intended for educational and research purposes.
