# Lightweight Anomaly-Based Intrusion Detection and Simulated Prevention System for Small Networks

## Overview
A lightweight Python-based intrusion detection and simulated prevention system designed for small network environments. The system monitors network traffic in real time, detects anomalous behaviour including traffic spikes and port scanning activities, and simulates prevention through IP blacklisting and alert logging.

## Author
- **Name:** Natasha Neema Mwangi

## Requirements
- Kali Linux (Monitor and Attacker VMs)
- Debian (Victim VM)
- Python 3
- VirtualBox

## Installation
```bash
pip3 install scapy pandas matplotlib
```

## Project Files
| File | Description |
|---|---|
| ids.py | Main IDS script — detection and prevention |
| dashboard.py | Matplotlib visualisation dashboard |
| baseline.py | Baseline traffic capture script |
| sniffer.py | Basic packet sniffer |

## How to Run

### Start the IDS
```bash
sudo python3 ids.py
```

### Start the Dashboard
Open a second terminal and run:
```bash
python3 dashboard.py
```

### Simulate Attacks (from Attacker VM)
```bash
# Port scan
sudo nmap -sS -p 1-1000 <monitor-vm-ip>

# DoS flood
sudo timeout 15 hping3 -S --flood -V -p 80 <monitor-vm-ip>
```

## Detection Thresholds
| Attack Type | Threshold | Time Window |
|---|---|---|
| DoS / Traffic Spike | 500 packets | 10 seconds |
| Port Scanning | 300 unique ports | 10 seconds |

Thresholds were determined empirically through baseline traffic observation on the virtual network.

## Virtual Network Setup
| VM | OS | Role |
|---|---|---|
| Attacker VM | Kali Linux | Generates attack traffic using Nmap and hping3 |
| Victim VM | Debian | Target machine |
| Monitor VM | Kali Linux | Runs IDS system — all Python scripts run here |

## Output
- Alerts printed to terminal in real time
- Events logged to alerts.csv
- Live dashboard showing traffic statistics and alert history

