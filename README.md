# 🌌 Cloud-Native Network Traffic Analyzer (Project 'Aether')

**An evolution of my thesis research on Network Traffic Patterns in Cloud-Native Environments.**

This tool is a real-time packet inspection engine designed for high-velocity cloud environments. It bridges the gap between academic traffic analysis and production-grade observability.

## 🚀 Key Features
* **Layer 7 Visibility:** Real-time packet dissection using Scapy.
* **Cloud-Context Aware:** Automatically differentiates between East-West (Internal) and North-South (Egress) traffic.
* **Time-Series Visualisation:** Integrated with InfluxDB and Grafana for sub-second monitoring.
* **Anomaly Detection:** Flags suspicious packet sizes and unusual protocol distributions.

## 🛠 Tech Stack
- **Engine:** Python / Scapy
- **Database:** InfluxDB (Time-Series)
- **Visualisation:** Grafana
- **Infrastructure:** Docker / Kubernetes

## ⏱️ Quick Start (Works Instantly)
1. **Clone & Spin up the environment:**
   ```bash
   docker-compose up -d
