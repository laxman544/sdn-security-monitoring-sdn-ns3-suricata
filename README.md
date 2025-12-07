# Security Network Monitoring in SDN  
### DDoS Detection using NS-3, Suricata, Wireshark, and Dash

This repository contains the complete source code for the graduate-level project:

**“Security Network Monitoring in Software-Defined Networks (SDN)”**

The project demonstrates a **full security monitoring pipeline**, starting from traffic generation to intrusion detection and visual analysis.  
It focuses specifically on **DDoS attack detection and monitoring**, not basic traffic forwarding.

---

## Project Objective

The goal of this project is to clearly demonstrate:

- What **security network monitoring in SDN** means
- How **DDoS attacks** manifest in network traffic
- How attacks can be **detected, validated, and visualized**
- How multiple tools complement each other in a monitoring pipeline

This project was designed to address academic feedback requiring:
- clear focus,
- real attack evidence,
- reproducibility,
- and security-oriented monitoring (not basic SDN demos).

---

## Monitoring Pipeline Overview

1. **NS-3**  
   - Simulates an SDN-like topology
   - Generates normal traffic and a **UDP flood DDoS attack**
   - Captures packets into a PCAP file
   - Collects flow-level statistics using FlowMonitor

2. **Suricata IDS**  
   - Runs in **offline mode** on NS-3 PCAP files
   - Detects DDoS-related anomalies using rules
   - Produces structured alerts (`eve.json`)

3. **Wireshark**  
   - Validates Suricata alerts at packet level
   - Confirms traffic spikes using I/O graphs and endpoints

4. **Plotly Dash Dashboard**  
   - Visualizes alerts over time
   - Shows top attacker IPs and alert categories

---

## Repository Structure

```text
sdn-security-monitoring-sdn-ns3-suricata/
├── ns3/              # NS-3 traffic simulation and DDoS generation
├── suricata/         # IDS rules, config, and offline analysis script
├── dashboard/        # Python Dash visualization
├── README.md         # Project overview (this file)
├── .gitignore        # Ignores generated artifacts
