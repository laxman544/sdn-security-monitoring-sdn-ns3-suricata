# NS-3 DDoS Traffic Simulation

This folder contains the **NS-3 simulation code** used in the
*Security Network Monitoring in SDN* project.

NS-3 is used to generate both **benign background traffic** and
**malicious DDoS attack traffic** in an SDN-like network topology.
The generated traffic is captured in PCAP format and later analyzed
using **Suricata** and **Wireshark** for security monitoring.

---

## 1. Purpose of NS-3 in This Project

NS-3 serves as the **traffic generation and flow monitoring layer**
of the security pipeline. Specifically, it is used to:

- Create a controlled SDN-like topology
- Generate legitimate and malicious UDP traffic
- Simulate a **UDP flood DDoS attack**
- Collect flow-level statistics (packet counts, throughput)
- Export PCAP traces for offline intrusion detection

NS-3 enables a fully reproducible experimental setup without requiring
physical network hardware or live SDN controllers.

---

## 2. Network Topology

The simulated topology consists of:

- **One victim node** (server-like host)
- **Two attacker nodes**
- **One background traffic node**

All nodes are connected using **point-to-point links**
with the following parameters:

- Bandwidth: `10 Mbps`
- Delay: `5 ms`

### IP Address Assignment

| Node Type | IP Address |
|---------|------------|
Background host | `10.0.0.1` |
Background host | `10.0.0.2` |
Attacker 1 | `10.0.0.3` |
Attacker 2 | `10.0.0.4` |
Victim | `10.0.0.5` |

---

## 3. DDoS Attack Model

The DDoS attack is implemented using **UDP flooding**:

- Attackers send high-rate UDP packets to the victim
- Destination port: `5000`
- Packet size: `512 bytes`
- Attack duration: configurable (e.g., 5s–15s)
- Traffic generator: `OnOffHelper`

During the attack window, attacker flows significantly exceed
normal throughput levels, making them detectable via both
flow statistics and IDS rules.

---

## 4. Flow Monitoring and Packet Capture

NS-3 uses:

- **FlowMonitor** to collect:
  - Packet counts
  - Throughput
  - Per-flow statistics
- **PCAP tracing** to record all packets

### Generated Outputs

| File | Description |
|-----|-------------|
`ns3_ddos.pcap` | Packet capture used by Suricata & Wireshark |
`flows.xml` | FlowMonitor statistics (XML format) |

> Note: These output files are usually **not tracked in Git**
> and are ignored via `.gitignore`.

---

## 5. File Description

```text
ns3/
├─ ns3_ddos_simulation.cc    # Main NS-3 simulation source code
└─ README.md                # This documentation
