#!/usr/bin/env bash
PCAP_FILE="../pcaps/ns3_ddos.pcap"

if [ ! -f "$PCAP_FILE" ]; then
  echo "PCAP file not found: $PCAP_FILE"
  exit 1
fi

sudo suricata -r "$PCAP_FILE" -l . -c /etc/suricata/suricata.yaml

echo "Suricata analysis completed. Check eve.json & fast.log"
