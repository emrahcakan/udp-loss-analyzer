# UDP Packet Loss Comparison Tool

This repository contains scripts to compare UDP packet traces and analyze packet loss patterns between a transmitter (TX) and receiver (RX). It is especially useful for investigating dropped UDP packets, burst loss, and loss correlation with traffic bursts.

## Contents

- `compare_udp.py` — Compares two UDP-only PCAP files (TX and RX), finds lost packets, and outputs missing packets to a CSV file.
- `plot.py` — Plots lost-packet statistics (from the CSV) over time or against traffic rates, for easy visual investigation.

## How it works

1. **compare_udp.py:**  
   - Takes two pcap files: one from the sender (TX), one from the receiver (RX).
   - Time-aligns both traces, focusing analysis on their overlapping window to avoid spurious edge losses.
   - Detects lost packets by comparing UDP payloads.
   - Outputs a CSV file with details (timestamp, TX index, payload hex) of missing packets.

2. **plot.py:**  
   - Takes the output CSV and visualizes lost packets over time.
   - Optionally, overlays total RX packet count for correlation analysis.

## Requirements

- Python 3.7+
- Dependencies: `scapy`, `pandas`, `matplotlib`

Install dependencies with:
```bash
pip install -r requirements.txt
```

## Usage

1. Detect Lost Packets

```python compare_udp.py --inputTx sender.pcap --inputRx receiver.pcap --output lost.csv```

--inputTx — Path to transmitter (sender) pcap file

--inputRx — Path to receiver pcap file

--output — Output CSV (default: missing_packets.csv)

2. Plot the Results

```python plot.py --inputData lost.csv --inputCapture receiver.pcap -b 1ms```

--inputData — Path to CSV with missing/lost packets

--inputCapture — Path to RX pcap (to plot total packet rates)

-b/--bin — Bin width for time aggregation (e.g. 1ms, 10ms)

Tip: You can use the scripts with executable permissions (e.g., ./compare_udp.py ...) if you like.
