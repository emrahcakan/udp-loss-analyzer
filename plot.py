#!/usr/bin/env python3
import argparse
import csv
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import rdpcap, UDP

def load_drop_times(csv_path):
    """Read missing_packets.csv, return pandas DataFrame indexed by datetime of each drop."""
    times = []
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = float(row['timestamp'])
            times.append(datetime.fromtimestamp(ts))
    df = pd.DataFrame({'drops': 1}, index=pd.DatetimeIndex(times))
    return df

def load_total_times(pcap_path):
    """Read a pcap, return pandas DataFrame indexed by datetime of every UDP packet."""
    pkts = rdpcap(pcap_path)
    times = [datetime.fromtimestamp(float(p.time)) for p in pkts if UDP in p]
    df = pd.DataFrame({'pkts': 1}, index=pd.DatetimeIndex(times))
    return df

def main():
    parser = argparse.ArgumentParser(
        description="""
Overlay graph: packet drop count per time bin vs total UDP packet count per bin.

Example:
  ./plot_drops_vs_total.py --inputData missing_packets.csv --inputCapture receiver.pcap -b 1ms

The drops (from CSV) are shown as a dotted line (left axis).
The total packets (from capture) are shown as a translucent area (right axis).
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--inputData", required=True, help="Path to missing_packets.csv")
    parser.add_argument("--inputCapture", required=True, help="Path to UDP-capture pcap file")
    parser.add_argument("-b", "--bin", type=str, default="1ms",
                        help="Bin size for time axis (e.g. '1ms', '5ms', '10ms'). Default is 1ms.")
    args = parser.parse_args()

    # Load data
    df_drops = load_drop_times(args.inputData)
    df_pkts = load_total_times(args.inputCapture)

    # Resample both to the same bins, filling zeros where no events
    drops_rate = df_drops.resample(args.bin).sum().fillna(0)
    pkts_rate = df_pkts.resample(args.bin).sum().fillna(0)

    # Plot
    fig, ax_d = plt.subplots(figsize=(12, 4))

    # Left axis: drops (dotted, points only)
    ax_d.plot(
        drops_rate.index, drops_rate['drops'],
        color='C1', label='Drops per '+args.bin,
        marker="o", linestyle="None", markersize=5
    )
    ax_d.set_ylabel(f"Drops per {args.bin}", color='C1')
    ax_d.tick_params(axis='y', labelcolor='C1')

    # Right axis: total packets (translucent area)
    ax_p = ax_d.twinx()
    ax_p.fill_between(
        pkts_rate.index, pkts_rate['pkts'],
        step='post', alpha=0.3, color='C0', label='Pkts per '+args.bin
    )
    ax_p.set_ylabel(f"Pkts per {args.bin}", color='C0')
    ax_p.tick_params(axis='y', labelcolor='C0')

    # X-axis formatting
    ax_d.set_xlabel("Time")
    fig.autofmt_xdate()

    # Legends
    lines, labels = ax_d.get_legend_handles_labels()
    lines2, labels2 = ax_p.get_legend_handles_labels()
    ax_d.legend(lines+lines2, labels+labels2, loc='upper left')

    plt.title("Packet Drops vs Total Packets Over Time")
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()

