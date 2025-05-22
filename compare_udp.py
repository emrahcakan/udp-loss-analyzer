#!/usr/bin/env python3
import argparse
import csv
from scapy.all import rdpcap, UDP

def load_udp_packets(pcap_file):
    """
    Read a pcap and return a list of (payload_bytes, timestamp) for each UDP packet.
    """
    pkts = rdpcap(pcap_file)
    out = []
    for p in pkts:
        if UDP in p:
            payload = bytes(p[UDP].payload)
            ts = p.time  # epoch float
            out.append((payload, ts))
    return out

def trim_to_overlap(tx, rx):
    """
    Find the overlapping window by payload, then slice both lists.
    tx, rx are lists of (payload, timestamp).
    Returns:
      tx_trim, rx_trim,
      (first_tx, last_tx),  # indices in original tx
      (first_rx, last_rx)   # indices in original rx
    """
    tx_payloads = [p for p,_ in tx]
    rx_payloads = [p for p,_ in rx]
    common = set(tx_payloads) & set(rx_payloads)
    if not common:
        raise RuntimeError("No overlapping packets between TX and RX!")

    first_tx = next(i for i, (p,_) in enumerate(tx) if p in common)
    last_tx  = max(i for i, (p,_) in enumerate(tx) if p in common)
    first_rx = next(i for i, (p,_) in enumerate(rx) if p in common)
    last_rx  = max(i for i, (p,_) in enumerate(rx) if p in common)

    return (
        tx[first_tx:last_tx+1],
        rx[first_rx:last_rx+1],
        (first_tx, last_tx),
        (first_rx, last_rx)
    )

def find_missing(tx_trim, rx_trim, tx_offset):
    """
    Return list of (abs_index, timestamp, payload_bytes) for payloads
    in tx_trim not seen in rx_trim.
    """
    rx_set = set(p for p,_ in rx_trim)
    missing = []
    for idx, (payload, ts) in enumerate(tx_trim):
        if payload not in rx_set:
            missing.append((tx_offset + idx, ts, payload))
    return missing

def hex_snip(b, length=32):
    h = b.hex()
    return h[:length] + ("…" if len(h)>length else "")

def main():
    parser = argparse.ArgumentParser(
        description="""
Compares two UDP-only PCAP files (transmitter and receiver) and reports missing packets (lost UDP payloads).
It trims both captures to their overlapping window, avoiding "false losses" at the beginning and end.
The output is a CSV file listing the timestamp, original TX index, and payload of every lost packet.

Example:
  ./udp_loss_compare.py --inputTx sender.pcap --inputRx receiver.pcap --output lost.csv
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--inputTx", required=True, help="Transmitter (TX) pcap file")
    parser.add_argument("--inputRx", required=True, help="Receiver (RX) pcap file")
    parser.add_argument(
        "--output", "-o", default="missing_packets.csv",
        help="CSV file to write missing packets to (default: missing_packets.csv)"
    )
    args = parser.parse_args()

    tx = load_udp_packets(args.inputTx)
    rx = load_udp_packets(args.inputRx)
    print(f"Loaded: TX={len(tx)} pkts, RX={len(rx)} pkts")

    tx_trim, rx_trim, (ftx, ltx), (frx, lrx) = trim_to_overlap(tx, rx)
    print(f"Overlap window → TX[{ftx}…{ltx}] ({len(tx_trim)} pkts), "
          f"RX[{frx}…{lrx}] ({len(rx_trim)} pkts)\n")

    missing = find_missing(tx_trim, rx_trim, tx_offset=ftx)
    print("===== Lost-packet Report =====")
    print(f"Packets in window: TX={len(tx_trim)}, RX={len(rx_trim)}")
    print(f"Missing packets:   {len(missing)}")
    print(f"Writing details to {args.output!r}")

    # Write CSV
    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "tx_index", "payload_hex"])
        for abs_idx, ts, payload in missing:
            writer.writerow([ts, abs_idx, hex_snip(payload)])

    print("Done.")

if __name__ == "__main__":
    main()

