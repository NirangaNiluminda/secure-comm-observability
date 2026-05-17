from scapy.all import sniff, IP, TCP, get_if_list
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import time
import os
from collections import deque

# InfluxDB Configuration
INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "my-super-secret-auth-token")
INFLUX_ORG = os.getenv("INFLUX_ORG", "securechat")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "network_metrics")
CAPTURE_FILTER = os.getenv("CAPTURE_FILTER", "tcp port 80")
SYN_ACK_WINDOW = int(os.getenv("SYN_ACK_WINDOW", "200"))
DOS_RATIO_THRESHOLD = float(os.getenv("DOS_RATIO_THRESHOLD", "3.0"))

client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = client.write_api(write_options=SYNCHRONOUS)

syn_window = deque(maxlen=SYN_ACK_WINDOW)
ack_window = deque(maxlen=SYN_ACK_WINDOW)


def parse_tcp_flags(flags):
    text = str(flags)
    return {
        "S": 1 if "S" in text else 0,
        "A": 1 if "A" in text else 0,
        "F": 1 if "F" in text else 0,
        "R": 1 if "R" in text else 0,
        "P": 1 if "P" in text else 0,
        "U": 1 if "U" in text else 0,
    }


def write_ratio_metric(timestamp_ns):
    syn_count = sum(syn_window)
    ack_count = sum(ack_window)
    ratio = syn_count / max(ack_count, 1)
    is_anomalous = 1 if ratio >= DOS_RATIO_THRESHOLD and syn_count > 10 else 0

    point = Point("network_anomaly") \
        .field("syn_count", syn_count) \
        .field("ack_count", ack_count) \
        .field("syn_ack_ratio", ratio) \
        .field("dos_suspected", is_anomalous) \
        .time(timestamp_ns)

    write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
    if is_anomalous:
        print(f"[ALERT] Elevated SYN/ACK ratio={ratio:.2f} (SYN={syn_count}, ACK={ack_count})")

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = parse_tcp_flags(packet[TCP].flags)
        timestamp_ns = time.time_ns()

        syn_window.append(flags["S"])
        ack_window.append(flags["A"])

        point = Point("network_traffic") \
            .tag("src_ip", src_ip) \
            .tag("dst_ip", dst_ip) \
            .tag("transport", "tcp") \
            .field("size", size) \
            .field("src_port", sport) \
            .field("dst_port", dport) \
            .field("syn", flags["S"]) \
            .field("ack", flags["A"]) \
            .field("fin", flags["F"]) \
            .field("rst", flags["R"]) \
            .field("psh", flags["P"]) \
            .field("urg", flags["U"]) \
            .time(timestamp_ns)
        
        try:
            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
            write_ratio_metric(timestamp_ns)
            print(
                f"[{src_ip}:{sport} -> {dst_ip}:{dport}] "
                f"Size={size} SYN={flags['S']} ACK={flags['A']} FIN={flags['F']} RST={flags['R']}"
            )
        except Exception as e:
            print(f"InfluxDB write error: {e}")

ifaces = get_if_list()
print(f"Starting Scapy Sniffer — interfaces: {ifaces}  filter: {CAPTURE_FILTER}")
sniff(filter=CAPTURE_FILTER, iface=ifaces, prn=process_packet, store=False)
