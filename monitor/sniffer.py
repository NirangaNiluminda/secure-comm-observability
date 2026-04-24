from scapy.all import sniff, IP, TCP
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import time

# InfluxDB Configuration
INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "my-super-secret-auth-token"
INFLUX_ORG = "securechat"
INFLUX_BUCKET = "network_metrics"

client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = client.write_api(write_options=SYNCHRONOUS)

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        flags = packet[TCP].flags

        # Extract flags (S=SYN, A=ACK)
        is_syn = 1 if 'S' in flags else 0
        is_ack = 1 if 'A' in flags else 0

        # Push to InfluxDB
        point = Point("network_traffic") \
            .tag("src_ip", src_ip) \
            .tag("dst_ip", dst_ip) \
            .field("size", size) \
            .field("syn", is_syn) \
            .field("ack", is_ack) \
            .time(time.time_ns())
        
        try:
            write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
            print(f"[{src_ip} -> {dst_ip}] Size: {size}, SYN: {is_syn}, ACK: {is_ack}")
        except Exception as e:
            print(f"InfluxDB write error: {e}")

print("Starting Scapy Sniffer on port 5000...")
# Sniff packets strictly for the application server (port 5000)
# Use loopback / external interfaces
sniff(filter="tcp port 5000", prn=process_packet, store=False)
