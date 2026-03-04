import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from influxdb_client import InfluxDBClient, Point, WriteOptions
import datetime

# --- CONFIGURATION ---
TOKEN = "my-super-secret-token"
ORG = "my-org"
BUCKET = "network_metrics"
URL = "http://localhost:8086"

client = InfluxDBClient(url=URL, token=TOKEN, org=ORG)
write_api = client.write_api(write_options=WriteOptions(batch_size=1))

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        size = len(packet)
        
        # Cloud-Native Logic: Flagging Internal vs External Traffic
        traffic_type = "Internal" if src.startswith("10.") or src.startswith("192.168.") else "Egress"
        
        point = Point("network_flow") \
            .tag("source", src) \
            .tag("destination", dst) \
            .tag("protocol", proto) \
            .tag("type", traffic_type) \
            .field("bytes", size) \
            .time(datetime.datetime.utcnow())
        
        write_api.write(bucket=BUCKET, record=point)
        print(f"Captured: {src} -> {dst} | {proto} | {size} bytes")

print("🚀 Cloud-Native Traffic Analyzer Started...")
sniff(iface="eth0", prn=process_packet, store=0)
