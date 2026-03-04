# Add this global variable at the top
packet_sizes = []

def detect_anomaly(current_size):
    global packet_sizes
    packet_sizes.append(current_size)
    if len(packet_sizes) > 100: packet_sizes.pop(0)
    
    # Calculate average size of last 100 packets
    avg = sum(packet_sizes) / len(packet_sizes)
    
    # Threshold: If a packet is 3x larger than average, flag it
    return 1 if current_size > (avg * 3) and len(packet_sizes) > 10 else 0

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        size = len(packet)
        
        # Anomaly Detection Logic
        is_anomaly = detect_anomaly(size)
        
        # Cloud-Native Classification
        traffic_type = "Internal" if src.startswith("10.") or src.startswith("192.168.") else "Egress"
        
        point = Point("network_flow") \
            .tag("source", src) \
            .tag("destination", dst) \
            .tag("protocol", proto) \
            .tag("type", traffic_type) \
            .field("bytes", size) \
            .field("anomaly_flag", is_anomaly) \
            .time(datetime.datetime.utcnow())
        
        write_api.write(bucket=BUCKET, record=point)
        
        if is_anomaly:
            print(f"⚠️  ANOMALY DETECTED: {size} bytes from {src}")
        else:
            print(f"Captured: {src} -> {dst} | {proto} | {size} bytes")
          
            
