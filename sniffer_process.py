from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, ARP
from datetime import datetime
from analyzer import analyze_payload, get_geo
from logger import log_alert, log_label
import sys
import json
import queue
import time
import re # Import re for regex matching in filters

SNIFFING_ACTIVE = False

# Live Filter (from UI search bar)
current_live_filter = {
    "query": "",
    "only_filtered": False
}

# Queues for IPC
packet_output_queue = None
alert_output_queue = None
filter_input_queue = None # New queue for receiving filter commands

# Database connection for sniffer process
import sqlite3
DATABASE = 'ids.db'

def get_db_connection_sniffer():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def add_packet_to_db_sniffer(packet_info):
    conn = get_db_connection_sniffer()
    conn.execute(
        "INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, source_port, destination_port, packet_length, info) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (packet_info['timestamp'], packet_info['source_ip'], packet_info['destination_ip'],
         packet_info['protocol'], packet_info['source_port'], packet_info['destination_port'],
         packet_info['packet_length'], packet_info['info'])
    )
    conn.commit()
    conn.close()

def add_alert_to_db_sniffer(alert_message, packet_data):
    conn = get_db_connection_sniffer()
    conn.execute(
        "INSERT INTO alerts (timestamp, alert_message, source_ip, destination_ip, protocol, source_port, destination_port, packet_length, attack_type, severity, geo, suggestion, full_packet_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
         alert_message,
         packet_data.get('source_ip'), # Use 'source_ip' from parsed_packet
         packet_data.get('destination_ip'), # Use 'destination_ip' from parsed_packet
         packet_data.get('protocol'),
         packet_data.get('source_port'),
         packet_data.get('destination_port'),
         packet_data.get('packet_length'),
         packet_data.get('attack_type'),
         packet_data.get('severity'),
         packet_data.get('geo'),
         packet_data.get('suggestion'),
         json.dumps(packet_data))
    )
    conn.commit()
    conn.close()

def set_queues(p_q, a_q, f_q):
    global packet_output_queue, alert_output_queue, filter_input_queue
    packet_output_queue = p_q
    alert_output_queue = a_q
    filter_input_queue = f_q
    print(f"Sniffer: Queues set in child process.", file=sys.stderr)

def set_sniffing_state(state):
    global SNIFFING_ACTIVE
    SNIFFING_ACTIVE = state
    print(f"Sniffer: Sniffing state set to {state}", file=sys.stderr)

def set_filters(filter_params):
    global current_live_filter
    current_live_filter = filter_params
    print(f"Sniffer: Live filter updated: {current_live_filter}", file=sys.stderr)

def parse_packet_data(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    src_ip = "N/A"
    dst_ip = "N/A"
    protocol = "N/A"
    src_port = "N/A"
    dst_port = "N/A"
    packet_length = len(packet)
    info = ""
    payload_raw = b"" # Store raw payload bytes
    ttl = "N/A"
    id_field = "N/A" # IP ID field

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl = packet[IP].ttl
        id_field = packet[IP].id # IP ID
        proto_map = {
            1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH",
            89: "OSPF", 132: "SCTP"
        }
        protocol = proto_map.get(packet[IP].proto, f"IP_PROTO_{packet[IP].proto}")

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            info = packet[TCP].summary()
            if Raw in packet:
                payload_raw = bytes(packet[Raw].load)
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            info = packet[UDP].summary()
            if Raw in packet:
                payload_raw = bytes(packet[Raw].load)
        elif ICMP in packet:
            protocol = "ICMP"
            info = packet[ICMP].summary()
            if Raw in packet:
                payload_raw = bytes(packet[Raw].load)
    elif ARP in packet:
        protocol = "ARP"
        src_ip = packet[ARP].psrc if packet.haslayer(ARP) else "N/A"
        dst_ip = packet[ARP].pdst if packet.haslayer(ARP) else "N/A"
        info = packet[ARP].summary()
    elif Ether in packet: # Handle pure Ethernet frames
        protocol = "Ethernet"
        src_ip = packet[Ether].src # MAC address
        dst_ip = packet[Ether].dst # MAC address
        info = packet[Ether].summary()
        # You might want to distinguish MACs from IPs in the UI
        # For simplicity, keeping in same columns for now.

    payload_snippet = payload_raw.decode('utf-8', errors='replace')[:100] + "..." if len(payload_raw) > 100 else payload_raw.decode('utf-8', errors='replace')

    return {
        'timestamp': timestamp,
        'source_ip': src_ip,
        'destination_ip': dst_ip,
        'protocol': protocol,
        'source_port': str(src_port),
        'destination_port': str(dst_port),
        'packet_length': packet_length,
        'info': str(info),
        'payload_snippet': payload_snippet,
        'payload_raw': payload_raw.hex(), # Store raw payload as hex for full detail if needed
        'ttl': ttl,
        'id_field': id_field # IP ID field
    }

def apply_traffic_filter(packet_data):
    """
    Applies the live filter query from the UI search bar.
    The query can contain keywords, IPs, ports, or protocol names.
    Returns True if packet should be displayed/processed, False otherwise.
    """
    query = current_live_filter["query"].lower()
    only_filtered = current_live_filter["only_filtered"]
    packet_matches_filter = False

    if not query:
        packet_matches_filter = True
    else:
        # Try matching against various fields
        if query in packet_data['source_ip'].lower() or \
           query in packet_data['destination_ip'].lower() or \
           query in packet_data['protocol'].lower() or \
           query in packet_data['source_port'].lower() or \
           query in packet_data['destination_port'].lower() or \
           query in packet_data['payload_snippet'].lower() or \
           query in packet_data['info'].lower():
            packet_matches_filter = True
        elif query.startswith("ip:") and (query.split(":")[1] == packet_data['source_ip'].lower() or query.split(":")[1] == packet_data['destination_ip'].lower()):
            packet_matches_filter = True
        elif query.startswith("port:") and (packet_data['source_port'] == query.split(":")[1] or packet_data['destination_port'] == query.split(":")[1]):
            packet_matches_filter = True
        elif query.startswith("protocol:") and packet_data['protocol'].lower() == query.split(":")[1]:
            packet_matches_filter = True
        # Add more specific checks if needed

    if only_filtered and not packet_matches_filter:
        return False, "" # No user filter match concept anymore

    return packet_matches_filter, ""

def process_and_queue_packet(packet):
    global SNIFFING_ACTIVE, packet_output_queue, alert_output_queue, filter_input_queue

    if not SNIFFING_ACTIVE:
        return

    # Check for filter updates from the main process
    try:
        while True: # Process all pending filter commands
            command_data = filter_input_queue.get_nowait()
            if command_data.get("command") == "stop":
                set_sniffing_state(False)
                return # Stop processing this packet as sniffing is ending
            elif command_data.get("command") == "filter":
                set_filters({"query": command_data.get("query", ""), "only_filtered": command_data.get("only_filtered", False)})
            print(f"Sniffer: Processed command: {command_data.get('command')}", file=sys.stderr)
    except queue.Empty:
        pass # No new filter commands

    # If sniffing just stopped, return
    if not SNIFFING_ACTIVE:
        return

    parsed_packet = parse_packet_data(packet)

    # Apply live UI filter (and check for user_filter_match for display)
    should_display_live, user_filter_match_info = apply_traffic_filter(parsed_packet)
    parsed_packet['user_filter_match'] = user_filter_match_info # Pass this to UI

    if not should_display_live:
        return # Do not send to frontend if filtered out by live search bar

    # Extract payload for analysis
    payload = ""
    if 'payload_raw' in parsed_packet and parsed_packet['payload_raw']:
        payload = bytes.fromhex(parsed_packet['payload_raw']).decode('utf-8', errors='replace')


    # Analyze payload (using analyzer.py functions)
    label, attack_type, severity, suggestion = analyze_payload(payload)
    geo = get_geo(parsed_packet['source_ip']) if label == "Malicious" else "N/A"

    parsed_packet['label'] = label
    parsed_packet['attack_type'] = attack_type
    parsed_packet['severity'] = severity
    parsed_packet['geo'] = geo
    parsed_packet['suggestion'] = suggestion

    # Add to internal database (packets table)
    add_packet_to_db_sniffer(parsed_packet)

    # Send to packet queue for live traffic page
    if packet_output_queue:
        try:
            packet_output_queue.put_nowait(parsed_packet)
        except queue.Full:
            pass # print("Sniffer: Packet queue is full, dropping packet.", file=sys.stderr)

    # If malicious, also send to alert queue and log to file
    if label == "Malicious":
        alert_message = f"Malicious Traffic Detected: {attack_type} from {parsed_packet['source_ip']} ({geo})"
        # Store comprehensive alert data in DB
        add_alert_to_db_sniffer(alert_message, parsed_packet)
        log_alert(parsed_packet['source_ip'], parsed_packet['destination_ip'], payload, attack_type, severity, geo, suggestion)

        if alert_output_queue:
            try:
                alert_output_queue.put_nowait({
                    'alert_message': alert_message,
                    'timestamp': parsed_packet['timestamp'],
                    'src_ip': parsed_packet['source_ip'],
                    'dst_ip': parsed_packet['destination_ip'],
                    'attack_type': attack_type,
                    'severity': severity,
                    'geo': geo,
                    'suggestion': suggestion,
                    'protocol': parsed_packet['protocol'],
                    'source_port': parsed_packet['source_port'],
                    'destination_port': parsed_packet['destination_port'],
                    'packet_length': parsed_packet['packet_length']
                })
            except queue.Full:
                pass # print("Sniffer: Alert queue is full, dropping alert.", file=sys.stderr)

    # Log to CSV (always)
    log_label(parsed_packet['timestamp'], parsed_packet['source_ip'], parsed_packet['destination_ip'],
              label, attack_type, severity, geo, suggestion, user_filter_match_info)

def start_sniffing(interface=None): # Add interface parameter
   global SNIFFING_ACTIVE
   print(f"Sniffer process starting sniff loop on interface: {interface}", file=sys.stderr)
   try:
       sniff(prn=process_and_queue_packet, store=False, filter="ip", timeout=0.1, stop_filter=lambda x: not SNIFFING_ACTIVE, iface=interface) # Use the parameter
   except Exception as e:
       print(f"Sniffing error on interface {interface}: {e}", file=sys.stderr)
   finally:
       print("Sniffer process finished sniffing.", file=sys.stderr)

if __name__ == "__main__":
   # For direct testing, you can specify the interface here
   # from multiprocessing import Queue
   # p_q = Queue()
   # a_q = Queue()
   # f_q = Queue()
   # set_queues(p_q, a_q, f_q)
   # set_sniffing_state(True)
   # print("Starting sniffing for direct test...", file=sys.stderr)
   # start_sniffing(interface="your_interface_name") # Replace with your interface
   # print("Direct test sniffing stopped.", file=sys.stderr)