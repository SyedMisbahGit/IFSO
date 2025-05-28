from scapy.all import sniff, wrpcap, IP, TCP, UDP
from datetime import datetime
from analyzer import analyze_payload, get_geo
from logger import log_alert, log_label
import sys
import json
import queue

SNIFFING_ACTIVE = False
# PACKETS_BUFFER = [] # No longer needed for web display as we stream directly
MAX_BUFFER_SIZE = 1000 # Still useful if we re-introduce local buffering for AI agent, etc.

current_filters = {
    "target_ips": [],
    "monitor_ports": [],
    "keywords": [],
    "only_filtered": False
}

# Now two separate queues
packet_output_queue = None
alert_output_queue = None

def set_queues(p_q, a_q): # New function to set both queues
    global packet_output_queue, alert_output_queue
    packet_output_queue = p_q
    alert_output_queue = a_q

def set_sniffing_state(state):
    global SNIFFING_ACTIVE
    SNIFFING_ACTIVE = state

def set_filters(filters_dict):
    global current_filters
    current_filters = filters_dict

def log_packet_for_web(packet):
    global SNIFFING_ACTIVE

    if not SNIFFING_ACTIVE:
        return

    src_ip = packet[IP].src if packet.haslayer(IP) else 'N/A'
    dst_ip = packet[IP].dst if packet.haslayer(IP) else 'N/A'
    proto = packet.proto if hasattr(packet, 'proto') else 'N/A'
    ttl = packet.ttl if hasattr(packet, 'ttl') else 'N/A'

    payload = ""
    try:
        raw = bytes(packet.payload)
        payload = raw.decode('utf-8', errors='replace')
    except Exception:
        pass

    # --- Filtering Logic ---
    packet_matches_filter = False
    filters_active = bool(current_filters["target_ips"] or
                          current_filters["monitor_ports"] or
                          current_filters["keywords"])

    # Determine if the packet should be logged/displayed based on filters
    should_process_for_web = True
    user_filter_match_info = ""

    if filters_active:
        if current_filters["target_ips"]:
            if src_ip in current_filters["target_ips"] or dst_ip in current_filters["target_ips"]:
                packet_matches_filter = True
                user_filter_match_info = "User Filter Match" # Mark for UI

        if current_filters["monitor_ports"]:
            if packet.haslayer(TCP):
                if packet[TCP].sport in current_filters["monitor_ports"] or packet[TCP].dport in current_filters["monitor_ports"]:
                    packet_matches_filter = True
                    user_filter_match_info = "User Filter Match"
            elif packet.haslayer(UDP):
                if packet[UDP].sport in current_filters["monitor_ports"] or packet[UDP].dport in current_filters["monitor_ports"]:
                    packet_matches_filter = True
                    user_filter_match_info = "User Filter Match"

        if current_filters["keywords"] and payload:
            payload_lower = payload.lower()
            for keyword in current_filters["keywords"]:
                if keyword.lower() in payload_lower:
                    packet_matches_filter = True
                    user_filter_match_info = "User Filter Match"
                    break

        if current_filters["only_filtered"] and not packet_matches_filter:
            should_process_for_web = False # Do not process/send to web if only_filtered and no match

    if not should_process_for_web:
        return # Skip this packet if it doesn't meet the only_filtered criteria

    # --- End Filtering Logic ---

    # Analyze payload regardless of whether it matched user filter, unless only_filtered is true
    label, attack_type, severity, suggestion = analyze_payload(payload)
    geo = get_geo(src_ip) if label == "Malicious" else "N/A"

    # Log to CSV (always, or based on a different logging policy)
    # The user_filter_match_info goes to the CSV
    log_label(datetime.now(), src_ip, dst_ip, label, attack_type, severity, geo, suggestion, user_filter_match_info)

    packet_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "proto": proto,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ttl": ttl,
        "payload_snippet": payload[:100] + "..." if len(payload) > 100 else payload,
        "label": label, # 'Benign' or 'Malicious'
        "attack_type": attack_type,
        "severity": severity,
        "geo": geo,
        "suggestion": suggestion,
        "user_filter_match": user_filter_match_info # For UI indication
    }

    # Send to packet queue for live traffic page
    if packet_output_queue:
        try:
            packet_output_queue.put_nowait(packet_data)
        except queue.Full:
            pass

    # If malicious, also send to alert queue
    if label == "Malicious":
        if alert_output_queue:
            try:
                alert_output_queue.put_nowait(packet_data) # Send the full packet data as alert info
                log_alert(src_ip, dst_ip, payload, attack_type, severity, geo, suggestion) # Also log to alerts.log
            except queue.Full:
                pass


def start_sniffing():
    global SNIFFING_ACTIVE
    # print("Sniffer process started sniffing...", file=sys.stderr) # For debugging
    try:
        sniff(prn=log_packet_for_web, store=False, filter="ip") # Sniff all IP traffic
    except Exception as e:
        print(f"Sniffing error in child process: {e}", file=sys.stderr)
    # print("Sniffer process stopped sniffing.", file=sys.stderr) # For debugging

if __name__ == "__main__":
    print("Sniffer process initialized. Waiting for commands from main app...", file=sys.stderr)