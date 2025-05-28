# logger.py
import os
from datetime import datetime

alert_log = "alerts.log"
label_log = "packet_labels.csv"

def setup_logs():
    # Overwrite both files each time the script runs
    with open(alert_log, "w") as f:
        f.write(f"=== Alert Log Started at {datetime.now()} ===\n\n")

    # Add a new column 'user_filter_match'
    with open(label_log, "w") as f:
        f.write("timestamp,src_ip,dst_ip,label,attack_type,severity,geolocation,suggestion,user_filter_match\n")

def log_alert(src_ip, dst_ip, payload, attack_type, severity, geo, suggestion):
    with open(alert_log, "a") as f:
        f.write(f"[{datetime.now()}] [{attack_type} | Severity: {severity}] From {src_ip} ({geo}) to {dst_ip}\n")
        f.write(f"Suggestion: {suggestion}\n")
        f.write(payload + "\n\n")

# Modified to accept user_filter_match argument
def log_label(timestamp, src_ip, dst_ip, label, attack_type, severity, geo, suggestion, user_filter_match=""):
    with open(label_log, "a") as f:
        # The user_filter_match will be 'User Filter Match' or empty string
        f.write(f"{timestamp},{src_ip},{dst_ip},{label},{attack_type},{severity},{geo},{suggestion},{user_filter_match}\n")