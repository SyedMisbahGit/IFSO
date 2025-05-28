# main.py
import subprocess
import threading
import time
from datetime import datetime # ENSURE THIS IS PRESENT
import json

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Ensure Scapy imports are correct for the layers you're using
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, ARP

# CORRECTED: Import all functions by their new names
from database import init_db, add_packet_to_db, add_alert_to_db, get_packets, get_alerts, add_user_rule, get_user_rules, delete_user_rule, get_db_connection


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# UNIFIED DATABASE PATH
app.config['DATABASE'] = 'ids.db' # Path to your SQLite database file

# Global flags and data structures
sniffing_active = False
packet_count = 0
# IMPORTANT: Packet limit for real-time display should be managed on client side too.
# Here, it's for buffering before sending to client.
packet_buffer_size = 10 # Emit every 10 packets
live_packets_buffer = [] # Buffer to hold packets before sending to client

# User-defined rules will be loaded from DB and used in process_packet
active_user_rules = []

# --- IPTABLES Helper Functions ---
def execute_iptables_command(command_args):
    """Executes an iptables command. Requires root privileges."""
    full_command = ['sudo', 'iptables'] + command_args
    try:
        result = subprocess.run(full_command, check=True, capture_output=True, text=True)
        print(f"IPTables command executed: {' '.join(full_command)}")
        print(f"STDOUT: {result.stdout}")
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing IPTables command: {' '.join(full_command)}")
        print(f"STDERR: {e.stderr}")
        return False, e.stderr
    except FileNotFoundError:
        print("Error: 'sudo' or 'iptables' command not found. Ensure they are in your PATH.")
        return False, "Command not found."

def apply_block_rule_iptables(rule_details):
    protocol = rule_details['target_protocol']
    ip_address = rule_details['target_ip']
    port = rule_details['target_port']
    direction = rule_details['direction'] # 'inbound', 'outbound', 'both'
    rule_name = rule_details['rule_name']

    chains_to_apply = []
    if direction == 'inbound':
        chains_to_apply = ['INPUT']
    elif direction == 'outbound':
        chains_to_apply = ['OUTPUT']
    elif direction == 'both':
        chains_to_apply = ['INPUT', 'OUTPUT']
    else:
        print(f"Invalid direction for iptables rule: {direction}")
        return False, "Invalid direction"

    all_success = True
    for chain in chains_to_apply:
        command_args = [
            '-A', chain,
            '-m', 'comment', '--comment', f'IDS_BLOCK_{rule_name.replace(" ", "_")}' # Add a comment for easier identification
        ]

        if ip_address and ip_address != 'any':
            if chain == 'INPUT': # Source IP for inbound traffic
                command_args.extend(['-s', ip_address])
            elif chain == 'OUTPUT': # Destination IP for outbound traffic
                command_args.extend(['-d', ip_address])

        if protocol and protocol != 'all':
            command_args.extend(['-p', protocol])

        if port and port != 'any':
            try:
                port_int = int(port)
                # Check for TCP/UDP specific ports
                if protocol.lower() in ['tcp', 'udp']:
                    command_args.extend(['--dport', str(port_int)])
                elif protocol == 'all': # If protocol is 'all', apply to TCP/UDP destination ports
                    command_args.extend(['-m', 'multiport', '--dports', str(port_int)])
                # For other protocols like ICMP, port isn't applicable directly like dport
            except ValueError:
                print(f"Invalid port value: {port}")
                all_success = False
                continue

        command_args.append('-j')
        command_args.append('DROP') # Drop the packet

        success, message = execute_iptables_command(command_args)
        if not success:
            add_alert_to_db(f"Failed to apply iptables block rule '{rule_name}' on chain {chain}: {message}", json.dumps({}))
            all_success = False
    return all_success, "IPTables rule(s) applied." if all_success else "Some IPTables rules failed."


def remove_block_rule_iptables(rule_details):
    protocol = rule_details['target_protocol']
    ip_address = rule_details['target_ip']
    port = rule_details['target_port']
    direction = rule_details['direction']
    rule_name = rule_details['rule_name']

    chains_to_remove = []
    if direction == 'inbound':
        chains_to_remove = ['INPUT']
    elif direction == 'outbound':
        chains_to_remove = ['OUTPUT']
    elif direction == 'both':
        chains_to_remove = ['INPUT', 'OUTPUT']
    else:
        print(f"Invalid direction for iptables rule: {direction}")
        return False, "Invalid direction"

    all_success = True
    for chain in chains_to_remove:
        command_args = [
            '-D', chain, # Use -D for delete
            '-m', 'comment', '--comment', f'IDS_BLOCK_{rule_name.replace(" ", "_")}'
        ]

        if ip_address and ip_address != 'any':
            if chain == 'INPUT':
                command_args.extend(['-s', ip_address])
            elif chain == 'OUTPUT':
                command_args.extend(['-d', ip_address])

        if protocol and protocol != 'all':
            command_args.extend(['-p', protocol])

        if port and port != 'any':
            try:
                port_int = int(port)
                if protocol.lower() in ['tcp', 'udp']:
                    command_args.extend(['--dport', str(port_int)])
                elif protocol == 'all':
                    command_args.extend(['-m', 'multiport', '--dports', str(port_int)])
            except ValueError:
                print(f"Invalid port value: {port}")
                all_success = False
                continue

        command_args.append('-j')
        command_args.append('DROP')

        success, message = execute_iptables_command(command_args)
        if not success:
            add_alert_to_db(f"Failed to remove iptables block rule '{rule_name}' on chain {chain}: {message}", json.dumps({}))
            all_success = False
    return all_success, "IPTables rule(s) removed." if all_success else "Some IPTables rules failed to remove."

# --- Packet Processing and Sniffing ---
def parse_packet(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    src_ip = "N/A"
    dst_ip = "N/A"
    protocol = "N/A"
    src_port = "N/A"
    dst_port = "N/A"
    packet_length = len(packet)
    info = ""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Map IP protocol numbers to names for better readability
        proto_map = {
            1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH",
            89: "OSPF", 132: "SCTP"
        }
        protocol = proto_map.get(packet[IP].proto, f"IP_PROTO_{packet[IP].proto}")

        if TCP in packet:
            protocol = "TCP" # Override if specific layer found
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            info = packet[TCP].summary()
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            info = packet[UDP].summary()
        elif ICMP in packet:
            protocol = "ICMP"
            info = packet[ICMP].summary()
    elif ARP in packet:
        protocol = "ARP"
        src_ip = packet[ARP].psrc if packet.haslayer(ARP) else "N/A"
        dst_ip = packet[ARP].pdst if packet.haslayer(ARP) else "N/A"
        info = packet[ARP].summary()
    elif Ether in packet:
        protocol = "Ethernet"
        src_ip = packet[Ether].src
        dst_ip = packet[Ether].dst
        info = packet[Ether].summary()

    return {
        'timestamp': timestamp,
        'source_ip': src_ip,
        'destination_ip': dst_ip,
        'protocol': protocol,
        'source_port': str(src_port), # Store as string to handle N/A gracefully
        'destination_port': str(dst_port), # Store as string
        'packet_length': packet_length,
        'info': str(info)
    }


def process_packet(packet):
    global packet_count
    global live_packets_buffer

    parsed_packet = parse_packet(packet)
    add_packet_to_db(parsed_packet)

    # --- Dynamic Alerting based on User Rules ---
    for rule in active_user_rules:
        if rule['rule_type'] == 'alert':
            match = True
            # Check protocol
            if rule['target_protocol'] and rule['target_protocol'] != 'all' and parsed_packet['protocol'].lower() != rule['target_protocol'].lower():
                match = False
            # Check IP (source or destination, depending on context)
            if rule['target_ip'] and rule['target_ip'] != 'any':
                # Match if source OR destination IP matches the rule's target IP
                if not (parsed_packet['source_ip'] == rule['target_ip'] or parsed_packet['destination_ip'] == rule['target_ip']):
                    match = False
            # Check Port (source or destination)
            if rule['target_port'] and rule['target_port'] != 'any':
                try:
                    target_port_str = str(rule['target_port']) # Ensure it's a string for comparison
                    if not (parsed_packet['source_port'] == target_port_str or parsed_packet['destination_port'] == target_port_str):
                        match = False
                except ValueError:
                    pass # Invalid port in rule, ignore for now

            if match:
                alert_msg = f"User Alert: Rule '{rule['rule_name']}' matched on {parsed_packet['protocol']} traffic from {parsed_packet['source_ip']}:{parsed_packet['source_port']} to {parsed_packet['destination_ip']}:{parsed_packet['destination_port']}"
                add_alert_to_db(alert_msg, json.dumps(parsed_packet)) # Store original packet info with alert
                socketio.emit('new_alert', {'message': alert_msg}, broadcast=True) # Broadcast alert


    packet_count += 1
    # Add to buffer
    live_packets_buffer.append(parsed_packet)

    # Emit packets to client in batches or when buffer exceeds a size
    if len(live_packets_buffer) >= packet_buffer_size:
        socketio.emit('new_packet', live_packets_buffer, broadcast=True) # Broadcast packet list
        live_packets_buffer = [] # Clear buffer after emitting

# Sniffing Thread Management ---
sniff_thread = None
def start_sniffing_thread_func():
    global sniffing_active
    print("Sniffing started...")
    sniffing_active = True
    try:
        # Using a timeout to allow the stop_filter to be checked more frequently
        # Note: If traffic is very sparse, `timeout` can introduce latency for stopping.
        # For very high performance, consider `socket.timeout` or `select.select` with raw sockets.
        sniff(prn=process_packet, store=0, timeout=1, stop_filter=lambda x: not sniffing_active)
    except Exception as e:
        print(f"Error during sniffing: {e}")
        sniffing_active = False # Ensure flag is set to False on error
    finally:
        print("Sniffing thread finished.")


def stop_sniffing():
    global sniffing_active
    sniffing_active = False
    print("Signaling sniffing thread to stop...")

def reload_active_user_rules():
    global active_user_rules
    active_user_rules = get_user_rules()
    print(f"Reloaded active user rules: {active_user_rules}")


# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_sniff')
def start_sniff():
    global sniffing_active, sniff_thread
    if not sniffing_active:
        # Ensure only one sniffing thread is active
        if sniff_thread is None or not sniff_thread.is_alive():
            sniff_thread = threading.Thread(target=start_sniffing_thread_func, daemon=True)
            sniff_thread.start()
            return jsonify({"status": "Sniffing started."})
        else:
            return jsonify({"status": "Sniffing already running."})
    return jsonify({"status": "Sniffing already active."})

@app.route('/stop_sniff')
def stop_sniff_route(): # Renamed to avoid clash with internal stop_sniff function
    stop_sniffing()
    # Give a brief moment for the thread to terminate gracefully
    if sniff_thread and sniff_thread.is_alive():
        sniff_thread.join(timeout=2)
    return jsonify({"status": "Sniffing stopped."})

@app.route('/get_historical_packets')
def get_historical_packets():
    # Frontend will pass limit if needed, defaulting to 100 in get_packets
    packets = get_packets(limit=500) # Fetch more for initial display
    return jsonify(packets)

@app.route('/get_alerts')
def get_historical_alerts():
    # Frontend will pass limit if needed, defaulting to 100 in get_alerts
    alerts = get_alerts(limit=200) # Fetch more for initial display
    return jsonify(alerts)

@app.route('/add_rule', methods=['POST'])
def add_rule():
    data = request.json
    rule_name = data.get('rule_name')
    rule_type = data.get('rule_type') # 'block' or 'alert'
    target_protocol = data.get('target_protocol')
    target_ip = data.get('target_ip')
    target_port = data.get('target_port')
    direction = data.get('direction') # For block rules

    if not rule_name or not rule_type:
        return jsonify({"status": "error", "message": "Rule name and type are required."}), 400

    # Sanitize inputs for database and iptables
    target_protocol = target_protocol if target_protocol and target_protocol.lower() != 'all' else None
    target_ip = target_ip if target_ip and target_ip.lower() != 'any' else None
    target_port = int(target_port) if target_port and str(target_port).isdigit() and int(target_port) > 0 else None
    direction = direction if direction else 'inbound' # Default for block rules

    success = add_user_rule(rule_name, rule_type, target_protocol, target_ip, target_port, direction)

    if success:
        reload_active_user_rules() # Reload rules for IDS logic
        if rule_type == 'block':
            rule_details = {
                'rule_name': rule_name,
                'target_protocol': target_protocol,
                'target_ip': target_ip,
                'target_port': target_port,
                'direction': direction
            }
            iptables_applied, msg = apply_block_rule_iptables(rule_details)
            if iptables_applied:
                return jsonify({"status": "success", "message": f"Rule '{rule_name}' added and iptables rule applied."})
            else:
                return jsonify({"status": "warning", "message": f"Rule '{rule_name}' added, but iptables rule failed to apply: {msg}"}), 202
        else:
            return jsonify({"status": "success", "message": f"Rule '{rule_name}' added."})
    else:
        return jsonify({"status": "error", "message": f"Rule '{rule_name}' already exists or another DB error occurred."}), 409

@app.route('/delete_rule/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    conn = get_db_connection()
    rule_row = conn.execute("SELECT * FROM user_rules WHERE id = ?", (rule_id,)).fetchone()
    conn.close()

    if rule_row:
        rule_details = dict(rule_row)
        delete_user_rule(rule_id)
        reload_active_user_rules() # Reload rules for IDS logic

        if rule_details['rule_type'] == 'block':
            iptables_removed, msg = remove_block_rule_iptables(rule_details)
            if iptables_removed:
                return jsonify({"status": "success", "message": f"Rule '{rule_details['rule_name']}' deleted and iptables rule removed."})
            else:
                return jsonify({"status": "warning", "message": f"Rule '{rule_details['rule_name']}' deleted, but iptables rule failed to remove: {msg}"}), 202
        else:
            return jsonify({"status": "success", "message": f"Rule '{rule_details['rule_name']}' deleted."})
    else:
        return jsonify({"status": "error", "message": "Rule not found."}), 404

@app.route('/get_rules')
def get_rules_endpoint():
    rules = get_user_rules()
    return jsonify(rules)

@socketio.on('connect')
def test_connect():
    print('Client connected')
    # When a client connects, send them the current buffered packets (if any)
    if live_packets_buffer:
        emit('new_packet', list(live_packets_buffer), broadcast=False) # Only send to connecting client

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    # Initialize the database and tables based on schema.sql
    init_db() # Call init_db from database.py to create tables
    reload_active_user_rules() # Load existing rules on startup
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host='0.0.0.0', port=5000)