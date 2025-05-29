import subprocess
import threading
import time
from datetime import datetime
import json
import multiprocessing

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

from database import init_db, add_packet_to_db, add_alert_to_db, get_packets, get_alerts, \
                     add_user_rule, get_user_rules, delete_user_rule # Re-import user rule functions
from logger import log_alert, log_label, setup_logs

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

app.config['DATABASE'] = 'ids.db'

sniffing_process = None
sniffing_active = False
packet_queue = multiprocessing.Queue(maxsize=1000) # Increased size
alert_queue = multiprocessing.Queue(maxsize=500)   # Increased size
filter_queue = multiprocessing.Queue(maxsize=1) # For sending filter updates to sniffer

packet_buffer_size = 20 # Emit more packets at once for smoother updates
live_packets_buffer = []

# --- Background Consumer Thread ---
def consume_queues():
    global live_packets_buffer

    while True:
        # Process packets
        if not packet_queue.empty():
            try:
                packet_data = packet_queue.get_nowait()
                live_packets_buffer.append(packet_data)

                if len(live_packets_buffer) >= packet_buffer_size:
                    socketio.emit('new_packet', live_packets_buffer, broadcast=True)
                    live_packets_buffer = []

            except multiprocessing.Queue.Empty:
                pass
            except Exception as e:
                print(f"Error consuming packet queue: {e}")

        # Process alerts
        if not alert_queue.empty():
            try:
                alert_info = alert_queue.get_nowait()
                # add_alert_to_db is called within sniffer_process.py now,
                # so main just needs to emit.
                socketio.emit('new_alert', alert_info, broadcast=True)

            except multiprocessing.Queue.Empty:
                pass
            except Exception as e:
                print(f"Error consuming alert queue: {e}")

        time.sleep(0.01)

def start_sniffer_process(packet_q, alert_q, filter_q, initial_user_rules=None, interface=None): # Add interface
   from sniffer_process import set_queues, set_sniffing_state, set_filters, start_sniffing # Remove user rules import
   set_queues(packet_q, alert_q, filter_q)
   set_sniffing_state(True)
   set_filters({"query": "", "only_filtered": False})
   print(f"Child sniffer process initiated on interface: {interface}. Calling start_sniffing()...", flush=True)
   start_sniffing(interface=interface) # Pass the interface
   print("Child sniffer process start_sniffing() returned.", flush=True)

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_sniff')
def start_sniff():
   global sniffing_active, sniffing_process, packet_queue, alert_queue, filter_queue
   if not sniffing_active:
       print("Attempting to start sniffing process...")
       # ... queue clearing ...

       interface_to_sniff = None # You might want to get this from a config or UI later
       print(f"Attempting to sniff on interface: {interface_to_sniff}")

       sniffing_process = multiprocessing.Process(
           target=start_sniffer_process,
           args=(packet_queue, alert_queue, filter_queue, None, interface_to_sniff) # Pass None for rules, and the interface
       )
       sniffing_process.daemon = True
       sniffing_process.start()
       sniffing_active = True
       print(f"Sniffing process started with PID: {sniffing_process.pid}")
       return jsonify({"status": "Sniffing started."})
   return jsonify({"status": "Sniffing already active."})

def start_sniffer_process(packet_q, alert_q, filter_q, initial_user_rules):
    from sniffer_process import set_queues, set_sniffing_state, set_filters, start_sniffing, set_user_rules_sniff_process
    set_queues(packet_q, alert_q, filter_q)
    set_sniffing_state(True)
    # Set initial rules and an empty live filter
    set_filters({"query": "", "only_filtered": False}) # Reset live filter
    set_user_rules_sniff_process(initial_user_rules) # Set user rules from DB
    print("Child sniffer process initiated. Calling start_sniffing()...", flush=True)
    start_sniffing()
    print("Child sniffer process start_sniffing() returned.", flush=True)

@app.route('/stop_sniff')
def stop_sniff_route():
    global sniffing_active, sniffing_process
    if sniffing_active and sniffing_process and sniffing_process.is_alive():
        print("Attempting to stop sniffing process...")
        # A more robust way to stop would be to send a signal via a queue
        # For this example, we send a specific 'stop' command via the filter queue
        try:
            filter_queue.put_nowait({"command": "stop"})
        except multiprocessing.Queue.Full:
            print("Filter queue full, direct terminate instead for stop.")
            sniffing_process.terminate()

        sniffing_process.join(timeout=5)
        sniffing_active = False
        print("Sniffing process stopped.")
        return jsonify({"status": "Sniffing stopped."})
    return jsonify({"status": "Sniffing not active."})

@app.route('/get_historical_packets')
def get_historical_packets():
    packets = get_packets(limit=500)
    return jsonify(packets)

@app.route('/get_alerts')
def get_historical_alerts():
    alerts = get_alerts(limit=200)
    processed_alerts = []
    for alert in alerts:
        alert_dict = dict(alert)
        # These fields are now directly stored in the DB, so no need to parse full_packet_info
        # unless more deep dive is needed.
        processed_alerts.append(alert_dict)
    return jsonify(processed_alerts)

@app.route('/set_live_filter', methods=['POST'])
def set_live_filter_route():
    global filter_queue
    data = request.get_json()
    query = data.get('query', '').lower()
    only_filtered = data.get('only_filtered', False)
    print(f"Received filter request: Query='{query}', Only Filtered={only_filtered}")

    try:
        # Clear any existing filter command before adding a new one
        while not filter_queue.empty():
            try: filter_queue.get_nowait()
            except: pass
        filter_queue.put_nowait({"command": "filter", "query": query, "only_filtered": only_filtered})
        return jsonify({"status": "Live filter updated successfully."})
    except multiprocessing.Queue.Full:
        return jsonify({"status": "Error: Filter update queue is full. Try again."}), 503
    except Exception as e:
        return jsonify({"status": f"Error setting filter: {e}"}), 500

# RE-INTRODUCED USER RULE ROUTES
@app.route('/add_rule', methods=['POST'])
def add_rule():
    data = request.get_json()
    rule_content = data.get('rule_content')
    if not rule_content:
        return jsonify({"status": "Rule content is required."}), 400
    try:
        rule_id = add_user_rule(rule_content)
        # Update sniffer with new rules immediately
        all_rules = [rule['rule_content'] for rule in get_user_rules()]
        try:
            while not filter_queue.empty():
                try: filter_queue.get_nowait()
                except: pass
            filter_queue.put_nowait({"command": "user_rules_update", "rules": all_rules})
        except multiprocessing.Queue.Full:
            print("Filter queue full on rule add, sniffer rules might be stale until next sync.")
        return jsonify({"status": "Rule added.", "id": rule_id})
    except sqlite3.IntegrityError:
        return jsonify({"status": "Rule already exists."}), 409
    except Exception as e:
        return jsonify({"status": f"Error adding rule: {e}"}), 500

@app.route('/get_rules')
def get_rules():
    rules = get_user_rules()
    return jsonify(rules)

@app.route('/delete_rule/<int:rule_id>', methods=['POST'])
def delete_rule_route(rule_id):
    try:
        delete_user_rule(rule_id)
        # Update sniffer with new rules immediately
        all_rules = [rule['rule_content'] for rule in get_user_rules()]
        try:
            while not filter_queue.empty():
                try: filter_queue.get_nowait()
                except: pass
            filter_queue.put_nowait({"command": "user_rules_update", "rules": all_rules})
        except multiprocessing.Queue.Full:
            print("Filter queue full on rule delete, sniffer rules might be stale until next sync.")
        return jsonify({"status": "Rule deleted."})
    except Exception as e:
        return jsonify({"status": f"Error deleting rule: {e}"}), 500

@socketio.on('connect')
def test_connect():
    print('Client connected')
    global live_packets_buffer
    if live_packets_buffer:
        emit('new_packet', list(live_packets_buffer), broadcast=False)

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    init_db()
    setup_logs()
    consumer_thread = threading.Thread(target=consume_queues, daemon=True)
    consumer_thread.start()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, host='0.0.0.0', port=5001)

    if sniffing_process and sniffing_process.is_alive():
        print("Main app shutting down. Terminating sniffing process...")
        try:
            filter_queue.put_nowait({"command": "stop"}) # Graceful stop attempt
        except multiprocessing.Queue.Full:
            pass # If queue is full, will force terminate
        sniffing_process.terminate()
        sniffing_process.join(timeout=5)