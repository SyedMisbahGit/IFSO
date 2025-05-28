# database.py
import sqlite3
import os
from datetime import datetime # ADDED: Import datetime here

# IMPORTANT: Ensure this matches the DATABASE path in main.py
DATABASE = 'ids.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # This allows accessing columns by name
    return conn

# init_app is kept for consistency but doesn't do much in this direct-access model
def init_app(app):
    """
    Placeholder for Flask app initialization if database connection
    were managed via Flask's app context (e.g., g.db).
    For direct function calls opening/closing connections, it's not strictly needed.
    """
    pass

def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print("Database initialized/updated based on schema.sql.")

# RENAMED from insert_packet to add_packet_to_db
def add_packet_to_db(packet_info):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, source_port, destination_port, packet_length, info) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (packet_info['timestamp'], packet_info['source_ip'], packet_info['destination_ip'],
         packet_info['protocol'], packet_info['source_port'], packet_info['destination_port'],
         packet_info['packet_length'], packet_info['info'])
    )
    conn.commit()
    conn.close()

# RENAMED from insert_alert to add_alert_to_db
def add_alert_to_db(alert_message, packet_info_json):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO alerts (timestamp, alert_message, packet_info) VALUES (?, ?, ?)",
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], alert_message, packet_info_json)
    )
    conn.commit()
    conn.close()

# ADDED or CORRECTED get_packets
def get_packets(limit=100):
    conn = get_db_connection()
    # Order by timestamp descending to get most recent packets first
    packets = conn.execute("SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    # Convert sqlite3.Row objects to dictionaries for easier JSON serialization in Flask
    return [dict(row) for row in packets]

# ADDED or CORRECTED get_alerts
def get_alerts(limit=100):
    conn = get_db_connection()
    # Order by timestamp descending to get most recent alerts first
    alerts = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    # Convert sqlite3.Row objects to dictionaries
    return [dict(row) for row in alerts]

def add_user_rule(rule_name, rule_type, target_protocol, target_ip, target_port, direction):
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO user_rules (rule_name, rule_type, target_protocol, target_ip, target_port, direction) VALUES (?, ?, ?, ?, ?, ?)",
            (rule_name, rule_type, target_protocol, target_ip, target_port, direction)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        print(f"Rule with name '{rule_name}' already exists.")
        return False
    finally:
        conn.close()

def get_user_rules():
    conn = get_db_connection()
    rules = conn.execute("SELECT * FROM user_rules").fetchall()
    conn.close()
    return [dict(row) for row in rules]

def delete_user_rule(rule_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM user_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()