import sqlite3
import os
from datetime import datetime
import json

DATABASE = 'ids.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_app(app):
    pass

def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print("Database initialized/updated based on schema.sql.")

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

def add_alert_to_db(alert_message, packet_data):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO alerts (timestamp, alert_message, source_ip, destination_ip, protocol, source_port, destination_port, packet_length, attack_type, severity, geo, suggestion, full_packet_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
         alert_message,
         packet_data.get('src_ip'),
         packet_data.get('dst_ip'),
         packet_data.get('proto'),
         packet_data.get('src_port'),
         packet_data.get('dst_port'),
         packet_data.get('packet_length'),
         packet_data.get('attack_type'),
         packet_data.get('severity'),
         packet_data.get('geo'),
         packet_data.get('suggestion'),
         json.dumps(packet_data))
    )
    conn.commit()
    conn.close()

def get_packets(limit=500):
    conn = get_db_connection()
    packets = conn.execute("SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in packets]

def get_alerts(limit=200):
    conn = get_db_connection()
    alerts = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in alerts]

# RE-INTRODUCED USER RULE FUNCTIONS
def add_user_rule(rule_content):
    conn = get_db_connection()
    cursor = conn.execute("INSERT INTO user_rules (rule_content, created_at) VALUES (?, ?)",
                   (rule_content, datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]))
    conn.commit()
    rule_id = cursor.lastrowid
    conn.close()
    return rule_id

def get_user_rules():
    conn = get_db_connection()
    rules = conn.execute("SELECT id, rule_content FROM user_rules ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rules]

def delete_user_rule(rule_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM user_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()