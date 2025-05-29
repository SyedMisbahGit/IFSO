CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    source_port TEXT,
    destination_port TEXT,
    packet_length INTEGER,
    info TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    alert_message TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    source_port TEXT,
    destination_port TEXT,
    packet_length INTEGER,
    attack_type TEXT,
    severity TEXT,
    geo TEXT,
    suggestion TEXT,
    full_packet_info TEXT
);

-- RE-INTRODUCED user_rules table
CREATE TABLE IF NOT EXISTS user_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_content TEXT NOT NULL UNIQUE, -- Store the rule (e.g., "facebook.com", "1.2.3.4", "malicious_keyword")
    created_at TEXT NOT NULL
);