-- schema.sql

-- Existing tables
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    packet_length INTEGER,
    info TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    alert_message TEXT NOT NULL,
    packet_info TEXT -- Store relevant packet data as JSON or string
);

-- New table for user-defined rules
CREATE TABLE IF NOT EXISTS user_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL UNIQUE,
    rule_type TEXT NOT NULL, -- 'block' or 'alert'
    target_protocol TEXT,    -- e.g., 'tcp', 'udp', 'all'
    target_ip TEXT,          -- e.g., '192.168.1.1', 'any'
    target_port INTEGER,     -- e.g., 80, 443, 'any'
    direction TEXT           -- 'inbound', 'outbound', 'both' (for 'block' rules)
);