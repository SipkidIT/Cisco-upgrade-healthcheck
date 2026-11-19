CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    device_type VARCHAR(20) NOT NULL, -- 'switch' or 'router'
    platform VARCHAR(50) DEFAULT 'cisco_ios',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS health_snapshots (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    phase VARCHAR(10) NOT NULL CHECK (phase IN ('PRE', 'POST')),
    captured_at TIMESTAMPTZ DEFAULT NOW(),
    interfaces_json JSONB,
    arp_table_json JSONB,
    mac_table_json JSONB,  -- Includes enriched OUI vendor mapping
    running_config TEXT
);

