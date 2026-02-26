CREATE TABLE threat_cache(
observable TEXT PRIMARY KEY,
indicator_type TEXT,
pulse_count INTEGER,
last_seen TEXT,
provider_rawdata TEXT,
threat_score INTEGER );