CREATE TABLE threat_cache(
observable TEXT PRIMARY KEY,
indicator_type TEXT,
reputation_score INTEGER,
last_seen TEXT,
provider_rawdata TEXT );