import sqlite3
from datetime import datetime

def lookup_indicator(observable):
    with sqlite3.connect("threat_cache.db") as conn:
        cursor = conn.cursor()
        query = "SELECT pulse_count, threat_score, provider_rawdata FROM threat_cache WHERE observable = ?"
        cursor.execute(query, (observable,))
        
        # Capture the data
        result = cursor.fetchone() 

    if result:
        return {
            "pulse_count": result[0],
            "threat_score": result[1]
        }
    return None      


def store_enrichment(observable, indicator_type, pulse_count, threat_score, provider_rawdata):
    current_time = datetime.now().isoformat()

    with sqlite3.connect("threat_cache.db") as conn:
        cursor = conn.cursor()

        #Check if indicator already exists
        cursor.execute(
            "SELECT observable FROM threat_cache WHERE observable = ?",
            (observable,)
        )
        exists = cursor.fetchone()

        if exists:
            #Update existing record
            cursor.execute('''
                UPDATE threat_cache
                SET pulse_count = ?, last_seen = ?, threat_score = ?, provider_rawdata = ?
                WHERE observable = ?''', 
                (pulse_count, current_time, threat_score, provider_rawdata, observable))
        else:
            #Else insert new record
            cursor.execute('''
                INSERT INTO threat_cache (observable, indicator_type, pulse_count, last_seen, threat_score, provider_rawdata)
                VALUES (?, ?, ?, ?, ?, ?)''', 
                (observable, indicator_type, pulse_count, current_time, threat_score, provider_rawdata))

        conn.commit()
'''
#Test Script
test_ip = "8.8.8.8"

result = lookup_indicator(test_ip)

if result is None:
    print(f"{test_ip} not found. Adding to cache...")
    #Add it manually for now
    store_enrichment(test_ip, "IPv4", 0, "Initial Test Entry")
else:
    print(f"Success! Found {test_ip} with score: {result['reputation_score']}")'''