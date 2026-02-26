from dotenv import load_dotenv
import os
import requests
import json
from db_interface import lookup_indicator , store_enrichment
import time
import ipaddress

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

if not OTX_API_KEY:
    raise ValueError("OTX_API_KEY not set")

def process_log(filename):
    results_list = []

    with open(filename, "r") as file:
        IPs = [line.strip() for line in file if line.strip()]
    print(f"Starting batch process for {len(IPs)} indicators...")

    for ip in IPs:

        result = threat_check(ip)


        if result:
            print(f"[+] Processed {ip} | Pulse Count: {result['pulse_count']} | Score: {result['threat_score']}")
            # We save this for the PDF generator later
            results_list.append({"ip": ip, "data": result})

    return results_list

def threat_check(ip):
    cached_result = lookup_indicator(ip)

    if cached_result:
        print(f"IP found in DB: {ip}")
        return cached_result

    print(f"Looking up IP in OTX...")
    enrichment = enrich_ip_otx(ip)

    if enrichment is None:
        return None
    
    pulse_count , raw_json = enrichment
    ind_type = identify_ioc_type(ip)

    threat_score = calculate_risk(pulse_count,raw_json)
    store_enrichment(ip, ind_type, pulse_count, threat_score, json.dumps(raw_json))

    return{
         "threat_score": threat_score,          
         "pulse_count": pulse_count,
        }

def enrich_ip_otx(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    headers = {  "X-OTX-API-KEY": OTX_API_KEY  }

    pulse_count = 0
    data = []

    try:
        response = requests.get(url, headers=headers, timeout = 15)
    except requests.exceptions.Timeout:
        print(f"[!] Server Request timed out for {ip}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Network error for {ip} : {e}")
    
    if response.status_code == 401:
        print(f"[!] Invalid API key. Ending process")
        raise SystemExit(0) #exits completely
    elif response.status_code == 404:
        print(f"[!] Observable: {ip} | Not found")
        return None
    elif response.status_code == 429:
        print(f"[!] Rate limited by API. Waiting for 60seconds...")
        time.sleep(60)
        return enrich_ip_otx(ip)
    elif response.status_code != 200:
        return None

        data = response.json()
        pulse_count = data.get("pulse_info",{}).get("count",0)

    return pulse_count,data

def calculate_risk(pulse_count,raw_json):
    score = 0
    data = raw_json

    if pulse_count > 0:
        score = min(2 * pulse_count, 70)
    
    # Fix error: Data is list cannot execute .get
    if isinstance(data, dict):
        pulses = data.get("pulse_info", {}).get("pulses", [])
    else:
        pulses = []

    
    for pulse in pulses:
        pulses = data.get("pulse_info" , {}).get("pulses" , [])
        tags = [tag.lower() for tag in pulse.get("tags",[])]
        if any(keyword in tags for keyword in ["c2","malware","ransomware","attack","compromise"]):
            score+=20
    return min(score, 100)



def identify_ioc_type(indicator):
    try:
        ipaddress.IPv4Address(indicator)
    except ValueError:
        pass
    
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "URL"

    if len(indicator) == 64 and all(c in "abcdefABCDEF0123456789" for c in indicator):
        return "FileHash-SHA256"
    if len(indicator) == 32 and all(c in "abcdefABCDEF0123456789" for c in indicator):
        return "FileHash-MD5"

    if "." in indicator:
        return "Domain"
    
    return "Unknown"
    

if __name__ == "__main__":
    test_ip = "11.11.11.11"
    res = process_log("targets.txt")
    print(res)