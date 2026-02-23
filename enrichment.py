from dotenv import load_dotenv
import os
import requests
import json
from db_interface import lookup_indicator , store_enrichment
import time
import re

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

if not OTX_API_KEY:
    raise ValueError("OTX_API_KEY not set")


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
    store_enrichment(ip, ind_type, pulse_count, threat_score, raw_json)

    return{
         "threat_score": threat_score,          
         "pulse_count": pulse_count,
        }

def enrich_ip_otx(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return None

    data = response.json()
    pulse_count = data.get("pulse_info",{}).get("count",0)

    return pulse_count,json.dumps(data)

def calculate_risk(pulse_count,raw_json):
    score = 0
    data = json.loads(raw_json)

    if pulse_count > 0:
        score = min(2 * pulse_count, 70)
    
    pulses = data.get("pulse_info" , {}).get("pulses" , [])
    for pulse in pulses:
        tags = [tag.lower() for tag in pulse.get("tag",[])]
        if any(keyword in tags for keyword in ["c2","malware","ransomware","attack","compromise"]):
            score+=20
    return min(score, 100)

def process_log(filename):
    results_list = []

    with open(filename, "r") as file:
        IPs = [line.strip() for line in file if line.strip()]
    print(f"Starting batch process for {len(IPs)} indicators...")

    for ip in IPs:

        result = threat_check(ip)


        if result:
            print(f"[+] Processed {ip} | Score: {result['pulse_count']}")
            # We save this for the PDF generator later
            results_list.append({"ip": ip, "data": result})

    return results_list


def identify_ioc_type(indicator):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        return "IPv4"
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "FileHash-SHA256"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", indicator):
        return "Domain"
    return "URL"
    

if __name__ == "__main__":
    test_ip = "11.11.11.11"
    res = process_log("targets.txt")
    print(res)