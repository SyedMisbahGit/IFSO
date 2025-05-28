# analyzer.py
import re
import requests
from signatures import attack_signatures

def get_geo(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return f"{res.get('city', 'Unknown')}, {res.get('country', 'Unknown')}"
    except:
        return "Unknown"

def analyze_payload(payload):
    payload = payload.lower()
    for pattern, (attack_type, severity, suggestion) in attack_signatures.items():
        if re.search(pattern, payload):
            return "Malicious", attack_type, severity, suggestion
    return "Benign", "", "", ""

def severity_color(severity, Fore, Style):
    if severity == "High":
        return Fore.RED + severity + Style.RESET_ALL
    elif severity == "Medium":
        return Fore.YELLOW + severity + Style.RESET_ALL
    elif severity == "Low":
        return Fore.CYAN + severity + Style.RESET_ALL
    else:
        return severity
