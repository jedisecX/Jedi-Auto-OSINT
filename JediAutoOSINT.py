#!/usr/bin/env python3
# Jedi Security Auto-OSINT Scanner v1
# Domains: jedi-sec.com | jedi-sec.us | jedi-sec.cloud | jedi-sec.online | jedi-sec.me

import os
import sys
import time
import requests
import socket
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Create reports directory if it doesn't exist
if not os.path.exists("reports"):
    os.makedirs("reports")

# Jedi Security Banner
def banner():
    print(Fore.GREEN + """
     _____     _     _   _____                      _            
    |  __ \   | |   (_) |  __ \                    (_)           
    | |__) |__| |__  _  | |  | | ___ _ __ _ __  _ __ _  ___  ___  
    |  ___/ _ \ '_ \| | | |  | |/ _ \ '__| '_ \| '__| |/ _ \/ __| 
    | |  |  __/ |_) | | | |__| |  __/ |  | |_) | |  | |  __/\__ \ 
    |_|   \___|_.__/|_| |_____/ \___|_|  | .__/|_|  |_|\___||___/ 
                                        | |                      
                                        |_|                      
    Domains: jedi-sec.com | jedi-sec.us | jedi-sec.cloud | jedi-sec.online | jedi-sec.me
    """)

# Cinematic Startup
def cinematic_startup():
    banner()
    print(Fore.GREEN + "\nInitializing Jedi Auto-OSINT Scanner...")
    time.sleep(1)
    print("[+] Loading Core Modules...")
    time.sleep(1)
    print("[+] Establishing Secure Link...")
    time.sleep(1)
    print("[+] Ready.\n")

# Email Breach Search (Very basic example)
def email_breach_check(email):
    print(Fore.CYAN + f"\n[+] Checking breaches for email: {email}")
    # Simple dummy lookup, replace with real API/scraper later
    breaches = ["Adobe 2013 Breach", "LinkedIn 2012 Breach"]
    if "@" in email:
        print(Fore.YELLOW + f" - Potential breaches found: {', '.join(breaches)}")
        return breaches
    else:
        print(Fore.RED + " - Invalid email format.")
        return []

# Username Scanner (basic social checker)
def username_scanner(username):
    print(Fore.CYAN + f"\n[+] Searching social media for username: {username}")
    social_sites = ["https://twitter.com/", "https://instagram.com/", "https://github.com/"]
    found = []
    for site in social_sites:
        url = site + username
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(Fore.YELLOW + f" - Found at {url}")
                found.append(url)
            else:
                print(f" - Not found at {url}")
        except:
            print(Fore.RED + f" - Error connecting to {url}")
    return found

# IP Lookup
def ip_lookup(ip):
    print(Fore.CYAN + f"\n[+] Gathering IP info for: {ip}")
    try:
        host = socket.gethostbyaddr(ip)[0]
        print(Fore.YELLOW + f" - Hostname: {host}")
    except:
        host = "Unknown"
        print(Fore.RED + " - Reverse lookup failed.")

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        city = response.get("city", "N/A")
        country = response.get("country", "N/A")
        isp = response.get("isp", "N/A")
        print(Fore.YELLOW + f" - Location: {city}, {country}")
        print(Fore.YELLOW + f" - ISP: {isp}")
    except:
        city = country = isp = "N/A"
        print(Fore.RED + " - GeoIP lookup failed.")

    return {"hostname": host, "city": city, "country": country, "isp": isp}

# Domain Recon
def domain_recon(domain):
    print(Fore.CYAN + f"\n[+] Recon on domain: {domain}")
    try:
        whois_info = socket.gethostbyname(domain)
        print(Fore.YELLOW + f" - IP Address: {whois_info}")
    except:
        whois_info = "N/A"
        print(Fore.RED + " - Failed to resolve domain.")
    return {"domain": domain, "ip": whois_info}

# Phone Number Lookup (basic fake data for now)
def phone_lookup(phone):
    print(Fore.CYAN + f"\n[+] Checking info for phone number: {phone}")
    if phone.isdigit():
        print(Fore.YELLOW + " - Carrier: DummyCarrier")
        print(Fore.YELLOW + " - Region: USA (simulated)")
        return {"carrier": "DummyCarrier", "region": "USA"}
    else:
        print(Fore.RED + " - Invalid phone number.")
        return {}

# Save Report
def save_report(target, data):
    filename = f"reports/{target.replace('@','_').replace('.','_')}_report.txt"
    with open(filename, "w") as f:
        f.write(f"Jedi Security Auto-OSINT Report for {target}\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        for section, findings in data.items():
            f.write(f"--- {section} ---\n")
            if isinstance(findings, list):
                for item in findings:
                    f.write(f"{item}\n")
            elif isinstance(findings, dict):
                for key, value in findings.items():
                    f.write(f"{key}: {value}\n")
            else:
                f.write(f"{findings}\n")
            f.write("\n")
    print(Fore.GREEN + f"\n[+] Report saved to {filename}")

# Main Logic
def main():
    cinematic_startup()
    print(Fore.CYAN + "Target Types: email, username, ip, domain, phone")
    target_type = input(Fore.GREEN + "Enter target type: ").lower().strip()
    target = input(Fore.GREEN + "Enter target: ").strip()

    collected_data = {}

    if target_type == "email":
        collected_data["Breaches"] = email_breach_check(target)
    elif target_type == "username":
        collected_data["Social Media Accounts"] = username_scanner(target)
    elif target_type == "ip":
        collected_data["IP Information"] = ip_lookup(target)
    elif target_type == "domain":
        collected_data["Domain Info"] = domain_recon(target)
    elif target_type == "phone":
        collected_data["Phone Info"] = phone_lookup(target)
    else:
        print(Fore.RED + "[!] Invalid target type. Exiting.")
        sys.exit()

    save_report(target, collected_data)

if __name__ == "__main__":
    main()
