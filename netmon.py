import psutil
import time
import socket
import requests
import urllib3
import argparse
from datetime import datetime
from termcolor import colored
from requests.exceptions import RequestException
from colorama import init

# Network Monitor by SewDough, subtractive recursion for bytes in/out provided by xinnt.

"""
This script will monitor your network activity similar to "TOP" for BASH, 
but also provide comprehensive geolocation data and process data for the 
remote IPs connected to your machine.

This script relies heavily on the following libraries:
    - termcolor (formatting)
    - requests (Whois)
    - colorama (formatting)
    - psutil (Process Utilities)

To run this, please install the following with PIP:
    pip install requests
    pip install termcolor
    pip install psutil
    pip install colorama

USAGE: python netmon.py
Arguments: 
    --process (displays detailed process information per connection)
    --ports (Specify what ports you want to filter) 
    e.g. --ports 80,443,123 etc  
    --time (in seconds, refresh rate)
"""
# Initialize colorama for Windows compatibility
init(autoreset=True)

# Suppress InsecureRequestWarnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def bytes_to_human(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"

def get_whois_info(ip):
    url = f"https://whois.arin.net/rest/ip/{ip}.json"
    try:
        response = requests.get(url, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            if 'net' in data and 'orgRef' in data['net']:
                org_name = data['net']['orgRef']['@name']
                org_id = data['net']['orgRef']['@handle']
                return f"Org Name: {org_name}, Org ID: {org_id}"
            return "No organization info found."
        else:
            return f"Error fetching WHOIS for {ip}: {response.status_code}"
    except RequestException as e:
        return f"Error during WHOIS lookup for {ip}: {str(e)}"

def get_geolocation(ip):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            
            latitude, longitude = data.get("loc", "Unknown,Unknown").split(",")

            # Perform Reverse Geolocation
            address = get_physical_address(latitude, longitude)

            return {
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": data.get("country", "Unknown"),
                "loc": f"{latitude},{longitude}",
                "address": address
            }
        else:
            return {
                "city": "Unknown",
                "region": "Unknown",
                "country": "Unknown",
                "loc": "Unknown",
                "address": "Unknown"
            }
    except requests.exceptions.RequestException as e:
        return {
            "city": "Error",
            "region": "Error",
            "country": "Error",
            "loc": "Error",
            "address": "Error"
        }

def get_physical_address(latitude, longitude):
    url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}"
    
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("display_name", "Address not found")
        else:
            print(f"⚠️ Nominatim returned status code {response.status_code}, trying fallback...")
            return get_fallback_address(latitude, longitude)
    
    except requests.exceptions.RequestException:
        print("⚠️ Nominatim request failed, trying fallback...")
        return get_fallback_address(latitude, longitude)

def get_fallback_address(latitude, longitude):
    fallback_url = f"https://api.bigdatacloud.net/data/reverse-geocode-client?latitude={latitude}&longitude={longitude}&localityLanguage=en"

    try:
        response = requests.get(fallback_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("locality", "Unknown Address")
        return "Fallback Address Not Found"
    
    except requests.exceptions.RequestException:
        return "Reverse Geolocation Failed"

def log_to_file(log_data):
    with open("netmon.log", "a") as log_file:
        log_file.write(log_data + "\n")

def print_ports(ports):
    for port in ports:
        local_ip = colored(port['local_ip'], 'green')
        local_port = colored(port['local_port'], 'yellow')
        remote_ip = colored(port['remote_ip'], 'red')
        remote_port = colored(port['remote_port'], 'cyan')
        status = colored(port['status'], 'white')

        print(f"Local IP: {local_ip}   LPort: {local_port}   Remote IP: {remote_ip}   RPort:{remote_port}   CONN:{status}")

        log_data = f"{datetime.now()} | Local IP: {local_ip} | LPort: {local_port} | Remote IP: {remote_ip} | RPort:{remote_port} | CONN:{status}"
        log_to_file(log_data)

def get_network_activity(filtered_ports):
    open_ports = []
    for conn in psutil.net_connections(kind='inet'):
        local_ip, local_port = conn.laddr
        remote_ip, remote_port = conn.raddr if conn.raddr else ('-', '-')
        status = conn.status

        if (not filtered_ports or local_port in filtered_ports or remote_port in filtered_ports):
            open_ports.append({
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'status': status
            })
    return open_ports

def batch_whois_lookup(remote_ip_ports):
    print("\n" + "-" * 50)
    print("WHOIS and Geolocation Lookup Results:")
    for ip, port in remote_ip_ports.items():
        ip_colored = colored(ip, 'red')
        port_colored = colored(port, 'green')
        connector_text = colored("which is connected to port", 'cyan')

        print(f"\nPerforming WHOIS lookup for {ip_colored} {connector_text} {port_colored}...")

        whois_info = get_whois_info(ip)
        print(f"WHOIS Info for {ip}: {whois_info}")

        geolocation_info = get_geolocation(ip)

        city = colored(f"City: {geolocation_info['city']}", 'red')
        region = colored(f"Region: {geolocation_info['region']}", 'red')
        country = colored(f"Country: {geolocation_info['country']}", 'red')
        location_label = colored("Location:", 'yellow')
        coordinates = colored(geolocation_info['loc'], 'cyan')

        address_label = colored("Address:", "yellow")
        address = colored(geolocation_info["address"], "magenta")

        print(f"Geolocation Info for {colored(ip, 'green')}: {city}, {region}, {country}, {location_label} {coordinates}")
        print(f"{address_label} {address}")

        time.sleep(3)  
    print("-" * 50)

def netMon(refresh_time=2, filtered_ports=[], process_info=False):
    while True:
        open_ports = get_network_activity(filtered_ports)

        print("\n" + "-" * 50)
        print("NetMonCLI v0.5b by SewDough.")
        print("Monitoring Network Activity...")
        print(f"Last Refreshed: {datetime.now()}")
        print("-" * 50)

        print_ports(open_ports)

        if process_info:
            print("\n" + "-" * 50)
            print("Process Info:")
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                print(f"PID: {proc.info['pid']} | Process: {proc.info['name']} | CPU%: {proc.info['cpu_percent']} | Memory%: {proc.info['memory_percent']}")

        remote_ip_ports = {port['remote_ip']: port['remote_port'] for port in open_ports if port['remote_ip'] != '-'}
        
        user_input = input("\nWould you like to perform a WHOIS and Geolocation lookup for these IPs? (y/n): ").strip().lower()
        if user_input == 'y':
            batch_whois_lookup(remote_ip_ports)

        time.sleep(refresh_time)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Monitoring Script")
    parser.add_argument('--process', action='store_true', help="Display process info")
    args = parser.parse_args()

    netMon(refresh_time=2, filtered_ports=[80, 443], process_info=args.process)
