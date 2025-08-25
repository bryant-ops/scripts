import requests
import time

API_KEY = 'APIKEY'  # Replace this with your API key
INPUT_FILE = 'ip_list.txt'
RATE_LIMIT_SECONDS = 15

def query_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attributes = data['data']['attributes']

        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        reputation = attributes.get('reputation', 0)

        detection_ratio = f"{malicious}/{total}"
        print(f"IP: {ip} | Malicious: {malicious} | Suspicious: {suspicious} | Community Score: {reputation} | Detection Ratio: {detection_ratio}")
    else:
        print(f"IP: {ip} | Error: {response.status_code} - {response.text}")

def main():
    with open(INPUT_FILE, 'r') as file:
        ips = [line.strip() for line in file if line.strip()]

    for ip in ips:
        query_ip(ip)
        time.sleep(RATE_LIMIT_SECONDS)

if __name__ == "__main__":
    main()
