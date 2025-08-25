#!/usr/bin/env python3
import subprocess
import sys
import re
import socket

def nslookup(value):
    """Determines if the input is a domain or IP and performs the appropriate lookup."""
    if is_ip(value):
        return reverse_lookup(value)
    else:
        return forward_lookup(value)

def is_ip(value):
    """Checks if the given value is an IP address."""
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    return bool(ip_pattern.match(value))

def forward_lookup(domain):
    """Performs a forward DNS lookup (domain to IP)."""
    try:
        result = subprocess.run(['nslookup', domain],
                                capture_output=True, text=True, timeout=10)
        output = result.stdout
        ips = []
        skip = True  # Skip the first "Address:" (which is usually the DNS resolver)
        for line in output.splitlines():
            if line.startswith("Address:"):
                if skip:
                    skip = False
                    continue
                match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                if match:
                    ips.append(match.group(1))
        return ", ".join(ips) if ips else "Not Found"
    except Exception as e:
        return f"Error: {e}"

def reverse_lookup(ip):
    """Performs a reverse DNS lookup (IP to domain)."""
    try:
        domain = socket.getfqdn(ip)
        return domain if domain and domain != ip else "Not Found"
    except Exception as e:
        return f"Error: {e}"

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} input_file [output_file]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        with open(input_file, "r") as f:
            values = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print("Input file not found!")
        sys.exit(1)

    results = []
    for value in values:
        lookup_result = nslookup(value)
        results.append(f"{value} - {lookup_result}")

    # Print results to the console or write them to a file if specified
    if output_file:
        with open(output_file, "w") as f:
            f.write("\n".join(results))
        print(f"Results saved in {output_file}")
    else:
        for line in results:
            print(line)

if __name__ == '__main__':
    main()
