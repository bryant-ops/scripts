import subprocess

input_file = "ip_list.txt"
match_file = "matches.txt"
mismatch_file = "mismatches.txt"

def get_reverse_dns(ip):
    try:
        result = subprocess.run(["nslookup", ip], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            if "name = " in line:  # Unix-style
                return line.split("=", 1)[1].strip().rstrip(".")
            if line.strip().lower().startswith("name:"):  # Windows-style
                return line.split(":", 1)[1].strip().rstrip(".")
        return "N/A"
    except Exception:
        return "N/A"

def get_base_name(hostname):
    if hostname and hostname != "N/A":
        return hostname.split('.')[0].lower()
    return "N/A"

with open(input_file, "r") as infile, \
     open(match_file, "w", encoding="utf-8") as match_out, \
     open(mismatch_file, "w", encoding="utf-8") as mismatch_out:

    header = "IP\tExpected Hostname\tReverseDNS\tMatch\n"
    match_out.write(header)
    mismatch_out.write(header)

    for line in infile:
        if not line.strip():
            continue

        parts = line.strip().split()
        if len(parts) != 2:
            continue  # Skip malformed lines

        ip, expected_hostname = parts
        reverse_dns = get_reverse_dns(ip)

        expected_base = get_base_name(expected_hostname)
        reverse_base = get_base_name(reverse_dns)

        match = "Yes" if expected_base == reverse_base else "No"
        result = f"{ip}\t{expected_hostname}\t{reverse_dns}\t{match}"

        print(result)
        if match == "Yes":
            match_out.write(result + "\n")
        else:
            mismatch_out.write(result + "\n")
