#!/bin/bash

FILE=$1

echo "[*] Starting FULL automated analysis..."

mkdir -p auto_output

#  Detect IP 
IP_CHECK=$(tshark -r "$FILE" -T fields -e ip.src 2>/dev/null | grep -v '^$' | head -1)

# Detect IP traffic properly
IP_CHECK=$(tshark -r "$FILE" -T fields -e ip.src 2>/dev/null | grep -v '^$' | head -1)

if [ -n "$IP_CHECK" ]; then
    echo "[*] IP traffic detected"

    tshark -r "$FILE" -T fields -e ip.src 2>/dev/null | grep -v '^$' > auto_output/ip.txt
    tshark -r "$FILE" -T fields -e eth.src 2>/dev/null | grep -v '^$' > auto_output/mac.txt
    tshark -r "$FILE" -Y "dns" -T fields -e dns.qry.name 2>/dev/null | grep -v '^$' > auto_output/dns.txt
    tshark -r "$FILE" -Y "http" -T fields -e http.host 2>/dev/null | grep -v '^$' > auto_output/http.txt
    tshark -r "$FILE" -Y "smb || kerberos" -T fields -e smb.username 2>/dev/null | grep -v '^$' > auto_output/user.txt

else
    echo "[*] WiFi traffic detected"

    tshark -r "$FILE" -T fields -e wlan.ta 2>/dev/null | grep -v '^$' > auto_output/mac.txt
fi

# Summarise
[ -f auto_output/ip.txt ] && cat auto_output/ip.txt | sort | uniq -c | sort -nr > auto_output/ip_summary.txt
[ -f auto_output/mac.txt ] && cat auto_output/mac.txt | sort | uniq -c | sort -nr > auto_output/mac_summary.txt

echo "[*] Combining extracted data..."

OUTPUT="auto_output/final.txt"
> "$OUTPUT"

echo "===== IP SUMMARY =====" >> "$OUTPUT"
[ -s auto_output/ip_summary.txt ] && cat auto_output/ip_summary.txt >> "$OUTPUT"

echo -e "\n===== MAC SUMMARY =====" >> "$OUTPUT"
[ -s auto_output/mac_summary.txt ] && cat auto_output/mac_summary.txt >> "$OUTPUT"

echo -e "\n===== DNS DATA =====" >> "$OUTPUT"
[ -s auto_output/dns.txt ] && cat auto_output/dns.txt >> "$OUTPUT"

echo -e "\n===== HTTP DATA =====" >> "$OUTPUT"
[ -s auto_output/http.txt ] && cat auto_output/http.txt >> "$OUTPUT"

echo -e "\n===== USER DATA =====" >> "$OUTPUT"
[ -s auto_output/user.txt ] && cat auto_output/user.txt >> "$OUTPUT"

echo "[*] Final file ready: auto_output/final.txt"

# sinding script 

echo "[*] Sending to Ollama..."

"/mnt/c/Users/malit/AppData/Local/Programs/Ollama/ollama.exe" run llama3 <<EOF # the ollama file you usings 

You are an expert network forensic analyst.

You are given extracted network traffic data from a PCAP file.
Your task is to perform a structured forensic investigation.

-------------------------
ANALYSIS RULES
-------------------------
- Do NOT guess missing data
- If information is not available, say: "Not found in data"
- Identify patterns, not just counts
- Correlate IP, MAC, DNS, and HTTP together
- Look for abnormal behaviour (high traffic, unusual domains, repeated connections)

-------------------------
DATASET
-------------------------
$(cat auto_output/final.txt)

-------------------------
TASKS
-------------------------

1. Identify the most active device (IP and/or MAC)
2. Identify any suspicious device(s)
3. Determine the likely infected host
4. Identify attacker and victim (if applicable)
5. Identify any suspicious domains or communication
6. Determine the type of attack (if any)
7. Assess whether the attack was successful or not

-------------------------
OUTPUT FORMAT (STRICT)
-------------------------

[Summary]
- Most Active Device:
- Suspicious Device:
- Infected Host:

[Details]
- IP Address:
- MAC Address:
- Hostname:
- User Account:
- Full Name:

[Attack Analysis]
- Attacker:
- Victim:
- Attack Type:
- Attack Success:

[Reasoning]
Explain step-by-step how the conclusion was reached using the data.

EOF

echo "[*] DONE"