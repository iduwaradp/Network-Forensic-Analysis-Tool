#!/bin/bash

FILE=$1

echo "[*] Starting FULL forensic extraction..."

mkdir -p auto_output

# -----------------------------
# BASIC NETWORK DATA

tshark -r "$FILE" -T fields -e ip.src 2>/dev/null | grep -v '^$' > auto_output/ip.txt
tshark -r "$FILE" -T fields -e eth.src 2>/dev/null | grep -v '^$' > auto_output/mac.txt


# -----------------------------
# HOSTNAME EXTRACTION (MULTIPLE SOURCES)


# NBNS (main source)
tshark -r "$FILE" -Y "nbns" -T fields -e ip.src -e nbns.name 2>/dev/null | grep -v '^$' > auto_output/hostname_nbns.txt

# DHCP hostname
tshark -r "$FILE" -Y "bootp.option.hostname" \
-T fields -e ip.src -e bootp.option.hostname 2>/dev/null >> auto_output/hostname_nbns.txt

# -----------------------------
# USER EXTRACTION


# Kerberos (MOST IMPORTANT)
tshark -r "$FILE" -Y "kerberos.CNameString" -T fields -e ip.src -e kerberos.CNameString 2>/dev/null | grep -v '^$' > auto_output/user.txt


# -----------------------------
# FULL NAME EXTRACTION (DEEP SEARCH)

strings "$FILE" > auto_output/all_strings.txt

# Try common patterns
strings "$FILE" | grep -E "^[A-Z][a-z]+ [A-Z][a-z]+" | sort -u > auto_output/fullname.txt

# -----------------------------
# HTTP (FOR ATTACK DETECTION)

tshark -r "$FILE" -Y "http.request" \
-T fields -e ip.src -e ip.dst -e http.host -e http.request.uri \
2>/dev/null > auto_output/http.txt

# -----------------------------
# SUMMARIES

sort auto_output/ip.txt | uniq -c | sort -nr > auto_output/ip_summary.txt
sort auto_output/mac.txt | uniq -c | sort -nr > auto_output/mac_summary.txt
tshark -r "$FILE" -T fields -e ip.src -e eth.src 2>/dev/null > auto_output/ip_mac_map.txt

INFECTED_IP=$(head -1 auto_output/ip_summary.txt | awk '{print $2}')

echo "[*] Detected infected IP: $INFECTED_IP"

# -----------------------------
# COMBINE EVERYTHING


OUTPUT="auto_output/final.txt"
> "$OUTPUT"

echo "===== IP SUMMARY =====" >> "$OUTPUT"
cat auto_output/ip_summary.txt >> "$OUTPUT"

echo -e "\n===== MAC SUMMARY =====" >> "$OUTPUT"
cat auto_output/mac_summary.txt >> "$OUTPUT"

echo -e "\n===== HOSTNAMES (FILTERED) =====" >> "$OUTPUT"
grep "$INFECTED_IP" auto_output/hostname_nbns.txt | \
awk '{print $2}' | cut -d'<' -f1 | sort -u | head -1 >> "$OUTPUT"

echo -e "\n===== USERS =====" >> "$OUTPUT"
grep "$INFECTED_IP" auto_output/user.txt | \
awk '{print $2}' | sort -u | head -1 >> "$OUTPUT"

echo -e "\n===== FULL NAMES =====" >> "$OUTPUT"
cat auto_output/fullname.txt >> "$OUTPUT"

echo -e "\n===== HTTP TRAFFIC =====" >> "$OUTPUT"
cat auto_output/http.txt >> "$OUTPUT"

echo -e "\n===== DETECTED INFECTED HOST =====" >> "$OUTPUT"
echo "$INFECTED_IP" >> "$OUTPUT"

echo -e "\n--- MAC ---" >> "$OUTPUT"
grep "$INFECTED_IP" auto_output/ip_mac_map.txt | \
awk '{print $2}' | sort -u | head -1 >> "$OUTPUT"

echo -e "\n--- HOSTNAME ---" >> "$OUTPUT"
grep "$INFECTED_IP" auto_output/hostname_nbns.txt >> "$OUTPUT" 2>/dev/null


echo -e "\n--- USER ---" >> "$OUTPUT"
grep "$INFECTED_IP" auto_output/user.txt >> "$OUTPUT" 2>/dev/null

echo -e "\n--- FULL NAME ---" >> "$OUTPUT"
cat auto_output/fullname.txt >> "$OUTPUT"

echo "[*] Final dataset ready"


# -----------------------------
# SEND TO AI
# -----------------------------

# sinding script 

echo "[*] Sending to Ollama..."

"/mnt/c/Users/malit/AppData/Local/Programs/Ollama/ollama.exe" run llama3 <<EOF # the ollama file you usings 

You are an expert network forensic analyst.

You are given extracted network traffic data from a PCAP file.
Your task is to perform a structured forensic investigation.

-----------------------------------------------------------------------------------------
FLOW NEED TO FOLOW

1. Extract everything
2. Detect infected IP
3. Build MAC mapping
4. Combine structured data
5. Send to AI with strict instructions

-----------------------------------------------------------------------------------------
ANALYSIS RULES

Identify the most active device (IP and/or MAC)
Identify any suspicious device(s)
Determine the likely infected host
Identify attacker and victim (if applicable)
Identify any suspicious domains or communication
Determine the type of attack (if any)
Assess whether the attack was successful or not

-----------------------------------------------------------------------------------------
DATASET

$(cat auto_output/final.txt)

-----------------------------------------------------------------------------------------
TASKS

IMPORTANT:
- Do NOT guess missing data
- If information is not available, say: "Not found in data"
- Identify patterns, not just counts
- Correlate IP, MAC, DNS, and HTTP together
- Look for abnormal behaviour (high traffic, unusual domains, repeated connections)
- Always prioritise NBNS and Kerberos data
- The infected host is the most active internal IP
- Link MAC, hostname, and user to that same IP

If data exists, DO NOT say unknown

-----------------------------------------------------------------------------------------
OUTPUT FORMAT (STRICT)

IP Address:
MAC Address:
Hostname:
User Account:
Full Name:

Attacker:
Attack Type:
Attack Success:

[Reasoning]
Explain step-by-step how the conclusion was reached using the data.

EOF

echo "[*] DONE"