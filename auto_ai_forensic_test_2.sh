#!/bin/bash

FILE=$1

echo "[*] Starting FULL forensic extraction..."

mkdir -p auto_output


# BASIC NETWORK DATA

tshark -r "$FILE" -T fields -e ip.src 2>/dev/null | grep -v '^$' > auto_output/ip.txt
tshark -r "$FILE" -T fields -e eth.src 2>/dev/null | grep -v '^$' > auto_output/mac.txt


# HOSTNAME (CLEAN - NO DNS)

tshark -r "$FILE" -Y "nbns" -T fields -e ip.src -e nbns.name 2>/dev/null | grep -v '^$' > auto_output/hostname.txt
tshark -r "$FILE" -Y "bootp.option.hostname" -T fields -e ip.src -e bootp.option.hostname 2>/dev/null | grep -v '^$' >> auto_output/hostname.txt


# USER 

tshark -r "$FILE" -Y "kerberos.CNameString" -T fields -e ip.src -e kerberos.CNameString 2>/dev/null | grep -v '^$' > auto_output/user.txt


# FULL NAME 

strings "$FILE" | grep -E "^[A-Z][a-z]+ [A-Z][a-z]+" | sort -u > auto_output/fullname.txt


# ATTACK COUNT AND VICTEM COUNT

#ATTACK_COUNT=$(grep "$ATTACKER_IP" auto_output/http.txt | wc -l)
#VICTIM_COUNT=$(grep "$INFECTED_IP" auto_output/ip_summary.txt | awk '{print $1}')


# HTTP TRAFFIC

tshark -r "$FILE" -Y "http.request" \
-T fields -e ip.src -e ip.dst -e http.host -e http.request.uri \
2>/dev/null > auto_output/http.txt


# SUMMARIES

sort auto_output/ip.txt | uniq -c | sort -nr > auto_output/ip_summary.txt
INFECTED_IP=$(head -1 auto_output/ip_summary.txt | awk '{print $2}')
sort auto_output/mac.txt | uniq -c | sort -nr > auto_output/mac_summary.txt

INFECTED_IP=$(head -1 auto_output/ip_summary.txt | awk '{print $2}')
echo "[*] Detected infected IP: $INFECTED_IP"


# MAC MAPPING

tshark -r "$FILE" -T fields -e ip.src -e eth.src 2>/dev/null | grep "$INFECTED_IP" > auto_output/ip_mac_map.txt


# HOSTNAME (FILTERED)

VICTIM_HOSTNAME=$(grep "$INFECTED_IP" auto_output/hostname.txt | \
awk '{print $2}' | cut -d'<' -f1 | sort -u | head -1)


# USER (FILTERED)

VICTIM_USER=$(grep "$INFECTED_IP" auto_output/user.txt | \
awk '{print $2}' | sort -u | head -1)

# ATTACKER DETECTION 

awk '{print $2}' auto_output/http.txt | sort | uniq -c | sort -nr > auto_output/external_ips.txt
grep -v -E "^( *[0-9]+ )?(10\.|192\.168\.|172\.)" auto_output/external_ips.txt > auto_output/external_clean.txt

ATTACKER_IP=$(head -1 auto_output/external_clean.txt | awk '{print $2}')

ATTACK_COUNT=$(grep "$ATTACKER_IP" auto_output/http.txt | wc -l)

VICTIM_COUNT=$(grep "$INFECTED_IP" auto_output/ip_summary.txt | awk '{print $1}')

# ATTACK SUCCESS LOGIC

if [ "$ATTACK_COUNT" -gt 20 ]; then
    ATTACK_SUCCESS="Successful (repeated communication)"
elif [ "$ATTACK_COUNT" -gt 5 ]; then
    ATTACK_SUCCESS="Likely Successful"
else
    ATTACK_SUCCESS="Unclear / Low Activity"
fi


if grep -q -E "exe|payload|download" auto_output/http.txt; then
    ATTACK_TYPE="Malware Delivery"
elif [ "$ATTACK_COUNT" -gt 10 ]; then
    ATTACK_TYPE="Command & Control / Beaconing"
else
    ATTACK_TYPE="Suspicious HTTP Activity"
fi


# FINAL OUTPUT

OUTPUT="auto_output/final.txt"
> "$OUTPUT"

echo "===== FINAL FORENSIC RESULT =====" >> "$OUTPUT"


echo "Victim IP: $INFECTED_IP" >> "$OUTPUT"
echo "Victim MAC: $(grep "$INFECTED_IP" auto_output/ip_mac_map.txt | awk '{print $2}' | sort -u | head -1)" >> "$OUTPUT"
echo "Victim Hostname: ${VICTIM_HOSTNAME:-Not found}" >> "$OUTPUT"
echo "Victim User: ${VICTIM_USER:-Not found}" >> "$OUTPUT"
echo "Victim Full Name: $(head -1 auto_output/fullname.txt)" >> "$OUTPUT"
echo "Victim Packet Count: $VICTIM_COUNT" >> "$OUTPUT"

echo "" >> "$OUTPUT"

echo "Attacker IP: ${ATTACKER_IP:-Not found}" >> "$OUTPUT"
echo "Attack Count: $ATTACK_COUNT" >> "$OUTPUT"

echo "" >> "$OUTPUT"

echo "Attack Type: $ATTACK_TYPE" >> "$OUTPUT"
echo "Attack Success: $ATTACK_SUCCESS" >> "$OUTPUT"

echo "" >> "$OUTPUT"

#echo "Reason:" >> "$OUTPUT"
#echo "The victim ($INFECTED_IP) shows highest traffic and communicates repeatedly with external IP ($ATTACKER_IP). High number of HTTP requests indicates possible malware or command-and-control activity." >> "$OUTPUT"

echo "[*] Final dataset ready"

# sinding script 

echo "[*] Sending to Ollama..."

"/mnt/c/Users/malit/AppData/Local/Programs/Ollama/ollama.exe" run llama3 <<EOF # the ollama file you usings 

You are an expert network forensic analyst.

You are given extracted network traffic data from a PCAP file.
Your task is to perform a structured forensic investigation.

-----------------------------------------------------------------------------------------
FLOW NEED TO FOLOW

1. Extract data
2. Create HTTP file
3. Create summaries
4. Detect infected IP
5. Detect attacker IP
6. Calculate counts
7. Extract hostname/user
8. Write final output
9. Send to AI
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



Attacker:
IP Address:
MAC Address:
Attack Type:
Hostname:
attack count:
Attack Success:

[Reasoning]
Explain step-by-step how the conclusion was reached using the data.

EOF

echo "[*] DONE"