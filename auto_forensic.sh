#!/bin/bash

FILE=$1

echo "[*] Starting forensic analysis on $FILE"

# Create output folder
mkdir -p forensic_output

echo "[*] Extracting IP addresses..."
tshark -r "$FILE" -T fields -e ip.src -e ip.dst 2>/dev/null > forensic_output/ip.txt

echo "[*] Extracting MAC addresses..."
tshark -r "$FILE" -T fields -e eth.src -e eth.dst 2>/dev/null > forensic_output/mac.txt

echo "[*] Extracting DNS (hostnames)..."
tshark -r "$FILE" -Y "dns" -T fields -e dns.qry.name 2>/dev/null > forensic_output/dns.txt

echo "[*] Extracting HTTP info..."
tshark -r "$FILE" -Y "http" -T fields -e http.host -e http.request.uri 2>/dev/null > forensic_output/http.txt

echo "[*] Extracting user data (SMB/Kerberos)..."
tshark -r "$FILE" -Y "smb || kerberos" -T fields -e smb.username -e kerberos.CNameString 2>/dev/null > forensic_output/user.txt

echo "[*] Counting top IPs..."
tshark -r "$FILE" -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -nr > forensic_output/ip_summary.txt

echo "[*] Counting top MACs..."
tshark -r "$FILE" -T fields -e eth.src 2>/dev/null | sort | uniq -c | sort -nr > forensic_output/mac_summary.txt

echo "[*] Combining all results into one file..."

cat forensic_output/ip_summary.txt > forensic_output/final.txt
echo "" >> forensic_output/final.txt

cat forensic_output/mac_summary.txt >> forensic_output/final.txt
echo "" >> forensic_output/final.txt

cat forensic_output/dns.txt >> forensic_output/final.txt
echo "" >> forensic_output/final.txt

cat forensic_output/http.txt >> forensic_output/final.txt
echo "" >> forensic_output/final.txt

cat forensic_output/user.txt >> forensic_output/final.txt

echo ""
echo "[✅ DONE] Output ready: forensic_output/final.txt"
echo ""
echo "👉 Now copy this into Ollama and ask your questions."

