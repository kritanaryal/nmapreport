


## 🛠️ Nmap Tool
   - Nmap (v7.99)

# 🔐 Network Scanning & Vulnerability Assessment using Nmap

## 📌 Overview
This project demonstrates practical network reconnaissance and vulnerability assessment using Nmap. The scans were conducted in a controlled lab environment using VirtualBox with a local target system.

## 🎯 Objectives
- Identify live hosts in a network
- Discover open ports and services
- Detect operating system and service versions
- Identify potential vulnerabilities

## 🧪 Lab Environment
- Attacker Machine: Kali Linux
- Target Machine: Metasploitable2
- Network: VirtualBox Host-Only Network

  ## 🔍 Scan Types Performed

### 1. Ping Scan (Host Discovery)
Used to identify active hosts in the network.



---

### 2. TCP SYN Scan (Stealth Scan)
Performs a half-open scan to detect open ports without completing TCP handshake.


---

### 3. Full TCP Connect Scan
Completes full TCP connection; used when root privileges are not available.



---

### 4. Service & Version Detection
Identifies services and their versions running on open ports.



---

### 5. OS Detection
Attempts to identify the operating system of the target.



---

### 6. Aggressive Scan
Combines multiple scan techniques including OS detection, version detection, script scanning, and traceroute.



---

### 7. Vulnerability Scan (NSE Scripts)
Uses Nmap scripting engine to detect known vulnerabilities.


---

### 8. Fast Scan
Scans only the most common ports for quick results.



---

### 9. Specific Ports Scan
Scans only selected ports.

## ⚙️ Methodology

1. Verified connectivity using ping.
2. Performed host discovery to identify active systems.
3. Conducted multiple scan types:
   - SYN scan for stealth scanning
   - Version detection to identify services
   - OS detection for system identification
4. Executed aggressive scan for detailed enumeration.
5. Performed vulnerability scanning using NSE scripts.
6. Saved outputs using:
   nmap -A 192.168.56.102 -oN scans/scan_results.txt
   
