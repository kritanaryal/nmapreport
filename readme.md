


## 🛠️ Nmap Tool
   - Nmap (v7.99)

# 🔐 Network Scanning & Vulnerability Assessment using Nmap

## 📌 Overview

This project demonstrates how network scanning can be used to understand the security posture of a system. Using Nmap, multiple scan techniques were applied to identify open ports, running services, and potential vulnerabilities on a target machine.

The goal is to simulate a real-world security assessment in a controlled lab environment and analyze how exposed services can increase security risks.

---

## 🎯 Objectives

- Discover active hosts in a network
- Identify open ports and running services
- Detect service versions and operating system
- Analyze potential security risks
- Understand how attackers view a system during reconnaissance

---

## 🧪 Lab Environment

- Attacker Machine: Kali Linux  
- Target Machine: Metasploitable2  
- Network: VirtualBox Host-Only Network  

This setup ensures that all activities are performed safely within an isolated environment.

---

## 🔍 Scan Types Used

### 1. Host Discovery (Ping Scan)
Identifies which systems are active on the network.

### 2. TCP SYN Scan
A fast and stealthy method to detect open ports without completing a full connection.

### 3. TCP Connect Scan
Establishes a full connection to confirm open ports when elevated privileges are not available.

### 4. Service & Version Detection
Determines what services are running and their versions.

### 5. OS Detection
Attempts to identify the operating system based on network behavior.

### 6. Aggressive Scan
Combines multiple techniques (OS detection, version detection, scripts, traceroute).

### 7. Vulnerability Scan
Uses Nmap scripting engine to detect known vulnerabilities and misconfigurations.

---

## ⚙️ Methodology (Summary)

The assessment followed a structured approach:

1. Verified network connectivity
2. Discovered active hosts
3. Performed multiple scan types
4. Identified services and versions
5. Analyzed results for security risks


All scans were executed using standard Nmap commands in a controlled lab environment. Multiple scanning techniques were applied to ensure comprehensive enumeration of the target system.

The following commands represent the primary scans performed during the assessment:

```bash
# Aggressive scan (includes OS detection, version detection, scripts, traceroute)
nmap -A 192.168.56.102

# TCP SYN scan (stealth scan)
nmap -sS 192.168.56.102

# Service and version detection
nmap -sV 192.168.56.102

# OS detection
nmap -O 192.168.56.102

# Vulnerability scan using NSE scripts
nmap --script vuln 192.168.56.102

```
---

## 📊 Key Findings

The target system exposed multiple services, significantly increasing its attack surface.

### Important Observations:
- Multiple open ports (FTP, SSH, HTTP, SMB, databases)
- Outdated service versions detected
- Insecure protocols like Telnet in use
- Weak configurations in SMB and FTP

### Security Insight:
A system with many exposed services is like a house with multiple unlocked doors—each open port provides a potential entry point for attackers.

---

## 🛡️ Learning Outcomes

- Understanding how attackers perform reconnaissance
- Interpreting scan results from a defensive perspective
- Identifying weak configurations and outdated services
- Gaining hands-on experience with Nmap

---

## ⚖️ Ethical Considerations

All scans were conducted in a controlled lab environment using authorized systems.  
No unauthorized networks or systems were targeted.

This project is strictly for educational purposes.

---

## 🚀 Future Improvements

- Automate scanning using Bash or Python
- Integrate results with vulnerability scanners
- Map findings to known CVEs
- Extend analysis to web application security
