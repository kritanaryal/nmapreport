# 📄 Network Scanning & Vulnerability Assessment Report

---

## 1. Introduction

Network scanning is a fundamental step in cybersecurity, used to identify systems, services, and potential weaknesses. This project focuses on using Nmap to perform a structured security assessment of a target machine in a controlled lab environment.

The purpose of this assessment is to understand how exposed services and outdated software contribute to security risks.

---

## 2. Objectives

- Perform systematic network scanning
- Identify open ports and services
- Detect service versions and operating system
- Analyze vulnerabilities and misconfigurations
- Provide security recommendations

---

## 3. Methodology

The assessment followed a phased approach:

### Step 1: Environment Setup
A virtual lab was created using VirtualBox:
- Kali Linux as attacker machine
- Metasploitable2 as target system

 ![Ping](screenshots/Ping.jpeg)
  
### Step 2: Host Discovery
A ping scan was used to confirm that the target system is active.<br>
  ``` nmap -sn 192.168.56.0/24```

  
 ![HostD](screenshots/NetworkScanMultipleHosts.jpeg)

  
### Step 3: Port Scanning
Multiple scan types were used:
- SYN scan for stealth detection
- TCP connect scan for confirmation<br>
``` nmap -sS 192.168.56.102 ```


 ![PortScan](screenshots/TCPSYNScan.jpeg)

### Step 4: Service Enumeration
Service and version detection identified running applications.<br>
  ``` nmap -sV 192.168.56.102 ```

  
 ![Service+Version](screenshots/Service+VersionDetection.jpeg)
  
### Step 5: OS Detection
Nmap attempted to fingerprint the operating system.<br>
``` nmap -O 192.168.56.102 ```


 ![OS Detection](screenshots/OSDetection.jpeg)

### Step 6: Aggressive Scan
Combines multiple scan techniques including OS detection, version detection, script scanning, and traceroute. <br>
``` nmap -A 192.168.56.102 ```


 ![AgressiveScan](screenshots/FullDetailedScan.jpeg)
 ![AgressiveScan1](screenshots/FullDetailedScan1.jpeg)
 ![AgressiveScan2](screenshots/FullDetailedScan2.jpeg)
 ![AgressiveScan3](screenshots/FullDetailedScan3.jpeg)
 

### Step 7: Vulnerability Assessment
Nmap scripts were used to identify known vulnerabilities.<br>
  ``` nmap --script vuln 192.168.56.102 ```

  
![VulnerabilityScan](screenshots/VulnerabilityScan.jpeg)
![VulnerabilityScan1](screenshots/VulnerabilityScan1.jpeg)
![VulnerabilityScan2](screenshots/VulnerabilityScan2.jpeg)
![VulnerabilityScan3](screenshots/VulnerabilityScan3.jpeg)
![VulnerabilityScan4](screenshots/VulnerabilityScan4.jpeg)
![VulnerabilityScan5](screenshots/VulnerabilityScan5.jpeg)
![VulnerabilityScan6](screenshots/VulnerabilityScan6.jpeg)
![VulnerabilityScan7](screenshots/VulnerabilityScan7.jpeg)
![VulnerabilityScan8](screenshots/VulnerabilityScan8.jpeg)
![VulnerabilityScan9](screenshots/VulnerabilityScan9.jpeg)
![VulnerabilityScan10](screenshots/VulnerabilityScan10.jpeg)

  
### Step 8: Fast Scan
Scans only the most common ports for quick results.<br>
 ``` nmap -F 192.168.56.102```

 
![FastScan](screenshots/Fast.jpeg)
 
### Step 9: Specific Ports Scan
Scans only selected ports.<br>
``` nmap -p 21,22,80 192.168.56.102 ```

![SpecificPortScan](screenshots/SpecificPOrts.jpeg)


---

## 4. Results and Analysis

### 4.1 Overview

The scan results reveal a highly exposed system with numerous open ports and outdated services. This significantly increases the attack surface and potential entry points for attackers.

---

### 4.2 Open Ports and Services

| Port | Service | Risk Level |
|------|--------|------------|
| 21   | FTP    | High |
| 22   | SSH    | Medium |
| 23   | Telnet | High |
| 80   | HTTP   | High |
| 139/445 | SMB | High |
| 3306 | MySQL | High |
| 5432 | PostgreSQL | Medium |

---

### 4.3 Detailed Findings

#### FTP (Port 21)
The FTP service is accessible and may allow anonymous login.

**Impact:**
- Unauthorized file access
- Potential data exposure

---

#### Telnet (Port 23)
Telnet transmits data in plaintext.

**Impact:**
- Credentials can be intercepted easily
- High risk in real networks

---

#### SMB (Ports 139, 445)
SMB services appear misconfigured.

**Impact:**
- Vulnerable to known attacks
- Possible unauthorized access

---

#### HTTP (Port 80)
A web server is running, possibly with outdated software.

**Impact:**
- Web-based attacks
- Exploitable vulnerabilities

---

#### Database Services (MySQL, PostgreSQL)
Database ports are exposed.

**Impact:**
- Risk of unauthorized database access
- Potential data leakage

---

### 4.4 Security Assessment

The system demonstrates poor security posture:

- Excessive open ports
- Use of outdated services
- Weak or insecure protocols
- Lack of proper hardening

---

## 5. Challenges Encountered

- Interpreting large scan outputs
- Distinguishing between necessary and unnecessary services
- Understanding service versions and associated risks

These challenges were addressed through careful analysis and cross-referencing known vulnerabilities.

---

## 6. Recommendations

### Immediate Actions
- Disable Telnet and FTP services
- Close unnecessary ports

### Medium-Term Actions
- Update all outdated services
- Enforce strong authentication

### Long-Term Actions
- Implement firewall rules
- Perform regular vulnerability scans
- Apply system hardening practices

---

## 7. Conclusion

This assessment highlights how a system with multiple exposed services can become highly vulnerable. Even basic scanning techniques can reveal critical weaknesses if proper security measures are not implemented.

The project demonstrates the importance of proactive security practices and regular assessments.

---

## 8. Ethical Considerations

All activities were conducted in a controlled lab environment using authorized systems. No real-world systems were scanned.

This project strictly follows ethical hacking principles and is intended for educational purposes only.
