


🛠️ Nmap Tool
     Nmap (v7.95)

```bash
namp -p 22,80,443 -sV -O --script vuln 192.168.1.1
```
 -  -p : Scan specific ports
 -  -sV : Detect service versions
 -  -o : 	OS detection
 -  --script : Runs the Nmap Scripting Engine (NSE) with the vuln category, checking for known vulnerabilities on the detected services

   
