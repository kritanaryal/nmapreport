


## 🛠️ Nmap Tool
   - Nmap (v7.95)

```bash
namp -p 22,80,443 -sV -O --script vuln 192.168.1.1
```
 -  -p : Scan specific ports
 -  -sV : Detect service versions
 -  -o : 	OS detection
 -  --script : Runs the Nmap Scripting Engine (NSE) with the vuln category, checking for known vulnerabilities on the detected services

      ### Here is the result :
       Nmap 7.95 scan initiated Tue Jul 22 13:15:14 2025  
      as: /usr/lib/nmap/nmap --privileged -p 22,80,443 -sV -O --script vuln -oN forgithubproject.txt 192.168.1.1  
      Pre-scan script results:     
     broadcast-avahi-dos:      
    Discovered hosts: 224.0.0.251    
   After NULL UDP avahi packet DoS (CVE-2011-1002).    
   Hosts are all up (not vulnerable).    
  Nmap scan report for 192.168.1.1 (192.168.1.1)    
  Host  is up (0.0019s latency).     

       | PORT   |  STATE | SERVICE | VERSION |
       |--------|--------|---------|---------|
       | 22/tcp | closed | ssh     |
       | 80/tcp | open   | http    |

      http-server-header: <empty>    
      http-fileupload-exploiter:       
      Couldn't find a file-type field.    
   
      fingerprint-strings:   
       GetRequest:   
       HTTP/1.0 200 OK  
       Connection: close  
       Cache-Control: no-cache,no-store  
       Pragma: no-cache  
       Content-Length: 154266  
       Set-Cookie: SID=d5fae5f7d71909afd2b57b34c68a6f9e0cb98155c4f7bc8f648ee242b96b071c;    
       PATH=/; HttpOnly; SameSite=strict   
       Set-Cookie: _TESTCOOKIESUPPORT=1; PATH=/; HttpOnly; SameSite=strict    
       Server:   
       Accept-Ranges: bytes  
       X-Content-Type-Options: nosniff  
       X-XSS-Protection: 1; mode=block  
       Content-Security-Policy: frame-ancestors 'self'   
       X-Frame-Options: SAMEORIGIN  
       Content-Type: text/html; charset=utf-8
     
     HTTP/1.1 400 Bad Request  
     Connection: close  
    Content-Type: text/html; charset=iso-8859-1  
    X-Content-Type-Options: nosniff  
    X-XSS-Protection: 1; mode=block  
    X-Frame-Options: SAMEORIGIN  
    Content-Security-Policy: frame-ancestors 'self';   
     Cache-Control: no-cache,no-store  
    Pragma: no-cache  
      .....................................................................      
    ............................................

    Read more ... : [Click Here](https://docs.google.com/document/d/1mEeYMK8CmS_thdsDuZGnv9lJTUruS9sf3uhuvmy9YRw/edit?usp=sharing)


    ```bash
       nmap -A 192.168.1.1
    ```

     -   -A :  "Aggressive Scan" ( The -A flag in Nmap activates multiple advanced scanning features at once )

            ### Here is the results :

            Nmap 7.95 scan initiated Tue Jul 22 13:20:51 2025 as: /usr/lib/nmap/nmap
           --privileged -A -oN forgithubprojectag.txt 192.168.1.1
         
      Nmap scan report for 192.168.1.1 (192.168.1.1)  
      Host is up (0.0029s latency).  
      Not shown: 996 closed tcp ports (reset)
    
       | PORT    | STATE    |  SERVICE  | VERSION  |
       |---------|----------|-----------|----------|
       | 23/tcp  | filtered | telnet    |
       | 53 /tcp |  open    |  domain   |
    
    
      (unknown banner: not currently available)  
      dns-nsid:     
      bind.version: not currently available  
      fingerprint-strings:   
      DNSVersionBindReqTCP:   
      version bind     currently available
    
      80/tcp  open     http
    
      http-title: &#70;&#54;&#54;&#50;&#48;  
      fingerprint-strings:   
      GetRequest:  
      HTTP/1.0 200 OK  
      Connection: close  
      Cache-Control: no-cache,no-store  
      Pragma: no-cache  
      Content-Length: 154266  
      Set-Cookie: SID=54b9ea6aee217e7bf9ee66c3c6f6d1cb9a89f5b962ff8e0ce478021a130d91b9;  
        PATH=/; HttpOnly; SameSite=strict  
     Set-Cookie: _TESTCOOKIESUPPORT=1;      
     PATH=/; HttpOnly; SameSite=strict
     Server:   
     Accept-Ranges: bytes  
     X-Content-Type-Options: nosniff  
     X-XSS-Protection: 1; mode=block  
     Content-Security-Policy: frame-ancestors 'self'   
     X-Frame-Options: SAMEORIGIN    
        .......................................           
   .......................................................     
   .......................................................................................         
    Read More ... : [Click Here](https://docs.google.com/document/d/1zbiY-_Gigfxh1UdjFVdgO-OoLvCwRnbGgFvfpPggyio/edit?usp=sharing)
   
